from datetime import datetime, timedelta, timezone
from uuid import uuid4

import jwt
import psycopg
import pytest
from fastapi.testclient import TestClient

from api.auth import decode_token, issue_token, passwords
from api.main import create_app
from api.settings import Settings

CONFIG = Settings("postgresql://unused", "test-only-secret-" * 4)
PASSWORD = "test-judge-password-long"


class FakeDatabase:
    def __init__(self):
        self.user = {"id": uuid4(), "username": "judge", "password_hash": passwords.hash(PASSWORD), "role": "judge", "active": True}

    def ready(self):
        return True

    def user_by_name(self, name):
        return self.user if name == self.user["username"] else None

    def user_by_id(self, user_id):
        return self.user if user_id == self.user["id"] else None


@pytest.fixture
def api():
    db = FakeDatabase()
    with TestClient(create_app(CONFIG, db)) as client:
        yield client, db


@pytest.mark.parametrize(("username", "role"), [("judge", "judge"), ("admin", "admin")])
def test_login_and_authenticated_identity(api, username, role):
    client, db = api
    db.user["username"] = username
    db.user["role"] = role
    result = client.post("/auth/login", json={"username": username, "password": PASSWORD})
    assert result.status_code == 200
    assert result.headers["Cache-Control"] == "no-store"
    body = result.json()
    assert body["expires_in"] == 3600 and body["token_type"] == "bearer"
    claims = decode_token(body["access_token"], CONFIG)
    assert claims["sub"] == str(db.user["id"])
    me = client.get("/auth/me", headers={"Authorization": "Bearer " + body["access_token"]})
    assert me.status_code == 200
    assert me.json() == {"id": str(db.user["id"]), "username": username, "role": role}
    assert "password" not in result.text and "password_hash" not in me.text


@pytest.mark.parametrize("username,password", [("judge", "wrong"), ("missing", PASSWORD)])
def test_invalid_login_is_generic(api, username, password):
    client, _ = api
    response = client.post("/auth/login", json={"username": username, "password": password})
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid credentials"}


def test_missing_token(api):
    assert api[0].get("/auth/me").status_code == 401


@pytest.mark.parametrize("problem", ["expired", "wrong_signature", "wrong_audience", "wrong_issuer", "missing_exp", "bad_subject", "wrong_type", "wrong_algorithm"])
def test_reject_invalid_tokens(api, problem):
    client, db = api
    claims = decode_token(issue_token(db.user, CONFIG), CONFIG)
    secret, algorithm = CONFIG.jwt_secret, "HS256"
    if problem == "expired":
        claims["exp"] = datetime.now(timezone.utc) - timedelta(seconds=1)
    elif problem == "wrong_signature":
        secret = "different-secret-" * 4
    elif problem == "wrong_audience":
        claims["aud"] = "another-app"
    elif problem == "wrong_issuer":
        claims["iss"] = "another-issuer"
    elif problem == "missing_exp":
        del claims["exp"]
    elif problem == "bad_subject":
        claims["sub"] = "not-a-uuid"
    elif problem == "wrong_type":
        claims["type"] = "refresh"
    elif problem == "wrong_algorithm":
        algorithm = "HS384"
    token = jwt.encode(claims, secret, algorithm=algorithm)
    assert client.get("/auth/me", headers={"Authorization": "Bearer " + token}).status_code == 401


def test_disabled_user_cannot_login_or_use_old_token(api):
    client, db = api
    token = issue_token(db.user, CONFIG)
    db.user["active"] = False
    assert client.post("/auth/login", json={"username": "judge", "password": PASSWORD}).status_code == 401
    assert client.get("/auth/me", headers={"Authorization": "Bearer " + token}).status_code == 401


def test_database_failure_does_not_leak_credentials(api):
    client, db = api
    def unavailable(*args):
        raise psycopg.OperationalError("secret connection info")
    db.ready = unavailable
    db.user_by_name = unavailable
    assert client.get("/healthz").status_code == 200
    assert client.get("/readyz").status_code == 503
    response = client.post("/auth/login", json={"username": "judge", "password": PASSWORD})
    assert response.status_code == 503
    assert "secret" not in response.text
