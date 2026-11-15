import json
from contextlib import contextmanager

from fastapi.testclient import TestClient

from api.control import Policy
from api.main import create_app, current_user
from api.storage import MemoryDatabase
from api.telemetry import Ingest
from test_controls import CONFIG, batch


def test_direct_result_is_logged_after_router_execution(monkeypatch):
    db = MemoryDatabase(CONFIG)
    data = batch()
    db.ingest(Ingest.model_validate(data))
    db.put_policy(Policy(learning_mode=False))
    app = create_app(CONFIG, db)
    app.dependency_overrides[current_user] = lambda: {'username': 'judge'}
    monkeypatch.setenv('SECURIOT_ROUTER_URL', 'http://router')
    @contextmanager
    def execute(request, timeout):
        payload = json.loads(request.data)
        assert payload['command']['action'] == 'quarantine'
        row = next(row for row in db.audit() if row.get('command_id') == payload['command']['id'])
        assert row['outcome'] == 'requested'
        class Response:
            def read(self, size):
                return json.dumps({'status': 'applied', 'ts': '2026-11-14T13:00:00Z', 'detail': 'live enforcement'}).encode()
        yield Response()
    monkeypatch.setattr('urllib.request.urlopen', execute)
    try:
        with TestClient(app) as client:
            result = client.post('/actions', json={'action': 'quarantine', 'mac': data['devices'][0]['mac']})
            assert result.status_code == 202
            assert result.json()['status'] == 'applied'
            assert next(row for row in db.audit() if row.get('command_id') == result.json()['id'])['outcome'] == 'applied'
    finally:
        db.close()


def test_signup_requires_invitation_and_rejects_duplicates(monkeypatch):
    monkeypatch.setenv('SIGNUP_INVITE_CODE', 'test-invitation-code-long')
    db = MemoryDatabase(CONFIG)
    try:
        with TestClient(create_app(CONFIG, db)) as client:
            body = {'username': 'new-user', 'password': 'a-long-test-password', 'invite_code': 'wrong'}
            assert client.post('/auth/signup', json=body).status_code == 403
            body['invite_code'] = 'test-invitation-code-long'
            assert client.post('/auth/signup', json=body).status_code == 201
            assert client.post('/auth/signup', json=body).status_code == 409
            assert client.post('/auth/login', json={'username': body['username'], 'password': body['password']}).status_code == 200
    finally:
        db.close()
