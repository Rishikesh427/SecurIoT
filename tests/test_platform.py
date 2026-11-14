import copy
import json
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient
from jsonschema import Draft202012Validator, FormatChecker

from api.main import app

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "contract/schemas.json").read_text())
FIXTURES = json.loads((ROOT / "contract/fixtures.json").read_text())


def validator(name="Ingest"):
    return Draft202012Validator({**SCHEMA, "$ref": f"#/$defs/{name}"}, format_checker=FormatChecker())


def test_contract_and_fixtures():
    Draft202012Validator.check_schema(SCHEMA)
    validator().validate(FIXTURES)
    inventory = yaml.safe_load((ROOT / "contract/devices.yaml").read_text())
    assert inventory["placeholder_macs"] is True
    assert {d["mac"] for d in inventory["devices"]} == {d["mac"] for d in FIXTURES["devices"]}
    assert len({e["id"] for e in FIXTURES["events"]}) == len(FIXTURES["events"])
    camera = FIXTURES["devices"][0]
    assert camera["risk"] == 75 and len(camera["reasons"]) == 4
    assert all(d["simulated"] for d in FIXTURES["devices"])


@pytest.mark.parametrize("field,value", [("risk", 101), ("mac", "invalid"), ("last_seen", "yesterday"), ("ports", [65536])])
def test_reject_invalid_device(field, value):
    batch = copy.deepcopy(FIXTURES)
    batch["devices"][0][field] = value
    assert list(validator().iter_errors(batch))


def test_action_target_rules():
    validator("Action").validate({"action": "restore_all"})
    validator("Action").validate({"action": "quarantine", "mac": FIXTURES["devices"][0]["mac"]})
    assert list(validator("Action").iter_errors({"action": "quarantine"}))
    assert list(validator("Action").iter_errors({"action": "restore_all", "mac": FIXTURES["devices"][0]["mac"]}))


def test_api_health_docs_and_unimplemented_routes():
    with TestClient(app, root_path="/api") as client:
        assert client.get("/healthz").json()["stage"] == "platform-h1-4"
        assert "/api/openapi.json" in client.get("/docs").text
        assert client.post("/ingest", json=FIXTURES).status_code == 404
        assert client.get("/openapi.json").status_code == 200


def test_cors_rejects_unlisted_origin():
    with TestClient(app) as client:
        response = client.options("/healthz", headers={"Origin": "https://untrusted.invalid", "Access-Control-Request-Method": "GET"})
        assert response.status_code == 400
        assert "access-control-allow-origin" not in response.headers
