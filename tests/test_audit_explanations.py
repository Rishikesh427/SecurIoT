import json
from pathlib import Path
from uuid import uuid4

from fastapi.testclient import TestClient

from api.control import ActionRequest
from api.explanations import ExplanationService
from api.main import create_app, current_user
from api.settings import Settings
from api.storage import MemoryDatabase
from api.telemetry import Ack, Ingest

CONFIG = Settings('postgresql://unused', 'test-secret-' * 4,
                  agent_api_key='test-agent', judge_password='test-judge-long-password')


def fixture_batch():
    data = json.loads((Path(__file__).parents[1] / 'contract/fixtures.json').read_text())
    for event in data['events']:
        event['id'] = str(uuid4())
    return data


def test_audit_records_restore_request_and_ack_and_seed_history():
    db = MemoryDatabase(CONFIG)
    try:
        data = fixture_batch(); db.ingest(Ingest.model_validate(data))
        command = db.create_command(ActionRequest(action='restore',mac=data['devices'][0]['mac']),uuid4(),'judge')
        requested = next(row for row in db.audit() if row.get('command_id') == command['id'])
        assert requested['outcome'] == 'requested' and requested['actor'] == 'judge'
        db.ack(command['id'], Ack.model_validate({'status':'applied','ts':'2026-11-14T15:00:00Z'}))
        applied = next(row for row in db.audit() if row.get('command_id') == command['id'])
        assert applied['outcome'] == 'applied'
        assert any(row['actor']=='seeded-demo' and row['action']=='restore' for row in db.audit())
    finally:
        db.close()


def test_audit_routes_require_auth_and_digest_calls_person_c(monkeypatch):
    from ml.securiot_ml import digest as module
    db = MemoryDatabase(CONFIG)
    app = create_app(CONFIG,db)
    with TestClient(app) as client:
        assert client.get('/audit').status_code == 401
        app.dependency_overrides[current_user] = lambda: {'username':'judge'}
        assert client.get('/audit').status_code == 200
        assert client.post('/audit/run').status_code == 503
        seen = []
        monkeypatch.setattr(module,'digest',lambda history: seen.extend(history) or {'summary':f'{len(history)} entries'},raising=False)
        result = client.post('/audit/run')
        assert result.status_code == 200 and result.json() == {'summary':'4 entries'}
        assert len(seen) == 4 and any(row['action']=='restore' for row in seen)
    db.close()


def test_audit_and_event_views_match_contract():
    from jsonschema import Draft202012Validator, FormatChecker
    schema = json.loads((Path(__file__).parents[1] / 'contract/schemas.json').read_text())
    db = MemoryDatabase(CONFIG)
    app = create_app(CONFIG,db); app.dependency_overrides[current_user] = lambda: {'username':'judge'}
    with TestClient(app) as client:
        data = fixture_batch(); db.ingest(Ingest.model_validate(data))
        audit_validator = Draft202012Validator({**schema,'$ref':'#/$defs/AuditEntry'},format_checker=FormatChecker())
        event_validator = Draft202012Validator({**schema,'$ref':'#/$defs/EventView'},format_checker=FormatChecker())
        for row in client.get('/audit').json(): audit_validator.validate(row)
        for row in client.get('/events').json(): event_validator.validate(row)
    db.close()


def test_explanations_are_nonblocking_deduplicated_and_cached(monkeypatch):
    import api.explanations as module
    calls = []
    def generated(event, device):
        calls.append(event['id'])
        return {'plain_language':'Generated once.','recommended_next_step':'Review it.'}
    monkeypatch.setattr(module,'explain',generated)
    service = ExplanationService(workers=1); service.configured = True
    data = fixture_batch(); event = data['events'][0]; device = data['devices'][0]
    first = service.decorate([event],[device])[0]
    second = service.decorate([event],[device])[0]
    assert first['explanation_status'] == 'pending'
    assert second['explanation_status'] in ('pending','ready')
    service.pool.shutdown(wait=True)
    cached = service.decorate([event],[device])[0]
    assert cached['explanation_status'] == 'ready'
    assert cached['explanation']['plain_language'] == 'Generated once.'
    assert calls == [event['id']]


def test_unconfigured_explanation_uses_template_without_work():
    service = ExplanationService(); service.configured = False
    data = fixture_batch()
    result = service.decorate([data['events'][0]],data['devices'])[0]
    assert result['explanation_status'] == 'template'
    assert result['explanation']['plain_language']
    assert not service.pending
    service.close()
