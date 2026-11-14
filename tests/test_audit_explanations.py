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


def test_audit_digest_detection_containment_restore_roundtrip():
    db = MemoryDatabase(CONFIG)
    app = create_app(CONFIG,db)
    with TestClient(app) as client:
        assert client.get('/audit').status_code == 401
        assert client.post('/audit/run').status_code == 401
        login = client.post('/auth/login', json={'username': CONFIG.judge_username,
                                               'password': CONFIG.judge_password})
        assert login.status_code == 200
        auth = {'Authorization': 'Bearer ' + login.json()['access_token']}
        agent = {'X-API-Key': CONFIG.agent_api_key}
        seeded = client.post('/audit/run', headers=auth).json()['summary']
        assert 'Recorded activity: none yet.' in seeded
        assert 'Seeded demo history (4 entries)' in seeded

        data = fixture_batch()
        event = data['events'][1]
        event.update(source='agent', actions_taken=['block_wan', 'quarantine'], would_have=[])
        event['evidence'] = {'destination_port': 23}
        data['events'] = [event]
        assert client.post('/ingest', json=data, headers=agent).status_code == 200
        history = client.get('/audit', headers=auth).json()
        automatic = [r for r in history if r.get('event_id') == event['id']]
        assert {r['action'] for r in automatic} == {'detected:decoy_touch', 'block_wan', 'quarantine'}
        assert all(r['actor'] == 'agent' and r['outcome'] == 'applied' for r in automatic)
        assert client.post('/ingest', json=data, headers=agent).json()['accepted_events'] == 0
        assert client.get('/audit', headers=auth).json() == history

        response = client.post('/actions', headers=auth,
                               json={'action': 'restore', 'mac': event['mac']})
        assert response.status_code == 202
        command = response.json()
        pending = client.post('/audit/run', headers=auth).json()['summary'].split('Seeded demo history')[0]
        assert '1 request(s) awaiting acknowledgement' in pending
        assert '0 device restore(s) reported applied' in pending
        assert any(c['id'] == command['id'] for c in client.get('/sync', headers=agent).json()['commands'])
        ack = {'status': 'applied', 'ts': '2026-11-14T15:00:00Z'}
        for _ in range(2):
            assert client.post(f"/commands/{command['id']}/ack", headers=agent, json=ack).status_code == 204
        result = client.post('/audit/run', headers=auth)
        assert result.status_code == 200
        summary = result.json()['summary']
        recorded = summary.split('Seeded demo history')[0]
        for phrase in ('1 detection(s)', '1 internet block(s) reported applied',
                       '1 quarantine(s) reported applied', '1 device restore(s) reported applied',
                       '0 request(s) awaiting acknowledgement'):
            assert phrase in recorded
        assert 'Seeded demo history (4 entries)' in summary
        assert 'Containment does not fix a device' in summary
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


def test_learning_mode_and_simulator_audit_do_not_claim_containment():
    db = MemoryDatabase(CONFIG)
    try:
        data = fixture_batch()
        db.ingest(Ingest.model_validate(data))
        rows = db.audit()
        event = data['events'][1]
        actions = [r for r in rows if r.get('event_id') == event['id']]
        assert {r['action']: r['outcome'] for r in actions} == {
            'detected:decoy_touch': 'applied', 'block_wan': 'would_have', 'quarantine': 'would_have'}
        assert all(r['actor'] == 'simulator' for r in actions)
        from ml.securiot_ml.digest import digest
        summary = digest(rows)['summary']
        assert 'Recorded activity: none yet.' in summary
        simulated = summary.split('Simulator activity (')[1].split('Seeded demo history')[0]
        assert '0 quarantine(s) reported applied' in simulated
        assert '2 proposed action(s), not applied' in simulated
        data['events'][1]['actions_taken'] = ['quarantine']
        import pytest
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as error:
            db.ingest(Ingest.model_validate(data))
        assert error.value.status_code == 409
        assert db.audit() == rows
    finally:
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
