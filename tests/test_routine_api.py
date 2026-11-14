"""Volume event contract and idle device snapshot ordering."""
import copy
import json
from pathlib import Path
from types import SimpleNamespace
import pytest
from api.storage import MemoryDatabase
from api.telemetry import Ingest
from api.explanations import ExplanationService


def fixture():
    return json.loads((Path(__file__).resolve().parents[1] / 'contract/fixtures.json').read_text())


def test_idle_risk_update_preserves_last_seen_and_rejects_old_snapshot():
    db=MemoryDatabase(SimpleNamespace(judge_password='',judge_username='test'))
    try:
        data=fixture()
        data['devices']=data['devices'][:1]
        data['events']=[]
        data['devices'][0]['snapshot_at']='2026-11-14T12:01:00Z'
        assert db.ingest(Ingest.model_validate(data))['accepted_devices']==1
        newer=copy.deepcopy(data)
        newer['devices'][0].update(snapshot_at='2026-11-14T12:06:00Z',risk=0,band='low',anomaly=0)
        assert db.ingest(Ingest.model_validate(newer))['accepted_devices']==1
        assert db.devices()[0]['last_seen']==data['devices'][0]['last_seen']
        assert db.devices()[0]['risk']==0
        assert db.ingest(Ingest.model_validate(data))['accepted_devices']==0
    finally:
        db.close()


def test_volume_is_valid_and_explanation_never_claims_containment(monkeypatch):
    monkeypatch.setenv('GEMINI_API_KEY','configured-key')
    monkeypatch.setenv('GEMINI_MODEL','configured-model')
    data=fixture()
    data['events']=data['events'][:1]
    data['events'][0].update(kind='volume',actions_taken=[],would_have=[])
    Ingest.model_validate(data)
    service=ExplanationService()
    try:
        result=service.decorate(data['events'],data['devices'])[0]
        assert result['explanation_status']=='template'
        assert 'no automatic containment' in result['explanation']['plain_language']
        assert not service.pending
    finally:
        service.close()
