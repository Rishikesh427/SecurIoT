import copy
import json
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from jsonschema import Draft202012Validator

import api.explanations as module
from api.main import create_app, current_user
from api.settings import Settings
from api.storage import MemoryDatabase
from api.telemetry import Ingest

CONFIG = Settings('postgresql://unused', 'test-secret-' * 4, agent_api_key='test-agent')
REPLY = {'plain_language': 'The device contacted a decoy. No containment action was reported for this event.',
         'recommended_next_step': 'Review its settings.'}


def data():
    return json.loads((Path(__file__).parents[1] / 'contract/fixtures.json').read_text())


def wait_for_worker(service):
    deadline = time.perf_counter() + 2
    while time.perf_counter() < deadline:
        with service.lock:
            if not service.pending:
                return
        time.sleep(.005)
    raise AssertionError('Worker did not finish')


def test_stalled_generation_never_blocks_api_and_queue_is_bounded(monkeypatch):
    started, release = Event(), Event()
    calls = []
    def slow(event, device, **kwargs):
        calls.append(event['id']); started.set(); release.wait(10)
        return REPLY.copy()
    monkeypatch.setattr(module, 'explain', slow)
    db = MemoryDatabase(CONFIG)
    batch = data(); original = copy.deepcopy(batch['events'][0])
    batch['events'] = [{**original, 'id': str(uuid4())} for _ in range(1000)]
    db.ingest(Ingest.model_validate(batch))
    before = db.devices(), db.sync(), db.audit()
    app = create_app(CONFIG, db)
    app.dependency_overrides[current_user] = lambda: {'username': 'test'}
    schema = json.loads((Path(__file__).parents[1] / 'contract/schemas.json').read_text())
    validator = Draft202012Validator({**schema, '$ref': '#/$defs/EventView'})
    try:
        with TestClient(app) as client:
            service = app.state.explanations; service.configured = True
            start = time.perf_counter()
            response = client.get('/events?limit=1000')
            first_ms = (time.perf_counter() - start) * 1000
            assert response.status_code == 200 and first_ms < 1500
            assert started.wait(1) and not release.is_set()
            rows = response.json()
            assert len(rows) == 1000
            assert sum(row['explanation_status'] == 'pending' for row in rows) == service.max_pending
            assert all(row['explanation_status'] in ('pending', 'template') for row in rows)
            for row in rows: validator.validate(row)
            with service.lock: assert len(service.pending) == service.max_pending

            def request_events(_):
                start = time.perf_counter(); result = client.get('/events?limit=100')
                assert result.status_code == 200
                return (time.perf_counter() - start) * 1000
            with ThreadPoolExecutor(max_workers=8) as pool:
                durations = list(pool.map(request_events, range(24)))
            assert max(durations) < 1500
            assert client.get('/healthz').status_code == 200
            assert client.get('/sync', headers={'X-API-Key': 'test-agent'}).status_code == 200
            assert client.post('/ingest', json=batch, headers={'X-API-Key': 'test-agent'}).status_code == 200
            assert len(calls) <= 2 and len(service.pending) == service.max_pending
            # Network generation is still blocked after every HTTP request completed.
            assert not release.is_set()
            print(f' explanation latency: 1000-event page={first_ms:.1f}ms; 24 concurrent reads max={max(durations):.1f}ms')
            release.set(); wait_for_worker(service)
            assert before == (db.devices(), db.sync(), db.audit())
    finally:
        release.set(); db.close()


@pytest.mark.parametrize('failure', [TimeoutError('provider timeout'), OSError('offline'),
                                   {'plain_language': 'missing next step'}, {'plain_language': '', 'recommended_next_step': 'x'}])
def test_failure_is_template_and_retries_only_after_backoff(monkeypatch, failure):
    clock = [0.0]; calls = []
    monkeypatch.setattr(module.time, 'monotonic', lambda: clock[0])
    def generated(*args, **kwargs):
        calls.append(1)
        if isinstance(failure, Exception): raise failure
        return failure
    monkeypatch.setattr(module, 'explain', generated)
    service = module.ExplanationService(workers=1); service.configured = True
    batch = data(); event, devices = batch['events'][0], batch['devices']
    try:
        assert service.decorate([event], devices)[0]['explanation_status'] == 'pending'
        wait_for_worker(service)
        failed = service.decorate([event], devices)[0]
        assert failed['explanation_status'] == 'template'
        assert failed['explanation'] == module.template(event, devices[0])
        service.decorate([event], devices); assert len(calls) == 1
        clock[0] = 61
        assert service.decorate([event], devices)[0]['explanation_status'] == 'pending'
        wait_for_worker(service); assert len(calls) == 2
    finally:
        service.close()


def test_deadline_returns_template_without_replacing_stalled_worker(monkeypatch):
    clock = [0.0]; started, release = Event(), Event(); calls = []
    monkeypatch.setattr(module.time, 'monotonic', lambda: clock[0])
    def late(*args, **kwargs):
        calls.append(1); started.set(); release.wait(5)
        return REPLY.copy()
    monkeypatch.setattr(module, 'explain', late)
    service = module.ExplanationService(workers=1, max_pending=1); service.configured = True
    batch = data()
    try:
        service.decorate(batch['events'], batch['devices']); assert started.wait(1)
        clock[0] = 9
        for _ in range(10):
            assert all(row['explanation_status'] == 'template' for row in service.decorate(batch['events'], batch['devices']))
        assert len(calls) == 1 and len(service.pending) == 1
        release.set(); wait_for_worker(service)
        assert service.decorate(batch['events'][:1], batch['devices'])[0]['explanation_status'] == 'template'
    finally:
        release.set(); service.close()


def test_cache_invalidation_ttl_bound_and_response_mutation(monkeypatch):
    clock = [0.0]; calls = []
    monkeypatch.setattr(module.time, 'monotonic', lambda: clock[0])
    def generated(*args, **kwargs): calls.append(1); return REPLY.copy()
    monkeypatch.setattr(module, 'explain', generated)
    service = module.ExplanationService(workers=1, max_cache=2); service.configured = True
    batch = data(); event = batch['events'][0]
    def get(ev):
        service.decorate([ev], batch['devices']); wait_for_worker(service)
        return service.decorate([ev], batch['devices'])[0]
    try:
        row = get(event); assert row['explanation_status'] == 'ready'
        row['explanation']['plain_language'] = 'mutated'
        assert get(event)['explanation']['plain_language'] != 'mutated' and len(calls) == 1
        get({**event, 'actions_taken': ['quarantine'], 'source': 'agent', 'evidence': {}})
        assert len(calls) == 2
        get({**event, 'id': str(uuid4())}); assert len(service.cache) == 2
        clock[0] = service.TTL + 1
        get(event); assert len(calls) == 4
        service.close()
        assert all(row['explanation_status'] != 'pending' for row in service.decorate(batch['events'], batch['devices']))
    finally:
        service.close()
