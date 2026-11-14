import copy
import json
import os
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from api.db import Database
from api.main import create_app, current_user
from api.settings import Settings


@pytest.mark.skipif(os.getenv('SECURIOT_TEST_DATABASE') != '1', reason='Live database checks are opt-in')
def test_ingest_sync_ack_roundtrip():
    settings = replace(Settings.load(), agent_api_key='test-agent-key')
    with Database(settings).connect() as conn:
        with conn.transaction(force_rollback=True):
            class TransactionDatabase(Database):
                @contextmanager
                def connect(self):
                    # Keep all writes within the outer rollback-only transaction.
                    with conn.transaction():
                        yield conn

            app = create_app(settings, TransactionDatabase(settings))
            app.dependency_overrides[current_user] = lambda: {'username': 'test'}
            data = json.loads((Path(__file__).parents[1] / 'contract/fixtures.json').read_text())
            data['devices'] = [data['devices'][0]]
            data['devices'][0]['mac'] = '02:fe:' + ':'.join(uuid4().hex[i:i+2] for i in range(0,8,2))
            for event in data['events']:
                event['id'] = str(uuid4())
                event['mac'] = data['devices'][0]['mac']
            headers = {'X-API-Key': settings.agent_api_key}
            with TestClient(app) as client:
                assert client.post('/ingest', json=data).status_code == 401
                assert client.get('/sync').status_code == 401
                assert client.post('/ingest', json=data, headers={'X-API-Key':'wrong'}).status_code == 401
                assert client.post('/ingest', json=data, headers=headers).json() == {'accepted_devices':1,'accepted_events':2}
                assert client.post('/ingest', json=data, headers=headers).json() == {'accepted_devices':0,'accepted_events':0}
                conflict = copy.deepcopy(data)
                conflict['events'][0]['ts'] = '2026-11-15T12:00:00Z'
                assert client.post('/ingest', json=conflict, headers=headers).status_code == 409
                # A valid event before a conflicting event must also roll back.
                new_event = copy.deepcopy(data['events'][0])
                new_event['id'] = str(uuid4())
                conflict['events'].insert(0, new_event)
                assert client.post('/ingest', json=conflict, headers=headers).status_code == 409
                assert conn.execute('SELECT 1 FROM events WHERE id=%s', (new_event['id'],)).fetchone() is None
                stale = copy.deepcopy(data)
                stale['devices'][0]['last_seen'] = '2026-11-13T12:00:00Z'
                stale['devices'][0]['name'] = 'stale'
                assert client.post('/ingest', json=stale, headers=headers).json()['accepted_devices'] == 0
                devices = client.get('/devices').json()
                assert next(d for d in devices if d['mac'] == data['devices'][0]['mac'])['name'] == 'camera'
                newer = copy.deepcopy(data)
                newer['devices'][0].update(last_seen='2026-11-15T12:00:00Z', name='updated camera')
                assert client.post('/ingest', json=newer, headers=headers).json()['accepted_devices'] == 1
                assert client.get('/events?limit=1000').status_code == 200
                command_id = uuid4()
                conn.execute("INSERT INTO commands(id,action,mac) VALUES (%s,'restore',%s)", (command_id,data['devices'][0]['mac']))
                sync = client.get('/sync', headers=headers).json()
                assert any(c['id'] == str(command_id) for c in sync['commands'])
                assert client.get('/sync', params={'etag':sync['etag']}, headers=headers).status_code == 200
                ack = {'status':'applied','ts':'2026-11-14T13:00:00Z'}
                for _ in range(2):
                    assert client.post(f'/commands/{command_id}/ack',json=ack,headers=headers).status_code == 204
                assert client.post('/ack',params={'command_id':str(command_id)},json=ack,headers=headers).status_code == 204
                assert client.post(f'/commands/{command_id}/ack',json={**ack,'status':'failed'},headers=headers).status_code == 409
                assert client.post(f'/commands/{uuid4()}/ack',json=ack,headers=headers).status_code == 404
                assert all(c['id'] != str(command_id) for c in client.get('/sync',headers=headers).json()['commands'])
                # Hide unrelated queued commands only within this rolled-back test.
                conn.execute("UPDATE commands SET status='failed', ack_ts=now() WHERE status='pending'")
                unchanged = client.get('/sync', params={'etag':sync['etag']}, headers=headers)
                assert unchanged.status_code == 304 and unchanged.content == b''
                conn.execute('UPDATE policy SET revision=revision+1 WHERE id=true')
                assert client.get('/sync', params={'etag':sync['etag']}, headers=headers).status_code == 200
                restore_all = uuid4()
                conn.execute("INSERT INTO commands(id,action) VALUES (%s,'restore_all')", (restore_all,))
                result = client.get('/sync', headers=headers).json()
                assert 'mac' not in next(c for c in result['commands'] if c['id'] == str(restore_all))


def test_dashboard_routes_require_jwt():
    with TestClient(create_app(Settings('postgresql://unused', 'test-secret-' * 4))) as client:
        for route in ('/devices', '/events'):
            assert client.get(route).status_code == 401


@pytest.mark.parametrize('field,value', [('ip','::1'), ('ports',[23,23]), ('last_seen','yesterday'), ('risk',101)])
def test_invalid_ingest_rejected_before_storage(field, value):
    data = json.loads((Path(__file__).parents[1] / 'contract/fixtures.json').read_text())
    data['devices'][0][field] = value
    config = Settings('postgresql://unused', 'test-secret-' * 4, agent_api_key='test-key')
    with TestClient(create_app(config)) as client:
        assert client.post('/ingest', json=data, headers={'X-API-Key':'test-key'}).status_code == 422
