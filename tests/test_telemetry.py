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

                def sync(self):
                    # SET TRANSACTION cannot run in a savepoint; production sync
                    # uses its own connection. Read the same transactional state.
                    p = conn.execute('SELECT * FROM policy WHERE id = true').fetchone()
                    commands = conn.execute("SELECT id, created_at, action, mac FROM commands WHERE status='pending'").fetchall()
                    return {'etag': str(p['revision']), 'policy': {k:p[k] for k in ('learning_mode','protected_macs','ladder')}, 'commands': commands}

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
                assert client.post('/ingest', json=data, headers=headers).json() == {'accepted_devices':1,'accepted_events':2}
                assert client.post('/ingest', json=data, headers=headers).json() == {'accepted_devices':0,'accepted_events':0}
                conflict = copy.deepcopy(data)
                conflict['events'][0]['ts'] = '2026-11-15T12:00:00Z'
                assert client.post('/ingest', json=conflict, headers=headers).status_code == 409
                stale = copy.deepcopy(data)
                stale['devices'][0]['last_seen'] = '2026-11-13T12:00:00Z'
                stale['devices'][0]['name'] = 'stale'
                assert client.post('/ingest', json=stale, headers=headers).json()['accepted_devices'] == 0
                devices = client.get('/devices').json()
                assert next(d for d in devices if d['mac'] == data['devices'][0]['mac'])['name'] == 'camera'
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
