import copy
import json
import os
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

import psycopg
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from api.control import ActionRequest, Policy
from api.db import Database
from api.main import create_app, current_user
from api.manage import migrate
from api.settings import Settings
from api.storage import MemoryDatabase, Storage
from api.telemetry import Ingest

PASSWORD = 'test-judge-long-password'
CONFIG = Settings('postgresql://unused', 'test-secret-' * 4, agent_api_key='test-agent', judge_password=PASSWORD)


def batch():
    data = json.loads((Path(__file__).parents[1] / 'contract/fixtures.json').read_text())
    data['devices'] = [data['devices'][0]]
    mac = '02:fe:' + ':'.join(uuid4().hex[i:i+2] for i in range(0,8,2))
    data['devices'][0]['mac'] = mac
    for event in data['events']:
        event.update(id=str(uuid4()), mac=mac)
    return data


@pytest.fixture(params=['memory','postgres'])
def store(request):
    if request.param == 'memory':
        db = MemoryDatabase(CONFIG)
        yield db
        db.close()
    else:
        if os.getenv('SECURIOT_TEST_DATABASE') != '1':
            pytest.skip('Live database checks are opt-in')
        with Database(Settings.load()).connect() as conn:
            with conn.transaction(force_rollback=True):
                migrate(conn)
                class TransactionDatabase(Database):
                    @contextmanager
                    def connect(self):
                        with conn.transaction():
                            yield conn
                db = TransactionDatabase(Settings.load())
                db.put_policy(Policy())
                yield db


def test_actions_policy_and_ack_end_to_end(store):
    app = create_app(CONFIG, store)
    app.dependency_overrides[current_user] = lambda: {'username':'judge'}
    data = batch()
    mac = data['devices'][0]['mac']
    agent = {'X-API-Key':CONFIG.agent_api_key}
    with TestClient(app) as client:
        p = client.get('/policy')
        assert p.json() == Policy().model_dump()
        assert client.post('/actions', json={'action':'quarantine','mac':mac}).status_code == 404
        assert client.post('/ingest', json=data, headers=agent).status_code == 200
        assert client.post('/actions', json={'action':'quarantine','mac':mac}).status_code == 202
        armed = {**p.json(), 'learning_mode':False}
        update = client.put('/policy', json=armed, headers={'If-Match':p.headers['etag']})
        assert update.status_code == 200 and update.headers['etag'] != p.headers['etag']
        assert client.put('/policy', json=armed, headers={'If-Match':p.headers['etag']}).status_code == 412
        assert client.put('/policy', json=armed).headers['etag'] == update.headers['etag']
        key = str(uuid4())
        action = {'action':'quarantine','mac':mac}
        command = client.post('/actions', json=action, headers={'Idempotency-Key':key})
        assert command.status_code == 202 and command.json()['id'] == key
        assert client.post('/actions', json=action, headers={'Idempotency-Key':key}).json() == command.json()
        assert client.post('/actions', json={'action':'restore_all'}, headers={'Idempotency-Key':key}).status_code == 409
        assert next(d for d in client.get('/devices').json() if d['mac']==mac)['status'] == 'normal'
        assert any(c['id']==key for c in client.get('/sync',headers=agent).json()['commands'])
        ack = {'status':'applied','ts':'2026-11-14T15:00:00Z'}
        assert client.post(f'/commands/{key}/ack',json=ack,headers=agent).status_code == 204
        assert all(c['id']!=key for c in client.get('/sync',headers=agent).json()['commands'])
        pending = client.post('/actions',json=action).json()['id']
        protected = {**armed,'protected_macs':[mac]}
        assert client.put('/policy',json=protected).status_code == 200
        assert all(c['id']!=pending for c in client.get('/sync',headers=agent).json()['commands'])
        # A command may have reached the agent before it was cancelled.
        assert client.post(f'/commands/{pending}/ack',json=ack,headers=agent).status_code == 204
        assert client.post(f'/commands/{pending}/ack',json=ack,headers=agent).status_code == 204
        assert client.post('/actions',json=action).status_code == 409
        assert client.post('/actions',json={'action':'restore','mac':mac}).status_code == 202
        restored = client.post('/actions',json={'action':'restore_all'})
        assert restored.status_code == 202 and 'mac' not in restored.json()
        # Re-arming never resurrects the cancelled command.
        client.put('/policy',json=armed)
        assert all(c['id']!=pending for c in client.get('/sync',headers=agent).json()['commands'])
        disabled = {**armed, 'ladder':{**armed['ladder'],'quarantine':False}}
        client.put('/policy',json=disabled)
        assert client.post('/actions',json=action).status_code == 409


def test_memory_batch_atomicity_and_idempotence():
    db = MemoryDatabase(CONFIG)
    try:
        data = batch()
        assert db.ingest(Ingest.model_validate(data)) == {'accepted_devices':1,'accepted_events':2}
        assert db.ingest(Ingest.model_validate(data)) == {'accepted_devices':0,'accepted_events':0}
        conflict = copy.deepcopy(data)
        first = copy.deepcopy(data['events'][0])
        first['id'] = str(uuid4())
        conflict['events'][0]['evidence']['different'] = True
        conflict['events'].insert(0,first)
        with pytest.raises(HTTPException) as error:
            db.ingest(Ingest.model_validate(conflict))
        assert error.value.status_code == 409
        assert len(db.events(100,0)) == 2
    finally:
        db.close()


class DownDatabase:
    def __init__(self, error=None):
        self.error = error or psycopg.OperationalError('private database connection details')
        self.calls = 0

    def __getattr__(self, name):
        def failed(*args, **kwargs):
            self.calls += 1
            raise self.error
        return failed


def test_automatic_fallback_cold_login_badge_and_latching():
    primary = DownDatabase()
    storage = Storage(primary,CONFIG)
    with TestClient(create_app(CONFIG,storage)) as client:
        result = client.get('/storage')
        assert result.status_code == 200 and result.json()['demo_storage']
        assert result.headers['X-Storage-Mode'] == 'memory'
        login = client.post('/auth/login', json={'username':'judge','password':PASSWORD})
        assert login.status_code == 200
        headers = {'Authorization':'Bearer '+login.json()['access_token']}
        assert client.get('/policy',headers=headers).json()['learning_mode'] is True
        assert client.get('/readyz').json()['storage']['persistent'] is False
        assert client.get('/devices',headers=headers).json() == []
        assert primary.calls == 1  # No repeated connection stalls or silent return.
    restarted = MemoryDatabase(CONFIG)
    assert restarted.get_policy()['etag'] != storage.memory.get_policy()['etag']
    restarted.close()


def test_admin_account_can_read_dashboard():
    db = MemoryDatabase(CONFIG)
    user = db.user_by_name('judge')
    db.users[str(user['id'])]['role'] = 'admin'
    try:
        with TestClient(create_app(CONFIG, db)) as client:
            login = client.post('/auth/login', json={'username':'judge','password':PASSWORD})
            assert login.status_code == 200
            headers = {'Authorization':'Bearer '+login.json()['access_token']}
            assert client.get('/auth/me', headers=headers).json()['role'] == 'admin'
            for route in ('/devices', '/events', '/audit', '/policy'):
                assert client.get(route, headers=headers).status_code == 200
    finally:
        db.close()


def test_ambiguous_write_is_not_replayed_into_memory():
    storage = Storage(DownDatabase(),CONFIG)
    with pytest.raises(HTTPException) as error:
        storage.create_command(ActionRequest(action='restore_all'),uuid4())
    assert error.value.status_code == 503 and storage.status()['demo_storage']
    assert storage.sync()['commands'] == []
    storage.close()


@pytest.mark.parametrize('error',[psycopg.ProgrammingError('schema broken'),psycopg.errors.QueryCanceled('timeout')])
def test_non_connection_errors_do_not_trigger_fallback(error):
    storage = Storage(DownDatabase(error),CONFIG)
    with pytest.raises(type(error)):
        storage.ready()
    assert not storage.using_memory
    storage.close()


def test_postgres_mode_never_falls_back():
    storage = Storage(DownDatabase(),replace(CONFIG,storage_mode='postgres'))
    with pytest.raises(psycopg.OperationalError):
        storage.ready()
    assert not storage.using_memory
    storage.close()


def test_outage_keeps_logged_in_identity_and_remembered_disabled_state():
    from api.auth import issue_token
    primary = MemoryDatabase(CONFIG)
    user = primary.user_by_name('judge')
    storage = Storage(primary,CONFIG)
    storage.user_by_name('judge')
    token = issue_token(user,CONFIG)
    storage.primary = DownDatabase()
    with TestClient(create_app(CONFIG,storage)) as client:
        assert client.get('/auth/me',headers={'Authorization':'Bearer '+token}).status_code == 200
    primary.close()


def test_disabled_judge_stays_disabled_after_failover():
    primary = MemoryDatabase(CONFIG)
    user = primary.user_by_name('judge')
    primary.users[str(user['id'])]['active'] = False
    storage = Storage(primary,CONFIG)
    storage.user_by_name('judge')
    storage.primary = DownDatabase()
    with TestClient(create_app(CONFIG,storage)) as client:
        assert client.post('/auth/login',json={'username':'judge','password':PASSWORD}).status_code == 401
    primary.close()


def test_protected_list_survives_outage_but_learning_resets():
    primary = MemoryDatabase(CONFIG)
    primary.put_policy(Policy(learning_mode=False,protected_macs=['02:00:00:00:00:40']))
    storage = Storage(primary,CONFIG)
    storage.get_policy()
    storage.primary = DownDatabase()
    p = storage.get_policy()['policy']
    assert p['learning_mode'] and p['protected_macs']==['02:00:00:00:00:40']
    storage.close()
    primary.close()


def test_controls_require_jwt_and_reject_bad_shapes():
    db = MemoryDatabase(CONFIG)
    app = create_app(CONFIG,db)
    with TestClient(app) as client:
        assert client.get('/policy').status_code == 401
        assert client.put('/policy',json={}).status_code == 401
        assert client.post('/actions',json={'action':'restore_all'}).status_code == 401
        app.dependency_overrides[current_user] = lambda: {'username':'judge'}
        for value in ({'action':'quarantine'}, {'action':'power_cycle'}, {'action':'restore_all','mac':None}):
            assert client.post('/actions',json=value).status_code == 422
        for value in ({'learning_mode':'false'},{'ladder':{'notify':'yes'}},{'unknown':True}):
            assert client.put('/policy',json=value).status_code == 422
        assert client.put('/policy',json={}).json() == Policy().model_dump()
    db.close()


def test_concurrent_memory_action_retries_and_policy_edits():
    from concurrent.futures import ThreadPoolExecutor
    db = MemoryDatabase(CONFIG)
    key = uuid4()
    try:
        with ThreadPoolExecutor(max_workers=4) as pool:
            commands = list(pool.map(lambda _: db.create_command(ActionRequest(action='restore_all'),key), range(12)))
        assert all(c['id']==str(key) for c in commands)
        assert len(db.sync()['commands']) == 1
        etag = '"' + db.get_policy()['etag'] + '"'
        def save(i):
            try:
                db.put_policy(Policy(learning_mode=False,protected_macs=[f'02:00:00:00:00:{i:02x}']),etag)
                return 200
            except HTTPException as exc:
                return exc.status_code
        with ThreadPoolExecutor(max_workers=4) as pool:
            statuses = list(pool.map(save,range(4)))
        assert statuses.count(200)==1 and statuses.count(412)==3
    finally:
        db.close()


def test_storage_and_policy_responses_match_shared_contract():
    from jsonschema import Draft202012Validator, FormatChecker
    schema = json.loads((Path(__file__).parents[1] / 'contract/schemas.json').read_text())
    storage = Storage(DownDatabase(),replace(CONFIG,storage_mode='memory'))
    Draft202012Validator({**schema,'$ref':'#/$defs/StorageStatus'}).validate(storage.status())
    Draft202012Validator({**schema,'$ref':'#/$defs/Policy'}).validate(storage.get_policy()['policy'])
    command = storage.create_command(ActionRequest(action='restore_all'),uuid4())
    Draft202012Validator({**schema,'$ref':'#/$defs/Command'},format_checker=FormatChecker()).validate(command)
    Draft202012Validator({**schema,'$ref':'#/$defs/Sync'},format_checker=FormatChecker()).validate(storage.sync())
    storage.close()
