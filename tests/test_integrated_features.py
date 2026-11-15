import copy
import json
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID
import urllib.error

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from api.main import create_app
from api.settings import Settings
from api.storage import MemoryDatabase
from api.telemetry import Ingest, Ack
from securiot_agent.cloud_loop import CloudLoop
from securiot_agent.enforcement import MockEnforcer
from securiot_agent.inventory import Inventory
from securiot_agent.models import Device
from securiot_agent.runtime import Agent
from securiot_agent.storage import Storage
from ml.securiot_ml import research

ROOT=Path(__file__).resolve().parents[1]
MAC='02:00:00:00:00:20'
CONFIG=Settings('postgresql://unused','x'*48,storage_mode='memory',agent_api_key='agent-test-key',judge_password='a-test-password-long-enough')


def fixture():return json.loads((ROOT/'contract/fixtures.json').read_text())


def test_registration_capacity_preserves_existing_updates():
    db=MemoryDatabase(CONFIG)
    try:
        base=fixture()['devices'][0]
        devices=[]
        for i in range(20):
            d=copy.deepcopy(base);d.update(mac=f'02:00:00:00:01:{i:02x}',ip=f'10.42.0.{i+10}');devices.append(d)
        assert db.ingest(Ingest.model_validate({'devices':devices,'events':[]}))['accepted_devices']==20
        extra=copy.deepcopy(base);extra.update(mac='02:00:00:00:02:01',ip='10.42.0.100')
        with pytest.raises(HTTPException):db.ingest(Ingest.model_validate({'devices':[extra],'events':[]}))
        assert len(db.devices())==20
        devices[0]['snapshot_at']='2026-11-15T12:00:00Z'
        assert db.ingest(Ingest.model_validate({'devices':[devices[0]],'events':[]}))['accepted_devices']==1
    finally:db.close()


def test_warn_is_recorded_and_manual_block_completes_without_disappearing(tmp_path):
    db=MemoryDatabase(CONFIG)
    db.ingest(Ingest.model_validate({'devices':[fixture()['devices'][0]],'events':[]}))
    guest=Device(MAC,'10.42.0.20','Guest',protected=True,simulated=True,risk_facts={'_demo_discovered':True})
    agent=Agent(Inventory([guest]),SimpleNamespace(observe=lambda _:None),MockEnforcer(),Storage(tmp_path))
    loop=CloudLoop(agent,SimpleNamespace(identity='test-api'),ROOT/'contract/schemas.json')
    loop.apply_policy(db.get_policy()['policy'])
    original=db.command_result
    def complete(identifier):
        command=next(c for c in db.sync()['commands'] if c['id']==str(identifier))
        loop.command(command)
        db.ack(UUID(str(identifier)),Ack.model_validate(loop.state['commands'][str(identifier)]['ack']))
        return original(identifier)
    db.command_result=complete
    try:
        with TestClient(create_app(CONFIG,db)) as client:
            login=client.post('/auth/login',json={'username':CONFIG.judge_username,'password':CONFIG.judge_password})
            auth={'Authorization':'Bearer '+login.json()['access_token']}
            assert client.post(f'/devices/{MAC}/warn',headers=auth).json()['status']=='recorded'
            assert guest.status=='normal'
            result=client.post('/actions?wait=true',headers=auth,json={'action':'block_wan','mac':MAC})
            assert result.status_code==200 and result.json()['status']=='applied'
            assert agent.inventory.get(MAC).status=='blocked'
            assert len(agent.inventory.devices)==1
            # Automatic containment stays gated, and Settings protection is honored.
            loop.apply_policy({**db.get_policy()['policy'],'protected_macs':[MAC]})
            assert agent.request_action('quarantine',MAC,manual=True).evidence['decision']=='protected_device'
    finally:db.close()


def test_grounded_research_never_invents_installed_firmware_or_current_credentials(monkeypatch):
    monkeypatch.setenv('GEMINI_API_KEY','test-key')
    monkeypatch.setenv('GEMINI_MODEL','test-model')
    device={'vendor':'Example','model':'Cam','firmware':None,'default_creds':None,'risk':75,'name':'Private home device'}
    before=copy.deepcopy(device)
    payload={'candidates':[{'finishReason':'STOP','content':{'parts':[{'text':'Firmware Updates: see vendor documentation. Installed firmware is unknown.'}]},
        'groundingMetadata':{'groundingChunks':[{'web':{'uri':'https://example.com/manual','title':'Vendor Manual'}}]}}]}
    class Response:
        def __enter__(self):return self
        def __exit__(self,*_):pass
        def read(self,_):return json.dumps(payload).encode()
    def send(request,timeout):
        body=json.loads(request.data)
        assert body['tools']==[{'google_search':{}}]
        assert 'Private home device' not in request.data.decode()
        return Response()
    monkeypatch.setattr(research.urllib.request,'urlopen',send)
    result=research.lookup(device)
    assert result['status']=='ready' and result['sources']
    assert result['installed_firmware'] is None and result['current_default_credentials'] is None
    assert device==before


def test_research_requires_sources_and_reports_quota_without_exposing_credentials(monkeypatch):
    monkeypatch.setenv('GEMINI_API_KEY','private-key')
    monkeypatch.setenv('GEMINI_MODEL','test-model')
    def fail(*args,**kwargs):raise urllib.error.HTTPError('https://provider',429,'private-key',None,None)
    monkeypatch.setattr(research.urllib.request,'urlopen',fail)
    result=research.lookup({'vendor':'Example','model':'Cam'})
    assert result=={'source':'rules','status':'unavailable','reason':'quota'}
    assert 'private-key' not in json.dumps(result)


def test_research_api_keeps_findings_separate_and_enriches_chat_context(monkeypatch):
    import time
    from jsonschema import Draft202012Validator
    monkeypatch.delenv('GEMINI_API_KEY',raising=False)
    monkeypatch.delenv('GEMINI_MODEL',raising=False)
    db=MemoryDatabase(CONFIG)
    db.ingest(Ingest.model_validate({'devices':[fixture()['devices'][0]],'events':[]}))
    before=copy.deepcopy(db.devices())
    report={'source':'gemini','status':'ready','summary':'Vendor documentation describes updates, but installed firmware is unknown.',
            'sources':[{'url':'https://example.com/manual','title':'Manual'}], 'installed_firmware':None,'current_default_credentials':None}
    monkeypatch.setattr(research,'lookup',lambda device:copy.deepcopy(report))
    try:
        app=create_app(CONFIG,db)
        with TestClient(app) as client:
            login=client.post('/auth/login',json={'username':CONFIG.judge_username,'password':CONFIG.judge_password})
            auth={'Authorization':'Bearer '+login.json()['access_token']}
            assert client.post(f'/advisor/research/{MAC}').status_code==401
            assert client.post(f'/advisor/research/{MAC}',headers=auth).status_code==200
            result={}
            for _ in range(30):
                result=client.get(f'/advisor/research/{MAC}',headers=auth).json()
                if result['status']=='ready':break
                time.sleep(.01)
            assert result['status']=='ready'
            assert db.devices()==before
            enriched=app.state.advisor.enrich(db.devices()[0])
            assert enriched['public_research']['sources']
            view=client.get('/devices',headers=auth).json()[0]
            assert 'public_research' not in view
            schema=json.loads((ROOT/'contract/schemas.json').read_text())
            Draft202012Validator({**schema,'$ref':'#/$defs/DeviceView'}).validate(view)
    finally:db.close()


def test_background_enrichment_names_guests_without_overwriting_records(monkeypatch):
    import time
    from api.advisor import AdvisorService
    from ml.securiot_ml import advisor as ai
    monkeypatch.setattr(ai,'configured',lambda:True)
    monkeypatch.setattr(research,'lookup',lambda d:{'status':'ready','source':'gemini','summary':'Check the official support app.','sources':[]})
    monkeypatch.setattr(ai,'note',lambda device,events:{**ai.fallback(device),'source':'gemini','likely_type':'Android Phone','confidence':'medium','next_step':'Install updates using the phone settings.'})
    service=AdvisorService()
    guest={'mac':MAC,'name':'Guest 00:00:20','type':'unknown','risk':0,'identification':{'label':'Android','confidence':'medium'}}
    original=copy.deepcopy(guest)
    try:
        for _ in range(100):
            result=service.decorate([guest])[0]
            if result['name'].startswith('Possible ') and service.research_status(guest)['status']=='ready':break
            time.sleep(.01)
        assert result['name']=='Possible Android Phone 00:20'
        assert result['identification']['name_source']=='gemini'
        assert result['ai']['next_step']=='Install updates using the phone settings.'
        assert guest==original and result['risk']==0
        named={**guest,'name':'My Guest Phone'}
        for _ in range(100):
            output=service.decorate([named])[0]
            if output['ai']['source']=='gemini':break
            time.sleep(.01)
        assert output['name']=='My Guest Phone'
    finally:service.close()


def test_restore_supersedes_pending_containment_and_warn_never_queues():
    from api.control import ActionRequest
    from uuid import uuid4
    db=MemoryDatabase(CONFIG)
    try:
        db.ingest(Ingest.model_validate({'devices':[fixture()['devices'][0]],'events':[]}))
        block=db.create_command(ActionRequest(action='block_wan',mac=MAC),uuid4())
        db.warn(MAC,'tester')
        assert len(db.sync()['commands'])==1
        restored=db.create_command(ActionRequest(action='restore',mac=MAC),uuid4())
        assert db.command_result(block['id'])['status']=='cancelled'
        assert [c['id'] for c in db.sync()['commands']]==[restored['id']]
    finally:db.close()


def test_live_api_rejects_simulation_and_exposes_authenticated_diagnostics(monkeypatch):
    from dataclasses import replace
    from uuid import uuid4
    from ml.securiot_ml import advisor as ai
    monkeypatch.setattr(ai,'configured',lambda:False)
    config=replace(CONFIG,live_only=True)
    db=MemoryDatabase(config)
    old=fixture()['devices'][0]
    old['simulated']=True
    db.ingest(Ingest.model_validate({'devices':[old],'events':[]}))
    try:
        with TestClient(create_app(config,db)) as client:
            assert client.get('/diagnostics').status_code==401
            login=client.post('/auth/login',json={'username':config.judge_username,'password':config.judge_password})
            auth={'Authorization':'Bearer '+login.json()['access_token']}
            agent={'X-API-Key':config.agent_api_key}
            assert client.get('/dashboard',headers=auth).json()['devices']==[]
            assert client.post('/ingest',headers=agent,json={'devices':[old],'events':[]}).status_code==409
            assert client.post('/actions',headers=auth,json={'action':'quarantine','mac':old['mac']}).status_code==409
            assert client.get('/diagnostics',headers=auth).json()['agent']['connected'] is False
            real={**old,'simulated':False,'name':'Discovered Phone','label':'Discovered Phone','snapshot_at':'2030-01-01T00:00:00Z','last_seen':'2030-01-01T00:00:00Z'}
            assert client.post('/ingest',headers=agent,json={'devices':[real],'events':[]}).status_code==200
            assert client.get('/sync',headers=agent).status_code==200
            status=client.get('/diagnostics',headers=auth).json()
            assert status['agent']['connected'] is True
            assert config.agent_api_key not in json.dumps(status)
            snapshot=client.get('/dashboard',headers=auth)
            assert snapshot.status_code==200 and snapshot.headers.get('ETag')
            assert snapshot.json()['devices'][0]['name']=='Discovered Phone'
            command=client.post('/actions',headers=auth,json={'action':'restore','mac':real['mac']}).json()
            ack={'status':'applied','ts':'2026-11-15T12:00:00Z','detail':'allowed (mock enforcement)'}
            assert client.post('/commands/'+command['id']+'/ack',headers=agent,json=ack).status_code==409
    finally:db.close()


def test_repeated_dashboard_decoration_does_not_repeat_gemini_calls(monkeypatch):
    import time
    from api.advisor import AdvisorService
    from ml.securiot_ml import advisor as ai
    calls=[]
    monkeypatch.setattr(ai,'configured',lambda:True)
    monkeypatch.setattr(research,'lookup',lambda device:{'source':'rules','status':'needs_identity'})
    def note(device,events):
        calls.append(1)
        return {**ai.fallback(device),'source':'gemini'}
    monkeypatch.setattr(ai,'note',note)
    service=AdvisorService()
    device={'mac':MAC,'name':'Guest 00:20','risk':0,'identification':{}}
    try:
        service.decorate([device])
        for _ in range(100):
            if not service.pending:break
            time.sleep(.01)
        for _ in range(30):service.decorate([device])
        assert len(calls)==1
    finally:service.close()
