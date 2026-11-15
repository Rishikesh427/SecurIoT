import json
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

import pytest
from ml.securiot_ml import usage_guard as guard


def request(text='one'):
    return urllib.request.Request('https://example.test/models/example:generateContent',
        json.dumps({'text':text}).encode(),{'x-goog-api-key':'secret-test-key'})


def response():
    class Response:
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def read(self,size):return json.dumps({'candidates':[{'finishReason':'STOP','content':{'parts':[{'text':'OK'}]}}]}).encode()
    return Response()


def test_cache_survives_new_connections_and_counts_only_real_attempts(monkeypatch):
    calls=[]
    monkeypatch.setattr(guard.urllib.request,'urlopen',lambda *a,**k:(calls.append(1) or response()))
    assert guard.request_json(request(),timeout=1)==guard.request_json(request(),timeout=1)
    assert len(calls)==1 and guard.status()['attempts_today']==1
    assert 'secret-test-key' not in json.dumps(guard.status())


def test_daily_limit_is_shared_and_atomic_under_concurrency(monkeypatch):
    monkeypatch.setenv('GEMINI_DAILY_REQUEST_LIMIT','3')
    calls=[]
    monkeypatch.setattr(guard.urllib.request,'urlopen',lambda *a,**k:(calls.append(1) or response()))
    def run(i):
        try:guard.request_json(request(str(i)),timeout=1);return 'sent'
        except guard.BudgetBlocked as e:return e.reason
    with ThreadPoolExecutor(max_workers=8) as pool:results=list(pool.map(run,range(12)))
    assert results.count('sent')==3 and results.count('daily_request_limit')==9
    assert len(calls)==3 and guard.status()['attempts_today']==3


def test_quota_pause_persists_and_cached_answers_remain_available(monkeypatch):
    now=[1000000.]
    monkeypatch.setattr(guard.time,'time',lambda:now[0])
    monkeypatch.setattr(guard.urllib.request,'urlopen',lambda *a,**k:response())
    cached=guard.request_json(request('cached'),timeout=1)
    calls=[]
    def quota(*args,**kwargs):
        calls.append(1)
        raise urllib.error.HTTPError('https://example.test',429,'private provider body',{},None)
    monkeypatch.setattr(guard.urllib.request,'urlopen',quota)
    with pytest.raises(urllib.error.HTTPError):guard.request_json(request('quota'),timeout=1)
    with pytest.raises(guard.BudgetBlocked,match='quota_paused'):guard.request_json(request('different'),timeout=1)
    assert guard.request_json(request('cached'),timeout=1)==cached
    assert len(calls)==1 and guard.status()['attempts_today']==2
    now[0]+=86401
    monkeypatch.setattr(guard.urllib.request,'urlopen',lambda *a,**k:response())
    guard.request_json(request('different'),timeout=1)
    assert guard.status()['attempts_today']==1


def test_failures_count_zero_cap_and_storage_fail_closed(monkeypatch,tmp_path):
    def network(*a,**k):raise urllib.error.URLError('offline')
    monkeypatch.setattr(guard.urllib.request,'urlopen',network)
    with pytest.raises(urllib.error.URLError):guard.request_json(request(),timeout=1)
    assert guard.status()['attempts_today']==1
    monkeypatch.setenv('GEMINI_DAILY_REQUEST_LIMIT','0')
    with pytest.raises(guard.BudgetBlocked,match='daily_request_limit'):guard.request_json(request('other'),timeout=1)
    path=tmp_path/'file';path.write_text('not a directory')
    monkeypatch.setenv('GEMINI_STATE_PATH',str(path/'blocked.sqlite3'))
    with pytest.raises(guard.BudgetBlocked,match='usage_state_unavailable'):guard.request_json(request(),timeout=1)


def test_all_gemini_features_share_the_transport_and_budget(monkeypatch):
    from ml.securiot_ml import advisor, gemini, research
    monkeypatch.setenv('GEMINI_API_KEY','test-key')
    monkeypatch.setenv('GEMINI_MODEL','test-model')
    monkeypatch.setenv('GEMINI_DAILY_REQUEST_LIMIT','1')
    calls=[]
    monkeypatch.setattr(guard.urllib.request,'urlopen',lambda *a,**k:(calls.append(1) or response()))
    assert advisor._gemini('test',{})=='OK'
    with pytest.raises(guard.BudgetBlocked,match='daily_request_limit'):gemini.generate('explain',{}, {})
    assert research.lookup({'vendor':'Example'})['reason']=='daily_request_limit'
    assert len(calls)==1
