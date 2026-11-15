"""Direct requests execute on the runtime thread, never the HTTP handler."""
import json
import queue
import threading
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from securiot_agent.direct_control import DirectControl


class Validator:
    def validate(self, value):
        pass


def test_direct_control_auth_execution_and_result():
    calls = []
    result = {'status': 'applied', 'ts': '2026-11-14T12:00:00Z', 'detail': 'live enforcement'}
    cloud = SimpleNamespace(validators={'Command': Validator(), 'Sync': Validator()},
                            state={'commands': {}}, etag='old')
    def sync():
        calls.append(threading.get_ident())
        cloud.state['commands']['demo'] = {'ack': result}
    cloud.sync = sync
    cloud.ack = lambda status, detail: {**result, 'status': status, 'detail': detail}
    service = DirectControl(cloud, 'test-secret', port=0)
    url = f'http://127.0.0.1:{service.server.server_port}/actions'
    def send(key):
        req = urllib.request.Request(url, data=json.dumps({'command': {'id': 'demo'}, 'policy': {}}).encode(),
                                     headers={'X-API-Key': key})
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=5) as response:
            return json.load(response)
    try:
        with pytest.raises(urllib.error.HTTPError) as error:
            send('wrong')
        assert error.value.code == 401
        assert service.pending.empty()
        with ThreadPoolExecutor() as pool:
            future = pool.submit(send, 'test-secret')
            item = service.pending.get(timeout=3)
            assert not calls
            service.pending.put(item)
            service.drain()
            assert future.result() == result
        assert calls == [threading.get_ident()]
        assert cloud.etag == ''
    finally:
        service.close()


def test_cancelled_command_is_not_executed():
    service = DirectControl.__new__(DirectControl)
    service.pending = queue.Queue()
    service.cloud = SimpleNamespace(etag='old', sync=lambda: None, state={'commands': {}},
                                    ack=lambda status, detail: {'status': status, 'detail': detail})
    item = {'body': {'command': {'id': 'cancelled'}}, 'done': threading.Event()}
    service.pending.put(item)
    service.drain()
    assert item['done'].is_set()
    assert item['result']['status'] == 'failed'


def test_sync_outage_does_not_invent_a_failed_firewall_result():
    service = DirectControl.__new__(DirectControl)
    service.pending = queue.Queue()
    def offline():
        raise OSError('offline')
    service.cloud = SimpleNamespace(etag='', sync=offline, state={'commands': {}})
    item = {'body': {'command': {'id': 'pending'}}, 'done': threading.Event()}
    service.pending.put(item)
    service.drain()
    assert item['result'] is None
    assert item['done'].is_set()
