import copy
import json

import pytest

from securiot_ml import advisor as ai

D = {'mac': 'aa:bb:cc:dd:ee:01', 'ip': '10.42.0.9', 'type': 'camera', 'risk': 70,
     'band': 'high', 'reasons': ['Telnet open'], 'ports': [23], 'default_creds': True}
REPLY = {'assessment': 'Default credentials and Telnet increase exposure.', 'likely_type': 'camera',
         'expected_behavior': 'A camera usually streams video to configured clients.',
         'top_risk': 'Default credentials', 'next_step': 'Change the password.',
         'confidence': 'high', 'delta': 3, 'delta_reason': 'Combined exposure increases urgency.'}


@pytest.mark.parametrize('delta,risk,confidence,expected', [
    (500, 70, 'high', 80), (-500, 70, 'high', 60),
    (10, 98, 'high', 100), (-10, 2, 'high', 0), (8, 70, 'low', 70),
])
def test_adjustment_bounds(monkeypatch, delta, risk, confidence, expected):
    monkeypatch.setattr(ai, '_gemini', lambda *a: {**REPLY, 'delta': delta, 'confidence': confidence})
    device = {**D, 'risk': risk}
    before = copy.deepcopy(device)
    note = ai.note(device)
    assert note['source'] == 'gemini'
    assert -10 <= note['delta'] <= 10
    assert note['risk_adjusted'] == expected
    assert device == before


@pytest.mark.parametrize('change', [
    {'delta': '3'}, {'delta': True}, {'delta': 1.5}, {'confidence': 'certain'},
    {'assessment': 42}, {'assessment': 'word ' * 41}, {'next_step': ''}, {'extra': 'unexpected'},
])
def test_invalid_output_falls_back(monkeypatch, change):
    monkeypatch.setattr(ai, '_gemini', lambda *a: {**REPLY, **change})
    result = ai.note(D)
    assert result['source'] == 'rules' and result['risk_adjusted'] == 70
    assert result['next_step']


def test_known_type_is_preserved_and_unknown_type_is_only_a_guess(monkeypatch):
    monkeypatch.setattr(ai, '_gemini', lambda *a: {**REPLY, 'likely_type': 'speaker'})
    assert ai.note(D)['likely_type'] == 'camera'
    device = {**D, 'type': 'unknown'}
    assert ai.note(device)['likely_type'] == 'speaker'
    assert device['type'] == 'unknown'


def test_privacy_allowlist_and_cache_stability():
    device = {**D, 'dests': ['8.8.8.8'], 'name': 'camera 10.42.0.9 aa:bb:cc:dd:ee:01',
              'vendor': '2001:db8::1', 'banner': 'secret', 'dns_names': ['private.example'],
              'reasons': ['Talked to 8.8.8.8']}
    events = [{'kind': 'decoy_touch', 'evidence': {'ip': '10.42.0.9'}}]
    text = json.dumps(ai.facts(device, events))
    for secret in ('10.42.0.9', 'aa:bb:cc:dd:ee:01', '8.8.8.8', '2001:db8::1', 'private.example', 'secret'):
        assert secret not in text
    assert 'decoy_touch' in text
    assert ai.cache_key(device, events) == ai.cache_key({**device, 'last_seen': 'later', 'bytes_in': 999}, events)
    assert ai.cache_key(device) != ai.cache_key(device, events)
    assert ai.cache_key(device) != ai.cache_key({**device, 'ports': [23, 80]})


def test_offline_fallbacks_and_chat_privacy(monkeypatch):
    sent = []
    def offline(system, payload, *args):
        sent.append(payload)
        raise OSError('offline')
    monkeypatch.setattr(ai, '_gemini', offline)
    assert ai.note(D)['risk_adjusted'] == 70
    result = ai.chat(D, [{'role': 'user', 'text': '10.42.0.9'}], 'What about aa:bb:cc:dd:ee:01?')
    assert result['source'] == 'rules' and 'Telnet open' in result['answer']
    assert '10.42.0.9' not in json.dumps(sent[-1])
    assert 'aa:bb:cc:dd:ee:01' not in json.dumps(sent[-1])
    assert ai.triage([D])['order'][0]['mac'] == D['mac']


def test_triage_sends_highest_twelve_and_keeps_every_device(monkeypatch):
    devices = [{**D, 'mac': f'02:00:00:00:00:{i:02x}', 'risk': i * 5} for i in range(15)]
    def ranking(system, payload, schema):
        assert len(payload) == 12 and payload[0]['risk'] == 70
        assert 'mac' not in json.dumps(payload)
        return {'order': [{'id': p['id'], 'why': 'Review this device.'} for p in payload]}
    monkeypatch.setattr(ai, '_gemini', ranking)
    result = ai.triage(devices)
    assert result['source'] == 'gemini'
    assert len(result['order']) == 15
    assert {r['mac'] for r in result['order']} == {d['mac'] for d in devices}
    assert result['order'][0]['mac'] == devices[-1]['mac']


@pytest.mark.parametrize('order', [[{'id': 'invented', 'why': 'x'}], [],
                                  [{'id': 'd0', 'why': 'x'}, {'id': 'd0', 'why': 'x'}]])
def test_bad_triage_ids_fall_back(monkeypatch, order):
    monkeypatch.setattr(ai, '_gemini', lambda *a: {'order': order})
    assert ai.triage([D])['source'] == 'rules'


def test_transport_uses_schema_header_and_rejects_partial_output(monkeypatch):
    monkeypatch.setenv('GEMINI_API_KEY', 'test-key')
    monkeypatch.setenv('GEMINI_MODEL', 'test-model')
    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self, limit):
            return json.dumps({'candidates': [{'finishReason': 'MAX_TOKENS',
                                               'content': {'parts': [{'text': json.dumps(REPLY)}]}}]}).encode()
    def urlopen(request, timeout):
        assert 'test-key' not in request.full_url
        assert request.get_header('X-goog-api-key') == 'test-key'
        assert json.loads(request.data)['generationConfig']['responseJsonSchema'] == ai.NOTE_SCHEMA
        assert timeout == 8
        return Response()
    monkeypatch.setattr(ai.urllib.request, 'urlopen', urlopen)
    assert ai.note(D)['source'] == 'rules'
