"""Readiness/auth/transport smoke check; no fixture rows or commands are created.

From the repo root: python -m scripts.check_platform --url http://localhost:8080
"""
import argparse
from uuid import uuid4

import httpx

from api.settings import environment


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', default='http://localhost:8080')
    args = parser.parse_args()
    env = environment()
    agent_headers = {'X-API-Key': env['AGENT_API_KEY']}
    with httpx.Client(base_url=args.url.rstrip('/') + '/api/', timeout=20) as client:
        assert client.get('readyz').status_code == 200, 'Readiness failed'
        storage = client.get('storage')
        assert storage.status_code == 200 and storage.json()['mode'] in ('postgres','memory'), 'Storage status failed'
        assert storage.headers['X-Storage-Mode'] == storage.json()['mode'], 'Storage badge metadata missing'
        response = client.post('auth/login', json={'username': env.get('JUDGE_USERNAME', 'judge'), 'password': env['JUDGE_PASSWORD']})
        assert response.status_code == 200, 'Judge login failed'
        jwt_headers = {'Authorization': 'Bearer ' + response.json()['access_token']}
        assert client.get('policy').status_code == 401, 'Anonymous policy read allowed'
        assert client.post('actions',json={'action':'restore_all'}).status_code == 401, 'Anonymous action allowed'
        policy = client.get('policy',headers=jwt_headers)
        assert policy.status_code == 200 and 'etag' in policy.headers, 'Policy read failed'
        for path in ('devices', 'events'):
            assert client.get(path).status_code == 401, 'Anonymous read allowed'
            result = client.get(path, headers=jwt_headers)
            assert result.status_code == 200 and isinstance(result.json(), list), path + ' failed'
        assert client.get('sync').status_code == 401, 'Anonymous sync allowed'
        sync = client.get('sync', headers=agent_headers)
        assert sync.status_code == 200, 'Sync failed'
        body = sync.json()
        cached = client.get('sync', params={'etag':body['etag']}, headers=agent_headers)
        assert cached.status_code == (200 if body['commands'] else 304), 'Conditional sync failed'
        empty = client.post('ingest', json={'devices':[], 'events':[]}, headers=agent_headers)
        assert empty.status_code == 200 and empty.json() == {'accepted_devices':0, 'accepted_events':0}, 'Empty ingest failed'
        missing = client.post(f'commands/{uuid4()}/ack', headers=agent_headers,
                              json={'status':'failed', 'ts':'2026-11-14T00:00:00Z'})
        assert missing.status_code == 404, 'Unknown command acknowledgement failed'
    print('PASS: storage badge, readiness, judge login, policy, action authentication, reads, agent auth, conditional sync, ingest, and ack routing.')


if __name__ == '__main__':
    main()
