"""Upload labelled fixtures and scripted events; never scan or control devices."""
import argparse
import copy
import json
import math
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]


def build_batches(start=None, interval=3):
    """Fresh UUIDs per run; caller retains these exact batches for retries."""
    start = start or datetime.now(timezone.utc)
    data = json.loads((ROOT / 'contract/fixtures.json').read_text(encoding='utf-8'))
    data = copy.deepcopy(data)
    for device in data['devices']:
        device.update(last_seen=start.isoformat(), simulated=True, has_feed=False, status='normal')
    # Preserve fixture evidence, but make timestamps and event IDs fresh.
    for event in data['events']:
        event.update(id=str(uuid4()), ts=start.isoformat(), source='simulator')
        event['evidence']['simulated'] = True
        event['actions_taken'] = []
    batches = [('Fixture inventory and events', data)]
    mac = data['devices'][0]['mac']
    steps = [
        ('scan_arp', {'arp_targets': 12}, []),
        ('scan_targets', {'syn_targets': 20, 'destination_ports': [23, 80, 2323]}, []),
        ('decoy_touch', {'destination_ip': '10.42.0.50', 'destination_port': 23}, ['block_wan', 'quarantine']),
    ]
    for index, (kind, evidence, would_have) in enumerate(steps, 1):
        ts = (start + timedelta(seconds=interval * index)).isoformat()
        device = copy.deepcopy(data['devices'][0])
        device['last_seen'] = ts
        event = {'id': str(uuid4()), 'mac': mac, 'ts': ts, 'kind': kind,
                 'evidence': {**evidence, 'simulated': True, 'scripted': True, 'learning_mode': True},
                 'actions_taken': [], 'would_have': would_have, 'source': 'simulator'}
        batches.append((kind, {'devices': [device], 'events': [event]}))
    return batches


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # Never forward the agent credential to a redirect target.


def ingest_url(base):
    parsed = urlsplit(base)
    if parsed.scheme not in ('http', 'https') or not parsed.netloc or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError('URL must be an HTTP(S) origin or API base without credentials, query, or fragment')
    base = base.rstrip('/')
    return base + ('/ingest' if parsed.path.rstrip('/').endswith('/api') else '/api/ingest')


def post_batch(url, key, batch, opener=None):
    body = json.dumps(batch).encode('utf-8')
    request = Request(url, body, {'Content-Type': 'application/json', 'X-API-Key': key}, method='POST')
    opener = opener or build_opener(NoRedirect())
    try:
        with opener.open(request, timeout=15) as response:
            result = json.load(response)
            mode = response.headers.get('X-Storage-Mode', 'unknown')
    except HTTPError as exc:
        hints = {401: 'Check AGENT_API_KEY against the API configuration.',
                 409: 'Event ID conflict. Do not change a previously uploaded event.',
                 422: 'The API rejected the payload schema.',
                 503: 'Storage may have switched; the write outcome is uncertain. Check /api/storage before rerunning.'}
        raise RuntimeError(f'HTTP {exc.code}. {hints.get(exc.code, "Check the API URL and server logs.")}') from None
    except (URLError, TimeoutError, OSError, ValueError):
        raise RuntimeError('No valid API response. Check the server and URL. The upload outcome may be uncertain.') from None
    if not isinstance(result, dict) or not all(isinstance(result.get(k), int) for k in ('accepted_devices', 'accepted_events')):
        raise RuntimeError('Unexpected ingest response; check the API URL.')
    return result, mode


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', default='http://localhost', help='Origin or API base, e.g. http://localhost:8080/api')
    parser.add_argument('--interval', type=float, default=3, help='Seconds between steps (0 to 60)')
    parser.add_argument('--dry-run', action='store_true', help='Print batches without credentials or network requests')
    args = parser.parse_args(argv)
    if not math.isfinite(args.interval) or not 0 <= args.interval <= 60:
        parser.error('--interval must be between 0 and 60')
    try:
        url = ingest_url(args.url)
        batches = build_batches(interval=args.interval)
        if args.dry_run:
            print(json.dumps([{'step': title, **batch} for title, batch in batches], indent=2))
            return 0
        from dotenv import dotenv_values
        key = os.environ.get('AGENT_API_KEY', dotenv_values(ROOT / 'api/.env').get('AGENT_API_KEY', ''))
        if not key or key.startswith('GENERATE_'):
            raise RuntimeError('Set AGENT_API_KEY in api/.env or the process environment.')
        for index, (title, batch) in enumerate(batches):
            if index:
                time.sleep(args.interval)
                now = datetime.now(timezone.utc).isoformat()
                for device in batch['devices']:
                    device['last_seen'] = now
                for event in batch['events']:
                    event['ts'] = now
            result, mode = post_batch(url, key, batch)
            print(f'{title}: devices={result["accepted_devices"]}, events={result["accepted_events"]}, storage={mode}')
        print('Simulation complete. Refresh the dashboard. No network scans or device actions were performed.')
        return 0
    except (RuntimeError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except ImportError:
        print('Install dependencies: python -m pip install -r sim/requirements.txt', file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print('Stopped. Previously uploaded simulated reports remain in storage.', file=sys.stderr)
        return 130


if __name__ == '__main__':
    raise SystemExit(main())
