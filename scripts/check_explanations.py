"""Exercise the event API with synthetic data and optional real Gemini generation.

Run from the repository root with the API test dependencies installed:
  PYTHONPATH=.:ml agent/.venv/bin/python scripts/check_explanations.py --live
No configured database, running stack, packets, or real device inventory is used.
"""
import argparse
import json
import os
from pathlib import Path
import secrets
import time
from uuid import uuid4

from fastapi.testclient import TestClient
from jsonschema import Draft202012Validator

from api.main import create_app
from api.settings import Settings, environment
from api.storage import MemoryDatabase
from api.telemetry import Ingest
from ml.securiot_ml.advisor import configured
from ml.securiot_ml.explain import action_summary, template


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--live', action='store_true', help='Send minimal synthetic facts to Gemini using configured credentials')
    args = parser.parse_args()
    if args.live:
        config = environment()
        for key in ('GEMINI_API_KEY', 'GEMINI_MODEL'):
            if config.get(key): os.environ[key] = config[key]
        if not configured():
            raise SystemExit('Configure GEMINI_API_KEY and GEMINI_MODEL in .env or api/.env')
    root = Path(__file__).resolve().parents[1]
    batch = json.loads((root / 'contract/fixtures.json').read_text())
    event = {**batch['events'][1], 'id': str(uuid4())}
    batch['events'] = [event]
    schema = json.loads((root / 'contract/schemas.json').read_text())
    validator = Draft202012Validator({**schema, '$ref': '#/$defs/EventView'})
    settings = Settings('postgresql://unused', secrets.token_urlsafe(48), storage_mode='memory',
                        judge_password=secrets.token_urlsafe(24))
    db = MemoryDatabase(settings)
    db.ingest(Ingest.model_validate(batch))
    app = create_app(settings, db)
    report = {}
    try:
        with TestClient(app) as client:
            app.state.explanations.configured = args.live
            assert client.get('/events').status_code == 401
            login = client.post('/auth/login', json={'username': settings.judge_username, 'password': settings.judge_password})
            assert login.status_code == 200
            headers = {'Authorization': 'Bearer ' + login.json()['access_token']}
            durations = []
            def get():
                start = time.perf_counter()
                response = client.get('/events', headers=headers)
                durations.append((time.perf_counter() - start) * 1000)
                assert response.status_code == 200
                row = response.json()[0]; validator.validate(row)
                assert action_summary(event) in row['explanation']['plain_language']
                return row
            start = time.perf_counter()
            first = get()
            assert first['explanation'] == template(event, batch['devices'][0])
            expected = 'ready' if args.live else 'template'
            row = first
            deadline = start + 12
            while args.live and row['explanation_status'] == 'pending' and time.perf_counter() < deadline:
                time.sleep(.1)
                row = get()
            finished_after_ms = (time.perf_counter() - start) * 1000
            for _ in range(10):
                cached = get()
                assert cached['explanation'] == row['explanation']
            assert client.get('/healthz').status_code == 200
            report = {'live_gemini': args.live, 'initial_status': first['explanation_status'],
                      'final_status': row['explanation_status'], 'http_requests': len(durations),
                      'first_response_ms': round(durations[0], 2), 'slowest_response_ms': round(max(durations), 2),
                      'generation_observed_after_ms': round(finished_after_ms, 2),
                      'schema_valid': True, 'action_wording_valid': True,
                      'cached_result_stable': True, 'health_ok': True,
                      'explanation': row['explanation']}
            print(json.dumps(report, indent=2))
            assert max(durations) < 1000, 'The local events API exceeded the 1-second smoke-test limit'
            assert row['explanation_status'] == expected, 'Gemini was unavailable or its output failed validation; template remained available'
    finally:
        db.close()


if __name__ == '__main__':
    main()
