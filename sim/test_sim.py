import json
import unittest
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from sim.sim import build_batches, ingest_url, post_batch


class SimulationTests(unittest.TestCase):
    def test_payloads_match_api_contract(self):
        try:
            from api.telemetry import Ingest
        except ImportError:
            self.skipTest('Install API dependencies to check the API models')
        for _, batch in build_batches():
            Ingest.model_validate(batch)

    def test_batches_are_fresh_and_non_enforcing(self):
        batches = build_batches(datetime(2026, 11, 14, tzinfo=timezone.utc))
        events = [event for _, batch in batches for event in batch['events']]
        self.assertEqual(len(events), 5)
        self.assertEqual(len({e['id'] for e in events}), 5)
        for e in events:
            self.assertEqual(e['source'], 'simulator')
            self.assertEqual(e['actions_taken'], [])
        self.assertEqual(events[-1]['would_have'], ['block_wan', 'quarantine'])
        for _, batch in batches:
            self.assertTrue(all(d['simulated'] and d['status'] == 'normal' for d in batch['devices']))
        self.assertNotEqual(events[0]['id'], build_batches()[0][1]['events'][0]['id'])

    def test_url(self):
        self.assertEqual(ingest_url('http://localhost'), 'http://localhost/api/ingest')
        self.assertEqual(ingest_url('http://localhost:8080/api/'), 'http://localhost:8080/api/ingest')
        with self.assertRaises(ValueError):
            ingest_url('https://user:secret@example.com')

    def test_real_http_transport(self):
        received = []
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def do_POST(self):
                received.append((self.path, self.headers.get('X-API-Key'), json.loads(self.rfile.read(int(self.headers['Content-Length'])))))
                self.send_response(200)
                self.send_header('X-Storage-Mode', 'memory')
                self.end_headers()
                self.wfile.write(b'{"accepted_devices":3,"accepted_events":2}')
        server = HTTPServer(('127.0.0.1', 0), Handler)
        thread = Thread(target=server.serve_forever, daemon=True); thread.start()
        try:
            batch = build_batches()[0][1]
            result, mode = post_batch(f'http://127.0.0.1:{server.server_port}/api/ingest', 'test-only', batch)
            self.assertEqual(received, [('/api/ingest', 'test-only', batch)])
            self.assertEqual(mode, 'memory')
            self.assertEqual(result['accepted_events'], 2)
        finally:
            server.shutdown(); server.server_close(); thread.join()


if __name__ == '__main__':
    unittest.main()
