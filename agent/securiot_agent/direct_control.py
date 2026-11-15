"""Authenticated loopback control; runtime mutations stay on the capture thread."""
import hmac
import json
import queue
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class DirectControl:
    def __init__(self, cloud, key, port=18081):
        if not key:
            raise ValueError('Direct control requires an API key')
        self.cloud = cloud
        self.pending = queue.Queue(maxsize=16)
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                if self.path != '/actions':
                    self.send_error(404)
                    return
                if not hmac.compare_digest(self.headers.get('X-API-Key', ''), key):
                    self.send_error(401)
                    return
                try:
                    length = int(self.headers.get('Content-Length', '0'))
                    if not 0 < length <= 65536:
                        raise ValueError('Invalid request size')
                    body = json.loads(self.rfile.read(length))
                    owner.cloud.validators['Command'].validate(body['command'])
                    # Validate policy with the same contract used for cloud sync.
                    owner.cloud.validators['Sync'].validate({
                        'policy': body['policy'], 'commands': [], 'etag': 'direct'})
                    item = {'body': body, 'done': threading.Event(), 'result': None}
                    owner.pending.put_nowait(item)
                except Exception:
                    self.send_error(400, 'Invalid or busy control request')
                    return
                if not item['done'].wait(25):
                    self.send_error(504, 'Outcome pending; inspect the audit log')
                    return
                if item['result'] is None:
                    self.send_error(503, 'Outcome unavailable; inspect the audit log')
                    return
                payload = json.dumps(item['result']).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        self.server = ThreadingHTTPServer(('127.0.0.1', port), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def drain(self):
        try:
            item = self.pending.get_nowait()
        except queue.Empty:
            return
        try:
            body = item['body']
            # Fetch authoritative policy/commands, including cancellations, rather
            # than applying a policy snapshot that may have changed in transit.
            self.cloud.etag = ''
            self.cloud.sync()
            record = self.cloud.state['commands'].get(body['command']['id'])
            item['result'] = record['ack'] if record else self.cloud.ack('failed', 'Command cancelled or unavailable')
        except Exception:
            # A sync failure may occur after an operation. Return only durable
            # results; do not turn a transport failure into a firewall verdict.
            record = self.cloud.state['commands'].get(item['body']['command']['id'])
            item['result'] = record.get('ack') if record else None
        finally:
            item['done'].set()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
