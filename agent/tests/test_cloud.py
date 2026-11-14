"""Cloud skeleton against B's real HTTP routes with an in-memory test database."""
import copy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "agent"), str(ROOT)]

from fastapi import FastAPI
from fastapi.testclient import TestClient
from api.telemetry import router
from securiot_agent.cloud import CloudClient, CloudError
from securiot_agent.cloud_loop import CloudLoop, atomic_json
from securiot_agent.replay import load_devices, replay_capture
from securiot_agent.storage import Storage

MAC = "02:00:00:00:00:20"
SCHEMA = ROOT / "contract/schemas.json"


class TestDatabase:
    __test__ = False
    def __init__(self):
        self.event_rows, self.device_rows, self.acks = {}, {}, {}
        self.pending = []
        self.revision = "revision-1"
        self.policy = {"learning_mode": False, "protected_macs": [],
                       "ladder": {"notify": True, "block_wan": True, "quarantine": True}}

    def ingest(self, body):
        devices = events = 0
        for item in body.devices:
            row = item.model_dump(mode="json")
            old = self.device_rows.get(row["mac"])
            if old is None or row["last_seen"] > old["last_seen"]:
                self.device_rows[row["mac"]] = row
                devices += 1
        for item in body.events:
            row = item.model_dump(mode="json")
            if row["id"] in self.event_rows:
                assert self.event_rows[row["id"]] == row
            else:
                self.event_rows[row["id"]] = row
                events += 1
        return {"accepted_devices": devices, "accepted_events": events}

    def sync(self):
        return {"etag": self.revision, "policy": self.policy,
                "commands": [c for c in self.pending if c["id"] not in self.acks]}

    def ack(self, identifier, body):
        key, value = str(identifier), body.model_dump(mode="json")
        if key in self.acks:
            assert self.acks[key] == value
        self.acks[key] = value

    def devices(self):
        return list(self.device_rows.values())

    def events(self, limit, offset):
        return list(self.event_rows.values())[offset:offset + limit]


class RouteClient:
    def __init__(self, client):
        self.client = client
        self.identity = "test-api"
        self.offline = False
        self.lose_ingest_reply = False
        self.lose_ack_reply = False
        self.batches = []

    def request(self, method, path, payload=None, query=None):
        if self.offline:
            raise CloudError("offline test")
        if path == "/ingest":
            self.batches.append(copy.deepcopy(payload))
        result = self.client.request(method, path, json=payload, params=query,
                                     headers={"X-API-Key": "test-key"})
        if path == "/ingest" and self.lose_ingest_reply:
            self.lose_ingest_reply = False
            raise CloudError("accepted, but response lost")
        if path.endswith("/ack") and self.lose_ack_reply:
            self.lose_ack_reply = False
            raise CloudError("ack accepted, but response lost")
        if result.status_code not in (200, 204, 304):
            raise CloudError(f"HTTP {result.status_code}")
        return result.status_code, result.json() if result.status_code == 200 else None


class CloudTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.storage = Storage(Path(self.temp.name))
        self.agent = replay_capture(
            ROOT / "agent/fixtures/arp_scan.pcap", load_devices(ROOT / "agent/fixtures/devices.json"),
            self.storage, armed=True, detector="ml").agent
        self.db = TestDatabase()
        app = FastAPI()
        app.state.settings = SimpleNamespace(agent_api_key="test-key")
        app.state.db = self.db
        app.include_router(router(lambda: {"username": "test"}))
        self.http = TestClient(app)
        self.addCleanup(self.http.close)
        self.client = RouteClient(self.http)
        self.loop = CloudLoop(self.agent, self.client, SCHEMA, permit_arm=True)

    def restore_command(self):
        command = {"id": str(uuid4()), "created_at": "2026-11-14T12:00:00Z",
                   "action": "restore", "mac": MAC}
        self.db.pending.append(command)
        return command

    def test_actual_api_accepts_wire_records_and_restore_roundtrip(self):
        self.assertEqual(self.loop.tick(), [])
        # The ML detector may report one scan twice (early alert, then the 30-ARP rule).
        self.assertGreaterEqual(len(self.db.event_rows), 1)
        event = next(iter(self.db.event_rows.values()))
        self.assertEqual(event["kind"], "scan_arp")
        self.assertEqual(event["source"], "simulator")
        self.assertTrue(event["evidence"]["simulated"])
        self.assertEqual(self.http.get("/devices").json()[0]["status"], "quarantined")
        self.agent.clock.advance(2)
        command = self.restore_command()
        self.assertEqual(self.loop.tick(), [])
        self.assertEqual(self.db.acks[command["id"]]["status"], "applied")
        self.assertEqual(self.agent.inventory.get(MAC).status, "normal")
        self.assertEqual(self.db.device_rows[MAC]["status"], "normal")
        self.assertEqual(self.db.sync()["commands"], [])

    def test_lost_ingest_reply_retries_identical_payload_across_restart(self):
        self.client.lose_ingest_reply = True
        self.assertTrue(self.loop.tick())
        frozen = copy.deepcopy(self.loop.state["pending_batch"])
        stored = len(self.db.event_rows)
        self.assertGreaterEqual(stored, 1)
        self.agent.clock.advance(2)
        restarted = CloudLoop(self.agent, self.client, SCHEMA, permit_arm=True)
        self.assertEqual(restarted.tick(), [])
        self.assertEqual(self.client.batches[0], self.client.batches[1])
        self.assertEqual(frozen["payload"], self.client.batches[1])
        self.assertEqual(len(self.db.event_rows), stored)
        self.assertIsNone(restarted.state["pending_batch"])

    def test_offline_events_are_preserved_and_delivered_after_reconnect(self):
        self.client.offline = True
        self.assertTrue(self.loop.tick())
        self.assertEqual(len(self.db.event_rows), 0)
        self.assertEqual(self.loop.state["cursor"], 0)
        self.client.offline = False
        self.assertEqual(self.loop.tick(), [])
        self.assertGreaterEqual(len(self.db.event_rows), 1)
        self.assertGreater(self.loop.state["cursor"], 0)

    def test_ack_retry_does_not_repeat_restore_or_extend_grace(self):
        self.loop.tick()
        self.agent.clock.advance(2)
        command = self.restore_command()
        self.client.lose_ack_reply = True
        self.assertTrue(self.loop.tick())
        grace = self.agent.grace_until[MAC]
        calls = list(self.agent.enforcer.calls)
        self.agent.clock.advance(2)
        restarted = CloudLoop(self.agent, self.client, SCHEMA, permit_arm=True)
        self.assertEqual(restarted.tick(), [])
        self.assertEqual(self.agent.enforcer.calls, calls)
        self.assertEqual(self.agent.grace_until[MAC], grace)
        self.assertTrue(restarted.state["commands"][command["id"]]["sent"])

    def test_interrupted_command_fails_closed_instead_of_reexecuting(self):
        command = self.restore_command()
        import hashlib
        fingerprint = hashlib.sha256(json.dumps(command, sort_keys=True).encode()).hexdigest()
        self.loop.state["commands"][command["id"]] = {"fingerprint": fingerprint, "ack": None, "sent": False}
        self.loop.save()
        restarted = CloudLoop(self.agent, self.client, SCHEMA, permit_arm=True)
        restarted.tick()
        self.assertEqual(self.db.acks[command["id"]]["status"], "failed")
        self.assertEqual(self.agent.inventory.get(MAC).status, "quarantined")

    def test_cloud_policy_cannot_arm_without_local_permission_or_remove_local_protection(self):
        guarded = CloudLoop(self.agent, self.client, SCHEMA, permit_arm=False)
        guarded.tick()
        self.assertTrue(self.agent.policy.learning_mode)
        self.assertTrue(self.agent.inventory.get("02:00:00:00:00:02").protected)
        self.db.policy["ladder"]["quarantine"] = False
        self.db.revision = "revision-2"
        guarded.tick()
        self.assertEqual(self.agent.request_action("quarantine", MAC).evidence["decision"], "disabled_by_policy")

    def test_unknown_devices_are_failed_not_enforced(self):
        command = self.restore_command()
        command["mac"] = "02:00:00:00:00:99"
        self.loop.tick()
        self.assertEqual(self.db.acks[command["id"]]["status"], "failed")

    def test_http_transport_and_actual_authentication(self):
        parent = self
        class Handler(BaseHTTPRequestHandler):
            def forward(self):
                data = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                response = parent.http.request(self.command, self.path, content=data,
                    headers={"X-API-Key": self.headers.get("X-API-Key", ""), "Content-Type": "application/json"})
                self.send_response(response.status_code)
                self.end_headers()
                self.wfile.write(response.content)
            do_GET = forward
            do_POST = forward
            def log_message(self, *args):
                pass
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_port}"
            self.assertEqual(CloudClient(url, "test-key").request("GET", "/sync")[0], 200)
            with self.assertRaisesRegex(CloudError, "401"):
                CloudClient(url, "wrong-key").request("GET", "/sync")
            from securiot_agent.runner import run_connected
            result = run_connected(ROOT / "agent/fixtures/arp_scan.pcap",
                ROOT / "agent/fixtures/devices.json", Path(self.temp.name) / "runner",
                url, "test-key", armed=True, once=True, model_mode="rules")
            self.assertEqual(result.agent.inventory.get(MAC).status, "quarantined")
            self.assertGreaterEqual(len(self.db.event_rows), 1)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_transport_rejects_insecure_remote_urls_and_embedded_credentials(self):
        for url in ("http://example.com", "https://user:secret@example.com", "https://example.com?token=secret"):
            with self.assertRaises(ValueError):
                CloudClient(url, "key")

    def test_malformed_policy_does_not_change_runtime_safety(self):
        original = self.agent.policy.learning_mode
        self.db.policy["learning_mode"] = "false"
        errors = self.loop.tick()
        self.assertTrue(errors)
        self.assertEqual(self.agent.policy.learning_mode, original)

    def test_journal_cannot_be_reused_with_another_cloud(self):
        self.client.identity = "different-api"
        with self.assertRaisesRegex(ValueError, "another API"):
            CloudLoop(self.agent, self.client, SCHEMA)

    def test_conflicting_command_uuid_is_rejected_without_repeat_execution(self):
        command = self.restore_command()
        self.loop.tick()
        calls = list(self.agent.enforcer.calls)
        with self.assertRaisesRegex(ValueError, "UUID reused"):
            self.loop.command({**command, "action": "quarantine"})
        self.assertEqual(calls, self.agent.enforcer.calls)

    def test_invalid_ingest_ack_does_not_advance_cursor(self):
        original = self.client.request
        def invalid(method, path, payload=None, query=None):
            if path == "/ingest":
                return 200, {"accepted_events": 999999, "accepted_devices": 999999}
            return original(method, path, payload, query)
        self.client.request = invalid
        self.assertTrue(self.loop.tick())
        self.assertEqual(self.loop.state["cursor"], 0)
        self.assertIsNotNone(self.loop.state["pending_batch"])

    def test_unknown_action_in_cloud_batch_cannot_reach_enforcer(self):
        command = self.restore_command()
        command["action"] = "run_shell"
        calls = list(self.agent.enforcer.calls)
        self.assertTrue(self.loop.tick())
        self.assertEqual(calls, self.agent.enforcer.calls)

    def test_invalid_model_adapter_is_not_silently_replaced_by_rules(self):
        with self.assertRaisesRegex(ValueError, "Detector adapter"):
            replay_capture(ROOT / "agent/fixtures/arp_scan.pcap",
                load_devices(ROOT / "agent/fixtures/devices.json"), Storage(Path(self.temp.name) / "bad-model"),
                detector="ml", detector_factory=lambda **kwargs: object())

    def test_malformed_command_timestamp_is_rejected_before_action(self):
        command = self.restore_command()
        command["created_at"] = "tomorrow"
        calls = list(self.agent.enforcer.calls)
        self.assertTrue(self.loop.tick())
        self.assertEqual(self.agent.enforcer.calls, calls)

    def test_redelivered_acknowledged_command_reuses_exact_ack_without_reexecution(self):
        command = self.restore_command()
        self.loop.tick()
        old_ack = copy.deepcopy(self.db.acks[command["id"]])
        calls = list(self.agent.enforcer.calls)
        self.loop.command(command)
        self.loop.send_acks()
        self.assertEqual(old_ack, self.db.acks[command["id"]])
        self.assertEqual(calls, self.agent.enforcer.calls)
