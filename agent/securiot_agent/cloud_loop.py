"""Single-writer delivery and command journal for the mock agent runner."""
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
from datetime import datetime, timezone

from jsonschema import Draft202012Validator, FormatChecker, ValidationError

from .cloud import CloudError
from .models import normalize_mac
from .wire import device_record, event_record


def atomic_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, delete=False) as output:
            temporary = Path(output.name)
            json.dump(value, output, allow_nan=False)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


class CloudLoop:
    def __init__(self, agent, client, schema_path, *, permit_arm=False):
        self.agent, self.client, self.permit_arm = agent, client, permit_arm
        schema = json.loads(Path(schema_path).read_text())
        self.validators = {
            kind: Draft202012Validator({**schema, "$ref": f"#/$defs/{kind}"}, format_checker=FormatChecker())
            for kind in ("Ingest", "Sync", "Command", "Ack")
        }
        if len(agent.inventory.devices) > 1000:
            raise ValueError("This skeleton supports at most 1000 configured devices")
        self.path = agent.storage.directory / "cloud.json"
        identity = hashlib.sha256(client.identity.encode()).hexdigest()
        self.state = json.loads(self.path.read_text()) if self.path.exists() else {
            "version": 1, "cursor": 0, "pending_batch": None, "commands": {}, "endpoint": identity}
        if (self.state.get("version") != 1 or type(self.state.get("cursor")) is not int
                or self.state["cursor"] < 0 or not isinstance(self.state.get("commands"), dict)):
            raise ValueError("Invalid cloud journal")
        if self.state.get("endpoint") != identity:
            raise ValueError("Cloud journal belongs to another API; use a separate state directory")
        pending = self.state.get("pending_batch")
        if pending is not None:
            if not isinstance(pending, dict) or type(pending.get("stop")) is not int or pending["stop"] < self.state["cursor"]:
                raise ValueError("Invalid pending ingest journal")
            self.validators["Ingest"].validate(pending["payload"])
        self.etag = ""  # Fetch full policy again after every process restart.
        self.remote_protected = set()
        self.local_protected = {d.mac for d in agent.inventory.devices.values() if d.protected}
        # Never retry an action that might have executed before a process crash.
        for identifier, record in self.state["commands"].items():
            from uuid import UUID
            UUID(identifier)
            if not isinstance(record, dict) or type(record.get("sent")) is not bool or not isinstance(record.get("fingerprint"), str):
                raise ValueError("Invalid command journal")
            if record.get("ack") is not None:
                self.validators["Ack"].validate(record["ack"])
            if record.get("ack") is None:
                record["ack"] = self.ack("failed", "Interrupted action; outcome uncertain, manual review required")
        self.save()

    def save(self):
        atomic_json(self.path, self.state)

    def ack(self, status, detail):
        return {"status": status, "ts": datetime.fromtimestamp(self.agent.clock(), timezone.utc).isoformat(),
                "detail": detail + (" (mock enforcement)" if self.agent.enforcer.simulated else " (live enforcement)")}

    def apply_policy(self, policy):
        self.remote_protected = {normalize_mac(mac) for mac in policy["protected_macs"]}
        protected = self.local_protected | self.remote_protected
        for device in self.agent.inventory.devices.values():
            device.protected = device.mac in protected
        self.agent.policy.learning_mode = policy["learning_mode"] or not self.permit_arm
        self.agent.ladder = dict(policy["ladder"])

    def command(self, command):
        self.validators["Command"].validate(command)
        identifier = command["id"]
        fingerprint = hashlib.sha256(json.dumps(command, sort_keys=True).encode()).hexdigest()
        existing = self.state["commands"].get(identifier)
        if existing:
            if existing["fingerprint"] != fingerprint:
                raise ValueError("Command UUID reused with different content")
            existing["sent"] = False  # Re-delivery requests the same ack, never another action.
            self.save()
            return
        record = {"fingerprint": fingerprint, "ack": None, "sent": False}
        self.state["commands"][identifier] = record
        self.save()  # Durable intent before any action.
        event = self.agent.request_action(command["action"], command.get("mac"), manual=True)
        record["ack"] = self.ack("applied" if event.actions_taken else "failed",
                                 event.evidence["decision"])
        self.save()  # Freeze the exact acknowledgement for network retries.

    def sync(self):
        status, result = self.client.request("GET", "/sync", query={"etag": self.etag})
        if status == 304:
            return
        self.validators["Sync"].validate(result)
        self.apply_policy(result["policy"])
        for command in result["commands"]:
            self.command(command)
        self.etag = result["etag"]

    def send_acks(self):
        for identifier, record in self.state["commands"].items():
            if record["sent"]:
                continue
            status, _ = self.client.request("POST", f"/commands/{identifier}/ack", record["ack"])
            if status != 204:
                raise CloudError("Unexpected acknowledgement response")
            record["sent"] = True
            self.save()

    def upload(self):
        if self.state["pending_batch"] is None:
            events = self.agent.storage.pending_events()
            if self.state["cursor"] > len(events):
                raise ValueError("Outbox was truncated; refusing to skip events")
            stop = min(len(events), self.state["cursor"] + 1000)
            wire_events = [converted for event in events[self.state["cursor"]:stop]
                           if (converted := event_record(event)) is not None]
            anomalies = getattr(self.agent.detector, "anomaly", {})
            devices = [converted for d in self.agent.inventory.devices.values()
                       if (converted := device_record(d, anomalies.get(d.mac, 0))) is not None]
            batch = {"devices": devices, "events": wire_events}
            self.validators["Ingest"].validate(batch)
            self.state["pending_batch"] = {"payload": batch, "stop": stop}
            self.save()  # Exact payload survives a lost HTTP response/restart.
        pending = self.state["pending_batch"]
        _, result = self.client.request("POST", "/ingest", copy.deepcopy(pending["payload"]))
        if not isinstance(result, dict) or any(
            type(result.get(key)) is not int or not 0 <= result[key] <= len(pending["payload"][field])
            for key, field in (("accepted_devices", "devices"), ("accepted_events", "events"))
        ):
            raise CloudError("Invalid ingest acknowledgement; batch retained")
        self.state["cursor"] = pending["stop"]
        self.state["pending_batch"] = None
        self.save()

    def tick(self, *, upload=True):
        errors = []
        for operation in (self.sync, self.send_acks, *([self.upload] if upload else [])):
            try:
                operation()
            except CloudError as error:
                errors.append(str(error))
            except ValidationError:
                errors.append("API data failed shared-contract validation; retained local policy/pending work")
        return errors
