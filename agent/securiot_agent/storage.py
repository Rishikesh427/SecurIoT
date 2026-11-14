"""Atomic state snapshots plus an append-only event outbox.

    There is no uploader yet: events stay local and retain their original UUIDs.
"""

import json
import math
import os
from pathlib import Path
import tempfile
from typing import Any

from .models import Event, normalize_mac


class Storage:
    def __init__(self, directory: Path):
        self.directory = directory
        self.state_path = directory / "state.json"
        self.outbox_path = directory / "outbox.jsonl"

    def load_state(self) -> dict[str, Any]:
        if not self.state_path.exists():
            return {"version": 1, "mode": "simulation", "saved_at": 0, "devices": {}}
        try:
            state = json.loads(self.state_path.read_text())
            if state["version"] != 1 or state["mode"] != "simulation":
                raise ValueError("Unsupported state version or mode")
            self._check_time(state["saved_at"])
            if not isinstance(state["devices"], dict):
                raise ValueError("devices must be an object")
            for mac, record in state["devices"].items():
                if normalize_mac(mac) != mac:
                    raise ValueError("Saved MAC must be normalized")
                if record["status"] not in {"normal", "blocked", "quarantined"}:
                    raise ValueError("Invalid saved device status")
                self._check_time(record["last_action_at"])
                self._check_time(record["grace_until"])
            return state
        except (ValueError, KeyError, TypeError, AttributeError) as error:
            raise ValueError(f"Invalid state in {self.state_path}: {error}") from error

    @staticmethod
    def _check_time(value: Any) -> None:
        if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
            raise ValueError("Saved timestamps must be finite, nonnegative numbers")

    def save_state(self, state: dict[str, Any]) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        temp_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", dir=self.directory, delete=False) as output:
                temp_path = Path(output.name)
                json.dump(state, output, indent=2, allow_nan=False)
                output.write("\n")
                output.flush()
                os.fsync(output.fileno())
            os.replace(temp_path, self.state_path)
        finally:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)

    def append_event(self, event: Event) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        with self.outbox_path.open("a", encoding="utf-8") as output:
            output.write(json.dumps(event.to_dict(), allow_nan=False) + "\n")
            output.flush()
            os.fsync(output.fileno())

    def pending_events(self) -> list[dict[str, Any]]:
        if not self.outbox_path.exists():
            return []
        return [json.loads(line) for line in self.outbox_path.read_text().splitlines() if line.strip()]
