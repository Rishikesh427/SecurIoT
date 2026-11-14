"""Enforcement boundary. Only the in-memory simulation backend exists today."""

from typing import Protocol


class Enforcer(Protocol):
    simulated: bool

    def apply(self, action: str, mac: str) -> None: ...


class MockEnforcer:
    simulated = True

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []
        self.restrictions: dict[str, str] = {}

    def apply(self, action: str, mac: str) -> None:
        if action not in {"block_wan", "quarantine", "restore"}:
            raise ValueError(f"Mock enforcer does not support {action!r}")
        self.calls.append((action, mac))
        if action == "restore":
            self.restrictions.pop(mac, None)
        else:
            self.restrictions[mac] = "blocked" if action == "block_wan" else "quarantined"
