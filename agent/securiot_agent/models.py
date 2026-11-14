"""Local models. Cloud serialization must follow the separate shared contract."""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import re
from typing import Any
from uuid import uuid4


def normalize_mac(mac: str) -> str:
    if not re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", mac):
        raise ValueError(f"Invalid MAC address: {mac!r}")
    return mac.lower()


@dataclass
class Device:
    mac: str
    ip: str
    name: str
    protected: bool = False
    simulated: bool = True
    status: str = "normal"
    bytes_in: int = 0
    bytes_out: int = 0
    dests: list[str] = field(default_factory=list)
    last_seen: float | None = None
    dns_queries: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.mac = normalize_mac(self.mac)
        if self.status != "normal":
            raise ValueError("Register devices in normal state; saved restrictions load separately.")


@dataclass(frozen=True)
class Observation:
    """Traffic deltas plus a snapshot of the current activity window.

    Only bytes_in/out are deltas added to inventory. The window fields describe
    recent activity and must never be added repeatedly to lifetime counters.
    """

    mac: str
    bytes_in: int = 0
    bytes_out: int = 0
    destinations: tuple[str, ...] = ()
    syn_targets: tuple[tuple[str, int], ...] = ()
    arp_requests: int = 0
    dns_queries: tuple[str, ...] = ()
    window_bytes_in: int = 0
    window_bytes_out: int = 0
    captured_at: float | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "mac", normalize_mac(self.mac))
        if min(self.bytes_in, self.bytes_out, self.arp_requests) < 0:
            raise ValueError("Traffic counters cannot be negative.")


@dataclass(frozen=True)
class Finding:
    kind: str
    evidence: dict[str, Any]


@dataclass
class Event:
    mac: str | None
    ts: str
    kind: str
    evidence: dict[str, Any]
    actions_taken: list[str] = field(default_factory=list)
    would_have: list[str] = field(default_factory=list)
    id: str = field(default_factory=lambda: str(uuid4()))
    source: str = "agent"
    simulated: bool = True

    @classmethod
    def at(cls, now: float, **kwargs: Any) -> "Event":
        return cls(ts=datetime.fromtimestamp(now, timezone.utc).isoformat(), **kwargs)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
