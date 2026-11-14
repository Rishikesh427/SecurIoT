"""Explicit conversion to the shared cloud contract; local audit stays local."""
from datetime import datetime, timezone

KINDS = {"scan_arp", "scan_targets", "decoy_touch", "new_domain", "new_device", "volume"}
CONFIDENCE = {"confirmed": "high", "possible": "medium", "likely": "medium", "n/a": "low",
              "low": "low", "medium": "medium", "high": "high"}


def device_record(device, anomaly=0):
    if device.last_seen is None:
        return None
    score = device.assessment
    if not score:
        raise ValueError("Cloud upload requires a real assessment; use the C detector")
    facts = device.risk_facts
    persona = facts.get("persona", {})
    return {
        "mac": device.mac, "ip": device.ip, "name": device.name, "label": device.name,
        "type": score["type"], "vendor": persona.get("vendor", facts.get("vendor")),
        "ports": sorted(set(facts.get("ports", []))), "bytes_in": device.bytes_in,
        "bytes_out": device.bytes_out, "dests": device.dests,
        "last_seen": datetime.fromtimestamp(device.last_seen, timezone.utc).isoformat(),
        "snapshot_at": datetime.fromtimestamp(max(device.last_seen, device.snapshot_at or device.last_seen), timezone.utc).isoformat(),
        "simulated": device.simulated, "has_feed": False,
        "eol": score.get("eol"), "default_creds": facts.get("default_creds"),
        "cloud_only": score.get("cloud_only"), "anomaly": round(min(1, max(0, anomaly)) * 40),
        "risk": score["risk"], "band": score["band"],
        "confidence": CONFIDENCE[score["confidence"]], "reasons": score["reasons"],
        "status": {"blocked": "wan_blocked"}.get(device.status, device.status),
    }


def event_record(event):
    kind = event["evidence"].get("finding", event["kind"])
    if kind not in KINDS or event["mac"] is None:
        return None
    sim = event.get("simulated", True)
    return {"id": event["id"], "mac": event["mac"], "ts": event["ts"], "kind": kind,
            "evidence": {**event["evidence"], "simulated": sim, "enforcement": "mock" if sim else "live"},
            "actions_taken": event["actions_taken"], "would_have": event["would_have"],
            "source": "simulator" if sim else "agent"}
