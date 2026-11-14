from dataclasses import dataclass, field
from .rules import RISKY_PORTS, UPNP_PORTS, W

@dataclass
class ScoreResult:
    score: int
    band: str
    confidence: str
    factors: dict = field(default_factory=dict)
    reasons: list = field(default_factory=list)

def band(s): return "high" if s >= 60 else "medium" if s >= 30 else "low"

def score_device(d, kev=None):
    f, why, conf = {}, [], "n/a"
    exposed = sorted(p for p in d.get("ports", []) if p in RISKY_PORTS or p in UPNP_PORTS)
    kc = (kev or {}).get("confidence")
    if kc == "confirmed":
        f["kev"], conf = W["kev_confirmed"], "confirmed"
        why.append("Vendor and product match a known exploited CVE")
    elif kc == "possible":
        f["kev"], conf = W["kev_possible"], "possible"
        why.append("Vendor matches known exploited CVEs (model unconfirmed)")
    elif exposed and not d.get("model"):
        conf = "likely"
        why.append("Old protocols exposed, model unknown")
    if d.get("default_creds"): f["default_creds"] = W["default_creds"]; why.append("Default or weak credentials")
    if d.get("eol"): f["eol"] = W["eol"]; why.append("End-of-life: no more security updates")
    if exposed: f["ports"] = W["ports"]; why.append(f"Risky ports open: {exposed}")
    if d.get("cloud_only"): f["cloud_only"] = W["cloud_only"]; why.append("Cloud-only, no local control")
    a = max(0.0, min(1.0, float(d.get("anomaly") or 0)))
    if a > 0: f["anomaly"] = round(a * W["anomaly_max"]); why.append(f"Anomalous behavior ({a:.0%} confidence)")
    s = min(100, sum(f.values()))
    return ScoreResult(s, band(s), conf, f, why)