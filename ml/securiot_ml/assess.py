from .score import score_device
from .vendors import lookup
from .kev import match

def assess(d):
    h = lookup(d["mac"])
    hints = {k: v for k, v in h.items() if k in ("type", "cloud_only", "eol")}
    p = d.get("persona") or {}          # simulated devices only
    d = {**hints, **d, **p}             # persona wins
    d.setdefault("vendor", h.get("vendor"))
    kev = {"confidence": p["kev"]} if p.get("kev") else match(d.get("vendor"), d.get("model"))
    r = score_device(d, kev)
    return {"type": d.get("type", "unknown"), "eol": bool(d.get("eol")),
            "cloud_only": bool(d.get("cloud_only")),
            "risk": r.score, "band": r.band, "confidence": r.confidence,
            "reasons": r.reasons}