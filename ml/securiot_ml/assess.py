from .score import score_device
from .vendors import lookup
from .kev import match

def assess(d):
    h = lookup(d["mac"])
    hints = {k: v for k, v in h.items() if k in ("type", "cloud_only", "eol")}
    d = {**hints, **d}
    d.setdefault("vendor", h.get("vendor"))
    r = score_device(d, match(d.get("vendor"), d.get("model")))
    return {"type": d.get("type", "unknown"), "eol": bool(d.get("eol")),
            "cloud_only": bool(d.get("cloud_only")),
            "risk": r.score, "band": r.band, "confidence": r.confidence,
            "reasons": r.reasons}