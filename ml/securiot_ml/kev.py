import json, pathlib
_KEV = None

def _load():
    global _KEV
    if _KEV is None:
        p = pathlib.Path(__file__).parent.parent / "data" / "kev.json"
        _KEV = json.loads(p.read_text())["vulnerabilities"]
    return _KEV

def match(vendor, product=None):
    v, p = (vendor or "").lower().strip(), (product or "").lower().strip()
    if not v:
        return None
    hits = [k for k in _load() if v in k["vendorProject"].lower()]
    if not hits:
        return None
    if p:
        exact = [k for k in hits if p in k["product"].lower()]
        if exact:
            return {"confidence": "confirmed", "ids": [k["cveID"] for k in exact][:5]}
    return {"confidence": "possible", "ids": [k["cveID"] for k in hits][:5]}