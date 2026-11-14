import json, pathlib
_V = json.loads((pathlib.Path(__file__).parent.parent / "data" / "vendors.json").read_text())

def lookup(mac):
    return _V.get(mac.upper()[:8], _V["default"])