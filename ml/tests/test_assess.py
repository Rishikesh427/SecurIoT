from securiot_ml.assess import assess

def test_unknown_gets_no_guess():
    r = assess({"mac": "00:00:00:00:00:01", "ports": [443]})
    assert r["risk"] == 0 and r["type"] == "unknown"

def test_camera_hint():
    r = assess({"mac": "11:22:33:44:55:66", "ports": [23], "default_creds": True})
    assert r["eol"] and r["band"] in ("medium", "high")