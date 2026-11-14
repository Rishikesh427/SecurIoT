from securiot_ml.assess import assess

def test_unknown_gets_no_guess():
    r = assess({"mac": "00:00:00:00:00:01", "ports": [443]})
    assert r["risk"] == 0 and r["type"] == "unknown"

def test_camera_hint():
    r = assess({"mac": "11:22:33:44:55:66", "ports": [23], "default_creds": True})
    assert r["eol"] and r["band"] in ("medium", "high")

def test_camera_persona():
    r = assess({"mac": "00:00:00:00:00:20", "ports": [23, 2323, 80, 8080], "default_creds": True,
                "persona": {"vendor": "Edimax", "model": "IC-7100", "eol": True,
                            "kev": "possible", "type": "camera"}})
    assert r["risk"] == 75 and r["band"] == "high"
    assert r["confidence"] == "possible" and len(r["reasons"]) == 4