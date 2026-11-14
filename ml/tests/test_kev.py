from securiot_ml.kev import match

def test_vendor_only():
    r = match("D-Link")
    assert r and r["confidence"] == "possible"

def test_unknown():
    assert match("NotARealVendorXYZ") is None

def test_empty():
    assert match("") is None