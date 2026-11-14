from securiot_ml.detect import Detector

def mk():
    d = Detector(ignore=["AA:AA:AA:AA:AA:AA"])
    d.t0 = 0  # fake timestamps start at 1000, so warmup is already over
    return d

def test_scan_by_arp():
    d, r = mk(), None
    for i in range(35):
        r = d.observe("BB:BB:BB:BB:BB:BB", 1000 + i * 0.1, arp=1) or r
    assert r and r["kind"] == "scan" and r["anomaly"] > 0.5

def test_scan_by_ports():
    d, r = mk(), None
    for i in range(25):
        r = d.observe("BB:BB:BB:BB:BB:BB", 1000 + i * 0.1, pairs=[("10.42.0.50", 1000 + i)]) or r
    assert r and r["kind"] == "scan"

def test_ignore_list():
    d = mk()
    assert all(d.observe("AA:AA:AA:AA:AA:AA", 1000 + i, arp=50) is None for i in range(5))

def test_clamp():
    d = mk()
    d.update_policy({"arp_threshold": 1})
    assert d.cfg["arp_threshold"] == 10

def test_warmup():
    assert Detector().observe("BB:BB:BB:BB:BB:BB", arp=99) is None

def test_window_expiry():
    d = mk()
    for i in range(20):
        d.observe("BB:BB:BB:BB:BB:BB", 1000 + i * 0.1, arp=1)
    assert d.observe("BB:BB:BB:BB:BB:BB", 1100, arp=1) is None  # old entries aged out

def test_volume_zscore():
    d = Detector(baselines={"BB:BB:BB:BB:BB:BB": {"mean": 1000, "std": 100}})
    d.t0 = 0
    assert d.observe("BB:BB:BB:BB:BB:BB", 1000, nbytes=1500)["kind"] == "volume"