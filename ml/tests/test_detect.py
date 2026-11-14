from securiot_ml.detect import Detector

def mk():
    d = Detector(ignore=["AA:AA:AA:AA:AA:AA"])
    d.t0 = 0  # fake timestamps start at 1000, so warmup is already over
    return d

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

def test_scan_arp():
    d, r = mk(), None
    for i in range(35):
        r = d.observe("BB:BB:BB:BB:BB:BB", 1000 + i * 0.1, arp=1) or r
    assert r and r["kind"] == "scan_arp" and r["anomaly"] > 0.5

def test_targets_are_supporting_only():
    d, r = mk(), None
    for i in range(25):
        r = d.observe("BB:BB:BB:BB:BB:BB", 1000 + i * 0.1, pairs=[("10.42.0.50", 1000 + i)]) or r
    assert r["kind"] == "scan_targets" and r["anomaly"] < 0.5

def test_decoy_single_hit():
    d = mk()
    r = d.observe("BB:BB:BB:BB:BB:BB", 1000, decoy_hits=[23])
    assert r["kind"] == "decoy_touch" and r["anomaly"] == 1.0
    r2 = mk().observe("BB:BB:BB:BB:BB:BB", 1000, decoy_hits=[445])
    assert r2["anomaly"] == 0.9

def test_decoy_ignored_for_protected():
    assert mk().observe("AA:AA:AA:AA:AA:AA", 1000, decoy_hits=[23]) is None

def test_arp_score_ramps_through_tiers():
    d = mk()
    for i in range(29):
        d.observe("BB:BB:BB:BB:BB:BB", 1000 + i * 0.1, arp=1)
    first = d.observe("BB:BB:BB:BB:BB:BB", 1003.0, arp=1)
    assert first["kind"] == "scan_arp" and 0.95 <= first["anomaly"] < 0.97
    for i in range(30):
        last = d.observe("BB:BB:BB:BB:BB:BB", 1003.1 + i * 0.05, arp=1)
    assert last["anomaly"] >= 0.99