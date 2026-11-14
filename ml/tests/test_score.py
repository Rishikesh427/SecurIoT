from securiot_ml.score import score_device, band
def test_clean(): assert score_device({"ports":[443]}).score == 0
def test_camera():
    r = score_device({"ports":[23],"eol":1,"default_creds":1},{"confidence":"possible"})
    assert r.score == 75 and r.band == "high" and r.confidence == "possible"
def test_cap():
    d = {"eol":1,"default_creds":1,"cloud_only":1,"ports":[23],"anomaly":1}
    assert score_device(d,{"confidence":"confirmed"}).score == 100
def test_bands(): assert band(29)=="low" and band(30)=="medium" and band(60)=="high"