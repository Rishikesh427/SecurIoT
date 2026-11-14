import time, collections
import pathlib

from .model import Window, FEATS

try:
    import joblib
    import pandas as pd
except ImportError:          # no ML deps: threshold rules only
    joblib = pd = None

MODEL_PATH = pathlib.Path(__file__).resolve().parent.parent / "data" / "scan_model.joblib"

DEFAULTS = {"arp_threshold": 30, "pair_threshold": 20, "window": 10, "warmup": 30}
MIN_SAFE = {"arp_threshold": 10, "pair_threshold": 8}  # cloud policy can't go below these
ML_MIN_THRESHOLD = 0.9    # cloud policy can't lower the ML alert score below this
ML_DEFAULT_THRESHOLD = 0.95
ML_MIN_SIGNAL = 8         # ML may only alert when the window has this many ARP requests or SYN targets
ML_REALERT_SECS = 10      # repeat an ML alert for the same device at most this often
ML_CONSECUTIVE = 2        # consecutive over-threshold windows before alerting
TELNET_PORTS = {23, 2323}


class Detector:
    def __init__(self, policy=None, ignore=(), baselines=None):
        self.cfg = dict(DEFAULTS)
        self.ignore = {m.upper() for m in ignore}
        self.baselines = baselines or {}
        self.t0 = time.time()
        self.arp = collections.defaultdict(collections.deque)
        self.pairs = collections.defaultdict(collections.deque)
        self.win = collections.defaultdict(Window)
        self.streak = collections.defaultdict(int)
        self.last_alert = {}
        self.model, self.feats, self.thr = None, None, ML_DEFAULT_THRESHOLD
        if joblib is not None:
            try:
                b = joblib.load(MODEL_PATH)
                self.model, self.feats, self.thr = b["model"], b["feats"], b["threshold"]
            except Exception:
                pass          # no model file: falls back to the threshold rules
        if policy:
            self.update_policy(policy)

    def update_policy(self, p):
        for k, floor in MIN_SAFE.items():
            if k in p:
                self.cfg[k] = max(floor, int(p[k]))
        self.ignore |= {m.upper() for m in p.get("protected", [])}
        if "ml_threshold" in p:
            self.thr = max(ML_MIN_THRESHOLD, float(p["ml_threshold"]))

    def _trim(self, dq, now):
        while dq and now - dq[0][0] > self.cfg["window"]:
            dq.popleft()

    def observe(self, mac, ts=None, arp=0, pairs=(), nbytes=0, decoy_hits=()):
        """decoy_hits = dst ports this MAC touched on a decoy this second."""
        now = ts or time.time()
        mac = mac.upper()
        if mac in self.ignore or now - self.t0 < self.cfg["warmup"]:
            return None
        a, p = self.arp[mac], self.pairs[mac]
        for _ in range(arp):
            a.append((now,))
        for pr in pairs:
            p.append((now, tuple(pr)))
        self._trim(a, now)
        self._trim(p, now)
        n_arp, distinct = len(a), len({x[1] for x in p})
        ev = {"arp_in_window": n_arp, "distinct_targets": distinct}

        f = self.win[mac].add(now, arp, pairs, nbytes)   # keep ML features current

        hits = sorted(set(decoy_hits))
        if hits:   # fires on a single hit
            top = 1.0 if any(h in TELNET_PORTS for h in hits) else 0.9
            return {"kind": "decoy_touch", "anomaly": top, "ts": now,
                    "evidence": {**ev, "decoy_ports": hits}}

        if self.model is not None:
            score = float(self.model.predict_proba(pd.DataFrame([f], columns=FEATS)[self.feats])[0, 1])
            self.streak[mac] = self.streak[mac] + 1 if score >= self.thr and max(f[0], f[1]) >= ML_MIN_SIGNAL else 0
            if self.streak[mac] >= ML_CONSECUTIVE and now - self.last_alert.get(mac, -1e9) >= ML_REALERT_SECS:
                self.last_alert[mac] = now
                kind = "scan_arp" if f[0] >= f[1] else "scan_targets"
                # Target-only scans stay supporting evidence (low anomaly), as in the rule path.
                anomaly = score if kind == "scan_arp" else min(score, 0.3)
                return {"kind": kind,
                        "anomaly": round(anomaly, 2), "ts": now,
                        "evidence": {**ev, "ml_score": round(score, 2)}}

        thr = self.cfg["arp_threshold"]
        if n_arp >= thr:
            return {"kind": "scan_arp", "ts": now, "evidence": ev,
                    "anomaly": round(min(1.0, n_arp / (2 * thr) + 0.5), 2)}
        if distinct >= self.cfg["pair_threshold"]:   # supporting only
            return {"kind": "scan_targets", "anomaly": 0.3, "ts": now, "evidence": ev}
        return self._zscore(mac, nbytes, now)

    def _zscore(self, mac, nbytes, now):
        b = self.baselines.get(mac)
        if not b or b.get("std", 0) <= 0 or not nbytes:
            return None
        z = (nbytes - b["mean"]) / b["std"]
        if z >= 4:
            return {"kind": "volume", "anomaly": round(min(1.0, z / 8), 2), "ts": now,
                    "evidence": {"z": round(z, 1), "bytes": nbytes}}
        return None