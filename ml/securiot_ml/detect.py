import time, collections

DEFAULTS = {"arp_threshold": 30, "pair_threshold": 20, "window": 10, "warmup": 30}
MIN_SAFE = {"arp_threshold": 10, "pair_threshold": 8}  # cloud policy can't go below these
TELNET_PORTS = {23, 2323}

class Detector:
    def __init__(self, policy=None, ignore=(), baselines=None):
        self.cfg = dict(DEFAULTS)
        self.ignore = {m.upper() for m in ignore}
        self.baselines = baselines or {}
        self.t0 = time.time()
        self.arp = collections.defaultdict(collections.deque)
        self.pairs = collections.defaultdict(collections.deque)
        if policy:
            self.update_policy(policy)

    def update_policy(self, p):
        for k, floor in MIN_SAFE.items():
            if k in p:
                self.cfg[k] = max(floor, int(p[k]))
        self.ignore |= {m.upper() for m in p.get("protected", [])}

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
        hits = sorted(set(decoy_hits))
        if hits:   # fires on a single hit
            top = 1.0 if any(h in TELNET_PORTS for h in hits) else 0.9
            return {"kind": "decoy_touch", "anomaly": top, "ts": now,
                    "evidence": {**ev, "decoy_ports": hits}}
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