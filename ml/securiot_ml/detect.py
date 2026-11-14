import time, collections

DEFAULTS = {"arp_threshold": 30, "pair_threshold": 20, "window": 10, "warmup": 30}
MIN_SAFE = {"arp_threshold": 10, "pair_threshold": 8}  # cloud policy can't go below these

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

    def observe(self, mac, ts=None, arp=0, pairs=(), nbytes=0):
        """Call per MAC every ~1s. pairs = iterable of (dst_ip, dst_port).
        Returns an event dict or None."""
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
        if n_arp >= self.cfg["arp_threshold"] or distinct >= self.cfg["pair_threshold"]:
            conf = min(1.0, max(n_arp / (2 * self.cfg["arp_threshold"]),
                                distinct / (2 * self.cfg["pair_threshold"])) + 0.5)
            return {"kind": "scan", "anomaly": round(conf, 2), "ts": now,
                    "evidence": {"arp_in_window": n_arp, "distinct_targets": distinct}}
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