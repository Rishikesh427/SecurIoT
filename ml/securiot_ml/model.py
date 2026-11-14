import collections

FEATS = ["arp", "targets", "ips", "ports", "bytes", "arp_rate_1s", "new_ratio"]


class Window:
    """Rolling 10 s feature window for one MAC. Used by training AND the live detector."""

    def __init__(self, secs=10):
        self.secs, self.ev, self.seen = secs, collections.deque(), set()

    def add(self, ts, arp=0, pairs=(), nbytes=0):
        self.ev.append((ts, arp, tuple(map(tuple, pairs)), nbytes))
        while self.ev and ts - self.ev[0][0] > self.secs:
            self.ev.popleft()
        allp = {p for e in self.ev for p in e[2]}
        ips = {p[0] for p in allp}
        new = ips - self.seen
        self.seen |= ips
        return [sum(e[1] for e in self.ev), len(allp), len(ips), len({p[1] for p in allp}),
                sum(e[3] for e in self.ev), sum(e[1] for e in self.ev if ts - e[0] <= 1),
                len(new) / max(1, len(ips))]
