import sys, random, argparse, re, pandas as pd
from pathlib import Path
sys.path.insert(0, "agent")
from securiot_agent.packets import read_capture
from securiot_ml.model import Window, FEATS

PORTS = [22, 23, 80, 443, 445, 554, 8080, 8443, 1883, 5353]


def new_episode(rng, t, i):
    if rng.random() < 0.3:   # benign burst
        return dict(kind="burst", id=i, start=t, end=t + rng.randint(2, 4),
                    arp=rng.choice([3, 5, 8]), tps=0, ports=PORTS)
    arp, tps = rng.choice([0, 1, 2, 3, 5, 10, 20]), rng.choice([0, 1, 2, 3, 5, 10])
    return dict(kind="sweep", id=i, start=t, end=t + rng.randint(15, 90),
                arp=arp or (2 if not tps else 0), tps=tps, ports=rng.sample(PORTS, rng.randint(1, 3)))


def rows(path, dev=None, inject=False, labels=(), seed=0):
    rng, wins, last, ep, quiet, n, t0 = random.Random(seed), {}, {}, {}, {}, 0, None
    for p in read_capture(Path(path)):
        mac, sec = p.source_mac.lower(), int(p.timestamp)
        t0 = t0 or p.timestamp
        if dev and mac != dev:
            continue
        w = wins.setdefault(mac, Window())
        new_sec, e = sec != last.get(mac), ep.get(mac)
        if inject and new_sec:
            if e and sec > e["end"]:
                quiet[mac] = sec + (10 if e["kind"] == "sweep" else 0)
                e = ep[mac] = None
            if not e and sec >= quiet.get(mac, 0) and rng.random() < 1 / 600:
                n += 1
                e = ep[mac] = new_episode(rng, sec, n)
            if e:
                pairs = [(f"192.168.1.{rng.randint(2, 254)}", rng.choice(e["ports"])) for _ in range(e["tps"])]
                w.add(p.timestamp, e["arp"], pairs, 0)
        f = w.add(p.timestamp, int(bool(p.arp_request)),
                  [p.syn_target] if p.syn_target else [], p.captured_bytes)
        if not new_sec:
            continue
        last[mac] = sec
        label, eid, age = 0, -1, -1
        if e and e["kind"] == "sweep":
            label, eid, age = 1, e["id"], sec - e["start"]
        elif inject and not e and sec < quiet.get(mac, 0):
            continue
        rel, skip = p.timestamp - t0, False
        for i, (lm, s, en) in enumerate(labels):
            if lm == mac and s <= rel <= en:
                label, eid, age = 1, 1000 + i, int(rel - s)
            elif lm == mac and en < rel <= en + 10:
                skip = True
        if skip:
            continue
        yield [Path(path).name, mac, p.timestamp, *f, label, eid, age]


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["unsw", "live"])
    ap.add_argument("files", nargs="+")
    ap.add_argument("--labels")
    a = ap.parse_args()
    lab = pd.read_csv(a.labels) if a.labels else pd.DataFrame(columns=["pcap", "mac", "start_s", "end_s"])
    cols = ["pcap", "mac", "ts", *FEATS, "label", "ep", "ep_age"]
    for fp in a.files:
        name, dev = Path(fp).name, None
        if a.mode == "unsw":
            m = re.search(r"_([0-9a-fA-F]{12})\.pcap$", name).group(1).lower()
            dev = ":".join(m[i:i + 2] for i in range(0, 12, 2))
        L = [(r.mac.lower(), r.start_s, r.end_s) for r in lab[lab.pcap == name].itertuples()]
        df = pd.DataFrame(rows(fp, dev, a.mode == "unsw", L), columns=cols)
        df["source"] = a.mode
        df.to_parquet(f"ml/data/win_{a.mode}_{Path(fp).stem}.parquet")
        print(name, len(df), "rows,", df.ep.ge(0).sum(), "sweep rows,", df[df.ep >= 0].ep.nunique(), "sweeps")
