import sys, json, glob, joblib, numpy as np, pandas as pd


def load(files):
    df = pd.concat(pd.read_parquet(f) for f in files)
    return df.sort_values(["pcap", "mac", "ts"]).reset_index(drop=True)


def _shift(s, df):
    return s.groupby([df.pcap, df.mac]).shift(1, fill_value=False)


def report(df, hit, name):
    a = hit & _shift(hit, df)
    starts = a & ~_shift(a, df)
    norm = df.label == 0
    hours = df[norm].groupby(["pcap", "mac"]).ts.agg(lambda s: s.max() - s.min()).sum() / 3600
    out = {"detector": name, "normal_hours": round(hours, 2),
           "false_alerts_per_hour": round(int(starts[norm].sum()) / max(hours, 1e-9), 2)}
    res = []
    for _, g in df[df.ep >= 0].groupby(["pcap", "ep"]):
        h = g[a[g.index]]
        res.append(h.ep_age.min() if len(h) else None)
    det = [r for r in res if r is not None]
    if res:
        out.update(episodes=len(res), detected=len(det), recall=round(len(det) / len(res), 2),
                   median_secs_to_detect=float(np.median(det)) if det else None)
    return out


def rules(df):
    return (df.arp >= 30) | (df.targets >= 20)


if __name__ == "__main__":
    files = [f for f in sys.argv[1:] if f.endswith(".parquet")] or glob.glob("ml/data/win_*.parquet")
    df = load(files)
    if "--test-only" in sys.argv:
        df = df[df.pcap.isin(json.load(open("ml/data/split.json"))["test"])].reset_index(drop=True)
    b = joblib.load("ml/data/scan_model.joblib")
    p = pd.Series(b["model"].predict_proba(df[b["feats"]])[:, 1], index=df.index)
    for r in (report(df, p >= b["threshold"], "ml"), report(df, rules(df), "threshold_rules")):
        print(r)
