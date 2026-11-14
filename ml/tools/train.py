import glob, json, joblib, argparse, pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.calibration import CalibratedClassifierCV
from securiot_ml.model import FEATS
from evaluate import load, report

ap = argparse.ArgumentParser()
ap.add_argument("--holdout", default="")
ap.add_argument("--threshold", type=float, default=0.95)
ap.add_argument("--min-signal", type=int, default=8)  # weak sweep rows are ambiguous, not positives
a = ap.parse_args()

df = load(glob.glob("ml/data/win_*.parquet"))
weak = (df.label == 1) & (df.arp < a.min_signal) & (df.targets < a.min_signal)
df = df[~weak].reset_index(drop=True)          # drop ambiguous early-sweep rows
USE = [f for f in FEATS if f != "new_ratio"]    # new_ratio is unreliable (restarts, injection artifact)
pcaps = sorted(df.pcap.unique())
test = set(pcaps[::4]) | set(filter(None, a.holdout.split(",")))
val = {p for p in pcaps[1::4] if p not in test}
train = [p for p in pcaps if p not in test | val]
json.dump({"train": train, "val": sorted(val), "test": sorted(test)}, open("ml/data/split.json", "w"), indent=1)

tr = df[df.pcap.isin(train)]
m = CalibratedClassifierCV(HistGradientBoostingClassifier(max_depth=4, class_weight="balanced"),
                           method="isotonic", cv=3).fit(tr[USE], tr.label)

va = df[df.pcap.isin(val)].reset_index(drop=True)
pv = pd.Series(m.predict_proba(va[USE])[:, 1], index=va.index)
thr = a.threshold
joblib.dump({"model": m, "feats": USE, "threshold": thr}, "ml/data/scan_model.joblib")
print("threshold", thr, "| train", len(train), "val", len(val), "test", len(test))
