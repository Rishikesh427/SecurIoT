import glob, json, joblib, argparse, pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.calibration import CalibratedClassifierCV
from securiot_ml.model import FEATS
from evaluate import load, report

ap = argparse.ArgumentParser()
ap.add_argument("--holdout", default="")
a = ap.parse_args()

df = load(glob.glob("ml/data/win_*.parquet"))
pcaps = sorted(df.pcap.unique())
test = set(pcaps[::4]) | set(filter(None, a.holdout.split(",")))
val = {p for p in pcaps[1::4] if p not in test}
train = [p for p in pcaps if p not in test | val]
json.dump({"train": train, "val": sorted(val), "test": sorted(test)}, open("ml/data/split.json", "w"), indent=1)

tr = df[df.pcap.isin(train)]
m = CalibratedClassifierCV(HistGradientBoostingClassifier(max_depth=4, class_weight="balanced"),
                           method="isotonic", cv=3).fit(tr[FEATS], tr.label)

va = df[df.pcap.isin(val)].reset_index(drop=True)
pv = pd.Series(m.predict_proba(va[FEATS])[:, 1], index=va.index)
thr = 0.99
for t in [0.5, 0.6, 0.7, 0.8, 0.9, 0.95, 0.99]:
    if report(va, pv >= t, "ml")["false_alerts_per_hour"] <= 0.1:
        thr = t
        break
joblib.dump({"model": m, "feats": FEATS, "threshold": thr}, "ml/data/scan_model.joblib")
print("threshold", thr, "| train", len(train), "val", len(val), "test", len(test))
