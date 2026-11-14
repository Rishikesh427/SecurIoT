"""C's trained binary scan model, sampled like its training extractor."""
import hashlib
import math
from pathlib import Path

from securiot_ml.model import FEATS, Window


class TrainedScanModel:
    def __init__(self, mode, detector, artifact_path):
        self.windows, self.last_second, self.streak, self.last_alert = {}, {}, {}, {}
        self.status = {"mode": mode, "active": False, "predictions": 0}
        self.model = None
        if mode == "rules":
            return
        try:
            if detector.model is None:
                raise ValueError("artifact or pinned inference dependencies failed to load")
            self.features = list(detector.feats)
            names = list(getattr(detector.model, "feature_names_in_", self.features))
            if (not self.features or len(set(self.features)) != len(self.features)
                    or any(name not in FEATS for name in self.features) or self.features != names):
                raise ValueError("saved feature order differs from the estimator or feature extractor")
            if getattr(detector.model, "n_features_in_", len(self.features)) != len(self.features):
                raise ValueError("saved feature count differs from the estimator")
            classes = list(detector.model.classes_)
            if classes != [0, 1]:
                raise ValueError("expected benign=0 and scan=1 class labels")
            threshold = float(detector.thr)
            if not math.isfinite(threshold) or not 0 <= threshold <= 1:
                raise ValueError("invalid saved threshold")
            self.model, self.positive_index = detector.model, classes.index(1)
            self.threshold = max(0.9, threshold)
            self.status.update(active=True, saved_threshold=threshold, threshold=self.threshold,
                features=self.features, minimum_signal=8, alert_cooldown_seconds=10, sha256=hashlib.sha256(Path(artifact_path).read_bytes()).hexdigest(),
                sampling="first outgoing packet per observed second; 10-second Window")
        except (AttributeError, OSError, TypeError, ValueError) as error:
            self.status["reason"] = str(error)
            if mode == "required":
                raise ValueError("Trained model unavailable: " + str(error) + "; install ml/requirements-model.txt or choose --model-mode rules") from error

    def observe(self, observation, warmed):
        # Training rows() counts only frames whose source is the device.
        if observation.captured_at is None or observation.bytes_out <= 0:
            return None
        ts, mac = observation.captured_at, observation.mac
        window = self.windows.setdefault(mac, Window())
        features = window.add(ts, observation.packet_arp_requests,
                              observation.packet_syn_targets, observation.bytes_out)
        second = int(ts)
        previous = self.last_second.get(mac)
        if previous == second:
            return None
        self.last_second[mac] = second
        if self.model is None or not warmed:
            self.streak[mac] = 0
            return None
        import pandas as pd
        from threadpoolctl import threadpool_limits
        with threadpool_limits(limits=1):
            score = float(self.model.predict_proba(pd.DataFrame([features], columns=FEATS)[self.features])[0, self.positive_index])
        if not math.isfinite(score) or not 0 <= score <= 1:
            raise ValueError("Model returned an invalid probability")
        self.status["predictions"] += 1
        self.status["last_score"] = score
        consecutive = previous is not None and second == previous + 1
        qualifying = score >= self.threshold and max(features[0], features[1]) >= 8
        self.streak[mac] = (self.streak.get(mac, 0) if consecutive else 0) + 1 if qualifying else 0
        if self.streak[mac] < 2 or ts - self.last_alert.get(mac, -1e9) < 10:
            return None
        self.last_alert[mac] = ts
        return {"ml_score": score, "model_threshold": self.threshold,
                "features": dict(zip(FEATS, features)), "classification": "scan_like",
                "basis": "trained_scan_model", "advisory_only": True,
                "training_note": "UNSW normal traces with synthetic scan injections; Pi transfer not yet evaluated"}
