"""
Phase 3/4: Baseline supervised classifier + unsupervised anomaly detector.

No fabricated metrics: evaluate() always computes real sklearn metrics on
a held-out split and returns them as data, which the API/dashboard render
directly.
"""

from __future__ import annotations

import json
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, classification_report, confusion_matrix,
    f1_score, precision_score, recall_score, roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from app.ml.features import featurize, binary_labels

MODEL_DIR = Path(__file__).resolve().parent.parent.parent / "models"
MODEL_DIR.mkdir(exist_ok=True)


class BaselineClassifier:
    """Binary benign-vs-malicious classifier (Random Forest by default)."""

    def __init__(self, model_type: str = "random_forest"):
        self.model_type = model_type
        self.model = None
        self.scaler = StandardScaler()
        self.feature_names: list[str] = []

    def _build_model(self):
        if self.model_type == "logistic_regression":
            return LogisticRegression(max_iter=1000, class_weight="balanced")
        return RandomForestClassifier(
            n_estimators=200, max_depth=8, class_weight="balanced", random_state=42
        )

    def train(self, events: list[dict], test_size: float = 0.25, random_state: int = 42) -> dict:
        X_df = featurize(events)
        self.feature_names = list(X_df.columns)
        X = X_df.values
        y = binary_labels(events)

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=random_state,
            stratify=y if len(set(y)) > 1 else None,
        )
        X_train_s = self.scaler.fit_transform(X_train)
        X_test_s = self.scaler.transform(X_test)

        self.model = self._build_model()
        self.model.fit(X_train_s, y_train)

        return self.evaluate(X_test_s, y_test, already_scaled=True)

    def evaluate(self, X, y_true, already_scaled: bool = False) -> dict:
        X_s = X if already_scaled else self.scaler.transform(X)
        y_pred = self.model.predict(X_s)
        y_proba = self.model.predict_proba(X_s)[:, 1] if hasattr(self.model, "predict_proba") else None

        metrics = {
            "n_test_samples": int(len(y_true)),
            "accuracy": float(accuracy_score(y_true, y_pred)),
            "precision": float(precision_score(y_true, y_pred, zero_division=0)),
            "recall": float(recall_score(y_true, y_pred, zero_division=0)),
            "f1": float(f1_score(y_true, y_pred, zero_division=0)),
            "confusion_matrix": confusion_matrix(y_true, y_pred).tolist(),
            "classification_report": classification_report(y_true, y_pred, zero_division=0, output_dict=True),
        }
        if y_proba is not None and len(set(y_true)) > 1:
            metrics["roc_auc"] = float(roc_auc_score(y_true, y_proba))
        return metrics

    def predict(self, events: list[dict]) -> list[dict]:
        X_df = featurize(events)
        X_df = X_df.reindex(columns=self.feature_names, fill_value=0)
        X_s = self.scaler.transform(X_df.values)
        preds = self.model.predict(X_s)
        probas = (
            self.model.predict_proba(X_s)[:, 1]
            if hasattr(self.model, "predict_proba") else preds.astype(float)
        )
        return [
            {"event_id": e.get("event_id"), "is_malicious": bool(p), "confidence": float(c)}
            for e, p, c in zip(events, preds, probas)
        ]

    def save(self, name: str = "baseline"):
        joblib.dump(
            {"model": self.model, "scaler": self.scaler, "feature_names": self.feature_names,
             "model_type": self.model_type},
            MODEL_DIR / f"{name}.joblib",
        )

    @classmethod
    def load(cls, name: str = "baseline") -> "BaselineClassifier":
        data = joblib.load(MODEL_DIR / f"{name}.joblib")
        clf = cls(model_type=data["model_type"])
        clf.model = data["model"]
        clf.scaler = data["scaler"]
        clf.feature_names = data["feature_names"]
        return clf


class AnomalyDetector:
    """Unsupervised anomaly detector (Isolation Forest) — flags 'unusual', not 'known-bad'."""

    def __init__(self, contamination: float = 0.05):
        self.contamination = contamination
        self.model = IsolationForest(contamination=contamination, random_state=42, n_estimators=200)
        self.scaler = StandardScaler()
        self.feature_names: list[str] = []

    def train(self, events: list[dict]) -> dict:
        X_df = featurize(events)
        self.feature_names = list(X_df.columns)
        X_s = self.scaler.fit_transform(X_df.values)
        self.model.fit(X_s)

        scores = -self.model.score_samples(X_s)  # higher = more anomalous
        preds = self.model.predict(X_s)  # -1 anomaly, 1 normal
        return {
            "n_events": len(events),
            "n_flagged_anomalous": int((preds == -1).sum()),
            "anomaly_rate": float((preds == -1).mean()),
            "score_mean": float(scores.mean()),
            "score_std": float(scores.std()),
        }

    def score(self, events: list[dict]) -> list[dict]:
        X_df = featurize(events)
        X_df = X_df.reindex(columns=self.feature_names, fill_value=0)
        X_s = self.scaler.transform(X_df.values)
        raw_scores = -self.model.score_samples(X_s)
        preds = self.model.predict(X_s)
        # normalize raw scores to a 0-100 risk-friendly range for this batch
        lo, hi = raw_scores.min(), raw_scores.max()
        norm = (raw_scores - lo) / (hi - lo + 1e-9) * 100
        return [
            {
                "event_id": e.get("event_id"),
                "anomaly_score": float(s),
                "risk_score": float(n),
                "is_anomaly": bool(p == -1),
            }
            for e, s, n, p in zip(events, raw_scores, norm, preds)
        ]

    def save(self, name: str = "anomaly"):
        joblib.dump(
            {"model": self.model, "scaler": self.scaler, "feature_names": self.feature_names},
            MODEL_DIR / f"{name}.joblib",
        )

    @classmethod
    def load(cls, name: str = "anomaly") -> "AnomalyDetector":
        data = joblib.load(MODEL_DIR / f"{name}.joblib")
        det = cls()
        det.model = data["model"]
        det.scaler = data["scaler"]
        det.feature_names = data["feature_names"]
        return det


def run_experiment_and_save_report(events: list[dict], out_path: Path) -> dict:
    """Train baseline + anomaly detector, save real metrics as JSON (Phase 19)."""
    clf = BaselineClassifier()
    clf_metrics = clf.train(events)

    det = AnomalyDetector()
    det_metrics = det.train(events)

    report = {"baseline_classifier": clf_metrics, "anomaly_detector": det_metrics}
    out_path.write_text(json.dumps(report, indent=2, default=str))
    return report
