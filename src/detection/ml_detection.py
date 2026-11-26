"""Unsupervised ML anomaly detection using Isolation Forest."""

import glob
import os
import sys
from typing import Any, Dict, List

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from src.config import load_config
from src.ml.feature_engineering import NUMERIC_FEATURE_COLUMNS
from src.utils.logger import get_logger

logger = get_logger("ml_detection")


def _load_feature_table(feature_csv: str) -> pd.DataFrame:
    feature_dir = os.path.dirname(feature_csv)
    if os.path.exists(feature_csv):
        df = pd.read_csv(feature_csv, low_memory=False)
        base_req = ["action_count", "unique_hosts", "suspicious_process_count"]
        if all(c in df.columns for c in base_req):
            return df
    backups = glob.glob(os.path.join(feature_dir, "feature_table_backup_*.csv"))
    if backups:
        latest = max(backups, key=os.path.getmtime)
        logger.info("Using backup feature file: %s", latest)
        return pd.read_csv(latest, low_memory=False)
    raise FileNotFoundError(f"Feature table not found: {feature_csv}")


def _subsample_rows(arr: np.ndarray, max_samples: int, seed: int) -> np.ndarray:
    if len(arr) <= max_samples:
        return arr
    rng = np.random.default_rng(seed)
    idx = rng.choice(len(arr), size=max_samples, replace=False)
    return arr[idx]


def _normalize_scores(decision_scores: np.ndarray) -> np.ndarray:
    """Convert sklearn decision_function (lower = more anomalous) into [0, 1] anomaly score."""
    inv = -decision_scores
    min_v = float(np.min(inv))
    max_v = float(np.max(inv))
    if max_v - min_v < 1e-9:
        return np.zeros_like(inv, dtype=float)
    return (inv - min_v) / (max_v - min_v)


def train_and_predict_ml(
    feature_csv: str | None = None,
    alert_file: str | None = None,
    retrain: bool = True,
) -> pd.DataFrame:
    """Train (or load) Isolation Forest model and generate anomaly alerts."""
    cfg = load_config()
    feat_path = feature_csv or cfg["paths"]["features_file"]
    out_path = alert_file or cfg["paths"]["ml_alerts_file"]
    models_dir = cfg["paths"]["models_dir"]
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    os.makedirs(models_dir, exist_ok=True)

    ml_cfg = cfg["ml"]
    seed = int(ml_cfg["random_state"])
    contamination = float(ml_cfg["contamination"])
    max_train = int(ml_cfg.get("max_if_train_samples", 50000))

    df = _load_feature_table(feat_path)
    cols = ["time_window", "user", "alert_type", "anomaly_score", "severity", "details"]
    if df.empty:
        empty_df = pd.DataFrame(columns=cols)
        empty_df.to_csv(out_path, index=False)
        logger.warning("Empty feature table; wrote 0 ML alerts.")
        return empty_df

    feature_cols = [c for c in NUMERIC_FEATURE_COLUMNS if c in df.columns]
    if not feature_cols:
        feature_cols = [
            c for c in ["action_count", "unique_hosts", "suspicious_process_count",
                        "num_source_ips", "num_unique_commands", "outside_work_hours"]
            if c in df.columns
        ]

    X_raw = df[feature_cols].fillna(0.0).values.astype(np.float32)
    bundle_path = os.path.join(models_dir, "ml_bundle.joblib")

    if not retrain and os.path.exists(bundle_path):
        logger.info("Loading persisted Isolation Forest model from %s", bundle_path)
        bundle = joblib.load(bundle_path)
        scaler = bundle["scaler"]
        iso_forest = bundle["iso_forest"]
        feature_cols = bundle["feature_cols"]
        X_raw = df[feature_cols].fillna(0.0).values.astype(np.float32)
        X_scaled = scaler.transform(X_raw)
    else:
        logger.info("Training Isolation Forest on %d rows x %d features", len(X_raw), len(feature_cols))
        scaler = RobustScaler()
        X_scaled = scaler.fit_transform(X_raw)
        X_train = _subsample_rows(X_scaled, max_train, seed)

        iso_forest = IsolationForest(contamination=contamination, random_state=seed, n_jobs=-1)
        iso_forest.fit(X_train)

        joblib.dump(
            {
                "scaler": scaler,
                "iso_forest": iso_forest,
                "feature_cols": feature_cols,
            },
            bundle_path,
        )
        logger.info("Saved Isolation Forest model -> %s", bundle_path)

    labels = iso_forest.predict(X_scaled)
    raw_decision = iso_forest.decision_function(X_scaled)
    norm_scores = _normalize_scores(raw_decision)
    is_anomaly = labels == -1

    anoms = df[is_anomaly].copy()
    anoms["ml_score"] = norm_scores[is_anomaly]
    anoms["decision_score"] = raw_decision[is_anomaly]

    alerts: List[Dict[str, Any]] = []
    for _, r in anoms.iterrows():
        dec = float(r["decision_score"])
        sev = round(float(np.clip(0.35 + (-dec / 0.10) * 0.65, 0.35, 1.0)), 4)
        details = {
            "action_count": int(r.get("action_count", 0)),
            "unique_hosts": int(r.get("unique_hosts", 0)),
            "suspicious_process_count": int(r.get("suspicious_process_count", 0)),
            "failed_login_count": int(r.get("failed_login_count", 0)),
            "new_host_count": int(r.get("new_host_count", 0)),
            "anomaly_score": round(float(r["ml_score"]), 4),
            "decision_function": round(dec, 4),
        }
        alerts.append({
            "time_window": r["time_window"],
            "user": r["user"],
            "alert_type": "ML anomaly",
            "anomaly_score": round(float(r["ml_score"]), 4),
            "severity": sev,
            "details": str(details),
        })

    alerts_df = pd.DataFrame(alerts, columns=cols)
    alerts_df.to_csv(out_path, index=False)
    logger.info("Isolation Forest generated %d alerts -> %s", len(alerts_df), out_path)
    return alerts_df


if __name__ == "__main__":
    train_and_predict_ml()
