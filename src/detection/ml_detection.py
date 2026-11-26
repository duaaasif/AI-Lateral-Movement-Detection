"""Unsupervised tabular ML anomaly detection (IsolationForest + OneClassSVM + PyTorch Autoencoder)."""

import glob
import os
import sys
from typing import Any, Dict, List, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler
from sklearn.svm import OneClassSVM
import torch
import torch.nn as nn

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from src.config import load_config
from src.ml.feature_engineering import NUMERIC_FEATURE_COLUMNS
from src.utils.logger import get_logger

logger = get_logger("ml_detection")


class TabularAutoencoder(nn.Module):
    """Symmetric MLP autoencoder for tabular behavioral anomaly detection."""

    def __init__(self, input_dim: int) -> None:
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 16),
            nn.ReLU(),
            nn.Linear(16, 6),
            nn.ReLU(),
        )
        self.decoder = nn.Sequential(
            nn.Linear(6, 16),
            nn.ReLU(),
            nn.Linear(16, input_dim),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.decoder(self.encoder(x))


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


def _train_autoencoder(
    x_train: np.ndarray,
    epochs: int,
    lr: float,
    seed: int,
    batch_size: int = 1024,
) -> TabularAutoencoder:
    torch.manual_seed(seed)
    model = TabularAutoencoder(x_train.shape[1])
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)
    criterion = nn.MSELoss()
    tensor_x = torch.tensor(x_train, dtype=torch.float32)

    model.train()
    n = len(tensor_x)
    for _ in range(epochs):
        perm = torch.randperm(n)
        for start in range(0, n, batch_size):
            batch = tensor_x[perm[start:start + batch_size]]
            optimizer.zero_grad()
            recon = model(batch)
            loss = criterion(recon, batch)
            loss.backward()
            optimizer.step()

    model.eval()
    return model


def _batched_ae_mse(model: TabularAutoencoder, x_scaled: np.ndarray, batch_size: int = 8192) -> np.ndarray:
    errs: List[np.ndarray] = []
    model.eval()
    with torch.no_grad():
        for start in range(0, len(x_scaled), batch_size):
            t = torch.tensor(x_scaled[start:start + batch_size], dtype=torch.float32)
            recon = model(t)
            e = torch.mean((recon - t) ** 2, dim=1).numpy()
            errs.append(e)
    return np.concatenate(errs) if errs else np.zeros(0, dtype=np.float32)


def _normalize_scores(raw_scores: np.ndarray, higher_is_more_anomalous: bool = True) -> np.ndarray:
    arr = raw_scores if higher_is_more_anomalous else -raw_scores
    min_v = float(np.min(arr))
    max_v = float(np.max(arr))
    if max_v - min_v < 1e-9:
        return np.zeros_like(arr, dtype=float)
    return (arr - min_v) / (max_v - min_v)


def train_and_predict_ml(
    feature_csv: str | None = None,
    alert_file: str | None = None,
    retrain: bool = True,
) -> pd.DataFrame:
    """Train (or load) IF + OneClassSVM + Autoencoder ensemble and generate ML alerts."""
    cfg = load_config()
    feat_path = feature_csv or cfg["paths"]["features_file"]
    out_path = alert_file or cfg["paths"]["ml_alerts_file"]
    models_dir = cfg["paths"]["models_dir"]
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    os.makedirs(models_dir, exist_ok=True)

    ml_cfg = cfg["ml"]
    seed = int(ml_cfg["random_state"])
    contamination = float(ml_cfg["contamination"])
    train_ratio = float(ml_cfg.get("train_ratio", 0.7))
    max_svm = int(ml_cfg.get("max_svm_train_samples", 4000))
    max_ae = int(ml_cfg.get("max_ae_train_samples", 25000))

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
    ae_path = os.path.join(models_dir, "ae_model.pt")

    if not retrain and os.path.exists(bundle_path) and os.path.exists(ae_path):
        logger.info("Loading persisted ML models from %s", models_dir)
        bundle = joblib.load(bundle_path)
        scaler = bundle["scaler"]
        iso_forest = bundle["iso_forest"]
        oc_svm = bundle["oc_svm"]
        feature_cols = bundle["feature_cols"]
        ae_threshold = bundle["ae_threshold"]
        X_raw = df[feature_cols].fillna(0.0).values.astype(np.float32)
        X_scaled = scaler.transform(X_raw)

        ae_model = TabularAutoencoder(len(feature_cols))
        ae_model.load_state_dict(torch.load(ae_path, map_location="cpu", weights_only=True))
        ae_model.eval()
    else:
        logger.info("Training ML ensemble (IsolationForest + OneClassSVM + Autoencoder) on %d rows x %d features", len(X_raw), len(feature_cols))
        split_idx = int(len(X_raw) * train_ratio) if len(X_raw) >= 20 else len(X_raw)
        split_idx = max(split_idx, min(len(X_raw), 4))

        scaler = RobustScaler()
        X_train = scaler.fit_transform(X_raw[:split_idx])
        X_scaled = scaler.transform(X_raw)

        X_train_if = _subsample_rows(X_train, max_ae, seed)
        iso_forest = IsolationForest(contamination=contamination, random_state=seed, n_jobs=-1)
        iso_forest.fit(X_train_if)

        X_train_svm = _subsample_rows(X_train, max_svm, seed)
        oc_svm = OneClassSVM(kernel="rbf", nu=min(max(contamination, 0.01), 0.5))
        oc_svm.fit(X_train_svm)

        X_train_ae = _subsample_rows(X_train, max_ae, seed)
        ae_model = _train_autoencoder(
            X_train_ae,
            epochs=int(ml_cfg.get("autoencoder_epochs", 30)),
            lr=float(ml_cfg.get("autoencoder_lr", 0.005)),
            seed=seed,
        )
        train_errs = _batched_ae_mse(ae_model, X_train_ae)
        ae_threshold = float(np.quantile(train_errs, float(ml_cfg.get("autoencoder_threshold_quantile", 0.985))))

        joblib.dump(
            {
                "scaler": scaler,
                "iso_forest": iso_forest,
                "oc_svm": oc_svm,
                "feature_cols": feature_cols,
                "ae_threshold": ae_threshold,
            },
            bundle_path,
        )
        torch.save(ae_model.state_dict(), ae_path)
        logger.info("Saved ML models -> %s & %s", bundle_path, ae_path)

    # Batched scoring for 100k+ windows
    if_labels = iso_forest.predict(X_scaled)
    if_scores = _normalize_scores(iso_forest.decision_function(X_scaled), higher_is_more_anomalous=False)

    svm_labels = oc_svm.predict(X_scaled)
    svm_scores = _normalize_scores(oc_svm.decision_function(X_scaled), higher_is_more_anomalous=False)

    ae_errors = _batched_ae_mse(ae_model, X_scaled)
    ae_flags = (ae_errors > ae_threshold).astype(int)
    ae_scores = _normalize_scores(ae_errors, higher_is_more_anomalous=True)

    ensemble_score = (if_scores + svm_scores + ae_scores) / 3.0
    votes = (if_labels == -1).astype(int) + (svm_labels == -1).astype(int) + ae_flags
    is_anomaly = (votes >= 2) & (ensemble_score >= 0.55)

    anoms = df[is_anomaly].copy()
    anoms["if_score"] = if_scores[is_anomaly]
    anoms["svm_score"] = svm_scores[is_anomaly]
    anoms["ae_score"] = ae_scores[is_anomaly]
    anoms["ml_score"] = ensemble_score[is_anomaly]
    anoms["ml_votes"] = votes[is_anomaly]

    alerts: List[Dict[str, Any]] = []
    for _, r in anoms.iterrows():
        details = {
            "action_count": int(r.get("action_count", 0)),
            "unique_hosts": int(r.get("unique_hosts", 0)),
            "suspicious_process_count": int(r.get("suspicious_process_count", 0)),
            "failed_login_count": int(r.get("failed_login_count", 0)),
            "new_host_count": int(r.get("new_host_count", 0)),
            "ml_score": round(float(r["ml_score"]), 4),
            "if_score": round(float(r["if_score"]), 4),
            "svm_score": round(float(r["svm_score"]), 4),
            "ae_score": round(float(r["ae_score"]), 4),
            "votes": int(r["ml_votes"]),
        }
        alerts.append({
            "time_window": r["time_window"],
            "user": r["user"],
            "alert_type": "ML anomaly",
            "anomaly_score": round(float(r["ml_score"]), 4),
            "severity": round(float(min(1.0, max(0.4, r["ml_score"]))), 4),
            "details": str(details),
        })

    alerts_df = pd.DataFrame(alerts, columns=cols)
    alerts_df.to_csv(out_path, index=False)
    logger.info("ML detection generated %d alerts -> %s", len(alerts_df), out_path)
    return alerts_df


if __name__ == "__main__":
    train_and_predict_ml()
