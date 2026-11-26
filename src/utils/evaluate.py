"""Evaluation metrics calculator (Precision, Recall, F1, ROC-AUC, PR-AUC)."""

import json
import os
import sys
from typing import Any, Dict

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from src.config import load_config
from src.utils.logger import get_logger

logger = get_logger("evaluate")


def _binary_metrics(y_true: np.ndarray, y_pred: np.ndarray, y_score: np.ndarray | None = None) -> Dict[str, Any]:
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = [int(v) for v in cm.ravel()]
    res: Dict[str, Any] = {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
        "f1": round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
    }
    if y_score is not None and len(np.unique(y_true)) == 2:
        res["roc_auc"] = round(float(roc_auc_score(y_true, y_score)), 4)
        res["pr_auc"] = round(float(average_precision_score(y_true, y_score)), 4)
    return res


def evaluate_detections(cfg: Dict[str, Any] | None = None) -> Dict[str, Any]:
    """Evaluate window-level detection quality against ground-truth labels if present."""
    cfg = cfg or load_config()
    paths = cfg["paths"]

    feat_df = pd.read_csv(paths["features_file"])
    report_path = paths["eval_report_file"]
    os.makedirs(os.path.dirname(report_path), exist_ok=True)

    if feat_df.empty or "is_attack" not in feat_df.columns:
        report = {"status": "skipped", "reason": "Ground-truth 'is_attack' column not present."}
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        logger.info("Evaluation skipped (no ground-truth labels).")
        return report

    feat_df["time_window"] = pd.to_datetime(feat_df["time_window"])
    alerts_df = pd.read_csv(paths["all_alerts_file"]) if os.path.exists(paths["all_alerts_file"]) else pd.DataFrame()
    risk_df = pd.read_csv(paths["user_risk_file"]) if os.path.exists(paths["user_risk_file"]) else pd.DataFrame()

    if not alerts_df.empty:
        alerts_df["time_window"] = pd.to_datetime(alerts_df["time_window"])
    if not risk_df.empty:
        risk_df["time_window"] = pd.to_datetime(risk_df["time_window"])

    merged = feat_df[["user", "time_window", "is_attack"]].copy()
    if not risk_df.empty:
        merged = merged.merge(risk_df[["user", "time_window", "risk_score"]], on=["user", "time_window"], how="left")
    else:
        merged["risk_score"] = 0.0
    merged["risk_score"] = merged["risk_score"].fillna(0.0)

    medium_thresh = float(cfg["ensemble"]["risk_thresholds"].get("MEDIUM", 35))
    y_true = merged["is_attack"].astype(int).values
    y_score = (merged["risk_score"].values / 100.0)
    y_pred_ensemble = (merged["risk_score"].values >= medium_thresh).astype(int)
    y_pred_any = (merged["risk_score"].values > 0).astype(int)

    report: Dict[str, Any] = {
        "status": "evaluated",
        "total_windows": int(len(merged)),
        "attack_windows": int(y_true.sum()),
        "benign_windows": int((1 - y_true).sum()),
        "ensemble_at_medium_threshold": _binary_metrics(y_true, y_pred_ensemble, y_score),
        "any_detector_alert": _binary_metrics(y_true, y_pred_any, y_score),
        "per_detector": {},
    }

    if not alerts_df.empty:
        for src in ["Rule-based", "ML"]:
            src_wins = set(
                zip(
                    alerts_df[alerts_df["source"] == src]["user"],
                    alerts_df[alerts_df["source"] == src]["time_window"],
                )
            )
            y_src = np.array([1 if (u, tw) in src_wins else 0 for u, tw in zip(merged["user"], merged["time_window"])])
            report["per_detector"][src] = _binary_metrics(y_true, y_src)

    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    ens = report["ensemble_at_medium_threshold"]
    logger.info(
        "Evaluation complete -> Precision=%.3f Recall=%.3f F1=%.3f ROC-AUC=%s (saved %s)",
        ens["precision"],
        ens["recall"],
        ens["f1"],
        ens.get("roc_auc", "N/A"),
        report_path,
    )
    return report


if __name__ == "__main__":
    evaluate_detections()
