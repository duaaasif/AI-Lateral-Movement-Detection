"""Evaluation metrics calculator (Precision, Recall, F1, ROC-AUC, PR-AUC)."""

from datetime import datetime
import json
import os
import sys
from typing import Any, Dict, List

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


def get_model_history_path(cfg: Dict[str, Any] | None = None) -> str:
    """Return path to cumulative model evaluation history JSON."""
    cfg = cfg or load_config()
    paths = cfg["paths"]
    return paths.get("model_history_file") or os.path.join(paths["alerts_dir"], "model_history.json")


def load_model_history(cfg: Dict[str, Any] | None = None) -> List[Dict[str, Any]]:
    """Load persisted list of historical pipeline evaluation runs."""
    path = get_model_history_path(cfg)
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except (OSError, json.JSONDecodeError):
        return []


def clear_model_history(cfg: Dict[str, Any] | None = None) -> Dict[str, Any]:
    """Clear all recorded runs in cumulative model history."""
    path = get_model_history_path(cfg)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump([], f, indent=2)
    return summarize_model_history([])


def record_model_run(
    cfg: Dict[str, Any],
    mode: str,
    source_files: List[str],
    total_events: int,
    evaluated_events: int,
    evaluated_windows: int,
    total_alerts: int,
    rule_alerts: int,
    ml_alerts: int,
    eval_report: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    """Append one completed run's metrics to cumulative model history."""
    eval_report = eval_report or {}
    eval_status = str(eval_report.get("status", "skipped"))
    ens = eval_report.get("ensemble_at_medium_threshold") if eval_status == "evaluated" else None

    now = datetime.now()
    entry: Dict[str, Any] = {
        "run_id": now.strftime("%Y%m%d_%H%M%S_%f"),
        "timestamp": now.strftime("%Y-%m-%d %H:%M:%S"),
        "mode": mode,
        "source_files": list(source_files),
        "total_events": int(total_events),
        "evaluated_events": int(evaluated_events),
        "evaluated_windows": int(evaluated_windows),
        "total_alerts": int(total_alerts),
        "rule_alerts": int(rule_alerts),
        "ml_alerts": int(ml_alerts),
        "eval_status": eval_status if ens else "skipped",
    }
    if ens:
        entry.update({
            "tp": int(ens.get("tp", 0)),
            "fp": int(ens.get("fp", 0)),
            "tn": int(ens.get("tn", 0)),
            "fn": int(ens.get("fn", 0)),
            "accuracy": float(ens.get("accuracy", 0.0)),
            "precision": float(ens.get("precision", 0.0)),
            "recall": float(ens.get("recall", 0.0)),
            "f1": float(ens.get("f1", 0.0)),
            "roc_auc": ens.get("roc_auc"),
            "pr_auc": ens.get("pr_auc"),
            "per_detector": eval_report.get("per_detector", {}),
        })

    history = load_model_history(cfg)
    history.append(entry)
    path = get_model_history_path(cfg)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(history, f, indent=2)
    return entry


def _metrics_from_counts(tp: int, fp: int, tn: int, fn: int) -> Dict[str, Any]:
    total = tp + fp + tn + fn
    acc = (tp + tn) / total if total > 0 else 0.0
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
    return {
        "tp": int(tp),
        "fp": int(fp),
        "tn": int(tn),
        "fn": int(fn),
        "total_windows": int(total),
        "accuracy": round(float(acc), 4),
        "precision": round(float(prec), 4),
        "recall": round(float(rec), 4),
        "f1": round(float(f1), 4),
        "fpr": round(float(fpr), 4),
        "fnr": round(float(fnr), 4),
    }


def summarize_model_history(history: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Compute cumulative (pooled micro) and macro-averaged metrics across all recorded runs."""
    eval_runs = [r for r in history if r.get("eval_status") == "evaluated"]

    tot_tp = sum(int(r.get("tp", 0)) for r in eval_runs)
    tot_fp = sum(int(r.get("fp", 0)) for r in eval_runs)
    tot_tn = sum(int(r.get("tn", 0)) for r in eval_runs)
    tot_fn = sum(int(r.get("fn", 0)) for r in eval_runs)
    cumulative = _metrics_from_counts(tot_tp, tot_fp, tot_tn, tot_fn) if eval_runs else None

    macro: Dict[str, Any] | None = None
    if eval_runs:
        n = len(eval_runs)
        rocs = [float(r["roc_auc"]) for r in eval_runs if r.get("roc_auc") is not None]
        prs = [float(r["pr_auc"]) for r in eval_runs if r.get("pr_auc") is not None]
        macro = {
            "accuracy": round(sum(float(r.get("accuracy", 0.0)) for r in eval_runs) / n, 4),
            "precision": round(sum(float(r.get("precision", 0.0)) for r in eval_runs) / n, 4),
            "recall": round(sum(float(r.get("recall", 0.0)) for r in eval_runs) / n, 4),
            "f1": round(sum(float(r.get("f1", 0.0)) for r in eval_runs) / n, 4),
            "roc_auc": round(sum(rocs) / len(rocs), 4) if rocs else None,
            "pr_auc": round(sum(prs) / len(prs), 4) if prs else None,
        }

    per_detector: Dict[str, Dict[str, Any]] = {}
    for det_name in ("Rule-based", "ML"):
        d_runs = [r["per_detector"][det_name] for r in eval_runs if det_name in (r.get("per_detector") or {})]
        if d_runs:
            per_detector[det_name] = _metrics_from_counts(
                sum(int(d.get("tp", 0)) for d in d_runs),
                sum(int(d.get("fp", 0)) for d in d_runs),
                sum(int(d.get("tn", 0)) for d in d_runs),
                sum(int(d.get("fn", 0)) for d in d_runs),
            )

    return {
        "total_runs": len(history),
        "evaluated_runs": len(eval_runs),
        "unlabeled_runs": len(history) - len(eval_runs),
        "total_events": sum(int(r.get("total_events", 0)) for r in history),
        "total_evaluated_events": sum(int(r.get("evaluated_events", 0)) for r in history),
        "total_evaluated_windows": sum(int(r.get("evaluated_windows", 0)) for r in history),
        "total_alerts": sum(int(r.get("total_alerts", 0)) for r in history),
        "total_rule_alerts": sum(int(r.get("rule_alerts", 0)) for r in history),
        "total_ml_alerts": sum(int(r.get("ml_alerts", 0)) for r in history),
        "cumulative": cumulative,
        "macro_average": macro,
        "per_detector": per_detector,
        "runs": list(reversed(history)),
    }


if __name__ == "__main__":
    evaluate_detections()
