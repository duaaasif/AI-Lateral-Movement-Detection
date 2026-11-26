"""Alert merging, prioritization, and ensemble risk scoring."""

import datetime
import os
import sys
from typing import Any, Dict, List

import pandas as pd

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from src.config import load_config
from src.utils.logger import get_logger

logger = get_logger("merge_alerts")

MERGED_COLUMNS = [
    "time_window",
    "timestamp",
    "user",
    "host",
    "alert_type",
    "details",
    "source",
    "severity",
    "risk_score",
    "priority",
    "detectors_triggered",
]


def _classify_priority(score: float, thresholds: Dict[str, float]) -> str:
    if score >= thresholds.get("CRITICAL", 75):
        return "CRITICAL"
    if score >= thresholds.get("HIGH", 55):
        return "HIGH"
    if score >= thresholds.get("MEDIUM", 35):
        return "MEDIUM"
    return "LOW"


def _load_source_alerts(path: str, source_name: str, time_window: str) -> pd.DataFrame:
    if not os.path.exists(path):
        logger.debug("Alerts file missing for %s: %s", source_name, path)
        return pd.DataFrame()
    df = pd.read_csv(path, low_memory=False)
    if df.empty:
        return pd.DataFrame()

    ts_col = df["timestamp"] if "timestamp" in df.columns else df["time_window"]
    ts_dt = pd.to_datetime(ts_col, errors="coerce")
    if "time_window" in df.columns:
        tw_dt = pd.to_datetime(df["time_window"], errors="coerce")
        tw_dt = tw_dt.fillna(ts_dt.dt.floor(time_window))
    else:
        tw_dt = ts_dt.dt.floor(time_window)
    ts_dt = ts_dt.fillna(tw_dt)

    out = pd.DataFrame({
        "time_window": tw_dt,
        "timestamp": ts_dt,
        "user": df["user"].fillna("").astype(str),
        "host": df["host"].fillna("").astype(str) if "host" in df.columns else "",
        "alert_type": df["alert_type"].fillna(source_name).astype(str) if "alert_type" in df.columns else source_name,
        "details": df["details"].fillna("").astype(str) if "details" in df.columns else "",
        "source": source_name,
        "severity": pd.to_numeric(df.get("severity", 0.65), errors="coerce").fillna(0.65).clip(0.0, 1.0).round(4),
    })
    logger.info("Loaded %d %s alerts", len(out), source_name)
    return out


def merge_and_score_alerts(cfg: Dict[str, Any] | None = None) -> pd.DataFrame:
    """Merge alerts from all detectors, compute ensemble risk scores, and save outputs."""
    cfg = cfg or load_config()
    paths = cfg["paths"]
    time_window = cfg["features"]["time_window"]
    weights = cfg["ensemble"]["weights"]
    thresholds = cfg["ensemble"]["risk_thresholds"]

    parts: List[pd.DataFrame] = [
        _load_source_alerts(paths["ml_alerts_file"], "ML", time_window),
        _load_source_alerts(paths["rule_alerts_file"], "Rule-based", time_window),
        _load_source_alerts(paths["gnn_alerts_file"], "GNN", time_window),
        _load_source_alerts(paths["sequence_alerts_file"], "Sequence", time_window),
    ]
    non_empty = [p for p in parts if not p.empty]

    out_file = paths["all_alerts_file"]
    risk_file = paths["user_risk_file"]
    os.makedirs(os.path.dirname(out_file), exist_ok=True)

    if not non_empty:
        empty_df = pd.DataFrame(columns=MERGED_COLUMNS)
        empty_df.to_csv(out_file, index=False)
        pd.DataFrame(columns=["user", "time_window", "risk_score", "priority", "detectors_triggered", "alert_count"]).to_csv(risk_file, index=False)
        logger.warning("No alerts found to merge.")
        return empty_df

    df = pd.concat(non_empty, ignore_index=True)

    # Max severity per (user, time_window, source)
    src_max = (
        df.groupby(["user", "time_window", "source"], sort=False)["severity"]
        .max()
        .reset_index()
    )
    src_max["weighted"] = src_max["source"].map(lambda s: float(weights.get(s, 0.2))) * src_max["severity"]

    win_stats = (
        df.groupby(["user", "time_window"], sort=False)
        .agg(
            alert_count=("alert_type", "size"),
            distinct_types=("alert_type", "nunique"),
        )
        .reset_index()
    )
    src_agg = (
        src_max.groupby(["user", "time_window"], sort=False)
        .agg(
            weighted_sum=("weighted", "sum"),
            detectors_triggered=("source", lambda s: ",".join(sorted(s.unique()))),
            n_sources=("source", "nunique"),
        )
        .reset_index()
    )

    risk_df = win_stats.merge(src_agg, on=["user", "time_window"], how="inner")
    agreement_bonus = 0.15 * (risk_df["n_sources"] - 1).clip(lower=0) + 0.08 * (risk_df["distinct_types"] - 1).clip(lower=0)
    raw_risk = (risk_df["weighted_sum"] + agreement_bonus).clip(0.0, 1.0)
    risk_df["risk_score"] = (raw_risk * 100.0).round(2)
    risk_df["priority"] = risk_df["risk_score"].map(lambda sc: _classify_priority(sc, thresholds))
    risk_out = risk_df[["user", "time_window", "risk_score", "priority", "detectors_triggered", "alert_count"]].sort_values(
        ["risk_score", "time_window"], ascending=[False, True]
    )

    df = df.merge(
        risk_out[["user", "time_window", "risk_score", "priority", "detectors_triggered"]],
        on=["user", "time_window"],
        how="left",
    )
    df = df.sort_values(["time_window", "risk_score"], ascending=[True, False]).reset_index(drop=True)

    try:
        df.to_csv(out_file, index=False)
        logger.info("Merged %d alerts -> %s", len(df), out_file)
    except (PermissionError, OSError):
        backup = out_file.replace(".csv", f"_backup_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
        df.to_csv(backup, index=False)
        logger.warning("Target locked; saved merged alerts -> %s", backup)

    risk_out.to_csv(risk_file, index=False)
    logger.info("Saved %d user-window risk scores -> %s", len(risk_out), risk_file)

    return df


if __name__ == "__main__":
    merge_and_score_alerts()
