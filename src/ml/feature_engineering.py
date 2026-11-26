"""Vectorized behavioral, identity, host, and graph feature engineering."""

import datetime
import os
import re
import sys

import numpy as np
import pandas as pd

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from src.config import load_config
from src.ml.graph_features import extract_graph_features
from src.utils.logger import get_logger

logger = get_logger("feature_engineering")

NUMERIC_FEATURE_COLUMNS = [
    "action_count",
    "unique_hosts",
    "suspicious_process_count",
    "num_source_ips",
    "num_unique_commands",
    "outside_work_hours",
    "failed_login_count",
    "failed_then_success",
    "new_host_count",
    "admin_share_count",
    "sensitive_host_count",
    "unique_event_ids",
    "user_degree",
    "user_pagerank",
    "user_betweenness",
    "min_dist_to_sensitive",
    "new_edge_ratio",
]


def build_features(
    input_csv: str | None = None,
    output_csv: str | None = None,
) -> pd.DataFrame:
    """Extract per-user per-window behavioral + graph features from clean logs."""
    cfg = load_config()
    in_path = input_csv or cfg["paths"]["processed_file"]
    out_path = output_csv or cfg["paths"]["features_file"]
    gt_path = cfg["paths"].get("ground_truth_file")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)

    feat_cfg = cfg["features"]
    time_window = feat_cfg["time_window"]
    wh_start = int(feat_cfg["work_hours_start"])
    wh_end = int(feat_cfg["work_hours_end"])
    suspicious_procs = {p.lower() for p in feat_cfg["suspicious_processes"]}
    admin_keywords = [k.lower() for k in feat_cfg["admin_share_keywords"]]
    sensitive_hosts = {h.lower() for h in cfg["rules"]["sensitive_hosts"].keys()}

    logger.info("Loading cleaned logs from %s", in_path)
    df = pd.read_csv(in_path, low_memory=False)
    if df.empty:
        empty_cols = ["user", "time_window"] + NUMERIC_FEATURE_COLUMNS
        empty_df = pd.DataFrame(columns=empty_cols)
        empty_df.to_csv(out_path, index=False)
        logger.warning("Input logs empty; saved empty feature table to %s", out_path)
        return empty_df

    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df["time_window"] = df["timestamp"].dt.floor(time_window)
    df["event_id"] = pd.to_numeric(df["event_id"], errors="coerce").fillna(0).astype(int)
    df["process_lower"] = df["process_name"].fillna("-").astype(str).str.lower()
    df["cmd_str"] = df["command_line"].fillna("-").astype(str)
    df["cmd_lower"] = df["cmd_str"].str.lower()
    df["host_lower"] = df["host"].fillna("").astype(str).str.lower()

    # Precompute vectorized binary event flags
    df["is_susp_proc"] = df["process_lower"].isin(suspicious_procs).astype(np.int8)
    df["is_outside"] = ((df["timestamp"].dt.hour < wh_start) | (df["timestamp"].dt.hour >= wh_end)).astype(np.int8)
    df["is_failed"] = (df["event_id"] == 4625).astype(np.int8)
    df["is_sensitive"] = df["host_lower"].isin(sensitive_hosts).astype(np.int8)

    admin_regex = "|".join(re.escape(kw) for kw in admin_keywords)
    df["is_admin_share"] = (
        (df["event_id"] == 5140)
        | (df["cmd_lower"].str.contains(admin_regex, regex=True, na=False))
    ).astype(np.int8)

    # New host flag via vectorized first-seen time window per (user, host)
    first_tw = df.groupby(["user", "host_lower"], sort=False)["time_window"].transform("min")
    df["is_new_host_ev"] = (df["time_window"] == first_tw).astype(np.int8)

    # Valid commands for unique command count
    df["valid_cmd"] = df["cmd_str"].where(df["cmd_str"] != "-", other=np.nan)

    # Single vectorized aggregation over (user, time_window)
    feature_table = (
        df.groupby(["user", "time_window"], sort=False)
        .agg(
            action_count=("timestamp", "size"),
            unique_hosts=("host_lower", "nunique"),
            suspicious_process_count=("is_susp_proc", "sum"),
            num_source_ips=("source_ip", "nunique"),
            num_unique_commands=("valid_cmd", "nunique"),
            outside_work_hours=("is_outside", "max"),
            failed_login_count=("is_failed", "sum"),
            admin_share_count=("is_admin_share", "sum"),
            sensitive_host_count=("is_sensitive", "sum"),
            unique_event_ids=("event_id", "nunique"),
        )
        .reset_index()
    )

    # Vectorized new_host_count: unique hosts in window whose first_seen window equals this window
    new_host_df = (
        df[df["is_new_host_ev"] == 1]
        .groupby(["user", "time_window"], sort=False)["host_lower"]
        .nunique()
        .reset_index(name="new_host_count")
    )
    feature_table = feature_table.merge(new_host_df, on=["user", "time_window"], how="left")

    # Vectorized failed_then_success: only inspect windows containing 4625 events
    auth_df = df[df["event_id"].isin([4624, 4625])]
    if not auth_df.empty:
        fails = (
            auth_df[auth_df["event_id"] == 4625]
            .groupby(["user", "time_window"], sort=False)["timestamp"]
            .min()
            .reset_index(name="min_fail_ts")
        )
        succs = (
            auth_df[auth_df["event_id"] == 4624]
            .groupby(["user", "time_window"], sort=False)["timestamp"]
            .max()
            .reset_index(name="max_succ_ts")
        )
        fts = fails.merge(succs, on=["user", "time_window"], how="inner")
        fts["failed_then_success"] = (fts["min_fail_ts"] < fts["max_succ_ts"]).astype(int)
        feature_table = feature_table.merge(
            fts[["user", "time_window", "failed_then_success"]],
            on=["user", "time_window"],
            how="left",
        )
    else:
        feature_table["failed_then_success"] = 0

    # Merge NetworkX graph features
    graph_df = extract_graph_features(
        df, time_window=time_window, sensitive_hosts=sensitive_hosts
    )
    feature_table = feature_table.merge(graph_df, on=["user", "time_window"], how="left")

    for col in NUMERIC_FEATURE_COLUMNS:
        if col in ("user_pagerank", "user_betweenness", "new_edge_ratio"):
            feature_table[col] = feature_table[col].fillna(0.0).astype(float)
        else:
            feature_table[col] = feature_table[col].fillna(0).astype(int)

    # Preserve ground-truth label ONLY for evaluation (never fed into ML training)
    if "is_attack" in df.columns:
        gt = (
            df.groupby(["user", "time_window"], sort=False)["is_attack"]
            .max()
            .reset_index(name="is_attack")
        )
        feature_table = feature_table.merge(gt, on=["user", "time_window"], how="left")
        feature_table["is_attack"] = feature_table["is_attack"].fillna(0).astype(int)
    elif gt_path:
        candidate_gts = [gt_path]
        sample_gt = os.path.join(cfg["base_dir"], "data", "upload_samples", "ground_truth_samples.csv")
        if os.path.exists(sample_gt):
            candidate_gts.append(sample_gt)
        gt_frames = []
        for gpath in candidate_gts:
            if os.path.exists(gpath):
                gt_raw = pd.read_csv(gpath)
                if not gt_raw.empty and {"user", "time_window", "is_attack"}.issubset(gt_raw.columns):
                    gt_raw["time_window"] = pd.to_datetime(gt_raw["time_window"]).dt.floor(time_window)
                    gt_frames.append(gt_raw[["user", "time_window", "is_attack"]])
        if gt_frames:
            gt_all = pd.concat(gt_frames, ignore_index=True)
            gt_clean = (
                gt_all.groupby(["user", "time_window"], sort=False)["is_attack"]
                .max()
                .reset_index(name="is_attack")
            )
            feature_table = feature_table.merge(gt_clean, on=["user", "time_window"], how="left")
            feature_table["is_attack"] = feature_table["is_attack"].fillna(0).astype(int)

    feature_table = feature_table.sort_values(["time_window", "user"]).reset_index(drop=True)

    try:
        feature_table.to_csv(out_path, index=False)
        logger.info("Feature table (%d rows) saved -> %s", len(feature_table), out_path)
    except (PermissionError, OSError):
        backup_file = out_path.replace(
            ".csv",
            f"_backup_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
        )
        feature_table.to_csv(backup_file, index=False)
        logger.warning("Target locked; saved backup feature table -> %s", backup_file)

    return feature_table


if __name__ == "__main__":
    build_features()
