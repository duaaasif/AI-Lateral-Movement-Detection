"""Vectorized rule-based lateral movement detection engine."""

import os
import re
import sys
from typing import Any, Dict, List

import numpy as np
import pandas as pd

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from src.config import load_config
from src.utils.logger import get_logger

logger = get_logger("rule_based_detection")

ALERT_COLUMNS = ["timestamp", "user", "host", "alert_type", "details", "severity"]


def evaluate_rules(logs: pd.DataFrame, cfg: Dict[str, Any] | None = None) -> pd.DataFrame:
    """Apply all configured lateral movement detection rules on cleaned logs (vectorized)."""
    cfg = cfg or load_config()
    if logs.empty:
        return pd.DataFrame(columns=ALERT_COLUMNS)

    df = logs.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df["user_norm"] = df["user"].fillna("").astype(str).str.strip()
    df["host_norm"] = df["host"].fillna("").astype(str).str.strip()
    df["host_lower"] = df["host_norm"].str.lower()
    df["proc_lower"] = df["process_name"].fillna("-").astype(str).str.lower()
    df["cmd_str"] = df["command_line"].fillna("-").astype(str)
    df["cmd_lower"] = df["cmd_str"].str.lower()
    df["event_id"] = pd.to_numeric(df["event_id"], errors="coerce").fillna(0).astype(int)

    rules_cfg = cfg["rules"]
    feat_cfg = cfg["features"]
    severities = rules_cfg.get("severities", {})

    multi_host_ns = int(rules_cfg["multi_host_window_minutes"]) * 60 * 1_000_000_000
    fail_threshold = int(rules_cfg["failed_login_burst_threshold"])
    fail_ns = int(rules_cfg["failed_login_window_minutes"]) * 60 * 1_000_000_000
    wh_start = int(feat_cfg["work_hours_start"])
    wh_end = int(feat_cfg["work_hours_end"])
    suspicious_procs = {p.lower() for p in feat_cfg["suspicious_processes"]}
    admin_keywords = [k.lower() for k in feat_cfg["admin_share_keywords"]]
    sensitive_map = {
        h.lower(): {u.lower() for u in users}
        for h, users in rules_cfg["sensitive_hosts"].items()
    }
    sensitive_hosts_set = set(sensitive_map.keys())

    alert_frames: List[pd.DataFrame] = []

    def _make_frame(sub: pd.DataFrame, alert_type: str, details_series: pd.Series) -> pd.DataFrame:
        if sub.empty:
            return pd.DataFrame(columns=ALERT_COLUMNS)
        return pd.DataFrame({
            "timestamp": sub["timestamp"].values,
            "user": sub["user_norm"].values,
            "host": sub["host_norm"].values,
            "alert_type": alert_type,
            "details": details_series.values,
            "severity": float(severities.get(alert_type, 0.7)),
        })

    # Rule 2 (Vectorized): Login outside working hours (4624)
    off_mask = (df["event_id"] == 4624) & ((df["timestamp"].dt.hour < wh_start) | (df["timestamp"].dt.hour >= wh_end))
    if off_mask.any():
        sub = df[off_mask]
        details = "User logged in at " + sub["timestamp"].dt.strftime("%H:%M:%S") + f" (outside {wh_start:02d}:00-{wh_end:02d}:00)"
        alert_frames.append(_make_frame(sub, "Login outside working hours", details))

    # Rule 3 (Vectorized, null-safe): Remote / suspicious process creation (4688)
    proc_mask = (df["event_id"] == 4688) & df["proc_lower"].isin(suspicious_procs)
    if proc_mask.any():
        sub = df[proc_mask]
        details = "User ran " + sub["process_name"].fillna("-").astype(str) + ": " + sub["cmd_str"]
        alert_frames.append(_make_frame(sub, "Remote process creation", details))

    # Rule 4 (Vectorized, config-driven): Unauthorized sensitive host access
    sens_mask = df["host_lower"].isin(sensitive_hosts_set)
    if sens_mask.any():
        sub_s = df[sens_mask]
        unauth_idx = [
            idx
            for idx, u_low, h_low in zip(sub_s.index, sub_s["user_norm"].str.lower(), sub_s["host_lower"])
            if u_low not in sensitive_map[h_low]
        ]
        if unauth_idx:
            sub = df.loc[unauth_idx]
            details = "Unauthorized user '" + sub["user_norm"] + "' accessed sensitive host '" + sub["host_norm"] + "'"
            alert_frames.append(_make_frame(sub, "Sensitive host access", details))

    # Rule 6 (Vectorized): Admin share / SMB lateral movement indicators
    admin_regex = "|".join(re.escape(kw) for kw in admin_keywords)
    share_mask = (
        (df["event_id"] == 5140)
        | ((df["cmd_str"] != "-") & df["cmd_lower"].str.contains(admin_regex, regex=True, na=False))
    )
    if share_mask.any():
        sub = df[share_mask]
        details = "Suspicious share/SMB activity: " + sub["cmd_str"]
        alert_frames.append(_make_frame(sub, "Admin share access", details))

    # Rule 1 (Transition-filtered per user): Multiple hosts in short time
    # Check only auth/process/share events and host transitions to avoid scanning identical repeats
    hop_candidates = df[df["event_id"].isin([4624, 4648, 4688, 5140])].sort_values(["user_norm", "timestamp"])
    if not hop_candidates.empty:
        # Keep only rows where host changed compared to previous row for the same user
        prev_user = hop_candidates["user_norm"].shift(1)
        prev_host = hop_candidates["host_lower"].shift(1)
        trans = hop_candidates[(hop_candidates["user_norm"] != prev_user) | (hop_candidates["host_lower"] != prev_host)]

        rule1_rows: List[Dict[str, Any]] = []
        sev1 = float(severities.get("Multiple hosts in short time", 0.75))
        for user, grp in trans.groupby("user_norm", sort=False):
            ts_arr = grp["timestamp"].values.astype("datetime64[ns]").astype("int64")
            h_arr = grp["host_norm"].values
            hl_arr = grp["host_lower"].values
            u_low = user.lower()
            recent: List[tuple] = []

            for i in range(len(ts_arr)):
                t_ns = int(ts_arr[i])
                h = str(h_arr[i])
                hl = str(hl_arr[i])
                cutoff = t_ns - multi_host_ns
                recent = [(rh, rt) for rh, rt in recent if rt >= cutoff]
                prev_hosts = {rh for rh, _ in recent if rh != h}
                # Trigger when >=2 distinct prior hosts (3+ total hosts in 10 min) OR touching an unauthorized sensitive host after another host
                is_unauth_sens = (hl in sensitive_hosts_set) and (u_low not in sensitive_map.get(hl, set()))
                if len(prev_hosts) >= 2 or (len(prev_hosts) >= 1 and is_unauth_sens):
                    rule1_rows.append({
                        "timestamp": pd.Timestamp(t_ns),
                        "user": user,
                        "host": h,
                        "alert_type": "Multiple hosts in short time",
                        "details": f"User accessed {h} after {sorted(prev_hosts)} within {rules_cfg['multi_host_window_minutes']} min",
                        "severity": sev1,
                    })
                recent.append((h, t_ns))

        if rule1_rows:
            alert_frames.append(pd.DataFrame(rule1_rows, columns=ALERT_COLUMNS))

    # Rule 5 (Filtered per user with >= fail_threshold 4625 events): Failed login burst before success
    fail_counts = df[df["event_id"] == 4625].groupby("user_norm").size()
    burst_users = set(fail_counts[fail_counts >= fail_threshold].index)
    if burst_users:
        auth_sub = df[df["user_norm"].isin(burst_users) & df["event_id"].isin([4624, 4625])].sort_values(["user_norm", "timestamp"])
        rule5_rows: List[Dict[str, Any]] = []
        sev5 = float(severities.get("Failed login burst before success", 0.85))
        for user, grp in auth_sub.groupby("user_norm", sort=False):
            ts_arr = grp["timestamp"].values.astype("datetime64[ns]").astype("int64")
            eid_arr = grp["event_id"].values
            h_arr = grp["host_norm"].values
            recent_fails: List[int] = []
            for t_ns, eid, h in zip(ts_arr, eid_arr, h_arr):
                t_int = int(t_ns)
                cutoff = t_int - fail_ns
                if eid == 4625:
                    recent_fails = [ft for ft in recent_fails if ft >= cutoff]
                    recent_fails.append(t_int)
                elif eid == 4624:
                    recent_fails = [ft for ft in recent_fails if ft >= cutoff]
                    if len(recent_fails) >= fail_threshold:
                        rule5_rows.append({
                            "timestamp": pd.Timestamp(t_int),
                            "user": user,
                            "host": str(h),
                            "alert_type": "Failed login burst before success",
                            "details": f"{len(recent_fails)} failed logins followed by successful logon",
                            "severity": sev5,
                        })
                        recent_fails = []
        if rule5_rows:
            alert_frames.append(pd.DataFrame(rule5_rows, columns=ALERT_COLUMNS))

    if not alert_frames:
        return pd.DataFrame(columns=ALERT_COLUMNS)

    alerts_df = pd.concat(alert_frames, ignore_index=True)
    alerts_df = alerts_df.sort_values("timestamp").reset_index(drop=True)
    return alerts_df


def run_rule_detection(
    clean_logs_path: str | None = None,
    output_file: str | None = None,
) -> pd.DataFrame:
    """Load clean logs, evaluate rules, and save rule alerts."""
    cfg = load_config()
    in_path = clean_logs_path or cfg["paths"]["processed_file"]
    out_path = output_file or cfg["paths"]["rule_alerts_file"]
    os.makedirs(os.path.dirname(out_path), exist_ok=True)

    logs = pd.read_csv(in_path, low_memory=False)
    alerts_df = evaluate_rules(logs, cfg)
    alerts_df.to_csv(out_path, index=False)
    logger.info("Rule-based detection generated %d alerts -> %s", len(alerts_df), out_path)
    return alerts_df


if __name__ == "__main__":
    run_rule_detection()
