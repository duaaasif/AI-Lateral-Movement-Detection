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
    "alert_id",
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
    ]
    non_empty = [p for p in parts if not p.empty]

    out_file = paths["all_alerts_file"]
    risk_file = paths["user_risk_file"]
    os.makedirs(os.path.dirname(out_file), exist_ok=True)

    if not non_empty:
        empty_df = pd.DataFrame(columns=MERGED_COLUMNS)
        empty_df.to_csv(out_file, index=False)
        pd.DataFrame(columns=["alert_id", "user", "time_window", "risk_score", "priority", "detectors_triggered", "alert_count", "summary"]).to_csv(risk_file, index=False)
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

    # Attach behavioral window features (counts, hosts, failed logins, cmds) for ML-only counts & collective summary
    feat_lookup: Dict[tuple, Dict[str, int]] = {}
    feat_cols = {
        "user",
        "time_window",
        "action_count",
        "unique_hosts",
        "failed_login_count",
        "suspicious_process_count",
        "num_unique_commands",
        "num_source_ips",
        "sensitive_host_count",
    }
    feat_file = paths.get("features_file")
    if feat_file and os.path.exists(feat_file):
        try:
            fdf = pd.read_csv(feat_file, usecols=lambda c: c in feat_cols, low_memory=False)
            if {"user", "time_window", "action_count"}.issubset(fdf.columns):
                fdf["user"] = fdf["user"].fillna("").astype(str)
                fdf["time_window"] = pd.to_datetime(fdf["time_window"], errors="coerce").dt.floor(time_window)
                for c in feat_cols - {"user", "time_window"}:
                    if c in fdf.columns:
                        fdf[c] = pd.to_numeric(fdf[c], errors="coerce").fillna(0).astype(int)
                fdf = fdf.dropna(subset=["time_window"]).drop_duplicates(subset=["user", "time_window"])
                for _, fr in fdf.iterrows():
                    feat_lookup[(fr["user"], fr["time_window"])] = {
                        c: int(fr[c]) for c in (feat_cols - {"user", "time_window"}) if c in fdf.columns
                    }
                risk_df = risk_df.merge(fdf[["user", "time_window", "action_count"]], on=["user", "time_window"], how="left")
                ml_only_mask = (risk_df["detectors_triggered"] == "ML") & risk_df["action_count"].notna()
                risk_df.loc[ml_only_mask, "alert_count"] = (
                    risk_df.loc[ml_only_mask, "action_count"].astype(int).clip(lower=1)
                )
                risk_df = risk_df.drop(columns=["action_count"])
        except Exception as exc:
            logger.debug("Could not attach feature summary columns: %s", exc)

    # Build collective summary of actions & triggers per (user, time_window)
    summaries: Dict[tuple, str] = {}
    for (usr, tw), grp in df.groupby(["user", "time_window"], sort=False):
        finfo = feat_lookup.get((str(usr), tw), {})
        hosts_raw = [h.strip() for raw_h in grp["host"].dropna().astype(str) for h in raw_h.split(",") if h.strip() and h.strip() != "-"]
        uniq_rule_hosts = sorted(set(hosts_raw))

        # Window-wide activity & indicator counts
        act_parts: List[str] = []
        n_act = finfo.get("action_count")
        n_hosts = finfo.get("unique_hosts") or len(uniq_rule_hosts)
        if n_act:
            host_txt = f" across {n_hosts} host{'s' if n_hosts != 1 else ''}" if n_hosts else ""
            if uniq_rule_hosts and len(uniq_rule_hosts) <= 4:
                host_txt += f" ({', '.join(uniq_rule_hosts)})"
            act_parts.append(f"{n_act} events{host_txt}")
        elif uniq_rule_hosts:
            shown = ", ".join(uniq_rule_hosts[:4]) + ("..." if len(uniq_rule_hosts) > 4 else "")
            act_parts.append(f"Hosts: {shown}")

        ind_parts: List[str] = []
        for col_name, label in (
            ("failed_login_count", "failed logins"),
            ("num_source_ips", "src IPs"),
            ("suspicious_process_count", "susp procs"),
            ("num_unique_commands", "cmds"),
            ("sensitive_host_count", "sensitive hits"),
        ):
            val = finfo.get(col_name, 0)
            if val > 0:
                ind_parts.append(f"{val} {label}")

        # Collective trigger breakdown
        rule_grp = grp[grp["source"] == "Rule-based"]
        has_ml = bool((grp["source"] == "ML").any())
        trig_parts: List[str] = []
        if not rule_grp.empty:
            vc = rule_grp["alert_type"].value_counts()
            trig_parts.append("Triggers: " + ", ".join(f"{t} ({c})" for t, c in vc.items()))
        if has_ml:
            if rule_grp.empty:
                trig_parts.append("ML behavioral anomaly (no static rule match)")
            else:
                trig_parts.append("+ ML anomaly")

        head = " — ".join(filter(None, [" ".join(act_parts), ", ".join(ind_parts) if ind_parts else ""]))
        tail = " ".join(trig_parts)
        summaries[(str(usr), tw)] = " | ".join(filter(None, [head, tail])) or f"{len(grp)} alert triggers"

    risk_df["summary"] = [summaries.get((str(r["user"]), r["time_window"]), "") for _, r in risk_df.iterrows()]
    agreement_bonus = 0.15 * (risk_df["n_sources"] - 1).clip(lower=0) + 0.08 * (risk_df["distinct_types"] - 1).clip(lower=0)
    raw_risk = (risk_df["weighted_sum"] + agreement_bonus).clip(0.0, 1.0)
    risk_df["risk_score"] = (raw_risk * 100.0).round(2)
    risk_df["priority"] = risk_df["risk_score"].map(lambda sc: _classify_priority(sc, thresholds))
    risk_out = risk_df[["user", "time_window", "risk_score", "priority", "detectors_triggered", "alert_count", "summary"]].sort_values(
        ["risk_score", "time_window"], ascending=[False, True]
    ).reset_index(drop=True)
    risk_out.insert(0, "alert_id", [f"ALT-{i:04d}" for i in range(1, len(risk_out) + 1)])

    df = df.merge(
        risk_out[["alert_id", "user", "time_window", "risk_score", "priority", "detectors_triggered"]],
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
