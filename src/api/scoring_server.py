"""Lightweight local real-time HTTP scoring API (Rules + Isolation Forest)."""

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import sys
from typing import Any, Dict, List

import joblib
import numpy as np
import pandas as pd

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from src.config import load_config
from src.detection.rule_based_detection import evaluate_rules
from src.ml.graph_features import extract_graph_features
from src.utils.logger import get_logger

logger = get_logger("scoring_server")


def score_events(events: List[Dict[str, Any]], cfg: Dict[str, Any] | None = None) -> Dict[str, Any]:
    """Score a batch of raw log event dicts using rules and persisted Isolation Forest."""
    cfg = cfg or load_config()
    if not events:
        return {"event_count": 0, "alerts": [], "max_risk_score": 0.0, "priority": "LOW"}

    df = pd.DataFrame(events)
    for col, default in [
        ("timestamp", pd.Timestamp.now("UTC").isoformat()),
        ("user", ""),
        ("host", ""),
        ("event_id", 0),
        ("process_name", "-"),
        ("command_line", "-"),
        ("source_ip", "-"),
    ]:
        if col not in df.columns:
            df[col] = default

    df["timestamp"] = pd.to_datetime(df["timestamp"], format="mixed", dayfirst=True, errors="coerce")
    df = df.dropna(subset=["timestamp"])
    if df.empty:
        return {"event_count": 0, "alerts": [], "max_risk_score": 0.0, "priority": "LOW"}

    df["event_id"] = pd.to_numeric(df["event_id"], errors="coerce").fillna(0).astype(int)
    df["process_name"] = df["process_name"].fillna("-").astype(str)
    df["command_line"] = df["command_line"].fillna("-").astype(str)
    df["source_ip"] = df["source_ip"].fillna("-").astype(str)

    # 1. Rule-based evaluation
    rule_alerts_df = evaluate_rules(df, cfg)
    alerts: List[Dict[str, Any]] = []
    for _, r in rule_alerts_df.iterrows():
        alerts.append({
            "source": "Rule-based",
            "timestamp": str(r["timestamp"]),
            "user": r["user"],
            "host": r["host"],
            "alert_type": r["alert_type"],
            "severity": float(r["severity"]),
            "details": r["details"],
        })

    # 2. Persisted Isolation Forest scoring (if trained model exists)
    models_dir = cfg["paths"]["models_dir"]
    bundle_path = os.path.join(models_dir, "ml_bundle.joblib")
    ml_max_score = 0.0

    if os.path.exists(bundle_path):
        bundle = joblib.load(bundle_path)
        scaler = bundle["scaler"]
        iso_forest = bundle["iso_forest"]
        feature_cols = bundle["feature_cols"]

        feat_cfg = cfg["features"]
        tw = feat_cfg["time_window"]
        wh_start = int(feat_cfg["work_hours_start"])
        wh_end = int(feat_cfg["work_hours_end"])
        susp_procs = {p.lower() for p in feat_cfg["suspicious_processes"]}
        admin_kws = [k.lower() for k in feat_cfg["admin_share_keywords"]]
        sens_map = {
            h.lower(): {u.lower() for u in users}
            for h, users in cfg["rules"]["sensitive_hosts"].items()
        }
        sens_hosts = set(sens_map.keys())

        work = df.copy()
        work["time_window"] = work["timestamp"].dt.floor(tw)
        work["user_lower"] = work["user"].astype(str).str.strip().str.lower()
        work["proc_lower"] = work["process_name"].str.lower()
        work["cmd_lower"] = work["command_line"].str.lower()
        work["host_lower"] = work["host"].astype(str).str.strip().str.lower()
        work["is_susp"] = (
            work["proc_lower"].isin(susp_procs)
            | work["cmd_lower"].str.contains(r"/etc/shadow|/tmp/\.persist\.sh|\bscp\b.*@", regex=True, na=False)
        ).astype(int)
        work["is_outside"] = ((work["timestamp"].dt.hour < wh_start) | (work["timestamp"].dt.hour >= wh_end)).astype(int)
        work["is_fail"] = (work["event_id"] == 4625).astype(int)
        work["is_admin"] = work["cmd_lower"].apply(lambda c: 1 if any(k in c for k in admin_kws) else 0)
        work["is_sens"] = [
            1 if (h in sens_hosts and u not in sens_map[h]) else 0
            for u, h in zip(work["user_lower"], work["host_lower"])
        ]

        graph_df = extract_graph_features(work, time_window=tw, sensitive_hosts=sens_hosts)

        for (user, tw_val), grp in work.groupby(["user", "time_window"]):
            g_match = graph_df[(graph_df["user"] == user) & (graph_df["time_window"] == tw_val)]
            g_row = g_match.iloc[0].to_dict() if not g_match.empty else {}
            row_feats = {
                "action_count": len(grp),
                "unique_hosts": grp["host"].nunique(),
                "suspicious_process_count": int(grp["is_susp"].sum()),
                "num_source_ips": grp["source_ip"].nunique(),
                "num_unique_commands": grp[grp["command_line"] != "-"]["command_line"].nunique(),
                "outside_work_hours": int(grp["is_outside"].any()),
                "failed_login_count": int(grp["is_fail"].sum()),
                "failed_then_success": int((4625 in grp["event_id"].values) and (4624 in grp["event_id"].values)),
                "new_host_count": int(grp["host"].nunique()),
                "admin_share_count": int(grp["is_admin"].sum()),
                "sensitive_host_count": int(grp["is_sens"].sum()),
                "unique_event_ids": grp["event_id"].nunique(),
                "user_degree": float(g_row.get("user_degree", 1)),
                "user_pagerank": float(g_row.get("user_pagerank", 0.0)),
                "user_betweenness": float(g_row.get("user_betweenness", 0.0)),
                "min_dist_to_sensitive": float(g_row.get("min_dist_to_sensitive", 99)),
                "new_edge_ratio": float(g_row.get("new_edge_ratio", 1.0)),
            }
            vec = np.array([[row_feats.get(c, 0.0) for c in feature_cols]], dtype=np.float32)
            vec_scaled = scaler.transform(vec)
            pred = int(iso_forest.predict(vec_scaled)[0])
            dec = float(iso_forest.decision_function(vec_scaled)[0])
            if pred == -1:
                ml_sev = round(min(1.0, max(0.45, 0.5 - dec)), 4)
                ml_max_score = max(ml_max_score, ml_sev)
                alerts.append({
                    "source": "ML",
                    "timestamp": str(tw_val),
                    "user": user,
                    "host": "",
                    "alert_type": "ML anomaly",
                    "severity": ml_sev,
                    "details": f"IsolationForest decision_function={dec:.4f}",
                })

    max_rule_sev = max([a["severity"] for a in alerts if a["source"] == "Rule-based"], default=0.0)
    risk_score = round(min(100.0, (0.6 * max_rule_sev + 0.4 * ml_max_score) * 100.0), 2)
    thresholds = cfg["ensemble"]["risk_thresholds"]
    if risk_score >= thresholds["CRITICAL"]:
        priority = "CRITICAL"
    elif risk_score >= thresholds["HIGH"]:
        priority = "HIGH"
    elif risk_score >= thresholds["MEDIUM"]:
        priority = "MEDIUM"
    else:
        priority = "LOW"

    return {
        "event_count": len(df),
        "alerts": alerts,
        "max_risk_score": risk_score,
        "priority": priority,
    }


def make_handler(cfg: Dict[str, Any]):
    class ScoringHandler(BaseHTTPRequestHandler):
        def _send_json(self, status: int, payload: Dict[str, Any]) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            if self.path == "/health":
                self._send_json(200, {"status": "ok"})
            else:
                self._send_json(404, {"error": "Not found"})

        def do_POST(self) -> None:
            if self.path != "/score":
                self._send_json(404, {"error": "Not found"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length)
                data = json.loads(raw.decode("utf-8"))
                events = data.get("events", data if isinstance(data, list) else [data])
                result = score_events(events, cfg)
                self._send_json(200, result)
            except Exception as exc:
                self._send_json(400, {"error": str(exc)})

        def log_message(self, format: str, *args: Any) -> None:
            logger.info(format, *args)

    return ScoringHandler


def serve(host: str = "127.0.0.1", port: int = 8080) -> None:
    cfg = load_config()
    server = ThreadingHTTPServer((host, port), make_handler(cfg))
    logger.info("Scoring server listening on http://%s:%d", host, port)
    server.serve_forever()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Local real-time lateral movement scoring API")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    serve(host=args.host, port=args.port)
