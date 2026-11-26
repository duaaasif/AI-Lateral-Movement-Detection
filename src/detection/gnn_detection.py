"""Vectorized Graph Neural Network (PyTorch Geometric SAGEConv) lateral movement detector."""

import os
import sys
from typing import Any, Dict, List, Tuple

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch_geometric.data import Data
from torch_geometric.nn import SAGEConv

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from src.config import load_config
from src.ml.graph_features import build_user_host_graph
from src.utils.logger import get_logger

logger = get_logger("gnn_detection")

GNN_ALERT_COLUMNS = [
    "time_window",
    "timestamp",
    "user",
    "host",
    "alert_type",
    "anomaly_score",
    "severity",
    "details",
]


class GraphSAGEAutoencoder(nn.Module):
    """Two-layer GraphSAGE encoder + node feature decoder for bipartite anomaly scoring."""

    def __init__(self, in_channels: int, hidden_channels: int = 16, latent_channels: int = 8) -> None:
        super().__init__()
        self.conv1 = SAGEConv(in_channels, hidden_channels)
        self.conv2 = SAGEConv(hidden_channels, latent_channels)
        self.decoder = nn.Sequential(
            nn.Linear(latent_channels, hidden_channels),
            nn.ReLU(),
            nn.Linear(hidden_channels, in_channels),
        )

    def encode(self, x: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        h = torch.relu(self.conv1(x, edge_index))
        return self.conv2(h, edge_index)

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        z = self.encode(x, edge_index)
        x_hat = self.decoder(z)
        return x_hat, z


def _build_pyg_data(
    work: pd.DataFrame,
    cfg: Dict[str, Any],
) -> Tuple[Data, List[str], Dict[str, int]]:
    sensitive_hosts = {h.lower() for h in cfg["rules"]["sensitive_hosts"].keys()}
    graph, _ = build_user_host_graph(work, sensitive_hosts=sensitive_hosts)
    nodes = list(graph.nodes())
    node_idx = {n: i for i, n in enumerate(nodes)}

    # Vectorized node-level statistics via groupby
    user_stats = (
        work.groupby("user", sort=False)
        .agg(susp=("is_susp", "mean"), off=("is_off", "mean"), fail=("is_fail", "mean"))
        .to_dict("index")
    )
    host_stats = (
        work.groupby("host", sort=False)
        .agg(susp=("is_susp", "mean"), off=("is_off", "mean"), fail=("is_fail", "mean"))
        .to_dict("index")
    )
    max_deg = max([d for _, d in graph.degree()], default=1)

    features = []
    for n in nodes:
        is_user = 1.0 if n.startswith("user:") else 0.0
        is_host = 1.0 - is_user
        is_sens = float(graph.nodes[n].get("is_sensitive", 0))
        deg_norm = graph.degree(n) / max(max_deg, 1)
        raw_name = n.split(":", 1)[1]
        st = user_stats.get(raw_name, {}) if is_user else host_stats.get(raw_name, {})

        edge_weights = [graph[n][nbr]["weight"] for nbr in graph.neighbors(n)]
        avg_w = float(np.mean(edge_weights)) if edge_weights else 0.0
        features.append([
            is_user,
            is_host,
            is_sens,
            deg_norm,
            float(st.get("susp", 0.0)),
            float(st.get("off", 0.0)),
            float(st.get("fail", 0.0)) + 0.05 * min(avg_w, 10.0),
        ])

    x = torch.tensor(features, dtype=torch.float32) if features else torch.zeros((0, 7), dtype=torch.float32)
    edges = []
    for u, v in graph.edges():
        ui, vi = node_idx[u], node_idx[v]
        edges.append([ui, vi])
        edges.append([vi, ui])
    edge_index = (
        torch.tensor(edges, dtype=torch.long).t().contiguous()
        if edges
        else torch.zeros((2, 0), dtype=torch.long)
    )

    return Data(x=x, edge_index=edge_index), nodes, node_idx


def run_gnn_detection(
    clean_logs_path: str | None = None,
    output_file: str | None = None,
    retrain: bool = True,
) -> pd.DataFrame:
    """Train/load GraphSAGE autoencoder and detect anomalous user-host lateral edges."""
    cfg = load_config()
    in_path = clean_logs_path or cfg["paths"]["processed_file"]
    out_path = output_file or cfg["paths"]["gnn_alerts_file"]
    models_dir = cfg["paths"]["models_dir"]
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    os.makedirs(models_dir, exist_ok=True)

    logs = pd.read_csv(in_path, low_memory=False)
    if logs.empty or len(logs) < 2:
        empty_df = pd.DataFrame(columns=GNN_ALERT_COLUMNS)
        empty_df.to_csv(out_path, index=False)
        return empty_df

    ml_cfg = cfg["ml"]
    seed = int(ml_cfg["random_state"])
    epochs = int(ml_cfg.get("gnn_epochs", 40))
    lr = float(ml_cfg.get("gnn_lr", 0.01))
    quantile = float(ml_cfg.get("gnn_threshold_quantile", 0.985))
    feat_cfg = cfg["features"]
    time_window = feat_cfg["time_window"]
    wh_start = int(feat_cfg["work_hours_start"])
    wh_end = int(feat_cfg["work_hours_end"])
    suspicious_procs = {p.lower() for p in feat_cfg["suspicious_processes"]}

    work = logs[["timestamp", "user", "host", "event_id", "process_name"]].copy()
    work["timestamp"] = pd.to_datetime(work["timestamp"])
    work["time_window"] = work["timestamp"].dt.floor(time_window)
    work["user"] = work["user"].astype(str)
    work["host"] = work["host"].astype(str)
    work["proc_lower"] = work["process_name"].fillna("-").astype(str).str.lower()
    work["is_susp"] = work["proc_lower"].isin(suspicious_procs).astype(np.int8)
    work["is_off"] = ((work["timestamp"].dt.hour < wh_start) | (work["timestamp"].dt.hour >= wh_end)).astype(np.int8)
    work["is_fail"] = (pd.to_numeric(work["event_id"], errors="coerce").fillna(0) == 4625).astype(np.int8)

    data, _, node_idx = _build_pyg_data(work, cfg)
    if data.num_nodes < 2 or data.edge_index.numel() == 0:
        empty_df = pd.DataFrame(columns=GNN_ALERT_COLUMNS)
        empty_df.to_csv(out_path, index=False)
        return empty_df

    model_path = os.path.join(models_dir, "gnn_model.pt")
    torch.manual_seed(seed)
    model = GraphSAGEAutoencoder(in_channels=data.num_node_features)

    if not retrain and os.path.exists(model_path):
        logger.info("Loading persisted GNN model -> %s", model_path)
        model.load_state_dict(torch.load(model_path, map_location="cpu", weights_only=True))
    else:
        logger.info("Training GraphSAGE autoencoder (%d nodes, %d edges)", data.num_nodes, data.num_edges)
        optimizer = torch.optim.Adam(model.parameters(), lr=lr)
        criterion = nn.MSELoss()
        model.train()
        for _ in range(epochs):
            optimizer.zero_grad()
            x_hat, _ = model(data.x, data.edge_index)
            loss = criterion(x_hat, data.x)
            loss.backward()
            optimizer.step()
        torch.save(model.state_dict(), model_path)
        logger.info("Saved GNN model -> %s", model_path)

    model.eval()
    with torch.no_grad():
        x_hat, z = model(data.x, data.edge_index)
        node_errors = torch.mean((x_hat - data.x) ** 2, dim=1).numpy()
        z_norm = nn.functional.normalize(z, p=2, dim=1).numpy()

    max_err = float(np.max(node_errors)) + 1e-8
    min_err = float(np.min(node_errors))
    norm_node_err = (node_errors - min_err) / max(max_err - min_err, 1e-8)

    # Vectorized scoring over unique (time_window, user, host) edges
    win_edges = (
        work.groupby(["time_window", "user", "host"], sort=False)
        .agg(timestamp=("timestamp", "min"), susp_frac=("is_susp", "mean"), cnt=("is_susp", "size"))
        .reset_index()
    )
    edge_freq = work.groupby(["user", "host"], sort=False).size().to_dict()
    max_edge_freq = max(edge_freq.values(), default=1)

    sensitive_map = {
        h.lower(): {u.lower() for u in users}
        for h, users in cfg["rules"]["sensitive_hosts"].items()
    }

    u_idx = ("user:" + win_edges["user"]).map(node_idx).values
    h_idx = ("host:" + win_edges["host"]).map(node_idx).values

    u_err = norm_node_err[u_idx]
    h_err = norm_node_err[h_idx]
    cos_sim = np.sum(z_norm[u_idx] * z_norm[h_idx], axis=1)
    link_surprise = np.clip((1.0 - cos_sim) / 2.0, 0.0, 1.0)

    rarity = np.array([
        1.0 - (edge_freq.get((u, h), 1) / max_edge_freq)
        for u, h in zip(win_edges["user"], win_edges["host"])
    ], dtype=np.float32)
    susp_frac = win_edges["susp_frac"].values.astype(np.float32)
    unauth_bonus = np.array([
        0.25 if (h.lower() in sensitive_map and u.lower() not in sensitive_map[h.lower()]) else 0.0
        for u, h in zip(win_edges["user"], win_edges["host"])
    ], dtype=np.float32)

    scores = np.clip(
        0.20 * u_err + 0.20 * h_err + 0.20 * link_surprise + 0.25 * rarity * (0.3 + 0.7 * susp_frac) + 0.15 * susp_frac + unauth_bonus,
        0.0,
        1.0,
    )

    threshold = 0.55 if len(scores) < 100 else max(0.55, float(np.quantile(scores, quantile)))
    flagged_mask = scores >= threshold
    flagged = win_edges[flagged_mask].copy()
    flagged["score"] = scores[flagged_mask]
    flagged["u_err"] = u_err[flagged_mask]
    flagged["h_err"] = h_err[flagged_mask]
    flagged["link_surprise"] = link_surprise[flagged_mask]

    alerts: List[Dict[str, Any]] = []
    for _, r in flagged.iterrows():
        details = {
            "gnn_score": round(float(r["score"]), 4),
            "user_node_anomaly": round(float(r["u_err"]), 4),
            "host_node_anomaly": round(float(r["h_err"]), 4),
            "link_surprise": round(float(r["link_surprise"]), 4),
        }
        alerts.append({
            "time_window": r["time_window"],
            "timestamp": r["timestamp"],
            "user": r["user"],
            "host": r["host"],
            "alert_type": "GNN graph anomaly",
            "anomaly_score": round(float(r["score"]), 4),
            "severity": round(float(min(1.0, max(0.45, r["score"]))), 4),
            "details": str(details),
        })

    alerts_df = pd.DataFrame(alerts, columns=GNN_ALERT_COLUMNS)
    alerts_df.to_csv(out_path, index=False)
    logger.info("GNN detection generated %d alerts -> %s", len(alerts_df), out_path)
    return alerts_df


if __name__ == "__main__":
    run_gnn_detection()
