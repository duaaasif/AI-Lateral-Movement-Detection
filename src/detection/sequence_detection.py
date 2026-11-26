"""Vectorized LSTM Sequence Autoencoder for detecting anomalous per-user event chains."""

import os
import re
import sys
from typing import Any, Dict, List, Tuple

import numpy as np
from numpy.lib.stride_tricks import sliding_window_view
import pandas as pd
import torch
import torch.nn as nn

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from src.config import load_config
from src.utils.logger import get_logger

logger = get_logger("sequence_detection")

SEQ_ALERT_COLUMNS = [
    "time_window",
    "timestamp",
    "user",
    "host",
    "alert_type",
    "anomaly_score",
    "severity",
    "details",
]

EVENT_DIM = 7


class SequenceLSTMAutoencoder(nn.Module):
    """LSTM encoder-decoder reconstructing fixed-length event feature sequences."""

    def __init__(self, input_dim: int = EVENT_DIM, hidden_dim: int = 16) -> None:
        super().__init__()
        self.encoder = nn.LSTM(input_dim, hidden_dim, batch_first=True)
        self.decoder = nn.LSTM(hidden_dim, input_dim, batch_first=True)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        _, (h_n, _) = self.encoder(x)
        seq_len = x.size(1)
        repeated = h_n.squeeze(0).unsqueeze(1).repeat(1, seq_len, 1)
        out, _ = self.decoder(repeated)
        return out


def _encode_user_sequences(
    logs: pd.DataFrame,
    cfg: Dict[str, Any],
    seq_len: int,
) -> Tuple[np.ndarray, pd.DataFrame]:
    feat_cfg = cfg["features"]
    suspicious_procs = {p.lower() for p in feat_cfg["suspicious_processes"]}
    admin_keywords = [k.lower() for k in feat_cfg["admin_share_keywords"]]
    sensitive_hosts = {h.lower() for h in cfg["rules"]["sensitive_hosts"].keys()}
    wh_start = int(feat_cfg["work_hours_start"])
    wh_end = int(feat_cfg["work_hours_end"])
    time_window = feat_cfg["time_window"]

    work = logs[["timestamp", "user", "host", "event_id", "process_name", "command_line"]].copy()
    work["timestamp"] = pd.to_datetime(work["timestamp"])
    work["time_window"] = work["timestamp"].dt.floor(time_window)
    work["user"] = work["user"].astype(str)
    work["host"] = work["host"].astype(str)
    work["host_lower"] = work["host"].str.lower()
    work["proc_lower"] = work["process_name"].fillna("-").astype(str).str.lower()
    work["cmd_lower"] = work["command_line"].fillna("-").astype(str).str.lower()
    work["event_id"] = pd.to_numeric(work["event_id"], errors="coerce").fillna(0).astype(int)
    work = work.sort_values(["user", "timestamp"]).reset_index(drop=True)

    # Vectorized new-host indicator relative to each user's earliest access
    first_ts = work.groupby(["user", "host_lower"], sort=False)["timestamp"].transform("min")
    first_user_ts = work.groupby("user", sort=False)["timestamp"].transform("min")
    is_new_host = ((work["timestamp"] == first_ts) & (work["timestamp"] > first_user_ts)).astype(np.float32)

    admin_regex = "|".join(re.escape(kw) for kw in admin_keywords)
    is_admin = (
        (work["event_id"] == 5140)
        | work["cmd_lower"].str.contains(admin_regex, regex=True, na=False)
    ).astype(np.float32)

    event_matrix = np.column_stack([
        (work["event_id"] == 4624).values.astype(np.float32),
        (work["event_id"] == 4625).values.astype(np.float32),
        (work["event_id"] == 4688).values.astype(np.float32),
        work["proc_lower"].isin(suspicious_procs).values.astype(np.float32),
        is_admin.values,
        ((work["timestamp"].dt.hour < wh_start) | (work["timestamp"].dt.hour >= wh_end)).values.astype(np.float32),
        np.maximum(is_new_host.values, work["host_lower"].isin(sensitive_hosts).values.astype(np.float32)),
    ])

    seq_blocks: List[np.ndarray] = []
    meta_indices: List[np.ndarray] = []
    seq_lengths: List[np.ndarray] = []

    # Fast slicing over contiguous per-user blocks
    user_vals = work["user"].values
    split_pts = np.flatnonzero(user_vals[1:] != user_vals[:-1]) + 1
    starts = np.concatenate(([0], split_pts))
    ends = np.concatenate((split_pts, [len(work)]))

    for s, e in zip(starts, ends):
        block = event_matrix[s:e]
        n = e - s
        if n < seq_len:
            pad = np.zeros((seq_len - n, EVENT_DIM), dtype=np.float32)
            seq_blocks.append(np.vstack([pad, block])[None, :, :])
            meta_indices.append(np.array([e - 1], dtype=np.int64))
            seq_lengths.append(np.array([n], dtype=np.int32))
        else:
            # sliding_window_view returns (num_windows, EVENT_DIM, seq_len) -> transpose to (num_windows, seq_len, EVENT_DIM)
            win_view = sliding_window_view(block, window_shape=seq_len, axis=0)
            win_view = np.transpose(win_view, (0, 2, 1))
            seq_blocks.append(win_view)
            meta_indices.append(np.arange(s + seq_len - 1, e, dtype=np.int64))
            seq_lengths.append(np.full(n - seq_len + 1, seq_len, dtype=np.int32))

    if not seq_blocks:
        return np.zeros((0, seq_len, EVENT_DIM), dtype=np.float32), pd.DataFrame()

    X_seq = np.concatenate(seq_blocks, axis=0).astype(np.float32)
    idx_arr = np.concatenate(meta_indices)
    len_arr = np.concatenate(seq_lengths)

    meta_df = work.iloc[idx_arr][["user", "host", "timestamp", "time_window"]].copy().reset_index(drop=True)
    meta_df["events_in_seq"] = len_arr
    return X_seq, meta_df


def run_sequence_detection(
    clean_logs_path: str | None = None,
    output_file: str | None = None,
    retrain: bool = True,
) -> pd.DataFrame:
    """Train/load LSTM sequence autoencoder and flag anomalous event chains."""
    cfg = load_config()
    in_path = clean_logs_path or cfg["paths"]["processed_file"]
    out_path = output_file or cfg["paths"]["sequence_alerts_file"]
    models_dir = cfg["paths"]["models_dir"]
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    os.makedirs(models_dir, exist_ok=True)

    logs = pd.read_csv(in_path, low_memory=False)
    if logs.empty:
        empty_df = pd.DataFrame(columns=SEQ_ALERT_COLUMNS)
        empty_df.to_csv(out_path, index=False)
        return empty_df

    ml_cfg = cfg["ml"]
    seq_len = int(ml_cfg.get("sequence_length", 5))
    seed = int(ml_cfg["random_state"])
    epochs = int(ml_cfg.get("sequence_epochs", 25))
    lr = float(ml_cfg.get("sequence_lr", 0.005))
    quantile = float(ml_cfg.get("sequence_threshold_quantile", 0.985))
    max_train = int(ml_cfg.get("max_seq_train_samples", 20000))

    X_seq, meta_df = _encode_user_sequences(logs, cfg, seq_len)
    if len(X_seq) == 0:
        empty_df = pd.DataFrame(columns=SEQ_ALERT_COLUMNS)
        empty_df.to_csv(out_path, index=False)
        return empty_df

    model_path = os.path.join(models_dir, "seq_model.pt")
    torch.manual_seed(seed)
    model = SequenceLSTMAutoencoder(input_dim=EVENT_DIM)

    if not retrain and os.path.exists(model_path):
        logger.info("Loading persisted LSTM sequence model -> %s", model_path)
        model.load_state_dict(torch.load(model_path, map_location="cpu", weights_only=True))
    else:
        if len(X_seq) > max_train:
            rng = np.random.default_rng(seed)
            train_idx = rng.choice(len(X_seq), size=max_train, replace=False)
            X_train = X_seq[train_idx]
        else:
            X_train = X_seq

        logger.info("Training LSTM sequence autoencoder on %d/%d sequences", len(X_train), len(X_seq))
        optimizer = torch.optim.Adam(model.parameters(), lr=lr)
        criterion = nn.MSELoss()
        train_t = torch.tensor(X_train, dtype=torch.float32)
        batch_size = 1024
        n_train = len(train_t)
        model.train()
        for _ in range(epochs):
            perm = torch.randperm(n_train)
            for start in range(0, n_train, batch_size):
                batch = train_t[perm[start:start + batch_size]]
                optimizer.zero_grad()
                recon = model(batch)
                loss = criterion(recon, batch)
                loss.backward()
                optimizer.step()
        torch.save(model.state_dict(), model_path)
        logger.info("Saved LSTM sequence model -> %s", model_path)

    # Batched inference for 1M+ sequences
    model.eval()
    mse_parts: List[np.ndarray] = []
    infer_bs = 16384
    with torch.no_grad():
        for start in range(0, len(X_seq), infer_bs):
            batch_t = torch.tensor(X_seq[start:start + infer_bs], dtype=torch.float32)
            recon = model(batch_t)
            err = torch.mean((recon - batch_t) ** 2, dim=(1, 2)).numpy()
            mse_parts.append(err)
    seq_mse = np.concatenate(mse_parts)

    min_e = float(np.min(seq_mse))
    max_e = float(np.max(seq_mse))
    norm_scores = (seq_mse - min_e) / max(max_e - min_e, 1e-8)

    susp_density = X_seq[:, :, 3:7].mean(axis=(1, 2))
    combined = np.clip(0.6 * norm_scores + 0.4 * np.clip(susp_density * 2.0, 0.0, 1.0), 0.0, 1.0)
    threshold = 0.55 if len(combined) < 100 else max(0.55, float(np.quantile(combined, quantile)))

    mask = combined >= threshold
    flagged = meta_df[mask].copy()
    if flagged.empty:
        empty_df = pd.DataFrame(columns=SEQ_ALERT_COLUMNS)
        empty_df.to_csv(out_path, index=False)
        logger.info("Sequence detection generated 0 alerts -> %s", out_path)
        return empty_df

    flagged["score"] = combined[mask]
    flagged["recon_mse"] = seq_mse[mask]
    flagged = flagged.sort_values("score").drop_duplicates(subset=["user", "time_window"], keep="last")
    flagged = flagged.sort_values("timestamp").reset_index(drop=True)

    alerts: List[Dict[str, Any]] = []
    for _, item in flagged.iterrows():
        details = {
            "sequence_score": round(float(item["score"]), 4),
            "reconstruction_mse": round(float(item["recon_mse"]), 5),
            "sequence_length": int(item["events_in_seq"]),
        }
        alerts.append({
            "time_window": item["time_window"],
            "timestamp": item["timestamp"],
            "user": item["user"],
            "host": item["host"],
            "alert_type": "Sequence anomaly",
            "anomaly_score": round(float(item["score"]), 4),
            "severity": round(float(min(1.0, max(0.45, item["score"]))), 4),
            "details": str(details),
        })

    alerts_df = pd.DataFrame(alerts, columns=SEQ_ALERT_COLUMNS)
    alerts_df.to_csv(out_path, index=False)
    logger.info("Sequence detection generated %d alerts -> %s", len(alerts_df), out_path)
    return alerts_df


if __name__ == "__main__":
    run_sequence_detection()
