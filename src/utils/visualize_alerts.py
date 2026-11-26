"""Visualization generator for merged lateral movement alerts."""

import os
import sys

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from src.config import load_config
from src.utils.logger import get_logger

logger = get_logger("visualize_alerts")


def generate_visualizations(
    alerts_file: str | None = None,
    output_dir: str | None = None,
) -> int:
    """Create summary charts from merged alerts and return number of generated PNGs."""
    cfg = load_config()
    in_file = alerts_file or cfg["paths"]["all_alerts_file"]
    out_dir = output_dir or cfg["paths"]["visualizations_dir"]
    os.makedirs(out_dir, exist_ok=True)

    plt.style.use("default")
    plt.rcParams["figure.figsize"] = (12, 6)
    plt.rcParams["axes.grid"] = True
    plt.rcParams["grid.alpha"] = 0.3

    df = pd.read_csv(in_file)
    if df.empty:
        logger.warning("No alerts in %s; skipping chart generation.", in_file)
        return 0

    df["time_window"] = pd.to_datetime(df["time_window"])
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    generated = 0

    def _annotate_bars(ax, bars) -> None:
        for bar in bars:
            height = bar.get_height()
            ax.text(
                bar.get_x() + bar.get_width() / 2.0,
                height,
                f"{int(height)}",
                ha="center",
                va="bottom",
                fontweight="bold",
            )

    # 1. Alerts per User (dynamic palette for any number of users)
    fig, ax = plt.subplots(figsize=(10, 6))
    user_counts = df["user"].value_counts()
    palette = plt.cm.tab10.colors
    bar_colors = [palette[i % len(palette)] for i in range(len(user_counts))]
    bars = ax.bar(user_counts.index.astype(str), user_counts.values, color=bar_colors)
    ax.set_xlabel("User", fontsize=12, fontweight="bold")
    ax.set_ylabel("Number of Alerts", fontsize=12, fontweight="bold")
    ax.set_title("Alerts per User", fontsize=14, fontweight="bold", pad=16)
    plt.xticks(rotation=30, ha="right")
    _annotate_bars(ax, bars)
    plt.tight_layout()
    plt.savefig(os.path.join(out_dir, "alerts_per_user.png"), dpi=200, bbox_inches="tight")
    plt.close()
    generated += 1

    # 2. Alerts per Host
    host_df = df[df["host"].notna() & (df["host"].astype(str).str.strip() != "")]
    if not host_df.empty:
        fig, ax = plt.subplots(figsize=(10, 6))
        host_counts = host_df["host"].value_counts()
        bars = ax.bar(host_counts.index.astype(str), host_counts.values, color="#4ECDC4")
        ax.set_xlabel("Host", fontsize=12, fontweight="bold")
        ax.set_ylabel("Number of Alerts", fontsize=12, fontweight="bold")
        ax.set_title("Alerts per Host", fontsize=14, fontweight="bold", pad=16)
        plt.xticks(rotation=45, ha="right")
        _annotate_bars(ax, bars)
        plt.tight_layout()
        plt.savefig(os.path.join(out_dir, "alerts_per_host.png"), dpi=200, bbox_inches="tight")
        plt.close()
        generated += 1

    # 3. Alerts Over Time
    fig, ax = plt.subplots(figsize=(14, 6))
    time_counts = df.sort_values("time_window").groupby("time_window").size()
    ax.plot(time_counts.index, time_counts.values, marker="o", linewidth=2, markersize=6, color="#FF6B6B")
    ax.fill_between(time_counts.index, time_counts.values, alpha=0.25, color="#FF6B6B")
    ax.set_xlabel("Time Window", fontsize=12, fontweight="bold")
    ax.set_ylabel("Number of Alerts", fontsize=12, fontweight="bold")
    ax.set_title("Alerts Over Time", fontsize=14, fontweight="bold", pad=16)
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.savefig(os.path.join(out_dir, "alerts_over_time.png"), dpi=200, bbox_inches="tight")
    plt.close()
    generated += 1

    # 4. Alert Type Distribution
    fig, ax = plt.subplots(figsize=(10, 6))
    type_counts = df["alert_type"].value_counts()
    type_colors = [palette[i % len(palette)] for i in range(len(type_counts))]
    bars = ax.bar(type_counts.index.astype(str), type_counts.values, color=type_colors)
    ax.set_xlabel("Alert Type", fontsize=12, fontweight="bold")
    ax.set_ylabel("Number of Alerts", fontsize=12, fontweight="bold")
    ax.set_title("Alert Type Distribution", fontsize=14, fontweight="bold", pad=16)
    plt.xticks(rotation=35, ha="right")
    _annotate_bars(ax, bars)
    plt.tight_layout()
    plt.savefig(os.path.join(out_dir, "alert_type_distribution.png"), dpi=200, bbox_inches="tight")
    plt.close()
    generated += 1

    # 5. Detector Comparison (Rule-based, ML, GNN, Sequence)
    fig, ax = plt.subplots(figsize=(9, 6))
    source_counts = df["source"].value_counts()
    src_colors = [palette[i % len(palette)] for i in range(len(source_counts))]
    bars = ax.bar(source_counts.index.astype(str), source_counts.values, color=src_colors)
    ax.set_xlabel("Detection Method", fontsize=12, fontweight="bold")
    ax.set_ylabel("Number of Alerts", fontsize=12, fontweight="bold")
    ax.set_title("Detection Method Comparison (Rule-Based vs Isolation Forest)", fontsize=13, fontweight="bold", pad=16)
    _annotate_bars(ax, bars)
    plt.tight_layout()
    plt.savefig(os.path.join(out_dir, "ml_vs_rule_based.png"), dpi=200, bbox_inches="tight")
    plt.close()
    generated += 1

    # 6. User Activity Timeline (dynamic colors)
    fig, ax = plt.subplots(figsize=(14, 6))
    for i, user in enumerate(sorted(df["user"].astype(str).unique())):
        u_df = df[df["user"].astype(str) == user].sort_values("time_window")
        u_counts = u_df.groupby("time_window").size()
        ax.plot(
            u_counts.index,
            u_counts.values,
            marker="o",
            linewidth=2,
            markersize=6,
            label=user,
            color=palette[i % len(palette)],
        )
    ax.set_xlabel("Time Window", fontsize=12, fontweight="bold")
    ax.set_ylabel("Number of Alerts", fontsize=12, fontweight="bold")
    ax.set_title("User Alert Timeline", fontsize=14, fontweight="bold", pad=16)
    ax.legend(title="User", fontsize=9, ncol=2)
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.savefig(os.path.join(out_dir, "user_activity_timeline.png"), dpi=200, bbox_inches="tight")
    plt.close()
    generated += 1

    # 7. Priority Distribution (if ensemble priority exists)
    if "priority" in df.columns:
        fig, ax = plt.subplots(figsize=(8, 5))
        prio_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        prio_counts = df["priority"].value_counts().reindex(prio_order, fill_value=0)
        prio_colors = ["#D62828", "#F77F00", "#FCBF49", "#4ECDC4"]
        bars = ax.bar(prio_counts.index, prio_counts.values, color=prio_colors)
        ax.set_xlabel("Priority", fontsize=12, fontweight="bold")
        ax.set_ylabel("Alert Count", fontsize=12, fontweight="bold")
        ax.set_title("Ensemble Alert Priority Distribution", fontsize=14, fontweight="bold", pad=16)
        _annotate_bars(ax, bars)
        plt.tight_layout()
        plt.savefig(os.path.join(out_dir, "risk_priority_distribution.png"), dpi=200, bbox_inches="tight")
        plt.close()
        generated += 1

    logger.info("Generated %d visualization PNGs -> %s", generated, out_dir)
    return generated


if __name__ == "__main__":
    generate_visualizations()
