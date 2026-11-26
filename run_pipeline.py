"""End-to-End Pipeline for AI-Based Lateral Movement Detection (with Train/Test Split)."""

import argparse
import json
import os
import sys
from typing import Any, Dict

import pandas as pd

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from src.config import load_config
from src.detection.gnn_detection import run_gnn_detection
from src.detection.merge_alerts import merge_and_score_alerts
from src.detection.ml_detection import train_and_predict_ml
from src.detection.rule_based_detection import run_rule_detection
from src.detection.sequence_detection import run_sequence_detection
from src.ingestion.generate_synthetic_logs import generate_raw_dataset
from src.ingestion.log_ingestion import ingest_logs
from src.ml.feature_engineering import build_features
from src.utils.evaluate import evaluate_detections
from src.utils.logger import get_logger
from src.utils.visualize_alerts import generate_visualizations

logger = get_logger("run_pipeline")


def split_clean_logs(
    clean_df: pd.DataFrame,
    splits_dir: str,
    train_ratio: float = 0.70,
    split_mode: str = "chronological",
    time_window: str = "10min",
) -> Dict[str, Any]:
    """Split parsed logs into Train and Test CSVs with zero test leakage."""
    os.makedirs(splits_dir, exist_ok=True)
    train_path = os.path.join(splits_dir, "train_logs.csv")
    test_path = os.path.join(splits_dir, "test_logs.csv")

    if clean_df.empty:
        clean_df.to_csv(train_path, index=False)
        clean_df.to_csv(test_path, index=False)
        return {
            "split_mode": split_mode,
            "train_ratio": train_ratio,
            "total_events": 0,
            "train_events": 0,
            "test_events": 0,
            "train_path": train_path,
            "test_path": test_path,
        }

    df = clean_df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df = df.sort_values("timestamp").reset_index(drop=True)
    train_ratio = min(max(float(train_ratio), 0.1), 0.95)

    if split_mode == "window":
        df["_tw"] = df["timestamp"].dt.floor(time_window)
        unique_tws = sorted(df["_tw"].unique())
        cut = max(1, min(len(unique_tws) - 1, int(len(unique_tws) * train_ratio)))
        train_tws = set(unique_tws[:cut])
        train_df = df[df["_tw"].isin(train_tws)].drop(columns=["_tw"])
        test_df = df[~df["_tw"].isin(train_tws)].drop(columns=["_tw"])
    else:
        split_idx = max(1, min(len(df) - 1, int(len(df) * train_ratio)))
        train_df = df.iloc[:split_idx]
        test_df = df.iloc[split_idx:]

    if test_df.empty:
        test_df = train_df.copy()

    train_df.to_csv(train_path, index=False)
    test_df.to_csv(test_path, index=False)

    info = {
        "split_mode": split_mode,
        "train_ratio": round(train_ratio, 2),
        "total_events": int(len(df)),
        "train_events": int(len(train_df)),
        "test_events": int(len(test_df)),
        "train_start": str(train_df["timestamp"].min()),
        "train_end": str(train_df["timestamp"].max()),
        "test_start": str(test_df["timestamp"].min()),
        "test_end": str(test_df["timestamp"].max()),
        "train_path": train_path,
        "test_path": test_path,
    }
    logger.info(
        "Split %d parsed events -> Train=%d (%s..%s) | Test=%d (%s..%s)",
        info["total_events"],
        info["train_events"],
        info["train_start"],
        info["train_end"],
        info["test_events"],
        info["test_start"],
        info["test_end"],
    )
    return info


def run_pipeline(
    generate_data: bool = False,
    total_events: int = 1_050_000,
    days: int = 30,
    retrain: bool = True,
    skip_viz: bool = False,
    skip_eval: bool = False,
    raw_dir: str | None = None,
    train_ratio: float = 0.70,
    split_mode: str = "chronological",
    use_train_test_split: bool = True,
) -> Dict:
    """Execute ingestion, Train/Test split, model training on Train, detection on Test, eval, and charts."""
    cfg = load_config()
    os.chdir(BASE_DIR)

    active_raw = raw_dir or cfg["paths"]["raw_dir"]
    data_root = os.path.dirname(os.path.dirname(cfg["paths"]["processed_file"]))
    splits_dir = os.path.join(data_root, "splits")
    os.makedirs(splits_dir, exist_ok=True)

    logger.info("Starting AI Lateral Movement Detection pipeline (raw_dir=%s)", active_raw)

    if generate_data:
        logger.info("[Step 0] Generating %d+ raw Windows+Linux .log files", total_events)
        generate_raw_dataset(raw_dir=active_raw, total_events=total_events, days=days)

    logger.info("[Step 1] Parsing Raw Logs -> Readable Format")
    logs_df = ingest_logs(raw_dir=active_raw)
    if logs_df.empty:
        raise ValueError(f"No valid log events found in {active_raw}")

    if use_train_test_split and len(logs_df) >= 4:
        logger.info("[Step 2] Splitting Parsed Logs into Train (%.0f%%) & Test (%.0f%%)", train_ratio * 100, (1 - train_ratio) * 100)
        split_info = split_clean_logs(
            logs_df,
            splits_dir=splits_dir,
            train_ratio=train_ratio,
            split_mode=split_mode,
            time_window=cfg["features"]["time_window"],
        )
        train_logs_path = split_info["train_path"]
        test_logs_path = split_info["test_path"]
        train_feat_path = os.path.join(splits_dir, "train_features.csv")
        test_feat_path = cfg["paths"]["features_file"]

        logger.info("[Step 3] Feature & Graph Engineering (Train & Test separately)")
        train_feat_df = build_features(input_csv=train_logs_path, output_csv=train_feat_path)
        test_feat_df = build_features(input_csv=test_logs_path, output_csv=test_feat_path)
        split_info["train_windows"] = int(len(train_feat_df))
        split_info["test_windows"] = int(len(test_feat_df))

        split_summary_path = os.path.join(cfg["paths"]["alerts_dir"], "split_summary.json")
        os.makedirs(os.path.dirname(split_summary_path), exist_ok=True)
        with open(split_summary_path, "w", encoding="utf-8") as f:
            json.dump(split_info, f, indent=2)

        if retrain:
            logger.info("[Step 4] Training ML, GNN & Sequence Models on TRAIN Split")
            train_and_predict_ml(feature_csv=train_feat_path, alert_file=os.path.join(splits_dir, "_train_ml_alerts.csv"), retrain=True)
            run_gnn_detection(clean_logs_path=train_logs_path, output_file=os.path.join(splits_dir, "_train_gnn_alerts.csv"), retrain=True)
            run_sequence_detection(clean_logs_path=train_logs_path, output_file=os.path.join(splits_dir, "_train_seq_alerts.csv"), retrain=True)

        logger.info("[Step 5] Detecting Lateral Movement on TEST Split")
        rule_df = run_rule_detection(clean_logs_path=test_logs_path)
        ml_df = train_and_predict_ml(feature_csv=test_feat_path, retrain=False)
        gnn_df = run_gnn_detection(clean_logs_path=test_logs_path, retrain=False)
        seq_df = run_sequence_detection(clean_logs_path=test_logs_path, retrain=False)
        feat_df = test_feat_df
    else:
        logger.info("[Step 2] Feature & Graph Engineering")
        feat_df = build_features()
        split_info = {"split_mode": "none", "total_events": int(len(logs_df))}

        logger.info("[Step 3] Rule-Based Detection")
        rule_df = run_rule_detection()

        logger.info("[Step 4] Tabular ML Detection")
        ml_df = train_and_predict_ml(retrain=retrain)

        logger.info("[Step 5] Graph Neural Network Detection")
        gnn_df = run_gnn_detection(retrain=retrain)

        logger.info("[Step 6] Sequence Detection")
        seq_df = run_sequence_detection(retrain=retrain)

    logger.info("[Step 6] Alert Merging & Ensemble Risk Scoring")
    merged_df = merge_and_score_alerts(cfg)

    eval_report = {}
    if not skip_eval:
        logger.info("[Step 7] Evaluation Metrics")
        eval_report = evaluate_detections(cfg)

    charts_count = 0
    if not skip_viz:
        logger.info("[Step 8] Generating Visualizations")
        charts_count = generate_visualizations()

    summary = {
        "raw_events": len(logs_df),
        "feature_windows": len(feat_df),
        "split": split_info,
        "rule_alerts": len(rule_df),
        "ml_alerts": len(ml_df),
        "gnn_alerts": len(gnn_df),
        "sequence_alerts": len(seq_df),
        "total_merged_alerts": len(merged_df),
        "charts_generated": charts_count,
        "evaluation": eval_report,
    }
    logger.info(
        "Pipeline complete: %d events -> %d Test alerts (Rule=%d, ML=%d, GNN=%d, Seq=%d), %d charts",
        summary["raw_events"],
        summary["total_merged_alerts"],
        summary["rule_alerts"],
        summary["ml_alerts"],
        summary["gnn_alerts"],
        summary["sequence_alerts"],
        summary["charts_generated"],
    )
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="AI Lateral Movement Detection End-to-End Pipeline")
    parser.add_argument("--generate-data", action="store_true", help="Regenerate multi-format .log dataset before running")
    parser.add_argument("--total-events", type=int, default=1_050_000, help="Total raw synthetic events when --generate-data is set")
    parser.add_argument("--days", type=int, default=30, help="Days to span when --generate-data is set")
    parser.add_argument("--raw-dir", default=None, help="Optional custom raw log directory")
    parser.add_argument("--train-ratio", type=float, default=0.70, help="Train split ratio (default: 0.70)")
    parser.add_argument("--split-mode", choices=["chronological", "window"], default="chronological")
    parser.add_argument("--no-split", action="store_true", help="Disable Train/Test split")
    parser.add_argument("--no-retrain", action="store_true", help="Use saved models instead of retraining")
    parser.add_argument("--skip-viz", action="store_true", help="Skip chart generation")
    parser.add_argument("--skip-eval", action="store_true", help="Skip evaluation report")
    args = parser.parse_args()

    run_pipeline(
        generate_data=args.generate_data,
        total_events=args.total_events,
        days=args.days,
        retrain=not args.no_retrain,
        skip_viz=args.skip_viz,
        skip_eval=args.skip_eval,
        raw_dir=args.raw_dir,
        train_ratio=args.train_ratio,
        split_mode=args.split_mode,
        use_train_test_split=not args.no_split,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
