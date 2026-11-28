"""Build one unified, clean data/uploads/ folder containing paired full & _testing.log files."""

from datetime import datetime
import json
import os
import shutil
import sys
from typing import Dict, List, Tuple

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from src.config import load_config
from src.ingestion.log_ingestion import RFC3164_RE, RFC5424_RE
from src.utils.logger import get_logger

logger = get_logger("export_test_splits")


def _extract_raw_line_ts(line: str, default_year: int = 2025) -> datetime | None:
    s = line.strip()
    if not s:
        return None
    if s.startswith("{"):
        try:
            obj = json.loads(s)
            tc = str(obj.get("TimeCreated", "")).replace("Z", "")
            return datetime.fromisoformat(tc)
        except Exception:
            return None
    m5424 = RFC5424_RE.match(s)
    if m5424:
        try:
            return datetime.fromisoformat(m5424.group(1).replace("Z", ""))
        except Exception:
            return None
    m3164 = RFC3164_RE.match(s)
    if m3164:
        try:
            return datetime.strptime(f"{default_year} {m3164.group(1)}", "%Y %b %d %H:%M:%S")
        except Exception:
            return None
    return None


def _floor_10min(dt: datetime) -> datetime:
    return dt.replace(minute=(dt.minute // 10) * 10, second=0, microsecond=0)


def _compute_70_30_cutoff(paths: List[str], default_year: int = 2025, train_ratio: float = 0.70) -> datetime:
    windows = set()
    for path in paths:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                dt = _extract_raw_line_ts(line, default_year=default_year)
                if dt is not None:
                    windows.add(_floor_10min(dt))
    sorted_tws = sorted(windows)
    if len(sorted_tws) < 2:
        return sorted_tws[0] if sorted_tws else datetime(default_year, 1, 1)
    cut = max(1, min(len(sorted_tws) - 1, int(len(sorted_tws) * train_ratio)))
    return sorted_tws[cut]


def _write_test_slice(src_path: str, dst_path: str, cutoff: datetime, default_year: int = 2025) -> Tuple[int, int]:
    os.makedirs(os.path.dirname(dst_path), exist_ok=True)
    total = 0
    kept = 0
    with open(src_path, "r", encoding="utf-8", errors="replace") as fin, open(dst_path, "w", encoding="utf-8") as fout:
        for line in fin:
            if not line.strip():
                continue
            total += 1
            dt = _extract_raw_line_ts(line, default_year=default_year)
            if dt is not None and dt >= cutoff:
                fout.write(line if line.endswith("\n") else line + "\n")
                kept += 1
    return total, kept


def _build_windows_security_compact(raw_dir: str, dst_path: str) -> None:
    """Merge windows_security_part1..4 into one <100MB upload file preserving 100% of attacks."""
    parts = sorted(
        os.path.join(raw_dir, f)
        for f in os.listdir(raw_dir)
        if f.startswith("windows_security_part") and f.endswith(".log")
    )
    os.makedirs(os.path.dirname(dst_path), exist_ok=True)
    idx = 0
    with open(dst_path, "w", encoding="utf-8") as out_f:
        for p in parts:
            with open(p, "r", encoding="utf-8", errors="replace") as in_f:
                for line in in_f:
                    s = line.strip()
                    if not s:
                        continue
                    idx += 1
                    keep = (idx % 2 == 0)
                    if not keep:
                        try:
                            if int(json.loads(s).get("EventRecordID", 0)) >= 900_000_000:
                                keep = True
                        except Exception:
                            pass
                    if keep:
                        out_f.write(s + "\n")


def organize_uploads_folder(train_ratio: float = 0.70) -> Dict[str, Dict[str, int]]:
    cfg = load_config()
    base_dir = cfg["base_dir"]
    data_dir = os.path.join(base_dir, "data")
    raw_dir = cfg["paths"]["raw_dir"]
    uploads_dir = os.path.join(data_dir, "uploads")
    old_samples_dir = os.path.join(data_dir, "upload_samples")
    old_test30_dir = os.path.join(data_dir, "test_30")
    default_year = int(cfg["features"].get("default_year", 2025))

    os.makedirs(uploads_dir, exist_ok=True)
    summary: Dict[str, Dict[str, int]] = {}

    # Move ground_truth_samples.csv into data/raw/ so data/uploads/ contains only .log files
    for gt_cand in [
        os.path.join(old_samples_dir, "ground_truth_samples.csv"),
        os.path.join(uploads_dir, "ground_truth_samples.csv"),
    ]:
        if os.path.isfile(gt_cand):
            shutil.copy2(gt_cand, os.path.join(raw_dir, "ground_truth_samples.csv"))

    # 1. Unified upload sample bundles (combined, Windows-only, Linux-only, new_test_logs)
    bundle_moves = [
        (os.path.join(old_samples_dir, "combined_windows_linux_sample.log"), "combined_windows_linux_logs.log"),
        (os.path.join(old_samples_dir, "windows_all_channels_sample.log"), "windows_only_logs.log"),
        (os.path.join(old_samples_dir, "linux_all_logs_sample.log"), "linux_only_logs.log"),
        (os.path.join(base_dir, "new_test_logs.log"), "new_test_logs.log"),
    ]
    for src, target_name in bundle_moves:
        dst = os.path.join(uploads_dir, target_name)
        if os.path.isfile(src):
            shutil.copy2(src, dst)

    # 2. Per-category raw .log files from data/raw/
    raw_category_map = [
        ("windows_powershell_cmd.log", "windows_powershell_cmd_logs.log"),
        ("windows_rdp.log", "windows_rdp_logs.log"),
        ("windows_system_app.log", "windows_system_app_logs.log"),
        ("linux_auth.log", "linux_auth_logs.log"),
        ("linux_syslog_audit.log", "linux_syslog_audit_logs.log"),
    ]
    for raw_name, target_name in raw_category_map:
        src = os.path.join(raw_dir, raw_name)
        dst = os.path.join(uploads_dir, target_name)
        if os.path.isfile(src):
            shutil.copy2(src, dst)

    sec_dst = os.path.join(uploads_dir, "windows_security_logs.log")
    if any(f.startswith("windows_security_part") and f.endswith(".log") for f in os.listdir(raw_dir)) if os.path.isdir(raw_dir) else False:
        _build_windows_security_compact(raw_dir, sec_dst)

    # 3. Generate matching *_testing.log (30% test slice) alongside each base file in data/uploads/
    raw_based_names = [
        "windows_security_logs.log",
        "windows_powershell_cmd_logs.log",
        "windows_rdp_logs.log",
        "windows_system_app_logs.log",
        "linux_auth_logs.log",
        "linux_syslog_audit_logs.log",
    ]
    raw_files = sorted(
        os.path.join(raw_dir, f)
        for f in os.listdir(raw_dir)
        if f.endswith(".log") and os.path.isfile(os.path.join(raw_dir, f))
    ) if os.path.isdir(raw_dir) else []
    if not raw_files:
        raw_files = [
            os.path.join(uploads_dir, f)
            for f in raw_based_names
            if os.path.isfile(os.path.join(uploads_dir, f))
        ]
    raw_cutoff = _compute_70_30_cutoff(raw_files, default_year=default_year, train_ratio=train_ratio) if raw_files else None
    raw_based_set = set(raw_based_names)

    base_logs = sorted(
        f
        for f in os.listdir(uploads_dir)
        if f.endswith(".log") and not f.endswith("_testing.log")
    )
    for fname in base_logs:
        full_path = os.path.join(uploads_dir, fname)
        test_name = fname[:-4] + "_testing.log"
        test_path = os.path.join(uploads_dir, test_name)
        cutoff = raw_cutoff if (fname in raw_based_set and raw_cutoff is not None) else _compute_70_30_cutoff(
            [full_path], default_year=default_year, train_ratio=train_ratio
        )
        tot, kept = _write_test_slice(full_path, test_path, cutoff, default_year=default_year)
        summary[fname] = {"total_events": tot, "testing_events": kept}
        logger.info("Paired %s (%d) + %s (%d)", fname, tot, test_name, kept)

    # 4. Remove old redundant folders & leftover files
    for obsolete_dir in [old_samples_dir, old_test30_dir]:
        if os.path.isdir(obsolete_dir):
            shutil.rmtree(obsolete_dir, ignore_errors=True)
            logger.info("Removed obsolete directory: %s", obsolete_dir)

    root_new = os.path.join(base_dir, "new_test_logs.log")
    if os.path.isfile(root_new):
        os.remove(root_new)
        logger.info("Removed root duplicate: %s", root_new)

    splits_dir = os.path.join(data_dir, "splits")
    for stale in ["_train_gnn_alerts.csv", "_train_seq_alerts.csv"]:
        sp = os.path.join(splits_dir, stale)
        if os.path.isfile(sp):
            os.remove(sp)
            logger.info("Removed stale split file: %s", sp)

    return summary


if __name__ == "__main__":
    res = organize_uploads_folder()
    print(json.dumps(res, indent=2))
