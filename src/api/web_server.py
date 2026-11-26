"""Local SOC Web Dashboard & REST API server with clean session-based Upload -> Split -> Results flow."""

import argparse
import csv
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import shutil
import subprocess
import sys
import threading
import time
from typing import Any, Callable, Dict, List
from urllib.parse import parse_qs, urlparse

import pandas as pd

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from src.api.scoring_server import score_events
from src.config import load_config
from src.utils.logger import get_logger

logger = get_logger("web_server")

UI_DIR = os.path.join(BASE_DIR, "src", "ui")
_LINE_COUNT_CACHE: Dict[str, tuple] = {}


def _fast_csv_row_count(filepath: str) -> int:
    if not os.path.exists(filepath):
        return 0
    st = os.stat(filepath)
    cached = _LINE_COUNT_CACHE.get(filepath)
    if cached and cached[0] == st.st_mtime and cached[1] == st.st_size:
        return cached[2]
    count = 0
    with open(filepath, "rb") as f:
        while chunk := f.read(1024 * 1024):
            count += chunk.count(b"\n")
    rows = max(0, count - 1)
    _LINE_COUNT_CACHE[filepath] = (st.st_mtime, st.st_size, rows)
    return rows


class SessionState:
    """Tracks clean session uploads and whether analysis results are ready for display."""

    def __init__(self, session_raw_dir: str) -> None:
        self._lock = threading.Lock()
        self.session_raw_dir = session_raw_dir
        self.has_results = False
        self.reset()

    def reset(self) -> None:
        with self._lock:
            if os.path.isdir(self.session_raw_dir):
                shutil.rmtree(self.session_raw_dir, ignore_errors=True)
            os.makedirs(self.session_raw_dir, exist_ok=True)
            self.has_results = False

    def mark_results_ready(self, ready: bool) -> None:
        with self._lock:
            self.has_results = ready

    def list_uploaded(self) -> List[Dict[str, Any]]:
        with self._lock:
            files = []
            if os.path.isdir(self.session_raw_dir):
                for name in sorted(os.listdir(self.session_raw_dir)):
                    fpath = os.path.join(self.session_raw_dir, name)
                    if os.path.isfile(fpath):
                        size_b = os.path.getsize(fpath)
                        files.append({
                            "name": name,
                            "size_bytes": size_b,
                            "size_mb": round(size_b / (1024 * 1024), 2),
                        })
            return files


class JobManager:
    """Thread-safe single-job runner for pipeline execution and test runs."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.status = "idle"
        self.job_name = ""
        self.exit_code: int | None = None
        self.started_at: float | None = None
        self.finished_at: float | None = None
        self.logs: List[str] = []

    def start_subprocess(
        self,
        job_name: str,
        cmd: List[str],
        on_success: Callable[[], None] | None = None,
    ) -> bool:
        with self._lock:
            if self.status == "running":
                return False
            self.status = "running"
            self.job_name = job_name
            self.exit_code = None
            self.started_at = time.time()
            self.finished_at = None
            self.logs = [f"$ {' '.join(cmd)}"]

        thread = threading.Thread(target=self._run, args=(cmd, on_success), daemon=True)
        thread.start()
        return True

    def _run(self, cmd: List[str], on_success: Callable[[], None] | None) -> None:
        try:
            proc = subprocess.Popen(
                cmd,
                cwd=BASE_DIR,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
            )
            assert proc.stdout is not None
            for line in proc.stdout:
                cleaned = line.rstrip("\r\n")
                if cleaned:
                    with self._lock:
                        self.logs.append(cleaned)
                        if len(self.logs) > 500:
                            self.logs = self.logs[-500:]
            rc = proc.wait()
            if rc == 0 and on_success is not None:
                on_success()
            with self._lock:
                self.exit_code = rc
                self.status = "completed" if rc == 0 else "failed"
                self.finished_at = time.time()
        except Exception as exc:
            with self._lock:
                self.logs.append(f"[ERROR] {exc}")
                self.exit_code = 1
                self.status = "failed"
                self.finished_at = time.time()

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            elapsed = None
            if self.started_at is not None:
                end = self.finished_at if self.finished_at is not None else time.time()
                elapsed = round(end - self.started_at, 1)
            return {
                "status": self.status,
                "job_name": self.job_name,
                "exit_code": self.exit_code,
                "elapsed_seconds": elapsed,
                "logs": list(self.logs),
            }


def get_overview_payload(cfg: Dict[str, Any], session: SessionState) -> Dict[str, Any]:
    """Return clean empty payload until user completes a session run."""
    if not session.has_results:
        return {
            "has_results": False,
            "parsed_events_count": 0,
            "feature_windows_count": 0,
            "split": {},
            "alert_summary": {"total": 0, "by_source": {}, "by_priority": {}, "by_type": {}},
            "risk_scores": [],
            "evaluation": {},
            "charts": [],
            "models_present": [],
        }

    paths = cfg["paths"]
    eval_report: Dict[str, Any] = {}
    if os.path.exists(paths["eval_report_file"]):
        with open(paths["eval_report_file"], "r", encoding="utf-8") as f:
            eval_report = json.load(f)

    split_info: Dict[str, Any] = {}
    split_path = os.path.join(paths["alerts_dir"], "split_summary.json")
    if os.path.exists(split_path):
        with open(split_path, "r", encoding="utf-8") as f:
            split_info = json.load(f)

    risk_scores: List[Dict[str, Any]] = []
    if os.path.exists(paths["user_risk_file"]):
        rdf = pd.read_csv(paths["user_risk_file"])
        if not rdf.empty:
            risk_scores = rdf.fillna("").to_dict(orient="records")

    alert_summary = {"total": 0, "by_source": {}, "by_priority": {}, "by_type": {}}
    if os.path.exists(paths["all_alerts_file"]):
        adf = pd.read_csv(paths["all_alerts_file"], low_memory=False)
        if not adf.empty:
            alert_summary["total"] = int(len(adf))
            alert_summary["by_source"] = {str(k): int(v) for k, v in adf["source"].value_counts().items()}
            if "priority" in adf.columns:
                alert_summary["by_priority"] = {str(k): int(v) for k, v in adf["priority"].value_counts().items()}
            alert_summary["by_type"] = {str(k): int(v) for k, v in adf["alert_type"].value_counts().items()}

    charts: List[str] = []
    if os.path.isdir(paths["visualizations_dir"]):
        charts = sorted(f for f in os.listdir(paths["visualizations_dir"]) if f.lower().endswith(".png"))

    models_present = []
    if os.path.isdir(paths["models_dir"]):
        models_present = sorted(os.listdir(paths["models_dir"]))

    return {
        "has_results": True,
        "parsed_events_count": _fast_csv_row_count(paths["processed_file"]),
        "feature_windows_count": eval_report.get("total_windows", _fast_csv_row_count(paths["features_file"])),
        "split": split_info,
        "alert_summary": alert_summary,
        "risk_scores": risk_scores,
        "evaluation": eval_report,
        "charts": charts,
        "models_present": models_present,
    }


def query_alerts(
    cfg: Dict[str, Any],
    session: SessionState,
    priority: str = "",
    source: str = "",
    user: str = "",
    limit: int = 200,
) -> List[Dict[str, Any]]:
    if not session.has_results:
        return []
    path = cfg["paths"]["all_alerts_file"]
    if not os.path.exists(path):
        return []
    df = pd.read_csv(path, low_memory=False)
    if df.empty:
        return []
    if priority and "priority" in df.columns:
        df = df[df["priority"].astype(str).str.upper() == priority.upper()]
    if source and "source" in df.columns:
        df = df[df["source"].astype(str).str.lower() == source.lower()]
    if user:
        df = df[df["user"].astype(str).str.lower().str.contains(user.lower(), na=False)]
    if "risk_score" in df.columns:
        df = df.sort_values(["risk_score", "timestamp"], ascending=[False, False])
    return df.head(max(1, min(limit, 1000))).fillna("").to_dict(orient="records")


def preview_session_raw_file(session: SessionState, filename: str, lines: int = 40) -> Dict[str, Any]:
    safe_name = os.path.basename(filename)
    fpath = os.path.join(session.session_raw_dir, safe_name)
    if not safe_name or not os.path.isfile(fpath):
        raise FileNotFoundError(f"Uploaded raw file not found: {safe_name}")
    out_lines: List[str] = []
    with open(fpath, "r", encoding="utf-8", errors="replace") as f:
        for _ in range(max(1, min(lines, 200))):
            line = f.readline()
            if not line:
                break
            out_lines.append(line.rstrip("\r\n"))
    return {
        "filename": safe_name,
        "size_mb": round(os.path.getsize(fpath) / (1024 * 1024), 2),
        "lines": out_lines,
    }


def query_parsed_logs(
    cfg: Dict[str, Any],
    session: SessionState,
    log_source: str = "",
    user: str = "",
    event_id: str = "",
    limit: int = 100,
) -> List[Dict[str, Any]]:
    if not session.has_results:
        return []
    path = cfg["paths"]["processed_file"]
    if not os.path.exists(path):
        return []
    limit = max(1, min(limit, 500))
    results: List[Dict[str, Any]] = []
    src_l = log_source.strip().lower()
    usr_l = user.strip().lower()
    eid_s = event_id.strip()

    with open(path, "r", encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if src_l and row.get("log_source", "").lower() != src_l:
                continue
            if usr_l and usr_l not in row.get("user", "").lower():
                continue
            if eid_s and row.get("event_id", "") != eid_s:
                continue
            results.append(row)
            if len(results) >= limit:
                break
    return results


def make_web_handler(
    cfg: Dict[str, Any],
    session: SessionState | None = None,
    jobs: JobManager | None = None,
):
    if session is None:
        session = SessionState(os.path.join(cfg["base_dir"], "data", "session_uploads"))
    if jobs is None:
        jobs = JobManager()

    class WebHandler(BaseHTTPRequestHandler):
        def _send_json(self, status: int, payload: Any) -> None:
            body = json.dumps(payload, default=str).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _send_file(self, fpath: str, content_type: str) -> None:
            if not os.path.isfile(fpath):
                self._send_json(404, {"error": "File not found"})
                return
            with open(fpath, "rb") as f:
                data = f.read()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _read_json_body(self) -> Dict[str, Any]:
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length) if length > 0 else b"{}"
            return json.loads(raw.decode("utf-8"))

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            path = parsed.path
            qs = parse_qs(parsed.query)

            try:
                if path == "/" or path == "/index.html":
                    self._send_file(os.path.join(UI_DIR, "index.html"), "text/html; charset=utf-8")
                elif path == "/static/styles.css":
                    self._send_file(os.path.join(UI_DIR, "styles.css"), "text/css; charset=utf-8")
                elif path == "/static/app.js":
                    self._send_file(os.path.join(UI_DIR, "app.js"), "application/javascript; charset=utf-8")
                elif path == "/health":
                    self._send_json(200, {"status": "ok"})
                elif path == "/api/session":
                    samples_dir = os.path.join(cfg["base_dir"], "data", "upload_samples")
                    samples = []
                    if os.path.isdir(samples_dir):
                        for name in sorted(os.listdir(samples_dir)):
                            if name.endswith(".log"):
                                fp = os.path.join(samples_dir, name)
                                samples.append({
                                    "name": name,
                                    "size_mb": round(os.path.getsize(fp) / (1024 * 1024), 2),
                                })
                    self._send_json(200, {
                        "has_results": session.has_results,
                        "uploaded_files": session.list_uploaded(),
                        "available_samples": samples,
                        "job": jobs.snapshot(),
                    })
                elif path == "/api/overview":
                    self._send_json(200, get_overview_payload(cfg, session))
                elif path == "/api/alerts":
                    rows = query_alerts(
                        cfg,
                        session,
                        priority=qs.get("priority", [""])[0],
                        source=qs.get("source", [""])[0],
                        user=qs.get("user", [""])[0],
                        limit=int(qs.get("limit", ["200"])[0]),
                    )
                    self._send_json(200, {"alerts": rows})
                elif path == "/api/logs/raw":
                    fname = qs.get("file", [""])[0]
                    lines = int(qs.get("lines", ["40"])[0])
                    self._send_json(200, preview_session_raw_file(session, fname, lines))
                elif path == "/api/logs/parsed":
                    rows = query_parsed_logs(
                        cfg,
                        session,
                        log_source=qs.get("source", [""])[0],
                        user=qs.get("user", [""])[0],
                        event_id=qs.get("event_id", [""])[0],
                        limit=int(qs.get("limit", ["100"])[0]),
                    )
                    self._send_json(200, {"logs": rows})
                elif path.startswith("/api/visualizations/"):
                    if not session.has_results:
                        self._send_json(404, {"error": "No active session charts"})
                        return
                    fname = os.path.basename(path.split("/api/visualizations/", 1)[1])
                    fpath = os.path.join(cfg["paths"]["visualizations_dir"], fname)
                    self._send_file(fpath, "image/png")
                elif path == "/api/jobs/status":
                    self._send_json(200, jobs.snapshot())
                else:
                    self._send_json(404, {"error": f"Unknown endpoint: {path}"})
            except FileNotFoundError as exc:
                self._send_json(404, {"error": str(exc)})
            except Exception as exc:
                self._send_json(500, {"error": str(exc)})

        def do_POST(self) -> None:
            parsed = urlparse(self.path)
            path = parsed.path

            try:
                if path == "/api/upload-raw":
                    x_fname = self.headers.get("X-Filename")
                    if x_fname:
                        # Streaming binary file upload (supports large .log files cleanly)
                        fname = os.path.basename(x_fname.strip())
                        if not fname.endswith((".log", ".jsonl", ".ndjson", ".csv", ".txt")):
                            self._send_json(400, {"error": "Filename must end with .log, .jsonl, .csv, or .txt"})
                            return
                        length = int(self.headers.get("Content-Length", "0"))
                        dest = os.path.join(session.session_raw_dir, fname)
                        os.makedirs(session.session_raw_dir, exist_ok=True)
                        remaining = length
                        written = 0
                        with open(dest, "wb") as out_f:
                            while remaining > 0:
                                chunk = self.rfile.read(min(remaining, 1024 * 1024))
                                if not chunk:
                                    break
                                out_f.write(chunk)
                                written += len(chunk)
                                remaining -= len(chunk)
                        self._send_json(200, {
                            "saved": fname,
                            "size_bytes": written,
                            "uploaded_files": session.list_uploaded(),
                        })
                        return

                    data = self._read_json_body()
                    fname = os.path.basename(str(data.get("filename", "")).strip())
                    content = str(data.get("content", ""))
                    if not fname or not fname.endswith((".log", ".jsonl", ".ndjson", ".csv", ".txt")):
                        self._send_json(400, {"error": "Filename must end with .log, .jsonl, .csv, or .txt"})
                        return
                    dest = os.path.join(session.session_raw_dir, fname)
                    os.makedirs(session.session_raw_dir, exist_ok=True)
                    with open(dest, "w", encoding="utf-8") as f:
                        f.write(content)
                    self._send_json(200, {
                        "saved": fname,
                        "size_bytes": len(content.encode("utf-8")),
                        "uploaded_files": session.list_uploaded(),
                    })
                    return

                data = self._read_json_body()
                if path == "/score":
                    events = data.get("events", data if isinstance(data, list) else [data])
                    self._send_json(200, score_events(events, cfg))
                elif path == "/api/session/reset":
                    if jobs.snapshot()["status"] == "running":
                        self._send_json(409, {"error": "Cannot reset while a job is running."})
                        return
                    session.reset()
                    self._send_json(200, {"reset": True, "uploaded_files": []})
                elif path == "/api/session/remove-file":
                    fname = os.path.basename(str(data.get("filename", "")).strip())
                    target = os.path.join(session.session_raw_dir, fname)
                    if os.path.isfile(target):
                        os.remove(target)
                    self._send_json(200, {"uploaded_files": session.list_uploaded()})
                elif path == "/api/pipeline/analyze":
                    uploaded = session.list_uploaded()
                    if not uploaded:
                        self._send_json(400, {"error": "Please upload at least one raw .log file first."})
                        return
                    mode = str(data.get("mode", "train_and_test")).strip()
                    if mode not in ("train_and_test", "test_only"):
                        mode = "train_and_test"

                    session.mark_results_ready(False)
                    if mode == "test_only":
                        cmd = [
                            sys.executable,
                            os.path.join(BASE_DIR, "run_pipeline.py"),
                            "--raw-dir",
                            session.session_raw_dir,
                            "--no-split",
                            "--no-retrain",
                        ]
                        job_label = "Direct Test Pipeline (Skip Split & Training)"
                    else:
                        train_ratio = float(data.get("train_ratio", 0.70))
                        split_mode = "window"
                        cmd = [
                            sys.executable,
                            os.path.join(BASE_DIR, "run_pipeline.py"),
                            "--raw-dir",
                            session.session_raw_dir,
                            "--train-ratio",
                            str(train_ratio),
                            "--split-mode",
                            split_mode,
                        ]
                        job_label = "Upload -> Split -> Train/Detect Pipeline"

                    started = jobs.start_subprocess(
                        job_label,
                        cmd,
                        on_success=lambda: session.mark_results_ready(True),
                    )
                    if not started:
                        self._send_json(409, {"error": "Another job is already running."})
                        return
                    self._send_json(202, {"started": True, "mode": mode, "job": jobs.snapshot()})
                elif path == "/api/tests/run":
                    cmd = [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"]
                    started = jobs.start_subprocess("Automated Test Suite", cmd)
                    if not started:
                        self._send_json(409, {"error": "Another job is already running."})
                        return
                    self._send_json(202, {"started": True, "job": jobs.snapshot()})
                else:
                    self._send_json(404, {"error": f"Unknown endpoint: {path}"})
            except Exception as exc:
                self._send_json(400, {"error": str(exc)})

        def log_message(self, format: str, *args: Any) -> None:
            logger.debug(format, *args)

    return WebHandler


def start_server(host: str = "127.0.0.1", port: int = 8080) -> ThreadingHTTPServer:
    cfg = load_config()
    session = SessionState(os.path.join(cfg["base_dir"], "data", "session_uploads"))
    jobs = JobManager()
    server = ThreadingHTTPServer((host, port), make_web_handler(cfg, session=session, jobs=jobs))
    logger.info("AegisLM SOC Dashboard running at http://%s:%d (clean session)", host, port)
    return server


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Start Lateral Movement Detection GUI Server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    srv = start_server(args.host, args.port)
    srv.serve_forever()
