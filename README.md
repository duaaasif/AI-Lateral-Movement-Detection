# AI-Lateral-Movement-Detection (AegisLM)

AI-powered lateral movement detection system for **Windows** and **Linux** enterprise logs, combining **6 fixed detection rules** and **Isolation Forest** anomaly detection over 10-minute behavioral windows, served through a clean **Upload → Results & Graphs → Log Explorer** Web GUI.

---

## Project Structure

```
AI-Lateral-Movement-Detection/
├── app.py                                      # Single-command Web GUI launcher (http://127.0.0.1:8080)
├── start_gui.bat                               # Windows double-click / CMD launcher
├── config.json                                 # Unified paths, rules, feature, IsolationForest, and ensemble config
├── run_pipeline.py                             # End-to-end CLI & session pipeline (Train/Test split or Direct Test)
├── requirements.txt                            # Python dependencies
├── new_test_logs.log                           # Fresh 9,250-event mixed Windows + Linux .log file for quick testing
├── models/
│   └── ml_bundle.joblib                        # Pre-trained RobustScaler + IsolationForest model bundle
├── src/
│   ├── config.py                               # Central configuration loader
│   ├── ingestion/
│   │   ├── generate_synthetic_logs.py          # 1M+ Windows + Linux raw .log generator + sample bundles
│   │   └── log_ingestion.py                    # Streaming multi-format parser (.log/.jsonl/.csv -> clean_logs.csv)
│   ├── ml/
│   │   ├── graph_features.py                   # Vectorized NetworkX User-Host bipartite graph features
│   │   └── feature_engineering.py              # 17 behavioral, identity, host & graph features per (user, 10min) window
│   ├── detection/
│   │   ├── rule_based_detection.py             # 6 config-driven vectorized detection rules
│   │   ├── ml_detection.py                     # Isolation Forest anomaly detection
│   │   └── merge_alerts.py                     # Rule + ML alert merging & window risk scoring (0-100)
│   ├── api/
│   │   ├── scoring_server.py                   # Real-time event scoring engine & /score endpoint
│   │   └── web_server.py                       # Session-based Web GUI server, streaming upload & job runner
│   ├── ui/
│   │   ├── index.html                          # Executive Daylight UI (Light / Dark / System themes)
│   │   ├── styles.css                          # Light & pure-black Dark theme styles
│   │   └── app.js                              # Upload -> Run (Train+Test or Direct Test) -> Results & Log Explorer
│   └── utils/
│       ├── logger.py                           # Structured logging
│       ├── evaluate.py                         # Precision, Recall, F1, ROC-AUC, PR-AUC evaluation
│       └── visualize_alerts.py                 # Generates 7 alert & risk PNG charts
├── docs/                                       # Project documentation
└── tests/
    └── test_pipeline.py                        # Unit, integration, and GUI endpoint tests
```

---

## Supported Raw Log Categories (Windows + Linux)

The parser (`src/ingestion/log_ingestion.py`) automatically detects both Windows EVTX/Winlogbeat JSON lines and Linux RFC3164/RFC5424 syslog lines inside `.log` files:

### Windows Logs
- **Security** (`windows_security_part1..4.log`): `4624` (Logon), `4625` (Failed Logon), `4648`, `4672` (Special Privileges), `4688` (Process Creation), `4698` (Scheduled Task), `4768`/`4769` (Kerberos), `5140` (Network Share Access)
- **PowerShell, WinRM & CMD** (`windows_powershell_cmd.log`): PowerShell Operational (`4103`, `4104`), WinRM Operational (`6`, `91`), CMD command execution
- **RDP / Terminal Services** (`windows_rdp.log`): RemoteConnectionManager (`1149`) & LocalSessionManager (`21`, `24`)
- **System & Application** (`windows_system_app.log`): Service Control Manager (`7036`, `7045` including `PSEXESVC`) & Application (`1000`, `1001`, `1022`)

### Linux Logs
- **Auth Logs** (`linux_auth.log`): `/var/log/auth.log` (`sshd` Accepted/Failed, `sudo`, `su`, `pam_unix`, `xrdp-sesman`)
- **Syslog & Auditd** (`linux_syslog_audit.log`): `/var/log/syslog` & `auditd` (`systemd`, `CRON`, `auditd EXECVE`)

---

## Detection Architecture

1. **Two Execution Modes (`run_pipeline.py`)**:
   - **Train & Test (`70/30` Split — default)**: Orders parsed events chronologically and splits along **intact 10-minute window boundaries** into **Train** (`70%` earlier windows) and **Test** (`30%` later windows) with zero leakage. `IsolationForest` trains strictly on Train windows and evaluates alongside Rules on Test windows.
   - **Direct Test Only (Demo — `--no-split --no-retrain`)**: Skips Train/Test splitting and retraining, running Fixed Rules + the pre-trained `models/ml_bundle.joblib` directly on all uploaded events.
2. **17 Engineered Features per `(user, 10min)` Window**:
   - **Core behavioral (6)**: `action_count`, `unique_hosts`, `suspicious_process_count`, `num_source_ips`, `num_unique_commands`, `outside_work_hours` (`1` if outside `06:00–18:00`).
   - **Extended behavioral (6)**: `failed_login_count`, `failed_then_success`, `new_host_count`, `admin_share_count`, `sensitive_host_count`, `unique_event_ids`.
   - **NetworkX graph features (5)**: `user_degree`, `user_pagerank`, `user_betweenness`, `min_dist_to_sensitive`, `new_edge_ratio`.
3. **2 Detection Engines + Ensemble Risk Scoring**:
   - **Rule-Based (`rule_based_detection.py`)**: Multiple hosts in short time (`10` min), login outside working hours (`06:00–18:00`), remote/suspicious process creation (`4688`), unauthorized sensitive host access, failed login burst (`>= 3` in `10` min) before success, admin share / SMB access (`5140` / keywords).
   - **Isolation Forest (`ml_detection.py`)**: `RobustScaler` + `sklearn.ensemble.IsolationForest` persisted in `models/ml_bundle.joblib`.
   - **Ensemble Risk Score (`merge_alerts.py`)**: Correlates Rule-based and Isolation Forest alerts per `(user, 10min)` window into a `0–100` risk score and priority (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) for **Prioritized Threat Windows** alongside the individual **Merged Alert Feed**.

---

## Installation & Setup

1. **Clone and create a virtual environment (Python 3.11–3.13 recommended)**:
   ```powershell
   git clone https://github.com/duaaasif/AI-Lateral-Movement-Detection.git
   cd AI-Lateral-Movement-Detection
   python -m venv .venv
   .\.venv\Scripts\python.exe -m pip install --upgrade pip
   .\.venv\Scripts\python.exe -m pip install -r requirements.txt
   ```

2. **Generate 1,050,000+ raw Windows + Linux `.log` files & upload-ready samples**:
   ```powershell
   .\.venv\Scripts\python.exe src/ingestion/generate_synthetic_logs.py --total-events 1050000 --days 30
   ```
   This creates:
   - `data/raw/*.log` (`1,050,000+` Windows & Linux events)
   - `data/upload_samples/*.log` (convenient browser-uploadable `.log` samples: `combined_windows_linux_sample.log`, `windows_all_channels_sample.log`, `linux_all_logs_sample.log`)

---

## Running & Testing via the Web GUI

1. **Start the GUI** (from CMD or PowerShell):
   ```powershell
   .\.venv\Scripts\python.exe app.py
   ```
   *(Or double-click `start_gui.bat`.)*  
   Your browser opens at `http://127.0.0.1:8080` with a **clean session** (no stale pre-processed results).

2. **GUI Workflow**:
   - **Theme**: Switch between **Light (Executive Daylight)**, **Dark (pure black)**, or **System** in the top-right.
   - **1. Upload & Run**: Drag & drop raw `.log` file(s) (e.g., `new_test_logs.log`, `data/upload_samples/*.log`, or `data/raw/*.log`), choose an **Execution Mode**:
     - **Train & Test (70/30 Split)**: Parses logs, splits chronologically, trains Isolation Forest on Train, and detects/evaluates on Test.
     - **Direct Test Only (Demo)**: Skips splitting and training, and runs detection directly using Rules + the pre-trained `models/ml_bundle.joblib`.
   - **2. Results & Graphs** *(opens automatically after completion)*:
     - In **Train & Test** mode, displays **Total Parsed Events**, **Train Split (`train / total`)**, and **Test Split (`test / total`)**.
     - In **Direct Test Only** mode, hides the Train Split card and displays **Total Parsed Events** and **Analysis Mode (`Direct Test (No Split — Pre-trained Model)`)**.
     - Displays KPIs (`Precision`, `Recall`, `F1`, `ROC-AUC / PR-AUC`), 7 generated visualization charts, **Prioritized Threat Windows** (`user_risk_scores.csv`), and the filterable **Merged Alert Feed** (`all_alerts.csv`, capped at 200 rows per query).
   - **3. Log Explorer**: Previews raw uploaded `.log` lines (35 lines by default, server cap 200) and queries normalized parsed events in `clean_logs.csv` by Source, User, and Event ID (100 rows per query, server cap 500).
   - **New Analysis (Reset)**: Clears the active session back to a clean upload state.

---

## CLI Usage & Automated Tests

- **Run the unit & integration test suite**:
  ```powershell
  .\.venv\Scripts\python.exe -m unittest discover -s tests -v
  ```

- **Run the full 1M+ pipeline via CLI (with 70/30 10-min window Train/Test split)**:
  ```powershell
  .\.venv\Scripts\python.exe run_pipeline.py
  ```

- **Run inference with 70/30 split using persisted Isolation Forest (`--no-retrain`)**:
  ```powershell
  .\.venv\Scripts\python.exe run_pipeline.py --no-retrain
  ```

- **Run Direct Test mode via CLI (skip split & retraining, use persisted model)**:
  ```powershell
  .\.venv\Scripts\python.exe run_pipeline.py --no-split --no-retrain
  ```
