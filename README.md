# AI-Lateral-Movement-Detection (AegisLM)

AI-powered lateral movement detection system for **Windows** and **Linux** enterprise logs, combining rule-based heuristics, tabular unsupervised ML (`IsolationForest`, `OneClassSVM`, PyTorch `TabularAutoencoder`), Graph Neural Networks (`GraphSAGE` via PyTorch Geometric), and LSTM sequence modeling (`SequenceLSTMAutoencoder`), served through a clean **Upload → Train/Test Split → Results & Graphs** Web GUI.

---

## Project Structure

```
AI-Lateral-Movement-Detection/
├── app.py                                      # Single-command Web GUI launcher (http://127.0.0.1:8080)
├── start_gui.bat                               # Windows double-click / CMD launcher
├── config.json                                 # Unified paths, rules, feature, ML, and ensemble config
├── run_pipeline.py                             # End-to-end CLI & session pipeline (with Train/Test split)
├── requirements.txt                            # Python dependencies
├── src/
│   ├── config.py                               # Central configuration loader
│   ├── ingestion/
│   │   ├── generate_synthetic_logs.py          # 1M+ Windows + Linux raw .log generator + sample bundles
│   │   └── log_ingestion.py                    # Streaming multi-format parser (.log/.jsonl/.csv -> clean_logs.csv)
│   ├── ml/
│   │   ├── graph_features.py                   # Vectorized NetworkX User-Host bipartite graph features
│   │   └── feature_engineering.py              # 17 behavioral, identity, host & graph features per 10-min window
│   ├── detection/
│   │   ├── rule_based_detection.py             # 6 config-driven vectorized detection rules
│   │   ├── ml_detection.py                     # IsolationForest + OneClassSVM + PyTorch Autoencoder
│   │   ├── gnn_detection.py                    # PyTorch Geometric GraphSAGE bipartite detector
│   │   ├── sequence_detection.py               # PyTorch LSTM sequence autoencoder
│   │   └── merge_alerts.py                     # Multi-detector alert merging & ensemble risk scoring (0-100)
│   ├── api/
│   │   ├── scoring_server.py                   # Real-time event scoring engine & /score endpoint
│   │   └── web_server.py                       # Session-based Web GUI server, streaming upload & job runner
│   ├── ui/
│   │   ├── index.html                          # Executive Daylight UI (Light / Dark / System themes)
│   │   ├── styles.css                          # Light & pure-black Dark theme styles
│   │   └── app.js                              # Upload -> Split -> Results & Graphs frontend logic
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

1. **Train / Test Split (`run_pipeline.py`)**:
   - Uploaded or raw logs are normalized chronologically and split into **Train** (default `70%`) and **Test** (`30%`) with zero data leakage.
   - AI models train strictly on the **Train** split and detect/evaluate strictly on the **Test** split.
2. **17 Engineered Features per `(user, 10min)` Window**:
   - `action_count`, `unique_hosts`, `suspicious_process_count`, `num_source_ips`, `num_unique_commands`, `outside_work_hours`, `failed_login_count`, `failed_then_success`, `new_host_count`, `admin_share_count`, `sensitive_host_count`, `unique_event_ids`, `user_degree`, `user_pagerank`, `user_betweenness`, `min_dist_to_sensitive`, `new_edge_ratio`.
3. **4 Independent Detectors + Ensemble Scoring**:
   - **Rule-Based (`rule_based_detection.py`)**: Multiple hosts in short time, login outside working hours (`06:00–18:00`), remote/suspicious process creation, unauthorized sensitive host access, failed login burst before success, admin share / SMB access.
   - **Tabular ML (`ml_detection.py`)**: `RobustScaler` + `IsolationForest` + `OneClassSVM` + PyTorch `TabularAutoencoder` (persisted in `models/`).
   - **Graph Neural Network (`gnn_detection.py`)**: 2-layer `SAGEConv` autoencoder over the User-Host bipartite graph.
   - **Sequence Model (`sequence_detection.py`)**: PyTorch `LSTM` autoencoder over per-user chronological event sequences.
   - **Ensemble Risk Score (`merge_alerts.py`)**: Combines detector severities and multi-detector agreement into a `0–100` risk score and priority (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).

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
   - **1. Upload & Split**: Drag & drop raw `.log` file(s) (e.g., from `data/upload_samples/` or `data/raw/`), choose your Train/Test split ratio (`50%–90%`) and strategy, then click **Split Data & Run Lateral Movement Analysis**.
   - **2. Results & Graphs** *(opens automatically after completion)*: View Train/Test split summary, Test KPIs (`Precision`, `Recall`, `F1`, `ROC-AUC`), 7 generated visualization charts, prioritized threat windows, and the filterable alert feed.
   - **3. Log Explorer**: Preview raw uploaded `.log` lines and search normalized parsed events.
   - **4. Live Threat Tester**: Test real-time scoring (`POST /score`) with built-in attack presets or custom JSON events.
   - **5. System Tests**: Run the automated `unittest` suite directly inside the GUI.
   - **New Analysis (Reset)**: Clears the active session back to a clean upload state.

---

## CLI Usage & Automated Tests

- **Run the unit & integration test suite**:
  ```powershell
  .\.venv\Scripts\python.exe -m unittest discover -s tests -v
  ```

- **Run the full 1M+ pipeline via CLI (with 70/30 Train/Test split)**:
  ```powershell
  .\.venv\Scripts\python.exe run_pipeline.py --generate-data --total-events 1050000 --days 30
  ```

- **Run inference on existing `data/raw/` logs using persisted models**:
  ```powershell
  .\.venv\Scripts\python.exe run_pipeline.py --no-retrain
  ```
