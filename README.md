# AI-Lateral-Movement-Detection (AegisLM)

AI-powered lateral movement detection system for **Windows** and **Linux** enterprise logs, correlating multi-event **10-minute behavioral windows** across **6 fixed detection rules** and **Isolation Forest** anomaly detection, served through an interactive **Upload → Results & Graphs → Log Explorer → Model Performance** Web GUI.

---

## Project Structure

```
AI-Lateral-Movement-Detection/
├── app.py                                      # Single-command Web GUI launcher (http://127.0.0.1:8080)
├── start_gui.bat                               # Windows double-click / CMD launcher
├── config.json                                 # Unified paths, rules, feature, IsolationForest, and ensemble config
├── run_pipeline.py                             # End-to-end CLI & session pipeline (Train/Test split or Direct Test)
├── requirements.txt                            # Python dependencies
├── data/
│   ├── uploads/
│   │   ├── upload1.log .. upload5.log          # Full correlated Train+Test raw .log datasets (disjoint 2025 months)
│   │   └── upload1_test.log .. upload5_test.log# Test-split raw .log files for Direct Test Only mode
│   └── alerts/
│       └── model_history.json                  # Cumulative multi-run model performance log (Tab 4)
├── models/
│   └── ml_bundle.joblib                        # Pre-trained RobustScaler + IsolationForest model bundle
├── src/
│   ├── config.py                               # Central configuration loader
│   ├── ingestion/
│   │   ├── generate_synthetic_logs.py          # Synthetic Windows + Linux raw .log generator & scenario builder
│   │   ├── export_test_splits.py               # Exports upload1..5 .log + *_test.log datasets
│   │   └── log_ingestion.py                    # Streaming multi-format parser (.log/.jsonl/.csv -> clean_logs.csv)
│   ├── ml/
│   │   ├── graph_features.py                   # Vectorized NetworkX User-Host bipartite graph features
│   │   └── feature_engineering.py              # 17 behavioral, identity, host & graph features per (user, 10min) window
│   ├── detection/
│   │   ├── rule_based_detection.py             # 6 config-driven multi-event correlated detection rules
│   │   ├── ml_detection.py                     # Isolation Forest anomaly detection
│   │   └── merge_alerts.py                     # Rule + ML alert merging, ALT-xxxx IDs, risk scores & collective summaries
│   ├── api/
│   │   ├── scoring_server.py                   # Real-time event scoring engine & /score endpoint
│   │   └── web_server.py                       # Session-based Web GUI server, ML event expansion & job runner
│   ├── ui/
│   │   ├── index.html                          # Executive Daylight UI (Light / Dark / System themes)
│   │   ├── styles.css                          # Light & pure-black Dark theme styles
│   │   └── app.js                              # Upload -> Run -> Results (sortable/filterable) -> Logs -> Performance
│   └── utils/
│       ├── logger.py                           # Structured logging
│       ├── evaluate.py                         # Precision, Recall, F1, ROC-AUC, PR-AUC evaluation
│       └── visualize_alerts.py                 # Generates 7 alert-level PNG charts (distinct alert_id counts)
├── docs/                                       # Project documentation
└── tests/
    └── test_pipeline.py                        # 5 unit, integration, ML expansion & GUI endpoint tests
```

---

## Supported Raw Log Categories (Windows + Linux)

The parser (`src/ingestion/log_ingestion.py`) automatically detects both Windows EVTX/Winlogbeat JSON lines and Linux RFC3164/RFC5424 syslog lines inside `.log` files:

### Windows Logs
- **Security**: `4624` (Logon), `4625` (Failed Logon), `4648`, `4672` (Special Privileges), `4688` (Process Creation), `4698` (Scheduled Task), `4768`/`4769` (Kerberos), `5140` (Network Share Access)
- **PowerShell, WinRM & CMD**: PowerShell Operational (`4103`, `4104`), WinRM Operational (`6`, `91`), CMD command execution
- **RDP / Terminal Services**: RemoteConnectionManager (`1149`) & LocalSessionManager (`21`, `24`)
- **System & Application**: Service Control Manager (`7036`, `7045` including `PSEXESVC`) & Application (`1000`, `1001`, `1022`)

### Linux Logs
- **Auth Logs**: `/var/log/auth.log` (`sshd` Accepted/Failed, `sudo`, `su`, `pam_unix`, `xrdp-sesman`)
- **Syslog & Auditd**: `/var/log/syslog` & `auditd` (`systemd`, `CRON`, `auditd EXECVE`)

---

## Ready-to-Upload Datasets (`data/uploads/`)

The `data/uploads/` folder provides 5 progressively sized `.log` datasets across disjoint 2025 months (`Jul`–`Nov`), each interleaving normal baseline activity with multi-stage lateral movement chains (`failed login -> RDP/SSH logon -> privilege/share access -> remote execution -> Linux pivot`) and stealthy **Living-off-the-Land (LotL)** attacks that evade fixed rules so **Isolation Forest** catches them independently:

- **`upload1.log` .. `upload5.log`**: Full chronologically ordered logs for **Train & Test (70/30 Split)** mode.
- **`upload1_test.log` .. `upload5_test.log`**: Pre-split test sets for **Direct Test Only** mode.

---

## Detection Architecture

1. **Two Execution Modes (`run_pipeline.py`)**:
   - **Train & Test (`70/30` Split — default)**: Orders parsed events chronologically and splits along **intact 10-minute window boundaries** into **Train** (`70%` earlier windows) and **Test** (`30%` later windows) with zero leakage. `IsolationForest` trains strictly on Train windows and evaluates alongside Rules on Test windows.
   - **Direct Test Only (`--no-split --no-retrain`)**: Skips Train/Test splitting and retraining, running Fixed Rules + the pre-trained `models/ml_bundle.joblib` directly on all uploaded events.
2. **17 Engineered Features per `(user, 10min)` Window**:
   - **Core behavioral (6)**: `action_count`, `unique_hosts`, `suspicious_process_count`, `num_source_ips`, `num_unique_commands`, `outside_work_hours` (`1` if outside `06:00–18:00`).
   - **Extended behavioral (6)**: `failed_login_count`, `failed_then_success`, `new_host_count`, `admin_share_count`, `sensitive_host_count`, `unique_event_ids`.
   - **NetworkX graph features (5)**: `user_degree`, `user_pagerank`, `user_betweenness`, `min_dist_to_sensitive`, `new_edge_ratio`.
3. **Multi-Event 10-Minute Correlation (`rule_based_detection.py`)**:
   - Evaluates 6 detection rules: **Multiple hosts in short time** (`10` min), **Login outside working hours** (`06:00–18:00`), **Remote/suspicious process creation** (`4688`), **Unauthorized sensitive host access**, **Failed login burst (`>= 3` in `10` min) before success**, and **Admin share / SMB access** (`5140` / keywords).
   - Enforces `(user, 10min)` multi-event correlation (`>= 2` hits or multi-event rule) so single isolated events do not trigger false alerts, while emitting each individual contributing event payload.
4. **Isolation Forest ML Detection (`ml_detection.py`) & Window Risk Scoring (`merge_alerts.py`)**:
   - `RobustScaler` + `sklearn.ensemble.IsolationForest` catches subtle multi-step LotL and high-volume/multi-host anomalies missed by static rules.
   - `merge_alerts.py` assigns deterministic alert IDs (`ALT-0001`, `ALT-0002`, ...) per compromised `(user, 10min)` window, computes a `0–100` risk score (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`), and builds a **Collective Action Summary** (`summary` column) combining event/host counts, behavioral indicators, and triggered rules/ML signals.
5. **Individual Event Evidence Expansion (`web_server.py`)**:
   - Replaces consolidated `ML anomaly` summary rows in **2. Individual Activity Evidence** with each individual event payload from `clean_logs.csv` (event ID, process, source IP, logon type, host, command line).

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

2. **(Optional) Regenerate synthetic raw `.log` files or `data/uploads/` bundles**:
   ```powershell
   .\.venv\Scripts\python.exe src/ingestion/generate_synthetic_logs.py --total-events 1050000 --days 30
   .\.venv\Scripts\python.exe src/ingestion/export_test_splits.py
   ```

---

## Running & Testing via the Web GUI

1. **Start the GUI** (from CMD or PowerShell):
   ```powershell
   .\.venv\Scripts\python.exe app.py
   ```
   *(Or double-click `start_gui.bat`.)*  
   Your browser opens at `http://127.0.0.1:8080` with a **clean session** (no stale pre-processed results).

2. **GUI Workflow (4 Tabs)**:
   - **Theme**: Switch between **Light (Executive Daylight)**, **Dark (pure black)**, or **System** in the top-right.
   - **1. Upload & Run**: Drag & drop raw `.log` file(s) from `data/uploads/` (`upload1.log`–`upload5.log` for **Train & Test**, or `upload1_test.log`–`upload5_test.log` for **Direct Test Only**), choose an **Execution Mode**, and click **Run**.
   - **2. Results & Graphs** *(opens automatically after completion)*:
     - Displays KPIs (`Precision`, `Recall`, `F1`, `ROC-AUC / PR-AUC`, alert count) and 7 distinct-alert-level PNG visualizations.
     - **1. Prioritized Alerts**: One merged row per compromised `(user, 10min)` window (`ALT-xxxx`) with `Risk Score`, `Priority`, `Detectors`, `Activities`, and **Collective Action Summary** (click any `ALT-xxxx` button to jump directly to its events below).
     - **2. Individual Activity Evidence**: Lists individual rule payloads and expanded ML event payloads (filterable by `Alert ID`, `Detector`, and `User`, up to `5,000` rows), with **clickable column sorting** on every header (defaults to `Alert ID` ascending; click toggles ascending/descending).
   - **3. Log Explorer**: Previews raw uploaded `.log` lines and queries normalized parsed events in `clean_logs.csv` by Source, User, and Event ID.
   - **4. Model Performance**: Tracks cumulative accuracy, precision, recall, F1, ROC-AUC, and confusion matrix totals across runs (`data/alerts/model_history.json`), with a Clear History action.
   - **New Analysis (Reset)**: Clears the active session back to a clean upload state.

---

## CLI Usage & Automated Tests

- **Run the unit & integration test suite (`tests/test_pipeline.py`)**:
  ```powershell
  .\.venv\Scripts\python.exe -m unittest discover -s tests -v
  ```

- **Run the pipeline via CLI (with 70/30 10-min window Train/Test split)**:
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
