"""Unified Windows + Linux raw log ingestion and normalization into readable CSV.

Supports any .log, .jsonl, .ndjson, or .csv file, including files that mix
Windows EVTX/Winlogbeat JSON lines (Security, PowerShell, WinRM, RDP, System,
Application) and Linux plaintext RFC3164/RFC5424 syslog lines (auth.log,
syslog, systemd, CRON, auditd).
"""

from glob import glob
import json
import os
import re
import sys
from typing import Any, Dict, List

import pandas as pd

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from src.config import load_config
from src.utils.logger import get_logger

logger = get_logger("log_ingestion")

OUTPUT_COLUMNS = [
    "timestamp",
    "user",
    "host",
    "event_id",
    "process_name",
    "command_line",
    "source_ip",
    "dest_ip",
    "dest_port",
    "log_source",
    "raw_event_type",
    "logon_type",
]

CSV_REQUIRED_COLUMNS = [
    "timestamp",
    "user",
    "host",
    "event_id",
    "process_name",
    "command_line",
    "source_ip",
]

RFC3164_RE = re.compile(
    r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^\s\[:]+)(?:\[\d+\])?:\s+(.*)$"
)
RFC5424_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\S+)\s+(\S+)\s+([^\s\[:]+)(?:\[\d+\])?:\s+(.*)$"
)
SSH_ACC_RE = re.compile(r"Accepted\s+\S+\s+for\s+(?:invalid user\s+)?(\S+)\s+from\s+(\S+)")
SSH_FAIL_RE = re.compile(r"Failed\s+\S+\s+for\s+(?:invalid user\s+)?(\S+)\s+from\s+(\S+)")
PAM_OPEN_RE = re.compile(r"session opened for user\s+([^\s(]+)")
SUDO_RE = re.compile(r"^(\S+)\s*:\s*TTY=.*COMMAND=(.+)$")
SU_RE = re.compile(r"Successful su for \S+ by (\S+)")
XRDP_RE = re.compile(r"session.*user\s+(\S+)\s+from\s+(\S+)", re.IGNORECASE)
SYSTEMD_SESS_RE = re.compile(r"Started Session \d+ of user (\S+?)\.?\s*$")
CRON_RE = re.compile(r"^\(([^)]+)\)\s+CMD\s+\((.+)\)$")
AUDIT_EXEC_RE = re.compile(r'user=(\S+)\s+src=(\S+)\s+comm="([^"]+)"\s+cmdline="([^"]*)"')


def _basename(path_str: Any) -> str:
    if not path_str or path_str == "-":
        return "-"
    s = str(path_str).strip()
    return s.rsplit("\\", 1)[-1].rsplit("/", 1)[-1] or "-"


def _short_host(host_str: Any) -> str:
    if not host_str:
        return ""
    return str(host_str).strip().split(".", 1)[0]


def _strip_domain(user_str: Any) -> str:
    if not user_str:
        return ""
    return str(user_str).strip().split("\\", 1)[-1]


def _parse_windows_json_obj(obj: Dict[str, Any]) -> Dict[str, Any] | None:
    if "EventData" not in obj or "Channel" not in obj:
        return None
    channel = str(obj.get("Channel", ""))
    ch_low = channel.lower()
    raw_eid = int(obj.get("EventID", 0))
    ed = obj.get("EventData", {})
    host = _short_host(obj.get("Computer", ""))
    ts = obj.get("TimeCreated")

    if ch_low == "security":
        user = _strip_domain(ed.get("TargetUserName") or ed.get("SubjectUserName") or "")
        proc = _basename(ed.get("NewProcessName") or ed.get("ProcessName") or "-")
        cmd = str(ed.get("CommandLine", "-") or "-")
        if raw_eid == 5140 and cmd == "-":
            cmd = str(ed.get("ShareName", "-") or "-")
        return {
            "timestamp": ts,
            "user": user,
            "host": host,
            "event_id": raw_eid,
            "process_name": proc,
            "command_line": cmd,
            "source_ip": str(ed.get("IpAddress", "-") or "-"),
            "dest_ip": "-",
            "dest_port": 445 if raw_eid == 5140 else 0,
            "log_source": "windows_security",
            "raw_event_type": f"win_sec_{raw_eid}",
            "logon_type": int(ed.get("LogonType", 0) or 0),
        }

    if "powershell" in ch_low:
        return {
            "timestamp": ts,
            "user": _strip_domain(ed.get("User", "")),
            "host": host,
            "event_id": 4688,
            "process_name": _basename(ed.get("HostApplication", "powershell.exe")),
            "command_line": str(ed.get("ScriptBlockText", "-") or "-"),
            "source_ip": str(ed.get("IpAddress", "-") or "-"),
            "dest_ip": "-",
            "dest_port": 0,
            "log_source": "windows_powershell",
            "raw_event_type": f"win_ps_{raw_eid}",
            "logon_type": 0,
        }

    if "winrm" in ch_low:
        return {
            "timestamp": ts,
            "user": _strip_domain(ed.get("User", "")),
            "host": host,
            "event_id": 4688 if raw_eid == 6 else 4624,
            "process_name": _basename(ed.get("HostApplication", "winrm")),
            "command_line": str(ed.get("ScriptBlockText", "-") or "-"),
            "source_ip": str(ed.get("IpAddress", "-") or "-"),
            "dest_ip": "-",
            "dest_port": 5985,
            "log_source": "windows_winrm",
            "raw_event_type": f"win_winrm_{raw_eid}",
            "logon_type": 3,
        }

    if "terminalservices" in ch_low:
        return {
            "timestamp": ts,
            "user": _strip_domain(ed.get("Param1", "")),
            "host": host,
            "event_id": 4624 if raw_eid in (1149, 21) else 4634,
            "process_name": "mstsc.exe",
            "command_line": f"rdp_session_{ed.get('SessionID', 0)}",
            "source_ip": str(ed.get("Param3") or ed.get("Address") or "-"),
            "dest_ip": "-",
            "dest_port": 3389,
            "log_source": "windows_rdp",
            "raw_event_type": f"win_rdp_{raw_eid}",
            "logon_type": 10,
        }

    if ch_low in ("system", "application"):
        svc = str(ed.get("ServiceName", "-") or "-")
        img = str(ed.get("ImagePath", "-") or "-")
        msg = str(ed.get("Message", "-") or "-")
        combined_svc = (svc + " " + img).lower()
        is_psexec_svc = raw_eid == 7045 and ("psexec" in combined_svc or "psexesvc" in combined_svc)
        return {
            "timestamp": ts,
            "user": _strip_domain(ed.get("SubjectUserName", "")),
            "host": host,
            "event_id": 4688 if is_psexec_svc else raw_eid,
            "process_name": "psexec.exe" if is_psexec_svc else (svc if svc != "-" else _basename(obj.get("ProviderName", "-"))),
            "command_line": img if img != "-" else msg,
            "source_ip": str(ed.get("IpAddress", "-") or "-"),
            "dest_ip": "-",
            "dest_port": 0,
            "log_source": f"windows_{ch_low}",
            "raw_event_type": f"win_{ch_low[:3]}_{raw_eid}",
            "logon_type": 0,
        }

    return None


def _parse_linux_line(line: str) -> tuple[bool, Dict[str, Any]] | None:
    is_iso = False
    m = RFC3164_RE.match(line)
    if not m:
        m = RFC5424_RE.match(line)
        is_iso = True
    if not m:
        return None

    ts_str, host, proc, msg = m.groups()
    host = _short_host(host)
    proc_low = proc.lower()
    user = ""
    src_ip = "-"
    eid = 0
    cmd = "-"
    raw_type = proc_low
    dst_port = 0
    log_src = "linux_syslog"
    logon_type = 0
    proc_name = proc_low

    if proc_low == "sshd":
        log_src = "linux_auth"
        dst_port = 22
        logon_type = 10
        acc = SSH_ACC_RE.search(msg)
        if acc:
            user, src_ip = acc.group(1), acc.group(2)
            eid = 4624
            raw_type = "ssh_accepted"
        else:
            fail = SSH_FAIL_RE.search(msg)
            if fail:
                user, src_ip = fail.group(1), fail.group(2)
                eid = 4625
                raw_type = "ssh_failed"
            else:
                pam = PAM_OPEN_RE.search(msg)
                if pam:
                    user = pam.group(1)
                    eid = 4672
                    raw_type = "pam_session_open"
    elif proc_low == "sudo":
        log_src = "linux_auth"
        logon_type = 2
        su_m = SUDO_RE.match(msg)
        if su_m:
            user = su_m.group(1)
            cmd = su_m.group(2).strip()
            eid = 4688
            raw_type = "sudo_exec"
    elif proc_low == "su":
        log_src = "linux_auth"
        logon_type = 2
        su_m = SU_RE.search(msg)
        if su_m:
            user = su_m.group(1)
            eid = 4672
            raw_type = "su_elevate"
    elif proc_low == "xrdp-sesman":
        log_src = "linux_auth"
        dst_port = 3389
        logon_type = 10
        xm = XRDP_RE.search(msg)
        if xm:
            user, src_ip = xm.group(1), xm.group(2)
            eid = 4624
            raw_type = "xrdp_login"
    elif proc_low == "systemd":
        sm = SYSTEMD_SESS_RE.match(msg)
        if sm:
            user = sm.group(1)
            eid = 4624
            logon_type = 2
            raw_type = "systemd_session"
    elif proc_low == "cron":
        cm = CRON_RE.match(msg)
        if cm:
            user = cm.group(1).strip()
            cmd = cm.group(2).strip()
            eid = 4688
            raw_type = "cron_cmd"
    elif proc_low == "auditd":
        log_src = "linux_audit"
        am = AUDIT_EXEC_RE.search(msg)
        if am:
            user, src_ip, comm, cmd = am.groups()
            proc_name = _basename(comm)
            eid = 4688
            raw_type = "auditd_execve"

    if not user:
        return None

    return is_iso, {
        "timestamp": ts_str,
        "user": user,
        "host": host,
        "event_id": eid,
        "process_name": proc_name,
        "command_line": cmd,
        "source_ip": src_ip,
        "dest_ip": "-",
        "dest_port": dst_port,
        "log_source": log_src,
        "raw_event_type": raw_type,
        "logon_type": logon_type,
    }


def _parse_text_log_or_jsonl(
    filepath: str,
    default_year: int = 2025,
    chunk_size: int = 200_000,
) -> List[pd.DataFrame]:
    """Stream-parse .log or .jsonl files (auto-detecting Windows JSON lines and Linux syslog lines)."""
    chunks: List[pd.DataFrame] = []
    iso_records: List[Dict[str, Any]] = []
    rfc3164_records: List[Dict[str, Any]] = []

    def _flush() -> None:
        if iso_records:
            df_iso = pd.DataFrame(iso_records)
            df_iso["timestamp"] = pd.to_datetime(
                df_iso["timestamp"], format="ISO8601", utc=True, errors="coerce"
            ).dt.tz_localize(None)
            df_iso = df_iso.dropna(subset=["timestamp"])
            chunks.append(df_iso)
            iso_records.clear()
        if rfc3164_records:
            df_rfc = pd.DataFrame(rfc3164_records)
            df_rfc["timestamp"] = pd.to_datetime(
                f"{default_year} " + df_rfc["timestamp"].str.replace(r"\s+", " ", regex=True),
                format="%Y %b %d %H:%M:%S",
                errors="coerce",
            )
            df_rfc = df_rfc.dropna(subset=["timestamp"])
            chunks.append(df_rfc)
            rfc3164_records.clear()

    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            stripped = line.strip()
            if not stripped:
                continue

            if stripped.startswith("{"):
                try:
                    obj = json.loads(stripped)
                except json.JSONDecodeError:
                    continue
                rec = _parse_windows_json_obj(obj)
                if rec is not None:
                    iso_records.append(rec)
            else:
                parsed = _parse_linux_line(stripped)
                if parsed is not None:
                    is_iso, rec = parsed
                    if is_iso:
                        iso_records.append(rec)
                    else:
                        rfc3164_records.append(rec)

            if len(iso_records) + len(rfc3164_records) >= chunk_size:
                _flush()

    _flush()
    return chunks


def _parse_csv_file(filepath: str, chunk_size: int = 250_000) -> List[pd.DataFrame]:
    chunks: List[pd.DataFrame] = []
    for df in pd.read_csv(filepath, chunksize=chunk_size, low_memory=False):
        if any(c not in df.columns for c in CSV_REQUIRED_COLUMNS):
            logger.warning("Skipping %s; missing CSV required columns.", filepath)
            return []

        df = df.copy()
        df["timestamp"] = pd.to_datetime(df["timestamp"], format="mixed", dayfirst=True, errors="coerce")
        df = df.dropna(subset=["timestamp"])
        df["user"] = df["user"].fillna("").astype(str).str.strip()
        df["host"] = df["host"].fillna("").astype(str).str.strip()
        df = df[(df["user"] != "") & (df["host"] != "")]

        out = pd.DataFrame({
            "timestamp": df["timestamp"],
            "user": df["user"],
            "host": df["host"],
            "event_id": pd.to_numeric(df["event_id"], errors="coerce").fillna(0).astype(int),
            "process_name": df["process_name"].fillna("-").astype(str).str.strip(),
            "command_line": df["command_line"].fillna("-").astype(str).str.strip(),
            "source_ip": df["source_ip"].fillna("-").astype(str).str.strip(),
            "dest_ip": df["dest_ip"].fillna("-").astype(str) if "dest_ip" in df.columns else "-",
            "dest_port": pd.to_numeric(df["dest_port"], errors="coerce").fillna(0).astype(int) if "dest_port" in df.columns else 0,
            "log_source": df["log_source"].astype(str) if "log_source" in df.columns else "csv",
            "raw_event_type": df["raw_event_type"].astype(str) if "raw_event_type" in df.columns else "csv_event",
            "logon_type": pd.to_numeric(df["logon_type"], errors="coerce").fillna(0).astype(int) if "logon_type" in df.columns else 0,
        })
        if "is_attack" in df.columns:
            out["is_attack"] = pd.to_numeric(df["is_attack"], errors="coerce").fillna(0).astype(int)
        chunks.append(out)
    return chunks


def ingest_logs(raw_dir: str | None = None, output_file: str | None = None) -> pd.DataFrame:
    """Parse Windows + Linux raw logs (.log/.jsonl/.csv) into a normalized readable CSV."""
    cfg = load_config()
    raw_path = raw_dir or cfg["paths"]["raw_dir"]
    out_path = output_file or cfg["paths"]["processed_file"]
    default_year = int(cfg["features"].get("default_year", 2025))
    os.makedirs(os.path.dirname(out_path), exist_ok=True)

    raw_files = sorted(glob(os.path.join(raw_path, "*")))
    all_chunks: List[pd.DataFrame] = []

    for filepath in raw_files:
        if os.path.isdir(filepath):
            continue
        fname = os.path.basename(filepath).lower()
        if fname.startswith("ground_truth"):
            continue

        if fname.endswith((".log", ".jsonl", ".ndjson", ".txt")):
            file_chunks = _parse_text_log_or_jsonl(filepath, default_year=default_year)
        elif fname.endswith(".csv"):
            file_chunks = _parse_csv_file(filepath)
        else:
            logger.debug("Skipping unsupported file: %s", filepath)
            continue

        parsed_count = sum(len(c) for c in file_chunks)
        logger.info("Parsed %d events from %s", parsed_count, os.path.basename(filepath))
        all_chunks.extend(file_chunks)

    if all_chunks:
        all_logs = pd.concat(all_chunks, ignore_index=True)
        all_logs["user"] = all_logs["user"].fillna("").astype(str).str.strip()
        all_logs["host"] = all_logs["host"].fillna("").astype(str).str.strip()
        all_logs = all_logs[(all_logs["user"] != "") & (all_logs["host"] != "")]
        all_logs = all_logs.sort_values("timestamp").reset_index(drop=True)
    else:
        all_logs = pd.DataFrame(columns=OUTPUT_COLUMNS)

    all_logs.to_csv(out_path, index=False)
    logger.info("Saved %d normalized readable logs -> %s", len(all_logs), out_path)
    return all_logs


if __name__ == "__main__":
    ingest_logs()
