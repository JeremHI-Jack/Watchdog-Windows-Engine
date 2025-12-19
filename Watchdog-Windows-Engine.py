# Windows Event Watchdog - single-file script
# Adds: Anthracite DarkMode + Source filters (checkboxes) with live rebuild
# Adds (Option A): automatic UI purge at midnight + "today" state reset (browser) + optional marker
#
# Dependencies:
#   pip install pywin32 psutil pillow pystray watchdog
# Optional:
#   pip install wmi
#
# Notes:
# - Run as Administrator to enable advanced logging best-effort (wevtutil + policies + defender + firewall).
# - Tray icon handling uses run_detached() if available.

import sys
import os
import time
import threading
import queue
import sqlite3
import shutil
import tempfile
import datetime
import socket
import platform
import getpass
import subprocess
import ctypes
import xml.etree.ElementTree as ET

import pythoncom
import win32evtlog
import win32con
import psutil

import tkinter as tk
from tkinter import ttk

import pystray
from pystray import MenuItem
from PIL import Image, ImageDraw

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

try:
    import wmi
except ImportError:
    wmi = None


# =========================
# config
# =========================

ICON_FILENAME = "watchdog.ico"

LOGS_TO_MONITOR = [
    "System",
    "Application",
    "Security",
]

CHANNELS_TO_MONITOR = [
    "Microsoft-Windows-PowerShell/Operational",
    "Microsoft-Windows-Windows Defender/Operational",
    "Microsoft-Windows-WMI-Activity/Operational",
    "Microsoft-Windows-TaskScheduler/Operational",
    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational",
    "Microsoft-Windows-DNS-Client/Operational",
    "Microsoft-Windows-WinRM/Operational",
    "Setup",
    "ForwardedEvents",
    "Microsoft-Antimalware-Scan-Interface/Operational",
]

POLL_INTERVAL = 1.0
BROWSER_HISTORY_LIMIT = 200
BROWSER_POLL_INTERVAL = 5.0
COMMAND_POLL_INTERVAL = 1.0
PROCESS_POLL_INTERVAL = 1.5
NETWORK_POLL_INTERVAL = 2.0

LOG_DIR = r"C:\tmp\watchdog"
LOG_RETENTION_DAYS = 31

FILE_POLL_PATHS = [
    os.path.expanduser("~/Documents"),
    os.path.expanduser("~/Desktop"),
]

EVENT_TYPE_MAP = {
    win32con.EVENTLOG_ERROR_TYPE: "ERROR",
    win32con.EVENTLOG_WARNING_TYPE: "WARNING",
    win32con.EVENTLOG_INFORMATION_TYPE: "INFO",
    win32con.EVENTLOG_AUDIT_SUCCESS: "AUDIT_SUCCESS",
    win32con.EVENTLOG_AUDIT_FAILURE: "AUDIT_FAILURE",
}

LOG_COLORS = {
    "System": "blue",
    "Application": "green",
    "Security": "red",
    "Channel": "steelblue",
    "Firewall": "orange",
    "Network": "purple",
    "Browser": "darkcyan",
    "Command": "magenta",
    "Process": "brown",
    "Filesystem": "sienna",
    "USB": "darkgoldenrod",
    "HostInfo": "darkgreen",
}

COMMAND_PROCESS_NAMES = {
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "powershell_ise.exe",
    "wt.exe",
    "wsl.exe",
    "bash.exe",
}

# UI buffer limit to avoid unbounded memory growth
MAX_UI_BUFFER_LINES = 200_000
MAX_SECURITY_4624_INITIAL = 200

# Option A marker at midnight
MIDNIGHT_MARKER_ENABLED = True
MIDNIGHT_MARKER_TEXT = "=== new day: ui timeline reset at midnight ==="


# =========================
# helpers
# =========================

def sanitize_for_gui(text: str) -> str:
    return "".join(c for c in text if c.isprintable() or c in "\n\r\t")


def today_start() -> datetime.datetime:
    d = datetime.date.today()
    return datetime.datetime(d.year, d.month, d.day, 0, 0, 0)


def resource_path(relative_path: str) -> str:
    if getattr(sys, "frozen", False):
        base_path = getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
    else:
        base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, relative_path)


def create_tray_icon_image():
    icon_path = resource_path(ICON_FILENAME)
    try:
        if os.path.exists(icon_path):
            return Image.open(icon_path)
    except Exception:
        pass

    image = Image.new("RGB", (64, 64), color="black")
    draw = ImageDraw.Draw(image)
    draw.rectangle((16, 16, 48, 48), fill="cyan")
    return image


def is_running_as_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _run_cmd_silent(cmd: list[str]) -> tuple[int, str]:
    try:
        p = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        out = (p.stdout or "") + (p.stderr or "")
        return p.returncode, out.strip()
    except Exception as e:
        return 9999, str(e)


def enable_eventlog_channel(channel_name: str) -> tuple[bool, str]:
    rc, out = _run_cmd_silent(["wevtutil", "set-log", channel_name, "/enabled:true"])
    if rc == 0:
        return True, f"enabled: {channel_name}"
    return False, f"failed: {channel_name} (rc={rc}) {out}"


def apply_registry_powershell_logging() -> list[str]:
    ps = r"""
    $ErrorActionPreference = "Stop"

    New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell -Force | Out-Null

    New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -Force | Out-Null
    Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging `
      -Name EnableScriptBlockLogging -Value 1 -Type DWord

    New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging -Force | Out-Null
    Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging `
      -Name EnableModuleLogging -Value 1 -Type DWord

    New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames -Force | Out-Null
    Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames `
      -Name "*" -Value "*" -Type String

    "ok: powershell scriptblock+module logging policies applied"
    """
    rc, out = _run_cmd_silent(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps])
    if rc == 0:
        return [out or "ok: powershell logging policies applied"]
    return [f"failed: powershell logging policies (rc={rc}) {out}"]


def apply_defender_preferences() -> list[str]:
    ps = r"""
    $ErrorActionPreference = "Stop"
    try {
        Set-MpPreference -DisableRealtimeMonitoring $false | Out-Null
        Set-MpPreference -SubmitSamplesConsent 2 | Out-Null
        Set-MpPreference -MAPSReporting Advanced | Out-Null
        "ok: defender preferences applied"
    } catch {
        "failed: defender preferences " + $_.Exception.Message
    }
    """
    rc, out = _run_cmd_silent(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps])
    if rc == 0:
        return [out or "ok: defender preferences applied"]
    return [f"failed: defender preferences (rc={rc}) {out}"]


def apply_firewall_logging() -> list[str]:
    ps = r"""
    $ErrorActionPreference = "Stop"
    try {
        Set-NetFirewallProfile -Profile Domain,Public,Private `
          -LogAllowed True `
          -LogBlocked True `
          -LogFileName "%systemroot%\System32\LogFiles\Firewall\pfirewall.log" `
          -LogMaxSizeKilobytes 32767 | Out-Null
        "ok: firewall logging enabled"
    } catch {
        "failed: firewall logging " + $_.Exception.Message
    }
    """
    rc, out = _run_cmd_silent(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps])
    if rc == 0:
        return [out or "ok: firewall logging enabled"]
    return [f"failed: firewall logging (rc={rc}) {out}"]


def auto_enable_advanced_logs(event_queue) -> None:
    if not is_running_as_admin():
        event_queue.put(("warning", "[!] not running as admin: advanced log enablement skipped."))
        return

    event_queue.put(("info", "[+] running as admin: enabling advanced windows logging (best effort)."))

    for ch in CHANNELS_TO_MONITOR:
        ok, msg = enable_eventlog_channel(ch)
        event_queue.put(("info" if ok else "warning", f"[LOGCFG] {msg}"))

    for msg in apply_registry_powershell_logging():
        event_queue.put(("info" if msg.startswith("ok:") else "warning", f"[LOGCFG] {msg}"))

    for msg in apply_defender_preferences():
        event_queue.put(("info" if msg.startswith("ok:") else "warning", f"[LOGCFG] {msg}"))

    for msg in apply_firewall_logging():
        event_queue.put(("info" if msg.startswith("ok:") else "warning", f"[LOGCFG] {msg}"))

    event_queue.put(("info", "[+] advanced log enablement routine finished."))


# =========================
# host snapshot
# =========================

def log_host_security_snapshot(event_queue):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def _safe(f, default="unknown"):
        try:
            return f()
        except Exception:
            return default

    hostname = _safe(socket.gethostname)
    fqdn = _safe(socket.getfqdn)
    username = _safe(getpass.getuser)
    os_str = _safe(platform.platform)
    arch = _safe(platform.machine)

    try:
        boot_time = datetime.datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        boot_time = "unknown"

    net_lines = []
    try:
        addrs = psutil.net_if_addrs()
        for if_name, addr_list in addrs.items():
            for addr in addr_list:
                if getattr(addr, "family", None) == getattr(socket, "AF_INET", None):
                    net_lines.append(f"{if_name}={addr.address}")
    except Exception:
        pass

    user_sessions = []
    try:
        for u in psutil.users():
            started = datetime.datetime.fromtimestamp(u.started).strftime("%Y-%m-%d %H:%M:%S")
            user_sessions.append(f"{u.name}@{u.host or 'local'} (since {started})")
    except Exception:
        pass

    line_base = f"[{now}] {'HostInfo':<12} {'INFO':<13}"
    event_queue.put(("HostInfo", sanitize_for_gui(f"{line_base} hostname={hostname} fqdn={fqdn} user={username}")))
    event_queue.put(("HostInfo", sanitize_for_gui(f"{line_base} os={os_str} arch={arch} boot_time={boot_time}")))

    for net in net_lines:
        event_queue.put(("HostInfo", sanitize_for_gui(f"{line_base} ip={net}")))

    for sess in user_sessions:
        event_queue.put(("HostInfo", sanitize_for_gui(f"{line_base} session={sess}")))


# =========================
# classic windows events (OpenEventLog)
# =========================

def classify_event(base_log_name, event_id: int) -> str:
    if base_log_name == "Security":
        if event_id == 4624:
            return "LOGIN_SUCCESS"
        elif event_id == 4625:
            return "LOGIN_FAILURE"
        elif event_id in (4634, 4647):
            return "LOGOFF"
        elif event_id == 4688:
            return "PROCESS_CREATE"
        elif event_id == 4720:
            return "ACCOUNT_CREATED"
        elif event_id == 4726:
            return "ACCOUNT_DELETED"
    elif base_log_name == "System":
        if event_id == 7045:
            return "SERVICE_INSTALL"
        elif event_id in (6005, 6006):
            return "EVENTLOG_SERVICE"
    return "GENERIC"


def format_event(base_log_name, event):
    dt = event.TimeGenerated
    timestamp = dt.strftime("%Y-%m-%d %H:%M:%S")

    event_id = event.EventID & 0xFFFF
    event_type = EVENT_TYPE_MAP.get(event.EventType, f"TYPE_{event.EventType}")
    source = event.SourceName
    category = event.EventCategory

    if event.StringInserts:
        message = " | ".join(str(s) for s in event.StringInserts)
    else:
        message = ""

    evt_class = classify_event(base_log_name, event_id)

    line = (
        f"[{timestamp}] {base_log_name:<12} {event_type:<13} "
        f"ID={event_id:<5} Cat={category:<3} Class={evt_class:<16} "
        f"Source={source:<40} {message}"
    )
    return sanitize_for_gui(line)


def open_event_logs(event_queue):
    contexts = []
    for log_name in LOGS_TO_MONITOR:
        try:
            handle = win32evtlog.OpenEventLog(None, log_name)
            oldest = win32evtlog.GetOldestEventLogRecord(handle)
            total = win32evtlog.GetNumberOfEventLogRecords(handle)
            last_record = oldest + total - 1 if total > 0 else oldest - 1

            ctx = {
                "name": log_name,
                "handle": handle,
                "oldest_record": oldest,
                "total": total,
                "last_record": last_record,
                "last_seen": oldest - 1,
            }
            contexts.append(ctx)
            event_queue.put(("info", f"[+] opened log: {log_name} (oldest={oldest}, total={total}, last_record={last_record})"))
        except Exception as e:
            event_queue.put(("warning", f"[!] could not open log '{log_name}': {e}"))
    return contexts


def close_event_logs(contexts):
    for ctx in contexts:
        try:
            win32evtlog.CloseEventLog(ctx["handle"])
        except Exception:
            pass


def read_events_for_today(ctx, event_queue, max_events=None):
    handle = ctx["handle"]
    log_name = ctx["name"]

    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    collected = []
    today0 = today_start()
    reached_previous_day = False

    while True:
        try:
            events = win32evtlog.ReadEventLog(handle, flags, 0)
        except Exception as e:
            event_queue.put(("warning", f"[!] error reading log '{log_name}': {e}"))
            break

        if not events:
            break

        for ev in events:
            if ev.TimeGenerated < today0:
                reached_previous_day = True
                break

            collected.append(ev)
            if max_events is not None and len(collected) >= max_events:
                reached_previous_day = True
                break

        if reached_previous_day:
            break

    collected.reverse()
    return collected


def show_initial_events(contexts, event_queue):
    event_queue.put(("info", "=== initial events for today only (classic logs) ==="))

    for ctx in contexts:
        base_log_name = ctx["name"]
        last_record = ctx["last_record"]
        oldest = ctx["oldest_record"]

        if last_record < oldest:
            event_queue.put(("info", f"[-] log {base_log_name}: no events."))
            ctx["last_seen"] = last_record
            continue

        # WARNING: read all events from today (no global limit)
        events_today = read_events_for_today(ctx, event_queue, max_events=None)

        if not events_today:
            event_queue.put(("info", f"[-] log {base_log_name}: no events for today."))
            ctx["last_seen"] = last_record
            continue

        event_queue.put(("info", f"--- today's events for log: {base_log_name} ---"))

        filtered = []

        if base_log_name == "Security":
            login_4624 = []
            others = []

            for ev in events_today:
                event_id = ev.EventID & 0xFFFF
                if event_id == 4624:
                    login_4624.append(ev)
                else:
                    others.append(ev)

            # keep ONLY the last N 4624 events
            login_4624 = login_4624[-MAX_SECURITY_4624_INITIAL:]

            filtered = others + login_4624
            filtered.sort(key=lambda e: e.TimeGenerated)

            event_queue.put(
                ("info",
                 f"[Security] LOGIN_SUCCESS (4624) limited to last {MAX_SECURITY_4624_INITIAL}, others fully shown.")
            )
        else:
            filtered = events_today

        max_record_number = ctx["last_seen"]

        for ev in filtered:
            line = format_event(base_log_name, ev)
            event_queue.put((base_log_name, line))
            if hasattr(ev, "RecordNumber") and ev.RecordNumber > max_record_number:
                max_record_number = ev.RecordNumber

        ctx["last_seen"] = max_record_number

    event_queue.put(("info", "=== end of initial today history (classic logs) ==="))
    event_queue.put(("info", ""))


def read_events_range(ctx, start_record, end_record, max_batch=256):
    handle = ctx["handle"]
    flags = win32evtlog.EVENTLOG_SEEK_READ | win32evtlog.EVENTLOG_FORWARDS_READ

    collected = []
    current = start_record

    while current <= end_record:
        try:
            events = win32evtlog.ReadEventLog(handle, flags, current)
        except Exception:
            break

        if not events:
            break

        for ev in events:
            rn = ev.RecordNumber
            if rn < start_record:
                continue
            if rn > end_record:
                return collected

            collected.append(ev)
            current = rn + 1

            if len(collected) >= max_batch:
                return collected

    return collected


def worker_event_stream(event_queue, stop_event):
    contexts = open_event_logs(event_queue)
    if not contexts:
        event_queue.put(("error", "[-] no logs opened, exiting classic windows events worker."))
        return

    show_initial_events(contexts, event_queue)
    event_queue.put(("info", "=== classic windows event log stream started ==="))
    event_queue.put(("info", ""))

    try:
        while not stop_event.is_set():
            new_event_found = False

            for ctx in contexts:
                base_log_name = ctx["name"]
                handle = ctx["handle"]

                try:
                    oldest = win32evtlog.GetOldestEventLogRecord(handle)
                    total = win32evtlog.GetNumberOfEventLogRecords(handle)
                except Exception as e:
                    event_queue.put(("warning", f"[!] error querying log '{base_log_name}': {e}"))
                    continue

                last_record = oldest + total - 1 if total > 0 else oldest - 1
                ctx["oldest_record"] = oldest
                ctx["total"] = total
                ctx["last_record"] = last_record

                if ctx["last_seen"] < oldest - 1:
                    ctx["last_seen"] = oldest - 1

                if last_record <= ctx["last_seen"]:
                    continue

                start_record = max(ctx["last_seen"] + 1, oldest)
                end_record = last_record

                events = read_events_range(ctx, start_record, end_record, max_batch=512)
                if not events:
                    continue

                new_event_found = True
                for ev in events:
                    line = format_event(base_log_name, ev)
                    event_queue.put((base_log_name, line))
                    if hasattr(ev, "RecordNumber") and ev.RecordNumber > ctx["last_seen"]:
                        ctx["last_seen"] = ev.RecordNumber

            if not new_event_found:
                time.sleep(POLL_INTERVAL)

    finally:
        close_event_logs(contexts)
        event_queue.put(("info", "[+] classic event log handles closed."))


# =========================
# modern channels (EvtQuery) - forward stable bookmark
# =========================

def _xml_find_local(node, localname: str):
    if node is None:
        return None
    for child in list(node):
        tag = child.tag
        if tag.endswith("}" + localname) or tag == localname:
            return child
    return None


def _xml_findtext_local(node, localname: str, default: str = "") -> str:
    c = _xml_find_local(node, localname)
    if c is None or c.text is None:
        return default
    return c.text.strip()


def _parse_evt_xml_minimal(xml: str) -> dict:
    out = {"timestamp": "", "provider": "", "event_id": "?", "channel": "", "record_id": None}
    try:
        root = ET.fromstring(xml)
        sys_node = _xml_find_local(root, "System")
        if sys_node is None:
            return out

        prov = _xml_find_local(sys_node, "Provider")
        if prov is not None:
            out["provider"] = (prov.attrib.get("Name") or "").strip()

        out["event_id"] = _xml_findtext_local(sys_node, "EventID", "?")
        out["channel"] = _xml_findtext_local(sys_node, "Channel", "")

        erid = _xml_findtext_local(sys_node, "EventRecordID", "")
        if erid.isdigit():
            out["record_id"] = int(erid)

        tc = _xml_find_local(sys_node, "TimeCreated")
        if tc is not None:
            st = (tc.attrib.get("SystemTime") or "").strip()
            if st:
                st2 = st.replace("T", " ").replace("Z", "")
                st2 = st2.split(".")[0]
                out["timestamp"] = st2
    except Exception:
        return out

    return out


def _channel_exists(channel: str) -> bool:
    rc, _out = _run_cmd_silent(["wevtutil", "gl", channel])
    return rc == 0


def worker_channel_stream(event_queue, stop_event):
    event_queue.put(("info", "=== windows event log channel stream started ==="))

    try:
        _ = win32evtlog.EvtQuery
        _ = win32evtlog.EvtNext
        _ = win32evtlog.EvtRender
        _ = win32evtlog.EvtClose
    except AttributeError:
        event_queue.put(("warning", "[channel] evtquery api not available in this pywin32 build."))
        return

    active_channels = []
    for ch in CHANNELS_TO_MONITOR:
        if _channel_exists(ch):
            active_channels.append(ch)
        else:
            event_queue.put(("warning", f"[channel] disabled (not found): {ch}"))

    if not active_channels:
        event_queue.put(("warning", "[channel] no available channels on this host."))
        return

    last_warn = {ch: 0.0 for ch in active_channels}
    last_record_id = {ch: None for ch in active_channels}

    flags = win32evtlog.EvtQueryChannelPath

    try:
        while not stop_event.is_set():
            any_new = False

            for channel in active_channels:
                try:
                    if last_record_id[channel] is None:
                        query = "*"
                    else:
                        query = f"*[System[(EventRecordID>{last_record_id[channel]})]]"

                    hq = win32evtlog.EvtQuery(channel, flags, query)

                except Exception as e:
                    now = time.time()
                    if now - last_warn[channel] > 60:
                        last_warn[channel] = now
                        event_queue.put(("warning", f"[channel] cannot query {channel}: {e}"))
                    continue

                try:
                    handles = win32evtlog.EvtNext(hq, 64)
                    if not handles:
                        continue

                    any_new = True
                    for eh in list(handles):
                        try:
                            xml = win32evtlog.EvtRender(eh, win32evtlog.EvtRenderEventXml)
                        except Exception:
                            continue

                        meta = _parse_evt_xml_minimal(xml)
                        ts = meta.get("timestamp") or datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        chname = meta.get("channel") or channel
                        eid = meta.get("event_id") or "?"
                        prov = meta.get("provider") or "unknown"
                        rid = meta.get("record_id")

                        if rid is not None:
                            prev = last_record_id[channel]
                            if prev is None or rid > prev:
                                last_record_id[channel] = rid

                        line = (
                            f"[{ts}] {'Channel':<12} {'INFO':<13} "
                            f"Ch={chname:<55} ID={eid:<6} Provider={prov}"
                        )
                        event_queue.put(("Channel", sanitize_for_gui(line)))

                except Exception as e:
                    now = time.time()
                    if now - last_warn[channel] > 60:
                        last_warn[channel] = now
                        event_queue.put(("warning", f"[channel] read error {channel}: {e}"))

                finally:
                    try:
                        win32evtlog.EvtClose(hq)
                    except Exception:
                        pass

            time.sleep(1.0 if any_new else 2.0)

    finally:
        event_queue.put(("info", "[+] channel worker stopped."))


# =========================
# browser history (chrome/edge/firefox) - today only (with midnight reset support)
# =========================

def chrome_time_to_datetime(chrome_time: int):
    if not chrome_time:
        return None
    epoch_start = datetime.datetime(1601, 1, 1)
    return epoch_start + datetime.timedelta(microseconds=chrome_time)


def firefox_time_to_datetime(fx_time: int):
    if not fx_time:
        return None
    epoch_start = datetime.datetime(1970, 1, 1)
    return epoch_start + datetime.timedelta(microseconds=fx_time)


def chrome_datetime_to_raw(dt: datetime.datetime) -> int:
    epoch_start = datetime.datetime(1601, 1, 1)
    delta = dt - epoch_start
    return int(delta.total_seconds() * 1_000_000)


def firefox_datetime_to_raw(dt: datetime.datetime) -> int:
    epoch_start = datetime.datetime(1970, 1, 1)
    delta = dt - epoch_start
    return int(delta.total_seconds() * 1_000_000)


def find_browser_history_files():
    results = []
    local_app = os.environ.get("LOCALAPPDATA", "")
    app_data = os.environ.get("APPDATA", "")

    chrome_root = os.path.join(local_app, "Google", "Chrome", "User Data")
    if os.path.isdir(chrome_root):
        for prof in ["Default"] + [d for d in os.listdir(chrome_root) if d.lower().startswith("profile")]:
            hist = os.path.join(chrome_root, prof, "History")
            if os.path.exists(hist):
                results.append((f"Chrome ({prof})", hist))

    edge_root = os.path.join(local_app, "Microsoft", "Edge", "User Data")
    if os.path.isdir(edge_root):
        for prof in ["Default"] + [d for d in os.listdir(edge_root) if d.lower().startswith("profile")]:
            hist = os.path.join(edge_root, prof, "History")
            if os.path.exists(hist):
                results.append((f"Edge ({prof})", hist))

    firefox_profiles_root = os.path.join(app_data, "Mozilla", "Firefox", "Profiles")
    if os.path.isdir(firefox_profiles_root):
        for entry in os.listdir(firefox_profiles_root):
            profile_dir = os.path.join(firefox_profiles_root, entry)
            if not os.path.isdir(profile_dir):
                continue
            places = os.path.join(profile_dir, "places.sqlite")
            if os.path.exists(places):
                results.append((f"Firefox ({entry})", places))

    return results


def _copy_sqlite_best_effort(src_db_path: str) -> str:
    tmp_fd, tmp_db = tempfile.mkstemp(suffix=".sqlite")
    os.close(tmp_fd)

    try:
        shutil.copy2(src_db_path, tmp_db)
    except Exception:
        return tmp_db

    for suffix in ("-wal", "-shm"):
        src = src_db_path + suffix
        if os.path.exists(src):
            try:
                shutil.copy2(src, tmp_db + suffix)
            except Exception:
                pass

    return tmp_db


def load_chromium_history_incremental(browser_name: str, db_path: str, min_raw_time, limit: int):
    entries = []
    max_raw = None

    tmp_path = _copy_sqlite_best_effort(db_path)

    conn = None
    try:
        conn = sqlite3.connect(tmp_path)
        cur = conn.cursor()

        if min_raw_time is None:
            cur.execute(
                """
                SELECT url, title, last_visit_time
                FROM urls
                ORDER BY last_visit_time DESC
                LIMIT ?
                """,
                (limit,),
            )
            rows = cur.fetchall()
            rows.reverse()
        else:
            cur.execute(
                """
                SELECT url, title, last_visit_time
                FROM urls
                WHERE last_visit_time > ?
                ORDER BY last_visit_time ASC
                LIMIT ?
                """,
                (min_raw_time, limit),
            )
            rows = cur.fetchall()

        for url, title, last_visit_time in rows:
            dt = chrome_time_to_datetime(last_visit_time)
            ts = dt.strftime("%Y-%m-%d %H:%M:%S") if dt else ""
            entries.append(
                {"time": ts, "raw_time": last_visit_time, "browser": browser_name, "title": title or "", "url": url or ""}
            )
            if max_raw is None or last_visit_time > max_raw:
                max_raw = last_visit_time

    finally:
        try:
            if conn:
                conn.close()
        except Exception:
            pass
        for p in (tmp_path, tmp_path + "-wal", tmp_path + "-shm"):
            try:
                if os.path.exists(p):
                    os.remove(p)
            except Exception:
                pass

    return entries, max_raw


def load_firefox_history_incremental(browser_name: str, db_path: str, min_raw_time, limit: int):
    entries = []
    max_raw = None

    tmp_path = _copy_sqlite_best_effort(db_path)

    conn = None
    try:
        conn = sqlite3.connect(tmp_path)
        cur = conn.cursor()

        if min_raw_time is None:
            cur.execute(
                """
                SELECT url, title, last_visit_date
                FROM moz_places
                WHERE last_visit_date IS NOT NULL
                ORDER BY last_visit_date DESC
                LIMIT ?
                """,
                (limit,),
            )
            rows = cur.fetchall()
            rows.reverse()
        else:
            cur.execute(
                """
                SELECT url, title, last_visit_date
                FROM moz_places
                WHERE last_visit_date IS NOT NULL
                  AND last_visit_date > ?
                ORDER BY last_visit_date ASC
                LIMIT ?
                """,
                (min_raw_time, limit),
            )
            rows = cur.fetchall()

        for url, title, last_visit_date in rows:
            dt = firefox_time_to_datetime(last_visit_date)
            ts = dt.strftime("%Y-%m-%d %H:%M:%S") if dt else ""
            entries.append(
                {"time": ts, "raw_time": last_visit_date, "browser": browser_name, "title": title or "", "url": url or ""}
            )
            if max_raw is None or last_visit_date > max_raw:
                max_raw = last_visit_date

    finally:
        try:
            if conn:
                conn.close()
        except Exception:
            pass
        for p in (tmp_path, tmp_path + "-wal", tmp_path + "-shm"):
            try:
                if os.path.exists(p):
                    os.remove(p)
            except Exception:
                pass

    return entries, max_raw


def worker_browser_stream(event_queue, stop_event, browser_reset_state: dict, browser_reset_lock: threading.Lock):
    event_queue.put(("info", "=== browser history stream (today only) started ==="))

    browser_last_seen = {}
    initial_done = False
    current_day_str = datetime.date.today().strftime("%Y%m%d")

    def _recompute_day_thresholds():
        day0 = today_start()
        chrome_threshold = chrome_datetime_to_raw(day0)
        firefox_threshold = firefox_datetime_to_raw(day0)
        return chrome_threshold, firefox_threshold

    chrome_threshold, firefox_threshold = _recompute_day_thresholds()

    try:
        while not stop_event.is_set():
            # Option A: midnight reset signal from UI, plus self-detect day change
            now_day_str = datetime.date.today().strftime("%Y%m%d")

            reset_requested = False
            with browser_reset_lock:
                if browser_reset_state.get("reset", False):
                    reset_requested = True
                    browser_reset_state["reset"] = False

            if reset_requested or (now_day_str != current_day_str):
                current_day_str = now_day_str
                browser_last_seen.clear()
                initial_done = False
                chrome_threshold, firefox_threshold = _recompute_day_thresholds()
                event_queue.put(("info", f"[Browser] new day detected: thresholds reset for {current_day_str}"))

            files = find_browser_history_files()
            if not files and not initial_done:
                event_queue.put(("warning", "[Browser] no browser history database found (chrome/edge/firefox)."))

            for browser_name, path in files:
                is_chromium = ("chrome" in browser_name.lower()) or ("edge" in browser_name.lower())
                day_threshold = chrome_threshold if is_chromium else firefox_threshold

                last_seen_raw = browser_last_seen.get(browser_name)

                if not initial_done:
                    min_raw_time_for_query = day_threshold
                else:
                    min_raw_time_for_query = max(last_seen_raw or day_threshold, day_threshold)

                try:
                    if is_chromium:
                        entries, max_raw = load_chromium_history_incremental(
                            browser_name, path, min_raw_time_for_query, BROWSER_HISTORY_LIMIT
                        )
                    else:
                        entries, max_raw = load_firefox_history_incremental(
                            browser_name, path, min_raw_time_for_query, BROWSER_HISTORY_LIMIT
                        )
                except Exception as e:
                    event_queue.put(("warning", f"[Browser] error loading history for {browser_name}: {e}"))
                    continue

                if not entries:
                    continue

                for entry in entries:
                    ts = entry.get("time", "")
                    bname = entry.get("browser", "")
                    title = sanitize_for_gui(entry.get("title", ""))
                    url = sanitize_for_gui(entry.get("url", ""))

                    line = f"[{ts}] {'Browser':<12} {'INFO':<13} {bname:<25} {title} - {url}"
                    event_queue.put(("Browser", line))

                if max_raw is not None:
                    prev = browser_last_seen.get(browser_name, max_raw)
                    browser_last_seen[browser_name] = max(prev, max_raw)

            initial_done = True
            time.sleep(BROWSER_POLL_INTERVAL)

    finally:
        event_queue.put(("info", "[+] browser history worker stopped."))


# =========================
# command / process / network
# =========================

def worker_commands_stream(event_queue, stop_event):
    event_queue.put(("info", "=== command process watcher started ==="))
    seen_pids = set()

    try:
        while not stop_event.is_set():
            try:
                for proc in psutil.process_iter(["pid", "name", "create_time", "cmdline"]):
                    pid = proc.info.get("pid")
                    if pid in seen_pids:
                        continue

                    name = (proc.info.get("name") or "").lower()
                    if name not in COMMAND_PROCESS_NAMES:
                        continue

                    seen_pids.add(pid)

                    try:
                        create_ts = proc.info.get("create_time")
                        dt = datetime.datetime.fromtimestamp(create_ts) if create_ts else datetime.datetime.now()
                        timestamp = dt.strftime("%Y-%m-%d %H:%M:%S")
                        cmdline = " ".join(proc.info.get("cmdline") or [])
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue

                    line = f"[{timestamp}] {'Command':<12} {'INFO':<13} {name:<25} {cmdline}"
                    event_queue.put(("Command", sanitize_for_gui(line)))

            except Exception as e:
                event_queue.put(("warning", f"[!] error in command watcher: {e}"))

            time.sleep(COMMAND_POLL_INTERVAL)

    finally:
        event_queue.put(("info", "[+] command process watcher stopped."))


def worker_process_stream(event_queue, stop_event):
    event_queue.put(("info", "=== process watcher (all processes) started ==="))
    seen_pids = set()
    MAX_SEEN_PIDS = 50000

    try:
        while not stop_event.is_set():
            try:
                for proc in psutil.process_iter(["pid", "name", "exe", "create_time", "ppid", "username", "cmdline"]):
                    pid = proc.info.get("pid")
                    if pid in seen_pids:
                        continue

                    seen_pids.add(pid)
                    if len(seen_pids) > MAX_SEEN_PIDS:
                        seen_pids.clear()

                    name = proc.info.get("name") or ""
                    exe = proc.info.get("exe") or ""
                    ppid = proc.info.get("ppid")
                    user = proc.info.get("username") or ""
                    cmdline = " ".join(proc.info.get("cmdline") or [])

                    create_ts = proc.info.get("create_time") or time.time()
                    dt = datetime.datetime.fromtimestamp(create_ts)
                    timestamp = dt.strftime("%Y-%m-%d %H:%M:%S")

                    line = (
                        f"[{timestamp}] {'Process':<12} {'INFO':<13} "
                        f"pid={pid:<6} ppid={ppid:<6} user={user:<20} "
                        f"name={name:<25} exe={exe} cmd={cmdline}"
                    )
                    event_queue.put(("Process", sanitize_for_gui(line)))

            except Exception as e:
                event_queue.put(("warning", f"[!] error in process watcher: {e}"))

            time.sleep(PROCESS_POLL_INTERVAL)

    finally:
        event_queue.put(("info", "[+] process watcher stopped."))


def worker_network_stream(event_queue, stop_event):
    event_queue.put(("info", "=== network connection watcher started ==="))
    seen_conns = set()
    MAX_SEEN_CONNS = 100000

    try:
        while not stop_event.is_set():
            try:
                conns = psutil.net_connections(kind="inet")
                ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                for c in conns:
                    pid = c.pid
                    if pid is None:
                        continue

                    laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
                    raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""
                    key = (pid, laddr, raddr, c.status)

                    if key in seen_conns:
                        continue
                    seen_conns.add(key)
                    if len(seen_conns) > MAX_SEEN_CONNS:
                        seen_conns.clear()

                    try:
                        proc = psutil.Process(pid)
                        name = proc.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        name = "unknown"

                    line = (
                        f"[{ts}] {'Network':<12} {'INFO':<13} "
                        f"pid={pid:<6} proc={name:<20} "
                        f"laddr={laddr:<22} raddr={raddr:<22} status={c.status}"
                    )
                    event_queue.put(("Network", sanitize_for_gui(line)))

            except Exception as e:
                event_queue.put(("warning", f"[!] error in network watcher: {e}"))

            time.sleep(NETWORK_POLL_INTERVAL)

    finally:
        event_queue.put(("info", "[+] network connection watcher stopped."))


# =========================
# filesystem watcher
# =========================

class _FSHandler(FileSystemEventHandler):
    def __init__(self, event_queue):
        super().__init__()
        self.event_queue = event_queue

    def on_any_event(self, event):
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        action = "MODIFIED"
        if event.event_type == "created":
            action = "CREATED"
        elif event.event_type == "deleted":
            action = "DELETED"
        elif event.event_type == "moved":
            action = "MOVED"

        line = f"[{ts}] {'Filesystem':<12} {'INFO':<13} {action:<8} path={event.src_path}"
        self.event_queue.put(("Filesystem", sanitize_for_gui(line)))


def worker_filesystem_stream(event_queue, stop_event):
    event_queue.put(("info", "=== filesystem watcher started ==="))
    observer = Observer()
    handler = _FSHandler(event_queue)

    for path in FILE_POLL_PATHS:
        if os.path.isdir(path):
            try:
                observer.schedule(handler, path, recursive=True)
                event_queue.put(("info", f"[+] filesystem watcher monitoring: {path}"))
            except Exception as e:
                event_queue.put(("warning", f"[!] cannot watch path {path}: {e}"))

    observer.start()

    try:
        while not stop_event.is_set():
            time.sleep(1.0)
    finally:
        observer.stop()
        observer.join()
        event_queue.put(("info", "[+] filesystem watcher stopped."))


# =========================
# usb watcher
# =========================

def worker_usb_stream(event_queue, stop_event):
    if wmi is None:
        event_queue.put(("warning", "[!] usb watcher not started: 'wmi' module not installed."))
        return

    try:
        pythoncom.CoInitialize()
    except Exception as e:
        event_queue.put(("warning", f"[!] usb watcher: CoInitialize failed: {e}"))
        return

    event_queue.put(("info", "=== usb watcher started ==="))

    try:
        try:
            c = wmi.WMI()
        except Exception as e:
            event_queue.put(("warning", f"[!] usb watcher: cannot create WMI object: {e}"))
            return

        try:
            watcher = c.watch_for(notification_type="Creation", wmi_class="Win32_VolumeChangeEvent")
        except Exception as e:
            event_queue.put(("warning", f"[!] usb watcher: watch_for failed: {e}"))
            return

        while not stop_event.is_set():
            try:
                evt = watcher(timeout_ms=1000)
                ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                event_type = getattr(evt, "EventType", None)
                drive_name = getattr(evt, "DriveName", "")

                line = f"[{ts}] {'USB':<12} {'INFO':<13} VolumeEventType={event_type} DriveName={drive_name}"
                event_queue.put(("USB", sanitize_for_gui(line)))

            except wmi.x_wmi_timed_out:
                continue
            except Exception as e:
                event_queue.put(("warning", f"[!] usb watcher error: {e}"))
                time.sleep(1.0)

    finally:
        try:
            pythoncom.CoUninitialize()
        except Exception:
            pass
        event_queue.put(("info", "[+] usb watcher stopped."))


# =========================
# gui + tray + disk logs + DarkMode (anthracite) + Source filters
# + Option A: midnight UI purge + reset "today" state (browser)
# =========================

class EventViewerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Windows Event Watchdog")
        self.root.geometry("1250x780")

        try:
            icon_path = resource_path(ICON_FILENAME)
            if os.path.exists(icon_path):
                self.root.iconbitmap(icon_path)
        except Exception:
            pass

        self.event_queue = queue.Queue()
        self.stop_event = threading.Event()

        self.log_dir = LOG_DIR
        self.current_log_date = None
        self.log_file = None

        self.tray_icon = None

        # buffering for stable rebuild on filter changes
        self.pending_events = []           # incoming batch
        self.all_events_buffer = []        # stored (tag, line) in insertion order for rebuild

        # search
        self.search_var = tk.StringVar()
        self.last_search_index = "1.0"

        # follow mode
        self.follow_live = True

        # DarkMode state
        self.dark_mode = True

        # Source filters (checkboxes)
        self.filter_vars: dict[str, tk.BooleanVar] = {}

        # Browser "today" reset state shared with worker
        self.browser_reset_state = {"reset": False}
        self.browser_reset_lock = threading.Lock()

        self._init_log_dir()

        # initial snapshot
        log_host_security_snapshot(self.event_queue)

        # ui
        self._build_ui()
        self._apply_theme()

        # enable advanced logs (best effort, admin only)
        auto_enable_advanced_logs(self.event_queue)

        # workers
        self._start_workers()

        # tray
        self._setup_tray_icon()

        # midnight rollover (Option A)
        self._schedule_midnight_rollover()

        # queue polling
        self._poll_queue()

        # start hidden in tray
        self.root.after(0, self.root.withdraw)

        # close/minimize -> hide
        self.root.protocol("WM_DELETE_WINDOW", self._hide_to_tray)
        self.root.bind("<Unmap>", self._on_minimize)

    # ---------- disk logs ----------
    def _get_today_str(self) -> str:
        return datetime.date.today().strftime("%Y%m%d")

    def _init_log_dir(self):
        try:
            os.makedirs(self.log_dir, exist_ok=True)
        except Exception:
            pass
        self._cleanup_old_logs()
        self._roll_log_file_if_needed()

    def _roll_log_file_if_needed(self):
        today_str = self._get_today_str()
        if self.current_log_date == today_str and self.log_file:
            return

        if self.log_file:
            try:
                self.log_file.close()
            except Exception:
                pass
            self.log_file = None

        self.current_log_date = today_str
        log_path = os.path.join(self.log_dir, f"{today_str}.log")

        try:
            self.log_file = open(log_path, "a", encoding="utf-8", buffering=1)
        except Exception:
            self.log_file = None

    def _cleanup_old_logs(self):
        try:
            files = os.listdir(self.log_dir)
        except Exception:
            return

        today = datetime.date.today()

        for fname in files:
            if not fname.lower().endswith(".log"):
                continue

            name_no_ext, _ext = os.path.splitext(fname)
            if len(name_no_ext) != 8 or not name_no_ext.isdigit():
                continue

            try:
                fdate = datetime.datetime.strptime(name_no_ext, "%Y%m%d").date()
            except ValueError:
                continue

            if (today - fdate).days > LOG_RETENTION_DAYS:
                try:
                    os.remove(os.path.join(self.log_dir, fname))
                except Exception:
                    pass

    def _write_log_line(self, tag_name: str, line: str):
        try:
            self._roll_log_file_if_needed()
            if not self.log_file:
                return
            self.log_file.write(f"[{tag_name}] {line}\n")
        except Exception:
            pass

    # ---------- Option A: midnight UI rollover ----------
    def _seconds_until_next_midnight(self) -> int:
        now = datetime.datetime.now()
        tomorrow = (now + datetime.timedelta(days=1)).date()
        next_midnight = datetime.datetime(tomorrow.year, tomorrow.month, tomorrow.day, 0, 0, 0)
        delta = next_midnight - now
        seconds = int(max(1, delta.total_seconds()))
        return seconds

    def _schedule_midnight_rollover(self):
        # schedule a one-shot timer until next midnight, then reschedule
        seconds = self._seconds_until_next_midnight()
        self.root.after(seconds * 1000, self._daily_ui_rollover)

    def _daily_ui_rollover(self):
        if self.stop_event.is_set():
            return

        # Optional marker
        if MIDNIGHT_MARKER_ENABLED:
            ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            marker_line = f"[{ts}] {'info':<12} {'INFO':<13} {MIDNIGHT_MARKER_TEXT}"
            self.event_queue.put(("info", marker_line))

        # Purge UI buffer
        try:
            self.all_events_buffer.clear()
        except Exception:
            self.all_events_buffer = []

        try:
            self.pending_events.clear()
        except Exception:
            self.pending_events = []

        # Purge visible text widget
        try:
            self.text.configure(state=tk.NORMAL)
            self.text.delete("1.0", tk.END)
        except Exception:
            pass

        # Reset search state
        self.last_search_index = "1.0"
        self._clear_search_highlight()

        # Reset browser "today" state in worker
        with self.browser_reset_lock:
            self.browser_reset_state["reset"] = True

        # Roll disk log file (ensures we write into the new day file ASAP)
        try:
            self._roll_log_file_if_needed()
        except Exception:
            pass

        # Optional: re-log host snapshot at start of day
        log_host_security_snapshot(self.event_queue)

        # Reschedule for next midnight
        self._schedule_midnight_rollover()

    # ---------- theme / DarkMode ----------
    def _apply_theme(self):
        # Anthracite palette
        AN_BG       = "#3a3f46"   # main background (window)
        AN_PANEL    = "#353a40"   # panels/frames
        AN_TEXT_BG  = "#2f3338"   # text background
        AN_BORDER   = "#4a5058"   # borders/separators
        AN_FG       = "#e8eaed"
        AN_MUTED    = "#c2c7cf"
        AN_SEL_BG   = "#4a6fa5"
        AN_SEL_FG   = "#ffffff"

        # Light palette
        LI_BG = "#f0f0f0"
        LI_PANEL = "#f0f0f0"
        LI_TEXT_BG = "#ffffff"
        LI_FG = "#111111"
        LI_MUTED = "gray40"
        LI_SEL_BG = "#cfe8ff"
        LI_SEL_FG = "#111111"

        if self.dark_mode:
            bg, panel, text_bg, border = AN_BG, AN_PANEL, AN_TEXT_BG, AN_BORDER
            fg, muted, sel_bg, sel_fg = AN_FG, AN_MUTED, AN_SEL_BG, AN_SEL_FG
        else:
            bg, panel, text_bg, border = LI_BG, LI_PANEL, LI_TEXT_BG, "#d0d0d0"
            fg, muted, sel_bg, sel_fg = LI_FG, LI_MUTED, LI_SEL_BG, LI_SEL_FG

        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass

        try:
            self.root.configure(bg=bg)
        except Exception:
            pass

        style.configure(".", background=panel, foreground=fg)
        style.configure("TFrame", background=panel)
        style.configure("TLabel", background=panel, foreground=fg)
        style.configure("TButton", background=panel, foreground=fg)
        style.map("TButton",
                  background=[("active", border)],
                  foreground=[("active", fg)])

        style.configure("TEntry", fieldbackground=text_bg, foreground=fg, insertcolor=fg)
        style.map("TEntry",
                  fieldbackground=[("active", text_bg), ("focus", text_bg)],
                  foreground=[("active", fg), ("focus", fg)])

        for widget in (self.header_text, self.text):
            try:
                widget.configure(
                    bg=text_bg,
                    fg=fg,
                    insertbackground=fg,
                    selectbackground=sel_bg,
                    selectforeground=sel_fg,
                    highlightbackground=border,
                    highlightcolor=border,
                )
            except Exception:
                pass

        if self.dark_mode:
            self.text.tag_config("info", foreground=muted)
            self.text.tag_config("warning", foreground="#ffcc66")
            self.text.tag_config("error", foreground="#ff6b6b", font=("Consolas", 10, "bold"))
            self.text.tag_config("search", background="#ffd54f", foreground="#000000")
        else:
            self.text.tag_config("info", foreground="gray40")
            self.text.tag_config("warning", foreground="orange")
            self.text.tag_config("error", foreground="red", font=("Consolas", 10, "bold"))
            self.text.tag_config("search", background="yellow", foreground="black")

        # rebuild header
        try:
            self.header_text.configure(state=tk.NORMAL)
            self.header_text.delete("1.0", tk.END)
            self.header_text.insert(tk.END, "Global timeline (oldest → newest) | ")
            for name, color in LOG_COLORS.items():
                self.header_text.insert(tk.END, name + "  ", name)
                self.header_text.tag_config(name, foreground=color)
            self.header_text.configure(state=tk.DISABLED)
        except Exception:
            pass

        try:
            self.dark_btn.config(text="LIGHT" if self.dark_mode else "DARK")
        except Exception:
            pass

    def toggle_dark_mode(self):
        self.dark_mode = not self.dark_mode
        self._apply_theme()

    # ---------- filters ----------
    def _is_tag_enabled(self, tag: str) -> bool:
        v = self.filter_vars.get(tag)
        if v is None:
            return True
        return bool(v.get())

    def _on_filters_changed(self):
        self._rebuild_view_from_buffer()

    def _select_all_filters(self, value: bool):
        for v in self.filter_vars.values():
            v.set(value)
        self._rebuild_view_from_buffer()

    def _rebuild_view_from_buffer(self):
        # preserve view position if not following live
        try:
            view_first, _view_last = self.text.yview()
        except Exception:
            view_first = 1.0

        # avoid UI flicker
        self.text.configure(state=tk.NORMAL)
        self.text.delete("1.0", tk.END)

        for tag, line in self.all_events_buffer:
            if self._is_tag_enabled(tag):
                self.text.insert(tk.END, line + "\n", tag)

        self.text.configure(state=tk.NORMAL)  # keep editable for tag operations/search

        # clear search highlights because indices changed
        self._clear_search_highlight()
        self.last_search_index = "1.0"

        if self.follow_live:
            try:
                self.text.see(tk.END)
            except Exception:
                pass
        else:
            try:
                self.text.yview_moveto(view_first)
            except Exception:
                pass

    # ---------- ui ----------
    def _build_ui(self):
        # header legend
        top_frame = ttk.Frame(self.root)
        top_frame.pack(side=tk.TOP, fill=tk.X, padx=8, pady=4)

        self.header_text = tk.Text(
            top_frame,
            height=1,
            borderwidth=0,
            highlightthickness=1,
            font=("Consolas", 10),
        )
        self.header_text.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # filters row
        filters_frame = ttk.Frame(self.root)
        filters_frame.pack(side=tk.TOP, fill=tk.X, padx=8, pady=(0, 4))

        ttk.Label(filters_frame, text="Sources:").pack(side=tk.LEFT, padx=(0, 6))

        filter_order = [
            "System", "Application", "Security", "Channel",
            "Process", "Command", "Network", "Browser",
            "Filesystem", "USB", "HostInfo",
            "info", "warning", "error",
        ]

        for tag in filter_order:
            var = tk.BooleanVar(value=True)
            self.filter_vars[tag] = var
            cb = ttk.Checkbutton(filters_frame, text=tag, variable=var, command=self._on_filters_changed)
            cb.pack(side=tk.LEFT, padx=(0, 6))

        ttk.Button(filters_frame, text="All", width=5, command=lambda: self._select_all_filters(True)).pack(side=tk.RIGHT, padx=(6, 0))
        ttk.Button(filters_frame, text="None", width=5, command=lambda: self._select_all_filters(False)).pack(side=tk.RIGHT, padx=(6, 0))

        # search row
        search_frame = ttk.Frame(self.root)
        search_frame.pack(side=tk.TOP, fill=tk.X, padx=8, pady=(0, 4))

        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT)

        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(search_frame, textvariable=self.search_var, width=40)
        self.search_entry.pack(side=tk.LEFT, padx=(4, 4))

        ttk.Button(search_frame, text="Find", command=self.on_search).pack(side=tk.LEFT, padx=(2, 0))
        ttk.Button(search_frame, text="Next", command=self.on_search_next).pack(side=tk.LEFT, padx=(2, 0))
        ttk.Button(search_frame, text="Clear", command=self.on_search_clear).pack(side=tk.LEFT, padx=(2, 0))

        self.search_entry.bind("<Return>", lambda _event: self.on_search())

        # main text
        text_frame = ttk.Frame(self.root)
        text_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=8, pady=4)

        self.text = tk.Text(text_frame, wrap=tk.NONE, font=("Consolas", 10), highlightthickness=1)
        v_scroll = tk.Scrollbar(text_frame, orient=tk.VERTICAL, command=self.text.yview)
        h_scroll = tk.Scrollbar(text_frame, orient=tk.HORIZONTAL, command=self.text.xview)

        self.text.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)

        v_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        h_scroll.pack(side=tk.BOTTOM, fill=tk.X)
        self.text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        for name, color in LOG_COLORS.items():
            self.text.tag_config(name, foreground=color)

        # status bar
        status_frame = ttk.Frame(self.root)
        status_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=8, pady=2)

        self.status_label = ttk.Label(status_frame, text="Starting...", anchor="w")
        self.status_label.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.dark_btn = ttk.Button(status_frame, text="LIGHT", width=7, command=self.toggle_dark_mode)
        self.dark_btn.pack(side=tk.RIGHT, padx=(2, 4))

        self.follow_btn = ttk.Button(status_frame, text="FOLLOW", width=8, command=self._toggle_follow)
        self.follow_btn.pack(side=tk.RIGHT, padx=(2, 4))

        btn_top = ttk.Button(status_frame, text="TOP", width=6, command=self.scroll_top)
        btn_top.pack(side=tk.RIGHT, padx=(4, 2))

        btn_down = ttk.Button(status_frame, text="DOWN", width=6, command=self.scroll_bottom)
        btn_down.pack(side=tk.RIGHT, padx=(2, 4))

        self.status_label.config(
            text="Streaming TODAY: classic events + channels + browser + commands + processes + network + filesystem + usb..."
        )

        # base tags
        self.text.tag_config("info", foreground="gray40")
        self.text.tag_config("warning", foreground="orange")
        self.text.tag_config("error", foreground="red", font=("Consolas", 10, "bold"))
        self.text.tag_config("search", background="yellow", foreground="black")

    def _toggle_follow(self):
        self.follow_live = not self.follow_live
        self.follow_btn.config(text="FOLLOW" if self.follow_live else "PAUSED")
        if self.follow_live:
            try:
                self.text.see(tk.END)
            except Exception:
                pass

    # ---------- workers ----------
    def _start_workers(self):
        threading.Thread(target=worker_event_stream, args=(self.event_queue, self.stop_event), daemon=True).start()
        threading.Thread(target=worker_channel_stream, args=(self.event_queue, self.stop_event), daemon=True).start()
        threading.Thread(
            target=worker_browser_stream,
            args=(self.event_queue, self.stop_event, self.browser_reset_state, self.browser_reset_lock),
            daemon=True,
        ).start()
        threading.Thread(target=worker_commands_stream, args=(self.event_queue, self.stop_event), daemon=True).start()
        threading.Thread(target=worker_process_stream, args=(self.event_queue, self.stop_event), daemon=True).start()
        threading.Thread(target=worker_network_stream, args=(self.event_queue, self.stop_event), daemon=True).start()
        threading.Thread(target=worker_filesystem_stream, args=(self.event_queue, self.stop_event), daemon=True).start()
        if wmi is not None:
            threading.Thread(target=worker_usb_stream, args=(self.event_queue, self.stop_event), daemon=True).start()

    # ---------- queue → ui ----------
    def _extract_timestamp(self, line: str):
        if not line.startswith("[") or len(line) < 21 or line[20] != "]":
            return None
        ts_str = line[1:20]
        try:
            return datetime.datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return None

    def _poll_queue(self):
        try:
            max_drain = 2000
            drained = 0

            while drained < max_drain:
                try:
                    log_name, line = self.event_queue.get_nowait()
                except queue.Empty:
                    break

                ts = self._extract_timestamp(line) or datetime.datetime.now()
                self.pending_events.append((ts, log_name, line))
                drained += 1

            if self.pending_events:
                self.pending_events.sort(key=lambda x: x[0])
                for _ts, log_name, line in self.pending_events:
                    self._append_event(log_name, line)
                self.pending_events.clear()

        finally:
            self.root.after(200, self._poll_queue)

    def _append_event(self, tag: str, line: str):
        # detect if user was at bottom BEFORE inserting
        try:
            _first, last = self.text.yview()
            at_bottom = (last >= 0.995)
        except Exception:
            at_bottom = True

        # store into buffer (for rebuild), with trimming
        self.all_events_buffer.append((tag, line))
        if len(self.all_events_buffer) > MAX_UI_BUFFER_LINES:
            # drop oldest chunk
            drop = max(1, MAX_UI_BUFFER_LINES // 10)
            self.all_events_buffer = self.all_events_buffer[drop:]

        # always log to disk (even if filtered out)
        disk_tag = tag if tag in LOG_COLORS or tag in ("info", "warning", "error") else "info"
        self._write_log_line(disk_tag, line)

        # display only if enabled by filter
        if not self._is_tag_enabled(tag):
            return

        self.text.insert(tk.END, line + "\n", tag)

        # auto-scroll only if follow_live and user was at bottom
        if self.follow_live and at_bottom:
            self.text.see(tk.END)

    # ---------- navigation ----------
    def scroll_top(self):
        try:
            self.text.yview_moveto(0.0)
        except Exception:
            pass

    def scroll_bottom(self):
        try:
            self.text.yview_moveto(1.0)
        except Exception:
            pass

    # ---------- search ----------
    def _clear_search_highlight(self):
        try:
            self.text.tag_remove("search", "1.0", tk.END)
        except Exception:
            pass

    def on_search(self):
        pattern = (self.search_var.get() or "").strip()
        if not pattern:
            self._clear_search_highlight()
            self.last_search_index = "1.0"
            return

        self._clear_search_highlight()
        start_idx = "1.0"
        first_match = None
        plen = len(pattern)

        while True:
            idx = self.text.search(pattern, start_idx, nocase=1, stopindex=tk.END)
            if not idx:
                break
            end_idx = f"{idx}+{plen}c"
            self.text.tag_add("search", idx, end_idx)
            if first_match is None:
                first_match = idx
            start_idx = end_idx

        if first_match:
            self.text.see(first_match)
            self.text.mark_set(tk.INSERT, first_match)
            self.last_search_index = first_match
        else:
            self.last_search_index = "1.0"

    def on_search_next(self):
        pattern = (self.search_var.get() or "").strip()
        if not pattern:
            return

        plen = len(pattern)
        start_idx = self.last_search_index if self.last_search_index else "1.0"
        idx = self.text.search(pattern, start_idx + "+1c", nocase=1, stopindex=tk.END)
        if not idx:
            idx = self.text.search(pattern, "1.0", nocase=1, stopindex=tk.END)
            if not idx:
                return

        end_idx = f"{idx}+{plen}c"
        self.text.see(idx)
        self.text.mark_set(tk.INSERT, idx)
        self.last_search_index = idx

    def on_search_clear(self):
        self.search_var.set("")
        self._clear_search_highlight()
        self.last_search_index = "1.0"

    # ---------- tray ----------
    def _setup_tray_icon(self):
        def on_show_window(_icon, _item):
            self.root.after(0, self._show_window)

        def on_quit(_icon, _item):
            self.root.after(0, self.on_close)

        menu = (
            MenuItem("Show window", on_show_window),
            MenuItem("Quit", on_quit),
        )

        self.tray_icon = pystray.Icon(
            name="Watchdog",
            icon=create_tray_icon_image(),
            title="Windows Watchdog",
            menu=menu,
        )

        try:
            run_detached = getattr(self.tray_icon, "run_detached", None)
            if callable(run_detached):
                self.tray_icon.run_detached()
            else:
                threading.Thread(target=self.tray_icon.run, daemon=True).start()
        except Exception:
            threading.Thread(target=self.tray_icon.run, daemon=True).start()

    def _show_window(self):
        self.root.deiconify()
        self.root.after(50, self.root.lift)

    def _hide_to_tray(self):
        try:
            self.root.withdraw()
        except Exception:
            pass

    def _on_minimize(self, _event):
        try:
            if self.root.state() == "iconic":
                self.root.withdraw()
        except Exception:
            pass

    # ---------- shutdown ----------
    def on_close(self):
        self.status_label.config(text="Stopping...")
        self.stop_event.set()

        if self.tray_icon is not None:
            try:
                self.tray_icon.visible = False
                self.tray_icon.stop()
            except Exception:
                pass
            self.tray_icon = None

        if self.log_file:
            try:
                self.log_file.close()
            except Exception:
                pass
            self.log_file = None

        self.root.after(200, self.root.destroy)


def main():
    root = tk.Tk()
    _app = EventViewerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
