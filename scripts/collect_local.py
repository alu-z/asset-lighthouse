#!/usr/bin/env python3
"""Collect low-risk, read-only local metadata for crypto-theft triage.

The collector never reads secrets or file contents. It only collects process,
startup/task, browser-extension directory metadata, and optional network
configuration summaries. Use --dry-run to inspect planned commands without
executing them.
"""

from __future__ import annotations

import argparse
import csv
import ctypes
import io
import json
import os
import shlex
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "asset-lighthouse-evidence/v1"
COMMAND_TIMEOUT = 8
MAX_ROWS = 200
DEFAULT_WINDOWS_ROOT = Path(r"C:\\Windows")


def configure_stdio() -> None:
    """Keep JSON output usable under Windows PowerShell and non-UTF-8 shells."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8", errors="replace")


def windows_command(relative_path: str) -> str:
    """Resolve a Windows system command without searching the current PATH."""
    system_dir = windows_system_directory()
    candidate = system_dir / relative_path
    try:
        if candidate.is_file() and not candidate.is_symlink():
            return str(candidate)
    except OSError:
        pass
    return str(candidate)


def windows_system_directory() -> Path:
    """Get the trusted System32 directory, using the OS API when available."""
    if os.name == "nt":
        try:
            buffer = ctypes.create_unicode_buffer(32768)
            length = ctypes.windll.kernel32.GetSystemDirectoryW(buffer, len(buffer))
            if 0 < length < len(buffer):
                return Path(buffer.value)
        except (AttributeError, OSError):
            pass
    root_value = os.environ.get("SystemRoot") or os.environ.get("WINDIR")
    if root_value:
        return Path(root_value) / "System32"
    return DEFAULT_WINDOWS_ROOT / "System32"


def has_symlink_component(path: Path) -> bool:
    """Return True when any existing component of a path is a symlink."""
    current = path
    while True:
        try:
            if current.is_symlink():
                return True
        except OSError:
            return True
        parent = current.parent
        if parent == current:
            return False
        current = parent


def write_report(path: Path, encoded: str, force: bool) -> dict[str, str]:
    """Write a report without following symlinks or overwriting by default."""
    path = path.expanduser()
    if has_symlink_component(path):
        raise ValueError("output_path_contains_symlink")
    if path.exists() and not path.is_file():
        raise ValueError("output_path_is_not_file")
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = "w" if force else "x"
    with path.open(mode, encoding="utf-8", newline="\n") as handle:
        handle.write(encoded + "\n")
    return {"status": "written", "path": str(path), "schema": SCHEMA}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def detect_platform() -> str:
    if sys.platform == "win32":
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    if sys.platform.startswith("linux"):
        return "linux"
    return "unknown"


def command_text(args: list[str]) -> str:
    return shlex.join(args)


def run_command(args: list[str], dry_run: bool) -> dict[str, Any]:
    result: dict[str, Any] = {"command": args, "command_text": command_text(args)}
    if dry_run:
        result["status"] = "planned"
        return result
    started = time.monotonic()
    try:
        completed = subprocess.run(
            args,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=COMMAND_TIMEOUT,
            check=False,
            shell=False,
        )
    except FileNotFoundError:
        result.update({"status": "not_available", "error": "command_not_found"})
        return result
    except subprocess.TimeoutExpired:
        result.update({"status": "timeout", "error": "command_timeout"})
        return result
    elapsed_ms = round((time.monotonic() - started) * 1000, 1)
    stderr = completed.stderr
    permission_error = completed.returncode in {1, 5} and any(
        marker in stderr.lower() for marker in ("access denied", "permission denied", "\u62d2\u7edd\u8bbf\u95ee", "0x80041003")
    )
    result.update(
        {
            "status": "permission_denied" if permission_error else ("ok" if completed.returncode == 0 else "error"),
            "returncode": completed.returncode,
            "elapsed_ms": elapsed_ms,
            "stdout": completed.stdout[:20000],
            "stderr": stderr[:4000],
        }
    )
    return result


def parse_csv_rows(text: str, limit: int = MAX_ROWS) -> list[list[str]]:
    rows: list[list[str]] = []
    for row in csv.reader(io.StringIO(text)):
        if row:
            rows.append(row)
        if len(rows) >= limit:
            break
    return rows


def parse_processes(result: dict[str, Any], platform_name: str) -> None:
    if result.get("status") != "ok":
        return
    output = result.get("stdout", "")
    if platform_name == "windows":
        rows = parse_csv_rows(output)
        result["items"] = [
            {"image": row[0], "pid": row[1], "session": row[2]}
            for row in rows
            if len(row) >= 3 and row[0] != "INFO:"
        ]
    else:
        items = []
        for line in output.splitlines()[:MAX_ROWS]:
            parts = line.strip().split(None, 1)
            if len(parts) == 2 and parts[0].isdigit():
                items.append({"pid": parts[0], "command": parts[1]})
        result["items"] = items
    result.pop("stdout", None)


def parse_json_stdout(result: dict[str, Any]) -> None:
    if result.get("status") != "ok":
        return
    raw = result.pop("stdout", "").strip()
    if not raw:
        result["items"] = []
        return
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        result["status"] = "unparseable"
        result["raw_preview"] = raw[:4000]
        return
    if isinstance(value, list):
        result["items"] = value[:MAX_ROWS]
    else:
        result["items"] = [value]


def list_extension_dirs(platform_name: str) -> dict[str, Any]:
    home = Path.home()
    if platform_name == "windows":
        local = Path(os.environ.get("LOCALAPPDATA", home / "AppData/Local"))
        roaming = Path(os.environ.get("APPDATA", home / "AppData/Roaming"))
        roots = {
            "chrome": local / "Google/Chrome/User Data/Default/Extensions",
            "edge": local / "Microsoft/Edge/User Data/Default/Extensions",
            "firefox": roaming / "Mozilla/Firefox/Profiles",
        }
    elif platform_name == "macos":
        app_support = home / "Library/Application Support"
        roots = {
            "chrome": app_support / "Google/Chrome/Default/Extensions",
            "edge": app_support / "Microsoft Edge/Default/Extensions",
            "firefox": app_support / "Firefox/Profiles",
        }
    elif platform_name == "linux":
        config = home / ".config"
        roots = {
            "chrome": config / "google-chrome/Default/Extensions",
            "edge": config / "microsoft-edge/Default/Extensions",
            "firefox": home / ".mozilla/firefox/Profiles",
        }
    else:
        roots = {}

    browsers: dict[str, Any] = {}
    for browser, root in roots.items():
        item: dict[str, Any] = {"root": str(root), "exists": root.exists(), "extensions": []}
        if has_symlink_component(root):
            item["status"] = "skipped_symlink"
            browsers[browser] = item
            continue
        if root.is_dir():
            try:
                children = []
                for child in root.iterdir():
                    if child.is_symlink() or not child.is_dir():
                        continue
                    children.append(child)
                    if len(children) > MAX_ROWS:
                        break
                if len(children) > MAX_ROWS:
                    item["truncated"] = True
                    children = children[:MAX_ROWS]
                children.sort(key=lambda p: p.name.lower())
            except OSError as exc:
                item["error"] = f"list_failed:{type(exc).__name__}"
                browsers[browser] = item
                continue
            for child in children[:MAX_ROWS]:
                try:
                    stat = child.lstat()
                    item["extensions"].append(
                        {"id_or_profile": child.name, "modified": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat()}
                    )
                except OSError:
                    item["extensions"].append({"id_or_profile": child.name, "modified": None})
        browsers[browser] = item
    return browsers


def collect_commands(platform_name: str, include_network: bool, dry_run: bool) -> dict[str, Any]:
    checks: dict[str, Any] = {}
    if platform_name == "windows":
        processes = run_command([windows_command("tasklist.exe"), "/FO", "CSV", "/NH"], dry_run)
        if not dry_run and processes.get("status") != "ok":
            fallback = run_command(
                [
                    windows_command("WindowsPowerShell/v1.0/powershell.exe"),
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "Get-Process | Select-Object ProcessName,Id | ConvertTo-Json -Compress",
                ],
                dry_run,
            )
            if fallback.get("status") == "ok":
                parse_json_stdout(fallback)
                fallback["fallback_for"] = "tasklist"
                processes = fallback
        if not dry_run and processes.get("status") == "ok" and "items" not in processes:
            parse_processes(processes, platform_name)
        checks["processes"] = processes
        startup = run_command(
            [
                windows_command("WindowsPowerShell/v1.0/powershell.exe"),
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Get-CimInstance Win32_StartupCommand | Select-Object Name,Location | ConvertTo-Json -Compress",
            ],
            dry_run,
        )
        if not dry_run and startup.get("status") != "ok":
            fallback = run_command(
                [
                    windows_command("WindowsPowerShell/v1.0/powershell.exe"),
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "Get-ChildItem ($env:APPDATA + '\\Microsoft\\Windows\\Start Menu\\Programs\\Startup') | Select-Object Name,Length,LastWriteTime | ConvertTo-Json -Compress",
                ],
                dry_run,
            )
            if fallback.get("status") == "ok":
                parse_json_stdout(fallback)
                fallback["fallback_for"] = "Win32_StartupCommand"
                startup = fallback
        if not dry_run and startup.get("status") == "ok" and "items" not in startup:
            parse_json_stdout(startup)
        checks["startup_items"] = startup
        tasks = run_command(
            [
                windows_command("WindowsPowerShell/v1.0/powershell.exe"),
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Get-ScheduledTask | Select-Object TaskName,TaskPath,State | ConvertTo-Json -Compress",
            ],
            dry_run,
        )
        if not dry_run:
            parse_json_stdout(tasks)
        checks["scheduled_tasks"] = tasks
        if include_network:
            dns = run_command(
                [
                    windows_command("netsh.exe"),
                    "interface",
                    "ip",
                    "show",
                    "dns",
                ],
                dry_run,
            )
            checks["dns"] = dns
            checks["proxy"] = run_command(
                [windows_command("netsh.exe"), "winhttp", "show", "proxy"], dry_run
            )
    elif platform_name == "macos":
        processes = run_command(["/bin/ps", "-axo", "pid=,comm="], dry_run)
        if not dry_run:
            parse_processes(processes, platform_name)
        checks["processes"] = processes
        checks["launch_agents"] = run_command(["/bin/launchctl", "list"], dry_run)
        if include_network:
            checks["dns"] = run_command(["/usr/sbin/scutil", "--dns"], dry_run)
            checks["proxy"] = run_command(["/usr/sbin/networksetup", "-getwebproxy", "Wi-Fi"], dry_run)
    elif platform_name == "linux":
        processes = run_command(["/bin/ps", "-axo", "pid=,comm="], dry_run)
        if not dry_run:
            parse_processes(processes, platform_name)
        checks["processes"] = processes
        checks["user_services"] = run_command(["/usr/bin/systemctl", "--user", "list-units", "--type=service", "--no-pager"], dry_run)
        if include_network:
            checks["dns"] = run_command(["/bin/cat", "/etc/resolv.conf"], dry_run)
    else:
        checks["platform"] = {"status": "unsupported", "items": []}
    return checks


def main() -> int:
    configure_stdio()
    parser = argparse.ArgumentParser(description="Collect low-risk, read-only local triage metadata.")
    parser.add_argument("--platform", choices=["auto", "windows", "macos", "linux"], default="auto")
    parser.add_argument("--profile", choices=["basic", "network"], default="basic")
    parser.add_argument("--output", type=Path, help="Write JSON only to this explicitly selected path.")
    parser.add_argument("--force", action="store_true", help="Allow replacing an existing report file.")
    parser.add_argument("--dry-run", action="store_true", help="List planned commands without executing them.")
    args = parser.parse_args()

    detected = detect_platform()
    requested = detected if args.platform == "auto" else args.platform
    report: dict[str, Any] = {
        "schema": SCHEMA,
        "collected_at": now_iso(),
        "platform_requested": requested,
        "platform_detected": detected,
        "mode": "dry-run" if args.dry_run else "live",
        "permission_profile": "L1",
        "read_scope": ["process metadata", "startup/task metadata", "browser extension directory metadata"],
        "sensitive_content_read": False,
        "checks": {},
        "warnings": [],
    }
    if requested != detected and not args.dry_run:
        report["warnings"].append("requested platform differs from host; use --dry-run for another platform")
        report["mode"] = "blocked-platform-mismatch"
    else:
        report["checks"] = collect_commands(requested, args.profile == "network", args.dry_run)
        report["checks"]["browser_extension_dirs"] = {"status": "ok", "items": list_extension_dirs(requested)}

    encoded = json.dumps(report, ensure_ascii=False, indent=2)
    if args.output:
        try:
            result = write_report(args.output, encoded, args.force)
        except FileExistsError:
            result = {"status": "refused_existing_file", "path": str(args.output), "schema": SCHEMA}
        except (OSError, ValueError) as exc:
            result = {"status": "output_error", "path": str(args.output), "schema": SCHEMA, "error": str(exc)}
        print(json.dumps(result, ensure_ascii=False))
        return 0 if result["status"] == "written" else 2
    else:
        print(encoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
