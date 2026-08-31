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
import stat as stat_module
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "asset-lighthouse-evidence/v2"
COMMAND_TIMEOUT = 8
MAX_ROWS = 200
MAX_BROWSER_PROFILES = 20
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
    """Return True when any existing component is a symlink or junction."""
    is_junction = getattr(os.path, "isjunction", lambda _path: False)
    current = path
    while True:
        try:
            metadata = current.lstat()
            reparse_flag = getattr(stat_module, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
            file_attributes = getattr(metadata, "st_file_attributes", 0)
            if stat_module.S_ISLNK(metadata.st_mode) or is_junction(current) or (reparse_flag and file_attributes & reparse_flag):
                return True
        except FileNotFoundError:
            pass
        except OSError:
            return True
        parent = current.parent
        if parent == current:
            return False
        current = parent


def write_report(path: Path, encoded: str, force: bool) -> dict[str, str]:
    """Write a private report without following links or overwriting by default."""
    path = path.expanduser()
    if has_symlink_component(path):
        raise ValueError("output_path_contains_symlink")
    if path.exists() and not path.is_file():
        raise ValueError("output_path_is_not_file")
    path.parent.mkdir(parents=True, exist_ok=True)
    if has_symlink_component(path):
        raise ValueError("output_path_contains_symlink")
    flags = os.O_WRONLY | os.O_CREAT | (0 if force else os.O_EXCL)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        metadata = os.fstat(descriptor)
        if not stat_module.S_ISREG(metadata.st_mode):
            raise ValueError("output_path_is_not_regular_file")
        if metadata.st_nlink > 1:
            raise ValueError("output_file_has_multiple_hard_links")
        if force:
            os.ftruncate(descriptor, 0)
        if os.name != "nt" and hasattr(os, "fchmod"):
            os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            descriptor = -1
            handle.write(encoded + "\n")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
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


def parse_scheduled_tasks(result: dict[str, Any]) -> None:
    """Parse the stable leading columns from schtasks CSV output."""
    if result.get("status") != "ok":
        return
    rows = parse_csv_rows(result.pop("stdout", ""))
    result["items"] = [
        {"task_name": row[0], "next_run_time": row[1], "status": row[2]}
        for row in rows
        if len(row) >= 3 and not row[0].startswith("INFO:")
    ]


def parse_launch_agents(result: dict[str, Any]) -> None:
    """Convert bounded launchctl output into simple records."""
    if result.get("status") != "ok":
        return
    items: list[dict[str, Any]] = []
    for line in result.pop("stdout", "").splitlines():
        parts = line.strip().split(None, 2)
        if len(parts) != 3 or parts[0].upper() == "PID":
            continue
        items.append(
            {
                "pid": None if parts[0] == "-" else parts[0],
                "last_exit_status": parts[1],
                "label": parts[2],
            }
        )
        if len(items) >= MAX_ROWS:
            break
    result["items"] = items


def parse_user_services(result: dict[str, Any]) -> None:
    """Convert bounded systemctl user-service output into simple records."""
    if result.get("status") != "ok":
        return
    items: list[dict[str, str]] = []
    for line in result.pop("stdout", "").splitlines():
        parts = line.strip().split(None, 4)
        if len(parts) < 4:
            continue
        items.append(
            {
                "unit": parts[0],
                "load": parts[1],
                "active": parts[2],
                "sub": parts[3],
                "description": parts[4] if len(parts) == 5 else "",
            }
        )
        if len(items) >= MAX_ROWS:
            break
    result["items"] = items


def extension_roots(platform_name: str) -> dict[str, tuple[str, Path]]:
    """Return browser profile roots without touching the filesystem."""
    home = Path.home()
    if platform_name == "windows":
        local = Path(os.environ.get("LOCALAPPDATA", home / "AppData/Local"))
        roaming = Path(os.environ.get("APPDATA", home / "AppData/Roaming"))
        return {
            "chrome": ("chromium", local / "Google/Chrome/User Data"),
            "edge": ("chromium", local / "Microsoft/Edge/User Data"),
            "brave": ("chromium", local / "BraveSoftware/Brave-Browser/User Data"),
            "firefox": ("firefox", roaming / "Mozilla/Firefox/Profiles"),
        }
    if platform_name == "macos":
        app_support = home / "Library/Application Support"
        return {
            "chrome": ("chromium", app_support / "Google/Chrome"),
            "edge": ("chromium", app_support / "Microsoft Edge"),
            "brave": ("chromium", app_support / "BraveSoftware/Brave-Browser"),
            "firefox": ("firefox", app_support / "Firefox/Profiles"),
        }
    if platform_name == "linux":
        config = home / ".config"
        return {
            "chrome": ("chromium", config / "google-chrome"),
            "edge": ("chromium", config / "microsoft-edge"),
            "brave": ("chromium", config / "BraveSoftware/Brave-Browser"),
            "firefox": ("firefox", home / ".mozilla/firefox"),
        }
    return {}


def bounded_children(
    root: Path,
    limit: int,
    directories_only: bool = True,
    name_filter: Any = None,
) -> tuple[list[Path], bool]:
    """List at most limit children without following symlinks."""
    children: list[Path] = []
    for child in root.iterdir():
        if child.is_symlink():
            continue
        if directories_only and not child.is_dir():
            continue
        if name_filter is not None and not name_filter(child.name):
            continue
        children.append(child)
        if len(children) > limit:
            return sorted(children[:limit], key=lambda item: item.name.lower()), True
    return sorted(children, key=lambda item: item.name.lower()), False


def list_extension_dirs(platform_name: str) -> dict[str, Any]:
    roots = extension_roots(platform_name)

    browsers: dict[str, Any] = {}
    for browser, (family, root) in roots.items():
        item: dict[str, Any] = {"root": str(root), "exists": root.exists(), "profiles": []}
        if has_symlink_component(root):
            item["status"] = "skipped_symlink"
            browsers[browser] = item
            continue
        if root.is_dir():
            try:
                profile_filter = (
                    (lambda name: name == "Default" or name.startswith("Profile "))
                    if family == "chromium"
                    else None
                )
                candidates, profiles_truncated = bounded_children(
                    root,
                    MAX_BROWSER_PROFILES,
                    name_filter=profile_filter,
                )
                if profiles_truncated:
                    item["profiles_truncated"] = True
            except OSError as exc:
                item["error"] = f"list_failed:{type(exc).__name__}"
                browsers[browser] = item
                continue
            remaining = MAX_ROWS
            for profile in candidates:
                extensions_root = profile / "Extensions" if family == "chromium" else profile / "extensions"
                profile_item: dict[str, Any] = {
                    "name": profile.name,
                    "extensions_root": str(extensions_root),
                    "exists": extensions_root.is_dir(),
                    "extensions": [],
                }
                if remaining <= 0:
                    item["extensions_truncated"] = True
                    break
                if has_symlink_component(extensions_root) or not extensions_root.is_dir():
                    item["profiles"].append(profile_item)
                    continue
                try:
                    extensions, truncated = bounded_children(extensions_root, remaining, directories_only=(family == "chromium"))
                    for extension in extensions:
                        try:
                            stat = extension.lstat()
                            modified = datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat()
                        except OSError:
                            modified = None
                        profile_item["extensions"].append({"id_or_file": extension.name, "modified": modified})
                    remaining -= len(extensions)
                    if truncated:
                        item["extensions_truncated"] = True
                except OSError as exc:
                    profile_item["error"] = f"list_failed:{type(exc).__name__}"
                item["profiles"].append(profile_item)
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
                    "Get-Process | Select-Object -First 200 ProcessName,Id | ConvertTo-Json -Compress",
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
                "Get-CimInstance Win32_StartupCommand | Select-Object -First 200 Name,Location | ConvertTo-Json -Compress",
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
                    "Get-ChildItem ($env:APPDATA + '\\Microsoft\\Windows\\Start Menu\\Programs\\Startup') | Select-Object -First 200 Name,Length,LastWriteTime | ConvertTo-Json -Compress",
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
                "Get-ScheduledTask | Select-Object -First 200 TaskName,TaskPath,State | ConvertTo-Json -Compress",
            ],
            dry_run,
        )
        if not dry_run and tasks.get("status") != "ok":
            fallback = run_command(
                [windows_command("schtasks.exe"), "/Query", "/FO", "CSV", "/NH"],
                dry_run,
            )
            if fallback.get("status") == "ok":
                parse_scheduled_tasks(fallback)
                fallback["fallback_for"] = "Get-ScheduledTask"
                tasks = fallback
            else:
                tasks["fallback_attempt"] = fallback
        if not dry_run and tasks.get("status") == "ok" and "items" not in tasks:
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
            user_proxy = run_command(
                [
                    windows_command("WindowsPowerShell/v1.0/powershell.exe"),
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "Get-ItemProperty -LiteralPath 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' | Select-Object ProxyEnable,ProxyServer,AutoConfigURL | ConvertTo-Json -Compress",
                ],
                dry_run,
            )
            if not dry_run:
                parse_json_stdout(user_proxy)
            checks["proxy_user"] = user_proxy
    elif platform_name == "macos":
        processes = run_command(["/bin/ps", "-axo", "pid=,comm="], dry_run)
        if not dry_run:
            parse_processes(processes, platform_name)
        checks["processes"] = processes
        launch_agents = run_command(["/bin/launchctl", "list"], dry_run)
        if not dry_run:
            parse_launch_agents(launch_agents)
        checks["launch_agents"] = launch_agents
        if include_network:
            checks["dns"] = run_command(["/usr/sbin/scutil", "--dns"], dry_run)
            checks["proxy"] = run_command(["/usr/sbin/scutil", "--proxy"], dry_run)
    elif platform_name == "linux":
        processes = run_command(["/bin/ps", "-axo", "pid=,comm="], dry_run)
        if not dry_run:
            parse_processes(processes, platform_name)
        checks["processes"] = processes
        user_services = run_command(
            ["/usr/bin/systemctl", "--user", "list-units", "--type=service", "--no-pager", "--no-legend", "--plain"],
            dry_run,
        )
        if not dry_run:
            parse_user_services(user_services)
        checks["user_services"] = user_services
        if include_network:
            checks["dns"] = run_command(["/bin/cat", "/etc/resolv.conf"], dry_run)
            checks["proxy"] = {
                "status": "not_available",
                "reason": "no_safe_distribution-neutral_system_proxy_source",
                "environment_variables_read": False,
            }
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
        "read_scope": [
            "process metadata",
            "startup/task metadata",
            "browser extension directory metadata",
            *(["DNS and proxy summaries"] if args.profile == "network" else []),
        ],
        "sensitive_content_read": False,
        "checks": {},
        "warnings": [],
    }
    if requested != detected and not args.dry_run:
        report["warnings"].append("requested platform differs from host; use --dry-run for another platform")
        report["mode"] = "blocked-platform-mismatch"
    else:
        report["checks"] = collect_commands(requested, args.profile == "network", args.dry_run)
        if args.dry_run:
            report["checks"]["browser_extension_dirs"] = {
                "status": "planned",
                "browsers": list(extension_roots(requested)),
            }
        else:
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
