#!/usr/bin/env python3
"""Run a clipboard replacement test with a synthetic or public address value.

This intentionally writes a synthetic value to the clipboard. It must only be
run after the user asks for a clipboard test. It never uses a real wallet
address and never sends a transaction.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Any


SCHEMA = "asset-lighthouse-clipboard-test/v1"
DEFAULT_VALUE = "0x1111111111111111111111111111111111111111"
MAX_TEST_VALUE_LENGTH = 256
PRIVATE_KEY_LIKE = re.compile(r"^(?:0x)?[0-9a-fA-F]{64}$")


def configure_stdio() -> None:
    """Keep JSON output usable under Windows PowerShell and non-UTF-8 shells."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8", errors="replace")


def windows_powershell() -> str:
    """Resolve PowerShell from the Windows system directory, not PATH."""
    system_dir = windows_system_directory()
    candidate = system_dir / "WindowsPowerShell/v1.0/powershell.exe"
    if candidate.is_file() and not candidate.is_symlink():
        return str(candidate)
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
    root_value = os.environ.get("SystemRoot") or os.environ.get("WINDIR") or r"C:\\Windows"
    return Path(root_value) / "System32"


def detect_platform() -> str:
    if sys.platform == "win32":
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    return "unsupported"


def validate_test_value(value: str) -> str:
    """Accept a public address-like value, never a seed/private-key-like value."""
    value = value.strip()
    if not value:
        raise ValueError("test value must not be empty")
    if len(value) > MAX_TEST_VALUE_LENGTH:
        raise ValueError(f"test value must be at most {MAX_TEST_VALUE_LENGTH} characters")
    if any(char.isspace() or ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        raise ValueError("test value must not contain whitespace or control characters")
    if PRIVATE_KEY_LIKE.fullmatch(value):
        raise ValueError("private-key-like values are not accepted")
    return value


def run(args: list[str], value: str | None = None, dry_run: bool = False) -> dict[str, Any]:
    result: dict[str, Any] = {"command": args}
    if dry_run:
        result["status"] = "planned"
        return result
    try:
        completed = subprocess.run(
            args,
            input=value,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5,
            check=False,
            shell=False,
        )
    except FileNotFoundError:
        return {**result, "status": "not_available", "error": "command_not_found"}
    except subprocess.TimeoutExpired:
        return {**result, "status": "timeout", "error": "command_timeout"}
    result.update({"status": "ok" if completed.returncode == 0 else "error", "returncode": completed.returncode})
    result["stdout"] = completed.stdout
    result["stderr"] = completed.stderr[:1000]
    return result


def commands(platform_name: str) -> tuple[list[str], list[str]]:
    if platform_name == "macos":
        return ["/usr/bin/pbcopy"], ["/usr/bin/pbpaste"]
    if platform_name == "windows":
        write = [
            windows_powershell(),
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "$value = [Console]::In.ReadToEnd(); Set-Clipboard -Value $value",
        ]
        read = [windows_powershell(), "-NoProfile", "-NonInteractive", "-Command", "Get-Clipboard -Raw"]
        return write, read
    raise ValueError(f"unsupported platform: {platform_name}")


def main() -> int:
    configure_stdio()
    parser = argparse.ArgumentParser(description="Test clipboard replacement with a synthetic or public address value.")
    parser.add_argument("--platform", choices=["auto", "windows", "macos"], default="auto")
    parser.add_argument("--rounds", type=int, default=1)
    parser.add_argument("--delay", type=float, default=0.2)
    parser.add_argument(
        "--address",
        "--value",
        dest="test_value",
        metavar="ADDRESS",
        help="Public address-like value to test; defaults to a fixed synthetic EVM address.",
    )
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    if args.rounds < 1 or args.rounds > 20:
        parser.error("--rounds must be between 1 and 20")
    try:
        test_value = validate_test_value(args.test_value if args.test_value is not None else DEFAULT_VALUE)
    except ValueError as exc:
        parser.error(str(exc))
    value_source = "custom_address" if args.test_value is not None else "default_synthetic"

    detected = detect_platform()
    selected = detected if args.platform == "auto" else args.platform
    report: dict[str, Any] = {
        "schema": SCHEMA,
        "tested_at": datetime.now(timezone.utc).isoformat(),
        "platform": selected,
        "platform_detected": detected,
        "mode": "dry-run" if args.dry_run else "live",
        "test_value": test_value,
        "test_value_source": value_source,
        "rounds": [],
        "warning": "This test overwrites the current clipboard and does not restore it; clipboard sync may propagate the value. Use public addresses only; never provide a seed phrase or private key.",
    }
    if selected != detected and not args.dry_run:
        report["mode"] = "blocked-platform-mismatch"
        report["error"] = "requested platform differs from host; use --dry-run"
    else:
        write_cmd, read_cmd = commands(selected)
        for index in range(1, args.rounds + 1):
            write_result = run(write_cmd, test_value, args.dry_run)
            if args.dry_run:
                read_result = run(read_cmd, dry_run=True)
                observed = None
                matches = None
            else:
                time.sleep(max(args.delay, 0))
                read_result = run(read_cmd)
                observed = read_result.get("stdout", "").rstrip("\r\n") if read_result.get("status") == "ok" else None
                matches = observed == test_value
            report["rounds"].append(
                {
                    "round": index,
                    "write": {k: v for k, v in write_result.items() if k not in {"stdout", "stderr"}},
                    "read": {k: v for k, v in read_result.items() if k not in {"stdout", "stderr"}},
                    "observed": observed,
                    "matches": matches,
                }
            )
        matches = [item["matches"] for item in report["rounds"] if item["matches"] is not None]
        if args.dry_run:
            report["conclusion"] = "not-executed"
        elif not matches or any(item["write"].get("status") != "ok" or item["read"].get("status") != "ok" for item in report["rounds"]):
            report["conclusion"] = "tool-unavailable-or-error"
        elif all(matches):
            report["conclusion"] = "no-change-observed"
        else:
            report["conclusion"] = "clipboard-content-changed"
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
