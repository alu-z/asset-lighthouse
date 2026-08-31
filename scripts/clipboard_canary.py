#!/usr/bin/env python3
"""Run a clipboard replacement test with a synthetic or public address.

This intentionally overwrites the clipboard. Run it only after the user asks
for the test and confirms the overwrite. It never sends a transaction.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import math
import os
import re
from pathlib import Path
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Any


SCHEMA = "asset-lighthouse-clipboard-test/v2"
DEFAULT_VALUE = "0x1111111111111111111111111111111111111111"
MAX_TEST_VALUE_LENGTH = 256
MAX_CLIPBOARD_CAPTURE_LENGTH = 1024
BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE58_CLASS = re.escape(BASE58)
HEX_PRIVATE_KEY = re.compile(r"^(?:0x)?[0-9a-fA-F]{64}$")
EXTENDED_PRIVATE_KEY = re.compile(r"^(?:xprv|tprv|yprv|zprv|uprv|vprv)[A-Za-z0-9]{20,}$")
WIF_PRIVATE_KEY = re.compile(rf"^[5KL][{BASE58_CLASS}]{{50,51}}$")
BIP38_PRIVATE_KEY = re.compile(rf"^6P[{BASE58_CLASS}]{{56}}$")
STELLAR_SECRET_SEED = re.compile(r"^S[A-Z2-7]{55}$")
SOLANA_PRIVATE_KEY = re.compile(rf"^[{BASE58_CLASS}]{{80,100}}$")
XRP_FAMILY_SEED = re.compile(r"^s[1-9A-HJ-NP-Za-km-z]{27,34}$")
CARDANO_SIGNING_KEY = re.compile(r"^(?:addr|root|acct|payment|stake)_xsk1[ac-hj-np-z02-9]{20,}$", re.IGNORECASE)
SECRET_PATTERNS = (
    EXTENDED_PRIVATE_KEY,
    WIF_PRIVATE_KEY,
    BIP38_PRIVATE_KEY,
    STELLAR_SECRET_SEED,
    SOLANA_PRIVATE_KEY,
    XRP_FAMILY_SEED,
    CARDANO_SIGNING_KEY,
)
PUBLIC_ADDRESS_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("evm", re.compile(r"^0x[0-9a-fA-F]{40}$")),
    ("bitcoin-base58", re.compile(rf"^[13mn2][{BASE58_CLASS}]{{25,34}}$")),
    ("bitcoin-bech32", re.compile(r"^(?:bc1|tb1|bcrt1)[ac-hj-np-z02-9]{11,87}$", re.IGNORECASE)),
    ("tron", re.compile(rf"^T[{BASE58_CLASS}]{{33}}$")),
    ("ton", re.compile(r"^(?:EQ|UQ)[A-Za-z0-9_-]{46}$")),
    ("bech32", re.compile(r"^[a-z0-9]{1,20}1[ac-hj-np-z02-9]{10,80}$", re.IGNORECASE)),
    ("solana", re.compile(rf"^[{BASE58_CLASS}]{{32,44}}$")),
)


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


def validate_test_value(value: str, address_format: str) -> tuple[str, str]:
    """Validate common public-address shapes and reject common secret shapes."""
    if not value:
        raise ValueError("test value must not be empty")
    if len(value) > MAX_TEST_VALUE_LENGTH:
        raise ValueError(f"test value must be at most {MAX_TEST_VALUE_LENGTH} characters")
    if any(char.isspace() or ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        raise ValueError("test value must not contain whitespace or control characters")
    if any(pattern.fullmatch(value) for pattern in SECRET_PATTERNS):
        raise ValueError("private-key-like values are not accepted")

    if address_format in {"sui", "aptos"}:
        if not re.fullmatch(r"^0x[0-9a-fA-F]{64}$", value):
            raise ValueError(f"{address_format} addresses must be 0x followed by 64 hexadecimal characters")
        return value, address_format

    if HEX_PRIVATE_KEY.fullmatch(value):
        raise ValueError("ambiguous 64-hex values are rejected; select --address-format sui or aptos for those public addresses")

    matches = [(name, pattern) for name, pattern in PUBLIC_ADDRESS_PATTERNS if pattern.fullmatch(value)]
    if address_format == "auto":
        if not matches:
            raise ValueError("unrecognized public-address format; use --address-format generic only after verifying it is public")
        if len(matches) > 1:
            return value, "ambiguous:" + ",".join(name for name, _pattern in matches)
        return value, matches[0][0]
    if address_format == "generic":
        return value, "generic"
    for name, pattern in PUBLIC_ADDRESS_PATTERNS:
        if name == address_format and pattern.fullmatch(value):
            return value, name
    raise ValueError(f"test value does not match the selected {address_format} public-address format")


def validate_timing(delay: float, observe_for: float, poll_interval: float, rounds: int) -> None:
    """Bound timing arguments so a malformed request cannot hang the host Agent."""
    values = {"--delay": delay, "--observe-for": observe_for, "--poll-interval": poll_interval}
    if any(not math.isfinite(value) for value in values.values()):
        raise ValueError("timing values must be finite numbers")
    if not 0 <= delay <= 10:
        raise ValueError("--delay must be between 0 and 10 seconds")
    if not 0 <= observe_for <= 30:
        raise ValueError("--observe-for must be between 0 and 30 seconds")
    if not 0.1 <= poll_interval <= 5:
        raise ValueError("--poll-interval must be between 0.1 and 5 seconds")
    if rounds * (delay + observe_for) > 120:
        raise ValueError("requested clipboard observation time exceeds 120 seconds")


def value_metadata(value: str) -> dict[str, Any]:
    """Return compact metadata without including the literal clipboard value."""
    return {
        "value_sha256": hashlib.sha256(value.encode("utf-8")).hexdigest(),
        "value_length": len(value),
    }


def observed_fields(value: str | None) -> dict[str, Any]:
    """Describe an observed value without repeating its literal content."""
    if value is None:
        return {}
    return {
        "observed_sha256": hashlib.sha256(value.encode("utf-8")).hexdigest(),
        "observed_length": len(value),
    }


def reportable_observed_value(
    value: str | None,
    matches: bool | None,
    include_values: bool,
    address_format: str,
) -> str | None:
    """Include one literal result only when explicitly requested or clearly address-like."""
    if value is None:
        return None
    if include_values:
        return value
    if matches is not False:
        return None
    if any(pattern.fullmatch(value) for _name, pattern in PUBLIC_ADDRESS_PATTERNS):
        return value
    if address_format in {"sui", "aptos"} and re.fullmatch(r"^0x[0-9a-fA-F]{64}$", value):
        return value
    return None


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
    result["stdout"] = completed.stdout[:MAX_CLIPBOARD_CAPTURE_LENGTH]
    if len(completed.stdout) > MAX_CLIPBOARD_CAPTURE_LENGTH:
        result["stdout_truncated"] = True
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
    parser.add_argument("--observe-for", type=float, default=3.0)
    parser.add_argument("--poll-interval", type=float, default=0.25)
    parser.add_argument(
        "--address",
        "--value",
        dest="test_value",
        metavar="ADDRESS",
        help="Public address-like value to test; defaults to a fixed synthetic EVM address.",
    )
    parser.add_argument(
        "--address-format",
        choices=["auto", "evm", "bitcoin-base58", "bitcoin-bech32", "tron", "solana", "ton", "bech32", "sui", "aptos", "generic"],
        default="auto",
        help="Validate the supplied value as this public-address format (default: auto).",
    )
    parser.add_argument(
        "--include-values",
        action="store_true",
        help="Include unchanged clipboard values in JSON output; changed values are always retained as evidence.",
    )
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    if args.rounds < 1 or args.rounds > 20:
        parser.error("--rounds must be between 1 and 20")
    try:
        validate_timing(args.delay, args.observe_for, args.poll_interval, args.rounds)
        test_value, detected_format = validate_test_value(
            args.test_value if args.test_value is not None else DEFAULT_VALUE,
            args.address_format,
        )
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
        "test_value": test_value if args.include_values else None,
        "test_value_source": value_source,
        "test_value_redacted": not args.include_values,
        **{f"test_{key}": value for key, value in value_metadata(test_value).items()},
        "address_format": detected_format,
        "validation": {"method": "shape-only", "checksum_verified": False},
        "timing": {
            "initial_delay_seconds": args.delay,
            "observe_for_seconds": args.observe_for,
            "poll_interval_seconds": args.poll_interval,
        },
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
                observations: list[dict[str, Any]] = []
            else:
                observations = []
                if write_result.get("status") == "ok":
                    time.sleep(args.delay)
                    observation_started = time.monotonic()
                    deadline = observation_started + args.observe_for
                    while True:
                        read_result = run(read_cmd)
                        observed = read_result.get("stdout", "").rstrip("\r\n") if read_result.get("status") == "ok" else None
                        matches = observed == test_value if observed is not None else None
                        observations.append(
                            {
                                "elapsed_ms": round((time.monotonic() - observation_started) * 1000, 1),
                                "read": {k: v for k, v in read_result.items() if k not in {"stdout", "stderr"}},
                                "matches": matches,
                                **observed_fields(observed),
                            }
                        )
                        if matches is False or time.monotonic() >= deadline:
                            break
                        time.sleep(min(args.poll_interval, max(deadline - time.monotonic(), 0)))
                else:
                    read_result = {"command": read_cmd, "status": "not_executed", "error": "clipboard_write_failed"}
                    observed = None
                    matches = None
            report["rounds"].append(
                {
                    "round": index,
                    "write": {k: v for k, v in write_result.items() if k not in {"stdout", "stderr"}},
                    "read": {k: v for k, v in read_result.items() if k not in {"stdout", "stderr"}},
                    "observed": reportable_observed_value(observed, matches, args.include_values, detected_format),
                    "observed_redacted": observed is not None
                    and reportable_observed_value(observed, matches, args.include_values, detected_format) is None,
                    "matches": matches,
                    "observations": observations,
                }
            )
        observations = [observation for item in report["rounds"] for observation in item["observations"]]
        matches = [item["matches"] for item in observations if item["matches"] is not None]
        if args.dry_run:
            report["conclusion"] = "not-executed"
        elif any(match is False for match in matches):
            report["conclusion"] = "clipboard-content-changed"
        elif not matches or any(item["write"].get("status") != "ok" or item["read"].get("status") != "ok" for item in report["rounds"]):
            report["conclusion"] = "tool-unavailable-or-error"
        else:
            report["conclusion"] = "no-change-observed"
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
