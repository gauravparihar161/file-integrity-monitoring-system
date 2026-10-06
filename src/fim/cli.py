"""Command-line entry point."""

from __future__ import annotations

import argparse
import json
import signal
import sys
import time
from pathlib import Path

from .baseline import load_baseline, save_baseline
from .config import ConfigError, load_config, validate_state_locations
from .detector import compare
from .reporting import emit
from .scanner import scan


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="fim", description="SHA-256 file integrity monitor")
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("baseline", "scan", "monitor"):
        child = sub.add_parser(command)
        child.add_argument("--config", type=Path, default=Path("fim.json"))
        if command == "monitor":
            child.add_argument("--interval", type=float, help="override configured interval in seconds")
        if command == "scan":
            child.add_argument("--update-baseline", action="store_true", help="accept changes after a clean scan")
    return parser


def _load(args: argparse.Namespace):
    config = load_config(args.config)
    validate_state_locations(config)
    return config


def _baseline(config) -> int:
    result = scan(config)
    if result.errors:
        emit([], result.errors, config.log)
        print("Baseline not written because the scan was incomplete.", file=sys.stderr)
        return 2
    save_baseline(config.baseline, result.files)
    print(f"Baseline saved: {config.baseline} ({len(result.files)} files)")
    return 0


def _scan(config, update: bool = False) -> int:
    baseline = load_baseline(config.baseline)
    current = scan(config)
    events = compare(baseline, current)
    emit(events, current.errors, config.log)
    if update:
        if current.errors:
            print("Baseline not updated because the scan was incomplete.", file=sys.stderr)
            return 2
        save_baseline(config.baseline, current.files)
        print(f"Baseline updated: {config.baseline}")
    return 2 if current.errors else (1 if events else 0)


def main() -> int:
    args = _parser().parse_args()
    try:
        config = _load(args)
        if args.command == "baseline":
            return _baseline(config)
        if args.command == "scan":
            return _scan(config, args.update_baseline)
        interval = args.interval if args.interval is not None else config.interval_seconds
        if interval <= 0:
            raise ConfigError("monitor interval must be greater than zero")
        stopped = False

        def stop(_signum, _frame):
            nonlocal stopped
            stopped = True

        signal.signal(signal.SIGINT, stop)
        if hasattr(signal, "SIGTERM"):
            signal.signal(signal.SIGTERM, stop)
        print(f"Monitoring {len(config.watch)} path(s) every {interval:g}s. Press Ctrl+C to stop.")
        while not stopped:
            try:
                code = _scan(config)
                if code == 2:
                    print("Scan had errors; see the event log.", file=sys.stderr)
            except ValueError as exc:
                print(f"ERROR: {exc}", file=sys.stderr)
                return 2
            deadline = time.monotonic() + interval
            while not stopped and time.monotonic() < deadline:
                time.sleep(min(0.25, deadline - time.monotonic()))
        print("Monitor stopped.")
        return 0
    except (ConfigError, ValueError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
