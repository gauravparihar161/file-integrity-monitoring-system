"""Human-readable alerts and append-only JSON Lines event logging."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .baseline import utc_now


def emit(events: list[dict[str, Any]], errors: list[dict[str, str]], log_path: Path) -> None:
    records = [{"timestamp": utc_now(), **event} for event in events]
    records.extend({"timestamp": utc_now(), "event": "scan_error", **error} for error in errors)
    if records:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("a", encoding="utf-8") as stream:
            for record in records:
                stream.write(json.dumps(record, sort_keys=True) + "\n")
        if os.name == "posix":
            os.chmod(log_path, 0o600)
    for record in records:
        event = record["event"]
        if event == "scan_error":
            print(f"ERROR {record['path']}: {record['error']}")
        else:
            print(f"{event.upper()} {record['path']}")
    if not records:
        print("No changes detected.")
