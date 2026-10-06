"""Versioned JSON baseline with atomic replacement and restrictive permissions."""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__
from .scanner import FileRecord

SCHEMA_VERSION = 1


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def save_baseline(path: Path, files: dict[str, FileRecord]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": SCHEMA_VERSION,
        "tool_version": __version__,
        "created_at": utc_now(),
        "files": {name: record.to_dict() for name, record in sorted(files.items())},
    }
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        if os.name == "posix":
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, path)
        if os.name == "posix":
            os.chmod(path, 0o600)
    except Exception:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise


def load_baseline(path: Path) -> dict[str, dict[str, Any]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"Cannot read baseline {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"Baseline is not valid JSON: {exc}") from exc
    if payload.get("schema_version") != SCHEMA_VERSION or not isinstance(payload.get("files"), dict):
        raise ValueError("Unsupported or malformed baseline schema")
    return payload["files"]
