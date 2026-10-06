"""Compare a current inventory with its trusted baseline."""

from __future__ import annotations

from typing import Any

from .scanner import FileRecord, ScanResult


def compare(baseline: dict[str, dict[str, Any]], current: ScanResult) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    old_paths, new_paths = set(baseline), set(current.files)
    for path in sorted(new_paths - old_paths):
        events.append({"event": "created", "path": path, "current": current.files[path].to_dict()})
    for path in sorted(old_paths & new_paths):
        old = baseline[path]
        now = current.files[path].to_dict()
        if old.get("sha256") != now["sha256"]:
            events.append({"event": "modified", "path": path, "previous": old, "current": now})
        elif any(old.get(key) != now.get(key) for key in ("mode", "uid", "gid", "is_symlink")):
            events.append({"event": "metadata_changed", "path": path, "previous": old, "current": now})
    # Missing paths are only reliable when the entire scan completed cleanly.
    if not current.errors:
        for path in sorted(old_paths - new_paths):
            events.append({"event": "deleted", "path": path, "previous": baseline[path]})
    return events


def as_records(files: dict[str, FileRecord]) -> dict[str, FileRecord]:
    return files
