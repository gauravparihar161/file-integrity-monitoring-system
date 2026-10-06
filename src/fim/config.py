"""Configuration loading and path policy."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class ConfigError(ValueError):
    """Raised when configuration is invalid."""


@dataclass(frozen=True)
class Config:
    config_path: Path
    watch: tuple[Path, ...]
    exclude: tuple[str, ...]
    baseline: Path
    log: Path
    interval_seconds: float
    symlinks: str
    hash_chunk_size: int


def load_config(path: Path) -> Config:
    path = path.expanduser().resolve()
    try:
        raw: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"Cannot read config {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(f"Invalid JSON in {path}: {exc}") from exc

    base = path.parent

    def resolve(value: str) -> Path:
        candidate = Path(value).expanduser()
        return (candidate if candidate.is_absolute() else base / candidate).resolve()

    watch_value = raw.get("watch")
    if not isinstance(watch_value, list) or not watch_value or not all(isinstance(x, str) for x in watch_value):
        raise ConfigError("'watch' must be a non-empty list of paths")
    watch = tuple(resolve(item) for item in watch_value)
    for item in watch:
        if not item.exists():
            raise ConfigError(f"Monitored path does not exist: {item}")

    exclude = raw.get("exclude", [])
    if not isinstance(exclude, list) or not all(isinstance(x, str) for x in exclude):
        raise ConfigError("'exclude' must be a list of glob patterns")
    symlinks = raw.get("symlinks", "skip")
    if symlinks not in {"skip", "follow"}:
        raise ConfigError("'symlinks' must be 'skip' or 'follow'")

    interval = raw.get("interval_seconds", 30)
    chunk_size = raw.get("hash_chunk_size", 1024 * 1024)
    if not isinstance(interval, (int, float)) or interval <= 0:
        raise ConfigError("'interval_seconds' must be greater than zero")
    if not isinstance(chunk_size, int) or chunk_size < 4096:
        raise ConfigError("'hash_chunk_size' must be an integer of at least 4096")

    return Config(
        config_path=path,
        watch=watch,
        exclude=tuple(exclude),
        baseline=resolve(raw.get("baseline", ".fim/baseline.json")),
        log=resolve(raw.get("log", ".fim/events.jsonl")),
        interval_seconds=float(interval),
        symlinks=symlinks,
        hash_chunk_size=chunk_size,
    )


def validate_state_locations(config: Config) -> None:
    """Prevent the monitor from accidentally monitoring its own mutable state."""
    for state_path in (config.baseline, config.log):
        for root in config.watch:
            try:
                state_path.relative_to(root)
            except ValueError:
                continue
            raise ConfigError(
                f"State file {state_path} is inside monitored path {root}; "
                "move baseline and log outside watched directories"
            )
