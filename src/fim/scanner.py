"""Filesystem enumeration and stable, chunked SHA-256 hashing."""

from __future__ import annotations

import fnmatch
import hashlib
import os
import stat
from dataclasses import dataclass, asdict
from pathlib import Path

from .config import Config


@dataclass(frozen=True)
class FileRecord:
    sha256: str
    size: int
    mode: str
    mtime_ns: int
    uid: int | None
    gid: int | None
    is_symlink: bool

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass
class ScanResult:
    files: dict[str, FileRecord]
    errors: list[dict[str, str]]


def _excluded(path: Path, patterns: tuple[str, ...]) -> bool:
    text = path.as_posix()
    return any(fnmatch.fnmatch(text, pattern) or path.match(pattern) for pattern in patterns)


def _hash_file(path: Path, chunk_size: int, follow_symlinks: bool) -> FileRecord:
    before = path.stat() if follow_symlinks else path.lstat()
    if not follow_symlinks and stat.S_ISLNK(before.st_mode):
        raise OSError("symbolic link skipped by policy")
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as stream:
        while chunk := stream.read(chunk_size):
            digest.update(chunk)
            total += len(chunk)
    after = path.stat() if follow_symlinks else path.lstat()
    identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if identity_before != identity_after or total != after.st_size:
        raise OSError("file changed while it was being hashed; retry on next scan")
    return FileRecord(
        sha256=digest.hexdigest(),
        size=total,
        mode=stat.filemode(after.st_mode),
        mtime_ns=after.st_mtime_ns,
        uid=getattr(after, "st_uid", None),
        gid=getattr(after, "st_gid", None),
        is_symlink=path.is_symlink(),
    )


def scan(config: Config) -> ScanResult:
    files: dict[str, FileRecord] = {}
    errors: list[dict[str, str]] = []
    visited_dirs: set[tuple[int, int]] = set()
    follow = config.symlinks == "follow"

    def add_file(path: Path) -> None:
        key = str(path.absolute())
        if _excluded(path, config.exclude):
            return
        try:
            if not follow and path.is_symlink():
                return
            files[key] = _hash_file(path, config.hash_chunk_size, follow)
        except (OSError, PermissionError) as exc:
            errors.append({"path": key, "error": str(exc)})

    def walk(root: Path) -> None:
        if root.is_symlink() and not follow:
            return
        if root.is_file() or root.is_symlink() and not root.is_dir():
            add_file(root)
            return
        if not root.is_dir():
            errors.append({"path": str(root), "error": "not a regular file or directory"})
            return
        try:
            info = root.stat() if follow else root.lstat()
            identity = (info.st_dev, info.st_ino)
            if identity in visited_dirs:
                return
            visited_dirs.add(identity)
            with os.scandir(root) as entries:
                for entry in entries:
                    child = Path(entry.path)
                    if _excluded(child, config.exclude):
                        continue
                    try:
                        if entry.is_dir(follow_symlinks=follow):
                            walk(child)
                        elif entry.is_file(follow_symlinks=follow):
                            add_file(child)
                        elif entry.is_symlink() and follow:
                            if child.is_dir():
                                walk(child)
                            else:
                                add_file(child)
                    except OSError as exc:
                        errors.append({"path": str(child), "error": str(exc)})
        except OSError as exc:
            errors.append({"path": str(root), "error": str(exc)})

    for root in config.watch:
        walk(root)
    return ScanResult(files=files, errors=errors)
