"""Shared fail-closed file and JSON envelope checks for CI graph evidence."""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat
from typing import Any

from inspectra_cli.git_snapshot import SnapshotError

CI_GRAPH_ENVELOPE_VERSION = "2026-09-10.1"


def read_closed_graph_document(path: Path, *, ecosystem_label: str, max_bytes: int) -> tuple[bytes, dict[str, Any]]:
    """Read one inode once; ecosystem modules still validate every schema field."""

    try:
        raw = path.expanduser()
        candidate = (raw if raw.is_absolute() else Path.cwd() / raw)
        candidate = candidate.parent.resolve(strict=True) / candidate.name
        before = os.lstat(candidate)
        if stat.S_ISLNK(before.st_mode):
            raise SnapshotError(f"The {ecosystem_label} dependency graph must be one bounded regular file.")
        descriptor = os.open(candidate, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            metadata = os.fstat(descriptor)
            if (
                (before.st_dev, before.st_ino) != (metadata.st_dev, metadata.st_ino)
                or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or not 0 < metadata.st_size <= max_bytes
            ):
                raise SnapshotError(f"The {ecosystem_label} dependency graph must be one bounded regular file.")
            buffer = bytearray()
            while len(buffer) <= max_bytes:
                chunk = os.read(descriptor, min(65_536, max_bytes + 1 - len(buffer)))
                if not chunk:
                    break
                buffer.extend(chunk)
            payload = bytes(buffer)
        finally:
            os.close(descriptor)
    except SnapshotError:
        raise
    except OSError as exc:
        raise SnapshotError(f"The {ecosystem_label} dependency graph could not be read safely.") from exc
    if not payload or len(payload) > max_bytes:
        raise SnapshotError(f"The {ecosystem_label} dependency graph exceeds its fixed size limit.")
    try:
        document = json.loads(payload.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise SnapshotError(
            f"The {ecosystem_label} dependency graph is not valid unambiguous UTF-8 JSON."
        ) from exc
    if not isinstance(document, dict):
        raise SnapshotError(f"The {ecosystem_label} dependency graph does not match the supported contract.")
    return payload, document


def validate_source_binding(
    document: dict[str, Any], *, expected_commit_sha: str, expected_source_sha256: str, ecosystem_label: str
) -> None:
    if document.get("source_commit_sha") != expected_commit_sha or document.get("source_sha256") != expected_source_sha256:
        raise SnapshotError(f"The {ecosystem_label} dependency graph does not match this commit and snapshot.")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result
