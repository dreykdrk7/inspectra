"""Common transport envelope checks; ecosystem schemas remain closed elsewhere."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Callable


ErrorFactory = Callable[[str], Exception]
CI_GRAPH_ENVELOPE_VERSION = "2026-09-10.1"


def decode_graph_envelope(
    payload: bytes, *, declared_sha256: str, max_bytes: int, error: ErrorFactory
) -> tuple[dict[str, Any], str]:
    if not payload or len(payload) > max_bytes:
        raise error("artifact_size_invalid")
    digest = hashlib.sha256(payload).hexdigest()
    if declared_sha256 != digest:
        raise error("artifact_digest_mismatch")
    try:
        document = json.loads(payload.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise error("artifact_json_invalid") from None
    if not isinstance(document, dict):
        raise error("artifact_contract_invalid")
    return document, digest


def validate_graph_source_binding(
    artifact: Any, *, expected_commit_sha: str, expected_source_sha256: str, error: ErrorFactory
) -> None:
    if artifact.source_commit_sha != expected_commit_sha:
        raise error("source_commit_mismatch")
    if artifact.source_sha256 != expected_source_sha256:
        raise error("source_digest_mismatch")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result
