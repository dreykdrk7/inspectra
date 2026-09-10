"""Dependency-free validation for one source-bound Gradle relationship graph."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
from typing import Any

from inspectra_cli.dependency_graph_envelope import read_closed_graph_document, validate_source_binding
from inspectra_cli.git_snapshot import SnapshotError


MAX_BYTES, MAX_NODES, MAX_EDGES = 1_048_576, 2_000, 4_000
_ID = re.compile(r"[A-Za-z0-9_-]{1,32}")
_NAME = re.compile(r"[a-z0-9][a-z0-9_.-]*:[a-z0-9][a-z0-9_.-]*")
_VERSION = re.compile(
    r"(?:0|[1-9]\d*)(?:\.(?:0|[1-9]\d*))*"
    r"(?:[.-](?:alpha|a|beta|b|milestone|m|rc|cr|snapshot|ga|final|release|sp)"
    r"(?:[.-]?(?:0|[1-9]\d*))?)?",
    re.IGNORECASE,
)
_SCOPES = {"compile", "runtime", "test"}


@dataclass(frozen=True)
class ValidatedGradleDependencyGraph:
    payload: bytes
    sha256: str
    nodes: int
    edges: int
    complete: bool

    def public_dict(self) -> dict[str, object]:
        return {
            "contract_version": "2026-09-10.4", "ecosystem": "maven",
            "producer": "gradle", "artifact_sha256": self.sha256,
            "nodes": self.nodes, "edges": self.edges, "complete": self.complete,
            "source_binding_verified_locally": True,
        }


def validate_gradle_dependency_graph(
    path: Path, *, expected_commit_sha: str, expected_source_sha256: str
) -> ValidatedGradleDependencyGraph:
    payload, document = read_closed_graph_document(path, ecosystem_label="Gradle", max_bytes=MAX_BYTES)
    _validate(document, expected_commit_sha, expected_source_sha256)
    return ValidatedGradleDependencyGraph(
        payload, hashlib.sha256(payload).hexdigest(), len(document["nodes"]),
        len(document["edges"]), document["complete"],
    )


def _ordered_scopes(value: Any) -> bool:
    return (
        isinstance(value, list) and 1 <= len(value) <= 3
        and all(type(item) is str and item in _SCOPES for item in value)
        and value == sorted(value) and len(set(value)) == len(value)
    )


def _supported_version(value: Any) -> bool:
    if not isinstance(value, str) or len(value) > 160 or not _VERSION.fullmatch(value):
        return False
    lowered = value.lower()
    if re.search(r"(?:snapshot|ga|final|release)[.-]?\d+$", lowered):
        return False
    if re.search(r"\.(?:alpha|a|beta|b|milestone|m|rc|cr|snapshot|sp)(?:[.-]?\d+)?$", lowered):
        return False
    return not re.search(r"-(?:a|b|m)$", lowered)


def _validate(document: Any, commit: str, source: str) -> None:
    keys = {
        "contract_version", "ecosystem", "producer", "source_commit_sha", "source_sha256",
        "scope_coverage", "complete", "truncation_reason", "nodes", "roots", "edges",
    }
    if not isinstance(document, dict) or set(document) != keys:
        raise SnapshotError("The Gradle dependency graph does not match the supported contract.")
    if (
        document["contract_version"] != "2026-09-10.4" or document["ecosystem"] != "maven"
        or document["producer"] != "gradle-dependency-graph" or type(document["complete"]) is not bool
        or document["truncation_reason"] not in {None, "node_limit", "edge_limit", "producer_limit"}
        or document["complete"] != (document["truncation_reason"] is None)
        or not _ordered_scopes(document["scope_coverage"])
    ):
        raise SnapshotError("The Gradle dependency graph does not match this commit and snapshot.")
    validate_source_binding(document, expected_commit_sha=commit, expected_source_sha256=source, ecosystem_label="Gradle")
    nodes, roots, edges = document["nodes"], document["roots"], document["edges"]
    if not all(isinstance(value, list) for value in (nodes, roots, edges)) or not nodes or len(nodes) > MAX_NODES or not roots or len(roots) > MAX_NODES or len(edges) > MAX_EDGES:
        raise SnapshotError("The Gradle dependency graph exceeds its fixed collection limits.")
    covered, node_ids, identities = set(document["scope_coverage"]), [], []
    for node in nodes:
        if (
            not isinstance(node, dict) or set(node) != {"id", "name", "version", "scopes"}
            or not isinstance(node["id"], str) or not _ID.fullmatch(node["id"])
            or not isinstance(node["name"], str) or len(node["name"]) > 321 or not _NAME.fullmatch(node["name"])
            or not _supported_version(node["version"])
            or not _ordered_scopes(node["scopes"]) or not set(node["scopes"]).issubset(covered)
        ):
            raise SnapshotError("A Gradle dependency graph node is invalid.")
        node_ids.append(node["id"]); identities.append((node["name"], node["version"]))
    if node_ids != sorted(node_ids) or len(set(node_ids)) != len(node_ids) or len(set(identities)) != len(identities):
        raise SnapshotError("Gradle graph nodes must be unique and canonically ordered.")
    known = set(node_ids)
    if roots != sorted(roots) or len(set(roots)) != len(roots) or any(type(item) is not str or item not in known for item in roots):
        raise SnapshotError("Gradle graph roots must be unique, known and canonically ordered.")
    keys_seen = []
    for edge in edges:
        if (
            not isinstance(edge, dict) or set(edge) != {"source", "target", "scopes"}
            or edge["source"] not in known or edge["target"] not in known
            or not _ordered_scopes(edge["scopes"]) or not set(edge["scopes"]).issubset(covered)
        ):
            raise SnapshotError("A Gradle dependency graph edge is invalid.")
        keys_seen.append((edge["source"], edge["target"], tuple(edge["scopes"])))
    if keys_seen != sorted(keys_seen) or len(set(keys_seen)) != len(keys_seen):
        raise SnapshotError("Gradle graph edges must be unique and canonically ordered.")
