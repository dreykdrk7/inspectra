"""Dependency-free validation for one source-bound Composer graph."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
from typing import Any

from inspectra_cli.git_snapshot import SnapshotError
from inspectra_cli.dependency_graph_envelope import read_closed_graph_document, validate_source_binding

MAX_BYTES, MAX_NODES, MAX_EDGES = 1_048_576, 2_000, 4_000
_ID = re.compile(r"[A-Za-z0-9_-]{1,32}")
_NAME = re.compile(r"[a-z0-9][a-z0-9_.-]*/[a-z0-9][a-z0-9_.-]*")
_VERSION = re.compile(r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?")


@dataclass(frozen=True)
class ValidatedComposerDependencyGraph:
    payload: bytes
    sha256: str
    nodes: int
    edges: int
    complete: bool

    def public_dict(self) -> dict[str, object]:
        return {"contract_version": "2026-09-10.3", "ecosystem": "composer", "artifact_sha256": self.sha256,
                "nodes": self.nodes, "edges": self.edges, "complete": self.complete,
                "source_binding_verified_locally": True}


def validate_composer_dependency_graph(
    path: Path, *, expected_commit_sha: str, expected_source_sha256: str
) -> ValidatedComposerDependencyGraph:
    payload, document = read_closed_graph_document(path, ecosystem_label="Composer", max_bytes=MAX_BYTES)
    _validate(document, expected_commit_sha, expected_source_sha256)
    return ValidatedComposerDependencyGraph(payload, hashlib.sha256(payload).hexdigest(), len(document["nodes"]), len(document["edges"]), document["complete"])


def _validate(document: Any, commit: str, source: str) -> None:
    keys = {"contract_version", "ecosystem", "producer", "source_commit_sha", "source_sha256", "complete", "truncation_reason", "nodes", "roots", "edges"}
    if not isinstance(document, dict) or set(document) != keys:
        raise SnapshotError("The Composer dependency graph does not match the supported contract.")
    if (document["contract_version"] != "2026-09-10.3" or document["ecosystem"] != "composer"
            or document["producer"] != "composer-locked-graph" or type(document["complete"]) is not bool
            or document["truncation_reason"] not in {None, "node_limit", "edge_limit", "producer_limit"}
            or document["complete"] != (document["truncation_reason"] is None)):
        raise SnapshotError("The Composer dependency graph does not match this commit and snapshot.")
    validate_source_binding(document, expected_commit_sha=commit, expected_source_sha256=source, ecosystem_label="Composer")
    nodes, roots, edges = document["nodes"], document["roots"], document["edges"]
    if not all(isinstance(value, list) for value in (nodes, roots, edges)) or len(nodes) > MAX_NODES or len(roots) > MAX_NODES or len(edges) > MAX_EDGES:
        raise SnapshotError("The Composer dependency graph exceeds its fixed collection limits.")
    node_ids, identities = [], []
    for node in nodes:
        if (not isinstance(node, dict) or set(node) != {"id", "name", "version"}
                or not isinstance(node["id"], str) or not _ID.fullmatch(node["id"])
                or not isinstance(node["name"], str) or not _NAME.fullmatch(node["name"])
                or not isinstance(node["version"], str) or not _VERSION.fullmatch(node["version"])):
            raise SnapshotError("A Composer dependency graph node is invalid.")
        node_ids.append(node["id"]); identities.append((node["name"], node["version"]))
    if node_ids != sorted(node_ids) or len(set(node_ids)) != len(node_ids) or len(set(identities)) != len(identities):
        raise SnapshotError("Composer graph nodes must be unique and canonically ordered.")
    if roots != sorted(roots) or len(set(roots)) != len(roots) or any(not isinstance(item, str) or item not in node_ids for item in roots):
        raise SnapshotError("Composer graph roots must be unique, known and canonically ordered.")
    pairs = []
    for edge in edges:
        if not isinstance(edge, dict) or set(edge) != {"source", "target"} or edge["source"] not in node_ids or edge["target"] not in node_ids:
            raise SnapshotError("A Composer graph edge is invalid.")
        pairs.append((edge["source"], edge["target"]))
    if pairs != sorted(pairs) or len(set(pairs)) != len(pairs):
        raise SnapshotError("Composer graph edges must be unique and canonically ordered.")
