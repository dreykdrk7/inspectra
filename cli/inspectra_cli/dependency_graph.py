"""Dependency evidence preflight for the dependency-free Inspectra CLI."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
from typing import Any

from inspectra_cli.git_snapshot import SnapshotError
from inspectra_cli.dependency_graph_envelope import read_closed_graph_document, validate_source_binding


GO_GRAPH_CONTRACT_VERSION = "2026-09-10.1"
GO_GRAPH_MAX_BYTES = 1_048_576
GO_GRAPH_MAX_NODES = 2_000
GO_GRAPH_MAX_EDGES = 4_000
_GO_NAME = re.compile(r"[a-z0-9][a-z0-9._~-]*(?:/[a-z0-9][a-z0-9._~+\-]*)+")
_GO_VERSION = re.compile(r"v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?")
_NODE_ID = re.compile(r"[A-Za-z0-9_-]{1,32}")


@dataclass(frozen=True)
class ValidatedGoDependencyGraph:
    payload: bytes
    sha256: str
    nodes: int
    edges: int
    complete: bool

    def public_dict(self) -> dict[str, object]:
        return {
            "contract_version": GO_GRAPH_CONTRACT_VERSION,
            "ecosystem": "go",
            "artifact_sha256": self.sha256,
            "nodes": self.nodes,
            "edges": self.edges,
            "complete": self.complete,
            "source_binding_verified_locally": True,
        }


def validate_go_dependency_graph(
    path: Path,
    *,
    expected_commit_sha: str,
    expected_source_sha256: str,
) -> ValidatedGoDependencyGraph:
    """Read one regular file once, then validate the same closed server shape."""

    payload, document = read_closed_graph_document(path, ecosystem_label="Go", max_bytes=GO_GRAPH_MAX_BYTES)
    _validate_document(document, expected_commit_sha, expected_source_sha256)
    return ValidatedGoDependencyGraph(
        payload=payload,
        sha256=hashlib.sha256(payload).hexdigest(),
        nodes=len(document["nodes"]),
        edges=len(document["edges"]),
        complete=document["complete"],
    )


def _validate_document(document: Any, expected_commit_sha: str, expected_source_sha256: str) -> None:
    expected_keys = {
        "contract_version", "ecosystem", "producer", "source_commit_sha", "source_sha256",
        "complete", "truncation_reason", "nodes", "roots", "edges",
    }
    if not isinstance(document, dict) or set(document) != expected_keys:
        raise SnapshotError("The Go dependency graph does not match the supported contract.")
    if (
        document["contract_version"] != GO_GRAPH_CONTRACT_VERSION
        or document["ecosystem"] != "go"
        or document["producer"] != "go-mod-graph"
        or type(document["complete"]) is not bool
        or document["truncation_reason"] not in {None, "node_limit", "edge_limit", "producer_limit"}
        or document["complete"] != (document["truncation_reason"] is None)
    ):
        raise SnapshotError("The Go dependency graph does not match this commit and snapshot.")
    validate_source_binding(document, expected_commit_sha=expected_commit_sha, expected_source_sha256=expected_source_sha256, ecosystem_label="Go")
    nodes, roots, edges = document["nodes"], document["roots"], document["edges"]
    if not isinstance(nodes, list) or not isinstance(roots, list) or not isinstance(edges, list):
        raise SnapshotError("The Go dependency graph collections are invalid.")
    if len(nodes) > GO_GRAPH_MAX_NODES or len(roots) > GO_GRAPH_MAX_NODES or len(edges) > GO_GRAPH_MAX_EDGES:
        raise SnapshotError("The Go dependency graph exceeds its node or edge limit.")
    node_ids: list[str] = []
    identities: list[tuple[str, str]] = []
    for node in nodes:
        if not isinstance(node, dict) or set(node) != {"id", "name", "version"}:
            raise SnapshotError("A Go dependency graph node is invalid.")
        node_id, name, version = node["id"], node["name"], node["version"]
        if (
            not isinstance(node_id, str) or not _NODE_ID.fullmatch(node_id)
            or not isinstance(name, str) or len(name) > 300 or not _GO_NAME.fullmatch(name) or "." not in name.split("/", 1)[0]
            or not isinstance(version, str) or len(version) > 160 or not _GO_VERSION.fullmatch(version)
        ):
            raise SnapshotError("A Go dependency graph identity is not exact and correlatable.")
        node_ids.append(node_id)
        identities.append((name, version))
    if node_ids != sorted(node_ids) or len(set(node_ids)) != len(node_ids) or len(set(identities)) != len(identities):
        raise SnapshotError("Go dependency graph nodes must be unique and canonically ordered.")
    if any(not isinstance(root, str) or not _NODE_ID.fullmatch(root) for root in roots):
        raise SnapshotError("A Go dependency graph root is invalid.")
    if roots != sorted(roots) or len(set(roots)) != len(roots) or not set(roots).issubset(node_ids):
        raise SnapshotError("Go dependency graph roots must be unique, known and canonically ordered.")
    pairs: list[tuple[str, str]] = []
    for edge in edges:
        if not isinstance(edge, dict) or set(edge) != {"source", "target"}:
            raise SnapshotError("A Go dependency graph edge is invalid.")
        pair = (edge["source"], edge["target"])
        if any(not isinstance(item, str) or not _NODE_ID.fullmatch(item) for item in pair) or not set(pair).issubset(node_ids):
            raise SnapshotError("A Go dependency graph edge references an unknown node.")
        pairs.append(pair)
    if pairs != sorted(pairs) or len(set(pairs)) != len(pairs):
        raise SnapshotError("Go dependency graph edges must be unique and canonically ordered.")
