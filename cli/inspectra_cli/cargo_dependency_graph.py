"""Dependency-free preflight for one source-bound Cargo graph artifact."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
from typing import Any

from inspectra_cli.git_snapshot import SnapshotError
from inspectra_cli.dependency_graph_envelope import read_closed_graph_document, validate_source_binding


CARGO_GRAPH_CONTRACT_VERSION = "2026-09-10.2"
CARGO_GRAPH_MAX_BYTES = 1_048_576
CARGO_GRAPH_MAX_NODES = 2_000
CARGO_GRAPH_MAX_EDGES = 4_000
CARGO_GRAPH_MAX_TARGETS = 32
CARGO_GRAPH_MAX_FEATURES_PER_NODE = 64
_CARGO_NAME = re.compile(r"[a-z0-9][a-z0-9_-]{0,127}")
_CARGO_VERSION = re.compile(r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?")
_OPAQUE_ID = re.compile(r"[A-Za-z0-9_-]{1,32}")
_FEATURE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")


@dataclass(frozen=True)
class ValidatedCargoDependencyGraph:
    payload: bytes
    sha256: str
    nodes: int
    edges: int
    targets: int
    features: int
    complete: bool

    def public_dict(self) -> dict[str, object]:
        return {
            "contract_version": CARGO_GRAPH_CONTRACT_VERSION,
            "ecosystem": "cargo",
            "artifact_sha256": self.sha256,
            "nodes": self.nodes,
            "edges": self.edges,
            "targets": self.targets,
            "features": self.features,
            "complete": self.complete,
            "source_binding_verified_locally": True,
        }


def validate_cargo_dependency_graph(
    path: Path,
    *,
    expected_commit_sha: str,
    expected_source_sha256: str,
) -> ValidatedCargoDependencyGraph:
    payload, document = read_closed_graph_document(path, ecosystem_label="Cargo", max_bytes=CARGO_GRAPH_MAX_BYTES)
    _validate_document(document, expected_commit_sha, expected_source_sha256)
    return ValidatedCargoDependencyGraph(
        payload=payload,
        sha256=hashlib.sha256(payload).hexdigest(),
        nodes=len(document["nodes"]),
        edges=len(document["edges"]),
        targets=len(document["targets"]),
        features=sum(len(node["features"]) for node in document["nodes"]),
        complete=document["complete"],
    )


def _validate_document(document: Any, expected_commit_sha: str, expected_source_sha256: str) -> None:
    expected_keys = {
        "contract_version", "ecosystem", "producer", "source_commit_sha", "source_sha256",
        "target_coverage", "complete", "truncation_reason", "targets", "nodes", "roots", "edges",
    }
    if not isinstance(document, dict) or set(document) != expected_keys:
        raise SnapshotError("The Cargo dependency graph does not match the supported contract.")
    if (
        document["contract_version"] != CARGO_GRAPH_CONTRACT_VERSION
        or document["ecosystem"] != "cargo"
        or document["producer"] != "cargo-metadata-graph"
        or document["target_coverage"] != "all_locked_targets"
        or type(document["complete"]) is not bool
        or document["truncation_reason"] not in {None, "node_limit", "edge_limit", "feature_limit", "target_limit", "producer_limit"}
        or document["complete"] != (document["truncation_reason"] is None)
    ):
        raise SnapshotError("The Cargo dependency graph does not match this commit and snapshot.")
    validate_source_binding(document, expected_commit_sha=expected_commit_sha, expected_source_sha256=expected_source_sha256, ecosystem_label="Cargo")
    targets, nodes, roots, edges = document["targets"], document["nodes"], document["roots"], document["edges"]
    if not all(isinstance(value, list) for value in (targets, nodes, roots, edges)):
        raise SnapshotError("The Cargo dependency graph collections are invalid.")
    if (
        not 0 < len(targets) <= CARGO_GRAPH_MAX_TARGETS
        or len(nodes) > CARGO_GRAPH_MAX_NODES
        or len(roots) > CARGO_GRAPH_MAX_NODES
        or len(edges) > CARGO_GRAPH_MAX_EDGES
    ):
        raise SnapshotError("The Cargo dependency graph exceeds its fixed collection limits.")
    if targets != sorted(targets) or len(set(targets)) != len(targets) or any(not isinstance(value, str) or not _OPAQUE_ID.fullmatch(value) for value in targets):
        raise SnapshotError("Cargo graph targets must be opaque, unique and canonically ordered.")
    target_set = set(targets)
    node_ids: list[str] = []
    identities: list[tuple[str, str]] = []
    for node in nodes:
        if not isinstance(node, dict) or set(node) != {"id", "name", "version", "features", "targets"}:
            raise SnapshotError("A Cargo dependency graph node is invalid.")
        node_id, name, version = node["id"], node["name"], node["version"]
        features, node_targets = node["features"], node["targets"]
        if (
            not isinstance(node_id, str) or not _OPAQUE_ID.fullmatch(node_id)
            or not isinstance(name, str) or not _CARGO_NAME.fullmatch(name)
            or not isinstance(version, str) or not _CARGO_VERSION.fullmatch(version)
            or not isinstance(features, list) or len(features) > CARGO_GRAPH_MAX_FEATURES_PER_NODE
            or features != sorted(features) or len(set(features)) != len(features)
            or any(not isinstance(value, str) or not _FEATURE.fullmatch(value) for value in features)
            or not isinstance(node_targets, list) or not node_targets or len(node_targets) > CARGO_GRAPH_MAX_TARGETS
            or node_targets != sorted(node_targets) or len(set(node_targets)) != len(node_targets)
            or not set(node_targets).issubset(target_set)
        ):
            raise SnapshotError("A Cargo dependency graph identity or dimension is invalid.")
        node_ids.append(node_id)
        identities.append((name, version))
    if node_ids != sorted(node_ids) or len(set(node_ids)) != len(node_ids) or len(set(identities)) != len(identities):
        raise SnapshotError("Cargo dependency graph nodes must be unique and canonically ordered.")
    if roots != sorted(roots) or len(set(roots)) != len(roots) or any(not isinstance(value, str) or not _OPAQUE_ID.fullmatch(value) for value in roots) or not set(roots).issubset(node_ids):
        raise SnapshotError("Cargo dependency graph roots must be unique, known and canonically ordered.")
    edge_keys: list[tuple[str, str, tuple[str, ...]]] = []
    for edge in edges:
        if not isinstance(edge, dict) or set(edge) != {"source", "target", "targets"}:
            raise SnapshotError("A Cargo dependency graph edge is invalid.")
        source, target, edge_targets = edge["source"], edge["target"], edge["targets"]
        if (
            not isinstance(source, str) or source not in node_ids
            or not isinstance(target, str) or target not in node_ids
            or not isinstance(edge_targets, list) or not edge_targets or len(edge_targets) > CARGO_GRAPH_MAX_TARGETS
            or edge_targets != sorted(edge_targets) or len(set(edge_targets)) != len(edge_targets)
            or not set(edge_targets).issubset(target_set)
        ):
            raise SnapshotError("A Cargo dependency graph edge references an unknown node or target.")
        edge_keys.append((source, target, tuple(edge_targets)))
    if edge_keys != sorted(edge_keys) or len(set(edge_keys)) != len(edge_keys):
        raise SnapshotError("Cargo dependency graph edges must be unique and canonically ordered.")
