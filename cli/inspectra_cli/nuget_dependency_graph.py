"""Dependency-free validation for one source-bound NuGet target graph."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
from typing import Any

from inspectra_cli.dependency_graph_envelope import read_closed_graph_document, validate_source_binding
from inspectra_cli.git_snapshot import SnapshotError


MAX_BYTES, MAX_NODES, MAX_EDGES, MAX_TARGETS = 1_048_576, 2_000, 4_000, 32
_ID = re.compile(r"[A-Za-z0-9_-]{1,32}")
_TARGET = re.compile(r"t(?:0|[1-9]\d?)")
_NAME = re.compile(r"[a-z0-9][a-z0-9_.-]{0,199}")
_VERSION = re.compile(
    r"(\d+(?:\.\d+){0,3})(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
)


@dataclass(frozen=True)
class ValidatedNugetDependencyGraph:
    payload: bytes
    sha256: str
    nodes: int
    edges: int
    targets: int
    complete: bool

    def public_dict(self) -> dict[str, object]:
        return {
            "contract_version": "2026-09-10.5", "ecosystem": "nuget",
            "producer": "nuget", "artifact_sha256": self.sha256,
            "nodes": self.nodes, "edges": self.edges, "targets": self.targets,
            "complete": self.complete, "source_binding_verified_locally": True,
        }


def validate_nuget_dependency_graph(
    path: Path, *, expected_commit_sha: str, expected_source_sha256: str
) -> ValidatedNugetDependencyGraph:
    payload, document = read_closed_graph_document(path, ecosystem_label="NuGet", max_bytes=MAX_BYTES)
    _validate(document, expected_commit_sha, expected_source_sha256)
    return ValidatedNugetDependencyGraph(
        payload, hashlib.sha256(payload).hexdigest(), len(document["nodes"]),
        len(document["edges"]), len(document["targets"]), document["complete"],
    )


def _targets(value: Any) -> bool:
    return (
        isinstance(value, list) and 1 <= len(value) <= MAX_TARGETS
        and all(isinstance(item, str) and _TARGET.fullmatch(item) for item in value)
        and value == sorted(value, key=lambda item: int(item[1:])) and len(value) == len(set(value))
    )


def _target_universe(value: Any) -> bool:
    return _targets(value) and value == [f"t{index}" for index in range(len(value))]


def normalize_nuget_version(value: Any) -> str | None:
    """Mirror the bounded server-side NuGetVersion canonical identity."""

    if not isinstance(value, str) or len(value) > 64:
        return None
    matched = _VERSION.fullmatch(value.strip())
    if matched is None:
        return None
    numbers = [int(part) for part in matched.group(1).split(".")]
    if any(part > 2_147_483_647 for part in numbers):
        return None
    numbers.extend([0] * (4 - len(numbers)))
    core = ".".join(str(part) for part in numbers[:3])
    if numbers[3]:
        core = f"{core}.{numbers[3]}"
    prerelease = matched.group(2)
    if prerelease is None:
        return core
    labels = prerelease.split(".")
    if any(part.isdigit() and int(part) > 2_147_483_647 for part in labels):
        return None
    return f"{core}-" + ".".join(
        str(int(part)) if part.isdigit() else part.lower() for part in labels
    )


def _validate(document: Any, commit: str, source: str) -> None:
    keys = {
        "contract_version", "ecosystem", "producer", "source_commit_sha", "source_sha256",
        "target_coverage", "complete", "truncation_reason", "targets", "nodes", "roots", "edges",
    }
    if not isinstance(document, dict) or set(document) != keys:
        raise SnapshotError("The NuGet dependency graph does not match the supported contract.")
    if (
        document["contract_version"] != "2026-09-10.5" or document["ecosystem"] != "nuget"
        or document["producer"] != "nuget-dependency-graph"
        or document["target_coverage"] != "all_locked_targets"
        or type(document["complete"]) is not bool
        or document["truncation_reason"] not in {None, "node_limit", "edge_limit", "target_limit", "producer_limit"}
        or document["complete"] != (document["truncation_reason"] is None)
        or not _target_universe(document["targets"])
    ):
        raise SnapshotError("The NuGet dependency graph does not match this commit and snapshot.")
    validate_source_binding(document, expected_commit_sha=commit, expected_source_sha256=source, ecosystem_label="NuGet")
    nodes, roots, edges = document["nodes"], document["roots"], document["edges"]
    if not all(isinstance(value, list) for value in (nodes, roots, edges)) or not nodes or len(nodes) > MAX_NODES or not roots or len(roots) > MAX_NODES or len(edges) > MAX_EDGES:
        raise SnapshotError("The NuGet dependency graph exceeds its fixed collection limits.")
    covered, node_ids, identities, node_targets = set(document["targets"]), [], [], {}
    for node in nodes:
        if (
            not isinstance(node, dict) or set(node) != {"id", "name", "version", "targets"}
            or not isinstance(node["id"], str) or not _ID.fullmatch(node["id"])
            or not isinstance(node["name"], str) or not _NAME.fullmatch(node["name"])
            or normalize_nuget_version(node.get("version")) != node.get("version")
            or not _targets(node["targets"]) or not set(node["targets"]).issubset(covered)
        ):
            raise SnapshotError("A NuGet dependency graph node is invalid.")
        node_ids.append(node["id"]); identities.append((node["name"], node["version"])); node_targets[node["id"]] = set(node["targets"])
    if node_ids != sorted(node_ids) or len(set(node_ids)) != len(node_ids) or len(set(identities)) != len(identities):
        raise SnapshotError("NuGet graph nodes must be unique and canonically ordered.")
    root_keys = []
    for root in roots:
        if (
            not isinstance(root, dict) or set(root) != {"node", "targets"}
            or root["node"] not in node_targets or not _targets(root["targets"])
            or not set(root["targets"]).issubset(node_targets[root["node"]])
        ):
            raise SnapshotError("A NuGet dependency graph root is invalid.")
        root_keys.append((root["node"], tuple(root["targets"])))
    if root_keys != sorted(root_keys) or len(set(root_keys)) != len(root_keys) or {target for root in roots for target in root["targets"]} != covered:
        raise SnapshotError("NuGet graph roots must cover every opaque target exactly and canonically.")
    edge_keys = []
    for edge in edges:
        if (
            not isinstance(edge, dict) or set(edge) != {"source", "target", "targets"}
            or edge["source"] not in node_targets or edge["target"] not in node_targets
            or not _targets(edge["targets"])
            or not set(edge["targets"]).issubset(node_targets[edge["source"]] & node_targets[edge["target"]])
        ):
            raise SnapshotError("A NuGet dependency graph edge is invalid.")
        edge_keys.append((edge["source"], edge["target"], tuple(edge["targets"])))
    if edge_keys != sorted(edge_keys) or len(set(edge_keys)) != len(edge_keys):
        raise SnapshotError("NuGet graph edges must be unique and canonically ordered.")
