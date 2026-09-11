"""Closed, source-bound NuGet graph emitted by authorized CI."""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from app.dependency_graph_envelope import decode_graph_envelope, validate_graph_source_binding
from app.sbom import extract_exact_version, is_valid_nuget_name


NUGET_DEPENDENCY_GRAPH_CONTRACT_VERSION = "2026-09-10.5"
NUGET_DEPENDENCY_GRAPH_MAX_BYTES = 1_048_576
NUGET_DEPENDENCY_GRAPH_MAX_NODES = 2_000
NUGET_DEPENDENCY_GRAPH_MAX_EDGES = 4_000
NUGET_DEPENDENCY_GRAPH_MAX_TARGETS = 32


class NugetDependencyGraphError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class NugetDependencyGraphNode(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    id: str = Field(min_length=1, max_length=32, pattern=r"^[A-Za-z0-9_-]+$")
    name: str = Field(min_length=1, max_length=200)
    version: str = Field(min_length=5, max_length=64)
    targets: list[str] = Field(min_length=1, max_length=NUGET_DEPENDENCY_GRAPH_MAX_TARGETS)

    @model_validator(mode="after")
    def exact_identity_and_targets(self):
        if not is_valid_nuget_name(self.name) or extract_exact_version(self.version, "nuget") != self.version:
            raise ValueError("invalid NuGet identity")
        if not _canonical_target_ids(self.targets):
            raise ValueError("invalid NuGet target assignments")
        return self


class NugetDependencyGraphRoot(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    node: str = Field(min_length=1, max_length=32, pattern=r"^[A-Za-z0-9_-]+$")
    targets: list[str] = Field(min_length=1, max_length=NUGET_DEPENDENCY_GRAPH_MAX_TARGETS)

    @model_validator(mode="after")
    def canonical_targets(self):
        if not _canonical_target_ids(self.targets):
            raise ValueError("invalid NuGet root targets")
        return self


class NugetDependencyGraphEdge(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    source: str = Field(min_length=1, max_length=32, pattern=r"^[A-Za-z0-9_-]+$")
    target: str = Field(min_length=1, max_length=32, pattern=r"^[A-Za-z0-9_-]+$")
    targets: list[str] = Field(min_length=1, max_length=NUGET_DEPENDENCY_GRAPH_MAX_TARGETS)

    @model_validator(mode="after")
    def canonical_targets(self):
        if not _canonical_target_ids(self.targets):
            raise ValueError("invalid NuGet edge targets")
        return self


class NugetDependencyGraphArtifact(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    contract_version: Literal["2026-09-10.5"]
    ecosystem: Literal["nuget"]
    producer: Literal["nuget-dependency-graph"]
    source_commit_sha: str = Field(pattern=r"^[a-f0-9]{40,64}$")
    source_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    target_coverage: Literal["all_locked_targets"]
    complete: bool
    truncation_reason: Literal["node_limit", "edge_limit", "target_limit", "producer_limit"] | None
    targets: list[str] = Field(min_length=1, max_length=NUGET_DEPENDENCY_GRAPH_MAX_TARGETS)
    nodes: list[NugetDependencyGraphNode] = Field(min_length=1, max_length=NUGET_DEPENDENCY_GRAPH_MAX_NODES)
    roots: list[NugetDependencyGraphRoot] = Field(min_length=1, max_length=NUGET_DEPENDENCY_GRAPH_MAX_NODES)
    edges: list[NugetDependencyGraphEdge] = Field(max_length=NUGET_DEPENDENCY_GRAPH_MAX_EDGES)

    @model_validator(mode="after")
    def deterministic_closed_graph(self):
        if self.complete != (self.truncation_reason is None) or not _canonical_target_universe(self.targets):
            raise ValueError("invalid NuGet graph completeness or targets")
        covered = set(self.targets)
        node_ids = [node.id for node in self.nodes]
        identities = [(node.name.lower(), node.version) for node in self.nodes]
        root_keys = [(root.node, tuple(root.targets)) for root in self.roots]
        edge_keys = [(edge.source, edge.target, tuple(edge.targets)) for edge in self.edges]
        if node_ids != sorted(node_ids) or len(node_ids) != len(set(node_ids)) or len(identities) != len(set(identities)):
            raise ValueError("duplicate or unordered NuGet node")
        if root_keys != sorted(root_keys) or len(root_keys) != len(set(root_keys)):
            raise ValueError("duplicate or unordered NuGet root")
        if edge_keys != sorted(edge_keys) or len(edge_keys) != len(set(edge_keys)):
            raise ValueError("duplicate or unordered NuGet edge")
        nodes = {node.id: set(node.targets) for node in self.nodes}
        if any(not set(node.targets).issubset(covered) for node in self.nodes):
            raise ValueError("node target outside coverage")
        if any(root.node not in nodes or not set(root.targets).issubset(nodes[root.node]) for root in self.roots):
            raise ValueError("invalid NuGet root")
        if any(
            edge.source not in nodes or edge.target not in nodes
            or not set(edge.targets).issubset(nodes[edge.source] & nodes[edge.target])
            for edge in self.edges
        ):
            raise ValueError("invalid NuGet edge")
        rooted_targets = {target for root in self.roots for target in root.targets}
        if rooted_targets != covered:
            raise ValueError("each NuGet target requires a root")
        return self


def parse_nuget_dependency_graph_artifact(
    payload: bytes, *, declared_sha256: str, expected_commit_sha: str, expected_source_sha256: str
) -> tuple[NugetDependencyGraphArtifact, str]:
    document, digest = decode_graph_envelope(
        payload,
        declared_sha256=declared_sha256,
        max_bytes=NUGET_DEPENDENCY_GRAPH_MAX_BYTES,
        error=NugetDependencyGraphError,
    )
    try:
        artifact = NugetDependencyGraphArtifact.model_validate(document)
    except ValidationError:
        raise NugetDependencyGraphError("artifact_contract_invalid") from None
    validate_graph_source_binding(
        artifact,
        expected_commit_sha=expected_commit_sha,
        expected_source_sha256=expected_source_sha256,
        error=NugetDependencyGraphError,
    )
    return artifact, digest


def _canonical_target_ids(values: list[str]) -> bool:
    return (
        values == sorted(values, key=lambda value: int(value[1:]) if isinstance(value, str) and re.fullmatch(r"t(?:0|[1-9]\d?)", value) else -1)
        and len(values) == len(set(values))
        and all(isinstance(value, str) and re.fullmatch(r"t(?:0|[1-9]\d?)", value) for value in values)
    )


def _canonical_target_universe(values: list[str]) -> bool:
    return _canonical_target_ids(values) and values == [f"t{index}" for index in range(len(values))]
