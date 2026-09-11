"""Closed admission contract for a Cargo graph produced by trusted CI.

Inspectra never invokes Cargo. Raw nodes, feature labels, target identifiers and
edges are request-local evidence; callers persist only corroborated component
fields and a bounded aggregate receipt.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from app.sbom import extract_exact_version, is_valid_cargo_name
from app.dependency_graph_envelope import decode_graph_envelope, validate_graph_source_binding


CARGO_DEPENDENCY_GRAPH_CONTRACT_VERSION = "2026-09-10.2"
CARGO_DEPENDENCY_GRAPH_MAX_BYTES = 1_048_576
CARGO_DEPENDENCY_GRAPH_MAX_NODES = 2_000
CARGO_DEPENDENCY_GRAPH_MAX_EDGES = 4_000
CARGO_DEPENDENCY_GRAPH_MAX_TARGETS = 32
CARGO_DEPENDENCY_GRAPH_MAX_FEATURES_PER_NODE = 64


class CargoDependencyGraphError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class CargoDependencyGraphNode(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    id: str = Field(min_length=1, max_length=32, pattern=r"^[A-Za-z0-9_-]+$")
    name: str = Field(min_length=1, max_length=128)
    version: str = Field(min_length=5, max_length=160)
    features: list[str] = Field(max_length=CARGO_DEPENDENCY_GRAPH_MAX_FEATURES_PER_NODE)
    targets: list[str] = Field(min_length=1, max_length=CARGO_DEPENDENCY_GRAPH_MAX_TARGETS)

    @model_validator(mode="after")
    def exact_identity_and_bounded_dimensions(self):
        if not is_valid_cargo_name(self.name) or extract_exact_version(self.version, "cargo") is None:
            raise ValueError("invalid Cargo identity")
        if (
            self.features != sorted(self.features)
            or len(set(self.features)) != len(self.features)
            or any(not _valid_feature(value) for value in self.features)
            or self.targets != sorted(self.targets)
            or len(set(self.targets)) != len(self.targets)
            or any(not _valid_opaque_id(value) for value in self.targets)
        ):
            raise ValueError("invalid Cargo node dimensions")
        return self


class CargoDependencyGraphEdge(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    source: str = Field(min_length=1, max_length=32, pattern=r"^[A-Za-z0-9_-]+$")
    target: str = Field(min_length=1, max_length=32, pattern=r"^[A-Za-z0-9_-]+$")
    targets: list[str] = Field(min_length=1, max_length=CARGO_DEPENDENCY_GRAPH_MAX_TARGETS)

    @model_validator(mode="after")
    def canonical_targets(self):
        if (
            self.targets != sorted(self.targets)
            or len(set(self.targets)) != len(self.targets)
            or any(not _valid_opaque_id(value) for value in self.targets)
        ):
            raise ValueError("invalid Cargo edge targets")
        return self


class CargoDependencyGraphArtifact(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    contract_version: Literal["2026-09-10.2"]
    ecosystem: Literal["cargo"]
    producer: Literal["cargo-metadata-graph"]
    source_commit_sha: str = Field(pattern=r"^[a-f0-9]{40,64}$")
    source_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    target_coverage: Literal["all_locked_targets"]
    complete: bool
    truncation_reason: Literal["node_limit", "edge_limit", "feature_limit", "target_limit", "producer_limit"] | None
    targets: list[str] = Field(min_length=1, max_length=CARGO_DEPENDENCY_GRAPH_MAX_TARGETS)
    nodes: list[CargoDependencyGraphNode] = Field(max_length=CARGO_DEPENDENCY_GRAPH_MAX_NODES)
    roots: list[str] = Field(max_length=CARGO_DEPENDENCY_GRAPH_MAX_NODES)
    edges: list[CargoDependencyGraphEdge] = Field(max_length=CARGO_DEPENDENCY_GRAPH_MAX_EDGES)

    @model_validator(mode="after")
    def deterministic_closed_graph(self):
        if self.complete != (self.truncation_reason is None):
            raise ValueError("completion and truncation reason disagree")
        if (
            self.targets != sorted(self.targets)
            or len(set(self.targets)) != len(self.targets)
            or any(not _valid_opaque_id(value) for value in self.targets)
        ):
            raise ValueError("invalid Cargo targets")
        target_set = set(self.targets)
        node_ids = [node.id for node in self.nodes]
        identities = [(node.name, node.version) for node in self.nodes]
        edge_keys = [(edge.source, edge.target, tuple(edge.targets)) for edge in self.edges]
        if len(set(node_ids)) != len(node_ids) or len(set(identities)) != len(identities):
            raise ValueError("duplicate graph node")
        if len(set(self.roots)) != len(self.roots) or len(set(edge_keys)) != len(edge_keys):
            raise ValueError("duplicate graph relation")
        known = set(node_ids)
        if any(root not in known for root in self.roots):
            raise ValueError("unknown root")
        if any(not set(node.targets).issubset(target_set) for node in self.nodes):
            raise ValueError("unknown node target")
        if any(
            edge.source not in known
            or edge.target not in known
            or not set(edge.targets).issubset(target_set)
            for edge in self.edges
        ):
            raise ValueError("unknown edge endpoint or target")
        if node_ids != sorted(node_ids) or self.roots != sorted(self.roots) or edge_keys != sorted(edge_keys):
            raise ValueError("graph is not canonically ordered")
        return self


def parse_cargo_dependency_graph_artifact(
    payload: bytes,
    *,
    declared_sha256: str,
    expected_commit_sha: str,
    expected_source_sha256: str,
) -> tuple[CargoDependencyGraphArtifact, str]:
    document, digest = decode_graph_envelope(
        payload, declared_sha256=declared_sha256, max_bytes=CARGO_DEPENDENCY_GRAPH_MAX_BYTES,
        error=CargoDependencyGraphError,
    )
    try:
        artifact = CargoDependencyGraphArtifact.model_validate(document)
    except ValidationError:
        raise CargoDependencyGraphError("artifact_contract_invalid") from None
    validate_graph_source_binding(
        artifact, expected_commit_sha=expected_commit_sha,
        expected_source_sha256=expected_source_sha256, error=CargoDependencyGraphError,
    )
    return artifact, digest


def _valid_feature(value: object) -> bool:
    if not isinstance(value, str) or not 1 <= len(value) <= 64:
        return False
    return value.isascii() and value[0].isalnum() and all(character.isalnum() or character in "_-" for character in value)


def _valid_opaque_id(value: object) -> bool:
    if not isinstance(value, str) or not 1 <= len(value) <= 32:
        return False
    return all(character.isascii() and (character.isalnum() or character in "_-") for character in value)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result
