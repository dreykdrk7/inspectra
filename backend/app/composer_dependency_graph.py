"""Closed admission contract for a Composer graph produced by trusted CI."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from app.sbom import extract_exact_version, is_valid_composer_name
from app.dependency_graph_envelope import decode_graph_envelope, validate_graph_source_binding


COMPOSER_DEPENDENCY_GRAPH_CONTRACT_VERSION = "2026-09-10.3"
COMPOSER_DEPENDENCY_GRAPH_MAX_BYTES = 1_048_576
COMPOSER_DEPENDENCY_GRAPH_MAX_NODES = 2_000
COMPOSER_DEPENDENCY_GRAPH_MAX_EDGES = 4_000


class ComposerDependencyGraphError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class ComposerDependencyGraphNode(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    id: str = Field(min_length=1, max_length=32, pattern=r"^[A-Za-z0-9_-]+$")
    name: str = Field(min_length=3, max_length=200)
    version: str = Field(min_length=5, max_length=160)

    @model_validator(mode="after")
    def exact_identity(self):
        if not is_valid_composer_name(self.name) or extract_exact_version(self.version, "composer") is None:
            raise ValueError("invalid Composer identity")
        return self


class ComposerDependencyGraphEdge(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    source: str = Field(min_length=1, max_length=32, pattern=r"^[A-Za-z0-9_-]+$")
    target: str = Field(min_length=1, max_length=32, pattern=r"^[A-Za-z0-9_-]+$")


class ComposerDependencyGraphArtifact(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    contract_version: Literal["2026-09-10.3"]
    ecosystem: Literal["composer"]
    producer: Literal["composer-locked-graph"]
    source_commit_sha: str = Field(pattern=r"^[a-f0-9]{40,64}$")
    source_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    complete: bool
    truncation_reason: Literal["node_limit", "edge_limit", "producer_limit"] | None
    nodes: list[ComposerDependencyGraphNode] = Field(max_length=COMPOSER_DEPENDENCY_GRAPH_MAX_NODES)
    roots: list[str] = Field(max_length=COMPOSER_DEPENDENCY_GRAPH_MAX_NODES)
    edges: list[ComposerDependencyGraphEdge] = Field(max_length=COMPOSER_DEPENDENCY_GRAPH_MAX_EDGES)

    @model_validator(mode="after")
    def deterministic_closed_graph(self):
        if self.complete != (self.truncation_reason is None):
            raise ValueError("completion and truncation disagree")
        node_ids = [node.id for node in self.nodes]
        identities = [(node.name, node.version) for node in self.nodes]
        edge_pairs = [(edge.source, edge.target) for edge in self.edges]
        if len(set(node_ids)) != len(node_ids) or len(set(identities)) != len(identities):
            raise ValueError("duplicate graph node")
        if len(set(self.roots)) != len(self.roots) or len(set(edge_pairs)) != len(edge_pairs):
            raise ValueError("duplicate graph relation")
        known = set(node_ids)
        if not set(self.roots).issubset(known) or any(edge.source not in known or edge.target not in known for edge in self.edges):
            raise ValueError("unknown graph reference")
        if node_ids != sorted(node_ids) or self.roots != sorted(self.roots) or edge_pairs != sorted(edge_pairs):
            raise ValueError("graph is not canonically ordered")
        return self


def parse_composer_dependency_graph_artifact(
    payload: bytes, *, declared_sha256: str, expected_commit_sha: str, expected_source_sha256: str
) -> tuple[ComposerDependencyGraphArtifact, str]:
    document, digest = decode_graph_envelope(
        payload, declared_sha256=declared_sha256, max_bytes=COMPOSER_DEPENDENCY_GRAPH_MAX_BYTES,
        error=ComposerDependencyGraphError,
    )
    try:
        artifact = ComposerDependencyGraphArtifact.model_validate(document)
    except ValidationError:
        raise ComposerDependencyGraphError("artifact_contract_invalid") from None
    validate_graph_source_binding(
        artifact, expected_commit_sha=expected_commit_sha,
        expected_source_sha256=expected_source_sha256, error=ComposerDependencyGraphError,
    )
    return artifact, digest
