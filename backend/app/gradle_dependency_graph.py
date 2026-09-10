"""Closed Maven-coordinate graph emitted by authorized Gradle CI."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from app.dependency_graph_envelope import decode_graph_envelope, validate_graph_source_binding
from app.sbom import extract_exact_version, is_valid_maven_name


GRADLE_DEPENDENCY_GRAPH_CONTRACT_VERSION = "2026-09-10.4"
GRADLE_DEPENDENCY_GRAPH_MAX_BYTES = 1_048_576
GRADLE_DEPENDENCY_GRAPH_MAX_NODES = 2_000
GRADLE_DEPENDENCY_GRAPH_MAX_EDGES = 4_000
GRADLE_DEPENDENCY_GRAPH_SCOPES = frozenset({"compile", "runtime", "test"})


class GradleDependencyGraphError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class GradleDependencyGraphNode(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    id: str = Field(min_length=1, max_length=32, pattern=r"^[A-Za-z0-9_-]+$")
    name: str = Field(min_length=3, max_length=256)
    version: str = Field(min_length=5, max_length=160)
    scopes: list[Literal["compile", "runtime", "test"]] = Field(min_length=1, max_length=3)

    @model_validator(mode="after")
    def exact_identity_and_scopes(self):
        if not is_valid_maven_name(self.name) or extract_exact_version(self.version, "maven") is None:
            raise ValueError("invalid Maven identity")
        if self.scopes != sorted(self.scopes) or len(set(self.scopes)) != len(self.scopes):
            raise ValueError("invalid Gradle scopes")
        return self


class GradleDependencyGraphEdge(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    source: str = Field(min_length=1, max_length=32, pattern=r"^[A-Za-z0-9_-]+$")
    target: str = Field(min_length=1, max_length=32, pattern=r"^[A-Za-z0-9_-]+$")
    scopes: list[Literal["compile", "runtime", "test"]] = Field(min_length=1, max_length=3)

    @model_validator(mode="after")
    def canonical_scopes(self):
        if self.scopes != sorted(self.scopes) or len(set(self.scopes)) != len(self.scopes):
            raise ValueError("invalid Gradle edge scopes")
        return self


class GradleDependencyGraphArtifact(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    contract_version: Literal["2026-09-10.4"]
    ecosystem: Literal["maven"]
    producer: Literal["gradle-dependency-graph"]
    source_commit_sha: str = Field(pattern=r"^[a-f0-9]{40,64}$")
    source_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    scope_coverage: list[Literal["compile", "runtime", "test"]] = Field(min_length=1, max_length=3)
    complete: bool
    truncation_reason: Literal["node_limit", "edge_limit", "producer_limit"] | None
    nodes: list[GradleDependencyGraphNode] = Field(min_length=1, max_length=GRADLE_DEPENDENCY_GRAPH_MAX_NODES)
    roots: list[str] = Field(min_length=1, max_length=GRADLE_DEPENDENCY_GRAPH_MAX_NODES)
    edges: list[GradleDependencyGraphEdge] = Field(max_length=GRADLE_DEPENDENCY_GRAPH_MAX_EDGES)

    @model_validator(mode="after")
    def deterministic_closed_graph(self):
        if self.complete != (self.truncation_reason is None):
            raise ValueError("completion and truncation disagree")
        if self.scope_coverage != sorted(self.scope_coverage) or len(set(self.scope_coverage)) != len(self.scope_coverage):
            raise ValueError("invalid scope coverage")
        covered = set(self.scope_coverage)
        node_ids = [node.id for node in self.nodes]
        identities = [(node.name, node.version) for node in self.nodes]
        edge_keys = [(edge.source, edge.target, tuple(edge.scopes)) for edge in self.edges]
        if len(set(node_ids)) != len(node_ids) or len(set(identities)) != len(identities):
            raise ValueError("duplicate graph node")
        if len(set(self.roots)) != len(self.roots) or len(set(edge_keys)) != len(edge_keys):
            raise ValueError("duplicate graph relation")
        known = set(node_ids)
        if not set(self.roots).issubset(known):
            raise ValueError("unknown root")
        if any(not set(node.scopes).issubset(covered) for node in self.nodes):
            raise ValueError("node scope outside coverage")
        if any(edge.source not in known or edge.target not in known or not set(edge.scopes).issubset(covered) for edge in self.edges):
            raise ValueError("unknown edge endpoint or scope")
        if node_ids != sorted(node_ids) or self.roots != sorted(self.roots) or edge_keys != sorted(edge_keys):
            raise ValueError("graph is not canonically ordered")
        return self


def parse_gradle_dependency_graph_artifact(
    payload: bytes, *, declared_sha256: str, expected_commit_sha: str, expected_source_sha256: str
) -> tuple[GradleDependencyGraphArtifact, str]:
    document, digest = decode_graph_envelope(
        payload, declared_sha256=declared_sha256, max_bytes=GRADLE_DEPENDENCY_GRAPH_MAX_BYTES,
        error=GradleDependencyGraphError,
    )
    try:
        artifact = GradleDependencyGraphArtifact.model_validate(document)
    except ValidationError:
        raise GradleDependencyGraphError("artifact_contract_invalid") from None
    validate_graph_source_binding(
        artifact, expected_commit_sha=expected_commit_sha,
        expected_source_sha256=expected_source_sha256, error=GradleDependencyGraphError,
    )
    return artifact, digest
