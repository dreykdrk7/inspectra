"""Closed, source-bound admission contract for a Go graph produced by trusted CI.

Inspectra never invokes ``go``.  The caller supplies a bounded JSON artifact
produced in its own authorized CI environment.  This module validates the
envelope without logging package identities and returns a typed in-memory
representation; callers must persist only the derived inventory and receipt.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from app.sbom import extract_exact_version, is_valid_go_module_name
from app.dependency_graph_envelope import decode_graph_envelope, validate_graph_source_binding


GO_DEPENDENCY_GRAPH_CONTRACT_VERSION = "2026-09-10.1"
GO_DEPENDENCY_GRAPH_MAX_BYTES = 1_048_576
GO_DEPENDENCY_GRAPH_MAX_NODES = 2_000
GO_DEPENDENCY_GRAPH_MAX_EDGES = 4_000


class GoDependencyGraphError(ValueError):
    """Safe admission failure represented by one closed reason code."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class GoDependencyGraphNode(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    id: str = Field(min_length=1, max_length=32, pattern=r"^[A-Za-z0-9_-]+$")
    name: str = Field(min_length=3, max_length=300)
    version: str = Field(min_length=2, max_length=160)

    @model_validator(mode="after")
    def exact_go_identity(self):
        if not is_valid_go_module_name(self.name) or extract_exact_version(self.version, "go") is None:
            raise ValueError("invalid Go identity")
        return self


class GoDependencyGraphEdge(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    source: str = Field(min_length=1, max_length=32, pattern=r"^[A-Za-z0-9_-]+$")
    target: str = Field(min_length=1, max_length=32, pattern=r"^[A-Za-z0-9_-]+$")


class GoDependencyGraphArtifact(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    contract_version: Literal["2026-09-10.1"]
    ecosystem: Literal["go"]
    producer: Literal["go-mod-graph"]
    source_commit_sha: str = Field(pattern=r"^[a-f0-9]{40,64}$")
    source_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    complete: bool
    truncation_reason: Literal["node_limit", "edge_limit", "producer_limit"] | None
    nodes: list[GoDependencyGraphNode] = Field(max_length=GO_DEPENDENCY_GRAPH_MAX_NODES)
    roots: list[str] = Field(max_length=GO_DEPENDENCY_GRAPH_MAX_NODES)
    edges: list[GoDependencyGraphEdge] = Field(max_length=GO_DEPENDENCY_GRAPH_MAX_EDGES)

    @model_validator(mode="after")
    def deterministic_closed_graph(self):
        if self.complete != (self.truncation_reason is None):
            raise ValueError("completion and truncation reason disagree")
        node_ids = [node.id for node in self.nodes]
        identities = [(node.name, node.version) for node in self.nodes]
        edge_pairs = [(edge.source, edge.target) for edge in self.edges]
        if len(set(node_ids)) != len(node_ids) or len(set(identities)) != len(identities):
            raise ValueError("duplicate graph node")
        if len(set(self.roots)) != len(self.roots) or len(set(edge_pairs)) != len(edge_pairs):
            raise ValueError("duplicate graph relation")
        known = set(node_ids)
        if any(root not in known for root in self.roots):
            raise ValueError("unknown root")
        if any(edge.source not in known or edge.target not in known for edge in self.edges):
            raise ValueError("unknown edge endpoint")
        if node_ids != sorted(node_ids) or self.roots != sorted(self.roots) or edge_pairs != sorted(edge_pairs):
            raise ValueError("graph is not canonically ordered")
        return self


def parse_go_dependency_graph_artifact(
    payload: bytes,
    *,
    declared_sha256: str,
    expected_commit_sha: str,
    expected_source_sha256: str,
) -> tuple[GoDependencyGraphArtifact, str]:
    """Validate one artifact and its out-of-band binding without retaining it."""

    document, digest = decode_graph_envelope(
        payload, declared_sha256=declared_sha256, max_bytes=GO_DEPENDENCY_GRAPH_MAX_BYTES,
        error=GoDependencyGraphError,
    )
    try:
        artifact = GoDependencyGraphArtifact.model_validate(document)
    except ValidationError:
        raise GoDependencyGraphError("artifact_contract_invalid") from None
    validate_graph_source_binding(
        artifact, expected_commit_sha=expected_commit_sha,
        expected_source_sha256=expected_source_sha256, error=GoDependencyGraphError,
    )
    return artifact, digest
