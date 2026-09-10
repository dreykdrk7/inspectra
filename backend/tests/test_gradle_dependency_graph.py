from __future__ import annotations

import hashlib
import json

import pytest

from app.gradle_dependency_graph import GradleDependencyGraphError, parse_gradle_dependency_graph_artifact
from app.component_inventory import add_component_inventory


COMMIT, SOURCE = "a" * 40, "b" * 64


def payload() -> bytes:
    return json.dumps({
        "contract_version": "2026-09-10.4", "ecosystem": "maven", "producer": "gradle-dependency-graph",
        "source_commit_sha": COMMIT, "source_sha256": SOURCE,
        "scope_coverage": ["compile", "runtime"], "complete": True, "truncation_reason": None,
        "nodes": [
            {"id": "n1", "name": "org.example:root", "version": "1.2.3", "scopes": ["compile", "runtime"]},
            {"id": "n2", "name": "org.example:child", "version": "2.3.4", "scopes": ["runtime"]},
        ], "roots": ["n1"], "edges": [{"source": "n1", "target": "n2", "scopes": ["runtime"]}],
    }, sort_keys=True, separators=(",", ":")).encode()


def test_gradle_graph_accepts_only_exact_canonical_scoped_coordinates() -> None:
    raw = payload()
    graph, digest = parse_gradle_dependency_graph_artifact(raw, declared_sha256=hashlib.sha256(raw).hexdigest(), expected_commit_sha=COMMIT, expected_source_sha256=SOURCE)
    assert digest == hashlib.sha256(raw).hexdigest()
    assert graph.nodes[1].scopes == ["runtime"]


def test_gradle_graph_accepts_reviewed_maven_qualifier_but_not_unknown_qualifier() -> None:
    document = json.loads(payload())
    document["nodes"][0]["version"] = "1.2.3.Final"
    raw = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    graph, _ = parse_gradle_dependency_graph_artifact(raw, declared_sha256=hashlib.sha256(raw).hexdigest(), expected_commit_sha=COMMIT, expected_source_sha256=SOURCE)
    assert graph.nodes[0].version == "1.2.3.Final"
    document["nodes"][0]["version"] = "1.2.3-vendor"
    raw = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    with pytest.raises(GradleDependencyGraphError):
        parse_gradle_dependency_graph_artifact(raw, declared_sha256=hashlib.sha256(raw).hexdigest(), expected_commit_sha=COMMIT, expected_source_sha256=SOURCE)


def source_result() -> dict:
    return {
        "analyzer": "project_archive_basic",
        "summary": {"supported_manifests_found": 1, "lockfiles_parsed": 1},
        "supported_manifests": [{"path": "service/build.gradle.kts", "manifest_type": "gradle_build", "status": "parsed"}],
        "parsed_manifests": [{"path": "service/build.gradle.kts", "manifest_type": "gradle_build", "parsed": {"project": {"build_dsl_not_evaluated": True}, "dependencies": {}}}],
        "lockfiles": [{"path": "service/gradle.lockfile", "lockfile_type": "gradle_lock", "status": "parsed"}],
        "parsed_lockfiles": [{"path": "service/gradle.lockfile", "lockfile_type": "gradle_lock", "packages": [
            {"name": "org.example:root", "version": "1.2.3", "source_type": "unverified_registry"},
            {"name": "org.example:child", "version": "2.3.4", "source_type": "unverified_registry"},
        ]}], "findings": [],
    }


def test_gradle_graph_projects_ci_reported_scope_without_public_registry_claim() -> None:
    raw = payload()
    artifact, digest = parse_gradle_dependency_graph_artifact(raw, declared_sha256=hashlib.sha256(raw).hexdigest(), expected_commit_sha=COMMIT, expected_source_sha256=SOURCE)
    result = add_component_inventory("project_archive_basic", source_result(), gradle_dependency_graph=artifact, gradle_dependency_graph_sha256=digest)
    by_name = {item["name"]: item for item in result["component_inventory"]}
    assert by_name["org.example:root"]["dependency_scope"] == "direct"
    assert by_name["org.example:child"]["dependency_scope"] == "transitive"
    assert by_name["org.example:root"]["build_scope_count"] == 2
    assert result["gradle_dependency_graph_evidence"]["relationship_origin"] == "ci_reported"
    coverage = next(item for item in result["component_coverage_matrix"] if item["id"] == "gradle-lock")
    assert coverage["direct_coverage"] == "exact_ci_graph"
    assert coverage["transitive_coverage"] == "bounded_ci_graph"
    serialized = json.dumps(result)
    assert '"edges"' not in serialized and '"roots"' not in serialized
    assert "maven.org" not in serialized


def test_gradle_graph_foreign_or_unreachable_nodes_diverge_without_projection() -> None:
    for mutation in ("foreign", "unreachable"):
        document = json.loads(payload())
        if mutation == "foreign":
            document["nodes"][1]["name"] = "org.private:unknown"
        else:
            document["edges"] = []
        raw = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
        artifact, digest = parse_gradle_dependency_graph_artifact(raw, declared_sha256=hashlib.sha256(raw).hexdigest(), expected_commit_sha=COMMIT, expected_source_sha256=SOURCE)
        result = add_component_inventory("project_archive_basic", source_result(), gradle_dependency_graph=artifact, gradle_dependency_graph_sha256=digest)
        assert result["gradle_dependency_graph_evidence"]["state"] == "divergent"
        assert all(item["relationship_status"] == "not_reported" for item in result["component_inventory"])


@pytest.mark.parametrize("mutation", ["digest", "commit", "source", "metadata", "scope", "ecosystem", "duplicate"])
def test_gradle_graph_fails_closed_for_binding_cross_contract_and_free_metadata(mutation: str) -> None:
    document = json.loads(payload())
    digest, commit, source = None, COMMIT, SOURCE
    if mutation == "commit": commit = "c" * 40
    elif mutation == "source": source = "d" * 64
    elif mutation == "metadata": document["repository"] = "https://private.example"
    elif mutation == "scope": document["nodes"][0]["scopes"] = ["privateConfiguration"]
    elif mutation == "ecosystem": document["ecosystem"] = "cargo"
    raw = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    if mutation == "duplicate": raw = raw.replace(b'"ecosystem":"maven"', b'"ecosystem":"maven","ecosystem":"maven"')
    digest = "e" * 64 if mutation == "digest" else hashlib.sha256(raw).hexdigest()
    with pytest.raises(GradleDependencyGraphError):
        parse_gradle_dependency_graph_artifact(raw, declared_sha256=digest, expected_commit_sha=commit, expected_source_sha256=source)
