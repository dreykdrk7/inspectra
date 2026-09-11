from __future__ import annotations

import hashlib
import json

import pytest

from app.component_inventory import add_component_inventory
from app.nuget_dependency_graph import NugetDependencyGraphError, parse_nuget_dependency_graph_artifact


COMMIT, SOURCE = "a" * 40, "b" * 64


def payload() -> bytes:
    return json.dumps({
        "contract_version": "2026-09-10.5", "ecosystem": "nuget", "producer": "nuget-dependency-graph",
        "source_commit_sha": COMMIT, "source_sha256": SOURCE, "target_coverage": "all_locked_targets",
        "complete": True, "truncation_reason": None, "targets": ["t0", "t1"],
        "nodes": [
            {"id": "n1", "name": "newtonsoft.json", "version": "13.0.3", "targets": ["t0", "t1"]},
            {"id": "n2", "name": "system.text.encodings.web", "version": "8.0.0", "targets": ["t0", "t1"]},
            {"id": "n3", "name": "microsoft.extensions.primitives", "version": "8.0.0", "targets": ["t1"]},
        ],
        "roots": [{"node": "n1", "targets": ["t0", "t1"]}],
        "edges": [
            {"source": "n1", "target": "n2", "targets": ["t0", "t1"]},
            {"source": "n2", "target": "n3", "targets": ["t1"]},
        ],
    }, sort_keys=True, separators=(",", ":")).encode()


def source_result() -> dict:
    return {
        "analyzer": "project_archive_basic", "summary": {"supported_manifests_found": 1, "lockfiles_parsed": 1},
        "parsed_manifests": [{"path": "service/App.csproj", "manifest_type": "dotnet_project", "parsed": {"project": {"msbuild_not_evaluated": True}, "dependencies": {}}}],
        "parsed_lockfiles": [{"path": "service/packages.lock.json", "lockfile_type": "nuget_packages_lock", "target_count": 2, "packages": [
            {"name": "newtonsoft.json", "version": "13.0.3", "source_type": "unverified_registry", "dependency_scope": "direct"},
            {"name": "system.text.encodings.web", "version": "8.0.0", "source_type": "unverified_registry", "dependency_scope": "transitive"},
            {"name": "microsoft.extensions.primitives", "version": "8.0.0", "source_type": "unverified_registry", "dependency_scope": "transitive"},
        ]}], "findings": [],
    }


def parse(document: bytes | None = None):
    raw = document or payload()
    return parse_nuget_dependency_graph_artifact(
        raw, declared_sha256=hashlib.sha256(raw).hexdigest(),
        expected_commit_sha=COMMIT, expected_source_sha256=SOURCE,
    )


def test_nuget_graph_projects_target_aware_scope_without_retaining_target_ids_or_registry_claim() -> None:
    artifact, digest = parse()
    result = add_component_inventory(
        "project_archive_basic", source_result(),
        nuget_dependency_graph=artifact, nuget_dependency_graph_sha256=digest,
    )
    by_name = {item["name"]: item for item in result["component_inventory"]}
    assert by_name["newtonsoft.json"]["dependency_scope"] == "direct"
    assert by_name["system.text.encodings.web"]["dependency_scope"] == "transitive"
    assert by_name["microsoft.extensions.primitives"]["target_variant_count"] == 1
    receipt = result["nuget_dependency_graph_evidence"]
    assert receipt["state"] == "accepted"
    assert receipt["targets_reported"] == 2
    assert receipt["relationship_origin"] == "ci_reported"
    coverage = next(item for item in result["component_coverage_matrix"] if item["id"] == "nuget-packages-lock")
    assert coverage["direct_coverage"] == "exact_ci_graph"
    assert coverage["transitive_coverage"] == "bounded_ci_graph"
    serialized = json.dumps(result)
    assert '"edges"' not in serialized and '"roots"' not in serialized and '"targets"' not in serialized
    assert "nuget.org" not in serialized


@pytest.mark.parametrize("mutation", ["target_count", "identity", "unreachable"])
def test_nuget_graph_divergence_is_inconclusive_and_never_projects_relationships(mutation: str) -> None:
    source = source_result()
    document = json.loads(payload())
    if mutation == "target_count":
        source["parsed_lockfiles"][0]["target_count"] = 1
    elif mutation == "identity":
        document["nodes"][2]["name"] = "private.package"
    else:
        document["edges"] = document["edges"][:1]
    raw = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    artifact, digest = parse(raw)
    result = add_component_inventory(
        "project_archive_basic", source,
        nuget_dependency_graph=artifact, nuget_dependency_graph_sha256=digest,
    )
    assert result["nuget_dependency_graph_evidence"]["state"] == "divergent"
    assert all(item["target_variant_count"] is None if "target_variant_count" in item else True for item in result["component_inventory"])


@pytest.mark.parametrize("mutation", ["digest", "commit", "source", "metadata", "target", "edge_target", "ecosystem", "version", "duplicate"])
def test_nuget_graph_fails_closed_for_binding_free_metadata_and_invalid_targets(mutation: str) -> None:
    document = json.loads(payload())
    commit, source = COMMIT, SOURCE
    if mutation == "commit": commit = "c" * 40
    elif mutation == "source": source = "d" * 64
    elif mutation == "metadata": document["repository"] = "https://private.example/token"
    elif mutation == "target": document["targets"][0] = "net8.0/private"
    elif mutation == "edge_target": document["edges"][0]["targets"] = ["t2"]
    elif mutation == "ecosystem": document["ecosystem"] = "maven"
    elif mutation == "version": document["nodes"][0]["version"] = "013.0.03.0+private-build"
    raw = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    if mutation == "duplicate":
        raw = raw.replace(b'"ecosystem":"nuget"', b'"ecosystem":"nuget","ecosystem":"nuget"')
    digest = "e" * 64 if mutation == "digest" else hashlib.sha256(raw).hexdigest()
    with pytest.raises(NugetDependencyGraphError):
        parse_nuget_dependency_graph_artifact(
            raw, declared_sha256=digest,
            expected_commit_sha=commit, expected_source_sha256=source,
        )
