from __future__ import annotations

import hashlib
import json

import pytest

from app.component_inventory import add_component_inventory
from app.composer_dependency_graph import ComposerDependencyGraphError, parse_composer_dependency_graph_artifact

COMMIT = "e" * 40
SOURCE = "c" * 64


def _source(custom: bool = False) -> dict:
    return {
        "analyzer": "project_archive_basic",
        "summary": {"supported_manifests_found": 1, "lockfiles_parsed": 1},
        "supported_manifests": [{"path": "service/composer.json", "manifest_type": "composer_json", "status": "parsed"}],
        "lockfiles": [{"path": "service/composer.lock", "lockfile_type": "composer_lock", "status": "parsed"}],
        "parsed_manifests": [{"path": "service/composer.json", "manifest_type": "composer_json", "parsed": {
            "project": {"custom_repositories_declared": custom},
            "dependencies": {"require": [{"name": "symfony/http-foundation", "specifier": "^7.1" if not custom else "", "dependency_source_type": "registry" if not custom else "unknown"}]},
        }}],
        "parsed_lockfiles": [{"path": "service/composer.lock", "lockfile_type": "composer_lock", "packages": [
            {"name": "symfony/http-foundation", "version": "7.1.3", "dependency_group": "require", "source_type": "unverified_registry"},
            {"name": "psr/log", "version": "3.0.2", "dependency_group": "require", "source_type": "unverified_registry"},
        ]}], "findings": [],
    }


def _payload() -> bytes:
    return json.dumps({
        "contract_version": "2026-09-10.3", "ecosystem": "composer", "producer": "composer-locked-graph",
        "source_commit_sha": COMMIT, "source_sha256": SOURCE, "complete": True, "truncation_reason": None,
        "nodes": [
            {"id": "n1", "name": "symfony/http-foundation", "version": "7.1.3"},
            {"id": "n2", "name": "psr/log", "version": "3.0.2"},
        ], "roots": ["n1"], "edges": [{"source": "n1", "target": "n2"}],
    }, sort_keys=True, separators=(",", ":")).encode()


def _artifact(payload: bytes):
    return parse_composer_dependency_graph_artifact(
        payload, declared_sha256=hashlib.sha256(payload).hexdigest(),
        expected_commit_sha=COMMIT, expected_source_sha256=SOURCE,
    )[0]


def test_composer_graph_projects_relationships_but_not_public_provenance() -> None:
    payload = _payload()
    result = add_component_inventory(
        "project_archive_basic", _source(), composer_dependency_graph=_artifact(payload),
        composer_dependency_graph_sha256=hashlib.sha256(payload).hexdigest(),
    )
    by_name = {item["name"]: item for item in result["component_inventory"]}
    assert by_name["symfony/http-foundation"]["dependency_scope"] == "direct"
    assert by_name["psr/log"]["dependency_scope"] == "transitive"
    assert all(item["relationship_status"] == "reported" for item in by_name.values())
    assert result["composer_dependency_graph_evidence"]["state"] == "accepted"
    coverage = next(item for item in result["component_coverage_matrix"] if item["id"] == "composer-lock")
    assert coverage["transitive_coverage"] == "bounded_registry_graph"
    serialized = json.dumps(result)
    assert '"edges"' not in serialized and '"roots"' not in serialized
    assert "packagist.org" not in serialized


def test_custom_repository_and_foreign_identity_diverge_without_projection() -> None:
    payload = _payload()
    custom = add_component_inventory(
        "project_archive_basic", _source(True), composer_dependency_graph=_artifact(payload),
        composer_dependency_graph_sha256=hashlib.sha256(payload).hexdigest(),
    )
    assert custom["composer_dependency_graph_evidence"]["reason"] == "custom_repository_declared"
    assert all(item["relationship_status"] == "not_reported" for item in custom["component_inventory"])


@pytest.mark.parametrize("mutation", ["digest", "commit", "source", "duplicate"])
def test_composer_graph_binding_and_json_fail_closed(mutation: str) -> None:
    payload = _payload()
    digest, commit, source = hashlib.sha256(payload).hexdigest(), COMMIT, SOURCE
    if mutation == "digest": digest = "f" * 64
    elif mutation == "commit": commit = "a" * 40
    elif mutation == "source": source = "b" * 64
    else:
        payload = payload.replace(b'"ecosystem":"composer"', b'"ecosystem":"composer","ecosystem":"composer"')
        digest = hashlib.sha256(payload).hexdigest()
    with pytest.raises(ComposerDependencyGraphError):
        parse_composer_dependency_graph_artifact(
            payload, declared_sha256=digest, expected_commit_sha=commit, expected_source_sha256=source
        )
