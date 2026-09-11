from __future__ import annotations

import hashlib
import json

import pytest

from app.cargo_dependency_graph import CargoDependencyGraphError, parse_cargo_dependency_graph_artifact
from app.component_inventory import add_component_inventory, attach_dependency_graph_projection


COMMIT = "d" * 40
SOURCE = "b" * 64


def _artifact(*, complete: bool = True, nodes=None, roots=None, edges=None) -> bytes:
    document = {
        "contract_version": "2026-09-10.2",
        "ecosystem": "cargo",
        "producer": "cargo-metadata-graph",
        "source_commit_sha": COMMIT,
        "source_sha256": SOURCE,
        "target_coverage": "all_locked_targets",
        "complete": complete,
        "truncation_reason": None if complete else "producer_limit",
        "targets": ["linux_x86_64", "windows_x86_64"],
        "nodes": nodes if nodes is not None else [
            {"id": "n1", "name": "serde", "version": "1.0.210", "features": ["derive", "std"], "targets": ["linux_x86_64", "windows_x86_64"]},
            {"id": "n2", "name": "itoa", "version": "1.0.11", "features": [], "targets": ["linux_x86_64", "windows_x86_64"]},
        ],
        "roots": roots if roots is not None else ["n1"],
        "edges": edges if edges is not None else [
            {"source": "n1", "target": "n2", "targets": ["linux_x86_64", "windows_x86_64"]},
        ],
    }
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode()


def _source_result() -> dict:
    return {
        "analyzer": "project_archive_basic",
        "summary": {"supported_manifests_found": 1, "lockfiles_detected": 1, "lockfiles_parsed": 1},
        "supported_manifests": [{"path": "service/Cargo.toml", "manifest_type": "cargo_toml", "status": "parsed"}],
        "lockfiles": [{"path": "service/Cargo.lock", "lockfile_type": "cargo_lock", "status": "parsed"}],
        "parsed_manifests": [{
            "path": "service/Cargo.toml",
            "manifest_type": "cargo_toml",
            "parsed": {"dependencies": {"dependencies": [
                {"name": "serde", "specifier": "1", "dependency_source_type": "registry"},
            ]}},
        }],
        "parsed_lockfiles": [{
            "path": "service/Cargo.lock",
            "lockfile_type": "cargo_lock",
            "lockfile_version": 4,
            "packages": [
                {"name": "serde", "version": "1.0.210", "source_type": "registry"},
                {"name": "itoa", "version": "1.0.11", "source_type": "registry"},
                {"name": "private", "version": "", "source_type": "unknown"},
            ],
            "truncated": False,
        }],
        "findings": [],
    }


def _parsed(payload: bytes):
    return parse_cargo_dependency_graph_artifact(
        payload,
        declared_sha256=hashlib.sha256(payload).hexdigest(),
        expected_commit_sha=COMMIT,
        expected_source_sha256=SOURCE,
    )[0]


def test_exact_graph_projects_scope_and_counts_without_raw_dimensions() -> None:
    payload = _artifact()
    result = add_component_inventory(
        "project_archive_basic",
        _source_result(),
        cargo_dependency_graph=_parsed(payload),
        cargo_dependency_graph_sha256=hashlib.sha256(payload).hexdigest(),
    )

    by_name = {item["name"]: item for item in result["component_inventory"]}
    assert by_name["serde"]["dependency_scope"] == "direct"
    assert by_name["serde"]["enabled_feature_count"] == 2
    assert by_name["serde"]["target_variant_count"] == 2
    assert by_name["itoa"]["dependency_scope"] == "transitive"
    assert by_name["itoa"]["relationship_status"] == "reported"
    receipt = result["cargo_dependency_graph_evidence"]
    assert receipt["state"] == "accepted"
    assert receipt["features_reported"] == 2
    assert receipt["targets_reported"] == 2
    coverage = next(item for item in result["component_coverage_matrix"] if item["id"] == "cargo-lock")
    assert coverage["transitive_coverage"] == "bounded_registry_graph"
    assert coverage["exclusion_reason"] == "none"
    serialized = json.dumps(result, sort_keys=True)
    for withheld in ('"edges"', '"roots"', '"features"', 'linux_x86_64', 'windows_x86_64'):
        assert withheld not in serialized


def test_truncated_cycle_and_divergence_are_explicit() -> None:
    cycle = _artifact(
        complete=False,
        edges=[
            {"source": "n1", "target": "n2", "targets": ["linux_x86_64"]},
            {"source": "n2", "target": "n1", "targets": ["linux_x86_64"]},
        ],
    )
    truncated = add_component_inventory(
        "project_archive_basic", _source_result(),
        cargo_dependency_graph=_parsed(cycle),
        cargo_dependency_graph_sha256=hashlib.sha256(cycle).hexdigest(),
    )
    assert truncated["cargo_dependency_graph_evidence"]["state"] == "truncated"
    assert truncated["cargo_dependency_graph_evidence"]["cycles_detected"] is True
    assert all(item["relationship_status"] == "truncated" for item in truncated["component_inventory"] if item["ecosystem"] == "cargo")

    foreign = _artifact(
        nodes=[{"id": "n1", "name": "foreign", "version": "9.9.9", "features": [], "targets": ["linux_x86_64"]}],
        roots=["n1"], edges=[],
    )
    divergent = add_component_inventory(
        "project_archive_basic", _source_result(),
        cargo_dependency_graph=_parsed(foreign),
        cargo_dependency_graph_sha256=hashlib.sha256(foreign).hexdigest(),
    )
    assert divergent["cargo_dependency_graph_evidence"]["state"] == "divergent"
    assert divergent["cargo_dependency_graph_evidence"]["reason"] == "identity_not_in_lockfile"
    assert "foreign" not in {item["name"] for item in divergent["component_inventory"]}


def test_graph_projection_preserves_existing_other_ecosystem_receipt() -> None:
    base = add_component_inventory("project_archive_basic", _source_result())
    base["dependency_graph_evidence"] = {
        "contract_version": "2026-09-10.1", "ecosystem": "go", "state": "accepted",
        "reason": "none", "artifact_sha256": "a" * 64, "source_commit_sha": "c" * 40,
        "source_binding_verified": True, "nodes_reported": 1, "edges_reported": 0,
        "components_matched": 1, "components_unmatched": 0, "cycles_detected": False,
        "truncation_reason": None,
    }
    payload = _artifact()
    projected = attach_dependency_graph_projection(
        "project_archive_basic", base,
        cargo_dependency_graph=_parsed(payload),
        cargo_dependency_graph_sha256=hashlib.sha256(payload).hexdigest(),
    )
    assert projected["dependency_graph_evidence"] == base["dependency_graph_evidence"]
    assert projected["cargo_dependency_graph_evidence"]["state"] == "accepted"


@pytest.mark.parametrize("mutation", ["digest", "commit", "source", "duplicate", "unicode_feature"])
def test_artifact_binding_and_closed_ascii_contract_fail(mutation: str) -> None:
    payload = _artifact()
    digest = hashlib.sha256(payload).hexdigest()
    commit, source = COMMIT, SOURCE
    if mutation == "digest":
        digest = "f" * 64
    elif mutation == "commit":
        commit = "e" * 40
    elif mutation == "source":
        source = "c" * 64
    elif mutation == "duplicate":
        payload = payload.replace(b'"ecosystem":"cargo"', b'"ecosystem":"cargo","ecosystem":"cargo"')
        digest = hashlib.sha256(payload).hexdigest()
    else:
        payload = payload.replace(b'"derive"', '"dérive"'.encode())
        digest = hashlib.sha256(payload).hexdigest()

    with pytest.raises(CargoDependencyGraphError):
        parse_cargo_dependency_graph_artifact(
            payload,
            declared_sha256=digest,
            expected_commit_sha=commit,
            expected_source_sha256=source,
        )
