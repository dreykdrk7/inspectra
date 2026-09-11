from __future__ import annotations

import hashlib
import json

import pytest

from app.component_inventory import add_component_inventory
from app.go_dependency_graph import GoDependencyGraphError, parse_go_dependency_graph_artifact


COMMIT = "c" * 40
SOURCE = "a" * 64


def _artifact(*, complete: bool = True, nodes=None, roots=None, edges=None) -> bytes:
    document = {
        "contract_version": "2026-09-10.1",
        "ecosystem": "go",
        "producer": "go-mod-graph",
        "source_commit_sha": COMMIT,
        "source_sha256": SOURCE,
        "complete": complete,
        "truncation_reason": None if complete else "producer_limit",
        "nodes": nodes if nodes is not None else [
            {"id": "n1", "name": "golang.org/x/text", "version": "v0.19.0"},
            {"id": "n2", "name": "golang.org/x/sys", "version": "v0.26.0"},
            {"id": "n3", "name": "golang.org/x/net", "version": "v0.30.0"},
        ],
        "roots": roots if roots is not None else ["n1"],
        "edges": edges if edges is not None else [
            {"source": "n1", "target": "n2"},
            {"source": "n2", "target": "n3"},
        ],
    }
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode()


def _source_result() -> dict:
    return {
        "analyzer": "project_archive_basic",
        "summary": {"supported_manifests_found": 1, "lockfiles_detected": 1, "lockfiles_parsed": 1},
        "supported_manifests": [{"path": "services/api/go.mod", "manifest_type": "go_mod", "status": "parsed"}],
        "lockfiles": [{"path": "services/api/go.sum", "lockfile_type": "go_sum", "status": "parsed"}],
        "parsed_manifests": [{
            "path": "services/api/go.mod",
            "manifest_type": "go_mod",
            "parsed": {"dependencies": {
                "require": [{"name": "golang.org/x/text", "specifier": "v0.19.0", "dependency_source_type": "registry"}],
                "indirect": [{"name": "golang.org/x/sys", "specifier": "v0.26.0", "dependency_source_type": "registry"}],
            }},
        }],
        "parsed_lockfiles": [{
            "path": "services/api/go.sum",
            "lockfile_type": "go_sum",
            "lockfile_version": "go-sum-v1",
            "packages": [
                {"name": "golang.org/x/text", "version": "v0.19.0", "source_type": "unverified_registry"},
                {"name": "golang.org/x/sys", "version": "v0.26.0", "source_type": "unverified_registry"},
                {"name": "golang.org/x/net", "version": "v0.30.0", "source_type": "unverified_registry"},
            ],
            "truncated": False,
        }],
        "findings": [],
    }


def _parsed(payload: bytes):
    return parse_go_dependency_graph_artifact(
        payload,
        declared_sha256=hashlib.sha256(payload).hexdigest(),
        expected_commit_sha=COMMIT,
        expected_source_sha256=SOURCE,
    )[0]


def test_exact_graph_enriches_go_inventory_without_persisting_raw_edges() -> None:
    payload = _artifact()
    result = add_component_inventory(
        "project_archive_basic",
        _source_result(),
        go_dependency_graph=_parsed(payload),
        go_dependency_graph_sha256=hashlib.sha256(payload).hexdigest(),
    )

    by_name = {item["name"]: item for item in result["component_inventory"]}
    assert set(by_name) == {"golang.org/x/text", "golang.org/x/sys", "golang.org/x/net"}
    assert by_name["golang.org/x/text"]["dependency_scope"] == "direct"
    assert by_name["golang.org/x/sys"]["dependency_scope"] == "transitive"
    assert by_name["golang.org/x/net"]["relationship_status"] == "reported"
    assert result["component_inventory_summary"]["transitive_registry_components"] == 1
    assert result["dependency_graph_evidence"] == {
        "contract_version": "2026-09-10.1",
        "ecosystem": "go",
        "state": "accepted",
        "reason": "none",
        "artifact_sha256": hashlib.sha256(payload).hexdigest(),
        "source_commit_sha": COMMIT,
        "source_binding_verified": True,
        "nodes_reported": 3,
        "edges_reported": 2,
        "components_matched": 3,
        "components_unmatched": 0,
        "cycles_detected": False,
        "truncation_reason": None,
    }
    serialized = json.dumps(result, sort_keys=True)
    assert '"edges"' not in serialized
    assert '"roots"' not in serialized


def test_truncated_cycle_is_explicit_and_scope_remains_inconclusive() -> None:
    payload = _artifact(
        complete=False,
        nodes=[
            {"id": "n1", "name": "golang.org/x/text", "version": "v0.19.0"},
            {"id": "n2", "name": "golang.org/x/sys", "version": "v0.26.0"},
        ],
        edges=[{"source": "n1", "target": "n2"}, {"source": "n2", "target": "n1"}],
    )
    result = add_component_inventory(
        "project_archive_basic",
        _source_result(),
        go_dependency_graph=_parsed(payload),
        go_dependency_graph_sha256=hashlib.sha256(payload).hexdigest(),
    )

    assert result["dependency_graph_evidence"]["state"] == "truncated"
    assert result["dependency_graph_evidence"]["cycles_detected"] is True
    assert all(item["relationship_status"] == "truncated" for item in result["component_inventory"] if item["ecosystem"] == "go")
    go_coverage = next(item for item in result["component_coverage_matrix"] if item["id"] == "go-mod-sum")
    assert go_coverage["transitive_coverage"] == "bounded_registry_graph"
    assert go_coverage["exclusion_reason"] == "graph_truncated"


def test_unmatched_or_replaced_graph_is_retained_only_as_divergent_receipt() -> None:
    payload = _artifact(nodes=[{"id": "n1", "name": "private.example.test/module", "version": "v1.0.0"}], roots=["n1"], edges=[])
    result = add_component_inventory(
        "project_archive_basic",
        _source_result(),
        go_dependency_graph=_parsed(payload),
        go_dependency_graph_sha256=hashlib.sha256(payload).hexdigest(),
    )

    assert result["dependency_graph_evidence"]["state"] == "divergent"
    assert result["dependency_graph_evidence"]["reason"] == "identity_not_in_lockfile"
    assert "private.example.test/module" not in json.dumps(result)
    assert all(item["name"] != "private.example.test/module" for item in result["component_inventory"])


def test_deep_graph_cycle_check_is_iterative_and_bounded() -> None:
    nodes = [
        {"id": f"n{index:04d}", "name": f"example.org/mod{index}", "version": "v1.0.0"}
        for index in range(1_200)
    ]
    edges = [
        {"source": f"n{index:04d}", "target": f"n{index + 1:04d}"}
        for index in range(1_199)
    ]
    edges.append({"source": "n1199", "target": "n0000"})
    payload = _artifact(complete=False, nodes=nodes, roots=["n0000"], edges=edges)
    artifact = _parsed(payload)

    from app.component_inventory import _go_graph_has_cycle

    assert _go_graph_has_cycle(artifact) is True


@pytest.mark.parametrize("mutation", ["digest", "commit", "source", "duplicate"])
def test_artifact_binding_and_ambiguous_json_fail_closed(mutation: str) -> None:
    payload = _artifact()
    digest = hashlib.sha256(payload).hexdigest()
    commit, source = COMMIT, SOURCE
    if mutation == "digest":
        digest = "f" * 64
    elif mutation == "commit":
        commit = "d" * 40
    elif mutation == "source":
        source = "b" * 64
    elif mutation == "duplicate":
        payload = payload.replace(b'"ecosystem":"go"', b'"ecosystem":"go","ecosystem":"go"')
        digest = hashlib.sha256(payload).hexdigest()

    with pytest.raises(GoDependencyGraphError):
        parse_go_dependency_graph_artifact(
            payload,
            declared_sha256=digest,
            expected_commit_sha=commit,
            expected_source_sha256=source,
        )
