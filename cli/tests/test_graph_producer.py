from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from inspectra_cli.cargo_dependency_graph import validate_cargo_dependency_graph
from inspectra_cli.composer_dependency_graph import validate_composer_dependency_graph
from inspectra_cli.dependency_graph import validate_go_dependency_graph
from inspectra_cli.gradle_dependency_graph import validate_gradle_dependency_graph
from inspectra_cli.nuget_dependency_graph import validate_nuget_dependency_graph
from inspectra_cli.git_snapshot import SnapshotError
from inspectra_cli.graph_producer import produce_ci_graph
from inspectra_cli.commands import EXIT_OK, main


COMMIT = "a" * 40
SOURCE = "b" * 64


@pytest.mark.parametrize("ecosystem", ["go", "cargo", "composer", "gradle", "nuget"])
def test_producer_creates_canonical_private_artifact_for_each_closed_contract(tmp_path: Path, ecosystem: str) -> None:
    identities = {
        "go": [("example.test/root", "v1.2.3"), ("example.test/other", "v2.3.4")],
        "cargo": [("root", "1.2.3"), ("other", "2.3.4")],
        "composer": [("vendor/root", "1.2.3"), ("vendor/other", "2.3.4")],
        "gradle": [("org.example:root", "1.2.Final"), ("org.example:other", "2.3-sp1")],
        "nuget": [("newtonsoft.json", "013.0.03.0-BETA.010+private-build"), ("system.text.json", "8")],
    }[ecosystem]
    nodes = [{"id": node_id, "name": name, "version": version} for node_id, (name, version) in zip(("n2", "n1"), identities)]
    edges = [{"source": "n1", "target": "n2"}]
    observation = {"complete": True, "truncation_reason": None, "nodes": nodes, "roots": ["n2", "n1"], "edges": edges}
    if ecosystem == "cargo":
        observation.update({"target_coverage": "all_locked_targets", "targets": ["windows", "linux"]})
        for node in nodes:
            node.update({"features": ["std", "derive"], "targets": ["windows", "linux"]})
        edges[0]["targets"] = ["windows", "linux"]
    if ecosystem == "gradle":
        observation["scope_coverage"] = ["runtime", "compile"]
        for node in nodes:
            node["scopes"] = ["runtime", "compile"]
        edges[0]["scopes"] = ["runtime"]
    if ecosystem == "nuget":
        observation.update({"target_coverage": "all_locked_targets", "targets": ["t1", "t0"]})
        for node in nodes:
            node["targets"] = ["t1", "t0"]
        observation["roots"] = [
            {"node": "n2", "targets": ["t1", "t0"]},
            {"node": "n1", "targets": ["t1", "t0"]},
        ]
        edges[0]["targets"] = ["t1", "t0"]
    source, output = tmp_path / f"{ecosystem}.input.json", tmp_path / f"{ecosystem}.graph.json"
    source.write_text(json.dumps(observation), encoding="utf-8")
    receipt = produce_ci_graph(ecosystem, source, output, commit_sha=COMMIT, source_sha256=SOURCE)
    repeated = tmp_path / f"{ecosystem}.repeated.graph.json"
    repeated_receipt = produce_ci_graph(ecosystem, source, repeated, commit_sha=COMMIT, source_sha256=SOURCE)
    assert receipt["output_created"] is True
    assert repeated.read_bytes() == output.read_bytes()
    assert repeated_receipt["artifact_sha256"] == receipt["artifact_sha256"]
    assert output.stat().st_mode & 0o777 == 0o600
    validator = {"go": validate_go_dependency_graph, "cargo": validate_cargo_dependency_graph, "composer": validate_composer_dependency_graph, "gradle": validate_gradle_dependency_graph, "nuget": validate_nuget_dependency_graph}[ecosystem]
    validated = validator(output, expected_commit_sha=COMMIT, expected_source_sha256=SOURCE)
    assert validated.sha256 == receipt["artifact_sha256"]
    roots = json.loads(output.read_text())["roots"]
    assert roots == ([{"node": "n1", "targets": ["t0", "t1"]}, {"node": "n2", "targets": ["t0", "t1"]}] if ecosystem == "nuget" else ["n1", "n2"])
    if ecosystem == "nuget":
        rendered = output.read_text(encoding="utf-8")
        assert "13.0.3-beta.10" in rendered and '"8.0.0"' in rendered
        assert "private-build" not in rendered


def test_producer_rejects_metadata_links_and_preserves_existing_output(tmp_path: Path) -> None:
    observation = tmp_path / "input.json"
    observation.write_text(json.dumps({"complete": True, "truncation_reason": None, "nodes": [], "roots": [], "edges": [], "repository": "private"}), encoding="utf-8")
    output = tmp_path / "output.json"
    output.write_text("keep", encoding="utf-8")
    with pytest.raises(SnapshotError, match="unsupported metadata"):
        produce_ci_graph("go", observation, output, commit_sha=COMMIT, source_sha256=SOURCE)
    assert output.read_text() == "keep"

    clean = tmp_path / "clean.json"
    clean.write_text(json.dumps({"complete": True, "truncation_reason": None, "nodes": [], "roots": [], "edges": []}), encoding="utf-8")
    symlink = tmp_path / "linked.json"
    symlink.symlink_to(clean.name)
    with pytest.raises(SnapshotError, match="bounded regular file"):
        produce_ci_graph("go", symlink, tmp_path / "unused.json", commit_sha=COMMIT, source_sha256=SOURCE)
    hardlink = tmp_path / "hard.json"
    os.link(clean, hardlink)
    with pytest.raises(SnapshotError, match="bounded regular file"):
        produce_ci_graph("go", hardlink, tmp_path / "unused-hard.json", commit_sha=COMMIT, source_sha256=SOURCE)


def test_producer_does_not_overwrite_an_existing_artifact(tmp_path: Path) -> None:
    observation = tmp_path / "input.json"
    observation.write_text(json.dumps({"complete": True, "truncation_reason": None, "nodes": [], "roots": [], "edges": []}), encoding="utf-8")
    output = tmp_path / "output.json"
    output.write_text("keep", encoding="utf-8")
    with pytest.raises(SnapshotError, match="could not be created safely"):
        produce_ci_graph("go", observation, output, commit_sha=COMMIT, source_sha256=SOURCE)
    assert output.read_text() == "keep"


def test_graph_command_emits_a_source_free_receipt(tmp_path: Path, capsys) -> None:
    observation, output = tmp_path / "input.json", tmp_path / "output.json"
    observation.write_text(json.dumps({"complete": True, "truncation_reason": None, "nodes": [], "roots": [], "edges": []}), encoding="utf-8")
    assert main(["graph", "--ecosystem", "go", "--input", str(observation), "--output", str(output), "--commit", COMMIT, "--source-sha256", SOURCE, "--json"]) == EXIT_OK
    receipt = json.loads(capsys.readouterr().out)
    assert receipt["ecosystem"] == "go" and receipt["output_created"] is True
    serialized = json.dumps(receipt)
    assert str(tmp_path) not in serialized and "example.test" not in serialized
