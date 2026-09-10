"""Pure producer for binding already-sanitized CI graph observations."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any

from inspectra_cli.cargo_dependency_graph import _validate_document as validate_cargo
from inspectra_cli.composer_dependency_graph import _validate as validate_composer
from inspectra_cli.dependency_graph import _validate_document as validate_go
from inspectra_cli.gradle_dependency_graph import _validate as validate_gradle
from inspectra_cli.nuget_dependency_graph import _validate as validate_nuget, normalize_nuget_version
from inspectra_cli.dependency_graph_envelope import read_closed_graph_document
from inspectra_cli.git_snapshot import SnapshotError


_CONTRACTS = {
    "go": ("2026-09-10.1", "go-mod-graph"),
    "cargo": ("2026-09-10.2", "cargo-metadata-graph"),
    "composer": ("2026-09-10.3", "composer-locked-graph"),
    "gradle": ("2026-09-10.4", "gradle-dependency-graph"),
    "nuget": ("2026-09-10.5", "nuget-dependency-graph"),
}
_COMMON_KEYS = {"complete", "truncation_reason", "nodes", "roots", "edges"}


def produce_ci_graph(
    ecosystem: str, input_path: Path, output_path: Path, *, commit_sha: str, source_sha256: str
) -> dict[str, object]:
    """Canonicalize a closed observation without running tools or reading source."""

    if ecosystem not in _CONTRACTS or not re.fullmatch(r"[a-f0-9]{40,64}", commit_sha) or not re.fullmatch(r"[a-f0-9]{64}", source_sha256):
        raise SnapshotError("The graph producer binding or ecosystem is invalid.")
    _, observation = read_closed_graph_document(input_path, ecosystem_label=ecosystem.title(), max_bytes=1_048_576)
    expected = _COMMON_KEYS | ({"target_coverage", "targets"} if ecosystem in {"cargo", "nuget"} else {"scope_coverage"} if ecosystem == "gradle" else set())
    if set(observation) != expected:
        raise SnapshotError("The graph producer input contains unsupported metadata.")
    contract, producer = _CONTRACTS[ecosystem]
    nodes = sorted(observation["nodes"], key=lambda item: item.get("id", "") if isinstance(item, dict) else "") if isinstance(observation["nodes"], list) else observation["nodes"]
    roots = sorted(observation["roots"]) if isinstance(observation["roots"], list) and all(isinstance(item, str) for item in observation["roots"]) else observation["roots"]
    if ecosystem == "cargo" and isinstance(observation.get("targets"), list) and all(isinstance(item, str) for item in observation["targets"]):
        targets = sorted(observation["targets"])
        if isinstance(nodes, list):
            nodes = [{**item, "features": sorted(item.get("features", [])), "targets": sorted(item.get("targets", []))} if isinstance(item, dict) else item for item in nodes]
        edges = sorted(observation["edges"], key=lambda item: (item.get("source", ""), item.get("target", ""), tuple(sorted(item.get("targets", [])))) if isinstance(item, dict) else ("", "", ())) if isinstance(observation["edges"], list) else observation["edges"]
        if isinstance(edges, list):
            edges = [{**item, "targets": sorted(item.get("targets", []))} if isinstance(item, dict) else item for item in edges]
        document: dict[str, Any] = {"contract_version": contract, "ecosystem": ecosystem, "producer": producer, "source_commit_sha": commit_sha, "source_sha256": source_sha256, "target_coverage": observation["target_coverage"], "complete": observation["complete"], "truncation_reason": observation["truncation_reason"], "targets": targets, "nodes": nodes, "roots": roots, "edges": edges}
        validate_cargo(document, commit_sha, source_sha256)
    elif ecosystem == "gradle":
        coverage = sorted(observation["scope_coverage"]) if isinstance(observation.get("scope_coverage"), list) and all(isinstance(item, str) for item in observation["scope_coverage"]) else observation.get("scope_coverage")
        if isinstance(nodes, list):
            nodes = [{**item, "scopes": sorted(item.get("scopes", []))} if isinstance(item, dict) else item for item in nodes]
        edges = sorted(observation["edges"], key=lambda item: (item.get("source", ""), item.get("target", ""), tuple(sorted(item.get("scopes", [])))) if isinstance(item, dict) else ("", "", ())) if isinstance(observation["edges"], list) else observation["edges"]
        if isinstance(edges, list):
            edges = [{**item, "scopes": sorted(item.get("scopes", []))} if isinstance(item, dict) else item for item in edges]
        document = {"contract_version": contract, "ecosystem": "maven", "producer": producer, "source_commit_sha": commit_sha, "source_sha256": source_sha256, "scope_coverage": coverage, "complete": observation["complete"], "truncation_reason": observation["truncation_reason"], "nodes": nodes, "roots": roots, "edges": edges}
        validate_gradle(document, commit_sha, source_sha256)
    elif ecosystem == "nuget":
        target_key = lambda item: int(item[1:]) if isinstance(item, str) and re.fullmatch(r"t(?:0|[1-9]\d?)", item) else -1
        targets = sorted(observation["targets"], key=target_key) if isinstance(observation.get("targets"), list) and all(isinstance(item, str) for item in observation["targets"]) else observation.get("targets")
        if isinstance(nodes, list):
            nodes = [
                {
                    **item,
                    "version": normalize_nuget_version(item.get("version")) or item.get("version"),
                    "targets": sorted(item.get("targets", []), key=target_key),
                }
                if isinstance(item, dict) else item
                for item in nodes
            ]
        roots = sorted(
            observation["roots"],
            key=lambda item: (item.get("node", ""), tuple(sorted(item.get("targets", []), key=target_key))) if isinstance(item, dict) else ("", ()),
        ) if isinstance(observation["roots"], list) else observation["roots"]
        if isinstance(roots, list):
            roots = [{**item, "targets": sorted(item.get("targets", []), key=target_key)} if isinstance(item, dict) else item for item in roots]
        edges = sorted(
            observation["edges"],
            key=lambda item: (item.get("source", ""), item.get("target", ""), tuple(sorted(item.get("targets", []), key=target_key))) if isinstance(item, dict) else ("", "", ()),
        ) if isinstance(observation["edges"], list) else observation["edges"]
        if isinstance(edges, list):
            edges = [{**item, "targets": sorted(item.get("targets", []), key=target_key)} if isinstance(item, dict) else item for item in edges]
        document = {
            "contract_version": contract, "ecosystem": ecosystem, "producer": producer,
            "source_commit_sha": commit_sha, "source_sha256": source_sha256,
            "target_coverage": observation["target_coverage"], "complete": observation["complete"],
            "truncation_reason": observation["truncation_reason"], "targets": targets,
            "nodes": nodes, "roots": roots, "edges": edges,
        }
        validate_nuget(document, commit_sha, source_sha256)
    else:
        edges = sorted(observation["edges"], key=lambda item: (item.get("source", ""), item.get("target", "")) if isinstance(item, dict) else ("", "")) if isinstance(observation["edges"], list) else observation["edges"]
        document = {"contract_version": contract, "ecosystem": ecosystem, "producer": producer, "source_commit_sha": commit_sha, "source_sha256": source_sha256, "complete": observation["complete"], "truncation_reason": observation["truncation_reason"], "nodes": nodes, "roots": roots, "edges": edges}
        (validate_go if ecosystem == "go" else validate_composer)(document, commit_sha, source_sha256)
    payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    _write_new_private_file(output_path, payload)
    return {"contract_version": contract, "ecosystem": ecosystem, "artifact_sha256": hashlib.sha256(payload).hexdigest(), "bytes": len(payload), "nodes": len(nodes), "edges": len(edges), "output_created": True}


def _write_new_private_file(path: Path, payload: bytes) -> None:
    raw = path.expanduser()
    candidate = (raw if raw.is_absolute() else Path.cwd() / raw)
    created = False
    try:
        candidate = candidate.parent.resolve(strict=True) / candidate.name
        descriptor = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        created = True
        try:
            metadata = os.fstat(descriptor)
            if metadata.st_nlink != 1:
                raise OSError("unsafe output link count")
            view = memoryview(payload)
            while view:
                view = view[os.write(descriptor, view):]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as exc:
        if created:
            candidate.unlink(missing_ok=True)
        raise SnapshotError("The graph producer output could not be created safely.") from exc
