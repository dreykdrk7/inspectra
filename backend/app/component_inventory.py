"""Safe, deterministic component inventory derived from passive project manifests.

The inventory records declarations Inspectra actually parsed. It does not
resolve ranges, install packages, or contact a registry. Lockfile data is only
accepted after a versioned same-root pairing policy proves the association:
`package-lock.json` and supported Cargo locks have narrow public-registry
provenance contracts, while pnpm v9, Yarn Classic v1, Poetry 2.1 and Go sum
data are local-only because their registry origin cannot be proved safely
without an operator attestation.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from app.cargo_dependency_graph import CargoDependencyGraphArtifact
from app.composer_dependency_graph import ComposerDependencyGraphArtifact
from app.finding_normalization import normalize_project_relative_path
from app.go_dependency_graph import GoDependencyGraphArtifact
from app.gradle_dependency_graph import GradleDependencyGraphArtifact
from app.nuget_dependency_graph import NugetDependencyGraphArtifact
from app.sbom import (
    build_package_url,
    canonicalize_python_name,
    ecosystem_for_manifest,
    extract_exact_version,
    is_valid_go_module_name,
    is_valid_cargo_name,
    is_valid_composer_name,
    is_valid_maven_name,
    is_valid_nuget_name,
    is_valid_npm_name,
    is_valid_pypi_name,
)


COMPONENT_INVENTORY_CONTRACT_VERSION = "2026-09-10.1"
COMPONENT_COVERAGE_MATRIX_VERSION = "2026-09-10.1"
COMPATIBLE_AUDIT_TYPES = frozenset({"project_archive_basic"})
REGISTRY_SOURCE_TYPE = "registry"


def add_component_inventory(
    audit_type: str,
    result: dict[str, Any],
    *,
    go_dependency_graph: GoDependencyGraphArtifact | None = None,
    go_dependency_graph_sha256: str | None = None,
    cargo_dependency_graph: CargoDependencyGraphArtifact | None = None,
    cargo_dependency_graph_sha256: str | None = None,
    composer_dependency_graph: ComposerDependencyGraphArtifact | None = None,
    composer_dependency_graph_sha256: str | None = None,
    gradle_dependency_graph: GradleDependencyGraphArtifact | None = None,
    gradle_dependency_graph_sha256: str | None = None,
    nuget_dependency_graph: NugetDependencyGraphArtifact | None = None,
    nuget_dependency_graph_sha256: str | None = None,
) -> dict[str, Any]:
    """Attach the inventory only to project results supported by this contract."""

    if audit_type not in COMPATIBLE_AUDIT_TYPES:
        return result
    if (
        result.get("analyzer") == "sbom_import"
        and result.get("component_inventory_contract_version") in {
            "2026-09-07.1",
            "2026-09-08.1",
            COMPONENT_INVENTORY_CONTRACT_VERSION,
        }
        and isinstance(result.get("component_inventory"), list)
        and isinstance(result.get("component_inventory_summary"), dict)
    ):
        # The SBOM boundary constructs and validates this minimal projection
        # directly; rebuilding from absent source manifests would erase it.
        return {**result, "component_coverage_matrix": []}
    inventory, summary, graph_receipt, cargo_graph_receipt, composer_graph_receipt, gradle_graph_receipt, nuget_graph_receipt = _build_component_inventory(
        result,
        go_dependency_graph,
        go_dependency_graph_sha256,
        cargo_dependency_graph,
        cargo_dependency_graph_sha256,
        composer_dependency_graph,
        composer_dependency_graph_sha256,
        gradle_dependency_graph,
        gradle_dependency_graph_sha256,
        nuget_dependency_graph,
        nuget_dependency_graph_sha256,
    )
    enriched = dict(result)
    enriched["component_inventory_contract_version"] = COMPONENT_INVENTORY_CONTRACT_VERSION
    enriched["component_inventory"] = inventory
    enriched["component_inventory_summary"] = summary
    if graph_receipt is not None:
        enriched["dependency_graph_evidence"] = graph_receipt
    if cargo_graph_receipt is not None:
        enriched["cargo_dependency_graph_evidence"] = cargo_graph_receipt
    if composer_graph_receipt is not None:
        enriched["composer_dependency_graph_evidence"] = composer_graph_receipt
    if gradle_graph_receipt is not None:
        enriched["gradle_dependency_graph_evidence"] = gradle_graph_receipt
    if nuget_graph_receipt is not None:
        enriched["nuget_dependency_graph_evidence"] = nuget_graph_receipt
    enriched["component_coverage_matrix"] = build_component_coverage_matrix(enriched, inventory)
    return enriched


def attach_dependency_graph_projection(
    audit_type: str,
    result: dict[str, Any],
    *,
    go_dependency_graph: GoDependencyGraphArtifact | None = None,
    go_dependency_graph_sha256: str | None = None,
    cargo_dependency_graph: CargoDependencyGraphArtifact | None = None,
    cargo_dependency_graph_sha256: str | None = None,
    composer_dependency_graph: ComposerDependencyGraphArtifact | None = None,
    composer_dependency_graph_sha256: str | None = None,
    gradle_dependency_graph: GradleDependencyGraphArtifact | None = None,
    gradle_dependency_graph_sha256: str | None = None,
    nuget_dependency_graph: NugetDependencyGraphArtifact | None = None,
    nuget_dependency_graph_sha256: str | None = None,
) -> dict[str, Any]:
    """Attach one validated graph without erasing another ecosystem's projection."""

    if audit_type not in COMPATIBLE_AUDIT_TYPES:
        return result
    if not isinstance(result.get("component_inventory"), list) or not isinstance(
        result.get("component_inventory_summary"), dict
    ):
        return add_component_inventory(
            audit_type,
            result,
            go_dependency_graph=go_dependency_graph,
            go_dependency_graph_sha256=go_dependency_graph_sha256,
            cargo_dependency_graph=cargo_dependency_graph,
            cargo_dependency_graph_sha256=cargo_dependency_graph_sha256,
            composer_dependency_graph=composer_dependency_graph,
            composer_dependency_graph_sha256=composer_dependency_graph_sha256,
            gradle_dependency_graph=gradle_dependency_graph,
            gradle_dependency_graph_sha256=gradle_dependency_graph_sha256,
            nuget_dependency_graph=nuget_dependency_graph,
            nuget_dependency_graph_sha256=nuget_dependency_graph_sha256,
        )

    enriched = dict(result)
    components = [dict(component) for component in result["component_inventory"] if isinstance(component, dict)]
    if go_dependency_graph is not None:
        receipt, _added = _apply_go_dependency_graph(
            components, result, go_dependency_graph, go_dependency_graph_sha256
        )
        if receipt is not None:
            enriched["dependency_graph_evidence"] = receipt
    if cargo_dependency_graph is not None:
        receipt = _apply_cargo_dependency_graph(
            components, result, cargo_dependency_graph, cargo_dependency_graph_sha256
        )
        if receipt is not None:
            enriched["cargo_dependency_graph_evidence"] = receipt
    if composer_dependency_graph is not None:
        receipt = _apply_composer_dependency_graph(
            components, result, composer_dependency_graph, composer_dependency_graph_sha256
        )
        if receipt is not None:
            enriched["composer_dependency_graph_evidence"] = receipt
    if gradle_dependency_graph is not None:
        receipt = _apply_gradle_dependency_graph(
            components, result, gradle_dependency_graph, gradle_dependency_graph_sha256
        )
        if receipt is not None:
            enriched["gradle_dependency_graph_evidence"] = receipt
    if nuget_dependency_graph is not None:
        receipt = _apply_nuget_dependency_graph(
            components, result, nuget_dependency_graph, nuget_dependency_graph_sha256
        )
        if receipt is not None:
            enriched["nuget_dependency_graph_evidence"] = receipt

    _add_exact_package_urls(components)
    components.sort(
        key=lambda component: (
            _safe_text(component.get("manifest_path")),
            _safe_text(component.get("dependency_group")),
            _safe_text(component.get("ecosystem")),
            _safe_text(component.get("name")),
        )
    )
    summary = dict(result["component_inventory_summary"])
    summary.update(
        {
            "total_components": len(components),
            "exact_registry_components": sum(item.get("version_status") == "exact_declared" for item in components),
            "transitive_registry_components": sum(
                item.get("dependency_scope") == "transitive" and item.get("source_type") == REGISTRY_SOURCE_TYPE
                for item in components
            ),
            "relationship_reported_components": sum(item.get("relationship_status") == "reported" for item in components),
            "relationship_not_reported_components": sum(item.get("relationship_status") == "not_reported" for item in components),
            "relationship_truncated_components": sum(item.get("relationship_status") == "truncated" for item in components),
            "optional_registry_components": sum(
                item.get("dependency_scope") == "optional" and item.get("source_type") == REGISTRY_SOURCE_TYPE
                for item in components
            ),
            "matched_lockfile_components": sum(item.get("lockfile_match_status") == "matched" for item in components),
            "unmatched_lockfile_components": sum(item.get("lockfile_match_status") == "not_matched" for item in components),
            "ambiguous_lockfile_components": sum(item.get("lockfile_match_status") == "ambiguous" for item in components),
            "declared_range_components": sum(item.get("version_status") == "declared_range" for item in components),
            "not_correlatable_components": sum(item.get("version_status") == "not_correlatable" for item in components),
            "lockfile_graph_truncated": _npm_lockfile_graph_is_truncated(result)
            or _go_graph_state(enriched) == "truncated"
            or _cargo_graph_state(enriched) == "truncated"
            or _composer_graph_state(enriched) == "truncated"
            or _gradle_graph_state(enriched) == "truncated"
            or _nuget_graph_state(enriched) == "truncated",
        }
    )
    enriched["component_inventory"] = components
    enriched["component_inventory_summary"] = summary
    enriched["component_coverage_matrix"] = build_component_coverage_matrix(enriched, components)
    return enriched


def build_component_inventory(result: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Create a conservative inventory from the runner's already-redacted parse."""

    inventory, summary, _receipt, _cargo_receipt, _composer_receipt, _gradle_receipt, _nuget_receipt = _build_component_inventory(
        result, None, None, None, None, None, None, None, None, None, None
    )
    return inventory, summary


def _build_component_inventory(
    result: dict[str, Any],
    go_dependency_graph: GoDependencyGraphArtifact | None,
    go_dependency_graph_sha256: str | None,
    cargo_dependency_graph: CargoDependencyGraphArtifact | None,
    cargo_dependency_graph_sha256: str | None,
    composer_dependency_graph: ComposerDependencyGraphArtifact | None,
    composer_dependency_graph_sha256: str | None,
    gradle_dependency_graph: GradleDependencyGraphArtifact | None,
    gradle_dependency_graph_sha256: str | None,
    nuget_dependency_graph: NugetDependencyGraphArtifact | None,
    nuget_dependency_graph_sha256: str | None,
) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any] | None, dict[str, Any] | None, dict[str, Any] | None, dict[str, Any] | None, dict[str, Any] | None]:
    """Build inventory and optionally apply one trusted, source-bound CI graph."""

    components: list[dict[str, Any]] = []
    seen: set[tuple[str | None, str, str, str, str]] = set()
    parsed_manifest_count = 0
    workspace_manifest_paths: set[str] = set()

    for raw_manifest in _as_list(result.get("parsed_manifests")):
        manifest = _as_dict(raw_manifest)
        manifest_type = _safe_text(manifest.get("manifest_type"))
        ecosystem = ecosystem_for_manifest(manifest_type)
        path, path_status = _safe_manifest_path(manifest.get("path"))
        parsed = _as_dict(manifest.get("parsed"))
        if (
            manifest_type == "package_json"
            and path is not None
            and path_status == "reported"
            and _as_dict(parsed.get("project")).get("workspace_declared") is True
        ):
            workspace_manifest_paths.add(path)
        dependencies = _as_dict(parsed.get("dependencies"))
        parsed_manifest_count += 1

        for group, raw_dependencies in dependencies.items():
            if not isinstance(group, str) or not isinstance(raw_dependencies, list):
                continue
            for raw_dependency in raw_dependencies:
                component = _component_from_dependency(
                    ecosystem=ecosystem,
                    manifest_type=manifest_type,
                    manifest_path=path,
                    manifest_path_status=path_status,
                    dependency_group=group,
                    dependency=_as_dict(raw_dependency),
                )
                if component is None:
                    continue
                dedupe_key = (
                    component["manifest_path"],
                    component["dependency_group"],
                    component["ecosystem"],
                    component["name"],
                    component["source_type"],
                )
                if dedupe_key in seen:
                    continue
                seen.add(dedupe_key)
                components.append(component)

    parsed_lockfiles, skipped_lockfiles, skipped_lockfile_reasons = _lockfile_coverage(result)
    resolved_components, unverified_lockfile_components = _apply_lockfile_resolutions(
        components,
        result,
        workspace_manifest_paths,
    )
    transitive_components, lockfile_graph_truncated = _add_npm_transitive_lockfile_components(
        components,
        result,
        workspace_manifest_paths,
    )
    cargo_transitive_components = _add_cargo_transitive_lockfile_components(components, result)
    composer_transitive_components = _add_composer_transitive_lockfile_components(components, result)
    maven_transitive_components = _add_gradle_lockfile_components(components, result)
    nuget_transitive_components, nuget_unverified_components = _add_nuget_lockfile_components(components, result)
    graph_receipt, go_graph_transitive_components = _apply_go_dependency_graph(
        components,
        result,
        go_dependency_graph,
        go_dependency_graph_sha256,
    )
    cargo_graph_receipt = _apply_cargo_dependency_graph(
        components,
        result,
        cargo_dependency_graph,
        cargo_dependency_graph_sha256,
    )
    composer_graph_receipt = _apply_composer_dependency_graph(
        components, result, composer_dependency_graph, composer_dependency_graph_sha256
    )
    gradle_graph_receipt = _apply_gradle_dependency_graph(
        components, result, gradle_dependency_graph, gradle_dependency_graph_sha256
    )
    nuget_graph_receipt = _apply_nuget_dependency_graph(
        components, result, nuget_dependency_graph, nuget_dependency_graph_sha256
    )
    _add_exact_package_urls(components)
    components.sort(
        key=lambda component: (
            component["manifest_path"] or "",
            component["dependency_group"],
            component["ecosystem"],
            component["name"],
        )
    )
    runner_summary = _as_dict(result.get("summary"))
    supported_manifest_count = _safe_non_negative_int(runner_summary.get("supported_manifests_found"))
    if not supported_manifest_count:
        supported_manifest_count = parsed_manifest_count
    summary = {
        "total_components": len(components),
        "exact_registry_components": sum(component["version_status"] == "exact_declared" for component in components),
        "resolved_registry_components": resolved_components,
        "unverified_lockfile_components": unverified_lockfile_components + nuget_unverified_components,
        "transitive_registry_components": transitive_components + cargo_transitive_components + composer_transitive_components + maven_transitive_components + nuget_transitive_components + go_graph_transitive_components,
        "relationship_reported_components": sum(component.get("relationship_status") == "reported" for component in components),
        "relationship_not_reported_components": sum(component.get("relationship_status") == "not_reported" for component in components),
        "relationship_truncated_components": sum(component.get("relationship_status") == "truncated" for component in components),
        "optional_registry_components": sum(
            component.get("dependency_scope") == "optional" and component.get("source_type") == REGISTRY_SOURCE_TYPE
            for component in components
        ),
        "matched_lockfile_components": sum(component["lockfile_match_status"] == "matched" for component in components),
        "unmatched_lockfile_components": sum(component["lockfile_match_status"] == "not_matched" for component in components),
        "ambiguous_lockfile_components": sum(component["lockfile_match_status"] == "ambiguous" for component in components),
        "declared_range_components": sum(component["version_status"] == "declared_range" for component in components),
        "not_correlatable_components": sum(component["version_status"] == "not_correlatable" for component in components),
        "parsed_manifest_count": parsed_manifest_count,
        "supported_manifest_count": supported_manifest_count,
        "skipped_manifest_count": max(supported_manifest_count - parsed_manifest_count, 0),
        "result_truncated": bool(runner_summary.get("truncated")),
        "parsed_lockfile_count": parsed_lockfiles,
        "skipped_lockfile_count": skipped_lockfiles,
        "skipped_lockfile_reasons": skipped_lockfile_reasons,
        "lockfile_graph_truncated": lockfile_graph_truncated
        or any(receipt and receipt["state"] == "truncated" for receipt in (graph_receipt, cargo_graph_receipt, composer_graph_receipt, gradle_graph_receipt, nuget_graph_receipt)),
        "resolution": "declared_and_lockfile" if parsed_lockfiles else "declared_only",
    }
    return components, summary, graph_receipt, cargo_graph_receipt, composer_graph_receipt, gradle_graph_receipt, nuget_graph_receipt


def build_component_coverage_matrix(
    result: dict[str, Any],
    components: list[dict[str, Any]] | None = None,
) -> list[dict[str, str]]:
    """Describe current dependency coverage without exposing archive paths.

    This is a small, versioned capability view rather than a second parser. It
    only reduces already persisted manifest/lockfile records to fixed labels,
    so a detected filename, its path, a registry URL, or an error body cannot
    escape through the product response or an export.
    """

    captured_components = components if isinstance(components, list) else []
    npm_manifest = _manifest_observation(result, "package_json")
    requirements_manifest = _manifest_observation(result, "requirements_txt")
    pyproject_manifest = _manifest_observation(result, "pyproject_toml")
    pipfile_manifest = _manifest_observation(result, "pipfile")
    npm_lockfile = _lockfile_observation(result, "package-lock.json")
    pnpm_lockfile = _lockfile_observation(result, "pnpm-lock.yaml")
    yarn_lockfile = _lockfile_observation(result, "yarn.lock")
    poetry_lockfile = _lockfile_observation(result, "poetry.lock")
    pipfile_lockfile = _lockfile_observation(result, "Pipfile.lock")
    go_manifest = _manifest_observation(result, "go_mod")
    go_sum = _lockfile_observation(result, "go.sum")
    cargo_manifest = _manifest_observation(result, "cargo_toml")
    cargo_lock = _lockfile_observation(result, "Cargo.lock")
    composer_manifest = _manifest_observation(result, "composer_json")
    composer_lock = _lockfile_observation(result, "composer.lock")
    gradle_manifest = _manifest_observation(result, "gradle_build")
    gradle_lock = _lockfile_observation(result, "gradle.lockfile")
    dotnet_manifest = _manifest_observation(result, "dotnet_project")
    nuget_lock = _lockfile_observation(result, "packages.lock.json")

    npm_reason = _npm_lockfile_coverage_reason(result, npm_lockfile, captured_components)
    matrix = [
        _coverage_entry(
            identifier="npm-package-lock",
            ecosystem="npm",
            manager="npm",
            manifest="package.json",
            lockfile="package-lock.json",
            parser_version="package-lock-json-v2-v3",
            direct_coverage="exact_same_root_when_matched",
            transitive_coverage=(
                "bounded_registry_graph"
                if _npm_lockfile_has_bounded_graph(result)
                else "not_available"
            ),
            manifest_status=npm_manifest,
            lockfile_status=npm_lockfile,
            exclusion_reason=npm_reason,
        ),
        _coverage_entry(
            identifier="npm-pnpm-lock",
            ecosystem="npm",
            manager="pnpm",
            manifest="package.json",
            lockfile="pnpm-lock.yaml",
            parser_version="pnpm-lock-yaml-v9",
            direct_coverage="exact_same_root_local_only",
            transitive_coverage="not_available",
            manifest_status=npm_manifest,
            lockfile_status=pnpm_lockfile,
            exclusion_reason=_pnpm_lockfile_coverage_reason(pnpm_lockfile, captured_components),
        ),
        _coverage_entry(
            identifier="npm-yarn-lock",
            ecosystem="npm",
            manager="yarn",
            manifest="package.json",
            lockfile="yarn.lock",
            parser_version="yarn-classic-lock-v1",
            direct_coverage="exact_same_root_local_only",
            transitive_coverage="not_available",
            manifest_status=npm_manifest,
            lockfile_status=yarn_lockfile,
            exclusion_reason=_yarn_classic_lockfile_coverage_reason(yarn_lockfile, captured_components),
        ),
        _coverage_entry(
            identifier="pypi-requirements",
            ecosystem="pypi",
            manager="pip",
            manifest="requirements.txt",
            lockfile=None,
            parser_version="requirements-lines-v2-hash-summary",
            direct_coverage="declared_manifest_only",
            transitive_coverage="not_available",
            manifest_status=requirements_manifest,
            lockfile_status="not_applicable",
            exclusion_reason=_manifest_only_reason(requirements_manifest),
        ),
        _coverage_entry(
            identifier="pypi-pyproject",
            ecosystem="pypi",
            manager="python-packaging",
            manifest="pyproject.toml",
            lockfile=None,
            parser_version="pyproject-toml-v1",
            direct_coverage="declared_manifest_only",
            transitive_coverage="not_available",
            manifest_status=pyproject_manifest,
            lockfile_status="not_applicable",
            exclusion_reason=_manifest_only_reason(pyproject_manifest),
        ),
        _coverage_entry(
            identifier="pypi-poetry-lock",
            ecosystem="pypi",
            manager="poetry",
            manifest="pyproject.toml",
            lockfile="poetry.lock",
            parser_version="poetry-lock-toml-v2.1",
            direct_coverage="exact_same_root_local_only",
            transitive_coverage="not_available",
            manifest_status=pyproject_manifest,
            lockfile_status=poetry_lockfile,
            exclusion_reason=_poetry_lockfile_coverage_reason(poetry_lockfile, captured_components),
        ),
        _coverage_entry(
            identifier="pypi-pipfile-lock",
            ecosystem="pypi",
            manager="pipenv",
            manifest="Pipfile",
            lockfile="Pipfile.lock",
            parser_version="pipfile-lock-json-v6",
            direct_coverage="exact_same_root_local_only",
            transitive_coverage="not_available",
            manifest_status=pipfile_manifest,
            lockfile_status=pipfile_lockfile,
            exclusion_reason=_pipfile_lockfile_coverage_reason(pipfile_lockfile, captured_components),
        ),
        _coverage_entry(
            identifier="go-mod-sum",
            ecosystem="go",
            manager="go-modules",
            manifest="go.mod",
            lockfile="go.sum",
            parser_version="go-mod-sum-v1",
            direct_coverage="exact_same_root_local_only",
            transitive_coverage=(
                "bounded_registry_graph"
                if _go_graph_state(result) in {"accepted", "truncated"}
                else "not_available"
            ),
            manifest_status=go_manifest,
            lockfile_status=go_sum,
            exclusion_reason=_go_sum_coverage_reason(result, go_sum, captured_components),
        ),
        _coverage_entry(
            identifier="cargo-lock",
            ecosystem="cargo",
            manager="cargo",
            manifest="Cargo.toml",
            lockfile="Cargo.lock",
            parser_version="cargo-lock-toml-v3-v4",
            direct_coverage="exact_same_root_when_matched",
            transitive_coverage=(
                "bounded_registry_graph"
                if _cargo_graph_state(result) in {"accepted", "truncated"}
                else "not_available"
            ),
            manifest_status=cargo_manifest,
            lockfile_status=cargo_lock,
            exclusion_reason=_cargo_lock_coverage_reason(cargo_lock, captured_components, result),
        ),
        _coverage_entry(
            identifier="composer-lock",
            ecosystem="composer",
            manager="composer",
            manifest="composer.json",
            lockfile="composer.lock",
            parser_version="composer-lock-json-v1",
            direct_coverage="exact_same_root_local_only",
            transitive_coverage=(
                "bounded_registry_graph"
                if _composer_graph_state(result) in {"accepted", "truncated"}
                else "not_available"
            ),
            manifest_status=composer_manifest,
            lockfile_status=composer_lock,
            exclusion_reason=_composer_lock_coverage_reason(composer_lock, captured_components, result),
        ),
        _coverage_entry(
            identifier="gradle-lock",
            ecosystem="maven",
            manager="gradle",
            manifest="build.gradle",
            lockfile="gradle.lockfile",
            parser_version="gradle-lockfile-v1",
            direct_coverage=("exact_ci_graph" if _gradle_graph_state(result) in {"accepted", "truncated"} else "not_available"),
            transitive_coverage=("bounded_ci_graph" if _gradle_graph_state(result) in {"accepted", "truncated"} else "not_available"),
            manifest_status=gradle_manifest,
            lockfile_status=gradle_lock,
            exclusion_reason=_gradle_lock_coverage_reason(gradle_lock, captured_components, result),
        ),
        _coverage_entry(
            identifier="nuget-packages-lock",
            ecosystem="nuget",
            manager="nuget",
            manifest="*.csproj",
            lockfile="packages.lock.json",
            parser_version="nuget-packages-lock-json-v1",
            direct_coverage=("exact_ci_graph" if _nuget_graph_state(result) in {"accepted", "truncated"} else "exact_same_root_local_only"),
            transitive_coverage=("bounded_ci_graph" if _nuget_graph_state(result) in {"accepted", "truncated"} else "bounded_registry_graph"),
            manifest_status=dotnet_manifest,
            lockfile_status=nuget_lock,
            exclusion_reason=_nuget_lock_coverage_reason(result, nuget_lock, captured_components),
        ),
    ]
    return matrix


def _coverage_entry(
    *,
    identifier: str,
    ecosystem: str,
    manager: str,
    manifest: str,
    lockfile: str | None,
    parser_version: str,
    direct_coverage: str,
    transitive_coverage: str,
    manifest_status: str,
    lockfile_status: str,
    exclusion_reason: str,
) -> dict[str, str]:
    return {
        "id": identifier,
        "coverage_contract_version": COMPONENT_COVERAGE_MATRIX_VERSION,
        "ecosystem": ecosystem,
        "manager": manager,
        "manifest": manifest,
        "lockfile": lockfile or "not_applicable",
        "parser_version": parser_version,
        "direct_coverage": direct_coverage,
        "transitive_coverage": transitive_coverage,
        "manifest_status": manifest_status,
        "lockfile_status": lockfile_status,
        "exclusion_reason": exclusion_reason,
    }


def _manifest_observation(result: dict[str, Any], manifest_type: str) -> str:
    parsed_types = {
        _safe_text(_as_dict(item).get("manifest_type"))
        for item in _as_list(result.get("parsed_manifests"))
    }
    if manifest_type in parsed_types:
        return "parsed"
    supported_types = {
        _safe_text(_as_dict(item).get("manifest_type"))
        for item in _as_list(result.get("supported_manifests"))
    }
    return "detected_not_parsed" if manifest_type in supported_types else "not_detected"


def _lockfile_observation(result: dict[str, Any], filename: str) -> str:
    records = [
        _as_dict(item)
        for item in _as_list(result.get("lockfiles"))
        if _basename(_safe_text(_as_dict(item).get("path"))) == filename.lower()
    ]
    if not records:
        return "not_detected"
    return "parsed" if any(record.get("status") == "parsed" for record in records) else "detected_not_parsed"


def _npm_lockfile_coverage_reason(
    result: dict[str, Any],
    lockfile_status: str,
    components: list[dict[str, Any]],
) -> str:
    if lockfile_status == "not_detected":
        return "not_detected"
    if lockfile_status == "detected_not_parsed":
        return "defensive_limit_or_invalid_input"
    statuses = {_safe_text(component.get("lockfile_match_status")) for component in components}
    if "ambiguous" in statuses:
        return "ambiguous_root_pair"
    if "matched" not in statuses:
        return "no_same_root_match"
    return "graph_truncated" if _npm_lockfile_graph_is_truncated(result) else "none"


def _npm_lockfile_has_bounded_graph(result: dict[str, Any]) -> bool:
    return any(
        _safe_text(_as_dict(item).get("lockfile_type")) == "npm_package_lock"
        and isinstance(_as_dict(item).get("dependency_graph"), dict)
        for item in _as_list(result.get("parsed_lockfiles"))
    )


def _unsupported_lockfile_reason(result: dict[str, Any], filename: str) -> str:
    status = _lockfile_observation(result, filename)
    return "unsupported_lockfile_parser" if status == "detected_not_parsed" else "not_detected"


def _pnpm_lockfile_coverage_reason(lockfile_status: str, components: list[dict[str, Any]]) -> str:
    if lockfile_status == "not_detected":
        return "not_detected"
    if lockfile_status == "detected_not_parsed":
        return "defensive_limit_or_invalid_input"
    statuses = {
        _safe_text(component.get("lockfile_match_status"))
        for component in components
        if _safe_text(component.get("lockfile_type")) == "pnpm_lock"
    }
    if "ambiguous" in statuses:
        return "ambiguous_root_pair"
    return "none" if "matched" in statuses else "no_same_root_match"


def _yarn_classic_lockfile_coverage_reason(lockfile_status: str, components: list[dict[str, Any]]) -> str:
    if lockfile_status == "not_detected":
        return "not_detected"
    if lockfile_status == "detected_not_parsed":
        return "defensive_limit_or_invalid_input"
    statuses = {
        _safe_text(component.get("lockfile_match_status"))
        for component in components
        if _safe_text(component.get("lockfile_type")) == "yarn_classic_lock"
    }
    if "ambiguous" in statuses:
        return "ambiguous_root_pair"
    return "none" if "matched" in statuses else "no_same_root_match"


def _poetry_lockfile_coverage_reason(lockfile_status: str, components: list[dict[str, Any]]) -> str:
    if lockfile_status == "not_detected":
        return "not_detected"
    if lockfile_status == "detected_not_parsed":
        return "defensive_limit_or_invalid_input"
    statuses = {
        _safe_text(component.get("lockfile_match_status"))
        for component in components
        if _safe_text(component.get("lockfile_type")) == "poetry_lock"
    }
    if "ambiguous" in statuses:
        return "ambiguous_root_pair"
    return "none" if "matched" in statuses else "no_same_root_match"


def _pipfile_lockfile_coverage_reason(lockfile_status: str, components: list[dict[str, Any]]) -> str:
    if lockfile_status == "not_detected":
        return "not_detected"
    if lockfile_status == "detected_not_parsed":
        return "defensive_limit_or_invalid_input"
    statuses = {
        _safe_text(component.get("lockfile_match_status"))
        for component in components
        if _safe_text(component.get("lockfile_type")) == "pipfile_lock"
    }
    if "ambiguous" in statuses:
        return "ambiguous_root_pair"
    return "none" if "matched" in statuses else "no_same_root_match"


def _go_sum_coverage_reason(result: dict[str, Any], lockfile_status: str, components: list[dict[str, Any]]) -> str:
    if lockfile_status == "not_detected":
        return "not_detected"
    if lockfile_status == "detected_not_parsed":
        return "defensive_limit_or_invalid_input"
    statuses = {
        _safe_text(component.get("lockfile_match_status"))
        for component in components
        if _safe_text(component.get("lockfile_type")) == "go_sum"
    }
    if "ambiguous" in statuses:
        return "ambiguous_root_pair"
    if "matched" not in statuses:
        return "no_same_root_match"
    graph_state = _go_graph_state(result)
    if graph_state == "truncated":
        return "graph_truncated"
    if graph_state == "divergent":
        return "graph_divergent"
    return "none" if graph_state == "accepted" else "relationship_evidence_not_provided"


def _go_graph_state(result: dict[str, Any]) -> str:
    receipt = _as_dict(result.get("dependency_graph_evidence"))
    return _safe_text(receipt.get("state")) if receipt.get("ecosystem") == "go" else "not_provided"


def _cargo_lock_coverage_reason(lockfile_status: str, components: list[dict[str, Any]], result: dict[str, Any] | None = None) -> str:
    if lockfile_status == "not_detected":
        return "not_detected"
    if lockfile_status == "detected_not_parsed":
        return "defensive_limit_or_invalid_input"
    statuses = {
        _safe_text(component.get("lockfile_match_status"))
        for component in components
        if _safe_text(component.get("lockfile_type")) == "cargo_lock"
    }
    if "ambiguous" in statuses:
        return "ambiguous_root_pair"
    if "matched" not in statuses:
        return "no_same_root_match"
    graph_state = _cargo_graph_state(result or {})
    if graph_state == "truncated":
        return "graph_truncated"
    if graph_state == "divergent":
        return "graph_divergent"
    return "none" if graph_state == "accepted" else "relationship_evidence_not_provided"


def _cargo_graph_state(result: dict[str, Any]) -> str:
    receipt = _as_dict(result.get("cargo_dependency_graph_evidence"))
    return _safe_text(receipt.get("state")) if receipt.get("ecosystem") == "cargo" else "not_provided"


def _composer_lock_coverage_reason(
    lockfile_status: str, components: list[dict[str, Any]], result: dict[str, Any] | None = None
) -> str:
    if lockfile_status == "not_detected":
        return "not_detected"
    if lockfile_status == "detected_not_parsed":
        return "defensive_limit_or_invalid_input"
    statuses = {
        _safe_text(component.get("lockfile_match_status"))
        for component in components
        if _safe_text(component.get("lockfile_type")) == "composer_lock"
    }
    if "ambiguous" in statuses:
        return "ambiguous_root_pair"
    if "matched" not in statuses:
        return "no_same_root_match"
    graph_state = _composer_graph_state(result or {})
    if graph_state == "truncated":
        return "graph_truncated"
    if graph_state == "divergent":
        return "graph_divergent"
    return "none" if graph_state == "accepted" else "relationship_evidence_not_provided"


def _composer_graph_state(result: dict[str, Any]) -> str:
    receipt = _as_dict(result.get("composer_dependency_graph_evidence"))
    return _safe_text(receipt.get("state")) if receipt.get("ecosystem") == "composer" else "not_provided"


def _gradle_lock_coverage_reason(
    lockfile_status: str, components: list[dict[str, Any]], result: dict[str, Any] | None = None
) -> str:
    if lockfile_status == "not_detected":
        return "not_detected"
    if lockfile_status == "detected_not_parsed":
        return "defensive_limit_or_invalid_input"
    if not any(_safe_text(item.get("lockfile_type")) == "gradle_lock" for item in components):
        return "no_same_root_match"
    state = _gradle_graph_state(result or {})
    if state == "truncated":
        return "graph_truncated"
    if state == "divergent":
        return "graph_divergent"
    return "none" if state == "accepted" else "relationship_evidence_not_provided"


def _gradle_graph_state(result: dict[str, Any]) -> str:
    receipt = _as_dict(result.get("gradle_dependency_graph_evidence"))
    return _safe_text(receipt.get("state")) if receipt.get("ecosystem") == "maven" else "not_provided"


def _nuget_lock_coverage_reason(result: dict[str, Any], lockfile_status: str, components: list[dict[str, Any]]) -> str:
    if lockfile_status == "not_detected":
        return "not_detected"
    if lockfile_status != "parsed":
        return "defensive_limit_or_invalid_input"
    roots: dict[str, int] = {}
    for item in _as_list(result.get("parsed_manifests")):
        manifest = _as_dict(item)
        if _safe_text(manifest.get("manifest_type")) != "dotnet_project":
            continue
        path, status = _safe_manifest_path(manifest.get("path"))
        if path is not None and status == "reported":
            root = _project_root(path)
            roots[root] = roots.get(root, 0) + 1
    lock_roots = {
        _project_root(path)
        for item in _as_list(result.get("parsed_lockfiles"))
        if _safe_text(_as_dict(item).get("lockfile_type")) == "nuget_packages_lock"
        for path, status in [_safe_manifest_path(_as_dict(item).get("path"))]
        if path is not None and status == "reported"
    }
    lock_root_counts: dict[str, int] = {}
    for item in _as_list(result.get("parsed_lockfiles")):
        lockfile = _as_dict(item)
        if _safe_text(lockfile.get("lockfile_type")) != "nuget_packages_lock":
            continue
        path, status = _safe_manifest_path(lockfile.get("path"))
        if path is not None and status == "reported":
            root = _project_root(path)
            lock_root_counts[root] = lock_root_counts.get(root, 0) + 1
    if any(roots.get(root, 0) > 1 or lock_root_counts.get(root, 0) > 1 for root in lock_roots):
        return "ambiguous_root_pair"
    if not any(_safe_text(item.get("lockfile_type")) == "nuget_packages_lock" for item in components):
        return "no_same_root_match"
    state = _nuget_graph_state(result)
    if state == "truncated":
        return "graph_truncated"
    if state == "divergent":
        return "graph_divergent"
    return "none"


def _nuget_graph_state(result: dict[str, Any]) -> str:
    receipt = _as_dict(result.get("nuget_dependency_graph_evidence"))
    return _safe_text(receipt.get("state")) if receipt.get("ecosystem") == "nuget" else "not_provided"


def _manifest_only_reason(manifest_status: str) -> str:
    return "no_lockfile_contract" if manifest_status != "not_detected" else "not_detected"


def _basename(value: str) -> str:
    return value.replace("\\", "/").rsplit("/", 1)[-1].lower()


def _npm_lockfile_graph_is_truncated(result: dict[str, Any]) -> bool:
    for raw_lockfile in _as_list(result.get("parsed_lockfiles")):
        lockfile = _as_dict(raw_lockfile)
        if _safe_text(lockfile.get("lockfile_type")) != "npm_package_lock":
            continue
        graph = _as_dict(lockfile.get("dependency_graph"))
        if graph.get("nodes_truncated") is True or graph.get("edges_truncated") is True:
            return True
    return False


def _component_from_dependency(
    *,
    ecosystem: str,
    manifest_type: str,
    manifest_path: str | None,
    manifest_path_status: str,
    dependency_group: str,
    dependency: dict[str, Any],
) -> dict[str, Any] | None:
    raw_name = _safe_text(dependency.get("name"))
    source_type = _safe_text(dependency.get("dependency_source_type") or dependency.get("source_type")).lower()
    if source_type not in {"registry", "url", "vcs", "local", "editable", "workspace", "alias", "unknown"}:
        source_type = "unknown"

    # A malformed direct requirement may be parsed as its own "name".  Preserve
    # non-registry components only when that name is itself a valid public package
    # identifier; otherwise it may contain a private URL, local path, or token.
    name = _normalize_registry_name(ecosystem, raw_name)
    if not name:
        return None

    # Requirements from VCS/URL/local sources may contain credentials or private
    # topology.  We record their category, never their specifier or URL.
    specifier = _safe_text(dependency.get("specifier")) if source_type == REGISTRY_SOURCE_TYPE else ""
    exact_version = extract_exact_version(specifier, ecosystem) if source_type == REGISTRY_SOURCE_TYPE else None
    version_status = (
        "exact_declared"
        if exact_version
        else "declared_range"
        if source_type == REGISTRY_SOURCE_TYPE
        else "not_correlatable"
    )
    return {
        "id": _component_id(manifest_path, dependency_group, ecosystem, name, source_type, specifier),
        "ecosystem": ecosystem,
        "name": name,
        "manifest_path": manifest_path,
        "manifest_path_status": manifest_path_status,
        "dependency_group": dependency_group,
        "source_type": source_type,
        "declared_version": specifier or None,
        "exact_version": exact_version,
        "package_url": None,
        "version_status": version_status,
        "correlation_eligible": version_status == "exact_declared",
        "resolution": "declared",
        "dependency_scope": (
            "optional"
            if _is_optional_dependency_group(dependency_group)
            else "transitive"
            if ecosystem == "go" and dependency_group == "indirect"
            else "direct"
        ),
        "relationship_status": (
            "not_reported"
            if ecosystem in {"cargo", "composer"} or (ecosystem == "go" and dependency_group == "indirect")
            else "reported"
        ),
        "lockfile_match_status": "not_applicable",
        "manifest_type": manifest_type,
    }


def _apply_go_dependency_graph(
    components: list[dict[str, Any]],
    result: dict[str, Any],
    artifact: GoDependencyGraphArtifact | None,
    artifact_sha256: str | None,
) -> tuple[dict[str, Any] | None, int]:
    """Project a CI graph only when it agrees with one parsed Go source root.

    Raw node IDs and edges are intentionally not returned.  The terminal job
    keeps component identities already evidenced by ``go.sum`` plus a bounded
    aggregate receipt, so a hostile artifact cannot add unrelated names.
    """

    if artifact is None:
        return None, 0
    if not isinstance(artifact_sha256, str) or not re.fullmatch(r"[a-f0-9]{64}", artifact_sha256):
        raise ValueError("trusted Go graph digest is invalid")

    manifests: list[tuple[str, dict[str, Any]]] = []
    lockfiles: list[tuple[str, dict[str, Any]]] = []
    for item in _as_list(result.get("parsed_manifests")):
        record = _as_dict(item)
        if _safe_text(record.get("manifest_type")) != "go_mod":
            continue
        path, status = _safe_manifest_path(record.get("path"))
        if path is not None and status == "reported":
            manifests.append((path, _as_dict(record.get("parsed"))))
    for item in _as_list(result.get("parsed_lockfiles")):
        record = _as_dict(item)
        if _safe_text(record.get("lockfile_type")) != "go_sum":
            continue
        path, status = _safe_manifest_path(record.get("path"))
        if path is not None and status == "reported":
            lockfiles.append((path, record))

    reason = "none"
    if len(manifests) != 1 or len(lockfiles) != 1 or _project_root(manifests[0][0]) != _project_root(lockfiles[0][0]):
        reason = "no_single_source_root"

    nodes_by_id = {node.id: node for node in artifact.nodes}
    node_identities = {(node.name, node.version) for node in artifact.nodes}
    root_identities = {
        (nodes_by_id[node_id].name, nodes_by_id[node_id].version)
        for node_id in artifact.roots
    }
    lock_identities: set[tuple[str, str]] = set()
    expected_roots: set[tuple[str, str]] = set()
    expected_requirements: set[tuple[str, str]] = set()
    blocked_names: set[str] = set()
    manifest_path = ""
    lockfile_path = ""
    if reason == "none":
        manifest_path, parsed_manifest = manifests[0]
        lockfile_path, parsed_lockfile = lockfiles[0]
        for item in _as_list(parsed_lockfile.get("packages")):
            package = _as_dict(item)
            name = _safe_text(package.get("name"))
            version = _safe_text(package.get("version"))
            if is_valid_go_module_name(name) and extract_exact_version(version, "go") is not None:
                lock_identities.add((name, version))
        dependencies = _as_dict(parsed_manifest.get("dependencies"))
        for group in ("require", "indirect"):
            for item in _as_list(dependencies.get(group)):
                dependency = _as_dict(item)
                name = _safe_text(dependency.get("name"))
                version = _safe_text(dependency.get("specifier"))
                if dependency.get("dependency_source_type") != REGISTRY_SOURCE_TYPE:
                    if is_valid_go_module_name(name):
                        blocked_names.add(name)
                    continue
                if is_valid_go_module_name(name) and extract_exact_version(version, "go") is not None:
                    expected_requirements.add((name, version))
                    if group == "require":
                        expected_roots.add((name, version))

        if any(name in blocked_names for name, _version in node_identities):
            reason = "replaced_identity"
        elif not node_identities.issubset(lock_identities):
            reason = "identity_not_in_lockfile"
        elif root_identities != expected_roots:
            reason = "root_set_mismatch"
        elif artifact.complete and not expected_requirements.issubset(node_identities):
            reason = "complete_graph_omits_manifest_requirement"
        elif _go_graph_reachable_ids(artifact) != set(nodes_by_id):
            reason = "unreachable_node"

    matched_nodes = len(node_identities & lock_identities)
    cycles_detected = _go_graph_has_cycle(artifact)
    if reason != "none":
        return {
            "contract_version": artifact.contract_version,
            "ecosystem": "go",
            "state": "divergent",
            "reason": reason,
            "artifact_sha256": artifact_sha256,
            "source_commit_sha": artifact.source_commit_sha,
            "source_binding_verified": True,
            "nodes_reported": len(artifact.nodes),
            "edges_reported": len(artifact.edges),
            "components_matched": matched_nodes,
            "components_unmatched": len(artifact.nodes) - matched_nodes,
            "cycles_detected": cycles_detected,
            "truncation_reason": artifact.truncation_reason,
        }, 0

    relationship_status = "reported" if artifact.complete else "truncated"
    direct_identities = root_identities
    existing_identities: set[tuple[str, str]] = set()
    for component in components:
        if component.get("ecosystem") != "go":
            continue
        name = _safe_text(component.get("name"))
        version = _safe_text(component.get("exact_version") or component.get("declared_version"))
        identity = (name, version)
        if identity not in node_identities:
            continue
        component.update(
            {
                "exact_version": version,
                "version_status": "exact_resolved",
                "correlation_eligible": True,
                "resolution": "lockfile",
                "lockfile_path": lockfile_path,
                "lockfile_path_status": "reported",
                "lockfile_type": "go_sum",
                "lockfile_match_status": "matched",
                "dependency_scope": "direct" if identity in direct_identities else "transitive",
                "relationship_status": relationship_status,
            }
        )
        existing_identities.add(identity)

    added = 0
    for node in artifact.nodes:
        identity = (node.name, node.version)
        if identity in existing_identities:
            continue
        existing_identities.add(identity)
        scope = "direct" if identity in direct_identities else "transitive"
        components.append(
            {
                "id": _component_id(lockfile_path, "ci-go-graph", "go", node.name, REGISTRY_SOURCE_TYPE, node.version),
                "ecosystem": "go",
                "name": node.name,
                "manifest_path": manifest_path,
                "manifest_path_status": "reported",
                "dependency_group": "require" if scope == "direct" else "transitive",
                "dependency_scope": scope,
                "relationship_status": relationship_status,
                "source_type": REGISTRY_SOURCE_TYPE,
                "declared_version": None,
                "exact_version": node.version,
                "package_url": None,
                "version_status": "exact_resolved",
                "correlation_eligible": True,
                "resolution": "lockfile",
                "lockfile_match_status": "matched",
                "manifest_type": "go_mod",
                "lockfile_path": lockfile_path,
                "lockfile_path_status": "reported",
                "lockfile_type": "go_sum",
            }
        )
        if scope == "transitive":
            added += 1

    return {
        "contract_version": artifact.contract_version,
        "ecosystem": "go",
        "state": "accepted" if artifact.complete else "truncated",
        "reason": "none" if artifact.complete else "producer_truncated",
        "artifact_sha256": artifact_sha256,
        "source_commit_sha": artifact.source_commit_sha,
        "source_binding_verified": True,
        "nodes_reported": len(artifact.nodes),
        "edges_reported": len(artifact.edges),
        "components_matched": len(artifact.nodes),
        "components_unmatched": 0,
        "cycles_detected": cycles_detected,
        "truncation_reason": artifact.truncation_reason,
    }, added


def _go_graph_reachable_ids(artifact: GoDependencyGraphArtifact) -> set[str]:
    outgoing: dict[str, list[str]] = {}
    for edge in artifact.edges:
        outgoing.setdefault(edge.source, []).append(edge.target)
    pending = list(artifact.roots)
    reached: set[str] = set()
    while pending:
        node_id = pending.pop()
        if node_id in reached:
            continue
        reached.add(node_id)
        pending.extend(outgoing.get(node_id, ()))
    return reached


def _go_graph_has_cycle(artifact: GoDependencyGraphArtifact) -> bool:
    """Detect cycles iteratively so a bounded but deep graph cannot exhaust the stack."""

    outgoing: dict[str, list[str]] = {node.id: [] for node in artifact.nodes}
    incoming = {node.id: 0 for node in artifact.nodes}
    for edge in artifact.edges:
        outgoing[edge.source].append(edge.target)
        incoming[edge.target] += 1
    ready = [node_id for node_id, count in incoming.items() if count == 0]
    visited = 0
    while ready:
        node_id = ready.pop()
        visited += 1
        for target in outgoing[node_id]:
            incoming[target] -= 1
            if incoming[target] == 0:
                ready.append(target)
    return visited != len(incoming)


def _apply_cargo_dependency_graph(
    components: list[dict[str, Any]],
    result: dict[str, Any],
    artifact: CargoDependencyGraphArtifact | None,
    artifact_sha256: str | None,
) -> dict[str, Any] | None:
    """Project a bounded Cargo graph only after exact same-root corroboration.

    Feature labels, target IDs, node IDs and edges remain request-local. The
    stored component projection retains only counts and relationship state.
    """

    if artifact is None:
        return None
    if not isinstance(artifact_sha256, str) or not re.fullmatch(r"[a-f0-9]{64}", artifact_sha256):
        raise ValueError("trusted Cargo graph digest is invalid")

    manifests: list[tuple[str, dict[str, Any]]] = []
    lockfiles: list[tuple[str, dict[str, Any]]] = []
    for item in _as_list(result.get("parsed_manifests")):
        record = _as_dict(item)
        if _safe_text(record.get("manifest_type")) != "cargo_toml":
            continue
        path, status = _safe_manifest_path(record.get("path"))
        if path is not None and status == "reported":
            manifests.append((path, _as_dict(record.get("parsed"))))
    for item in _as_list(result.get("parsed_lockfiles")):
        record = _as_dict(item)
        if _safe_text(record.get("lockfile_type")) != "cargo_lock":
            continue
        path, status = _safe_manifest_path(record.get("path"))
        if path is not None and status == "reported":
            lockfiles.append((path, record))

    reason = "none"
    if len(manifests) != 1 or len(lockfiles) != 1 or _project_root(manifests[0][0]) != _project_root(lockfiles[0][0]):
        reason = "no_single_source_root"

    nodes_by_id = {node.id: node for node in artifact.nodes}
    node_identities = {(node.name, node.version) for node in artifact.nodes}
    root_identities = {(nodes_by_id[node_id].name, nodes_by_id[node_id].version) for node_id in artifact.roots}
    lock_identities: set[tuple[str, str]] = set()
    expected_roots: set[tuple[str, str]] = set()
    manifest_path = ""
    lockfile_path = ""
    if reason == "none":
        manifest_path, _parsed_manifest = manifests[0]
        lockfile_path, parsed_lockfile = lockfiles[0]
        for item in _as_list(parsed_lockfile.get("packages")):
            package = _as_dict(item)
            name = _safe_text(package.get("name"))
            version = _safe_text(package.get("version"))
            if (
                _safe_text(package.get("source_type")) == REGISTRY_SOURCE_TYPE
                and is_valid_cargo_name(name)
                and extract_exact_version(version, "cargo") is not None
            ):
                lock_identities.add((name, version))

        unresolved_root = False
        for component in components:
            if (
                component.get("ecosystem") != "cargo"
                or component.get("manifest_path") != manifest_path
                or component.get("dependency_group") not in {"dependencies", "dev-dependencies", "build-dependencies"}
                or component.get("source_type") != REGISTRY_SOURCE_TYPE
            ):
                continue
            version = _safe_text(component.get("exact_version"))
            if component.get("lockfile_match_status") != "matched" or not version:
                unresolved_root = True
                continue
            expected_roots.add((_safe_text(component.get("name")), version))

        if unresolved_root:
            reason = "unresolved_manifest_root"
        elif not node_identities.issubset(lock_identities):
            reason = "identity_not_in_lockfile"
        elif root_identities != expected_roots:
            reason = "root_set_mismatch"
        elif _cargo_graph_reachable_ids(artifact) != set(nodes_by_id):
            reason = "unreachable_node"

    matched_nodes = len(node_identities & lock_identities)
    cycles_detected = _cargo_graph_has_cycle(artifact)
    base_receipt = {
        "contract_version": artifact.contract_version,
        "ecosystem": "cargo",
        "artifact_sha256": artifact_sha256,
        "source_commit_sha": artifact.source_commit_sha,
        "source_binding_verified": True,
        "target_coverage": artifact.target_coverage,
        "nodes_reported": len(artifact.nodes),
        "edges_reported": len(artifact.edges),
        "features_reported": sum(len(node.features) for node in artifact.nodes),
        "targets_reported": len(artifact.targets),
        "components_matched": matched_nodes,
        "components_unmatched": len(artifact.nodes) - matched_nodes,
        "cycles_detected": cycles_detected,
        "truncation_reason": artifact.truncation_reason,
    }
    if reason != "none":
        return {**base_receipt, "state": "divergent", "reason": reason}

    relationship_status = "reported" if artifact.complete else "truncated"
    node_by_identity = {(node.name, node.version): node for node in artifact.nodes}
    for component in components:
        if component.get("ecosystem") != "cargo":
            continue
        identity = (_safe_text(component.get("name")), _safe_text(component.get("exact_version")))
        node = node_by_identity.get(identity)
        if node is None:
            continue
        component.update(
            {
                "dependency_scope": "direct" if identity in root_identities else "transitive",
                "relationship_status": relationship_status,
                "enabled_feature_count": len(node.features),
                "target_variant_count": len(node.targets),
            }
        )

    return {
        **base_receipt,
        "state": "accepted" if artifact.complete else "truncated",
        "reason": "none" if artifact.complete else "producer_truncated",
        "components_matched": len(artifact.nodes),
        "components_unmatched": 0,
    }


def _cargo_graph_reachable_ids(artifact: CargoDependencyGraphArtifact) -> set[str]:
    outgoing: dict[str, list[str]] = {}
    for edge in artifact.edges:
        outgoing.setdefault(edge.source, []).append(edge.target)
    pending = list(artifact.roots)
    reached: set[str] = set()
    while pending:
        node_id = pending.pop()
        if node_id in reached:
            continue
        reached.add(node_id)
        pending.extend(outgoing.get(node_id, ()))
    return reached


def _cargo_graph_has_cycle(artifact: CargoDependencyGraphArtifact) -> bool:
    outgoing: dict[str, set[str]] = {node.id: set() for node in artifact.nodes}
    incoming = {node.id: 0 for node in artifact.nodes}
    for edge in artifact.edges:
        if edge.target in outgoing[edge.source]:
            continue
        outgoing[edge.source].add(edge.target)
        incoming[edge.target] += 1
    ready = [node_id for node_id, count in incoming.items() if count == 0]
    visited = 0
    while ready:
        node_id = ready.pop()
        visited += 1
        for target in outgoing[node_id]:
            incoming[target] -= 1
            if incoming[target] == 0:
                ready.append(target)
    return visited != len(incoming)


def _apply_composer_dependency_graph(
    components: list[dict[str, Any]],
    result: dict[str, Any],
    artifact: ComposerDependencyGraphArtifact | None,
    artifact_sha256: str | None,
) -> dict[str, Any] | None:
    """Apply relation evidence without granting Packagist provenance."""

    if artifact is None:
        return None
    if not isinstance(artifact_sha256, str) or not re.fullmatch(r"[a-f0-9]{64}", artifact_sha256):
        raise ValueError("trusted Composer graph digest is invalid")
    manifests: list[tuple[str, dict[str, Any]]] = []
    lockfiles: list[tuple[str, dict[str, Any]]] = []
    for item in _as_list(result.get("parsed_manifests")):
        record = _as_dict(item)
        if _safe_text(record.get("manifest_type")) == "composer_json":
            path, status = _safe_manifest_path(record.get("path"))
            if path is not None and status == "reported":
                manifests.append((path, _as_dict(record.get("parsed"))))
    for item in _as_list(result.get("parsed_lockfiles")):
        record = _as_dict(item)
        if _safe_text(record.get("lockfile_type")) == "composer_lock":
            path, status = _safe_manifest_path(record.get("path"))
            if path is not None and status == "reported":
                lockfiles.append((path, record))
    reason = "none"
    if len(manifests) != 1 or len(lockfiles) != 1 or _project_root(manifests[0][0]) != _project_root(lockfiles[0][0]):
        reason = "no_single_source_root"
    nodes_by_id = {node.id: node for node in artifact.nodes}
    identities = {(node.name, node.version) for node in artifact.nodes}
    roots = {(nodes_by_id[node_id].name, nodes_by_id[node_id].version) for node_id in artifact.roots}
    lock_identities: set[tuple[str, str]] = set()
    expected_roots: set[tuple[str, str]] = set()
    if reason == "none":
        manifest_path, parsed_manifest = manifests[0]
        _lock_path, parsed_lock = lockfiles[0]
        if _as_dict(parsed_manifest.get("project")).get("custom_repositories_declared") is True:
            reason = "custom_repository_declared"
        for item in _as_list(parsed_lock.get("packages")):
            package = _as_dict(item)
            name, version = _safe_text(package.get("name")), _safe_text(package.get("version"))
            if is_valid_composer_name(name) and extract_exact_version(version, "composer") is not None:
                lock_identities.add((name, version))
        unresolved_root = False
        for component in components:
            if (
                component.get("ecosystem") != "composer"
                or component.get("manifest_path") != manifest_path
                or component.get("dependency_group") not in {"require", "require-dev"}
                or component.get("source_type") != REGISTRY_SOURCE_TYPE
                or component.get("declared_version") is None
            ):
                continue
            version = _safe_text(component.get("exact_version"))
            if component.get("lockfile_match_status") != "matched" or not version:
                unresolved_root = True
            else:
                expected_roots.add((_safe_text(component.get("name")), version))
        if reason == "none" and unresolved_root:
            reason = "unresolved_manifest_root"
        elif reason == "none" and not identities.issubset(lock_identities):
            reason = "identity_not_in_lockfile"
        elif reason == "none" and roots != expected_roots:
            reason = "root_set_mismatch"
        elif reason == "none" and _composer_graph_reachable_ids(artifact) != set(nodes_by_id):
            reason = "unreachable_node"
    matched = len(identities & lock_identities)
    base = {
        "contract_version": artifact.contract_version, "ecosystem": "composer",
        "artifact_sha256": artifact_sha256, "source_commit_sha": artifact.source_commit_sha,
        "source_binding_verified": True, "nodes_reported": len(artifact.nodes),
        "edges_reported": len(artifact.edges), "components_matched": matched,
        "components_unmatched": len(artifact.nodes) - matched,
        "cycles_detected": _composer_graph_has_cycle(artifact),
        "truncation_reason": artifact.truncation_reason,
    }
    if reason != "none":
        return {**base, "state": "divergent", "reason": reason}
    relation = "reported" if artifact.complete else "truncated"
    for component in components:
        identity = (_safe_text(component.get("name")), _safe_text(component.get("exact_version")))
        if component.get("ecosystem") == "composer" and identity in identities:
            component["dependency_scope"] = "direct" if identity in roots else "transitive"
            component["relationship_status"] = relation
    return {
        **base, "state": "accepted" if artifact.complete else "truncated",
        "reason": "none" if artifact.complete else "producer_truncated",
        "components_matched": len(artifact.nodes), "components_unmatched": 0,
    }


def _composer_graph_reachable_ids(artifact: ComposerDependencyGraphArtifact) -> set[str]:
    outgoing: dict[str, list[str]] = {}
    for edge in artifact.edges:
        outgoing.setdefault(edge.source, []).append(edge.target)
    pending, reached = list(artifact.roots), set()
    while pending:
        node = pending.pop()
        if node not in reached:
            reached.add(node)
            pending.extend(outgoing.get(node, ()))
    return reached


def _composer_graph_has_cycle(artifact: ComposerDependencyGraphArtifact) -> bool:
    outgoing = {node.id: set() for node in artifact.nodes}
    incoming = {node.id: 0 for node in artifact.nodes}
    for edge in artifact.edges:
        if edge.target not in outgoing[edge.source]:
            outgoing[edge.source].add(edge.target)
            incoming[edge.target] += 1
    ready, visited = [node for node, count in incoming.items() if count == 0], 0
    while ready:
        node = ready.pop()
        visited += 1
        for target in outgoing[node]:
            incoming[target] -= 1
            if incoming[target] == 0:
                ready.append(target)
    return visited != len(incoming)


def _apply_gradle_dependency_graph(
    components: list[dict[str, Any]],
    result: dict[str, Any],
    artifact: GradleDependencyGraphArtifact | None,
    artifact_sha256: str | None,
) -> dict[str, Any] | None:
    """Project CI-reported Gradle relationships without attesting a registry."""

    if artifact is None:
        return None
    if not isinstance(artifact_sha256, str) or not re.fullmatch(r"[a-f0-9]{64}", artifact_sha256):
        raise ValueError("trusted Gradle graph digest is invalid")
    manifests: list[str] = []
    lockfiles: list[tuple[str, dict[str, Any]]] = []
    for item in _as_list(result.get("parsed_manifests")):
        record = _as_dict(item)
        if _safe_text(record.get("manifest_type")) == "gradle_build":
            path, status = _safe_manifest_path(record.get("path"))
            if path is not None and status == "reported":
                manifests.append(path)
    for item in _as_list(result.get("parsed_lockfiles")):
        record = _as_dict(item)
        if _safe_text(record.get("lockfile_type")) == "gradle_lock":
            path, status = _safe_manifest_path(record.get("path"))
            if path is not None and status == "reported":
                lockfiles.append((path, record))
    reason = "none"
    if len(manifests) != 1 or len(lockfiles) != 1 or _project_root(manifests[0]) != _project_root(lockfiles[0][0]):
        reason = "no_single_source_root"
    identities = {(node.name, node.version) for node in artifact.nodes}
    lock_identities: set[tuple[str, str]] = set()
    if reason == "none":
        for item in _as_list(lockfiles[0][1].get("packages")):
            package = _as_dict(item)
            name, version = _safe_text(package.get("name")), _safe_text(package.get("version"))
            if is_valid_maven_name(name) and extract_exact_version(version, "maven") is not None:
                lock_identities.add((name, version))
        if not identities.issubset(lock_identities):
            reason = "identity_not_in_lockfile"
        elif _gradle_graph_reachable_ids(artifact) != {node.id for node in artifact.nodes}:
            reason = "unreachable_node"
    matched = len(identities & lock_identities)
    base = {
        "contract_version": artifact.contract_version,
        "ecosystem": "maven",
        "producer": "gradle",
        "state": "divergent",
        "reason": reason,
        "artifact_sha256": artifact_sha256,
        "source_commit_sha": artifact.source_commit_sha,
        "source_binding_verified": True,
        "relationship_origin": "ci_reported",
        "scope_coverage": list(artifact.scope_coverage),
        "nodes_reported": len(artifact.nodes),
        "edges_reported": len(artifact.edges),
        "scope_assignments_reported": sum(len(node.scopes) for node in artifact.nodes),
        "components_matched": matched,
        "components_unmatched": len(artifact.nodes) - matched,
        "cycles_detected": _gradle_graph_has_cycle(artifact),
        "truncation_reason": artifact.truncation_reason,
    }
    if reason != "none":
        return base
    roots = {
        (node.name, node.version)
        for node in artifact.nodes
        if node.id in set(artifact.roots)
    }
    scopes = {(node.name, node.version): len(node.scopes) for node in artifact.nodes}
    relationship = "reported" if artifact.complete else "truncated"
    for component in components:
        identity = (_safe_text(component.get("name")), _safe_text(component.get("exact_version")))
        if component.get("ecosystem") == "maven" and identity in identities:
            component["dependency_scope"] = "direct" if identity in roots else "transitive"
            component["relationship_status"] = relationship
            component["build_scope_count"] = scopes[identity]
    return {
        **base,
        "state": "accepted" if artifact.complete else "truncated",
        "reason": "none" if artifact.complete else "producer_truncated",
        "components_matched": len(artifact.nodes),
        "components_unmatched": 0,
    }


def _gradle_graph_reachable_ids(artifact: GradleDependencyGraphArtifact) -> set[str]:
    outgoing: dict[str, list[str]] = {}
    for edge in artifact.edges:
        outgoing.setdefault(edge.source, []).append(edge.target)
    pending, reached = list(artifact.roots), set()
    while pending:
        node = pending.pop()
        if node not in reached:
            reached.add(node)
            pending.extend(outgoing.get(node, ()))
    return reached


def _gradle_graph_has_cycle(artifact: GradleDependencyGraphArtifact) -> bool:
    outgoing = {node.id: set() for node in artifact.nodes}
    incoming = {node.id: 0 for node in artifact.nodes}
    for edge in artifact.edges:
        if edge.target not in outgoing[edge.source]:
            outgoing[edge.source].add(edge.target)
            incoming[edge.target] += 1
    ready, visited = [node for node, count in incoming.items() if count == 0], 0
    while ready:
        node = ready.pop()
        visited += 1
        for target in outgoing[node]:
            incoming[target] -= 1
            if incoming[target] == 0:
                ready.append(target)
    return visited != len(incoming)


def _apply_nuget_dependency_graph(
    components: list[dict[str, Any]],
    result: dict[str, Any],
    artifact: NugetDependencyGraphArtifact | None,
    artifact_sha256: str | None,
) -> dict[str, Any] | None:
    """Project target-aware CI relationships without claiming NuGet.org origin."""

    if artifact is None:
        return None
    if not isinstance(artifact_sha256, str) or not re.fullmatch(r"[a-f0-9]{64}", artifact_sha256):
        raise ValueError("trusted NuGet graph digest is invalid")
    manifests: list[str] = []
    lockfiles: list[tuple[str, dict[str, Any]]] = []
    for item in _as_list(result.get("parsed_manifests")):
        record = _as_dict(item)
        if _safe_text(record.get("manifest_type")) == "dotnet_project":
            path, status = _safe_manifest_path(record.get("path"))
            if path is not None and status == "reported":
                manifests.append(path)
    for item in _as_list(result.get("parsed_lockfiles")):
        record = _as_dict(item)
        if _safe_text(record.get("lockfile_type")) == "nuget_packages_lock":
            path, status = _safe_manifest_path(record.get("path"))
            if path is not None and status == "reported":
                lockfiles.append((path, record))
    reason = "none"
    if len(manifests) != 1 or len(lockfiles) != 1 or _project_root(manifests[0]) != _project_root(lockfiles[0][0]):
        reason = "no_single_source_root"
    identities = {(node.name, node.version) for node in artifact.nodes}
    lock_identities: set[tuple[str, str]] = set()
    if reason == "none":
        lockfile = lockfiles[0][1]
        if _safe_non_negative_int(lockfile.get("target_count")) != len(artifact.targets):
            reason = "target_count_mismatch"
        for item in _as_list(lockfile.get("packages")):
            package = _as_dict(item)
            name, version = _safe_text(package.get("name")), _safe_text(package.get("version"))
            if is_valid_nuget_name(name) and extract_exact_version(version, "nuget") is not None:
                lock_identities.add((name, version))
        if reason == "none" and not identities.issubset(lock_identities):
            reason = "identity_not_in_lockfile"
        elif reason == "none" and not _nuget_graph_is_reachable_by_target(artifact):
            reason = "unreachable_node"
    matched = len(identities & lock_identities)
    base = {
        "contract_version": artifact.contract_version,
        "ecosystem": "nuget",
        "producer": "nuget",
        "state": "divergent",
        "reason": reason,
        "artifact_sha256": artifact_sha256,
        "source_commit_sha": artifact.source_commit_sha,
        "source_binding_verified": True,
        "relationship_origin": "ci_reported",
        "target_coverage": artifact.target_coverage,
        "targets_reported": len(artifact.targets),
        "target_assignments_reported": sum(len(node.targets) for node in artifact.nodes),
        "nodes_reported": len(artifact.nodes),
        "edges_reported": len(artifact.edges),
        "components_matched": matched,
        "components_unmatched": len(artifact.nodes) - matched,
        "cycles_detected": _nuget_graph_has_cycle(artifact),
        "truncation_reason": artifact.truncation_reason,
    }
    if reason != "none":
        return base
    root_ids = {root.node for root in artifact.roots}
    nodes = {(node.name, node.version): node for node in artifact.nodes}
    relationship = "reported" if artifact.complete else "truncated"
    for component in components:
        identity = (_safe_text(component.get("name")), _safe_text(component.get("exact_version")))
        node = nodes.get(identity) if component.get("ecosystem") == "nuget" else None
        if node is not None:
            component["dependency_scope"] = "direct" if node.id in root_ids else "transitive"
            component["relationship_status"] = relationship
            component["target_variant_count"] = len(node.targets)
    return {
        **base,
        "state": "accepted" if artifact.complete else "truncated",
        "reason": "none" if artifact.complete else "producer_truncated",
        "components_matched": len(artifact.nodes),
        "components_unmatched": 0,
    }


def _nuget_graph_is_reachable_by_target(artifact: NugetDependencyGraphArtifact) -> bool:
    for target in artifact.targets:
        outgoing: dict[str, list[str]] = {}
        for edge in artifact.edges:
            if target in edge.targets:
                outgoing.setdefault(edge.source, []).append(edge.target)
        pending = [root.node for root in artifact.roots if target in root.targets]
        reached: set[str] = set()
        while pending:
            node = pending.pop()
            if node not in reached:
                reached.add(node)
                pending.extend(outgoing.get(node, ()))
        expected = {node.id for node in artifact.nodes if target in node.targets}
        if reached != expected:
            return False
    return True


def _nuget_graph_has_cycle(artifact: NugetDependencyGraphArtifact) -> bool:
    for target in artifact.targets:
        nodes = {node.id for node in artifact.nodes if target in node.targets}
        outgoing = {node: set() for node in nodes}
        incoming = {node: 0 for node in nodes}
        for edge in artifact.edges:
            if target in edge.targets and edge.target not in outgoing[edge.source]:
                outgoing[edge.source].add(edge.target)
                incoming[edge.target] += 1
        ready, visited = [node for node, count in incoming.items() if count == 0], 0
        while ready:
            node = ready.pop()
            visited += 1
            for child in outgoing[node]:
                incoming[child] -= 1
                if incoming[child] == 0:
                    ready.append(child)
        if visited != len(nodes):
            return True
    return False


def _add_exact_package_urls(components: list[dict[str, Any]]) -> None:
    """Attach a purl only to an already safe, exact public package identity.

    Package URLs make no claim about vulnerability status. They are the local
    identity input for a later, explicitly configured advisory boundary.
    """

    for component in components:
        exact_version = _safe_text(component.get("exact_version"))
        ecosystem = _safe_text(component.get("ecosystem"))
        name = _safe_text(component.get("name"))
        if (
            component.get("source_type") != REGISTRY_SOURCE_TYPE
            or component.get("correlation_eligible") is not True
            or not exact_version
        ):
            component["package_url"] = None
            continue
        specifier = f"=={exact_version}" if ecosystem == "pypi" else exact_version
        component["package_url"] = build_package_url(ecosystem, name, specifier, REGISTRY_SOURCE_TYPE)


def _is_optional_dependency_group(group: str) -> bool:
    """Classify only groups whose manifest grammar explicitly calls optional."""

    return group == "optionalDependencies" or group.startswith("optional:")


def _add_npm_transitive_lockfile_components(
    components: list[dict[str, Any]],
    result: dict[str, Any],
    workspace_manifest_paths: set[str],
) -> tuple[int, bool]:
    """Add safe transitive nodes only after an existing same-root match."""

    lockfiles_by_root: dict[str, list[tuple[str, dict[str, Any]]]] = {}
    for raw_lockfile in _as_list(result.get("parsed_lockfiles")):
        lockfile = _as_dict(raw_lockfile)
        if _safe_text(lockfile.get("lockfile_type")) != "npm_package_lock":
            continue
        path, path_status = _safe_manifest_path(lockfile.get("path"))
        if path is not None and path_status == "reported":
            lockfiles_by_root.setdefault(_project_root(path), []).append((path, lockfile))

    manifest_by_root: dict[str, str] = {}
    for component in components:
        manifest_path = component.get("manifest_path")
        if (
            component.get("ecosystem") == "npm"
            and component.get("manifest_type") == "package_json"
            and component.get("source_type") == REGISTRY_SOURCE_TYPE
            and component.get("lockfile_match_status") == "matched"
            and isinstance(manifest_path, str)
            and manifest_path not in workspace_manifest_paths
        ):
            manifest_by_root.setdefault(_project_root(manifest_path), manifest_path)

    existing_ids = {_safe_text(component.get("id")) for component in components}
    existing_registry_versions = {
        (_safe_text(component.get("name")), _safe_text(component.get("exact_version")))
        for component in components
        if component.get("source_type") == REGISTRY_SOURCE_TYPE
    }
    added = 0
    graph_truncated = False
    for root, manifest_path in manifest_by_root.items():
        candidates = lockfiles_by_root.get(root, [])
        if len(candidates) != 1:
            continue
        lockfile_path, lockfile = candidates[0]
        graph = _as_dict(lockfile.get("dependency_graph"))
        graph_truncated = graph_truncated or bool(graph.get("nodes_truncated")) or bool(graph.get("edges_truncated"))
        for raw_node in _as_list(graph.get("nodes")):
            node = _as_dict(raw_node)
            name = _normalize_registry_name("npm", _safe_text(node.get("name")))
            version = _safe_text(node.get("version"))
            node_id = _safe_text(node.get("id"))
            if (
                node.get("source_type") != REGISTRY_SOURCE_TYPE
                or node.get("dependency_scope") not in {"transitive", "optional"}
                or not name
                or not node_id
                or not extract_exact_version(version, "npm")
            ):
                continue
            component_id = _component_id(lockfile_path, "transitive", "npm", name, REGISTRY_SOURCE_TYPE, f"{version}:{node_id}")
            if component_id in existing_ids or (name, version) in existing_registry_versions:
                continue
            existing_ids.add(component_id)
            existing_registry_versions.add((name, version))
            components.append(
                {
                    "id": component_id,
                    "ecosystem": "npm",
                    "name": name,
                    "manifest_path": manifest_path,
                    "manifest_path_status": "reported",
                    "dependency_group": "optional" if node.get("dependency_scope") == "optional" else "transitive",
                    "dependency_scope": node.get("dependency_scope"),
                    "source_type": REGISTRY_SOURCE_TYPE,
                    "declared_version": None,
                    "exact_version": version,
                    "package_url": None,
                    "version_status": "exact_resolved",
                    "correlation_eligible": True,
                    "resolution": "lockfile",
                    "lockfile_match_status": "matched",
                    "manifest_type": "package_json",
                    "lockfile_path": lockfile_path,
                    "lockfile_path_status": "reported",
                    "lockfile_type": "npm_package_lock",
                }
            )
            added += 1
    return added, graph_truncated


def _add_cargo_transitive_lockfile_components(components: list[dict[str, Any]], result: dict[str, Any]) -> int:
    """Add exact public crates not already represented by direct declarations.

    Cargo.lock does not retain a complete edge contract here, so these nodes
    are labelled transitive with relationship ``not_reported`` rather than
    claiming a reconstructed dependency graph.
    """

    matched_roots = {
        _project_root(_safe_text(component.get("manifest_path")))
        for component in components
        if component.get("ecosystem") == "cargo"
        and component.get("lockfile_type") == "cargo_lock"
        and component.get("lockfile_match_status") == "matched"
    }
    existing = {
        (_safe_text(component.get("name")), _safe_text(component.get("exact_version")))
        for component in components
        if component.get("ecosystem") == "cargo"
    }
    added = 0
    for raw_lockfile in _as_list(result.get("parsed_lockfiles")):
        lockfile = _as_dict(raw_lockfile)
        if _safe_text(lockfile.get("lockfile_type")) != "cargo_lock":
            continue
        lockfile_path, path_status = _safe_manifest_path(lockfile.get("path"))
        if lockfile_path is None or path_status != "reported" or _project_root(lockfile_path) not in matched_roots:
            continue
        for raw_package in _as_list(lockfile.get("packages")):
            package = _as_dict(raw_package)
            name = _normalize_registry_name("cargo", _safe_text(package.get("name")))
            version = _safe_text(package.get("version"))
            if (
                not name
                or not extract_exact_version(version, "cargo")
                or _safe_text(package.get("source_type")) != REGISTRY_SOURCE_TYPE
                or (name, version) in existing
            ):
                continue
            existing.add((name, version))
            components.append(
                {
                    "id": _component_id(lockfile_path, "transitive", "cargo", name, REGISTRY_SOURCE_TYPE, version),
                    "ecosystem": "cargo",
                    "name": name,
                    "manifest_path": f"{_project_root(lockfile_path)}/Cargo.toml".lstrip("/"),
                    "manifest_path_status": "reported",
                    "dependency_group": "transitive",
                    "dependency_scope": "transitive",
                    "relationship_status": "not_reported",
                    "source_type": REGISTRY_SOURCE_TYPE,
                    "declared_version": None,
                    "exact_version": version,
                    "package_url": None,
                    "version_status": "exact_resolved",
                    "correlation_eligible": True,
                    "resolution": "lockfile",
                    "lockfile_match_status": "matched",
                    "manifest_type": "cargo_toml",
                    "lockfile_path": lockfile_path,
                    "lockfile_path_status": "reported",
                    "lockfile_type": "cargo_lock",
                }
            )
            added += 1
    return added


def _add_composer_transitive_lockfile_components(components: list[dict[str, Any]], result: dict[str, Any]) -> int:
    """Add exact local Composer resolutions without claiming Packagist origin."""

    matched_roots = {
        _project_root(_safe_text(component.get("manifest_path")))
        for component in components
        if component.get("ecosystem") == "composer"
        and component.get("lockfile_type") == "composer_lock"
        and component.get("lockfile_match_status") == "matched"
    }
    existing = {
        (_safe_text(component.get("name")), _safe_text(component.get("exact_version")))
        for component in components
        if component.get("ecosystem") == "composer"
    }
    added = 0
    for raw_lockfile in _as_list(result.get("parsed_lockfiles")):
        lockfile = _as_dict(raw_lockfile)
        if _safe_text(lockfile.get("lockfile_type")) != "composer_lock":
            continue
        lockfile_path, path_status = _safe_manifest_path(lockfile.get("path"))
        if lockfile_path is None or path_status != "reported" or _project_root(lockfile_path) not in matched_roots:
            continue
        for raw_package in _as_list(lockfile.get("packages")):
            package = _as_dict(raw_package)
            name = _normalize_registry_name("composer", _safe_text(package.get("name")))
            version = _safe_text(package.get("version"))
            if not name or not extract_exact_version(version, "composer") or (name, version) in existing:
                continue
            existing.add((name, version))
            group = _safe_text(package.get("dependency_group"))
            components.append({
                "id": _component_id(lockfile_path, "transitive", "composer", name, REGISTRY_SOURCE_TYPE, version),
                "ecosystem": "composer",
                "name": name,
                "manifest_path": f"{_project_root(lockfile_path)}/composer.json".lstrip("/"),
                "manifest_path_status": "reported",
                "dependency_group": group if group in {"require", "require-dev"} else "transitive",
                "dependency_scope": "transitive",
                "relationship_status": "not_reported",
                "source_type": REGISTRY_SOURCE_TYPE,
                "declared_version": None,
                "exact_version": version,
                "package_url": None,
                "version_status": "exact_resolved",
                "correlation_eligible": True,
                "resolution": "lockfile",
                "lockfile_match_status": "matched",
                "manifest_type": "composer_json",
                "lockfile_path": lockfile_path,
                "lockfile_path_status": "reported",
                "lockfile_type": "composer_lock",
            })
            added += 1
    return added


def _add_gradle_lockfile_components(components: list[dict[str, Any]], result: dict[str, Any]) -> int:
    """Represent a Gradle lock as an exact graph with unknown relationships."""

    manifest_by_root = {
        _project_root(path): path
        for item in _as_list(result.get("parsed_manifests"))
        if _safe_text(_as_dict(item).get("manifest_type")) == "gradle_build"
        for path, status in [_safe_manifest_path(_as_dict(item).get("path"))]
        if path is not None and status == "reported"
    }
    existing: set[tuple[str, str]] = set()
    added = 0
    for raw_lockfile in _as_list(result.get("parsed_lockfiles")):
        lockfile = _as_dict(raw_lockfile)
        if _safe_text(lockfile.get("lockfile_type")) != "gradle_lock":
            continue
        lockfile_path, status = _safe_manifest_path(lockfile.get("path"))
        if lockfile_path is None or status != "reported" or _project_root(lockfile_path) not in manifest_by_root:
            continue
        for raw_package in _as_list(lockfile.get("packages")):
            package = _as_dict(raw_package)
            name = _normalize_registry_name("maven", _safe_text(package.get("name")))
            version = _safe_text(package.get("version"))
            if not name or not extract_exact_version(version, "maven") or (name, version) in existing:
                continue
            existing.add((name, version))
            components.append({
                "id": _component_id(lockfile_path, "transitive", "maven", name, REGISTRY_SOURCE_TYPE, version),
                "ecosystem": "maven", "name": name,
                "manifest_path": manifest_by_root[_project_root(lockfile_path)],
                "manifest_path_status": "reported", "dependency_group": "locked",
                "dependency_scope": "transitive", "relationship_status": "not_reported",
                "source_type": REGISTRY_SOURCE_TYPE, "declared_version": None,
                "exact_version": version, "package_url": None,
                "version_status": "exact_resolved", "correlation_eligible": True,
                "resolution": "lockfile", "lockfile_match_status": "matched",
                "manifest_type": "gradle_build", "lockfile_path": lockfile_path,
                "lockfile_path_status": "reported", "lockfile_type": "gradle_lock",
            })
            added += 1
    return added


def _add_nuget_lockfile_components(components: list[dict[str, Any]], result: dict[str, Any]) -> tuple[int, int]:
    """Add resolved NuGet entries only for one unambiguous same-root project."""

    manifests_by_root: dict[str, list[str]] = {}
    for raw_manifest in _as_list(result.get("parsed_manifests")):
        manifest = _as_dict(raw_manifest)
        if _safe_text(manifest.get("manifest_type")) != "dotnet_project":
            continue
        path, status = _safe_manifest_path(manifest.get("path"))
        if path is not None and status == "reported":
            manifests_by_root.setdefault(_project_root(path), []).append(path)
    existing: set[tuple[str, str | None, str]] = set()
    lock_counts_by_root: dict[str, int] = {}
    for raw_lockfile in _as_list(result.get("parsed_lockfiles")):
        lockfile = _as_dict(raw_lockfile)
        if _safe_text(lockfile.get("lockfile_type")) != "nuget_packages_lock":
            continue
        path, status = _safe_manifest_path(lockfile.get("path"))
        if path is not None and status == "reported":
            root = _project_root(path)
            lock_counts_by_root[root] = lock_counts_by_root.get(root, 0) + 1
    transitive = 0
    unverified = 0
    for raw_lockfile in _as_list(result.get("parsed_lockfiles")):
        lockfile = _as_dict(raw_lockfile)
        if _safe_text(lockfile.get("lockfile_type")) != "nuget_packages_lock":
            continue
        lockfile_path, status = _safe_manifest_path(lockfile.get("path"))
        if lockfile_path is None or status != "reported":
            continue
        manifests = manifests_by_root.get(_project_root(lockfile_path), [])
        if len(manifests) != 1 or lock_counts_by_root.get(_project_root(lockfile_path)) != 1:
            continue
        for raw_package in _as_list(lockfile.get("packages")):
            package = _as_dict(raw_package)
            name = _normalize_registry_name("nuget", _safe_text(package.get("name")))
            raw_version = _safe_text(package.get("version"))
            version = extract_exact_version(raw_version, "nuget") if raw_version else None
            source_label = _safe_text(package.get("source_type"))
            scope_label = _safe_text(package.get("dependency_scope"))
            source_type = REGISTRY_SOURCE_TYPE if source_label == "unverified_registry" else source_label if source_label in {"local", "unknown"} else "unknown"
            if not name or (raw_version and version is None):
                continue
            dedupe = (name, version, source_type)
            if dedupe in existing:
                continue
            existing.add(dedupe)
            relationship_status = "reported" if scope_label in {"direct", "transitive"} else "not_reported"
            dependency_scope = scope_label if scope_label in {"direct", "transitive"} else "transitive"
            correlatable = source_type == REGISTRY_SOURCE_TYPE and version is not None
            components.append({
                "id": _component_id(lockfile_path, scope_label or "unknown", "nuget", name, source_type, version or "unknown"),
                "ecosystem": "nuget", "name": name,
                "manifest_path": manifests[0], "manifest_path_status": "reported",
                "dependency_group": "locked", "dependency_scope": dependency_scope,
                "relationship_status": relationship_status, "source_type": source_type,
                "declared_version": None, "exact_version": version,
                "package_url": None, "version_status": "exact_resolved" if correlatable else "not_correlatable",
                "correlation_eligible": correlatable, "resolution": "lockfile",
                "lockfile_match_status": "matched", "manifest_type": "dotnet_project",
                "lockfile_path": lockfile_path, "lockfile_path_status": "reported",
                "lockfile_type": "nuget_packages_lock",
            })
            if correlatable:
                unverified += 1
                if dependency_scope == "transitive":
                    transitive += 1
    return transitive, unverified


def _lockfile_coverage(result: dict[str, Any]) -> tuple[int, int, list[str]]:
    summary = _as_dict(result.get("summary"))
    parsed = _safe_non_negative_int(summary.get("lockfiles_parsed"))
    skipped = _safe_non_negative_int(summary.get("lockfiles_skipped"))
    safe_reasons = {
        "absolute_path",
        "entry_name_too_long",
        "lockfile_read_error",
        "lockfile_utf8_decode_error",
        "manifest_too_large",
        "npm_package_lock_json_parse_error",
        "npm_package_lock_packages_not_object",
        "npm_package_lock_root_not_object",
        "npm_package_lock_version_not_supported",
        "pnpm_lockfile_importers_not_object",
        "pnpm_lockfile_packages_not_object",
        "pnpm_lockfile_root_importer_not_object",
        "pnpm_lockfile_root_not_object",
        "pnpm_lockfile_version_not_supported",
        "pnpm_lockfile_yaml_feature_not_allowed",
        "pnpm_lockfile_yaml_parse_error",
        "pnpm_lockfile_yaml_token_limit",
        "yarn_classic_lockfile_grammar_not_supported",
        "yarn_classic_lockfile_line_limit",
        "yarn_classic_lockfile_version_not_supported",
        "yarn_lockfile_berry_not_supported",
        "poetry_lockfile_metadata_not_object",
        "poetry_lockfile_packages_not_array",
        "poetry_lockfile_parser_unavailable",
        "poetry_lockfile_root_not_object",
        "poetry_lockfile_toml_parse_error",
        "poetry_lockfile_version_not_supported",
        "pipfile_lock_dependency_group_not_object",
        "pipfile_lock_json_parse_error",
        "pipfile_lock_metadata_not_object",
        "pipfile_lock_root_not_object",
        "pipfile_lock_version_not_supported",
        "go_sum_line_limit",
        "go_sum_line_too_long",
        "cargo_lockfile_packages_not_array",
        "cargo_lockfile_parser_unavailable",
        "cargo_lockfile_root_not_object",
        "cargo_lockfile_toml_parse_error",
        "cargo_lockfile_version_not_supported",
        "composer_lockfile_json_parse_error",
        "composer_lockfile_packages_not_array",
        "composer_lockfile_root_not_object",
        "gradle_lockfile_line_limit",
        "gradle_lockfile_line_too_long",
        "nuget_lockfile_entry_limit",
        "nuget_lockfile_json_parse_error",
        "nuget_lockfile_root_not_object",
        "nuget_lockfile_target_limit",
        "nuget_lockfile_target_shape_invalid",
        "nuget_lockfile_targets_not_object",
        "nuget_lockfile_version_not_supported",
        "path_traversal",
        "total_manifest_bytes_limit",
        "too_many_lockfiles",
        "unsupported_lockfile_type",
    }
    reasons = sorted(
        {
            _safe_text(_as_dict(lockfile).get("reason"))
            for lockfile in _as_list(result.get("lockfiles"))
            if _safe_text(_as_dict(lockfile).get("reason")) in safe_reasons
        }
    )
    return parsed, skipped, reasons


def _apply_lockfile_resolutions(
    components: list[dict[str, Any]],
    result: dict[str, Any],
    workspace_manifest_paths: set[str],
) -> tuple[int, int]:
    """Attach exact direct versions only after one compatible same-root match.

    `package-lock.json` v2/v3 and Cargo.lock v3/v4 include narrow
    public-registry provenance contracts used by advisory egress. pnpm v9,
    Yarn Classic v1, Poetry 2.1, and Pipfile.lock v6
    yield local exact resolutions only: they can contain custom source data, so
    none becomes a public advisory identity or a transitive graph here.
    """

    lockfiles_by_root: dict[str, list[tuple[str, str, dict[str, str]]]] = {}
    for raw_lockfile in _as_list(result.get("parsed_lockfiles")):
        lockfile = _as_dict(raw_lockfile)
        lockfile_type = _safe_text(lockfile.get("lockfile_type"))
        if lockfile_type not in {"npm_package_lock", "pnpm_lock", "yarn_classic_lock", "poetry_lock", "pipfile_lock", "go_sum", "cargo_lock", "composer_lock"}:
            continue
        path, path_status = _safe_manifest_path(lockfile.get("path"))
        if path is None or path_status != "reported":
            continue
        if lockfile_type == "npm_package_lock":
            exact_packages = _unique_exact_npm_lockfile_packages(lockfile.get("packages"))
        elif lockfile_type == "pnpm_lock":
            exact_packages = _unique_exact_pnpm_lockfile_packages(lockfile.get("packages"))
        elif lockfile_type == "yarn_classic_lock":
            exact_packages = _unique_exact_yarn_classic_lockfile_packages(lockfile.get("packages"))
        elif lockfile_type == "poetry_lock":
            exact_packages = _unique_exact_poetry_lockfile_packages(lockfile.get("packages"))
        elif lockfile_type == "pipfile_lock":
            exact_packages = _unique_exact_pipfile_lockfile_packages(lockfile.get("packages"))
        elif lockfile_type == "go_sum":
            exact_packages = _unique_exact_go_sum_packages(lockfile.get("packages"))
        elif lockfile_type == "composer_lock":
            exact_packages = _unique_exact_composer_lockfile_packages(lockfile.get("packages"))
        else:
            exact_packages = _unique_exact_cargo_lockfile_packages(lockfile.get("packages"))
        lockfiles_by_root.setdefault(_project_root(path), []).append((path, lockfile_type, exact_packages))

    observed_lockfile_types_by_root: dict[str, list[str]] = {}
    for raw_lockfile in _as_list(result.get("lockfiles")):
        lockfile = _as_dict(raw_lockfile)
        path, path_status = _safe_manifest_path(lockfile.get("path"))
        lockfile_type = _safe_text(lockfile.get("lockfile_type"))
        if path is None or path_status != "reported" or not lockfile_type:
            continue
        observed_lockfile_types_by_root.setdefault(_project_root(path), []).append(lockfile_type)

    public_provenance_resolutions = 0
    unverified_resolutions = 0
    for component in components:
        compatible_lockfile_types = _component_lockfile_types(component)
        if not compatible_lockfile_types:
            continue
        if component["source_type"] != REGISTRY_SOURCE_TYPE or component["manifest_path_status"] != "reported":
            continue
        manifest_path = component["manifest_path"]
        if not isinstance(manifest_path, str):
            continue
        root = _project_root(manifest_path)
        candidates = [candidate for candidate in lockfiles_by_root.get(root, []) if candidate[1] in compatible_lockfile_types]
        observed_types = [lockfile_type for lockfile_type in observed_lockfile_types_by_root.get(root, []) if lockfile_type in compatible_lockfile_types]
        match_status = _lockfile_match_status(
            candidates=candidates,
            observed_lockfile_types=observed_types,
            workspace_declared=component["ecosystem"] == "npm" and manifest_path in workspace_manifest_paths,
        )
        component["lockfile_match_status"] = match_status
        if match_status != "matched":
            continue
        lockfile_path, lockfile_type, packages = candidates[0]
        if lockfile_type == "yarn_classic_lock":
            package_key = _yarn_classic_selector_id(component["name"], _safe_text(component.get("declared_version")))
        elif lockfile_type == "pipfile_lock":
            package_key = f"{component['dependency_group']}\0{component['name']}"
        else:
            package_key = component["name"]
        version = packages.get(package_key)
        if not version:
            continue
        component.update(
            {
                "exact_version": version,
                "version_status": "exact_resolved",
                "correlation_eligible": lockfile_type in {"npm_package_lock", "cargo_lock"} or component["ecosystem"] in {"go", "composer"},
                "resolution": "lockfile",
                "lockfile_path": lockfile_path,
                "lockfile_path_status": "reported",
                "lockfile_type": lockfile_type,
            }
        )
        if lockfile_type in {"npm_package_lock", "cargo_lock"}:
            public_provenance_resolutions += 1
        else:
            unverified_resolutions += 1
    return public_provenance_resolutions, unverified_resolutions


def _component_lockfile_types(component: dict[str, Any]) -> set[str]:
    if component.get("ecosystem") == "npm" and component.get("manifest_type") == "package_json":
        return {"npm_package_lock", "pnpm_lock", "yarn_classic_lock"}
    if component.get("ecosystem") == "pypi" and component.get("manifest_type") == "pyproject_toml":
        return {"poetry_lock"}
    if component.get("ecosystem") == "pypi" and component.get("manifest_type") == "pipfile":
        return {"pipfile_lock"}
    if component.get("ecosystem") == "go" and component.get("manifest_type") == "go_mod":
        return {"go_sum"}
    if component.get("ecosystem") == "cargo" and component.get("manifest_type") == "cargo_toml":
        return {"cargo_lock"}
    if component.get("ecosystem") == "composer" and component.get("manifest_type") == "composer_json":
        return {"composer_lock"}
    return set()


def _lockfile_match_status(
    *,
    candidates: list[tuple[str, str, dict[str, str]]],
    observed_lockfile_types: list[str],
    workspace_declared: bool,
) -> str:
    """Classify a manifest/lockfile relation without inferring a package version."""

    if workspace_declared:
        return "ambiguous"
    if observed_lockfile_types:
        if len(observed_lockfile_types) != 1:
            return "ambiguous"
        if len(candidates) == 1 and candidates[0][1] == observed_lockfile_types[0]:
            return "matched"
        return "ambiguous" if len(candidates) > 1 else "not_matched"
    if len(candidates) == 1:
        # Retained pre-2026-09-05.3 results may have parsed lockfiles but not
        # the accompanying coverage records; preserve a safe compatibility path.
        return "matched"
    return "ambiguous" if len(candidates) > 1 else "not_matched"


def _unique_exact_npm_lockfile_packages(value: Any) -> dict[str, str]:
    versions_by_name: dict[str, set[str]] = {}
    for raw_package in _as_list(value):
        package = _as_dict(raw_package)
        name = _normalize_registry_name("npm", _safe_text(package.get("name")))
        version = _safe_text(package.get("version"))
        if not name or not extract_exact_version(version, "npm") or _safe_text(package.get("source_type")) != REGISTRY_SOURCE_TYPE:
            continue
        versions_by_name.setdefault(name, set()).add(version)
    return {name: next(iter(versions)) for name, versions in versions_by_name.items() if len(versions) == 1}


def _unique_exact_pnpm_lockfile_packages(value: Any) -> dict[str, str]:
    """Use only the runner's already-trimmed exact direct pnpm records."""

    versions_by_name: dict[str, set[str]] = {}
    for raw_package in _as_list(value):
        package = _as_dict(raw_package)
        name = _normalize_registry_name("npm", _safe_text(package.get("name")))
        version = _safe_text(package.get("version"))
        if not name or not extract_exact_version(version, "npm") or _safe_text(package.get("source_type")) != "unverified_registry":
            continue
        versions_by_name.setdefault(name, set()).add(version)
    return {name: next(iter(versions)) for name, versions in versions_by_name.items() if len(versions) == 1}


def _unique_exact_yarn_classic_lockfile_packages(value: Any) -> dict[str, str]:
    """Use only opaque selector records from the runner's Classic v1 parser."""

    versions_by_selector: dict[str, set[str]] = {}
    for raw_package in _as_list(value):
        package = _as_dict(raw_package)
        name = _normalize_registry_name("npm", _safe_text(package.get("name")))
        selector_id = _safe_text(package.get("selector_id"))
        version = _safe_text(package.get("version"))
        if (
            not name
            or not _is_opaque_yarn_selector_id(selector_id)
            or not extract_exact_version(version, "npm")
            or _safe_text(package.get("source_type")) != "unverified_registry"
        ):
            continue
        versions_by_selector.setdefault(selector_id, set()).add(version)
    return {selector_id: next(iter(versions)) for selector_id, versions in versions_by_selector.items() if len(versions) == 1}


def _unique_exact_poetry_lockfile_packages(value: Any) -> dict[str, str]:
    """Use only name/version records already stripped by the Poetry parser."""

    versions_by_name: dict[str, set[str]] = {}
    for raw_package in _as_list(value):
        package = _as_dict(raw_package)
        name = _normalize_registry_name("pypi", _safe_text(package.get("name")))
        version = _safe_text(package.get("version"))
        if (
            not name
            or not extract_exact_version(f"=={version}", "pypi")
            or _safe_text(package.get("source_type")) != "unverified_registry"
        ):
            continue
        versions_by_name.setdefault(name, set()).add(version)
    return {name: next(iter(versions)) for name, versions in versions_by_name.items() if len(versions) == 1}


def _unique_exact_pipfile_lockfile_packages(value: Any) -> dict[str, str]:
    """Use only grouped name/version records stripped by the v6 parser."""

    versions_by_group_name: dict[str, set[str]] = {}
    for raw_package in _as_list(value):
        package = _as_dict(raw_package)
        name = _normalize_registry_name("pypi", _safe_text(package.get("name")))
        version = _safe_text(package.get("version"))
        group = _safe_text(package.get("dependency_group"))
        if (
            not name
            or group not in {"packages", "dev-packages"}
            or not extract_exact_version(f"=={version}", "pypi")
            or _safe_text(package.get("source_type")) != "unverified_registry"
        ):
            continue
        versions_by_group_name.setdefault(f"{group}\0{name}", set()).add(version)
    return {key: next(iter(versions)) for key, versions in versions_by_group_name.items() if len(versions) == 1}


def _unique_exact_go_sum_packages(value: Any) -> dict[str, str]:
    versions_by_name: dict[str, set[str]] = {}
    for raw_package in _as_list(value):
        package = _as_dict(raw_package)
        name = _normalize_registry_name("go", _safe_text(package.get("name")))
        version = _safe_text(package.get("version"))
        if (
            not name
            or not extract_exact_version(version, "go")
            or _safe_text(package.get("source_type")) != "unverified_registry"
        ):
            continue
        versions_by_name.setdefault(name, set()).add(version)
    return {name: next(iter(versions)) for name, versions in versions_by_name.items() if len(versions) == 1}


def _unique_exact_cargo_lockfile_packages(value: Any) -> dict[str, str]:
    versions_by_name: dict[str, set[str]] = {}
    for raw_package in _as_list(value):
        package = _as_dict(raw_package)
        name = _normalize_registry_name("cargo", _safe_text(package.get("name")))
        version = _safe_text(package.get("version"))
        if not name or not extract_exact_version(version, "cargo") or _safe_text(package.get("source_type")) != REGISTRY_SOURCE_TYPE:
            continue
        versions_by_name.setdefault(name, set()).add(version)
    return {name: next(iter(versions)) for name, versions in versions_by_name.items() if len(versions) == 1}


def _unique_exact_composer_lockfile_packages(value: Any) -> dict[str, str]:
    versions_by_name: dict[str, set[str]] = {}
    for raw_package in _as_list(value):
        package = _as_dict(raw_package)
        name = _normalize_registry_name("composer", _safe_text(package.get("name")))
        version = _safe_text(package.get("version"))
        if not name or not extract_exact_version(version, "composer"):
            continue
        versions_by_name.setdefault(name, set()).add(version)
    return {name: next(iter(versions)) for name, versions in versions_by_name.items() if len(versions) == 1}


def _yarn_classic_selector_id(name: str, specifier: str) -> str:
    return hashlib.sha256(f"{name}\0{specifier}".encode("utf-8")).hexdigest()[:24]


def _is_opaque_yarn_selector_id(value: str) -> bool:
    return len(value) == 24 and all(character in "0123456789abcdef" for character in value)


def _project_root(path: str) -> str:
    return path.rsplit("/", 1)[0] if "/" in path else ""


def _normalize_registry_name(ecosystem: str, name: str) -> str:
    if ecosystem == "npm":
        return name if is_valid_npm_name(name) else ""
    if ecosystem == "pypi":
        return canonicalize_python_name(name) if is_valid_pypi_name(name) else ""
    if ecosystem == "go":
        return name if is_valid_go_module_name(name) else ""
    if ecosystem == "cargo":
        return name if is_valid_cargo_name(name) else ""
    if ecosystem == "composer":
        return name if is_valid_composer_name(name) else ""
    if ecosystem == "maven":
        return name if is_valid_maven_name(name) else ""
    if ecosystem == "nuget":
        return name if is_valid_nuget_name(name) else ""
    return ""


def _safe_manifest_path(value: Any) -> tuple[str | None, str]:
    raw_path = _safe_text(value)
    if not raw_path:
        return None, "not_reported"
    path = normalize_project_relative_path(raw_path)
    if path is None:
        return None, "withheld_unsafe_path"
    return path, "reported"


def _component_id(
    manifest_path: str | None,
    dependency_group: str,
    ecosystem: str,
    name: str,
    source_type: str,
    specifier: str,
) -> str:
    stable_payload = json.dumps(
        [manifest_path, dependency_group, ecosystem, name, source_type, specifier],
        ensure_ascii=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(stable_payload.encode("utf-8")).hexdigest()


def _safe_non_negative_int(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else 0


def _safe_text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []
