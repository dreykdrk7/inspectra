"""Strict, offline normalization for immutable CycloneDX and SPDX JSON."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Literal
from urllib.parse import unquote

from app.version_matching import is_supported_maven_version


MAX_SBOM_COMPONENTS = 2_000
MAX_SBOM_RELATIONSHIPS = 10_000
SBOM_IMPORT_CONTRACT_VERSION = "2026-09-10.1"
_EXACT_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+_~-]{0,127}$")
_NPM_NAME = re.compile(r"^(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*$")
_PYPI_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
_MAVEN_PART = re.compile(r"^[a-z0-9][a-z0-9._-]*$")


class SbomImportError(ValueError):
    pass


def normalize_sbom(payload: bytes, *, public_identities_confirmed: bool) -> dict[str, Any]:
    try:
        document = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SbomImportError("invalid_json") from exc
    if not isinstance(document, dict):
        raise SbomImportError("invalid_document")
    if document.get("bomFormat") == "CycloneDX":
        source_format: Literal["cyclonedx", "spdx"] = "cyclonedx"
        version = document.get("specVersion")
        if version not in {"1.4", "1.5", "1.6"}:
            raise SbomImportError("unsupported_cyclonedx_version")
        source_spec_version = version
        raw_components = document.get("components")
        if not isinstance(raw_components, list):
            raise SbomImportError("missing_components")
        raw_dependencies = document.get("dependencies")
        relationships = raw_dependencies if isinstance(raw_dependencies, list) else []
        root = document.get("metadata", {}).get("component") if isinstance(document.get("metadata"), dict) else None
        root_ref = root.get("bom-ref") if isinstance(root, dict) and isinstance(root.get("bom-ref"), str) else None
        adjacency: dict[str, set[str]] = {}
        for relationship in relationships[:MAX_SBOM_RELATIONSHIPS]:
            if not isinstance(relationship, dict) or not isinstance(relationship.get("ref"), str):
                continue
            depends_on = relationship.get("dependsOn")
            if isinstance(depends_on, list):
                adjacency.setdefault(relationship["ref"], set()).update(
                    item for item in depends_on if isinstance(item, str) and len(item) <= 512
                )
        relationship_graph_truncated = len(relationships) > MAX_SBOM_RELATIONSHIPS
        depths = _reachable_depths({root_ref} if root_ref is not None else set(), adjacency)
        raw_identities = [
            (
                component.get("purl"),
                "direct" if depths.get(component.get("bom-ref")) == 1 else "transitive",
                _relationship_status(component.get("bom-ref"), depths, relationship_graph_truncated),
            )
            for component in raw_components
            if isinstance(component, dict)
        ]
    elif isinstance(document.get("spdxVersion"), str):
        source_format = "spdx"
        if document.get("spdxVersion") not in {"SPDX-2.2", "SPDX-2.3"}:
            raise SbomImportError("unsupported_spdx_version")
        source_spec_version = document["spdxVersion"]
        packages = document.get("packages")
        if not isinstance(packages, list):
            raise SbomImportError("missing_packages")
        package_purls: dict[str, str | None] = {}
        for package in packages:
            refs = package.get("externalRefs") if isinstance(package, dict) else None
            purl = None
            for ref in refs if isinstance(refs, list) else []:
                if (
                    isinstance(ref, dict)
                    and str(ref.get("referenceType", "")).lower() == "purl"
                    and isinstance(ref.get("referenceLocator"), str)
                ):
                    purl = ref["referenceLocator"]
                    break
            package_id = package.get("SPDXID") if isinstance(package, dict) else None
            if isinstance(package_id, str) and len(package_id) <= 512:
                package_purls[package_id] = purl
        raw_relationships = document.get("relationships")
        relationships = raw_relationships if isinstance(raw_relationships, list) else []
        root_refs: set[str] = set()
        for relationship in relationships[:MAX_SBOM_RELATIONSHIPS]:
            if not isinstance(relationship, dict):
                continue
            if (
                str(relationship.get("relationshipType", "")).upper() == "DESCRIBES"
                and relationship.get("spdxElementId") == "SPDXRef-DOCUMENT"
                and isinstance(relationship.get("relatedSpdxElement"), str)
            ):
                root_refs.add(relationship["relatedSpdxElement"])
        adjacency = {}
        for relationship in relationships[:MAX_SBOM_RELATIONSHIPS]:
            if not isinstance(relationship, dict) or str(relationship.get("relationshipType", "")).upper() != "DEPENDS_ON":
                continue
            source_ref = relationship.get("spdxElementId")
            target_ref = relationship.get("relatedSpdxElement")
            if isinstance(source_ref, str) and isinstance(target_ref, str) and len(source_ref) <= 512 and len(target_ref) <= 512:
                adjacency.setdefault(source_ref, set()).add(target_ref)
        relationship_graph_truncated = len(relationships) > MAX_SBOM_RELATIONSHIPS
        depths = _reachable_depths(root_refs | {"SPDXRef-DOCUMENT"}, adjacency)
        raw_identities = [
            (
                purl,
                "direct" if depths.get(package_id) == 1 else "transitive",
                _relationship_status(package_id, depths, relationship_graph_truncated),
            )
            for package_id, purl in package_purls.items()
        ]
    else:
        raise SbomImportError("unsupported_format")

    truncated = len(raw_identities) > MAX_SBOM_COMPONENTS
    components: list[dict[str, Any]] = []
    positions: dict[tuple[str, str, str], int] = {}
    rejected = 0
    for raw_purl, dependency_scope, relationship_status in raw_identities[:MAX_SBOM_COMPONENTS]:
        identity = _minimal_purl_identity(raw_purl)
        if identity is None:
            rejected += 1
            continue
        ecosystem, name, version, canonical_purl = identity
        key = (ecosystem, name, version)
        if key in positions:
            existing = components[positions[key]]
            if _scope_evidence_priority(dependency_scope, relationship_status) > _scope_evidence_priority(
                existing["dependency_scope"], existing["relationship_status"]
            ):
                components[positions[key]]["dependency_scope"] = dependency_scope
                components[positions[key]]["relationship_status"] = relationship_status
            continue
        positions[key] = len(components)
        eligible = public_identities_confirmed
        components.append(
            {
                "id": hashlib.sha256(f"sbom-v1\0{ecosystem}\0{name}\0{version}".encode("utf-8")).hexdigest(),
                "ecosystem": ecosystem,
                "name": name,
                "manifest_path": None,
                "manifest_path_status": "not_reported",
                "dependency_group": "sbom",
                "source_type": "registry",
                "declared_version": version,
                "exact_version": version,
                "package_url": canonical_purl,
                "dependency_scope": dependency_scope,
                "relationship_status": relationship_status,
                "version_status": "exact_resolved",
                "correlation_eligible": eligible,
                "resolution": "lockfile",
                "lockfile_match_status": "matched" if eligible else "not_matched",
                "manifest_type": source_format,
                "lockfile_path": None,
                "lockfile_path_status": "not_reported",
                "lockfile_type": None,
            }
        )
    return {
        "contract_version": SBOM_IMPORT_CONTRACT_VERSION,
        "format": source_format,
        "spec_version": source_spec_version,
        "input_components": len(raw_identities),
        "input_relationships": len(relationships),
        "retained_components": len(components),
        "rejected_or_ambiguous_components": rejected + max(0, len(raw_identities) - MAX_SBOM_COMPONENTS),
        "truncated": truncated,
        "relationship_graph_truncated": relationship_graph_truncated,
        "public_identities_confirmed": public_identities_confirmed,
        "components": components,
    }


def sbom_project_result(normalized: dict[str, Any]) -> dict[str, Any]:
    components = normalized["components"]
    eligible = sum(item["correlation_eligible"] is True for item in components)
    return {
        "analyzer": "sbom_import",
        "sbom_import_contract_version": normalized["contract_version"],
        "sbom_format": normalized["format"],
        "normalized_findings": [],
        "component_inventory_contract_version": "2026-09-10.1",
        "component_inventory": components,
        "component_inventory_summary": {
            "total_components": len(components),
            "exact_registry_components": eligible,
            "resolved_registry_components": len(components),
            "unverified_lockfile_components": len(components) - eligible,
            "transitive_registry_components": sum(item["dependency_scope"] == "transitive" for item in components),
            "relationship_reported_components": sum(item["relationship_status"] == "reported" for item in components),
            "relationship_not_reported_components": sum(item["relationship_status"] == "not_reported" for item in components),
            "relationship_truncated_components": sum(item["relationship_status"] == "truncated" for item in components),
            "optional_registry_components": 0,
            "matched_lockfile_components": eligible,
            "unmatched_lockfile_components": len(components) - eligible,
            "ambiguous_lockfile_components": normalized["rejected_or_ambiguous_components"],
            "declared_range_components": 0,
            "not_correlatable_components": len(components) - eligible,
            "parsed_manifest_count": 1,
            "supported_manifest_count": 1,
            "skipped_manifest_count": 0,
            "result_truncated": normalized["truncated"],
            "parsed_lockfile_count": 0,
            "skipped_lockfile_count": 0,
            "skipped_lockfile_reasons": [],
            "lockfile_graph_truncated": normalized["relationship_graph_truncated"],
            "resolution": "declared_and_lockfile",
        },
        "summary": {
            "total_entries_seen": normalized["input_components"],
            "supported_manifests_found": 1,
            "supported_manifests_parsed": 1,
            "unsupported_manifests_detected": 0,
            "lockfiles_detected": 0,
            "lockfiles_parsed": 0,
            "total_dependencies": len(components),
            "truncated": normalized["truncated"],
            "sbom_rejected_or_ambiguous": normalized["rejected_or_ambiguous_components"],
        },
    }


def _reachable_depths(roots: set[str], adjacency: dict[str, set[str]]) -> dict[str, int]:
    """Return shortest demonstrated dependency distance under the bounded graph."""

    depths = {root: 0 for root in roots if isinstance(root, str)}
    queue = list(depths)
    while queue:
        current = queue.pop(0)
        for target in adjacency.get(current, set()):
            next_depth = depths[current] + 1
            if target in depths and depths[target] <= next_depth:
                continue
            depths[target] = next_depth
            queue.append(target)
    return depths


def _relationship_status(reference: Any, depths: dict[str, int], truncated: bool) -> str:
    if truncated:
        return "truncated"
    if isinstance(reference, str) and depths.get(reference, 0) >= 1:
        return "reported"
    return "not_reported"


def _scope_evidence_priority(scope: str, relationship_status: str) -> int:
    if relationship_status == "reported":
        return 2 if scope == "direct" else 1
    return 0


def _minimal_purl_identity(raw: Any) -> tuple[str, str, str, str] | None:
    if not isinstance(raw, str) or len(raw) > 512 or "?" in raw or "#" in raw:
        return None
    match = re.fullmatch(r"pkg:(npm|pypi|maven)/(.+)@([^/@]+)", raw)
    if match is None:
        return None
    ecosystem = match.group(1)
    try:
        decoded_name = unquote(match.group(2))
        name = decoded_name.lower()
        version = unquote(match.group(3))
    except (UnicodeDecodeError, ValueError):
        return None
    if any(ord(character) < 32 for character in name + version):
        return None
    if ecosystem == "maven":
        if decoded_name != name:
            return None
        path_parts = name.split("/")
        if (
            len(path_parts) != 2 or any(len(part) > limit for part, limit in zip(path_parts, (200, 120)))
            or any(_MAVEN_PART.fullmatch(part) is None for part in path_parts)
            or not is_supported_maven_version(version)
        ):
            return None
        coordinate = f"{path_parts[0]}:{path_parts[1]}"
        return ecosystem, coordinate, version, f"pkg:maven/{path_parts[0]}/{path_parts[1]}@{version}"
    if not _EXACT_VERSION.fullmatch(version):
        return None
    validator = _NPM_NAME if ecosystem == "npm" else _PYPI_NAME
    if not validator.fullmatch(name):
        return None
    return ecosystem, name, version, f"pkg:{ecosystem}/{name}@{version}"
