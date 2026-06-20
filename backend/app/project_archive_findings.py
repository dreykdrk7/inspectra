from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any


@dataclass(frozen=True)
class ProjectArchiveFindingMetadata:
    category: str
    category_label: str
    ecosystem: str
    ecosystem_label: str


PROJECT_ARCHIVE_ECOSYSTEM_LABELS = {
    "python_requirements": "Python / requirements",
    "node_package": "Node / package.json",
    "docker_compose": "Docker / Compose",
    "ci_cd": "CI/CD",
    "framework_config": "Framework/config",
    "generic_project_metadata": "Generic project metadata",
    "unknown_ecosystem": "Unknown ecosystem",
}


UNKNOWN_ECOSYSTEM = "unknown_ecosystem"
GENERIC_PROJECT_METADATA_ECOSYSTEM = "generic_project_metadata"


def project_archive_finding_metadata_record(
    category: str,
    category_label: str,
    ecosystem: str = UNKNOWN_ECOSYSTEM,
) -> ProjectArchiveFindingMetadata:
    return ProjectArchiveFindingMetadata(
        category=category,
        category_label=category_label,
        ecosystem=ecosystem,
        ecosystem_label=PROJECT_ARCHIVE_ECOSYSTEM_LABELS[ecosystem],
    )


UNCATEGORIZED_PROJECT_ARCHIVE_FINDING = ProjectArchiveFindingMetadata(
    category="uncategorized_review_indicator",
    category_label="Uncategorized review indicator",
    ecosystem=UNKNOWN_ECOSYSTEM,
    ecosystem_label=PROJECT_ARCHIVE_ECOSYSTEM_LABELS[UNKNOWN_ECOSYSTEM],
)


PROJECT_ARCHIVE_FINDING_METADATA: dict[str, ProjectArchiveFindingMetadata] = {
    "dependency_not_exactly_pinned": project_archive_finding_metadata_record("dependency_hygiene", "Dependency hygiene"),
    "requirements_dependency_not_exactly_pinned": project_archive_finding_metadata_record(
        "dependency_hygiene",
        "Dependency hygiene",
        "python_requirements",
    ),
    "dependency_broad_range": project_archive_finding_metadata_record("dependency_hygiene", "Dependency hygiene"),
    "requirements_option_present": project_archive_finding_metadata_record(
        "dependency_hygiene",
        "Dependency hygiene",
        "python_requirements",
    ),
    "dependency_external_or_local_source": project_archive_finding_metadata_record(
        "dependency_source_review",
        "Dependency source review",
    ),
    "requirements_custom_index": project_archive_finding_metadata_record(
        "dependency_source_review",
        "Dependency source review",
        "python_requirements",
    ),
    "requirements_editable_install": project_archive_finding_metadata_record(
        "dependency_source_review",
        "Dependency source review",
        "python_requirements",
    ),
    "package_scripts_present": project_archive_finding_metadata_record(
        "package_script_review",
        "Package script review",
        "node_package",
    ),
    "package_sensitive_lifecycle_script": project_archive_finding_metadata_record(
        "package_script_review",
        "Package script review",
        "node_package",
    ),
    "project_archive_multiple_ecosystems": project_archive_finding_metadata_record(
        "ecosystem_inventory",
        "Ecosystem inventory",
        GENERIC_PROJECT_METADATA_ECOSYSTEM,
    ),
    "project_archive_manifest_parse_error": project_archive_finding_metadata_record(
        "manifest_parse_limits",
        "Manifest parsing and limits",
    ),
    "project_archive_manifest_read_error": project_archive_finding_metadata_record(
        "manifest_parse_limits",
        "Manifest parsing and limits",
    ),
    "project_archive_manifest_decode_error": project_archive_finding_metadata_record(
        "manifest_parse_limits",
        "Manifest parsing and limits",
    ),
    "project_archive_manifest_too_large": project_archive_finding_metadata_record(
        "manifest_parse_limits",
        "Manifest parsing and limits",
    ),
    "project_archive_too_many_supported_manifests": project_archive_finding_metadata_record(
        "manifest_parse_limits",
        "Manifest parsing and limits",
    ),
    "project_archive_total_manifest_bytes_limit": project_archive_finding_metadata_record(
        "manifest_parse_limits",
        "Manifest parsing and limits",
    ),
    "project_archive_entry_name_too_long": project_archive_finding_metadata_record(
        "manifest_parse_limits",
        "Manifest parsing and limits",
        GENERIC_PROJECT_METADATA_ECOSYSTEM,
    ),
    "project_archive_entry_limit_reached": project_archive_finding_metadata_record(
        "archive_safety_metadata",
        "Archive safety metadata",
        GENERIC_PROJECT_METADATA_ECOSYSTEM,
    ),
    "project_archive_path_traversal": project_archive_finding_metadata_record(
        "archive_safety_metadata",
        "Archive safety metadata",
        GENERIC_PROJECT_METADATA_ECOSYSTEM,
    ),
    "project_archive_absolute_path": project_archive_finding_metadata_record(
        "archive_safety_metadata",
        "Archive safety metadata",
        GENERIC_PROJECT_METADATA_ECOSYSTEM,
    ),
    "project_archive_manifest_not_regular_file": project_archive_finding_metadata_record(
        "archive_safety_metadata",
        "Archive safety metadata",
        GENERIC_PROJECT_METADATA_ECOSYSTEM,
    ),
    "project_archive_zip_entry_limit_preflight": project_archive_finding_metadata_record(
        "archive_safety_metadata",
        "Archive safety metadata",
        GENERIC_PROJECT_METADATA_ECOSYSTEM,
    ),
    "project_archive_zip_central_directory_too_large": project_archive_finding_metadata_record(
        "archive_safety_metadata",
        "Archive safety metadata",
        GENERIC_PROJECT_METADATA_ECOSYSTEM,
    ),
    "project_archive_zip64_metadata_requires_review": project_archive_finding_metadata_record(
        "archive_safety_metadata",
        "Archive safety metadata",
        GENERIC_PROJECT_METADATA_ECOSYSTEM,
    ),
    "project_archive_multidisk_zip_unsupported": project_archive_finding_metadata_record(
        "archive_safety_metadata",
        "Archive safety metadata",
        GENERIC_PROJECT_METADATA_ECOSYSTEM,
    ),
    "project_archive_zip_metadata_preflight_unavailable": project_archive_finding_metadata_record(
        "archive_safety_metadata",
        "Archive safety metadata",
        GENERIC_PROJECT_METADATA_ECOSYSTEM,
    ),
}


CONTEXTUAL_ECOSYSTEM_FINDING_IDS = {
    "dependency_not_exactly_pinned",
    "dependency_broad_range",
    "dependency_external_or_local_source",
    "project_archive_manifest_parse_error",
    "project_archive_manifest_read_error",
    "project_archive_manifest_decode_error",
    "project_archive_manifest_too_large",
}


def project_archive_finding_metadata(
    finding_id: str | None,
    *,
    evidence: str | None = None,
    path: str | None = None,
    manifest_type: str | None = None,
) -> ProjectArchiveFindingMetadata:
    if finding_id:
        metadata = PROJECT_ARCHIVE_FINDING_METADATA.get(finding_id, UNCATEGORIZED_PROJECT_ARCHIVE_FINDING)
    else:
        metadata = UNCATEGORIZED_PROJECT_ARCHIVE_FINDING

    if finding_id not in CONTEXTUAL_ECOSYSTEM_FINDING_IDS:
        return metadata

    ecosystem = infer_project_archive_ecosystem(evidence=evidence, path=path, manifest_type=manifest_type)
    if not ecosystem:
        return metadata
    return replace(metadata, ecosystem=ecosystem, ecosystem_label=PROJECT_ARCHIVE_ECOSYSTEM_LABELS[ecosystem])


def categorize_project_archive_finding(
    value: Any,
    *,
    context_path: str | None = None,
    context_manifest_type: str | None = None,
) -> Any:
    if not isinstance(value, dict):
        return value
    finding = dict(value)
    metadata = project_archive_finding_metadata(
        str(finding.get("id") or ""),
        evidence=str(finding.get("evidence") or ""),
        path=context_path,
        manifest_type=context_manifest_type,
    )
    finding["category"] = metadata.category
    finding["category_label"] = metadata.category_label
    finding["ecosystem"] = metadata.ecosystem
    finding["ecosystem_label"] = metadata.ecosystem_label
    return finding


def categorize_project_archive_result(result: dict[str, Any]) -> dict[str, Any]:
    categorized = dict(result)
    categorized["findings"] = [categorize_project_archive_finding(item) for item in as_list(result.get("findings"))]

    parsed_manifests: list[Any] = []
    for item in as_list(result.get("parsed_manifests")):
        if not isinstance(item, dict):
            parsed_manifests.append(item)
            continue
        parsed_manifest = dict(item)
        parsed_manifest["findings"] = [
            categorize_project_archive_finding(
                finding,
                context_path=str(item.get("path") or ""),
                context_manifest_type=str(item.get("manifest_type") or ""),
            )
            for finding in as_list(item.get("findings"))
        ]
        parsed_manifests.append(parsed_manifest)
    if "parsed_manifests" in result:
        categorized["parsed_manifests"] = parsed_manifests

    categorized["ecosystem_summary"] = summarize_project_archive_ecosystems(
        categorized["findings"] or [finding for item in parsed_manifests for finding in as_list(as_dict(item).get("findings"))]
    )
    return categorized


def infer_project_archive_ecosystem(
    *,
    evidence: str | None = None,
    path: str | None = None,
    manifest_type: str | None = None,
) -> str | None:
    values = " ".join(value for value in (path, manifest_type, evidence) if value)
    normalized = values.replace("\\", "/").lower()
    if not normalized:
        return None
    if any(marker in normalized for marker in ("package.json", "package-lock.json", "package_json", "package-lock")):
        return "node_package"
    if any(marker in normalized for marker in ("requirements.txt", "requirements_txt", "pyproject.toml", "pyproject_toml")):
        return "python_requirements"
    if any(marker in normalized for marker in ("docker-compose.yml", "docker-compose.yaml", "compose.yaml", "compose.yml")):
        return "docker_compose"
    if any(marker in normalized for marker in (".github/workflows/", ".gitlab-ci.yml", "circleci/config.yml", "jenkinsfile")):
        return "ci_cd"
    if any(marker in normalized for marker in ("vite.config.", "next.config.", "nuxt.config.", "django", "settings.py")):
        return "framework_config"
    return None


def summarize_project_archive_ecosystems(findings: list[Any]) -> list[dict[str, Any]]:
    counts: dict[str, dict[str, Any]] = {}
    for item in findings:
        record = as_dict(item)
        if not record:
            continue
        ecosystem = str(record.get("ecosystem") or UNKNOWN_ECOSYSTEM)
        ecosystem_label = str(
            record.get("ecosystem_label") or PROJECT_ARCHIVE_ECOSYSTEM_LABELS.get(ecosystem, PROJECT_ARCHIVE_ECOSYSTEM_LABELS[UNKNOWN_ECOSYSTEM])
        )
        counts.setdefault(
            ecosystem,
            {
                "ecosystem": ecosystem,
                "ecosystem_label": ecosystem_label,
                "findings_count": 0,
            },
        )["findings_count"] += 1
    return sorted(
        counts.values(),
        key=lambda item: (item["ecosystem"] == UNKNOWN_ECOSYSTEM, item["ecosystem_label"]),
    )


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []
