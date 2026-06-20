from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ProjectArchiveFindingMetadata:
    category: str
    category_label: str


UNCATEGORIZED_PROJECT_ARCHIVE_FINDING = ProjectArchiveFindingMetadata(
    category="uncategorized_review_indicator",
    category_label="Uncategorized review indicator",
)


PROJECT_ARCHIVE_FINDING_METADATA: dict[str, ProjectArchiveFindingMetadata] = {
    "dependency_not_exactly_pinned": ProjectArchiveFindingMetadata("dependency_hygiene", "Dependency hygiene"),
    "requirements_dependency_not_exactly_pinned": ProjectArchiveFindingMetadata("dependency_hygiene", "Dependency hygiene"),
    "dependency_broad_range": ProjectArchiveFindingMetadata("dependency_hygiene", "Dependency hygiene"),
    "requirements_option_present": ProjectArchiveFindingMetadata("dependency_hygiene", "Dependency hygiene"),
    "dependency_external_or_local_source": ProjectArchiveFindingMetadata("dependency_source_review", "Dependency source review"),
    "requirements_custom_index": ProjectArchiveFindingMetadata("dependency_source_review", "Dependency source review"),
    "requirements_editable_install": ProjectArchiveFindingMetadata("dependency_source_review", "Dependency source review"),
    "package_scripts_present": ProjectArchiveFindingMetadata("package_script_review", "Package script review"),
    "package_sensitive_lifecycle_script": ProjectArchiveFindingMetadata("package_script_review", "Package script review"),
    "project_archive_multiple_ecosystems": ProjectArchiveFindingMetadata("ecosystem_inventory", "Ecosystem inventory"),
    "project_archive_manifest_parse_error": ProjectArchiveFindingMetadata("manifest_parse_limits", "Manifest parsing and limits"),
    "project_archive_manifest_read_error": ProjectArchiveFindingMetadata("manifest_parse_limits", "Manifest parsing and limits"),
    "project_archive_manifest_decode_error": ProjectArchiveFindingMetadata("manifest_parse_limits", "Manifest parsing and limits"),
    "project_archive_manifest_too_large": ProjectArchiveFindingMetadata("manifest_parse_limits", "Manifest parsing and limits"),
    "project_archive_too_many_supported_manifests": ProjectArchiveFindingMetadata(
        "manifest_parse_limits",
        "Manifest parsing and limits",
    ),
    "project_archive_total_manifest_bytes_limit": ProjectArchiveFindingMetadata(
        "manifest_parse_limits",
        "Manifest parsing and limits",
    ),
    "project_archive_entry_name_too_long": ProjectArchiveFindingMetadata(
        "manifest_parse_limits",
        "Manifest parsing and limits",
    ),
    "project_archive_entry_limit_reached": ProjectArchiveFindingMetadata(
        "archive_safety_metadata",
        "Archive safety metadata",
    ),
    "project_archive_path_traversal": ProjectArchiveFindingMetadata("archive_safety_metadata", "Archive safety metadata"),
    "project_archive_absolute_path": ProjectArchiveFindingMetadata("archive_safety_metadata", "Archive safety metadata"),
    "project_archive_manifest_not_regular_file": ProjectArchiveFindingMetadata(
        "archive_safety_metadata",
        "Archive safety metadata",
    ),
    "project_archive_zip_entry_limit_preflight": ProjectArchiveFindingMetadata(
        "archive_safety_metadata",
        "Archive safety metadata",
    ),
    "project_archive_zip_central_directory_too_large": ProjectArchiveFindingMetadata(
        "archive_safety_metadata",
        "Archive safety metadata",
    ),
    "project_archive_zip64_metadata_requires_review": ProjectArchiveFindingMetadata(
        "archive_safety_metadata",
        "Archive safety metadata",
    ),
    "project_archive_multidisk_zip_unsupported": ProjectArchiveFindingMetadata(
        "archive_safety_metadata",
        "Archive safety metadata",
    ),
    "project_archive_zip_metadata_preflight_unavailable": ProjectArchiveFindingMetadata(
        "archive_safety_metadata",
        "Archive safety metadata",
    ),
}


def project_archive_finding_metadata(finding_id: str | None) -> ProjectArchiveFindingMetadata:
    if finding_id:
        return PROJECT_ARCHIVE_FINDING_METADATA.get(finding_id, UNCATEGORIZED_PROJECT_ARCHIVE_FINDING)
    return UNCATEGORIZED_PROJECT_ARCHIVE_FINDING


def categorize_project_archive_finding(value: Any) -> Any:
    if not isinstance(value, dict):
        return value
    finding = dict(value)
    metadata = project_archive_finding_metadata(str(finding.get("id") or ""))
    finding["category"] = metadata.category
    finding["category_label"] = metadata.category_label
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
            categorize_project_archive_finding(finding) for finding in as_list(item.get("findings"))
        ]
        parsed_manifests.append(parsed_manifest)
    if "parsed_manifests" in result:
        categorized["parsed_manifests"] = parsed_manifests

    return categorized


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []
