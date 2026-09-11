"""Deterministic, privacy-bounded remediation plan exports."""

from __future__ import annotations

import csv
import hashlib
import io
import json
from typing import TYPE_CHECKING

from app.models import RemediationActionGroup, RemediationPage

if TYPE_CHECKING:
    from app.remediation_plan_jobs import RemediationPlanArtifact


REMEDIATION_REPORT_CONTRACT_VERSION = "2026-09-09.1"
REMEDIATION_REPORT_MAX_GROUPS = 2_000
REMEDIATION_REPORT_MAX_OCCURRENCES = 5_000


def render_remediation_report(
    first_page: RemediationPage,
    groups: list[RemediationActionGroup],
    *,
    report_format: str,
    groups_truncated: bool,
) -> tuple[bytes, str, str, str]:
    """Return bytes, media type and digest without source paths or finding bodies."""

    rows, occurrence_rows_truncated = _rows(groups)
    metadata = {
        "contract_version": REMEDIATION_REPORT_CONTRACT_VERSION,
        "snapshot_at": first_page.snapshot_at.isoformat(),
        "resolution_policy": first_page.resolution_policy,
        "priority_model": "closed_signals_no_opaque_score",
        "exposure_state": "not_assessed",
        "summary": first_page.summary.model_dump(mode="json"),
        "included_groups": len(groups),
        "groups_truncated": groups_truncated,
        "occurrence_rows_truncated": occurrence_rows_truncated,
        "privacy": {
            "project_names_included": True,
            "source_paths_included": False,
            "source_content_included": False,
            "decision_comments_included": False,
            "actor_identifiers_included": False,
        },
        "limitations": list(first_page.limitations),
    }
    if report_format == "json":
        payload = {
            **metadata,
            "groups": [_group_payload(item) for item in groups],
        }
        content = (json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
        media_type = "application/json"
        extension = "json"
    elif report_format == "csv":
        output = io.StringIO(newline="")
        writer = csv.DictWriter(output, fieldnames=list(rows[0]) if rows else _csv_fields())
        writer.writeheader()
        writer.writerows(_csv_safe_row(row) for row in rows)
        content = output.getvalue().encode("utf-8")
        media_type = "text/csv; charset=utf-8"
        extension = "csv"
    else:  # pragma: no cover - request model closes the set.
        raise ValueError("Unsupported remediation report format.")
    digest = hashlib.sha256(content).hexdigest()
    return content, media_type, f"inspectra-remediation-{first_page.snapshot_at.date().isoformat()}.{extension}", digest


def _group_payload(group: RemediationActionGroup) -> dict[str, object]:
    return {
        "id": group.id,
        "evidence_kind": group.evidence_kind,
        "title": group.title,
        "ecosystem": group.ecosystem,
        "component_name": group.component_name,
        "advisory_ids": group.advisory_ids,
        "observed_versions": group.observed_versions,
        "affected_ranges": [item.model_dump(mode="json") for item in group.affected_ranges],
        "fixed_versions": group.fixed_versions,
        "recommended_fixed_version": group.recommended_fixed_version,
        "recommendation": group.recommendation,
        "priority": group.priority,
        "priority_reasons": group.priority_reasons,
        "highest_severity": group.highest_severity,
        "known_exploited": group.known_exploited,
        "source_conflict": group.source_conflict,
        "exposure_state": group.exposure_state,
        "dependency_scopes": group.dependency_scopes,
        "affected_project_count": group.affected_project_count,
        "occurrence_count": group.occurrence_count,
        "workflow_counts": group.workflow_counts.model_dump(mode="json"),
        "occurrences": [
            {
                "project_name": item.project.name,
                "analysis_id": item.analysis.id,
                "finding_id": item.finding_id,
                "observed_version": item.observed_version,
                "dependency_scope": item.dependency_scope,
                "workflow_state": item.workflow_state,
                "assignee_username": item.assignee_username,
                "review_at": item.review_at.isoformat() if item.review_at else None,
                "is_new": item.is_new,
                "coverage_state": item.coverage_state,
            }
            for item in group.occurrences
        ],
        "occurrences_truncated": group.occurrences_truncated,
        "limitations": group.limitations,
    }


def _rows(groups: list[RemediationActionGroup]) -> tuple[list[dict[str, object]], bool]:
    rows: list[dict[str, object]] = []
    truncated = False
    for group in groups:
        for occurrence in group.occurrences:
            if len(rows) >= REMEDIATION_REPORT_MAX_OCCURRENCES:
                truncated = True
                return rows, truncated
            rows.append({
                "group_id": group.id,
                "priority": group.priority,
                "priority_reasons": ";".join(group.priority_reasons),
                "highest_severity": group.highest_severity,
                "known_exploited": str(group.known_exploited).lower(),
                "source_conflict": str(group.source_conflict).lower(),
                "ecosystem": group.ecosystem or "",
                "component": group.component_name or group.title,
                "advisory_ids": ";".join(group.advisory_ids),
                "observed_version": occurrence.observed_version or "",
                "fixed_versions": ";".join(group.fixed_versions),
                "project_name": occurrence.project.name,
                "analysis_id": occurrence.analysis.id,
                "finding_id": occurrence.finding_id,
                "dependency_scope": occurrence.dependency_scope,
                "workflow_state": occurrence.workflow_state,
                "assignee": occurrence.assignee_username or "",
                "review_at": occurrence.review_at.isoformat() if occurrence.review_at else "",
                "coverage_state": occurrence.coverage_state,
                "exposure_state": "not_assessed",
                "recommendation": group.recommendation,
            })
    return rows, truncated


def _csv_fields() -> list[str]:
    return [
        "group_id", "priority", "priority_reasons", "highest_severity", "known_exploited",
        "source_conflict", "ecosystem", "component", "advisory_ids", "observed_version",
        "fixed_versions", "project_name", "analysis_id", "finding_id", "dependency_scope",
        "workflow_state", "assignee", "review_at", "coverage_state", "exposure_state", "recommendation",
    ]


def render_durable_remediation_plan(
    artifact: "RemediationPlanArtifact", *, report_format: str
) -> tuple[bytes, str, str]:
    """Render JSON/CSV from one already-committed immutable snapshot."""

    if report_format == "json":
        document = artifact.model_dump(mode="json")
        content = (json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
        media_type = "application/json"
        extension = "json"
    elif report_format == "csv":
        rows, _truncated = _rows(artifact.groups)
        output = io.StringIO(newline="")
        fields = [
            "record_type", "contract_version", "cutoff_at", "processed_projects",
            "total_projects", "included_groups", "included_occurrences",
            "groups_truncated", "occurrences_truncated", *_csv_fields(),
        ]
        writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
        writer.writeheader()
        writer.writerow(_csv_safe_row({
            "record_type": "manifest",
            "contract_version": artifact.contract_version,
            "cutoff_at": artifact.cutoff_at.isoformat(),
            "processed_projects": artifact.processed_projects,
            "total_projects": artifact.total_projects,
            "included_groups": artifact.included_groups,
            "included_occurrences": artifact.included_occurrences,
            "groups_truncated": str(artifact.groups_truncated).lower(),
            "occurrences_truncated": str(artifact.occurrences_truncated).lower(),
        }))
        for row in rows:
            writer.writerow(_csv_safe_row({"record_type": "occurrence", "contract_version": artifact.contract_version, **row}))
        content = output.getvalue().encode("utf-8")
        media_type = "text/csv; charset=utf-8"
        extension = "csv"
    else:
        raise ValueError("Unsupported remediation plan format.")
    if len(content) > 16 * 1024 * 1024:
        raise ValueError("Remediation plan download exceeds its safe size limit.")
    return content, media_type, f"inspectra-remediation-plan-{artifact.cutoff_at.date().isoformat()}.{extension}"


def _csv_safe_row(row: dict[str, object]) -> dict[str, object]:
    """Neutralize spreadsheet formulas while preserving non-text values and JSON."""

    return {
        key: f"'{value}" if isinstance(value, str) and value.startswith(("=", "+", "-", "@", "\t", "\r", "\n")) else value
        for key, value in row.items()
    }
