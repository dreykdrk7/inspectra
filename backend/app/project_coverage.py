"""Safe, aggregate coverage for retained project-archive analyses."""

from __future__ import annotations

from typing import Any

from app.models import JobRecord, ProjectAnalysisCoverage, ProjectAnalysisCoverageComparison


_COVERAGE_COMPARISON_METRICS = (
    "analysis_limit_reached",
    "total_entries_seen",
    "supported_manifests_found",
    "supported_manifests_parsed",
    "unsupported_manifests_detected",
    "lockfiles_detected",
    "lockfiles_parsed",
    "total_dependencies",
)


def build_project_analysis_coverage(job: JobRecord) -> ProjectAnalysisCoverage:
    """Project only scalar counts and controlled limitations from a retained result."""

    result = job.result if isinstance(job.result, dict) else {}
    summary = result.get("summary") if isinstance(result.get("summary"), dict) else None
    source_retained = job.source_file_deleted_at is None
    if job.audit_type != "project_archive_basic" or summary is None:
        return ProjectAnalysisCoverage(
            coverage_status="unknown",
            source_retained=source_retained,
            limitations=["source_removed"] if not source_retained else [],
        )

    found = _safe_count(summary.get("supported_manifests_found"))
    parsed = min(_safe_count(summary.get("supported_manifests_parsed")), found)
    lockfiles_detected = _safe_count(summary.get("lockfiles_detected"))
    lockfiles_parsed = min(_safe_count(summary.get("lockfiles_parsed")), lockfiles_detected)
    truncated = summary.get("truncated") is True
    limitations: list[str] = []
    if truncated:
        limitations.append("analysis_limit_reached")
    if parsed < found:
        limitations.append("supported_manifests_not_parsed")
    if lockfiles_parsed < lockfiles_detected:
        limitations.append("lockfiles_not_parsed")
    if not source_retained:
        limitations.append("source_removed")
    return ProjectAnalysisCoverage(
        coverage_status="partial" if limitations else "complete",
        total_entries_seen=_safe_count(summary.get("total_entries_seen")),
        supported_manifests_found=found,
        supported_manifests_parsed=parsed,
        supported_manifests_skipped=max(found - parsed, 0),
        unsupported_manifests_detected=_safe_count(summary.get("unsupported_manifests_detected")),
        lockfiles_detected=lockfiles_detected,
        lockfiles_parsed=lockfiles_parsed,
        lockfiles_skipped=max(lockfiles_detected - lockfiles_parsed, 0),
        total_dependencies=_safe_count(summary.get("total_dependencies")),
        source_retained=source_retained,
        limitations=limitations,
    )


def compare_project_analysis_coverage(
    base: JobRecord,
    target: JobRecord,
) -> ProjectAnalysisCoverageComparison | None:
    """Compare recorded passive coverage without treating source retention as scope.

    The retained result remains comparable after its archive bytes expire.  By
    contrast, missing or changed parser/limit counts mean a finding disappearance
    cannot be safely classified as a resolution.
    """

    if base.audit_type != "project_archive_basic" or target.audit_type != "project_archive_basic":
        return None

    base_coverage = build_project_analysis_coverage(base)
    target_coverage = build_project_analysis_coverage(target)
    base_summary = _project_summary(base)
    target_summary = _project_summary(target)
    if base_summary is None or target_summary is None:
        return ProjectAnalysisCoverageComparison(
            status="unknown",
            base=base_coverage,
            target=target_coverage,
            changed_metrics=["coverage_summary"],
        )

    changed_metrics = [
        metric
        for metric in _COVERAGE_COMPARISON_METRICS
        if _coverage_metric_value(base_summary, metric) != _coverage_metric_value(target_summary, metric)
    ]
    return ProjectAnalysisCoverageComparison(
        status="changed" if changed_metrics else "equivalent",
        base=base_coverage,
        target=target_coverage,
        changed_metrics=changed_metrics,
    )


def _project_summary(job: JobRecord) -> dict[str, Any] | None:
    result = job.result if isinstance(job.result, dict) else {}
    summary = result.get("summary")
    return summary if isinstance(summary, dict) else None


def _coverage_metric_value(summary: dict[str, Any], metric: str) -> int | bool:
    if metric == "analysis_limit_reached":
        return summary.get("truncated") is True
    return _safe_count(summary.get(metric))


def _safe_count(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0
