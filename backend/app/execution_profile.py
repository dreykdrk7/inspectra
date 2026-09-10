"""Typed, non-sensitive execution profiles retained with Inspectra jobs.

The profile intentionally captures only backend limits that apply at admission
and scheduling time. It is not a dump of process configuration: paths, URLs,
credentials, headers, provider settings, and environment values are excluded.
Analyzer-specific limits reported by a runner remain part of the redacted job
result and are never inferred from this profile.
"""

from __future__ import annotations

from app.config import Settings
from app.models import AuditType, JobExecutionProfile
from app.runner_contract import ISOLATED_RUNNER_CONTRACT_VERSION, ISOLATED_RUNNER_FILE_AUDIT_TYPES, ISOLATED_RUNNER_LIMITS


EXECUTION_PROFILE_CONTRACT_VERSION = "2026-09-06.3"
EXECUTION_RULESET_VERSION = "2026-09-09.5"


def build_execution_profile(
    settings: Settings,
    *,
    audit_type: AuditType,
    analysis_profile: str | None,
) -> JobExecutionProfile:
    """Return the immutable, safe profile for one newly created job.

    ``analysis_profile`` is intentionally restricted to the already persisted
    job profile/audit type. All numeric values come from validated ``Settings``
    fields, rather than request input or runner responses.
    """

    is_project_archive = audit_type == "project_archive_basic"
    uses_isolated_worker = audit_type in ISOLATED_RUNNER_FILE_AUDIT_TYPES
    return JobExecutionProfile(
        contract_version=EXECUTION_PROFILE_CONTRACT_VERSION,
        profile_name=analysis_profile or audit_type,
        ruleset_version=EXECUTION_RULESET_VERSION,
        max_upload_bytes=settings.max_upload_bytes,
        audit_max_concurrency=settings.audit_max_concurrency,
        audit_max_inflight_jobs=settings.audit_max_inflight_jobs,
        audit_max_inflight_jobs_per_owner=settings.audit_max_inflight_jobs_per_owner,
        timeout_seconds=settings.project_archive_timeout_seconds if is_project_archive else 60.0,
        workspace_policy=(
            "isolated_copy_stream_worker_v1"
            if is_project_archive
            else "isolated_stream_worker_v1"
            if uses_isolated_worker
            else "shared_source_v1"
        ),
        workspace_max_bytes=settings.execution_workspace_max_bytes,
        worker_contract_version=ISOLATED_RUNNER_CONTRACT_VERSION if uses_isolated_worker else None,
        worker_source_transport="inline_base64_sha256_v1" if uses_isolated_worker else None,
        worker_lifecycle="ephemeral_subprocess" if uses_isolated_worker else None,
        worker_max_concurrency=1 if uses_isolated_worker else None,
        worker_cpu_seconds=ISOLATED_RUNNER_LIMITS["cpu_seconds"] if uses_isolated_worker else None,
        worker_memory_bytes=ISOLATED_RUNNER_LIMITS["memory_bytes"] if uses_isolated_worker else None,
        worker_max_result_bytes=ISOLATED_RUNNER_LIMITS["result_bytes"] if uses_isolated_worker else None,
        worker_max_file_bytes=ISOLATED_RUNNER_LIMITS["file_bytes"] if uses_isolated_worker else None,
        worker_max_open_files=ISOLATED_RUNNER_LIMITS["open_files"] if uses_isolated_worker else None,
        worker_max_processes=ISOLATED_RUNNER_LIMITS["processes"] if uses_isolated_worker else None,
        max_total_uncompressed_bytes=settings.project_archive_max_total_uncompressed_bytes if is_project_archive else None,
        max_archive_entries=settings.project_archive_max_archive_entries if is_project_archive else None,
        max_manifests=settings.project_archive_max_manifests if is_project_archive else None,
        max_manifest_bytes=settings.project_archive_max_manifest_bytes if is_project_archive else None,
        max_total_manifest_bytes=settings.project_archive_max_total_manifest_bytes if is_project_archive else None,
        max_lockfiles=settings.project_archive_max_lockfiles if is_project_archive else None,
        max_lockfile_packages=settings.project_archive_max_lockfile_packages if is_project_archive else None,
        max_lockfile_edges=settings.project_archive_max_lockfile_edges if is_project_archive else None,
        license_policy_contract_version="2026-09-09.1" if is_project_archive else None,
        license_policy_denied_identifiers=settings.license_review_denied_identifiers if is_project_archive else (),
    )


def execution_profiles_are_compatible(
    base: JobExecutionProfile | None,
    target: JobExecutionProfile | None,
) -> bool:
    """Whether two profiles contain sufficient equal evidence for comparison.

    Two legacy records with no captured profile may still be compared under the
    old contract, but callers must present the explicit limitation returned by
    :func:`execution_profile_comparison_limitation`.
    """

    if base is None and target is None:
        return True
    return base is not None and base == target


def execution_profile_comparison_limitation(
    base: JobExecutionProfile | None,
    target: JobExecutionProfile | None,
) -> str | None:
    """Return a public, non-sensitive comparability explanation when needed."""

    if base is None and target is None:
        return (
            "Neither selected legacy analysis recorded an execution profile; matching analyzer labels do not prove that "
            "their admission or scheduling limits were equal."
        )
    if base is None or target is None:
        return "One selected analysis has no recorded execution profile, so it cannot be compared safely with a profiled analysis."
    if base != target:
        return "The selected analyses have different recorded execution profiles and are not comparable."
    return None


def execution_profile_report_text(profile: JobExecutionProfile | None) -> str:
    """Format a minimal profile summary for a trusted local report surface."""

    if profile is None:
        return "Not recorded (legacy analysis)"
    timeout = f"{profile.timeout_seconds:g} seconds" if profile.timeout_seconds is not None else "not recorded"
    workspace = profile.workspace_policy or "legacy shared source"
    summary = (
        f"{profile.profile_name}; contract {profile.contract_version}; rules {profile.ruleset_version}; "
        f"upload limit {profile.max_upload_bytes} bytes; timeout {timeout}; "
        f"audit concurrency {profile.audit_max_concurrency}; "
        f"in-flight global {profile.audit_max_inflight_jobs if profile.audit_max_inflight_jobs is not None else 'not recorded'}; "
        f"in-flight per owner {profile.audit_max_inflight_jobs_per_owner if profile.audit_max_inflight_jobs_per_owner is not None else 'not recorded'}; "
        f"workspace {workspace}; "
        f"workspace copy limit {profile.workspace_max_bytes if profile.workspace_max_bytes is not None else 'not recorded'} bytes"
    )
    if profile.worker_contract_version is not None:
        summary += (
            f"; isolated worker {profile.worker_contract_version}; lifecycle {profile.worker_lifecycle}; "
            f"worker concurrency {profile.worker_max_concurrency}; CPU {profile.worker_cpu_seconds} seconds; "
            f"memory {profile.worker_memory_bytes} bytes; result {profile.worker_max_result_bytes} bytes; "
            f"file {profile.worker_max_file_bytes} bytes; open files {profile.worker_max_open_files}; "
            f"processes {profile.worker_max_processes}"
        )
    if profile.license_policy_contract_version is not None:
        summary += (
            f"; license review {profile.license_policy_contract_version}; "
            f"exact deny entries {len(profile.license_policy_denied_identifiers)}"
        )
    project_limits = [
        ("expanded bytes", profile.max_total_uncompressed_bytes),
        ("archive entries", profile.max_archive_entries),
        ("manifests", profile.max_manifests),
        ("manifest bytes", profile.max_manifest_bytes),
        ("total manifest bytes", profile.max_total_manifest_bytes),
        ("lockfiles", profile.max_lockfiles),
        ("lockfile packages", profile.max_lockfile_packages),
        ("lockfile edges", profile.max_lockfile_edges),
    ]
    recorded = [f"{label} {value}" for label, value in project_limits if value is not None]
    return f"{summary}; {'; '.join(recorded)}." if recorded else f"{summary}."


def termination_reason_report_text(reason: str | None) -> str:
    """Render only a fixed, non-sensitive terminal explanation."""

    return {
        "completed": "Completed under the recorded execution contract",
        "cancelled_by_owner": "Cancelled by the project owner after workspace cleanup",
        "application_restart": "Interrupted by application restart; safe retry required",
        "application_shutdown": "Interrupted during application shutdown; safe retry required",
        "recovery_rejected": "Queued work was rejected because its retained source or execution contract was no longer valid",
        "runner_timeout": "Stopped at the recorded time limit",
        "runner_resource_limit": "Stopped at the recorded isolated-worker resource boundary",
        "runner_unavailable": "Runner unavailable; safe retry required",
        "runner_contract_invalid": "Runner limit contract did not match",
        "workspace_error": "Workspace could not be prepared within limits",
        "internal_error": "Controlled internal execution error",
    }.get(reason or "", "Not recorded" if reason is None else "Unrecognized legacy terminal reason")
