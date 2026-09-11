import json

import pytest
from pydantic import ValidationError

from app.config import load_settings
from app.execution_profile import (
    EXECUTION_PROFILE_CONTRACT_VERSION,
    EXECUTION_RULESET_VERSION,
    build_execution_profile,
    execution_profile_comparison_limitation,
    execution_profile_report_text,
    execution_profiles_are_compatible,
)
from app.finding_normalization import normalize_result_findings
from app.models import JobExecutionProfile
from app.passive_profiles import DEFAULT_PASSIVE_PROFILE, default_passive_analysis_profile, get_passive_analysis_profile
from app.project_archive_findings import categorize_project_archive_result
from app.storage import JobStore


def test_execution_profile_is_minimal_versioned_and_persisted_immutably(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("INSPECTRA_MAX_UPLOAD_BYTES", "123456")
    monkeypatch.setenv("INSPECTRA_AUDIT_MAX_CONCURRENCY", "3")
    settings = load_settings()
    settings.ensure_directories()
    jobs = JobStore(settings)

    job = jobs.create_project_archive_job(
        "a" * 32,
        project_id="b" * 32,
        source_sha256="c" * 64,
    )

    assert job.execution_profile is not None
    assert job.execution_profile.model_dump() == {
        "contract_version": EXECUTION_PROFILE_CONTRACT_VERSION,
        "profile_name": "project_archive_basic",
        "ruleset_version": EXECUTION_RULESET_VERSION,
        "max_upload_bytes": 123456,
        "audit_max_concurrency": 3,
        "audit_max_inflight_jobs": 128,
        "audit_max_inflight_jobs_per_owner": 32,
        "timeout_seconds": 60.0,
        "workspace_policy": "isolated_copy_stream_worker_v1",
        "workspace_max_bytes": 20 * 1024 * 1024,
        "worker_contract_version": "2026-09-06.1",
        "worker_source_transport": "inline_base64_sha256_v1",
        "worker_lifecycle": "ephemeral_subprocess",
        "worker_max_concurrency": 1,
        "worker_cpu_seconds": 45,
        "worker_memory_bytes": 402_653_184,
        "worker_max_result_bytes": 4_194_304,
        "worker_max_file_bytes": 33_554_432,
        "worker_max_open_files": 64,
        "worker_max_processes": 32,
        "max_total_uncompressed_bytes": 200 * 1024 * 1024,
        "max_archive_entries": 5_000,
        "max_manifests": 25,
        "max_manifest_bytes": 1024 * 1024,
        "max_total_manifest_bytes": 5 * 1024 * 1024,
        "max_lockfiles": 5,
        "max_lockfile_packages": 2_000,
        "max_lockfile_edges": 4_000,
        "license_policy_contract_version": "2026-09-09.1",
        "license_policy_denied_identifiers": (),
    }

    # A retry or terminal update must not rewrite admission evidence.
    altered_profile = job.execution_profile.model_copy(update={"max_upload_bytes": 999999})
    jobs.save(job.model_copy(update={"execution_profile": altered_profile}))
    persisted = jobs.get(job.id)
    assert persisted.execution_profile == job.execution_profile

    serialized = (settings.jobs_dir / f"{job.id}.json").read_text(encoding="utf-8")
    assert json.loads(serialized)["execution_profile"] == job.execution_profile.model_dump(mode="json")
    for forbidden in (str(tmp_path), "http://", "https://", "token", "secret", "password", "INSPECTRA_"):
        assert forbidden not in serialized.lower()


def test_execution_profile_comparison_distinguishes_legacy_and_changed_contracts(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("INSPECTRA_MAX_UPLOAD_BYTES", "123456")
    monkeypatch.setenv("INSPECTRA_AUDIT_MAX_CONCURRENCY", "3")
    settings = load_settings()
    baseline = build_execution_profile(
        settings,
        audit_type="project_archive_basic",
        analysis_profile="project_archive_basic",
    )
    changed = baseline.model_copy(update={"ruleset_version": "fixture-next-rules"})

    assert execution_profiles_are_compatible(baseline, baseline) is True
    assert execution_profile_comparison_limitation(baseline, baseline) is None
    assert execution_profiles_are_compatible(baseline, changed) is False
    assert execution_profile_comparison_limitation(baseline, changed) == (
        "The selected analyses have different recorded execution profiles and are not comparable."
    )
    assert execution_profiles_are_compatible(None, None) is True
    assert execution_profile_comparison_limitation(None, None) == (
        "Neither selected legacy analysis recorded an execution profile; matching analyzer labels do not prove that "
        "their admission or scheduling limits were equal."
    )
    assert execution_profiles_are_compatible(None, baseline) is False
    assert execution_profile_comparison_limitation(None, baseline) == (
        "One selected analysis has no recorded execution profile, so it cannot be compared safely with a profiled analysis."
    )
    assert execution_profile_report_text(None) == "Not recorded (legacy analysis)"
    assert "fixture-next-rules" in execution_profile_report_text(changed)


def test_passive_profile_catalog_is_closed_safe_and_matches_execution_ruleset():
    profile = default_passive_analysis_profile()

    assert profile.profile_name == DEFAULT_PASSIVE_PROFILE == "project_archive_basic"
    assert profile.safe_default is True
    assert profile.selection_mode == "manifest_driven_closed_catalog"
    assert profile.execution_mode == "passive_no_project_execution"
    assert profile.network_access == "disabled"
    assert profile.ruleset_version == EXECUTION_RULESET_VERSION
    assert {rule.id for rule in profile.rules} == {
        "archive_safety_limits",
        "manifest_parse_integrity",
        "dependency_repeatability",
        "dependency_source_boundary",
        "package_execution_indicators",
        "multi_ecosystem_coverage",
        "sensitive_data_indicators",
        "container_configuration",
        "kubernetes_configuration",
        "terraform_configuration",
        "declared_license_review",
    }
    assert get_passive_analysis_profile(DEFAULT_PASSIVE_PROFILE) is profile

    with pytest.raises(ValueError, match="Unknown passive analysis profile"):
        get_passive_analysis_profile("user-controlled-profile")


def test_license_policy_configuration_is_bounded_and_captured(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("INSPECTRA_LICENSE_REVIEW_DENIED_IDENTIFIERS", "GPL-3.0-only,AGPL-3.0-only,GPL-3.0-only")
    settings = load_settings()
    profile = build_execution_profile(settings, audit_type="project_archive_basic", analysis_profile="project_archive_basic")

    assert settings.license_review_denied_identifiers == ("AGPL-3.0-only", "GPL-3.0-only")
    assert profile.license_policy_contract_version == "2026-09-09.1"
    assert profile.license_policy_denied_identifiers == ("AGPL-3.0-only", "GPL-3.0-only")
    assert "exact deny entries 2" in execution_profile_report_text(profile)

    monkeypatch.setenv("INSPECTRA_LICENSE_REVIEW_DENIED_IDENTIFIERS", "MIT,https://private.example/license")
    with pytest.raises(ValueError, match="exact SPDX-like identifiers"):
        load_settings()


def test_integrated_sensitive_data_findings_keep_redacted_location_and_normalized_category():
    result = categorize_project_archive_result(
        {
            "findings": [
                {
                    "id": "secret_like_assignment",
                    "title": "Secret-like assignment observed",
                    "level": "medium",
                    "confidence": "medium",
                    "file_path": "config/settings.py",
                    "line": 7,
                    "description": "A value was redacted.",
                    "evidence": "API_KEY=[REDACTED]",
                    "recommendation": "Use an approved runtime mechanism.",
                }
            ]
        }
    )

    finding = result["findings"][0]
    assert finding["category"] == "sensitive_data_review"
    assert finding["category_label"] == "Sensitive data review"
    assert finding["ecosystem"] == "framework_config"
    assert finding["file_path"] == "config/settings.py"
    assert finding["line"] == 7
    assert "[REDACTED]" in finding["evidence"]

    normalized = normalize_result_findings("project_archive_basic", result)["normalized_findings"][0]
    assert normalized["location"] == {"path": "config/settings.py", "line": 7}
    assert normalized["location_status"] == "reported"
    assert normalized["confidence"] == "medium"


@pytest.mark.parametrize("field", ["contract_version", "profile_name", "ruleset_version", "worker_contract_version"])
def test_execution_profile_rejects_values_that_could_be_configuration_or_location_data(field):
    values = {
        "contract_version": "2026-09-05.1",
        "profile_name": "project_archive_basic",
        "ruleset_version": "2026-09-05.1",
        "max_upload_bytes": 123456,
        "audit_max_concurrency": 3,
    }
    values[field] = "https://private.example/?token=should-not-persist"

    with pytest.raises(ValidationError):
        JobExecutionProfile.model_validate(values)
