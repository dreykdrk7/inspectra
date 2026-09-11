from __future__ import annotations

from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor
import csv
import gc
import io
import json
import os
from time import perf_counter
import tracemalloc
from types import SimpleNamespace

import pytest

from app.config import Settings
from app.models import RemediationSearchRequest, RemediationSummary
from app.remediation_plan_jobs import (
    REMEDIATION_PLAN_ARTIFACT_TTL_DAYS,
    REMEDIATION_PLAN_PROGRESS_CHECKPOINT_PROJECTS,
    RemediationPlanCreateRequest,
    RemediationPlanJobError,
    RemediationPlanJobStore,
    RemediationPlanRetryRequest,
    build_remediation_plan,
)
from app.remediation_reporting import render_durable_remediation_plan, render_remediation_report


OWNER = "1" * 32
OTHER_OWNER = "2" * 32
NOW = datetime(2026, 9, 9, 12, tzinfo=timezone.utc)


def _settings(tmp_path):
    settings = Settings(data_dir=tmp_path, tool_runner_url="http://audit-tools:8081")
    settings.ensure_directories()
    return settings


def _request(key="idem-remediation-plan-0001"):
    return RemediationPlanCreateRequest(
        filters=RemediationSearchRequest(priority="urgent"),
        idempotency_key=key,
        project_metadata_confirmed=True,
    )


class IndexedProjects:
    def __init__(self, total=20_000):
        self.total = total
        self.revision = "revision-a"
        self.page_calls = 0

    def source_revision(self):
        return self.revision

    def page(self, *, owner_id, page_size, cursor):
        assert owner_id == OWNER
        assert page_size == 100
        self.page_calls += 1
        start = int(cursor or 0)
        stop = min(start + page_size, self.total)
        items = [SimpleNamespace(id=f"{index:032x}") for index in range(start, stop)]
        return items, self.total, str(stop) if stop < self.total else None


class EmptyRemediationCenter:
    def __init__(self, callback=None):
        self.seen = 0
        self.callback = callback

    def report_decision_snapshot(self, *, organization_id, observed_at):
        assert organization_id == OWNER
        assert observed_at == NOW
        return {}

    def collect_report_projects(self, *, organization_id, projects, observed_at, accumulators, decisions_by_project):
        assert organization_id == OWNER
        assert observed_at == NOW
        assert decisions_by_project == {}
        self.seen += len(projects)
        if self.callback:
            self.callback(self.seen)

    @staticmethod
    def finalize_report_groups(*, organization_id, payload, observed_at, accumulators):
        assert organization_id == OWNER
        return [], RemediationSummary(
            total_groups=0,
            filtered_groups=0,
            urgent_groups=0,
            high_groups=0,
            projects_affected=0,
            known_exploited_groups=0,
            conflicting_groups=0,
            awaiting_reanalysis=0,
        )


def test_builds_reproducible_private_artifact_for_twenty_thousand_indexed_projects(tmp_path):
    store = RemediationPlanJobStore(_settings(tmp_path), now_func=lambda: NOW)
    durable_writes = 0
    original_write = store._write_job_unlocked

    def counted_write(record):
        nonlocal durable_writes
        durable_writes += 1
        return original_write(record)

    store._write_job_unlocked = counted_write
    created = store.create(OWNER, _request())
    projects = IndexedProjects()

    # Keep this suite-order independent: objects left by earlier integration tests
    # must not trigger an unrelated cyclic collection inside the timed section.
    gc.collect()
    tracemalloc.start()
    started = perf_counter()
    try:
        completed = build_remediation_plan(
            store=store,
            projects=projects,
            remediation_center=EmptyRemediationCenter(),
            organization_id=OWNER,
            job_id=created.id,
        )
        elapsed = perf_counter() - started
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert completed.status == "completed"
    assert completed.processed_projects == 20_000
    assert projects.page_calls == 200
    assert durable_writes == 3 + 20_000 // REMEDIATION_PLAN_PROGRESS_CHECKPOINT_PROJECTS
    assert elapsed < 5.0
    assert peak < 32 * 1024 * 1024
    assert completed.snapshot_sha256
    assert completed.expires_at == NOW + timedelta(days=REMEDIATION_PLAN_ARTIFACT_TTL_DAYS)
    mode = os.stat(store._artifact_path(OWNER, created.id)).st_mode & 0o777
    assert mode == 0o600
    assert os.stat(store._artifact_path(OWNER, created.id).parent).st_mode & 0o777 == 0o700
    _job, artifact = store.artifact(OWNER, created.id)
    json_body, _, _ = render_durable_remediation_plan(artifact, report_format="json")
    csv_body, _, _ = render_durable_remediation_plan(artifact, report_format="csv")
    assert json.loads(json_body)["cutoff_at"] == NOW.isoformat().replace("+00:00", "Z")
    assert b"manifest" in csv_body
    for canary in (b"/home/private", b"secret-canary", b"actor-canary"):
        assert canary not in store._artifact_path(OWNER, created.id).read_bytes()


def test_csv_exports_neutralize_spreadsheet_formulas_without_changing_json():
    dangerous_values = ["=1+1", "+cmd", "-2+3", "@SUM(A1)", "\tformula", "\rformula", "\nformula"]
    occurrence = SimpleNamespace(
        project=SimpleNamespace(name=dangerous_values[0]),
        analysis=SimpleNamespace(id="a" * 32),
        finding_id="f" * 64,
        observed_version="1.0.0",
        dependency_scope="direct",
        workflow_state="open",
        assignee_username=dangerous_values[1],
        review_at=None,
        is_new=True,
        coverage_state="complete",
    )
    group = SimpleNamespace(
        id="1" * 64,
        revision="2" * 64,
        evidence_kind="public_vulnerability",
        title="Fixture",
        ecosystem="npm",
        component_name=dangerous_values[2],
        advisory_ids=[dangerous_values[3]],
        observed_versions=["1.0.0"],
        affected_ranges=[],
        fixed_versions=[dangerous_values[4]],
        recommended_fixed_version=None,
        recommendation=dangerous_values[5],
        priority="high",
        priority_reasons=[dangerous_values[6]],
        highest_severity="high",
        known_exploited=False,
        source_conflict=False,
        exposure_state="not_assessed",
        dependency_scopes=["direct"],
        affected_project_count=1,
        occurrence_count=1,
        occurrences=[occurrence],
        occurrences_truncated=False,
        workflow_counts=SimpleNamespace(model_dump=lambda **_kwargs: {}),
        limitations=[],
    )
    page = SimpleNamespace(
        snapshot_at=NOW,
        resolution_policy="comparable_reanalysis_required",
        summary=SimpleNamespace(model_dump=lambda **_kwargs: {}),
        limitations=[],
    )

    csv_body, *_rest = render_remediation_report(page, [group], report_format="csv", groups_truncated=False)
    csv_row = next(csv.DictReader(io.StringIO(csv_body.decode("utf-8"))))
    assert csv_row["project_name"] == "'=1+1"
    assert csv_row["assignee"] == "'+cmd"
    assert csv_row["component"] == "'-2+3"
    assert csv_row["advisory_ids"] == "'@SUM(A1)"
    assert csv_row["fixed_versions"] == "'\tformula"
    assert csv_row["recommendation"] == "'\rformula"
    assert csv_row["priority_reasons"] == "'\nformula"

    artifact = SimpleNamespace(
        contract_version="2026-09-09.1",
        cutoff_at=NOW,
        processed_projects=1,
        total_projects=1,
        included_groups=1,
        included_occurrences=1,
        groups_truncated=False,
        occurrences_truncated=False,
        groups=[group],
    )
    durable_body, *_rest = render_durable_remediation_plan(artifact, report_format="csv")
    durable_rows = list(csv.DictReader(io.StringIO(durable_body.decode("utf-8"))))
    assert durable_rows[1]["project_name"] == "'=1+1"

    json_body, *_rest = render_remediation_report(page, [group], report_format="json", groups_truncated=False)
    payload = json.loads(json_body)
    assert payload["groups"][0]["component_name"] == "-2+3"
    assert payload["groups"][0]["occurrences"][0]["project_name"] == "=1+1"


def test_idempotency_is_owner_and_payload_bound_and_cross_owner_reads_fail_closed(tmp_path):
    store = RemediationPlanJobStore(_settings(tmp_path), now_func=lambda: NOW)
    first = store.create(OWNER, _request())
    replay = store.create(OWNER, _request())
    assert replay.id == first.id and replay.replayed is True
    with pytest.raises(RemediationPlanJobError, match="idempotency_conflict"):
        store.create(OWNER, RemediationPlanCreateRequest(
            filters=RemediationSearchRequest(priority="high"),
            idempotency_key="idem-remediation-plan-0001",
            project_metadata_confirmed=True,
        ))
    other = store.create(OTHER_OWNER, _request())
    assert other.id != first.id
    with pytest.raises(RemediationPlanJobError, match="not_found"):
        store.get(OTHER_OWNER, first.id)
    raw = store._job_path(OWNER, first.id).read_text()
    assert "idem-remediation-plan-0001" not in raw


def test_cancel_discards_partial_artifact_and_retry_has_new_identity(tmp_path):
    store = RemediationPlanJobStore(_settings(tmp_path), now_func=lambda: NOW)
    created = store.create(OWNER, _request())
    center = EmptyRemediationCenter(callback=lambda seen: store.cancel(OWNER, created.id) if seen == 100 else None)
    result = build_remediation_plan(
        store=store, projects=IndexedProjects(total=300), remediation_center=center,
        organization_id=OWNER, job_id=created.id,
    )
    assert result.status == "cancelled"
    assert not store._artifact_path(OWNER, created.id).exists()
    retried = store.retry(
        OWNER, created.id,
        RemediationPlanRetryRequest(idempotency_key="idem-remediation-plan-retry", confirmation=True),
    )
    assert retried.status == "queued"
    assert retried.id != created.id
    assert retried.retry_of_job_id == created.id


def test_cancel_is_checked_between_durable_progress_checkpoints(tmp_path):
    store = RemediationPlanJobStore(_settings(tmp_path), now_func=lambda: NOW)
    created = store.create(OWNER, _request("idem-remediation-plan-mid-checkpoint"))
    center = EmptyRemediationCenter(
        callback=lambda seen: store.cancel(OWNER, created.id) if seen == 200 else None
    )

    result = build_remediation_plan(
        store=store,
        projects=IndexedProjects(total=300),
        remediation_center=center,
        organization_id=OWNER,
        job_id=created.id,
    )

    assert result.status == "cancelled"
    assert center.seen == 200
    assert not store._artifact_path(OWNER, created.id).exists()


def test_restart_requeues_running_job_and_closes_cancelling_job(tmp_path):
    settings = _settings(tmp_path)
    store = RemediationPlanJobStore(settings, now_func=lambda: NOW)
    running = store.create(OWNER, _request("idem-remediation-plan-run"))
    store.claim(OWNER, running.id, project_revision="revision-a", total_projects=10)
    cancelling = store.create(OWNER, _request("idem-remediation-plan-cancel"))
    store.claim(OWNER, cancelling.id, project_revision="revision-a", total_projects=10)
    store.cancel(OWNER, cancelling.id)

    recovered = RemediationPlanJobStore(settings, now_func=lambda: NOW).recover()

    assert [item.id for item in recovered] == [running.id]
    assert store.get(OWNER, running.id).status == "queued"
    assert store.get(OWNER, running.id).recovery_count == 1
    assert store.get(OWNER, cancelling.id).status == "cancelled"


def test_revision_change_fails_without_publishing_and_expiry_removes_artifact(tmp_path):
    clock = [NOW]
    store = RemediationPlanJobStore(_settings(tmp_path), now_func=lambda: clock[0])
    changed = store.create(OWNER, _request("idem-remediation-plan-changed"))
    projects = IndexedProjects(total=1)
    center = EmptyRemediationCenter(callback=lambda _seen: setattr(projects, "revision", "revision-b"))
    result = build_remediation_plan(
        store=store, projects=projects, remediation_center=center,
        organization_id=OWNER, job_id=changed.id,
    )
    assert result.status == "failed"
    assert result.failure_reason == "portfolio_changed"
    assert not store._artifact_path(OWNER, changed.id).exists()

    completed = store.create(OWNER, _request("idem-remediation-plan-expire"))
    completed = build_remediation_plan(
        store=store, projects=IndexedProjects(total=0), remediation_center=EmptyRemediationCenter(),
        organization_id=OWNER, job_id=completed.id,
    )
    clock[0] = NOW + timedelta(days=8)
    assert store.get(OWNER, completed.id).status == "expired"
    assert not store._artifact_path(OWNER, completed.id).exists()
    with pytest.raises(RemediationPlanJobError, match="artifact_expired"):
        store.artifact(OWNER, completed.id)


def test_corrupt_or_linked_job_and_artifact_fail_closed(tmp_path):
    store = RemediationPlanJobStore(_settings(tmp_path), now_func=lambda: NOW)
    created = store.create(OWNER, _request())
    original = store._job_path(OWNER, created.id)
    original.write_text("{}")
    with pytest.raises(RemediationPlanJobError, match="store_invalid"):
        store.get(OWNER, created.id)
    original.unlink()
    outside = tmp_path / "outside.json"
    outside.write_text("{}")
    original.symlink_to(outside)
    with pytest.raises(RemediationPlanJobError, match="store_invalid"):
        store.get(OWNER, created.id)

    artifact_store = RemediationPlanJobStore(_settings(tmp_path / "artifact"), now_func=lambda: NOW)
    artifact_job = artifact_store.create(OWNER, _request("idem-remediation-plan-artifact"))
    build_remediation_plan(
        store=artifact_store,
        projects=IndexedProjects(total=0),
        remediation_center=EmptyRemediationCenter(),
        organization_id=OWNER,
        job_id=artifact_job.id,
    )
    artifact_path = artifact_store._artifact_path(OWNER, artifact_job.id)
    artifact_path.unlink()
    artifact_path.symlink_to(outside)
    with pytest.raises(RemediationPlanJobError, match="store_invalid"):
        artifact_store.artifact(OWNER, artifact_job.id)


def test_owner_capacity_is_bounded_and_old_terminal_history_is_cleaned(tmp_path):
    clock = [NOW]
    store = RemediationPlanJobStore(_settings(tmp_path), now_func=lambda: clock[0])
    first = store.create(OWNER, _request("idem-remediation-plan-cap-1"))
    second = store.create(OWNER, _request("idem-remediation-plan-cap-2"))
    with pytest.raises(RemediationPlanJobError, match="capacity"):
        store.create(OWNER, _request("idem-remediation-plan-cap-3"))
    store.cancel(OWNER, first.id)
    store.cancel(OWNER, second.id)
    clock[0] = NOW + timedelta(days=31)
    replacement = store.create(OWNER, _request("idem-remediation-plan-cap-3"))
    assert replacement.status == "queued"
    assert {item.id for item in store.list(OWNER).items} == {replacement.id}


def test_concurrent_idempotent_create_publishes_one_job(tmp_path):
    store = RemediationPlanJobStore(_settings(tmp_path), now_func=lambda: NOW)

    with ThreadPoolExecutor(max_workers=8) as executor:
        jobs = list(executor.map(lambda _index: store.create(OWNER, _request()), range(16)))

    assert len({item.id for item in jobs}) == 1
    assert len(store.list(OWNER).items) == 1
