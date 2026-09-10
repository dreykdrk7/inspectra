import asyncio
from datetime import datetime, timedelta, timezone
import json
import logging
from types import SimpleNamespace
from zoneinfo import ZoneInfo

import pytest

from app import main as backend_main
from app.active_asset_verification import (
    ActiveAssetVerificationObservation,
    ActiveAssetVerificationStartRequest,
    ActiveAssetVerificationStore,
)
from app.active_assets import ACTIVE_CAPABILITIES, ActiveAssetCreateRequest, ActiveAssetStore
from app.active_recurrence import (
    ACTIVE_RECURRENCE_WEEKDAYS,
    ACTIVE_RECURRENCE_MAX_BACKOFF_SECONDS,
    ACTIVE_RECURRENCE_MAX_FAILURES,
    ActiveRecurrenceCreateRequest,
    ActiveRecurrenceError,
    ActiveRecurrenceStore,
    recurrence_is_within_window,
    recurrence_jitter_seconds,
    recurrence_occurrence_key,
)
from app.config import Settings
from app.product_audit import ProductAuditStore
from app.storage import JobStore


OWNER = "a" * 32


def configured(tmp_path):
    now = [datetime.now(timezone.utc).replace(microsecond=0)]
    settings = Settings(
        data_dir=tmp_path,
        tool_runner_url="http://audit-tools:8081",
        active_dns_inventory_enabled=True,
        active_asset_verification_enabled=True,
        active_recurrence_enabled=True,
    )
    settings.ensure_directories()
    assets = ActiveAssetStore(settings, now_func=lambda: now[0])
    verifications = ActiveAssetVerificationStore(settings, now_func=lambda: now[0])
    recurrences = ActiveRecurrenceStore(settings, now_func=lambda: now[0])
    asset = assets.create(
        ActiveAssetCreateRequest(
            asset_type="domain",
            value="recurrence.example.test",
            responsible_user_ids=[OWNER],
            capabilities=["active_dns_inventory"],
            allowed_ports=[],
            allowed_protocols=["dns"],
            authorization_method="manual_attestation",
            authorization_reference="approved-weekly-review",
            authorized_at=now[0],
            expires_at=now[0] + timedelta(days=60),
            notes=[],
        ),
        organization_id=OWNER,
        actor_id=OWNER,
    )
    pending, token = verifications.start(
        asset,
        ActiveAssetVerificationStartRequest(
            method="manual_attestation", valid_for_days=30, control_check_confirmed=True
        ),
        organization_id=OWNER,
        actor_id=OWNER,
    )
    verified = verifications.complete(
        pending.id,
        asset=asset,
        organization_id=OWNER,
        challenge_token=token,
        observation=ActiveAssetVerificationObservation(True, "matched"),
    )
    revision = asset.authorization_revisions[-1]
    request = ActiveRecurrenceCreateRequest(
        capability="active_dns_inventory",
        interval_days=7,
        timezone_name="UTC",
        window_weekdays=list(ACTIVE_RECURRENCE_WEEKDAYS),
        window_start_hour=0,
        window_duration_hours=12,
        recurrence_confirmed=True,
        idempotency_key="b" * 32,
    )
    return now, settings, assets, verifications, recurrences, asset, verified, revision, request


def test_recurrence_store_is_idempotent_owner_scoped_and_collapses_missed_occurrences(tmp_path):
    now, _settings, _assets, _verifications, store, asset, verified, revision, request = configured(tmp_path)
    record, replayed = store.create(
        request,
        organization_id=OWNER,
        asset_id=asset.id,
        actor_id=OWNER,
        actor_role="administrator",
        authorization_revision_id=revision.id,
        authorization_revision_digest_sha256=revision.digest_sha256,
        authorization_revision_sequence=revision.sequence,
        authorization_expires_at=revision.expires_at,
        verification_id=verified.id,
    )
    repeated, was_replayed = store.create(
        request,
        organization_id=OWNER,
        asset_id=asset.id,
        actor_id=OWNER,
        actor_role="administrator",
        authorization_revision_id=revision.id,
        authorization_revision_digest_sha256=revision.digest_sha256,
        authorization_revision_sequence=revision.sequence,
        authorization_expires_at=revision.expires_at,
        verification_id=verified.id,
    )
    assert replayed is False and was_replayed is True and repeated.id == record.id
    assert recurrence_occurrence_key(record) == recurrence_occurrence_key(repeated)
    view = store.view(record).model_dump(mode="json")
    assert "organization_id" not in view
    assert "actor_id" not in view
    assert "authorization_revision_digest_sha256" not in view
    assert "recurrence.example.test" not in str(view)
    with pytest.raises(ActiveRecurrenceError, match="not_found"):
        store.get(record.id, organization_id="c" * 32, asset_id=asset.id)

    now[0] = record.next_run_at + timedelta(days=14)
    assert [item.id for item in store.list_due(now=now[0])] == [record.id]
    dispatched = store.record_dispatch(record, job_id="d" * 32, now=now[0])
    assert dispatched.last_scheduled_at == record.next_run_at
    jitter = timedelta(seconds=recurrence_jitter_seconds(record.id))
    assert record.next_run_at >= record.created_at + timedelta(days=7) + jitter
    assert recurrence_is_within_window(record, record.next_run_at)
    assert dispatched.next_run_at >= now[0] + timedelta(days=7) + jitter
    assert recurrence_is_within_window(dispatched, dispatched.next_run_at)
    assert store.list_due(now=now[0]) == []
    paused = store.pause(
        dispatched.id,
        organization_id=OWNER,
        asset_id=asset.id,
        expected_updated_at=dispatched.updated_at,
    )
    assert paused.status == "paused"
    resumed = store.resume(
        paused.id,
        organization_id=OWNER,
        asset_id=asset.id,
        expected_updated_at=paused.updated_at,
        authorization_revision_id=revision.id,
        authorization_revision_digest_sha256=revision.digest_sha256,
        authorization_revision_sequence=revision.sequence,
        authorization_expires_at=revision.expires_at,
        verification_id=verified.id,
    )
    assert resumed.status == "active"
    assert resumed.next_run_at >= now[0] + timedelta(days=7) + jitter
    assert recurrence_is_within_window(resumed, resumed.next_run_at)


@pytest.mark.anyio
async def test_due_recurrence_creates_one_bound_job_and_never_requires_network_in_tests(monkeypatch, tmp_path):
    now, settings, assets, verifications, recurrences, asset, verified, revision, request = configured(tmp_path)
    record, _ = recurrences.create(
        request,
        organization_id=OWNER,
        asset_id=asset.id,
        actor_id=OWNER,
        actor_role="administrator",
        authorization_revision_id=revision.id,
        authorization_revision_digest_sha256=revision.digest_sha256,
        authorization_revision_sequence=revision.sequence,
        authorization_expires_at=revision.expires_at,
        verification_id=verified.id,
    )
    now[0] = record.next_run_at

    async def healthy(_url, *, timeout_seconds):
        return {
            "available": True,
            "capabilities": {
                capability: {"execution_enabled": True} for capability in ACTIVE_CAPABILITIES
            },
        }

    dispatched = []

    async def no_live_dispatch(_app, job_id):
        dispatched.append(job_id)

    monkeypatch.setattr(backend_main, "run_scheduled_active_execution", no_live_dispatch)
    state = SimpleNamespace(
        active_recurrences=recurrences,
        active_assets=assets,
        active_asset_verifications=verifications,
        active_tools_health_checker=healthy,
        settings=settings,
        jobs=JobStore(settings),
        product_audit=ProductAuditStore(settings, now_func=lambda: now[0]),
        scheduled_active_execution_job_ids=set(),
        durable_audit_tasks=set(),
    )
    fake_app = SimpleNamespace(state=state)

    jobs = await backend_main.process_due_active_recurrences(fake_app, now=now[0])
    await __import__("asyncio").sleep(0)

    assert len(jobs) == 1 and dispatched == jobs
    job = state.jobs.get(jobs[0])
    assert job.active_asset_id == asset.id
    assert job.active_authorization_revision_id == revision.id
    assert job.active_execution_idempotency_key_sha256 == recurrence_occurrence_key(record)
    current = recurrences.get(record.id, organization_id=OWNER, asset_id=asset.id)
    assert current.last_job_id == job.id
    assert current.next_run_at >= now[0] + timedelta(days=7, seconds=recurrence_jitter_seconds(record.id))
    assert recurrence_is_within_window(current, current.next_run_at)
    assert await backend_main.process_due_active_recurrences(fake_app, now=now[0]) == []


@pytest.mark.anyio
async def test_two_concurrent_ticks_admit_one_durable_occurrence(monkeypatch, tmp_path):
    now, settings, assets, verifications, recurrences, asset, verified, revision, request = configured(tmp_path)
    record, _ = recurrences.create(
        request,
        organization_id=OWNER,
        asset_id=asset.id,
        actor_id=OWNER,
        actor_role="administrator",
        authorization_revision_id=revision.id,
        authorization_revision_digest_sha256=revision.digest_sha256,
        authorization_revision_sequence=revision.sequence,
        authorization_expires_at=revision.expires_at,
        verification_id=verified.id,
    )
    now[0] = record.next_run_at
    both_selected = asyncio.Event()
    health_calls = 0

    async def synchronized_health(_url, *, timeout_seconds):
        nonlocal health_calls
        health_calls += 1
        if health_calls == 2:
            both_selected.set()
        await both_selected.wait()
        return {
            "available": True,
            "capabilities": {
                capability: {"execution_enabled": True} for capability in ACTIVE_CAPABILITIES
            },
        }

    dispatched = []

    async def no_live_dispatch(_app, job_id):
        dispatched.append(job_id)

    monkeypatch.setattr(backend_main, "run_scheduled_active_execution", no_live_dispatch)
    job_store = JobStore(settings)
    state = SimpleNamespace(
        active_recurrences=recurrences,
        active_assets=assets,
        active_asset_verifications=verifications,
        active_tools_health_checker=synchronized_health,
        settings=settings,
        jobs=job_store,
        product_audit=ProductAuditStore(settings, now_func=lambda: now[0]),
        scheduled_active_execution_job_ids=set(),
        durable_audit_tasks=set(),
    )
    fake_app = SimpleNamespace(state=state)

    outcomes = await asyncio.gather(
        backend_main.process_due_active_recurrences(fake_app, now=now[0]),
        backend_main.process_due_active_recurrences(fake_app, now=now[0]),
    )
    await asyncio.sleep(0)

    scheduled = [job_id for outcome in outcomes for job_id in outcome]
    assert len(scheduled) == 1
    assert dispatched == scheduled
    assert len(job_store.list(owner_id=OWNER)) == 1
    assert recurrences.get(record.id, organization_id=OWNER, asset_id=asset.id).last_job_id == scheduled[0]


@pytest.mark.anyio
async def test_provider_outage_defers_without_advancing_and_revocation_suspends(tmp_path, caplog):
    caplog.set_level(logging.INFO, logger="inspectra.audit")
    now, settings, assets, verifications, recurrences, asset, verified, revision, request = configured(tmp_path)
    record, _ = recurrences.create(
        request,
        organization_id=OWNER,
        asset_id=asset.id,
        actor_id=OWNER,
        actor_role="administrator",
        authorization_revision_id=revision.id,
        authorization_revision_digest_sha256=revision.digest_sha256,
        authorization_revision_sequence=revision.sequence,
        authorization_expires_at=revision.expires_at,
        verification_id=verified.id,
    )
    now[0] = record.next_run_at

    async def unavailable(_url, *, timeout_seconds):
        raise TimeoutError("synthetic fixture; no socket")

    fake_app = SimpleNamespace(
        state=SimpleNamespace(
            active_recurrences=recurrences,
            active_assets=assets,
            active_asset_verifications=verifications,
            active_tools_health_checker=unavailable,
            settings=settings,
            jobs=JobStore(settings),
            product_audit=ProductAuditStore(settings, now_func=lambda: now[0]),
            scheduled_active_execution_job_ids=set(),
            durable_audit_tasks=set(),
        )
    )
    assert await backend_main.process_due_active_recurrences(fake_app, now=now[0]) == []
    retained = recurrences.get(record.id, organization_id=OWNER, asset_id=asset.id)
    assert retained.next_run_at == record.next_run_at and retained.status == "active"
    assert retained.failure_count == 1
    assert retained.last_outcome == "runner_unavailable"
    assert retained.next_retry_at is not None and retained.next_retry_at > now[0]
    assert recurrences.list_due(now=retained.next_retry_at - timedelta(seconds=1)) == []
    assert not list(settings.jobs_dir.glob("*.json"))
    assert '"event":"active_recurrence.deferred"' in caplog.text
    assert '"reason_code":"runner_unavailable"' in caplog.text
    assert asset.canonical_value not in caplog.text

    reloaded = ActiveRecurrenceStore(settings, now_func=lambda: now[0])
    fake_app.state.active_recurrences = reloaded
    now[0] = retained.next_retry_at
    assert await backend_main.process_due_active_recurrences(fake_app, now=now[0]) == []
    retried = reloaded.get(record.id, organization_id=OWNER, asset_id=asset.id)
    assert retried.failure_count == 2 and retried.next_retry_at > retained.next_retry_at

    reloaded.suspend_for_asset(asset.id, organization_id=OWNER)
    suspended = reloaded.get(record.id, organization_id=OWNER, asset_id=asset.id)
    assert suspended.status == "suspended"
    assert suspended.reason_code == "authorization_unavailable"


@pytest.mark.anyio
async def test_newer_unverified_control_signal_suspends_without_contacting_runner(tmp_path):
    now, settings, assets, verifications, recurrences, asset, verified, revision, request = configured(tmp_path)
    record, _ = recurrences.create(
        request,
        organization_id=OWNER, asset_id=asset.id, actor_id=OWNER, actor_role="administrator",
        authorization_revision_id=revision.id,
        authorization_revision_digest_sha256=revision.digest_sha256,
        authorization_revision_sequence=revision.sequence,
        authorization_expires_at=revision.expires_at, verification_id=verified.id,
    )
    now[0] = record.next_run_at
    verifications.start(
        asset,
        ActiveAssetVerificationStartRequest(
            method="manual_attestation", valid_for_days=30, control_check_confirmed=True
        ),
        organization_id=OWNER,
        actor_id=OWNER,
    )

    async def must_not_contact_runner(_url, *, timeout_seconds):
        raise AssertionError("runner health must not be contacted after failed local revalidation")

    fake_app = SimpleNamespace(state=SimpleNamespace(
        active_recurrences=recurrences, active_assets=assets,
        active_asset_verifications=verifications, active_tools_health_checker=must_not_contact_runner,
        settings=settings, jobs=JobStore(settings),
        product_audit=ProductAuditStore(settings, now_func=lambda: now[0]),
        scheduled_active_execution_job_ids=set(), durable_audit_tasks=set(),
    ))
    assert await backend_main.process_due_active_recurrences(fake_app, now=now[0]) == []
    suspended = recurrences.get(record.id, organization_id=OWNER, asset_id=asset.id)
    assert suspended.status == "suspended" and suspended.reason_code == "verification_unavailable"


def test_weekly_window_handles_dst_and_remains_bounded_for_a_year(tmp_path):
    now = [datetime(2026, 3, 22, 0, 0, tzinfo=timezone.utc)]
    settings = Settings(data_dir=tmp_path, tool_runner_url="http://audit-tools:8081")
    settings.ensure_directories()
    store = ActiveRecurrenceStore(settings, now_func=lambda: now[0])
    request = ActiveRecurrenceCreateRequest(
        capability="active_dns_inventory", interval_days=7,
        timezone_name="Europe/Madrid", window_weekdays=["sunday"],
        window_start_hour=2, window_duration_hours=2,
        recurrence_confirmed=True, idempotency_key="1" * 32,
    )
    record, _ = store.create(
        request, organization_id=OWNER, asset_id="2" * 32, actor_id=OWNER,
        actor_role="administrator", authorization_revision_id="3" * 32,
        authorization_revision_digest_sha256="4" * 64,
        authorization_revision_sequence=1,
        authorization_expires_at=now[0] + timedelta(days=800), verification_id="5" * 32,
    )
    # Europe/Madrid 02:00 does not exist on 2026-03-29; the contract skips
    # that whole window rather than inventing a local instant.
    local = record.next_run_at.astimezone(ZoneInfo("Europe/Madrid"))
    assert local.date().isoformat() == "2026-04-05"
    assert local.hour == 2 and recurrence_is_within_window(record, record.next_run_at)

    observed = []
    for index in range(52):
        assert recurrence_is_within_window(record, record.next_run_at)
        observed.append(record.next_run_at)
        now[0] = record.next_run_at
        record = store.record_dispatch(record, job_id=f"{index + 1:032x}", now=now[0])
        assert record.status == "active"
    assert observed == sorted(set(observed))
    assert all(next_value > value for value, next_value in zip(observed, observed[1:]))

    # The repeated hour at the end of DST is one continuous bounded window:
    # both real instants represented by local 02:30 remain eligible.
    assert recurrence_is_within_window(
        record, datetime(2026, 10, 25, 0, 30, tzinfo=timezone.utc)
    )
    assert recurrence_is_within_window(
        record, datetime(2026, 10, 25, 1, 30, tzinfo=timezone.utc)
    )


def test_failure_backoff_is_persisted_capped_and_stops_at_authorization(tmp_path):
    now, _settings, _assets, _verifications, store, asset, verified, revision, request = configured(tmp_path)
    record, _ = store.create(
        request, organization_id=OWNER, asset_id=asset.id, actor_id=OWNER,
        actor_role="administrator", authorization_revision_id=revision.id,
        authorization_revision_digest_sha256=revision.digest_sha256,
        authorization_revision_sequence=revision.sequence,
        authorization_expires_at=revision.expires_at, verification_id=verified.id,
    )
    now[0] = record.next_run_at
    delays = []
    for _ in range(ACTIVE_RECURRENCE_MAX_FAILURES + 2):
        attempted_at = now[0]
        record = store.record_failure(record, "runner_unavailable", now=attempted_at)
        assert record.failure_count <= ACTIVE_RECURRENCE_MAX_FAILURES
        assert record.next_retry_at is not None
        assert recurrence_is_within_window(record, record.next_retry_at)
        delays.append((record.next_retry_at - attempted_at).total_seconds())
        now[0] = record.next_retry_at
    assert record.failure_count == ACTIVE_RECURRENCE_MAX_FAILURES
    # While the retry remains in the same daily window, exponential base
    # delay is capped at six hours plus its documented 0..60 second jitter.
    assert any(
        ACTIVE_RECURRENCE_MAX_BACKOFF_SECONDS <= delay <= ACTIVE_RECURRENCE_MAX_BACKOFF_SECONDS + 60
        for delay in delays
    )

    expiring = record.model_copy(
        update={
            "authorization_expires_at": now[0] + timedelta(seconds=1),
            "updated_at": record.updated_at,
        }
    )
    path = store._path(OWNER, record.id)
    path.write_text(expiring.model_dump_json(), encoding="utf-8")
    suspended = store.record_failure(expiring, "runner_unavailable", now=now[0])
    assert suspended.status == "suspended"
    assert suspended.reason_code == "authorization_unavailable"
    assert suspended.next_retry_at is None


def test_legacy_policy_migrates_lazily_without_changing_occurrence_identity(tmp_path):
    _now, settings, _assets, _verifications, store, asset, verified, revision, request = configured(tmp_path)
    record, _ = store.create(
        request, organization_id=OWNER, asset_id=asset.id, actor_id=OWNER,
        actor_role="administrator", authorization_revision_id=revision.id,
        authorization_revision_digest_sha256=revision.digest_sha256,
        authorization_revision_sequence=revision.sequence,
        authorization_expires_at=revision.expires_at, verification_id=verified.id,
    )
    occurrence_key = recurrence_occurrence_key(record)
    path = settings.data_dir / "results" / "active_recurrences" / OWNER / f"{record.id}.json"
    legacy = json.loads(path.read_text(encoding="utf-8"))
    legacy["contract_version"] = "2026-09-08.1"
    for field in (
        "idempotency_domain_version", "authorization_expires_at", "timezone_name",
        "window_weekdays", "window_start_hour", "window_duration_hours",
        "failure_count", "next_retry_at", "last_attempt_at", "last_outcome",
    ):
        legacy.pop(field, None)
    path.write_text(json.dumps(legacy), encoding="utf-8")

    migrated = ActiveRecurrenceStore(settings).get(record.id, organization_id=OWNER, asset_id=asset.id)
    assert migrated.contract_version == "2026-09-08.2"
    assert migrated.timezone_name == "UTC" and migrated.window_duration_hours == 24
    assert migrated.authorization_expires_at is None
    assert migrated.status == "suspended"
    assert migrated.reason_code == "authorization_unavailable"
    assert recurrence_occurrence_key(migrated) == occurrence_key
    paused = ActiveRecurrenceStore(settings).pause(
        migrated.id, organization_id=OWNER, asset_id=asset.id,
        expected_updated_at=migrated.updated_at,
    )
    assert json.loads(path.read_text(encoding="utf-8"))["contract_version"] == "2026-09-08.2"
    assert paused.status == "paused"


def test_recurrence_window_rejects_unknown_timezone_cross_midnight_and_stale_writer(tmp_path):
    with pytest.raises(ValueError):
        ActiveRecurrenceCreateRequest(
            capability="active_dns_inventory", timezone_name="Unknown/Private",
            window_weekdays=["monday"], window_start_hour=9, window_duration_hours=2,
            recurrence_confirmed=True, idempotency_key="6" * 32,
        )
    with pytest.raises(ValueError):
        ActiveRecurrenceCreateRequest(
            capability="active_dns_inventory", timezone_name="UTC",
            window_weekdays=["monday"], window_start_hour=23, window_duration_hours=2,
            recurrence_confirmed=True, idempotency_key="6" * 32,
        )

    now, _settings, _assets, _verifications, store, asset, verified, revision, request = configured(tmp_path / "cas")
    record, _ = store.create(
        request, organization_id=OWNER, asset_id=asset.id, actor_id=OWNER,
        actor_role="administrator", authorization_revision_id=revision.id,
        authorization_revision_digest_sha256=revision.digest_sha256,
        authorization_revision_sequence=revision.sequence,
        authorization_expires_at=revision.expires_at, verification_id=verified.id,
    )
    now[0] = record.next_run_at
    first = store.list_due(now=now[0])[0]
    stale = store.list_due(now=now[0])[0]
    store.record_dispatch(first, job_id="7" * 32, now=now[0])
    with pytest.raises(ActiveRecurrenceError, match="state_changed"):
        store.record_dispatch(stale, job_id="8" * 32, now=now[0])
