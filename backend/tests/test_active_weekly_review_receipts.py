from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import json
import os

import pytest

from app.active_weekly_report import ActiveWeeklyReportPreflight
from app.active_weekly_review_receipts import (
    ACTIVE_WEEKLY_REVIEW_RECEIPT_KEY_NAME,
    ACTIVE_WEEKLY_REVIEW_RECEIPT_MAX_RECORDS,
    ActiveWeeklyReviewReceiptError,
    ActiveWeeklyReviewReceiptStore,
)
from app.config import Settings
from app.storage import storage_lock


ORG = "1" * 32
OTHER_ORG = "2" * 32
NOW = datetime(2026, 9, 10, 12, tzinfo=timezone.utc)
RAW_DIGEST = "a" * 64


def _settings(tmp_path):
    settings = Settings(data_dir=tmp_path, tool_runner_url="http://audit-tools:8081")
    settings.ensure_directories()
    return settings


def _preflight(*, digest=RAW_DIGEST, state_at=NOW, state="ready", incomplete=False):
    return ActiveWeeklyReportPreflight(
        state=state,
        period="7d",
        starts_at=state_at - timedelta(days=7),
        state_at=state_at,
        snapshot_digest=digest,
        assets_total=1,
        assets_included=1,
        jobs_total=0,
        jobs_included=0,
        actions_total=0,
        actions_included=0,
        recurrence_attention_total=0,
        recurrence_attention_included=0,
        incomplete=incomplete,
    )


def test_receipt_is_target_free_keyed_private_and_survives_restart(tmp_path):
    settings = _settings(tmp_path)
    store = ActiveWeeklyReviewReceiptStore(settings, now_func=lambda: NOW)
    result = store.create(
        organization_id=ORG,
        preflight=_preflight(),
        outcome="follow_up_required",
        expected_revision=0,
        idempotency_key="weekly-review-idempotency-001",
    )

    receipt_path = settings.active_weekly_review_receipts_dir / f"{ORG}.json"
    key_path = settings.active_weekly_review_receipts_dir / ACTIVE_WEEKLY_REVIEW_RECEIPT_KEY_NAME
    raw = receipt_path.read_bytes()
    assert result.replayed is False
    assert result.receipt.snapshot_hmac_sha256 != RAW_DIGEST
    assert RAW_DIGEST.encode() not in raw
    for canary in (
        b"private-target.example.test",
        b"authorization-note-canary",
        b"reviewer@example.test",
        b"runner-result-canary",
    ):
        assert canary not in raw
    assert os.stat(receipt_path).st_mode & 0o777 == 0o600
    assert os.stat(key_path).st_mode & 0o777 == 0o600
    assert os.stat(settings.active_weekly_review_receipts_dir).st_mode & 0o777 == 0o700
    assert store.verify(ORG, result.receipt.id, RAW_DIGEST).valid is True
    assert store.verify(ORG, result.receipt.id, "b" * 64).valid is False

    restarted = ActiveWeeklyReviewReceiptStore(settings, now_func=lambda: NOW)
    page = restarted.list(ORG)
    assert page.revision == 1
    assert page.items == (result.receipt,)
    assert restarted.verify(ORG, result.receipt.id, RAW_DIGEST).valid is True


def test_receipt_idempotency_revision_and_tenant_boundaries_fail_closed(tmp_path):
    store = ActiveWeeklyReviewReceiptStore(_settings(tmp_path), now_func=lambda: NOW)
    first = store.create(
        organization_id=ORG,
        preflight=_preflight(),
        outcome="reviewed",
        expected_revision=0,
        idempotency_key="weekly-review-idempotency-001",
    )
    replay = store.create(
        organization_id=ORG,
        preflight=_preflight(),
        outcome="reviewed",
        expected_revision=0,
        idempotency_key="weekly-review-idempotency-001",
    )
    assert replay.replayed is True
    assert replay.receipt.id == first.receipt.id
    with pytest.raises(ActiveWeeklyReviewReceiptError, match="idempotency_conflict"):
        store.create(
            organization_id=ORG,
            preflight=_preflight(),
            outcome="follow_up_required",
            expected_revision=1,
            idempotency_key="weekly-review-idempotency-001",
        )
    with pytest.raises(ActiveWeeklyReviewReceiptError, match="stale_revision"):
        store.create(
            organization_id=ORG,
            preflight=_preflight(),
            outcome="reviewed",
            expected_revision=0,
            idempotency_key="weekly-review-idempotency-002",
        )
    with pytest.raises(ActiveWeeklyReviewReceiptError, match="not_found"):
        store.verify(OTHER_ORG, first.receipt.id, RAW_DIGEST)


def test_concurrent_receipt_creation_accepts_exactly_one_revision(tmp_path):
    settings = _settings(tmp_path)
    ActiveWeeklyReviewReceiptStore(settings, now_func=lambda: NOW)

    def create(index: int):
        return ActiveWeeklyReviewReceiptStore(settings, now_func=lambda: NOW).create(
            organization_id=ORG,
            preflight=_preflight(),
            outcome="reviewed" if index == 0 else "follow_up_required",
            expected_revision=0,
            idempotency_key=f"weekly-review-concurrent-{index:02d}",
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(create, index) for index in range(2)]
    successes = []
    failures = []
    for future in futures:
        try:
            successes.append(future.result())
        except ActiveWeeklyReviewReceiptError as exc:
            failures.append(exc.code)
    assert len(successes) == 1
    assert failures == ["stale_revision"]
    assert len(ActiveWeeklyReviewReceiptStore(settings, now_func=lambda: NOW).list(ORG).items) == 1


def test_receipts_are_bounded_and_expire_without_affecting_other_tenants(tmp_path):
    clock = [NOW]
    store = ActiveWeeklyReviewReceiptStore(_settings(tmp_path), now_func=lambda: clock[0])
    for index in range(ACTIVE_WEEKLY_REVIEW_RECEIPT_MAX_RECORDS + 1):
        page = store.list(ORG)
        store.create(
            organization_id=ORG,
            preflight=_preflight(state_at=clock[0]),
            outcome="reviewed",
            expected_revision=page.revision,
            idempotency_key=f"weekly-review-bounded-{index:03d}",
        )
        clock[0] += timedelta(minutes=1)
    assert len(store.list(ORG).items) == ACTIVE_WEEKLY_REVIEW_RECEIPT_MAX_RECORDS

    clock[0] += timedelta(days=401)
    other = store.create(
        organization_id=OTHER_ORG,
        preflight=_preflight(state_at=clock[0]),
        outcome="follow_up_required",
        expected_revision=0,
        idempotency_key="weekly-review-other-tenant-001",
    )
    assert store.purge(organization_id=ORG, cutoff=clock[0] - timedelta(days=400)) == 52
    assert store.list(ORG).items == ()
    assert store.list(OTHER_ORG).items[0].id == other.receipt.id


def test_receipt_collection_and_key_tampering_fail_closed(tmp_path):
    settings = _settings(tmp_path)
    store = ActiveWeeklyReviewReceiptStore(settings, now_func=lambda: NOW)
    store.create(
        organization_id=ORG,
        preflight=_preflight(),
        outcome="reviewed",
        expected_revision=0,
        idempotency_key="weekly-review-idempotency-001",
    )
    receipt_path = settings.active_weekly_review_receipts_dir / f"{ORG}.json"
    document = json.loads(receipt_path.read_text())
    document["receipts"][0]["outcome"] = "follow_up_required"
    receipt_path.write_text(json.dumps(document), encoding="utf-8")
    receipt_path.chmod(0o600)
    with pytest.raises(ActiveWeeklyReviewReceiptError, match="invalid_store"):
        store.list(ORG)

    other_settings = _settings(tmp_path / "other")
    key_path = other_settings.active_weekly_review_receipts_dir / ACTIVE_WEEKLY_REVIEW_RECEIPT_KEY_NAME
    key_path.symlink_to(tmp_path / "outside-key")
    with pytest.raises(ActiveWeeklyReviewReceiptError, match="invalid_store"):
        ActiveWeeklyReviewReceiptStore(other_settings, now_func=lambda: NOW)


def test_receipt_creation_is_safe_inside_the_shared_snapshot_lock(tmp_path):
    settings = _settings(tmp_path)
    store = ActiveWeeklyReviewReceiptStore(settings, now_func=lambda: NOW)
    with storage_lock(settings):
        created = store.create_with_shared_lock_held(
            organization_id=ORG,
            preflight=_preflight(),
            outcome="reviewed",
            expected_revision=0,
            idempotency_key="weekly-review-shared-lock-001",
        )
        assert store.list(ORG).items[0].id == created.receipt.id
