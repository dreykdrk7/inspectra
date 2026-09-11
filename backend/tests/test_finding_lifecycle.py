from datetime import datetime, timedelta, timezone
import json

import pytest

import app.finding_lifecycle as lifecycle_module
from app.config import Settings
from app.finding_lifecycle import (
    FindingDecisionStore,
    FindingLifecycleError,
    extract_decision_mentions,
)
from app.models import NormalizedFinding


PROJECT_ID = "b" * 32
FINDING_ID = "a" * 64


def _settings(tmp_path):
    settings = Settings(data_dir=tmp_path, tool_runner_url="http://audit-tools:8081")
    settings.ensure_directories()
    return settings


def _finding() -> NormalizedFinding:
    return NormalizedFinding(
        id=FINDING_ID,
        rule_id="configuration_debug_enabled",
        source_audit_type="project_archive_basic",
        title="Review production setting",
        category="configuration",
        severity="high",
        confidence="high",
    )


def _record(store: FindingDecisionStore, **overrides):
    values = {
        "organization_id": "local-admin",
        "project_id": PROJECT_ID,
        "finding_id": FINDING_ID,
        "rule_id": "configuration_debug_enabled",
        "status": "in_review",
        "reason": "Needs owner validation",
        "comment": None,
        "actor_id": "team-admin",
        "actor_username": "admin",
        "actor_role": "administrator",
        "review_at": None,
        "assignee_user_id": None,
        "assignee_username": None,
    }
    values.update(overrides)
    return store.record(**values)


def _batch(store: FindingDecisionStore, *, key="recoverable-batch-key-01", payload=None):
    request_payload = payload or {"group_id": "e" * 64, "selection": "two"}
    operation_id, request_digest = store.batch_binding(
        organization_id="local-admin",
        actor_id="team-admin",
        idempotency_key=key,
        request_payload=request_payload,
    )
    result = store.record_many(
        organization_id="local-admin",
        operation_id=operation_id,
        request_digest=request_digest,
        group_id="e" * 64,
        items=[
            (PROJECT_ID, FINDING_ID, "configuration_debug_enabled"),
            ("c" * 32, "d" * 64, "configuration_other"),
        ],
        status="in_review",
        reason="Review together",
        comment="No sensitive evidence is copied to the journal",
        actor_id="team-admin",
        actor_username="admin",
        actor_role="administrator",
        review_at=None,
        assignee_user_id=None,
        assignee_username=None,
    )
    return operation_id, request_digest, result


def test_decisions_are_append_only_redacted_and_scoped(tmp_path):
    now = datetime(2026, 9, 6, 9, 0, tzinfo=timezone.utc)
    store = FindingDecisionStore(_settings(tmp_path), now_func=lambda: now)

    first = _record(
        store,
        reason="password=super-secret-value",
        comment="Authorization: Bearer sensitive-token-value",
        assignee_user_id="reader-id",
        assignee_username="reader",
    )
    second = _record(store, status="resolved", reason="Verified in a new snapshot")

    assert first.reason == "password=[REDACTED]"
    assert first.comment is not None and "sensitive-token-value" not in first.comment
    assert "[REDACTED" in first.comment
    assert second.previous_decision_id == first.id
    assert first.id != second.id
    assert store.list_for_project("local-admin", PROJECT_ID) == [first, second]
    assert store.list_for_project("c" * 32, PROJECT_ID) == []

    persisted = "\n".join(path.read_text() for path in store.directory.glob("*.json"))
    assert "super-secret-value" not in persisted
    assert "sensitive-token-value" not in persisted
    assert json.loads(next(store.directory.glob("*.json")).read_text())["organization_id"] == "local-admin"


def test_mentions_are_bounded_and_activity_pages_are_stable_and_owner_scoped(tmp_path):
    store = FindingDecisionStore(_settings(tmp_path))
    decisions = []
    for index in range(12):
        decisions.append(_record(
            store,
            status="in_review" if index % 2 == 0 else "open",
            reason=f"Review step {index}",
            comment="Coordinate with @reader.one and admin@example.test is an email.",
            mentioned_usernames=["reader.one"],
        ))

    first, total, cursor = store.page_for_finding(
        "local-admin", PROJECT_ID, FINDING_ID, page_size=5
    )
    second, second_total, second_cursor = store.page_for_finding(
        "local-admin", PROJECT_ID, FINDING_ID, page_size=5, cursor=cursor
    )
    third, third_total, final_cursor = store.page_for_finding(
        "local-admin", PROJECT_ID, FINDING_ID, page_size=5, cursor=second_cursor
    )

    assert [record.id for record in first + second + third] == [
        record.id for record in reversed(decisions)
    ]
    assert total == second_total == third_total == 12
    assert cursor == first[-1].id
    assert second_cursor == second[-1].id
    assert final_cursor is None
    assert all(record.mentioned_usernames == ["reader.one"] for record in decisions)
    assert extract_decision_mentions("mail admin@example.test and mention @reader.one twice @reader.one") == ["reader.one"]
    lifecycle = store.lifecycle_for_findings("local-admin", PROJECT_ID, [_finding()])[FINDING_ID]
    assert lifecycle.history_total == 12
    assert lifecycle.history_has_more is True
    assert len(lifecycle.history) == 10
    assert lifecycle.history[0].id == decisions[-1].id

    with pytest.raises(FindingLifecycleError, match="invalid_activity_cursor"):
        store.page_for_finding("c" * 32, PROJECT_ID, FINDING_ID, cursor=cursor)
    with pytest.raises(FindingLifecycleError, match="invalid_activity_cursor"):
        store.page_for_finding("local-admin", PROJECT_ID, FINDING_ID, cursor="f" * 32)
    with pytest.raises(FindingLifecycleError, match="invalid_mentions"):
        _record(
            store,
            status="in_review",
            comment="Coordinate with @reader.one",
            mentioned_usernames=[],
        )
    with pytest.raises(FindingLifecycleError, match="invalid_mentions"):
        extract_decision_mentions(" ".join(f"@member{index}" for index in range(6)))


def test_report_snapshot_is_owner_scoped_and_rejects_decisions_after_cutoff(tmp_path):
    clock = [datetime(2026, 9, 9, 9, 0, tzinfo=timezone.utc)]
    store = FindingDecisionStore(_settings(tmp_path), now_func=lambda: clock[0])
    first = _record(store)
    foreign = _record(
        store,
        organization_id="c" * 32,
        project_id="d" * 32,
        finding_id="e" * 64,
        rule_id="configuration_other",
    )

    snapshot = store.report_snapshot("local-admin", cutoff=clock[0])

    assert snapshot == {PROJECT_ID: [first]}
    assert foreign.id not in {item.id for records in snapshot.values() for item in records}
    cutoff = clock[0]
    clock[0] += timedelta(seconds=1)
    _record(store, status="resolved", reason="Observed after the report cutoff")
    with pytest.raises(FindingLifecycleError, match="snapshot_changed"):
        store.report_snapshot("local-admin", cutoff=cutoff)


def test_exception_expiry_returns_finding_to_review_without_mutating_history(tmp_path):
    clock = [datetime(2026, 9, 6, 9, 0, tzinfo=timezone.utc)]
    store = FindingDecisionStore(_settings(tmp_path), now_func=lambda: clock[0])
    review_at = clock[0] + timedelta(days=30)
    accepted = _record(
        store,
        status="accepted",
        reason="Documented temporary risk acceptance",
        review_at=review_at,
    )

    current = store.lifecycle_for_findings("local-admin", PROJECT_ID, [_finding()])[FINDING_ID]
    assert current.current_status == "accepted"
    assert current.needs_review is False
    assert current.review_overdue is False

    clock[0] = review_at + timedelta(seconds=1)
    expired = store.lifecycle_for_findings("local-admin", PROJECT_ID, [_finding()])[FINDING_ID]
    assert expired.current_status == "in_review"
    assert expired.needs_review is True
    assert expired.review_overdue is True
    assert expired.current_decision == accepted
    assert expired.history == [accepted]

    renewed = _record(
        store,
        status="accepted",
        reason="Risk acceptance reviewed again",
        review_at=clock[0] + timedelta(days=30),
    )
    assert renewed.previous_decision_id == accepted.id


def test_invalid_transitions_review_dates_and_assignees_fail_closed(tmp_path):
    now = datetime(2026, 9, 6, 9, 0, tzinfo=timezone.utc)
    store = FindingDecisionStore(_settings(tmp_path), now_func=lambda: now)
    _record(store, status="resolved", reason="Verified as remediated")

    with pytest.raises(FindingLifecycleError, match="invalid_transition"):
        _record(
            store,
            status="accepted",
            reason="Cannot accept a resolved item directly",
            review_at=now + timedelta(days=30),
        )
    with pytest.raises(FindingLifecycleError, match="review_date_not_allowed"):
        _record(store, status="open", reason="Reopen for review", review_at=now + timedelta(days=1))
    with pytest.raises(FindingLifecycleError, match="review_date_not_future"):
        _record(store, status="in_review", reason="First reopen")
        _record(store, status="accepted", reason="Expired immediately", review_at=now)
    with pytest.raises(FindingLifecycleError, match="review_date_required"):
        _record(store, status="false_positive", reason="Must be reviewed later")
    with pytest.raises(FindingLifecycleError, match="review_date_timezone_required"):
        _record(store, status="false_positive", reason="Timezone is required", review_at=datetime(2026, 10, 1))
    with pytest.raises(FindingLifecycleError, match="review_date_too_far"):
        _record(store, status="false_positive", reason="Not a temporary exception", review_at=now + timedelta(days=367))
    with pytest.raises(FindingLifecycleError, match="invalid_assignee"):
        _record(store, status="open", reason="Reopen after resolution", assignee_user_id="reader-id")


def test_legacy_exception_without_review_date_fails_into_review(tmp_path):
    now = datetime(2026, 9, 6, 9, 0, tzinfo=timezone.utc)
    store = FindingDecisionStore(_settings(tmp_path), now_func=lambda: now)
    legacy = _record(store, status="accepted", reason="Legacy exception", review_at=now + timedelta(days=30))
    path = store.directory / f"{legacy.id}.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["review_at"] = None
    path.write_text(json.dumps(payload), encoding="utf-8")

    state = store.lifecycle_for_findings("local-admin", PROJECT_ID, [_finding()])[FINDING_ID]

    assert state.current_status == "in_review"
    assert state.needs_review is True
    assert state.review_overdue is True
    assert state.current_decision is not None and state.current_decision.review_at is None


def test_store_rejects_invalid_persisted_records_without_leaking_path(tmp_path):
    store = FindingDecisionStore(_settings(tmp_path))
    (store.directory / ("f" * 32 + ".json")).write_text("{not-json", encoding="utf-8")

    with pytest.raises(FindingLifecycleError, match="stored_decision_invalid"):
        store.list_for_project("local-admin", PROJECT_ID)


@pytest.mark.parametrize("mutation", ["filename", "broken_chain", "assignment", "naive_time"])
def test_store_rejects_semantically_invalid_or_tampered_history(tmp_path, mutation):
    store = FindingDecisionStore(
        _settings(tmp_path),
        now_func=lambda: datetime(2026, 9, 6, 9, 0, tzinfo=timezone.utc),
        id_factory=iter(["1" * 32, "0" * 32]).__next__,
    )
    first = _record(store)
    second = _record(store, status="resolved", reason="Verified in a new snapshot")
    assert store.list_for_project("local-admin", PROJECT_ID) == [first, second]

    target_path = store.directory / f"{second.id}.json"
    payload = json.loads(target_path.read_text(encoding="utf-8"))
    if mutation == "filename":
        target_path.rename(store.directory / ("f" * 32 + ".json"))
    elif mutation == "broken_chain":
        payload["previous_decision_id"] = "e" * 32
        target_path.write_text(json.dumps(payload), encoding="utf-8")
    elif mutation == "assignment":
        payload["assignee_user_id"] = "reader-id"
        target_path.write_text(json.dumps(payload), encoding="utf-8")
    else:
        payload["created_at"] = "2026-09-06T09:00:00"
        target_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(FindingLifecycleError, match="stored_decision_invalid"):
        store.list_for_project("local-admin", PROJECT_ID)


def test_bounded_batch_supports_public_fingerprints_and_is_append_only(tmp_path):
    now = datetime(2026, 9, 9, 9, 0, tzinfo=timezone.utc)
    store = FindingDecisionStore(
        _settings(tmp_path),
        now_func=lambda: now,
        id_factory=iter(["1" * 32, "2" * 32]).__next__,
    )
    public_id = "pvf_" + "c" * 64
    operation_id, request_digest = store.batch_binding(
        organization_id="local-admin", actor_id="team-admin",
        idempotency_key="batch-public-fingerprints-01", request_payload={"selection": "two"},
    )
    records, replayed = store.record_many(
        organization_id="local-admin",
        operation_id=operation_id,
        request_digest=request_digest,
        group_id="e" * 64,
        items=[
            (PROJECT_ID, FINDING_ID, "configuration_debug_enabled"),
            ("c" * 32, public_id, "public_vulnerability:CVE-2026-1000"),
        ],
        status="in_review",
        reason="password=must-not-persist",
        comment=None,
        actor_id="team-admin",
        actor_username="admin",
        actor_role="administrator",
        review_at=None,
        assignee_user_id=None,
        assignee_username=None,
    )

    assert replayed is False
    assert len(records) == 2
    assert records[1].finding_id == public_id
    assert records[0].reason == "password=[REDACTED]"
    assert store.list_for_project("local-admin", PROJECT_ID) == [records[0]]
    assert store.list_for_project("local-admin", "c" * 32) == [records[1]]


def test_batch_rolls_back_new_records_when_a_write_fails(monkeypatch, tmp_path):
    store = FindingDecisionStore(
        _settings(tmp_path),
        now_func=lambda: datetime(2026, 9, 9, 9, 0, tzinfo=timezone.utc),
        id_factory=iter(["1" * 32, "2" * 32]).__next__,
    )
    original = lifecycle_module._durable_write_json
    calls = 0

    def fail_second(path, payload):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("simulated storage outage")
        original(path, payload)

    monkeypatch.setattr(lifecycle_module, "_durable_write_json", fail_second)
    operation_id, request_digest = store.batch_binding(
        organization_id="local-admin", actor_id="team-admin",
        idempotency_key="batch-storage-failure-01", request_payload={"selection": "two"},
    )
    with pytest.raises(FindingLifecycleError, match="store_unavailable"):
        store.record_many(
            organization_id="local-admin",
            operation_id=operation_id,
            request_digest=request_digest,
            group_id="e" * 64,
            items=[
                (PROJECT_ID, FINDING_ID, "configuration_debug_enabled"),
                ("c" * 32, "d" * 64, "configuration_other"),
            ],
            status="in_review",
            reason="Review together",
            comment=None,
            actor_id="team-admin",
            actor_username="admin",
            actor_role="administrator",
            review_at=None,
            assignee_user_id=None,
            assignee_username=None,
        )

    assert list(store.directory.glob("*.json")) == []


@pytest.mark.parametrize(
    ("boundary", "committed_before_restart"),
    [("prepared", False), ("decision_written", False), ("committed", True), ("cleaned", True)],
)
def test_recoverable_batch_survives_each_durable_boundary(tmp_path, boundary, committed_before_restart):
    settings = _settings(tmp_path)
    triggered = False

    def interrupt(step):
        nonlocal triggered
        if step == boundary and not triggered:
            triggered = True
            raise RuntimeError("simulated abrupt process exit")

    interrupted = FindingDecisionStore(
        settings,
        now_func=lambda: datetime(2026, 9, 9, 9, 0, tzinfo=timezone.utc),
        id_factory=iter(["1" * 32, "2" * 32]).__next__,
        after_batch_step=interrupt,
    )
    with pytest.raises(RuntimeError, match="abrupt process exit"):
        _batch(interrupted)
    assert bool(interrupted.list_for_project("local-admin", PROJECT_ID)) is committed_before_restart

    restarted = FindingDecisionStore(settings)
    assert restarted.recover_pending_batches() == (0 if boundary == "cleaned" else 1)
    visible = restarted.list_for_project("local-admin", PROJECT_ID)
    assert len(visible) == 1
    operation_id, request_digest = restarted.batch_binding(
        organization_id="local-admin", actor_id="team-admin",
        idempotency_key="recoverable-batch-key-01",
        request_payload={"group_id": "e" * 64, "selection": "two"},
    )
    replay = restarted.replay_batch(
        operation_id, organization_id="local-admin", request_digest=request_digest,
    )
    assert replay is not None and len(replay) == 2
    assert restarted.replay_batch(
        operation_id, organization_id="local-admin", request_digest=request_digest,
    ) == replay
    assert len(list(restarted.directory.glob("*.json"))) == 2
    assert restarted.has_pending_batches() is False


def test_failure_before_prepare_removes_uncommitted_staging(tmp_path):
    settings = _settings(tmp_path)

    def interrupt(step):
        if step == "staged":
            raise RuntimeError("simulated pre-prepare exit")

    store = FindingDecisionStore(
        settings,
        id_factory=iter(["1" * 32, "2" * 32]).__next__,
        after_batch_step=interrupt,
    )
    with pytest.raises(RuntimeError, match="pre-prepare"):
        _batch(store)
    assert store.has_pending_batches() is False
    assert list(store.directory.glob("*.json")) == []
    assert FindingDecisionStore(settings).recover_pending_batches() == 0


def test_batch_idempotency_is_owner_scoped_and_request_bound(tmp_path):
    settings = _settings(tmp_path)
    first = FindingDecisionStore(settings, id_factory=iter(["1" * 32, "2" * 32]).__next__)
    operation_id, request_digest, (records, replayed) = _batch(first)
    assert replayed is False
    repeated = _batch(first)[2]
    assert repeated == (records, True)

    _same_operation, conflicting_digest = first.batch_binding(
        organization_id="local-admin", actor_id="team-admin",
        idempotency_key="recoverable-batch-key-01", request_payload={"selection": "different"},
    )
    with pytest.raises(FindingLifecycleError, match="idempotency_conflict"):
        first.replay_batch(
            operation_id, organization_id="local-admin", request_digest=conflicting_digest,
        )

    other_operation, _other_digest = first.batch_binding(
        organization_id="f" * 32, actor_id="team-admin",
        idempotency_key="recoverable-batch-key-01", request_payload={"selection": "different"},
    )
    assert other_operation != operation_id


def test_batch_journal_and_receipt_exclude_human_text_and_reject_corruption(tmp_path):
    settings = _settings(tmp_path)
    store = FindingDecisionStore(settings, id_factory=iter(["1" * 32, "2" * 32]).__next__)
    operation_id, _request_digest, (_records, replayed) = _batch(store)
    assert replayed is False
    receipt_path = settings.remediation_batches_dir / f"{operation_id}.json"
    persisted_receipt = receipt_path.read_text(encoding="utf-8")
    assert "Review together" not in persisted_receipt
    assert "sensitive evidence" not in persisted_receipt
    assert '"admin"' not in persisted_receipt

    payload = json.loads(persisted_receipt)
    payload["decision_digests"][payload["decision_ids"][0]] = "0" * 64
    receipt_path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(FindingLifecycleError, match="batch_state_invalid|stored_decision_invalid"):
        store.list_for_project("local-admin", PROJECT_ID)


def test_pending_batch_corruption_fails_closed_and_retains_recovery_evidence(tmp_path):
    settings = _settings(tmp_path)

    def interrupt(step):
        if step == "prepared":
            raise RuntimeError("simulated stop after durable prepare")

    store = FindingDecisionStore(
        settings,
        id_factory=iter(["1" * 32, "2" * 32]).__next__,
        after_batch_step=interrupt,
    )
    with pytest.raises(RuntimeError):
        operation_id, _digest, _result = _batch(store)
    journal_path = next(settings.remediation_batch_journals_dir.glob("*.json"))
    operation_id = journal_path.stem
    journal_text = journal_path.read_text(encoding="utf-8")
    assert "Review together" not in journal_text
    assert "sensitive evidence" not in journal_text
    staged_path = next((settings.remediation_batch_journals_dir / f".{operation_id}.staging").glob("*.json"))
    staged = json.loads(staged_path.read_text(encoding="utf-8"))
    staged["reason"] = "Tampered after prepare"
    staged_path.write_text(json.dumps(staged), encoding="utf-8")

    restarted = FindingDecisionStore(settings)
    with pytest.raises(FindingLifecycleError, match="batch_state_invalid"):
        restarted.recover_pending_batches()
    assert restarted.has_pending_batches() is True
    assert restarted.list_for_project("local-admin", PROJECT_ID) == []


def test_same_idempotency_key_cannot_cross_organization_boundary(tmp_path):
    settings = _settings(tmp_path)
    store = FindingDecisionStore(
        settings,
        id_factory=iter(["1" * 32, "2" * 32]).__next__,
    )
    operations = []
    for owner, project, finding in [
        ("a" * 32, "b" * 32, "c" * 64),
        ("d" * 32, "e" * 32, "f" * 64),
    ]:
        operation_id, request_digest = store.batch_binding(
            organization_id=owner,
            actor_id="team-admin",
            idempotency_key="same-private-client-key-01",
            request_payload={"project": project},
        )
        decisions, replayed = store.record_many(
            organization_id=owner,
            operation_id=operation_id,
            request_digest=request_digest,
            group_id="9" * 64,
            items=[(project, finding, "configuration_owner_scope")],
            status="in_review",
            reason="Owner scoped review",
            comment=None,
            actor_id="team-admin",
            actor_username="admin",
            actor_role="administrator",
            review_at=None,
            assignee_user_id=None,
            assignee_username=None,
        )
        assert replayed is False
        assert store.list_for_project(owner, project) == decisions
        operations.append(operation_id)
    assert operations[0] != operations[1]
