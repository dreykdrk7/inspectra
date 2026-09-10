from __future__ import annotations

from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor
import json
import stat

import pytest
from pydantic import BaseModel

from app.active_change_approvals import (
    ActiveChangeApprovalError,
    ActiveChangeApprovalStore,
    ActiveChangeSummary,
    active_change_operation_digest,
)
from app.config import load_settings


NOW = datetime(2026, 9, 10, 12, tzinfo=timezone.utc)
ORG_A = "a" * 32
ORG_B = "b" * 32
REQUESTER = "c" * 32
APPROVER = "d" * 32


class ExamplePayload(BaseModel):
    value: str
    authorization_reference: str
    responsible_user_ids: list[str]


def _store(monkeypatch, tmp_path, clock):
    monkeypatch.setenv("INSPECTRA_DATA_DIR", str(tmp_path))
    settings = load_settings()
    settings.ensure_directories()
    return ActiveChangeApprovalStore(settings, now_func=lambda: clock[0]), settings


def _request(store, *, organization_id=ORG_A, actor_id=REQUESTER, payload=None):
    payload = payload or ExamplePayload(
        value="private.example.test",
        authorization_reference="private-ticket-42",
        responsible_user_ids=["e" * 32],
    )
    digest = active_change_operation_digest(
        organization_id=organization_id, kind="registration", asset_id=None, payload=payload
    )
    record = store.request(
        organization_id=organization_id, actor_id=actor_id, actor_role="maintainer",
        kind="registration", asset_id=None, operation_digest_sha256=digest,
        summary=ActiveChangeSummary(
            asset_type="domain", review_target=payload.value,
            scope_change="new_registration", capabilities=("active_dns_inventory",),
            allowed_protocols=("dns",), authorization_expires_at=NOW + timedelta(days=30),
        ),
    )
    return payload, digest, record


def test_four_eyes_is_durable_one_use_and_scrubs_terminal_target(monkeypatch, tmp_path):
    clock = [NOW]
    store, settings = _store(monkeypatch, tmp_path, clock)
    payload, digest, requested = _request(store)

    approved = store.approve(ORG_A, requested.id, APPROVER, "administrator")
    claimed = store.claim(
        ORG_A, requested.id, REQUESTER, kind="registration", asset_id=None,
        operation_digest_sha256=digest,
    )
    consumed = store.finish(ORG_A, requested.id, succeeded=True)
    restarted = ActiveChangeApprovalStore(settings, now_func=lambda: clock[0])
    persisted = restarted.list(ORG_A)[0]

    assert approved.status == "approved"
    assert claimed.status == "executing"
    assert consumed.status == persisted.status == "consumed"
    assert persisted.summary.review_target is None
    with pytest.raises(ActiveChangeApprovalError, match="approval_not_ready"):
        restarted.claim(
            ORG_A, requested.id, REQUESTER, kind="registration", asset_id=None,
            operation_digest_sha256=digest,
        )
    serialized = (settings.results_dir / "active_change_approvals" / f"{ORG_A}.json").read_text()
    assert payload.value not in serialized
    assert payload.authorization_reference not in serialized
    assert payload.responsible_user_ids[0] not in serialized
    assert REQUESTER not in serialized
    assert APPROVER not in serialized
    assert stat.S_IMODE(settings.active_change_approvals_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE((settings.active_change_approvals_dir / f"{ORG_A}.json").stat().st_mode) == 0o600


def test_same_actor_mismatch_and_cross_tenant_fail_closed(monkeypatch, tmp_path):
    clock = [NOW]
    store, _settings = _store(monkeypatch, tmp_path, clock)
    _payload, digest, requested = _request(store)

    with pytest.raises(ActiveChangeApprovalError, match="same_actor"):
        store.approve(ORG_A, requested.id, REQUESTER, "administrator")
    with pytest.raises(ActiveChangeApprovalError, match="approval_not_found"):
        store.approve(ORG_B, requested.id, APPROVER, "administrator")
    approved = store.approve(ORG_A, requested.id, APPROVER, "administrator")
    assert approved.status == "approved"
    with pytest.raises(ActiveChangeApprovalError, match="approval_mismatch"):
        store.claim(
            ORG_A, requested.id, REQUESTER, kind="registration", asset_id=None,
            operation_digest_sha256="f" * 64,
        )
    with pytest.raises(ActiveChangeApprovalError, match="requester_required"):
        store.claim(
            ORG_A, requested.id, "e" * 32, kind="registration", asset_id=None,
            operation_digest_sha256=digest,
        )


def test_expiry_rejection_and_interrupted_claim_scrub_actionable_target(monkeypatch, tmp_path):
    clock = [NOW]
    store, settings = _store(monkeypatch, tmp_path, clock)
    _payload, digest, expiring = _request(store)
    clock[0] = NOW + timedelta(hours=25)
    expired = store.list(ORG_A)[0]
    assert expired.status == "expired"
    assert expired.summary.review_target is None

    clock[0] = NOW + timedelta(hours=26)
    _payload2, digest2, rejected_request = _request(store, payload=ExamplePayload(
        value="second.example.test", authorization_reference="ticket-2",
        responsible_user_ids=["e" * 32],
    ))
    rejected = store.reject(ORG_A, rejected_request.id, APPROVER, "administrator")
    assert rejected.status == "rejected"
    assert rejected.summary.review_target is None

    _payload3, digest3, interrupted_request = _request(store, payload=ExamplePayload(
        value="third.example.test", authorization_reference="ticket-3",
        responsible_user_ids=["e" * 32],
    ))
    store.approve(ORG_A, interrupted_request.id, APPROVER, "administrator")
    store.claim(
        ORG_A, interrupted_request.id, REQUESTER, kind="registration", asset_id=None,
        operation_digest_sha256=digest3,
    )
    restarted = ActiveChangeApprovalStore(settings, now_func=lambda: clock[0])
    recovered = next(item for item in restarted.list(ORG_A) if item.id == interrupted_request.id)
    assert recovered.status == "interrupted"
    assert recovered.summary.review_target is None


def test_corrupt_or_linked_store_fails_closed(monkeypatch, tmp_path):
    clock = [NOW]
    store, settings = _store(monkeypatch, tmp_path, clock)
    _request(store)
    path = settings.results_dir / "active_change_approvals" / f"{ORG_A}.json"
    path.write_text("{not-json", encoding="utf-8")
    with pytest.raises(ActiveChangeApprovalError, match="invalid_store"):
        store.list(ORG_A)

    path.unlink()
    target = tmp_path / "outside.json"
    target.write_text(json.dumps({}), encoding="utf-8")
    path.symlink_to(target)
    with pytest.raises(ActiveChangeApprovalError, match="invalid_store"):
        store.list(ORG_A)


def test_only_one_concurrent_administrator_can_decide(monkeypatch, tmp_path):
    clock = [NOW]
    store, _settings = _store(monkeypatch, tmp_path, clock)
    _payload_value, _digest, requested = _request(store)

    def decide(actor: str):
        try:
            return store.approve(ORG_A, requested.id, actor, "administrator").status
        except ActiveChangeApprovalError as exc:
            return exc.code

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(decide, (APPROVER, "e" * 32)))

    assert sorted(outcomes) == ["approval_state_changed", "approved"]


def test_terminal_metadata_is_purged_per_tenant_only(monkeypatch, tmp_path):
    clock = [NOW]
    store, _settings = _store(monkeypatch, tmp_path, clock)
    _payload_a, _digest_a, request_a = _request(store)
    store.reject(ORG_A, request_a.id, APPROVER, "administrator")
    _payload_b, _digest_b, request_b = _request(
        store, organization_id=ORG_B, actor_id=REQUESTER,
    )
    store.reject(ORG_B, request_b.id, APPROVER, "administrator")
    clock[0] = NOW + timedelta(days=91)

    removed = store.purge_terminal(
        organization_id=ORG_A, cutoff=clock[0] - timedelta(days=90)
    )

    assert removed == 1
    assert store.list(ORG_A) == ()
    assert len(store.list(ORG_B)) == 0  # Lazy bounded cleanup is independently enforced.
