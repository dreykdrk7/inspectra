from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from app.config import load_settings
from app.integration_events import (
    INTEGRATION_EVENT_MAX_ATTEMPTS,
    INTEGRATION_EVENT_SIGNATURE_VERSION,
    IntegrationEventConfig,
    IntegrationEventDispatcher,
    IntegrationEventError,
    IntegrationEventReplayRequest,
    IntegrationEventStore,
    IntegrationEventTransport,
)
from app.main import enqueue_terminal_project_analysis_event


NOW = datetime(2026, 9, 11, 12, 0, tzinfo=timezone.utc)
ORG = "a" * 32
PROJECT = "b" * 32
ANALYSIS = "c" * 32
KEY = b"k" * 32


class Clock:
    def __init__(self) -> None:
        self.value = NOW

    def __call__(self) -> datetime:
        return self.value


def config() -> IntegrationEventConfig:
    return IntegrationEventConfig(
        endpoint="https://hooks.example.test/inspectra/events",
        host="hooks.example.test",
        signing_key=KEY,
        signing_key_id="rotation-2",
    )


def queued(store: IntegrationEventStore):
    return store.enqueue_terminal_analysis(
        organization_id=ORG,
        project_id=PROJECT,
        analysis_id=ANALYSIS,
        status="completed",
        occurred_at=NOW,
        finding_count=3,
    )


def test_config_is_disabled_by_default_and_rejects_partial_or_unsafe_destination(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("INSPECTRA_DATA_DIR", str(tmp_path))
    assert load_settings().integration_events_enabled is False

    monkeypatch.setenv("INSPECTRA_INTEGRATION_EVENT_ENDPOINT", "https://hooks.example.test/events")
    with pytest.raises(ValueError, match="require INSPECTRA_INTEGRATION_EVENTS_ENABLED"):
        load_settings()

    monkeypatch.setenv("INSPECTRA_INTEGRATION_EVENTS_ENABLED", "true")
    monkeypatch.setenv("INSPECTRA_INTEGRATION_EVENT_ALLOWED_HOST", "hooks.example.test")
    monkeypatch.setenv("INSPECTRA_INTEGRATION_EVENT_SIGNING_KEY", "a2tra2tra2tra2tra2tra2tra2tra2tra2tra2tra2s")
    monkeypatch.setenv("INSPECTRA_INTEGRATION_EVENT_SIGNING_KEY_ID", "rotation-1")
    monkeypatch.setenv("INSPECTRA_INTEGRATION_EVENT_ENDPOINT", "https://hooks.example.test@127.0.0.1/events")
    with pytest.raises(ValueError, match="allowlisted HTTPS URL"):
        load_settings()


@pytest.mark.parametrize(
    "endpoint,host",
    [
        ("http://hooks.example.test/events", "hooks.example.test"),
        ("https://hooks.example.test:8443/events", "hooks.example.test"),
        ("https://hooks.example.test/events?project=x", "hooks.example.test"),
        ("https://other.example.test/events", "hooks.example.test"),
        ("https://127.0.0.1/events", "127.0.0.1"),
    ],
)
def test_config_rejects_noncanonical_destination(endpoint: str, host: str) -> None:
    with pytest.raises(ValueError):
        IntegrationEventConfig(endpoint=endpoint, host=host, signing_key=KEY, signing_key_id="key-1")


def test_store_is_durable_idempotent_tenant_scoped_and_content_minimal(tmp_path: Path) -> None:
    path = tmp_path / "runtime" / "outbox.sqlite3"
    store = IntegrationEventStore(path, now_func=lambda: NOW)
    first = queued(store)
    second = queued(store)

    assert first == second
    assert store.summary(ORG) == {"pending": 1, "delivering": 0, "delivered": 0, "dead": 0}
    assert store.summary("d" * 32) == {"pending": 0, "delivering": 0, "delivered": 0, "dead": 0}
    persisted = path.read_bytes()
    for forbidden in (b"/home/", b".env", b"secret", b"source", b"filename", b"https://"):
        assert forbidden not in persisted
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700
    assert IntegrationEventStore(path, now_func=lambda: NOW).get(first.payload.event_id) == first


def test_store_recovers_expired_claim_and_bounds_retries(tmp_path: Path) -> None:
    clock = Clock()
    store = IntegrationEventStore(tmp_path / "outbox.sqlite3", now_func=clock)
    queued(store)
    claimed = store.claim_due()
    assert claimed is not None and claimed.state == "delivering"
    assert store.claim_due() is None
    clock.value += timedelta(seconds=31)
    recovered = store.claim_due()
    assert recovered is not None and recovered.payload.event_id == claimed.payload.event_id

    record = store.record_result(recovered.payload.event_id, accepted=False, retryable=True)
    while record.state == "pending":
        clock.value = record.next_attempt_at
        claim = store.claim_due()
        assert claim is not None
        record = store.record_result(claim.payload.event_id, accepted=False, retryable=True)
    assert record.state == "dead"
    assert record.attempts == INTEGRATION_EVENT_MAX_ATTEMPTS
    assert record.last_result == "permanent_failure"


def test_store_purges_old_terminal_receipts_without_removing_pending(tmp_path: Path) -> None:
    clock = Clock()
    store = IntegrationEventStore(tmp_path / "outbox.sqlite3", now_func=clock)
    delivered = queued(store)
    claim = store.claim_due()
    assert claim is not None
    store.record_result(claim.payload.event_id, accepted=True, retryable=False)
    clock.value += timedelta(days=31)
    pending = store.enqueue_terminal_analysis(
        organization_id=ORG,
        project_id=PROJECT,
        analysis_id="d" * 32,
        status="failed",
        occurred_at=clock.value,
        finding_count=None,
    )

    assert store.summary(ORG) == {"pending": 1, "delivering": 0, "delivered": 0, "dead": 0}
    assert store.get(pending.payload.event_id).state == "pending"
    with pytest.raises(IntegrationEventError, match="event_not_found"):
        store.get(delivered.payload.event_id)


def test_replay_is_tenant_scoped_snapshot_bound_and_idempotent(tmp_path: Path) -> None:
    clock = Clock()
    store = IntegrationEventStore(tmp_path / "outbox.sqlite3", now_func=clock)
    own = queued(store)
    foreign = store.enqueue_terminal_analysis(
        organization_id="d" * 32,
        project_id="e" * 32,
        analysis_id="f" * 32,
        status="failed",
        occurred_at=NOW,
        finding_count=None,
    )
    for event in (own, foreign):
        claim = store.claim_due()
        assert claim is not None
        store.record_result(claim.payload.event_id, accepted=False, retryable=False)

    preflight = store.replay_preflight(ORG)
    assert preflight.total_dead == preflight.selected_events == 1
    assert "event_id" not in preflight.model_dump(mode="json")
    with pytest.raises(IntegrationEventError, match="replay_snapshot_changed"):
        store.replay_dead(
            ORG,
            IntegrationEventReplayRequest(
                observed_at=preflight.observed_at,
                snapshot_digest="0" * 64,
                confirmation="replay_dead_integration_events",
            ),
        )
    replayed = store.replay_dead(
        ORG,
        IntegrationEventReplayRequest(
            observed_at=preflight.observed_at,
            snapshot_digest=preflight.snapshot_digest,
            confirmation="replay_dead_integration_events",
        ),
    )
    assert replayed.replayed_events == 1 and replayed.remaining_dead == 0
    assert store.get(own.payload.event_id).state == "pending"
    assert store.get(foreign.payload.event_id).state == "dead"
    with pytest.raises(IntegrationEventError, match="no_dead_events"):
        store.replay_dead(
            ORG,
            IntegrationEventReplayRequest(
                observed_at=preflight.observed_at,
                snapshot_digest=preflight.snapshot_digest,
                confirmation="replay_dead_integration_events",
            ),
        )


def test_replay_preflight_expires(tmp_path: Path) -> None:
    clock = Clock()
    store = IntegrationEventStore(tmp_path / "outbox.sqlite3", now_func=clock)
    queued(store)
    claim = store.claim_due()
    assert claim is not None
    store.record_result(claim.payload.event_id, accepted=False, retryable=False)
    preflight = store.replay_preflight(ORG)
    clock.value += timedelta(seconds=301)
    with pytest.raises(IntegrationEventError, match="replay_preflight_expired"):
        store.replay_dead(
            ORG,
            IntegrationEventReplayRequest(
                observed_at=preflight.observed_at,
                snapshot_digest=preflight.snapshot_digest,
                confirmation="replay_dead_integration_events",
            ),
        )


@pytest.mark.anyio
async def test_replay_preserves_event_identity_and_uses_current_rotated_key(tmp_path: Path) -> None:
    store = IntegrationEventStore(tmp_path / "outbox.sqlite3", now_func=lambda: NOW)
    original = queued(store)
    claimed = store.claim_due()
    assert claimed is not None
    store.record_result(claimed.payload.event_id, accepted=False, retryable=False)
    preflight = store.replay_preflight(ORG)
    store.replay_dead(
        ORG,
        IntegrationEventReplayRequest(
            observed_at=preflight.observed_at,
            snapshot_digest=preflight.snapshot_digest,
            confirmation="replay_dead_integration_events",
        ),
    )
    replayed = store.claim_due()
    assert replayed is not None
    captured: dict[str, str] = {}
    rotated_key = b"r" * 32

    async def handler(request: httpx.Request) -> httpx.Response:
        body = await request.aread()
        timestamp = request.headers["X-Inspectra-Timestamp"]
        captured["key_id"] = request.headers["X-Inspectra-Key-ID"]
        captured["event_id"] = request.headers["X-Inspectra-Event-ID"]
        captured["signature"] = request.headers["X-Inspectra-Signature"]
        captured["expected_signature"] = (
            f"{INTEGRATION_EVENT_SIGNATURE_VERSION}="
            + hmac.new(
                rotated_key,
                timestamp.encode("ascii") + b"." + body,
                hashlib.sha256,
            ).hexdigest()
        )
        return httpx.Response(204)

    rotated = IntegrationEventConfig(
        endpoint="https://hooks.example.test/inspectra/events",
        host="hooks.example.test",
        signing_key=rotated_key,
        signing_key_id="rotation-3",
    )
    accepted, retryable = await IntegrationEventTransport(
        rotated, transport=httpx.MockTransport(handler)
    ).deliver(replayed)

    assert (accepted, retryable) == (True, False)
    assert captured == {
        "key_id": "rotation-3",
        "event_id": original.payload.event_id,
        "signature": captured["expected_signature"],
        "expected_signature": captured["expected_signature"],
    }


@pytest.mark.anyio
async def test_transport_signs_exact_minimal_body_without_following_redirects(tmp_path: Path) -> None:
    store = IntegrationEventStore(tmp_path / "outbox.sqlite3", now_func=lambda: NOW)
    record = queued(store)
    captured: dict[str, object] = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["headers"] = dict(request.headers)
        captured["body"] = await request.aread()
        return httpx.Response(204)

    transport = IntegrationEventTransport(config(), transport=httpx.MockTransport(handler))
    accepted, retryable = await transport.deliver(record)

    assert (accepted, retryable) == (True, False)
    assert captured["url"] == "https://hooks.example.test/inspectra/events"
    body = captured["body"]
    assert isinstance(body, bytes)
    payload = json.loads(body)
    assert set(payload) == {
        "analysis_id", "contract_version", "event_id", "event_type", "finding_count",
        "occurred_at", "project_id", "status",
    }
    headers = captured["headers"]
    assert isinstance(headers, dict)
    timestamp = headers["x-inspectra-timestamp"]
    expected = hmac.new(KEY, timestamp.encode("ascii") + b"." + body, hashlib.sha256).hexdigest()
    assert headers["x-inspectra-signature"] == f"{INTEGRATION_EVENT_SIGNATURE_VERSION}={expected}"
    assert headers["x-inspectra-key-id"] == "rotation-2"
    assert headers["x-inspectra-event-id"] == record.payload.event_id


@pytest.mark.anyio
@pytest.mark.parametrize("status_code,expected", [(302, (False, False)), (429, (False, True)), (503, (False, True)), (400, (False, False))])
async def test_transport_classifies_response_without_redirect(status_code: int, expected: tuple[bool, bool], tmp_path: Path) -> None:
    store = IntegrationEventStore(tmp_path / "outbox.sqlite3", now_func=lambda: NOW)
    record = queued(store)
    calls = 0

    async def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(status_code, headers={"Location": "https://other.example.test/leak"})

    result = await IntegrationEventTransport(config(), transport=httpx.MockTransport(handler)).deliver(record)
    assert result == expected
    assert calls == 1


@pytest.mark.anyio
async def test_transport_denies_private_resolution_before_opening_socket(tmp_path: Path) -> None:
    store = IntegrationEventStore(tmp_path / "outbox.sqlite3", now_func=lambda: NOW)
    record = queued(store)

    async def private_resolver(_host: str) -> list[str]:
        return ["127.0.0.1"]

    with pytest.raises(IntegrationEventError, match="destination_resolution_denied"):
        await IntegrationEventTransport(config(), resolver=private_resolver).deliver(record)


@pytest.mark.anyio
async def test_transport_bounds_response_and_retries_timeout_without_internet(tmp_path: Path) -> None:
    store = IntegrationEventStore(tmp_path / "outbox.sqlite3", now_func=lambda: NOW)
    record = queued(store)
    oversized = IntegrationEventTransport(
        config(), transport=httpx.MockTransport(lambda _request: httpx.Response(200, content=b"x" * 8_193))
    )
    assert await oversized.deliver(record) == (False, False)

    def timeout(_request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("fixture")

    timed_out = IntegrationEventTransport(config(), transport=httpx.MockTransport(timeout))
    assert await timed_out.deliver(record) == (False, True)


@pytest.mark.anyio
async def test_dispatcher_persists_success_and_retry_without_internet(tmp_path: Path) -> None:
    clock = Clock()
    store = IntegrationEventStore(tmp_path / "outbox.sqlite3", now_func=clock)
    record = queued(store)
    statuses = iter([503, 204])
    transport = IntegrationEventTransport(
        config(), transport=httpx.MockTransport(lambda _request: httpx.Response(next(statuses)))
    )
    dispatcher = IntegrationEventDispatcher(store, transport, concurrency=2)

    assert await dispatcher.drain_once() == 1
    retry = store.get(record.payload.event_id)
    assert retry.state == "pending" and retry.attempts == 1
    clock.value = retry.next_attempt_at
    assert await dispatcher.drain_once() == 1
    delivered = store.get(record.payload.event_id)
    assert delivered.state == "delivered" and delivered.attempts == 2


def test_terminal_job_hook_enqueues_only_minimal_project_event(tmp_path: Path) -> None:
    store = IntegrationEventStore(tmp_path / "outbox.sqlite3", now_func=lambda: NOW)
    job = SimpleNamespace(
        id=ANALYSIS,
        owner_id=ORG,
        project_id=PROJECT,
        status="completed",
        result={"findings": [{"path": "/private/project/.env", "evidence": "secret"}]},
        finished_at=NOW,
        updated_at=NOW,
    )
    wake = SimpleNamespace(set=lambda: None)
    app = SimpleNamespace(
        state=SimpleNamespace(
            integration_event_store=store,
            integration_event_wake=wake,
            jobs=SimpleNamespace(get=lambda _job_id: job),
        )
    )

    enqueue_terminal_project_analysis_event(app, ANALYSIS)
    record = store.claim_due()
    assert record is not None
    assert record.payload.finding_count == 1
    encoded = json.dumps(record.payload.model_dump(mode="json"))
    assert "/private" not in encoded and "secret" not in encoded and ".env" not in encoded
