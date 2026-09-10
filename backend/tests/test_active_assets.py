from datetime import datetime, timedelta, timezone
import asyncio
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from dataclasses import replace
import hashlib
from io import BytesIO
import json
import logging
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tarfile
import threading
import time
import tracemalloc

import pytest
from fastapi import HTTPException
from httpx import ASGITransport, AsyncClient
from pydantic import ValidationError

from app.active_assets import (
    ActiveAssetCreateRequest,
    ActiveAssetRenewRequest,
    ActiveAssetResponsiblesUpdateRequest,
    ActiveAssetStore,
    ActiveAssetStoreError,
    ActiveAssetTriageRequest,
)
from app import active_assets as active_assets_module
from app.active_asset_verification import (
    ActiveAssetVerificationObservation,
    ActiveAssetVerificationStartRequest,
    ActiveAssetVerificationStore,
)
from app.active_asset_deletion import ActiveAssetDeletionService
from app.active_asset_batch import (
    ACTIVE_ASSET_BATCH_MAX_BYTES,
    ActiveAssetBatchPreflightStore,
    mark_existing_active_asset_conflicts,
    parse_active_asset_batch,
)
from app.active_change_approvals import ActiveChangeApprovalStore
from app.active_weekly_review_receipts import ActiveWeeklyReviewReceiptStore
from app.active_recurrence import (
    ACTIVE_RECURRENCE_WEEKDAYS,
    ActiveRecurrenceCreateRequest,
    ActiveRecurrenceStore,
)
from app.active_evidence_bundle import (
    ACTIVE_EVIDENCE_BUNDLE_CONTRACT_VERSION,
    ACTIVE_EVIDENCE_BUNDLE_MAX_EXECUTIONS,
    ActiveEvidenceBundleError,
    build_active_evidence_bundle,
    validate_active_evidence_bundle,
)
from app.active_dns_inventory import ActiveDnsInventoryQueryResult
from app.active_nmap_lifecycle import ActiveNmapBasicRouteNoLiveClient
from app.auth import ADMIN_CSRF_HEADER_NAME, build_session_cookie_settings, hash_password
from app.config import get_auth_mode, get_current_operator_for_trusted_local, load_settings
from app.main import app
from app.models import ProjectRecord, ProjectSourceSnapshot
from app import main as backend_main
from app.product_audit import ProductAuditStore
from app.storage import JobStore, ProjectStore


def _payload(**overrides):
    now = datetime.now(timezone.utc)
    payload = {
        "asset_type": "domain",
        "value": "Example.Test.",
        "responsible_user_ids": ["local-admin"],
        "capabilities": ["active_dns_inventory", "active_dns_osint"],
        "allowed_ports": [],
        "allowed_protocols": ["dns"],
        "authorization_method": "manual_attestation",
        "authorization_reference": "change-ticket SEC-42",
        "authorized_at": (now - timedelta(minutes=1)).isoformat(),
        "expires_at": (now + timedelta(days=30)).isoformat(),
        "notes": [{"kind": "scope_constraint", "value": "Exact apex only"}],
    }
    payload.update(overrides)
    return payload


def _renewal_payload(asset: dict, **overrides):
    now = datetime.now(timezone.utc)
    payload = {
        "idempotency_key": "7" * 32,
        "expected_revision_id": asset.get("authorization_revisions", [{}])[-1].get("id") if asset.get("authorization_revisions") else None,
        "responsible_user_ids": asset["responsible_user_ids"],
        "capabilities": asset["capabilities"],
        "allowed_ports": asset["allowed_ports"],
        "allowed_protocols": asset["allowed_protocols"],
        "authorization_method": "manual_attestation",
        "authorization_reference": "change-ticket SEC-43",
        "authorized_at": now.isoformat(),
        "expires_at": (now + timedelta(days=90)).isoformat(),
        "renewal_confirmed": True,
        "scope_expansion_confirmed": False,
    }
    payload.update(overrides)
    return payload


def _configure(monkeypatch, tmp_path, *, verification_enabled=False, auth_mode="trusted_local_no_auth", all_standard_capabilities=False, four_eyes_enabled=False):
    monkeypatch.setenv("INSPECTRA_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("INSPECTRA_AUTH_MODE", auth_mode)
    if auth_mode == "private_team_lightweight_users":
        monkeypatch.setenv("INSPECTRA_AUTH_STATE_STORE", "sqlite")
        monkeypatch.setenv("INSPECTRA_ADMIN_PASSWORD_HASH", hash_password("admin-weekly-password"))
        monkeypatch.setenv("INSPECTRA_TEAM_ORGANIZATION_NAME", "Synthetic Active team")
    monkeypatch.setenv("INSPECTRA_ACTIVE_DNS_INVENTORY_ENABLED", "true")
    monkeypatch.setenv("INSPECTRA_ACTIVE_NMAP_BASIC_ENABLED", "true")
    if all_standard_capabilities:
        monkeypatch.setenv("INSPECTRA_ACTIVE_DNS_OSINT_ENABLED", "true")
        monkeypatch.setenv("INSPECTRA_ACTIVE_HTTP_BASIC_HEADER_REVIEW_ENABLED", "true")
        monkeypatch.setenv("INSPECTRA_ACTIVE_HTTP_BASIC_HEADER_REVIEW_LIVE_HEAD_ENABLED", "true")
        monkeypatch.setenv("INSPECTRA_ACTIVE_TLS_BASIC_ENABLED", "true")
    monkeypatch.setenv("INSPECTRA_ACTIVE_ASSET_VERIFICATION_ENABLED", "true" if verification_enabled else "false")
    monkeypatch.setenv("INSPECTRA_ACTIVE_FOUR_EYES_ENABLED", "true" if four_eyes_enabled else "false")
    settings = load_settings()
    settings.ensure_directories()
    app.state.settings = settings
    app.state.auth_mode = get_auth_mode(settings)
    app.state.default_local_operator = get_current_operator_for_trusted_local(settings)
    app.state.single_admin_auth_configured = backend_main.is_single_admin_auth_configured(settings)
    app.state.admin_sessions = backend_main.create_admin_session_store(settings)
    app.state.login_attempts = backend_main.create_login_attempt_store(settings)
    app.state.session_cookie_settings = build_session_cookie_settings(settings.session_ttl_seconds, secure=settings.session_cookie_secure)
    app.state.automation_tokens = backend_main.create_automation_token_store(settings)
    app.state.team_identity = backend_main.create_team_identity_store(settings)
    app.state.active_assets = ActiveAssetStore(settings)
    app.state.active_change_approvals = ActiveChangeApprovalStore(settings)
    app.state.active_weekly_review_receipts = ActiveWeeklyReviewReceiptStore(settings)
    app.state.active_asset_batch_preflights = ActiveAssetBatchPreflightStore()
    app.state.active_asset_verifications = ActiveAssetVerificationStore(settings)
    app.state.active_recurrences = ActiveRecurrenceStore(settings)
    verification_transport = FakeVerificationTransport()
    app.state.active_asset_verification_transport = verification_transport
    app.state.active_asset_verification_runner = verification_transport
    app.state.active_verification_cancellation_events = {}
    app.state.active_capability_runner = FakeActiveCapabilityRunner()
    app.state.active_capability_semaphore = asyncio.Semaphore(4)
    app.state.active_tools_health_checker = healthy_active_tools
    app.state.jobs = JobStore(settings)
    app.state.projects = ProjectStore(settings)
    app.state.remediation_saved_views = backend_main.RemediationSavedViewStore(settings)
    app.state.remediation_plan_jobs = backend_main.RemediationPlanJobStore(settings)
    app.state.product_audit = ProductAuditStore(settings)
    app.state.active_asset_deletions = ActiveAssetDeletionService(
        settings,
        app.state.active_assets,
        app.state.active_asset_verifications,
        app.state.jobs,
        app.state.product_audit,
        app.state.active_recurrences,
        app.state.active_change_approvals,
    )
    app.state.active_asset_revocation_events = {}
    app.state.active_execution_cancellation_events = {}
    app.state.scheduled_active_execution_job_ids = set()
    app.state.scheduled_remediation_plan_job_ids = set()
    app.state.remediation_plan_semaphore = asyncio.Semaphore(2)
    app.state.durable_audit_tasks = set()
    app.state.active_dns_inventory_resolver = EmptyDnsResolver()
    return settings


async def healthy_active_tools(_base_url, *, timeout_seconds):
    return {
        "available": True,
        "service": "inspectra-active-tools",
        "status": "ok",
        "network_requests_sent": 0,
        "nmap_executed": False,
        "capabilities": {
            capability: {"execution_enabled": True, "status": "ready", "target_input_allowed": False}
            for capability in (*backend_main.ACTIVE_CAPABILITIES, "active_asset_verification")
        },
    }


def _batch_json(*values: str) -> bytes:
    return json.dumps(
        [
            _payload(
                value=value,
                responsible_user_ids=["local-admin"],
                capabilities=["active_dns_inventory"],
                allowed_protocols=["dns"],
                notes=[],
            )
            for value in values
        ],
        sort_keys=True,
    ).encode("utf-8")


@pytest.mark.anyio
async def test_four_eyes_registration_renewal_and_revocation_flow(monkeypatch, tmp_path):
    _configure(
        monkeypatch, tmp_path,
        auth_mode="private_team_lightweight_users",
        four_eyes_enabled=True,
    )
    identity = app.state.team_identity
    bootstrap = identity.get_principal("team-admin", "local-admin")
    invitation = identity.create_invitation(
        principal=bootstrap, username="active.approver", role="administrator"
    )
    identity.accept_invitation(token=invitation.token, password="approver-password")
    reader_invitation = identity.create_invitation(
        principal=bootstrap, username="active.reader", role="reader"
    )
    identity.accept_invitation(token=reader_invitation.token, password="reader-password")
    transport = ASGITransport(app=app)
    payload = _payload(
        value="four-eyes.example.test",
        responsible_user_ids=["team-admin"],
        capabilities=["active_dns_inventory"],
        allowed_protocols=["dns"],
        notes=[{"kind": "scope_constraint", "value": "Exact target only"}],
    )
    emergency_asset = app.state.active_assets.create(
        ActiveAssetCreateRequest.model_validate(_payload(
            value="emergency.example.test", responsible_user_ids=["team-admin"],
            capabilities=["active_dns_inventory"], allowed_protocols=["dns"], notes=[],
        )),
        organization_id="local-admin", actor_id="team-admin",
    )

    async with AsyncClient(transport=transport, base_url="http://testserver") as requester, AsyncClient(
        transport=transport, base_url="http://testserver"
    ) as approver, AsyncClient(transport=transport, base_url="http://testserver") as reader:
        assert (await requester.post(
            "/auth/login", json={"username": "admin", "password": "admin-weekly-password"}
        )).status_code == 200
        requester_csrf = (await requester.get("/auth/status")).json()["csrf_token"]
        requester_headers = {ADMIN_CSRF_HEADER_NAME: requester_csrf}
        assert (await approver.post(
            "/auth/login", json={"username": "active.approver", "password": "approver-password"}
        )).status_code == 200
        approver_csrf = (await approver.get("/auth/status")).json()["csrf_token"]
        approver_headers = {ADMIN_CSRF_HEADER_NAME: approver_csrf}
        assert (await reader.post(
            "/auth/login", json={"username": "active.reader", "password": "reader-password"}
        )).status_code == 200
        reader_list = await reader.get("/active/change-approvals")

        blocked = await requester.post("/active/assets", json=payload, headers=requester_headers)
        requested = await requester.post(
            "/active/change-approvals/registrations", json=payload, headers=requester_headers
        )
        same_actor = await requester.post(
            f"/active/change-approvals/{requested.json()['id']}/approve", headers=requester_headers
        )
        approved = await approver.post(
            f"/active/change-approvals/{requested.json()['id']}/approve", headers=approver_headers
        )
        created = await requester.post(
            "/active/assets", json=payload,
            headers=requester_headers | {"X-Inspectra-Active-Approval": requested.json()["id"]},
        )

        renewal_payload = _renewal_payload(created.json())
        renewal_request = await requester.post(
            f"/active/assets/{created.json()['id']}/change-approvals/renewals",
            json=renewal_payload, headers=requester_headers,
        )
        await approver.post(
            f"/active/change-approvals/{renewal_request.json()['id']}/approve",
            headers=approver_headers,
        )
        renewed = await requester.post(
            f"/active/assets/{created.json()['id']}/renew", json=renewal_payload,
            headers=requester_headers | {"X-Inspectra-Active-Approval": renewal_request.json()["id"]},
        )

        revoke_payload = {"reason_code": "authorization_withdrawn"}
        revoke_request = await requester.post(
            f"/active/assets/{created.json()['id']}/change-approvals/revocations",
            json=revoke_payload, headers=requester_headers,
        )
        await approver.post(
            f"/active/change-approvals/{revoke_request.json()['id']}/approve",
            headers=approver_headers,
        )
        revoked = await requester.post(
            f"/active/assets/{created.json()['id']}/revoke", json=revoke_payload,
            headers=requester_headers | {"X-Inspectra-Active-Approval": revoke_request.json()["id"]},
        )
        approvals = await requester.get("/active/change-approvals")
        blocked_batch = await requester.post(
            "/active/assets/batch/preflight",
            files={"file": ("assets.json", _batch_json("batch.example.test"), "application/json")},
            headers=requester_headers,
        )
        emergency = await approver.post(
            f"/active/assets/{emergency_asset.id}/revoke",
            json={"reason_code": "security_hold"}, headers=approver_headers,
        )

    assert blocked.status_code == 409
    assert reader_list.status_code == 403
    assert requested.status_code == 202
    assert requested.json()["summary"]["review_target"] == "four-eyes.example.test"
    assert "change-ticket" not in requested.text
    assert "team-admin" not in requested.text
    assert same_actor.status_code == 403
    assert approved.status_code == 200
    assert created.status_code == 201
    assert renewed.status_code == 200
    assert revoked.status_code == 200
    assert revoked.json()["status"] == "revoked"
    assert {item["status"] for item in approvals.json()["items"]} == {"consumed"}
    assert all(item["summary"]["review_target"] is None for item in approvals.json()["items"])
    assert blocked_batch.status_code == 409
    assert emergency.status_code == 200
    assert emergency.json()["status"] == "revoked"


class EmptyDnsResolver:
    def query(self, _name: str, _record_type: str) -> ActiveDnsInventoryQueryResult:
        return ActiveDnsInventoryQueryResult(status="ok")


class FakeVerificationTransport:
    def __init__(self, *, matched=True, reason_code="matched"):
        self.matched = matched
        self.reason_code = reason_code
        self.calls = []

    def dns_txt(self, *, record_name, expected_token):
        self.calls.append(("dns_txt", record_name, expected_token))
        return ActiveAssetVerificationObservation(self.matched, self.reason_code)

    def http_well_known(self, *, origin, expected_token):
        self.calls.append(("http_well_known", origin, expected_token))
        return ActiveAssetVerificationObservation(self.matched, self.reason_code)

    async def verify(self, *, method, target, challenge_token):
        self.calls.append((method, target, challenge_token))
        return ActiveAssetVerificationObservation(self.matched, self.reason_code)

    def managed_private(self, *, asset, expected_token):
        self.calls.append(("managed_private", asset.id, expected_token))
        return ActiveAssetVerificationObservation(self.matched, self.reason_code)


class SlowVerificationRunner:
    def __init__(self):
        self.started = asyncio.Event()
        self.cancelled = asyncio.Event()

    async def verify(self, *, method, target, challenge_token):
        self.started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.cancelled.set()
            raise


class FakeActiveCapabilityRunner:
    def __init__(self):
        self.calls = []

    async def execute(self, *, capability, target, port=None):
        self.calls.append((capability, target, port))
        if capability != "active_dns_inventory":
            raise AssertionError("unexpected synthetic Active capability")
        contract = backend_main.validate_active_dns_inventory_contract(
            {
                "mode": "live_dns_inventory",
                "profile": "dns_inventory_authorized",
                "domain": target,
                "record_types": ["A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT", "CAA"],
                "include_security_records": True,
                "include_subdomain_discovery": False,
                "attempt_zone_transfer": False,
                "authorization_confirmed": True,
                "local_private_or_owned_scope_confirmed": True,
                "live_dns_queries_confirmed": True,
            }
        )
        return backend_main.run_active_dns_inventory(contract, resolver=EmptyDnsResolver(), axfr_transport=None)


class FixtureActiveCapabilityRunner:
    def __init__(self, results):
        self.results = results
        self.calls = []

    async def execute(self, *, capability, target, port=None):
        self.calls.append((capability, target, port))
        return self.results[capability]


class SlowActiveCapabilityRunner:
    def __init__(self):
        self.started = asyncio.Event()
        self.cancelled = asyncio.Event()

    async def execute(self, *, capability, target, port=None):
        del capability, target, port
        self.started.set()
        try:
            await asyncio.sleep(30)
        except asyncio.CancelledError:
            self.cancelled.set()
            raise


class FailingActiveCapabilityRunner:
    async def execute(self, *, capability, target, port=None):
        del capability, target, port
        raise backend_main.ActiveCapabilityRunnerError("active_tools_unavailable")

@pytest.mark.anyio
async def test_active_asset_registration_list_search_and_revocation(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        created_response = await client.post("/active/assets", json=_payload())
        assert created_response.status_code == 201
        created = created_response.json()
        assert created["canonical_value"] == "example.test"
        assert created["status"] == "active"
        assert created["history"][0]["kind"] == "registered"
        assert len(created["authorization_revisions"]) == 1
        revision = created["authorization_revisions"][0]
        assert revision["sequence"] == 1
        assert revision["source"] == "registration"
        assert len(revision["id"]) == 32
        assert len(revision["digest_sha256"]) == 64
        assert not ({"canonical_value", "organization_id", "owner_id", "authorization_reference"} & revision.keys())
        assert "change-ticket SEC-42" in json.dumps(created)

        listed = await client.post("/active/assets/search", json={"status": "active", "query": "EXAMPLE", "query_mode": "prefix", "page_size": 24})
        assert listed.status_code == 200
        assert [item["id"] for item in listed.json()["items"]] == [created["id"]]

        revoked_response = await client.post(
            f"/active/assets/{created['id']}/revoke",
            json={"reason_code": "authorization_withdrawn"},
        )
        assert revoked_response.status_code == 200
        revoked = revoked_response.json()
        assert revoked["status"] == "revoked"
        assert [event["kind"] for event in revoked["history"]] == ["registered", "revoked"]

        assert (await client.post("/active/assets/search", json={"status": "active", "page_size": 24})).json()["items"] == []


@pytest.mark.anyio
async def test_active_asset_revocation_cancels_every_inflight_job_beyond_history_window(
    monkeypatch, tmp_path
):
    _configure(monkeypatch, tmp_path)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        created = (await client.post("/active/assets", json=_payload())).json()
        revision = created["authorization_revisions"][-1]
        job_ids = []
        for _index in range(501):
            job = app.state.jobs.create_active_nmap_basic_no_live_job(
                {"capability": "active_nmap_basic", "status": "queued"},
                status="queued",
                owner_id="local-admin",
                active_asset_id=created["id"],
                active_authorization_contract=created["contract_version"],
                active_authorization_revision_id=revision["id"],
                active_authorization_revision_digest_sha256=revision["digest_sha256"],
                active_authorization_revision_sequence=revision["sequence"],
            )
            job_ids.append(job.id)

        revoked = await client.post(
            f"/active/assets/{created['id']}/revoke",
            json={"reason_code": "authorization_withdrawn"},
        )

    assert revoked.status_code == 200
    records = app.state.jobs.active_asset_complete_history(
        owner_id="local-admin", asset_id=created["id"]
    )
    assert len(records) == len(job_ids) == 501
    assert {record.id for record in records} == set(job_ids)
    assert {record.status for record in records} == {"cancelled"}
    assert {record.termination_reason for record in records} == {"authorization_revoked"}
    assert app.state.jobs.active_asset_inflight_history(
        owner_id="local-admin", asset_id=created["id"]
    ) == []


@pytest.mark.anyio
async def test_active_asset_registration_rejects_same_canonical_identity_without_cross_owner_conflict(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)
    other = app.state.active_assets.create(
        ActiveAssetCreateRequest.model_validate(_payload()),
        organization_id="b" * 32,
        actor_id="b" * 32,
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        first = await client.post("/active/assets", json=_payload(value="Unique.Example.Test."))
        duplicate = await client.post("/active/assets", json=_payload(value="unique.example.test"))
        page = await client.post("/active/assets/search", json={"query": "unique.example.test", "query_mode": "exact", "page_size": 24})

    assert first.status_code == 201
    assert duplicate.status_code == 409
    assert duplicate.json() == {"detail": "An Active asset with this exact identity is already registered in the current workspace."}
    assert "unique.example.test" not in duplicate.text
    assert [item["id"] for item in page.json()["items"]] == [first.json()["id"]]
    assert other.canonical_value == "example.test"


def test_active_asset_registration_is_atomic_across_store_instances_and_preserves_legacy_duplicates(monkeypatch, tmp_path):
    settings = _configure(monkeypatch, tmp_path)
    request = ActiveAssetCreateRequest.model_validate(_payload(value="race.example.test"))
    stores = [ActiveAssetStore(settings), ActiveAssetStore(settings)]
    barrier = threading.Barrier(2)

    def create(store):
        barrier.wait()
        try:
            return store.create(request, organization_id="local-admin", actor_id="local-admin")
        except ActiveAssetStoreError as exc:
            return str(exc)

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(create, stores))
    assert sum(not isinstance(result, str) for result in results) == 1
    assert results.count("asset_identity_conflict") == 1

    legacy_request = ActiveAssetCreateRequest.model_validate(_payload(value="legacy-duplicate.example.test"))
    now = datetime(2026, 9, 8, tzinfo=timezone.utc)
    legacy_records = [
        stores[0]._build_registration_record(
            legacy_request,
            organization_id="local-admin",
            actor_id="local-admin",
            asset_id=identifier * 32,
            now=now,
        )
        for identifier in ("c", "d")
    ]
    for record in legacy_records:
        active_assets_module._atomic_write(stores[0]._path("local-admin", record.id), record)
    assert len([record for record in stores[0].list(organization_id="local-admin") if record.canonical_value == legacy_request.value]) == 2
    with pytest.raises(ActiveAssetStoreError, match="asset_identity_conflict"):
        stores[0].create(legacy_request, organization_id="local-admin", actor_id="local-admin")
    unrelated = stores[0].create(
        ActiveAssetCreateRequest.model_validate(_payload(value="unrelated.example.test")),
        organization_id="local-admin",
        actor_id="local-admin",
    )
    assert unrelated.canonical_value == "unrelated.example.test"


def test_active_asset_registration_waits_for_pending_owner_deletion_cleanup(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)
    request = ActiveAssetCreateRequest.model_validate(_payload(value="deleting.example.test"))
    asset = app.state.active_assets.create(request, organization_id="local-admin", actor_id="local-admin")
    interrupted = False

    def interrupt_after_asset(step):
        nonlocal interrupted
        if step == "asset_metadata" and not interrupted:
            interrupted = True
            raise RuntimeError("simulated interruption")

    app.state.active_asset_deletions._after_step = interrupt_after_asset
    with pytest.raises(Exception, match="cleanup_failed"):
        app.state.active_asset_deletions.delete(organization_id="local-admin", asset_id=asset.id)
    with pytest.raises(ActiveAssetStoreError, match="asset_deletion_pending"):
        app.state.active_assets.create(request, organization_id="local-admin", actor_id="local-admin")
    with pytest.raises(ActiveAssetStoreError, match="asset_deletion_pending"):
        app.state.active_assets.existing_registration_identities(organization_id="local-admin")
    app.state.active_asset_deletions._after_step = None
    assert app.state.active_asset_deletions.recover_pending() == 1
    recreated = app.state.active_assets.create(request, organization_id="local-admin", actor_id="local-admin")
    assert recreated.id != asset.id


@pytest.mark.anyio
async def test_active_asset_page_route_is_bounded_filter_bound_and_retires_legacy_list(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        created = []
        for index in range(31):
            created.append((await client.post(
                "/active/assets",
                json=_payload(value=f"page-{index:02d}.example.test"),
            )).json())
        first = await client.post(
            "/active/assets/search",
            json={"page_size": 10, "query": "PAGE-", "query_mode": "prefix", "capability": "active_dns_inventory"},
        )
        assert first.status_code == 200
        page = first.json()
        assert page["contract_version"] == "2026-09-08.1"
        assert page["returned_count"] == 10
        assert page["page_size"] == 10
        assert page["has_more"] is True
        assert len(page["items"]) == 10
        assert page["next_cursor"] and len(page["next_cursor"]) <= 512

        second = await client.post(
            "/active/assets/search",
            json={
                "page_size": 10,
                "query": "page-",
                "query_mode": "prefix",
                "capability": "active_dns_inventory",
                "cursor": page["next_cursor"],
            },
        )
        assert second.status_code == 200
        assert not ({item["id"] for item in page["items"]} & {item["id"] for item in second.json()["items"]})

        tampered = page["next_cursor"][:-1] + ("A" if page["next_cursor"][-1] != "A" else "B")
        invalid_cursor = await client.post("/active/assets/search", json={"page_size": 10, "query": "page-", "cursor": tampered})
        changed_filter = await client.post(
            "/active/assets/search",
            json={"page_size": 10, "query": "page-0", "cursor": page["next_cursor"]},
        )
        exact = await client.post(
            "/active/assets/search",
            json={"page_size": 10, "query": "page-00.example.test", "query_mode": "exact"},
        )
        legacy = await client.get("/active/assets", params={"query": "private-canary.example.test"})
        openapi = (await client.get("/openapi.json")).json()

    assert invalid_cursor.status_code == 422
    assert invalid_cursor.json() == {"detail": "Active asset request could not be applied."}
    assert changed_filter.status_code == 422
    assert [item["canonical_value"] for item in exact.json()["items"]] == ["page-00.example.test"]
    assert legacy.status_code == 410
    assert legacy.json() == {
        "contract_version": "2026-09-08.1",
        "detail": "The unbounded Active asset list has been retired.",
        "successor": "/active/assets/search",
    }
    assert legacy.headers["deprecation"] == "true"
    assert legacy.headers["sunset"] == "Tue, 01 Dec 2026 00:00:00 GMT"
    assert legacy.headers["link"] == '</active/assets/search>; rel="successor-version"'
    assert legacy.headers["cache-control"] == "no-store"
    assert "private-canary" not in legacy.text
    retired_operation = openapi["paths"]["/active/assets"]["get"]
    assert retired_operation["deprecated"] is True
    assert "410" in retired_operation["responses"]
    assert "/active/assets/search" in retired_operation["responses"]["410"]["description"]


@pytest.mark.anyio
async def test_active_asset_search_body_requires_private_session_csrf(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path, auth_mode="private_team_lightweight_users")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        assert (await client.post(
            "/auth/login",
            json={"username": "admin", "password": "admin-weekly-password"},
        )).status_code == 200
        csrf = (await client.get("/auth/status")).json()["csrf_token"]
        without_csrf = await client.post(
            "/active/assets/search",
            json={"page_size": 24, "query": "private-target.example.test", "query_mode": "exact"},
        )
        accepted = await client.post(
            "/active/assets/search",
            headers={ADMIN_CSRF_HEADER_NAME: csrf},
            json={"page_size": 24, "query": "private-target.example.test", "query_mode": "exact"},
        )

    assert without_csrf.status_code == 403
    assert "private-target.example.test" not in without_csrf.text
    assert accepted.status_code == 200
    assert accepted.json()["items"] == []


def test_active_asset_page_scales_without_duplicates_and_rejects_foreign_cursor(monkeypatch, tmp_path):
    settings = _configure(monkeypatch, tmp_path)
    now = datetime.now(timezone.utc)
    mutable_now = [now]
    fixture_store = ActiveAssetStore(settings, now_func=lambda: mutable_now[0])
    organization_a = "a" * 32
    organization_b = "b" * 32
    request = ActiveAssetCreateRequest.model_validate(_payload(value="portfolio-0.example.test"))
    for index in range(10_005):
        created_at = now + timedelta(microseconds=index)
        record = fixture_store._build_registration_record(
            request.model_copy(update={"value": f"portfolio-{index}.example.test"}),
            organization_id=organization_a,
            actor_id=organization_a,
            asset_id=f"{index + 1:032x}",
            now=created_at,
        )
        active_assets_module._atomic_write(
            fixture_store._path(organization_a, record.id), record
        )
    store = ActiveAssetStore(settings, now_func=lambda: mutable_now[0])
    store.create(request, organization_id=organization_b, actor_id=organization_b)

    read_count = 0
    original_read = store._read

    def counted_read(*args, **kwargs):
        nonlocal read_count
        read_count += 1
        return original_read(*args, **kwargs)

    monkeypatch.setattr(store, "_read", counted_read)
    tracemalloc.start()
    started = time.perf_counter()
    first = store.page(organization_id=organization_a, page_size=100, query="portfolio", query_mode="prefix")
    elapsed = time.perf_counter() - started
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    assert elapsed < 0.5
    assert peak < 128 * 1024 * 1024
    assert read_count <= 101
    assert first.returned_count == 100
    assert first.has_more is True
    assert first.next_cursor is not None
    assert organization_a not in first.next_cursor
    assert "portfolio" not in first.next_cursor
    assert len(json.dumps(first.model_dump(mode="json"))) < 1_000_000

    samples = []
    for _index in range(20):
        sample_started = time.perf_counter()
        store.page(organization_id=organization_a, page_size=100, query="portfolio", query_mode="prefix")
        samples.append(time.perf_counter() - sample_started)
    assert sorted(samples)[18] < 0.5

    read_count = 0
    operations_assets, operations_counts = store.operations_snapshot(
        organization_id=organization_a
    )
    assert len(operations_assets) == 500
    assert read_count <= 501
    assert operations_counts == {
        "total": 10_005,
        "active": 10_005,
        "expired": 0,
        "revoked": 0,
        "expiring_14_days": 0,
        "duplicate_identity_groups": 0,
        "duplicate_identity_records": 0,
        "priority_candidates": 0,
    }

    mutable_now[0] += timedelta(microseconds=1)
    request = ActiveAssetCreateRequest.model_validate(_payload(value="portfolio-inserted.example.test"))
    inserted = store.create(request, organization_id=organization_a, actor_id=organization_a)
    second = store.page(
        organization_id=organization_a,
        page_size=100,
        query="portfolio",
        query_mode="prefix",
        cursor=first.next_cursor,
    )
    assert not ({item.id for item in first.items} & {item.id for item in second.items})
    assert inserted.id not in {item.id for item in second.items}

    recency_first = store.page(
        organization_id=organization_a,
        page_size=100,
        query="portfolio",
        query_mode="prefix",
        updated_within_days=7,
    )
    assert recency_first.next_cursor is not None
    mutable_now[0] += timedelta(days=365)
    recency_second = store.page(
        organization_id=organization_a,
        page_size=100,
        query="portfolio",
        query_mode="prefix",
        updated_within_days=7,
        cursor=recency_first.next_cursor,
    )
    assert recency_second.returned_count == 100
    assert not ({item.id for item in recency_first.items} & {item.id for item in recency_second.items})
    with pytest.raises(ActiveAssetStoreError, match="invalid_cursor"):
        store.page(
            organization_id=organization_b,
            page_size=100,
            query="portfolio",
            query_mode="prefix",
            cursor=first.next_cursor,
        )


def test_operations_snapshot_prioritizes_old_urgent_assets_before_recent_fill(tmp_path, monkeypatch):
    settings = _configure(monkeypatch, tmp_path)
    now = datetime(2026, 9, 9, tzinfo=timezone.utc)
    organization_id = "a" * 32
    store = ActiveAssetStore(settings, now_func=lambda: now)
    request = ActiveAssetCreateRequest.model_validate(
        _payload(
            authorized_at=(now - timedelta(days=2)).isoformat(),
            expires_at=(now + timedelta(days=30)).isoformat(),
        )
    )
    urgent_id = "f" * 32
    urgent = store._build_registration_record(
        request.model_copy(
            update={
                "value": "old-expired.example.test",
                "expires_at": now - timedelta(days=1),
            }
        ),
        organization_id=organization_id,
        actor_id=organization_id,
        asset_id=urgent_id,
        now=now - timedelta(days=30),
    )
    active_assets_module._atomic_write(store._path(organization_id, urgent.id), urgent)
    high_id = f"{10_001:032x}"
    for index in range(501):
        asset_id = high_id if index == 0 else f"{index + 1:032x}"
        record = store._build_registration_record(
            request.model_copy(update={"value": f"recent-{index}.example.test"}),
            organization_id=organization_id,
            actor_id=organization_id,
            asset_id=asset_id,
            now=now + timedelta(microseconds=index),
        )
        active_assets_module._atomic_write(store._path(organization_id, record.id), record)

    selected, counts = ActiveAssetStore(settings, now_func=lambda: now).operations_snapshot(
        organization_id=organization_id,
        high_priority_asset_ids={high_id},
    )

    assert len(selected) == 500
    assert selected[0].id == urgent_id
    assert high_id in {item.id for item in selected[:2]}
    assert counts["total"] == 502
    assert counts["expired"] == 1
    assert counts["priority_candidates"] == 2
    repeated, repeated_counts = ActiveAssetStore(
        settings, now_func=lambda: now
    ).operations_snapshot(
        organization_id=organization_id,
        high_priority_asset_ids={high_id},
    )
    assert [item.id for item in repeated] == [item.id for item in selected]
    assert repeated_counts == counts

def test_active_asset_index_repairs_external_divergence_and_cross_store_updates(monkeypatch, tmp_path):
    settings = _configure(monkeypatch, tmp_path)
    first_store = ActiveAssetStore(settings)
    second_store = ActiveAssetStore(settings)
    organization_id = "a" * 32
    first = first_store.create(
        ActiveAssetCreateRequest.model_validate(_payload(value="index-first.example.test")),
        organization_id=organization_id,
        actor_id=organization_id,
    )
    second = first_store.create(
        ActiveAssetCreateRequest.model_validate(_payload(value="index-second.example.test")),
        organization_id=organization_id,
        actor_id=organization_id,
    )

    assert {item.id for item in second_store.page(organization_id=organization_id).items} == {
        first.id,
        second.id,
    }

    with sqlite3.connect(second_store.index_path) as connection:
        connection.execute(
            "DELETE FROM active_asset_index WHERE organization_id = ? AND asset_id = ?",
            (organization_id, first.id),
        )
    repaired = second_store.page(organization_id=organization_id)
    assert {item.id for item in repaired.items} == {first.id, second.id}
    assert second_store.index_ready() is True

    with sqlite3.connect(second_store.index_path) as connection:
        connection.execute(
            "UPDATE active_asset_index_metadata SET value = '0' WHERE key = 'schema_version'"
        )
    migrated = second_store.page(organization_id=organization_id)
    assert {item.id for item in migrated.items} == {first.id, second.id}

    second_store.index_path.write_bytes(b"not-a-sqlite-database")
    os.chmod(second_store.index_path, 0o600)
    assert second_store.index_ready() is True
    rebuilt = second_store.page(organization_id=organization_id)
    assert {item.id for item in rebuilt.items} == {first.id, second.id}
    assert second_store.index_ready() is True

    os.chmod(second_store.index_path, 0o644)
    assert second_store.index_ready() is False
    with pytest.raises(ActiveAssetStoreError, match="asset_index_invalid"):
        second_store.page(organization_id=organization_id)
    os.chmod(second_store.index_path, 0o600)
    assert {item.id for item in second_store.page(organization_id=organization_id).items} == {
        first.id,
        second.id,
    }

    stale_temporary = second_store.index_path.with_name(
        f".{second_store.index_path.name}.{'d' * 32}.tmp"
    )
    stale_temporary.write_bytes(b"incomplete-derived-index")
    stale_journal = Path(f"{second_store.index_path}-journal")
    stale_journal.write_bytes(b"incomplete-derived-journal")
    restarted_store = ActiveAssetStore(settings)
    assert {item.id for item in restarted_store.page(organization_id=organization_id).items} == {
        first.id,
        second.id,
    }
    assert not stale_temporary.exists()
    assert not stale_journal.exists()

    interrupted = first_store._build_registration_record(
        ActiveAssetCreateRequest.model_validate(_payload(value="index-interrupted.example.test")),
        organization_id=organization_id,
        actor_id=organization_id,
        asset_id="c" * 32,
        now=datetime.now(timezone.utc),
    )
    active_assets_module._atomic_write(
        first_store._path(organization_id, interrupted.id), interrupted
    )
    after_interrupted_write = second_store.page(organization_id=organization_id)
    assert {item.id for item in after_interrupted_write.items} == {
        first.id,
        second.id,
        interrupted.id,
    }

    first_store.delete_for_deletion(first.id, organization_id=organization_id)
    after_delete = second_store.page(organization_id=organization_id)
    assert {item.id for item in after_delete.items} == {second.id, interrupted.id}


def test_active_asset_index_fails_closed_when_authoritative_json_is_corrupt(monkeypatch, tmp_path):
    settings = _configure(monkeypatch, tmp_path)
    store = ActiveAssetStore(settings)
    organization_id = "a" * 32
    record = store.create(
        ActiveAssetCreateRequest.model_validate(_payload(value="index-corrupt.example.test")),
        organization_id=organization_id,
        actor_id=organization_id,
    )
    path = store._path(organization_id, record.id)
    replacement = path.with_suffix(".replacement")
    replacement.write_text("{}", encoding="utf-8")
    replacement.replace(path)

    assert store.index_ready() is False
    with pytest.raises(ActiveAssetStoreError, match="asset_store_invalid"):
        store.page(organization_id=organization_id)


def test_active_asset_index_tracks_all_aggregate_mutations(monkeypatch, tmp_path):
    settings = _configure(monkeypatch, tmp_path)
    store = ActiveAssetStore(settings)
    organization_id = "a" * 32
    record = store.create(
        ActiveAssetCreateRequest.model_validate(_payload(value="index-mutations.example.test")),
        organization_id=organization_id,
        actor_id=organization_id,
    )

    def indexed():
        page = store.page(
            organization_id=organization_id,
            query="index-mutations.example.test",
            query_mode="exact",
        )
        assert page.returned_count == 1
        return page.items[0]

    assert indexed().id == record.id
    renewed, _replayed, _expanded = store.renew(
        record.id,
        ActiveAssetRenewRequest.model_validate(
            _renewal_payload(
                record.model_dump(mode="json"),
                capabilities=["active_dns_inventory"],
            )
        ),
        organization_id=organization_id,
        actor_id=organization_id,
    )
    assert indexed().authorization_revisions[-1].id == renewed.authorization_revisions[-1].id
    assigned, changed = store.set_responsibles(
        record.id,
        ActiveAssetResponsiblesUpdateRequest(
            responsible_user_ids=[],
            expected_updated_at=renewed.updated_at,
            assignment_confirmed=True,
        ),
        organization_id=organization_id,
        actor_id=organization_id,
    )
    assert changed is True
    assert indexed().responsible_user_ids == []
    admitted = store.admit_execution(
        record.id,
        organization_id=organization_id,
        actor_id=organization_id,
        capability="active_dns_inventory",
    )
    assert indexed().updated_at == admitted.updated_at
    baseline = store.set_baseline(
        record.id,
        organization_id=organization_id,
        actor_id=organization_id,
        execution_id="b" * 32,
    )
    assert indexed().baseline_execution_id == baseline.baseline_execution_id
    triaged = store.set_triage(
        record.id,
        organization_id=organization_id,
        actor_id=organization_id,
        request=ActiveAssetTriageRequest(
            observation_key="dns_count:records",
            status="acknowledged",
            comment_code="investigating",
        ),
    )
    assert indexed().triage == triaged.triage
    revoked = store.revoke(
        record.id,
        organization_id=organization_id,
        actor_id=organization_id,
        reason_code="security_hold",
    )
    revoked_page = store.page(organization_id=organization_id, status="revoked")
    assert [item.id for item in revoked_page.items] == [revoked.id]
    assert store.page(
        organization_id=organization_id,
        capability="active_dns_osint",
    ).items == []


@pytest.mark.anyio
async def test_active_asset_deletion_route_requires_preflight_and_exact_confirmation(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        created = (await client.post("/active/assets", json=_payload())).json()

        preview = await client.get(f"/active/assets/{created['id']}/deletion")
        assert preview.status_code == 200
        assert preview.json()["state"] == "ready"
        serialized = preview.text
        assert created["canonical_value"] not in serialized
        assert "authorization_revisions" in serialized
        assert "product_audit" in serialized

        rejected = await client.request(
            "DELETE",
            f"/active/assets/{created['id']}",
            json={"confirmation": "DELETE"},
        )
        assert rejected.status_code == 422
        deleted = await client.request(
            "DELETE",
            f"/active/assets/{created['id']}",
            json={"confirmation": "DELETE ACTIVE ASSET"},
        )
        assert deleted.status_code == 200
        assert deleted.json()["state"] == "completed"
        assert (await client.get(f"/active/assets/{created['id']}")).status_code == 404
        assert (await client.post("/active/assets/search", json={"page_size": 24})).json()["items"] == []


@pytest.mark.anyio
async def test_active_asset_deletion_route_blocks_pending_challenge(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path, verification_enabled=True)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        created = (await client.post("/active/assets", json=_payload())).json()
        challenge = await client.post(
            f"/active/assets/{created['id']}/verification/challenge",
            json={"method": "manual_attestation", "valid_for_days": 7, "control_check_confirmed": True},
        )
        assert challenge.status_code == 201
        preview = await client.get(f"/active/assets/{created['id']}/deletion")
        assert preview.json()["state"] == "blocked_active_work"
        blocked = await client.request(
            "DELETE",
            f"/active/assets/{created['id']}",
            json={"confirmation": "DELETE ACTIVE ASSET"},
        )
        assert blocked.status_code == 409
        assert "token" not in blocked.text.lower()


@pytest.mark.anyio
async def test_active_asset_contract_rejects_scope_expansion_and_sensitive_material(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)
    rejected = [
        _payload(value="*.example.test"),
        _payload(value="10.0.0.0/8", asset_type="ip"),
        _payload(
            value="https://user:password@example.test/private?token=secret",
            asset_type="http_origin",
            capabilities=["active_http_basic_header_review"],
            allowed_protocols=["https"],
        ),
        _payload(notes=[{"kind": "business_context", "value": "api_key=do-not-store"}]),
    ]
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        for payload in rejected:
            response = await client.post("/active/assets", json=payload)
            assert response.status_code == 422
            assert "do-not-store" not in response.text
    assert list((tmp_path / "results" / "active_assets").glob("**/*.json")) == []


def test_active_asset_accepts_bootstrap_team_actor_without_expanding_organization_ids(monkeypatch, tmp_path):
    settings = _configure(monkeypatch, tmp_path)
    store = ActiveAssetStore(settings)
    request = ActiveAssetCreateRequest.model_validate(_payload(responsible_user_ids=["team-admin"], notes=[]))

    record = store.create(request, organization_id="local-admin", actor_id="team-admin")

    assert record.owner_id == "team-admin"
    assert record.responsible_user_ids == ["team-admin"]
    assert record.history[0].actor_id == "team-admin"
    with pytest.raises(ActiveAssetStoreError, match="invalid_identity"):
        store.create(request, organization_id="team-admin", actor_id="team-admin")
    with pytest.raises(ActiveAssetStoreError, match="invalid_identity"):
        store.create(request, organization_id="local-admin", actor_id="arbitrary-admin")
    with pytest.raises(ValidationError):
        ActiveAssetCreateRequest.model_validate(_payload(responsible_user_ids=["arbitrary-admin"]))


def test_active_asset_store_isolates_two_organizations_and_materializes_expiration(monkeypatch, tmp_path):
    settings = _configure(monkeypatch, tmp_path)
    now = datetime.now(timezone.utc)
    mutable_now = [now]
    store = ActiveAssetStore(settings, now_func=lambda: mutable_now[0])
    request = ActiveAssetCreateRequest.model_validate(_payload())
    organization_a = "a" * 32
    organization_b = "b" * 32
    asset = store.create(request, organization_id=organization_a, actor_id=organization_a)
    assert store.list(organization_id=organization_b) == []
    assert store.get(asset.id, organization_id=organization_a).status == "active"
    with pytest.raises(Exception, match="asset_not_found"):
        store.get(asset.id, organization_id=organization_b)

    mutable_now[0] = request.expires_at + timedelta(seconds=1)
    assert store.get(asset.id, organization_id=organization_a).status == "expired"


def test_active_authorization_revision_detects_persisted_scope_tampering(monkeypatch, tmp_path):
    settings = _configure(monkeypatch, tmp_path)
    store = ActiveAssetStore(settings)
    asset = store.create(
        ActiveAssetCreateRequest.model_validate(_payload()),
        organization_id="local-admin",
        actor_id="local-admin",
    )
    path = next((tmp_path / "results" / "active_assets").rglob(f"{asset.id}.json"))
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["authorization_revisions"][0]["capabilities"] = ["active_tls_basic"]
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ActiveAssetStoreError, match="asset_store_invalid"):
        store.get(asset.id, organization_id="local-admin")


def test_active_asset_store_rejects_malformed_persisted_responsible_identity(monkeypatch, tmp_path):
    settings = _configure(monkeypatch, tmp_path)
    store = ActiveAssetStore(settings)
    asset = store.create(
        ActiveAssetCreateRequest.model_validate(_payload()),
        organization_id="local-admin",
        actor_id="local-admin",
    )
    path = next((tmp_path / "results" / "active_assets").rglob(f"{asset.id}.json"))
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["responsible_user_ids"] = ["../../../other-workspace"]
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ActiveAssetStoreError, match="asset_store_invalid"):
        store.get(asset.id, organization_id="local-admin")


@pytest.mark.anyio
async def test_legacy_active_asset_stays_revision_unknown_and_cannot_execute(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        asset = (await client.post("/active/assets", json=_payload())).json()
        path = next((tmp_path / "results" / "active_assets").rglob(f"{asset['id']}.json"))
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload.pop("authorization_revisions")
        path.write_text(json.dumps(payload), encoding="utf-8")

        loaded = await client.get(f"/active/assets/{asset['id']}")
        execution = await client.post(
            f"/active/assets/{asset['id']}/executions",
            json={"capability": "active_dns_inventory", "authorization_reconfirmed": True, "idempotency_key": "1" * 32},
        )

    assert loaded.status_code == 200
    assert loaded.json()["authorization_revisions"] == []
    assert execution.status_code == 409
    assert execution.json() == {"detail": "Active asset authorization must be re-attested before execution."}
    assert list((tmp_path / "results" / "jobs").glob("*.json")) == []


def test_job_updates_cannot_replace_immutable_active_authorization_evidence(monkeypatch, tmp_path):
    settings = _configure(monkeypatch, tmp_path)
    jobs = JobStore(settings)
    original = jobs.create_active_dns_inventory_job(
        {"capability": "active_dns_inventory", "records": {}},
        status="completed",
        owner_id="local-admin",
        active_asset_id="a" * 32,
        active_authorization_contract="2026-09-09.1",
        active_authorization_revision_id="b" * 32,
        active_authorization_revision_digest_sha256="c" * 64,
        active_authorization_revision_sequence=1,
    )

    jobs.save(original.model_copy(update={
        "active_asset_id": "d" * 32,
        "active_authorization_contract": "tampered.1",
        "active_authorization_revision_id": "e" * 32,
        "active_authorization_revision_digest_sha256": "f" * 64,
        "active_authorization_revision_sequence": 2,
    }))

    reloaded = jobs.get(original.id)
    assert reloaded.active_asset_id == "a" * 32
    assert reloaded.active_authorization_contract == "2026-09-09.1"
    assert reloaded.active_authorization_revision_id == "b" * 32
    assert reloaded.active_authorization_revision_digest_sha256 == "c" * 64
    assert reloaded.active_authorization_revision_sequence == 1


def test_second_active_admission_read_rejects_a_different_revision(monkeypatch, tmp_path):
    settings = _configure(monkeypatch, tmp_path)
    store = ActiveAssetStore(settings)
    asset = store.create(
        ActiveAssetCreateRequest.model_validate(_payload()),
        organization_id="local-admin",
        actor_id="local-admin",
    )

    with pytest.raises(ActiveAssetStoreError, match="authorization_revision_changed"):
        store.assert_executable(
            asset.id,
            organization_id="local-admin",
            capability="active_dns_inventory",
            expected_authorization_revision_id="f" * 32,
        )


@pytest.mark.anyio
async def test_active_asset_execution_derives_target_and_persists_authorization_contract(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        asset = (await client.post("/active/assets", json=_payload())).json()
        response = await client.post(
            f"/active/assets/{asset['id']}/executions",
            json={"capability": "active_dns_inventory", "authorization_reconfirmed": True, "idempotency_key": "2" * 32},
        )
        assert response.status_code == 202
        job = response.json()
        assert job["active_asset_id"] == asset["id"]
        assert job["active_authorization_contract"] == "2026-09-09.1"
        revision = asset["authorization_revisions"][0]
        assert job["active_authorization_revision_id"] == revision["id"]
        assert job["active_authorization_revision_digest_sha256"] == revision["digest_sha256"]
        assert job["active_authorization_revision_sequence"] == 1
        assert job["target_url"] == "[REDACTED_DOMAIN]"
        assert job["status"] == "queued"
        serialized = json.dumps(job)
        assert "example.test" not in serialized
        assert "discovered" not in serialized.lower()

        detail = await client.get(f"/jobs/{job['id']}")
        assert detail.status_code == 200
        assert detail.json()["status"] == "completed"
        assert detail.json()["active_asset_id"] == asset["id"]
        assert detail.json()["active_authorization_revision_id"] == revision["id"]
        history = (await client.get(f"/active/assets/{asset['id']}")).json()["history"]
        assert [event["kind"] for event in history] == ["registered", "execution_requested"]
        audit_events = app.state.product_audit.list("local-admin", limit=10).items
        execution_event = next(event for event in audit_events if event.action == "active_asset.execution_requested")
        assert execution_event.metadata == {
            "job_id": job["id"],
            "authorization_revision_id": revision["id"],
            "authorization_revision_sequence": 1,
            "replayed": False,
        }


@pytest.mark.anyio
async def test_active_execution_admission_is_idempotent_and_does_not_expose_key(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path, all_standard_capabilities=True)
    request_body = {
        "capability": "active_dns_inventory",
        "authorization_reconfirmed": True,
        "idempotency_key": "b" * 32,
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        asset = (await client.post("/active/assets", json=_payload())).json()
        first = await client.post(f"/active/assets/{asset['id']}/executions", json=request_body)
        replay = await client.post(f"/active/assets/{asset['id']}/executions", json=request_body)
        conflict = await client.post(
            f"/active/assets/{asset['id']}/executions",
            json={**request_body, "capability": "active_dns_osint"},
        )
        listed = await client.get("/jobs")
        detail = await client.get(f"/jobs/{first.json()['id']}")

    assert first.status_code == replay.status_code == 202
    assert replay.json()["id"] == first.json()["id"]
    assert conflict.status_code == 409
    history = app.state.active_assets.get(asset["id"], organization_id="local-admin").history
    assert [event.kind for event in history].count("execution_requested") == 1
    public_payload = first.text + replay.text + listed.text + detail.text
    assert "b" * 32 not in public_payload
    assert hashlib.sha256(("b" * 32).encode()).hexdigest() not in public_payload


def test_active_execution_claim_is_atomic_between_workers(monkeypatch, tmp_path):
    settings = _configure(monkeypatch, tmp_path)
    store = JobStore(settings)
    job, replayed = store.create_active_asset_execution_job(
        "active_dns_inventory",
        owner_id="local-admin",
        active_asset_id="a" * 32,
        active_authorization_contract="2026-09-09.1",
        active_authorization_revision_id="b" * 32,
        active_authorization_revision_digest_sha256="c" * 64,
        active_authorization_revision_sequence=1,
        active_execution_port=None,
        idempotency_key_sha256="d" * 64,
    )
    assert replayed is False
    barrier = threading.Barrier(2)

    def claim():
        barrier.wait()
        return store.claim_queued_active_execution(job.id)

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _index: claim(), range(2)))
    assert sum(result is not None for result in results) == 1
    assert store.get(job.id).status == "running"


def _create_active_quota_job(store: JobStore, *, key: str, owner: str, asset: str, capability: str = "active_dns_inventory"):
    return store.create_active_asset_execution_job(
        capability,
        owner_id=owner,
        active_asset_id=asset,
        active_authorization_contract="2026-09-09.1",
        active_authorization_revision_id="b" * 32,
        active_authorization_revision_digest_sha256="c" * 64,
        active_authorization_revision_sequence=1,
        active_execution_port=None,
        idempotency_key_sha256=key * 64,
    )[0]


def test_active_admission_quotas_are_scope_bounded_generic_and_release_terminal_work(monkeypatch, tmp_path, caplog):
    caplog.set_level(logging.INFO, logger="inspectra.audit")
    base = _configure(monkeypatch, tmp_path)
    generic_detail = "Active execution capacity is temporarily full. Wait for bounded work to finish, then retry."
    scenarios = (
        ("global", dict(active_max_inflight_jobs=1, active_max_inflight_jobs_per_organization=1, active_max_inflight_jobs_per_asset=1, active_max_inflight_jobs_per_capability=1), ("org-a", "a" * 32, "active_dns_inventory"), ("org-b", "d" * 32, "active_dns_osint")),
        ("organization", dict(active_max_inflight_jobs=4, active_max_inflight_jobs_per_organization=1, active_max_inflight_jobs_per_asset=1, active_max_inflight_jobs_per_capability=4), ("org-a", "a" * 32, "active_dns_inventory"), ("org-a", "d" * 32, "active_dns_osint")),
        ("capability", dict(active_max_inflight_jobs=4, active_max_inflight_jobs_per_organization=4, active_max_inflight_jobs_per_asset=2, active_max_inflight_jobs_per_capability=1), ("org-a", "a" * 32, "active_dns_inventory"), ("org-b", "d" * 32, "active_dns_inventory")),
    )
    for index, (_scope, limits, first_identity, rejected_identity) in enumerate(scenarios):
        scenario_dir = tmp_path / f"quota-{index}"
        settings = replace(base, data_dir=scenario_dir, **limits)
        settings.ensure_directories()
        store = JobStore(settings)
        first = _create_active_quota_job(
            store,
            key=str(index + 1),
            owner=first_identity[0],
            asset=first_identity[1],
            capability=first_identity[2],
        )
        with pytest.raises(HTTPException) as rejection:
            _create_active_quota_job(
                store,
                key=str(index + 4),
                owner=rejected_identity[0],
                asset=rejected_identity[1],
                capability=rejected_identity[2],
            )
        assert rejection.value.status_code == 429
        assert rejection.value.detail == generic_detail
        assert rejection.value.headers == {"Retry-After": "5"}
        assert first_identity[1] not in str(rejection.value.detail)
        assert first_identity[1] not in caplog.text
        assert rejected_identity[1] not in caplog.text

        store.update(first.id, status="failed", error="controlled", termination_reason="runner_unavailable")
        admitted = _create_active_quota_job(
            store,
            key=str(index + 7),
            owner=rejected_identity[0],
            asset=rejected_identity[1],
            capability=rejected_identity[2],
        )
        assert admitted.status == "queued"
    assert "active_execution.admission.rejected" in caplog.text
    assert "active_asset_id" not in caplog.text


def test_active_asset_quota_admission_is_atomic_between_workers(monkeypatch, tmp_path):
    base = _configure(monkeypatch, tmp_path)
    settings = replace(
        base,
        active_max_inflight_jobs=8,
        active_max_inflight_jobs_per_organization=8,
        active_max_inflight_jobs_per_asset=1,
        active_max_inflight_jobs_per_capability=8,
    )
    store = JobStore(settings)
    barrier = threading.Barrier(8)

    def admit(index: int):
        worker_store = JobStore(settings)
        barrier.wait()
        try:
            return _create_active_quota_job(worker_store, key=f"{index + 1:x}", owner="org-a", asset="a" * 32)
        except HTTPException as exc:
            return exc

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(admit, range(8)))

    admitted = [result for result in results if not isinstance(result, HTTPException)]
    rejected = [result for result in results if isinstance(result, HTTPException)]
    assert len(admitted) == 1
    assert len(rejected) == 7
    assert {result.status_code for result in rejected} == {429}
    assert len(store._active_inflight_jobs_unlocked()) == 1


def test_active_revocation_releases_queued_capacity_and_retains_running_capacity_until_stopped(monkeypatch, tmp_path):
    base = _configure(monkeypatch, tmp_path)
    settings = replace(
        base,
        active_max_inflight_jobs=1,
        active_max_inflight_jobs_per_organization=1,
        active_max_inflight_jobs_per_asset=1,
        active_max_inflight_jobs_per_capability=1,
    )
    store = JobStore(settings)
    queued = _create_active_quota_job(store, key="1", owner="org-a", asset="a" * 32)
    revoked_queued = store.request_active_authorization_revocation(
        queued.id,
        owner_id="org-a",
        active_asset_id="a" * 32,
    )
    assert revoked_queued.status == "cancelled"
    assert revoked_queued.termination_reason == "authorization_revoked"

    running = _create_active_quota_job(store, key="2", owner="org-b", asset="d" * 32)
    assert store.claim_queued_active_execution(running.id) is not None
    stopping = store.request_active_authorization_revocation(
        running.id,
        owner_id="org-b",
        active_asset_id="d" * 32,
    )
    assert stopping.status == "cancelling"
    assert stopping.termination_reason == "authorization_revoked"
    restarted_worker = JobStore(settings)
    assert restarted_worker.active_admission_available(owner_id="org-c") is False
    with pytest.raises(HTTPException) as still_consumed:
        _create_active_quota_job(restarted_worker, key="3", owner="org-c", asset="e" * 32, capability="active_dns_osint")
    assert still_consumed.value.status_code == 429

    store.update(
        running.id,
        status="cancelled",
        error="Authorization revoked.",
        termination_reason="authorization_revoked",
        active_execution_phase="terminal",
    )
    admitted = _create_active_quota_job(store, key="4", owner="org-c", asset="e" * 32, capability="active_dns_osint")
    assert admitted.status == "queued"


@pytest.mark.anyio
async def test_active_route_rejects_saturated_asset_before_runner_without_leaking_scope(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_ACTIVE_MAX_INFLIGHT_JOBS", "8")
    monkeypatch.setenv("INSPECTRA_ACTIVE_MAX_INFLIGHT_JOBS_PER_ORGANIZATION", "8")
    monkeypatch.setenv("INSPECTRA_ACTIVE_MAX_INFLIGHT_JOBS_PER_ASSET", "1")
    monkeypatch.setenv("INSPECTRA_ACTIVE_MAX_INFLIGHT_JOBS_PER_CAPABILITY", "8")
    _configure(monkeypatch, tmp_path)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        asset = (await client.post("/active/assets", json=_payload())).json()
        revision = asset["authorization_revisions"][-1]
        held = _create_active_quota_job(
            app.state.jobs,
            key="1",
            owner="local-admin",
            asset=asset["id"],
        )
        rejected = await client.post(
            f"/active/assets/{asset['id']}/executions",
            json={"capability": "active_dns_inventory", "authorization_reconfirmed": True, "idempotency_key": "2" * 32},
        )

    assert rejected.status_code == 429
    assert rejected.headers["Retry-After"] == "5"
    assert rejected.json() == {
        "detail": "Active execution capacity is temporarily full. Wait for bounded work to finish, then retry."
    }
    assert asset["id"] not in rejected.text
    assert revision["id"] not in rejected.text
    assert app.state.active_capability_runner.calls == []
    assert app.state.jobs.get(held.id).status == "queued"


@pytest.mark.anyio
async def test_active_execution_can_be_cancelled_and_retried_without_duplicate_runner_traffic(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)
    slow_runner = SlowActiveCapabilityRunner()
    app.state.active_capability_runner = slow_runner
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        asset = (await client.post("/active/assets", json=_payload())).json()
        launch_task = asyncio.create_task(client.post(
            f"/active/assets/{asset['id']}/executions",
            json={"capability": "active_dns_inventory", "authorization_reconfirmed": True, "idempotency_key": "c" * 32},
        ))
        await asyncio.wait_for(slow_runner.started.wait(), timeout=1)
        job_id = next((tmp_path / "results" / "jobs").glob("*.json")).stem
        # Simulate the cancel request landing on another backend worker: the
        # persisted state, not a process-local event, must still stop traffic.
        app.state.active_execution_cancellation_events.clear()
        cancelled = await client.post(
            f"/active/assets/{asset['id']}/executions/{job_id}/cancel",
            json={"cancellation_confirmed": True},
        )
        launched = await asyncio.wait_for(launch_task, timeout=2)
        assert cancelled.status_code == 200
        assert launched.status_code == 202
        assert app.state.jobs.get(job_id).status == "cancelled"
        assert slow_runner.cancelled.is_set()

        app.state.active_capability_runner = FakeActiveCapabilityRunner()
        retried = await client.post(
            f"/active/assets/{asset['id']}/executions/{job_id}/retry",
            json={"authorization_reconfirmed": True, "idempotency_key": "d" * 32},
        )
        retry_detail = await client.get(f"/jobs/{retried.json()['id']}")
        replay = await client.post(
            f"/active/assets/{asset['id']}/executions/{job_id}/retry",
            json={"authorization_reconfirmed": True, "idempotency_key": "d" * 32},
        )

    assert retried.status_code == replay.status_code == 202
    assert replay.json()["id"] == retried.json()["id"]
    assert retry_detail.json()["status"] == "completed"
    assert retry_detail.json()["retry_of_job_id"] == job_id


def test_active_restart_recovery_preserves_only_never_started_work(monkeypatch, tmp_path):
    settings = _configure(monkeypatch, tmp_path)
    store = JobStore(settings)
    arguments = dict(
        audit_type="active_dns_inventory",
        owner_id="local-admin",
        active_asset_id="a" * 32,
        active_authorization_contract="2026-09-09.1",
        active_authorization_revision_id="b" * 32,
        active_authorization_revision_digest_sha256="c" * 64,
        active_authorization_revision_sequence=1,
        active_execution_port=None,
    )
    queued, _ = store.create_active_asset_execution_job(**arguments, idempotency_key_sha256="1" * 64)
    running, _ = store.create_active_asset_execution_job(**arguments, idempotency_key_sha256="2" * 64)
    assert store.claim_queued_active_execution(running.id) is not None
    interrupted = store.recover_interrupted_jobs(preserve_queued_active_jobs=True)
    assert [record.id for record in interrupted] == [running.id]
    assert store.get(queued.id).status == "queued"
    assert store.get(running.id).status == "failed"
    assert store.get(running.id).termination_reason == "application_restart"


@pytest.mark.anyio
async def test_active_startup_revalidates_and_resumes_only_current_authorization(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)
    asset = app.state.active_assets.create(
        ActiveAssetCreateRequest.model_validate(_payload()),
        organization_id="local-admin",
        actor_id="local-admin",
    )
    revision = asset.authorization_revisions[-1]
    queued, _ = app.state.jobs.create_active_asset_execution_job(
        "active_dns_inventory",
        owner_id="local-admin",
        active_asset_id=asset.id,
        active_authorization_contract="2026-09-09.1",
        active_authorization_revision_id=revision.id,
        active_authorization_revision_digest_sha256=revision.digest_sha256,
        active_authorization_revision_sequence=revision.sequence,
        active_execution_port=None,
        idempotency_key_sha256="3" * 64,
    )

    recovered = backend_main.resume_queued_active_jobs(app)
    await asyncio.gather(*list(app.state.durable_audit_tasks))

    assert [job.id for job in recovered] == [queued.id]
    assert app.state.jobs.get(queued.id).status == "completed"
    assert app.state.jobs.get(queued.id).recovery_count == 1

    changed, _ = app.state.jobs.create_active_asset_execution_job(
        "active_dns_inventory",
        owner_id="local-admin",
        active_asset_id=asset.id,
        active_authorization_contract="2026-09-09.1",
        active_authorization_revision_id="f" * 32,
        active_authorization_revision_digest_sha256="e" * 64,
        active_authorization_revision_sequence=revision.sequence,
        active_execution_port=None,
        idempotency_key_sha256="4" * 64,
    )
    calls_before_rejection = len(app.state.active_capability_runner.calls)

    assert backend_main.resume_queued_active_jobs(app) == []
    rejected = app.state.jobs.get(changed.id)
    assert rejected.status == "failed"
    assert rejected.termination_reason == "recovery_rejected"
    assert rejected.active_execution_phase == "terminal"
    assert len(app.state.active_capability_runner.calls) == calls_before_rejection


@pytest.mark.anyio
async def test_active_authorization_renewal_is_append_only_idempotent_and_audited(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        asset = (await client.post("/active/assets", json=_payload())).json()
        request = _renewal_payload(asset)
        renewed = await client.post(f"/active/assets/{asset['id']}/renew", json=request)
        replayed = await client.post(f"/active/assets/{asset['id']}/renew", json=request)
        conflict = await client.post(
            f"/active/assets/{asset['id']}/renew",
            json={**request, "authorization_reference": "change-ticket SEC-44"},
        )
        report = await client.get(f"/active/assets/{asset['id']}/report")

    assert renewed.status_code == 200, renewed.text
    body = renewed.json()
    assert body["replayed"] is False
    assert body["scope_expanded"] is False
    assert [item["sequence"] for item in body["asset"]["authorization_revisions"]] == [1, 2]
    assert [item["source"] for item in body["asset"]["authorization_revisions"]] == ["registration", "renewal"]
    assert body["asset"]["authorization_revisions"][0] == asset["authorization_revisions"][0]
    assert body["asset"]["authorization_revisions"][1]["id"] != asset["authorization_revisions"][0]["id"]
    assert body["asset"]["authorization_revisions"][1]["scope_expanded"] is False
    assert body["asset"]["history"][-1]["kind"] == "renewed"
    assert body["asset"]["history"][-1]["reason_code"] == "authorization_renewed"
    assert replayed.status_code == 200
    assert replayed.json()["replayed"] is True
    assert replayed.json()["asset"]["authorization_revisions"] == body["asset"]["authorization_revisions"]
    assert replayed.json()["asset"]["history"] == body["asset"]["history"]
    assert conflict.status_code == 409
    assert "SEC-44" not in conflict.text
    assert "`r1`" in report.text and "`r2`" in report.text
    assert "example.test" not in report.text
    assert "SEC-42" not in report.text and "SEC-43" not in report.text
    events = [item for item in app.state.product_audit.list("local-admin", limit=10).items if item.action == "active_asset.authorization_renewed"]
    assert [item.metadata["replayed"] for item in events] == [True, False]
    assert all("SEC-" not in json.dumps(item.metadata) for item in events)


@pytest.mark.anyio
async def test_concurrent_identical_renewals_append_exactly_one_revision(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        asset = (await client.post("/active/assets", json=_payload())).json()
        request = _renewal_payload(asset, idempotency_key="6" * 32)
        responses = await asyncio.gather(
            client.post(f"/active/assets/{asset['id']}/renew", json=request),
            client.post(f"/active/assets/{asset['id']}/renew", json=request),
        )

    assert all(response.status_code == 200 for response in responses)
    assert sorted(response.json()["replayed"] for response in responses) == [False, True]
    revision_ids = {response.json()["asset"]["authorization_revisions"][-1]["id"] for response in responses}
    assert len(revision_ids) == 1
    stored = app.state.active_assets.get(asset["id"], organization_id="local-admin")
    assert len(stored.authorization_revisions) == 2
    assert [event.kind for event in stored.history].count("renewed") == 1


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("initial", "changes"),
    [
        ({"capabilities": ["active_dns_inventory"]}, {"capabilities": ["active_dns_inventory", "active_dns_osint"]}),
        (
            {"asset_type": "ip", "value": "127.0.0.1", "capabilities": ["active_nmap_basic"], "allowed_ports": [443], "allowed_protocols": ["tcp"]},
            {"allowed_ports": [443, 8443]},
        ),
        (
            {"asset_type": "http_origin", "value": "https://headers.example.test", "capabilities": ["active_http_basic_header_review"], "allowed_ports": [], "allowed_protocols": ["https"]},
            {"allowed_protocols": ["http", "https"]},
        ),
    ],
)
async def test_renewal_requires_specific_confirmation_for_each_scope_expansion(monkeypatch, tmp_path, initial, changes):
    _configure(monkeypatch, tmp_path)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        asset = (await client.post("/active/assets", json=_payload(**initial))).json()
        request = _renewal_payload(asset, **changes)
        blocked = await client.post(f"/active/assets/{asset['id']}/renew", json=request)
        confirmed_request = {**request, "scope_expansion_confirmed": True}
        accepted = await client.post(
            f"/active/assets/{asset['id']}/renew",
            json=confirmed_request,
        )
        app.state.active_assets.append_event(
            asset["id"],
            organization_id="local-admin",
            actor_id="local-admin",
            kind="verification_started",
        )
        replayed_after_later_event = await client.post(
            f"/active/assets/{asset['id']}/renew",
            json=confirmed_request,
        )

    assert blocked.status_code == 409
    assert blocked.json() == {"detail": "Expanded capability, protocol, or port scope requires a specific confirmation."}
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["scope_expanded"] is True
    assert accepted.json()["asset"]["authorization_revisions"][-1]["scope_expanded"] is True
    assert accepted.json()["asset"]["history"][-1]["reason_code"] == "scope_expanded"
    assert replayed_after_later_event.status_code == 200
    assert replayed_after_later_event.json()["replayed"] is True
    assert replayed_after_later_event.json()["scope_expanded"] is True


@pytest.mark.anyio
async def test_renewal_rejects_stale_revision_and_never_reactivates_revoked_asset(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        asset = (await client.post("/active/assets", json=_payload())).json()
        stale = await client.post(
            f"/active/assets/{asset['id']}/renew",
            json=_renewal_payload(asset, expected_revision_id="f" * 32),
        )
        revoked = await client.post(f"/active/assets/{asset['id']}/revoke", json={"reason_code": "authorization_withdrawn"})
        blocked = await client.post(f"/active/assets/{asset['id']}/renew", json=_renewal_payload(asset, idempotency_key="8" * 32))

    assert stale.status_code == 409
    assert revoked.status_code == 200
    assert blocked.status_code == 409
    stored = app.state.active_assets.get(asset["id"], organization_id="local-admin")
    assert stored.status == "revoked"
    assert len(stored.authorization_revisions) == 1


def test_expired_and_legacy_assets_can_only_return_via_a_new_re_attested_revision(monkeypatch, tmp_path):
    settings = _configure(monkeypatch, tmp_path)
    now = datetime.now(timezone.utc)
    mutable_now = [now]
    store = ActiveAssetStore(settings, now_func=lambda: mutable_now[0])
    asset = store.create(
        ActiveAssetCreateRequest.model_validate(_payload(expires_at=(now + timedelta(days=30)).isoformat())),
        organization_id="local-admin",
        actor_id="local-admin",
    )
    mutable_now[0] = now + timedelta(days=31)
    expired = store.get(asset.id, organization_id="local-admin")
    assert expired.status == "expired"
    request = ActiveAssetRenewRequest.model_validate(
        _renewal_payload(
            expired.model_dump(mode="json"),
            authorized_at=now.isoformat(),
            expires_at=(now + timedelta(days=60)).isoformat(),
        )
    )
    renewed, replayed, _expanded = store.renew(
        asset.id,
        request,
        organization_id="local-admin",
        actor_id="local-admin",
    )
    assert renewed.status == "active"
    assert replayed is False
    assert [item.sequence for item in renewed.authorization_revisions] == [1, 2]

    legacy_path = next((tmp_path / "results" / "active_assets").rglob(f"{renewed.id}.json"))
    legacy_payload = json.loads(legacy_path.read_text(encoding="utf-8"))
    legacy_payload["authorization_revisions"] = []
    legacy_payload["status"] = "expired"
    legacy_path.write_text(json.dumps(legacy_payload), encoding="utf-8")
    legacy_request = ActiveAssetRenewRequest.model_validate(
        _renewal_payload(
            legacy_payload,
            idempotency_key="9" * 32,
            expected_revision_id=None,
            expires_at=(now + timedelta(days=90)).isoformat(),
        )
    )
    legacy_renewed, _, _ = store.renew(
        renewed.id,
        legacy_request,
        organization_id="local-admin",
        actor_id="local-admin",
    )
    assert len(legacy_renewed.authorization_revisions) == 1
    assert legacy_renewed.authorization_revisions[0].sequence == 1
    assert legacy_renewed.authorization_revisions[0].source == "renewal"


@pytest.mark.anyio
async def test_team_renewal_requires_csrf_and_does_not_cross_organizations(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path, auth_mode="private_team_lightweight_users")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        assert (await client.post("/auth/login", json={"username": "admin", "password": "admin-weekly-password"})).status_code == 200
        csrf = (await client.get("/auth/status")).json()["csrf_token"]
        asset = (await client.post("/active/assets", json=_payload(responsible_user_ids=["team-admin"]), headers={ADMIN_CSRF_HEADER_NAME: csrf})).json()
        without_csrf = await client.post(f"/active/assets/{asset['id']}/renew", json=_renewal_payload(asset))
        with_csrf = await client.post(
            f"/active/assets/{asset['id']}/renew",
            json=_renewal_payload(asset),
            headers={ADMIN_CSRF_HEADER_NAME: csrf},
        )
        other = await client.post(
            f"/active/assets/{'f' * 32}/renew",
            json=_renewal_payload(asset, idempotency_key="a" * 32),
            headers={ADMIN_CSRF_HEADER_NAME: csrf},
        )

    assert without_csrf.status_code == 403
    assert with_csrf.status_code == 200
    assert other.status_code == 404


@pytest.mark.anyio
async def test_active_responsibles_are_current_workspace_members_without_role_escalation_or_enumeration(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path, auth_mode="private_team_lightweight_users")
    identity = app.state.team_identity
    admin_principal = identity.authenticate("admin", "admin-weekly-password")
    assert admin_principal is not None

    reader_invitation = identity.create_invitation(principal=admin_principal, username="active.reader", role="reader")
    reader = identity.accept_invitation(token=reader_invitation.token, password="reader-weekly-password")
    maintainer_invitation = identity.create_invitation(principal=admin_principal, username="active.maintainer", role="maintainer")
    maintainer = identity.accept_invitation(token=maintainer_invitation.token, password="maintainer-weekly-password")
    revoked_invitation = identity.create_invitation(principal=admin_principal, username="former.member", role="reader")
    revoked = identity.accept_invitation(token=revoked_invitation.token, password="former-weekly-password")
    identity.revoke_member(principal=admin_principal, user_id=revoked.user_id)

    other_workspace = identity.create_organization(principal=admin_principal, name="Other isolated workspace")
    other_admin = identity.get_principal(admin_principal.user_id, other_workspace.organization_id)
    assert other_admin is not None
    external_invitation = identity.create_invitation(principal=other_admin, username="external.member", role="reader")
    external = identity.accept_invitation(token=external_invitation.token, password="external-weekly-password")

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as admin:
        assert (await admin.post("/auth/login", json={"username": "admin", "password": "admin-weekly-password"})).status_code == 200
        csrf = (await admin.get("/auth/status")).json()["csrf_token"]
        headers = {ADMIN_CSRF_HEADER_NAME: csrf}
        created = await admin.post(
            "/active/assets",
            json=_payload(responsible_user_ids=["team-admin", reader.user_id, maintainer.user_id]),
            headers=headers,
        )
        assert created.status_code == 201, created.text
        asset = created.json()
        renewed = await admin.post(
            f"/active/assets/{asset['id']}/renew",
            json=_renewal_payload(asset, responsible_user_ids=[reader.user_id]),
            headers=headers,
        )
        rejected_external = await admin.post(
            "/active/assets",
            json=_payload(value="external.example.test", responsible_user_ids=[external.user_id]),
            headers=headers,
        )
        rejected_revoked = await admin.post(
            "/active/assets",
            json=_payload(value="former.example.test", responsible_user_ids=[revoked.user_id]),
            headers=headers,
        )

    assert renewed.status_code == 200, renewed.text
    assert renewed.json()["asset"]["responsible_user_ids"] == [reader.user_id]
    assert rejected_external.status_code == rejected_revoked.status_code == 422
    assert rejected_external.json() == rejected_revoked.json() == {
        "detail": "Responsible accounts must be active members of the current workspace."
    }
    rejected_payload = rejected_external.text + rejected_revoked.text
    assert external.user_id not in rejected_payload and revoked.user_id not in rejected_payload
    assert "external.member" not in rejected_payload and "former.member" not in rejected_payload

    async with AsyncClient(transport=transport, base_url="http://testserver") as reader_client:
        assert (await reader_client.post("/auth/login", json={"username": "active.reader", "password": "reader-weekly-password"})).status_code == 200
        reader_status = (await reader_client.get("/auth/status")).json()
        visible = await reader_client.get(f"/active/assets/{asset['id']}")
        forbidden = await reader_client.post(
            "/active/assets",
            json=_payload(value="reader-write.example.test", responsible_user_ids=[reader.user_id]),
            headers={ADMIN_CSRF_HEADER_NAME: reader_status["csrf_token"]},
        )
    assert visible.status_code == 200
    assert visible.json()["responsible_user_ids"] == [reader.user_id]
    assert forbidden.status_code == 403


@pytest.mark.anyio
async def test_member_revocation_invalidates_sessions_then_reconciles_active_assignments_without_identity_history(
    monkeypatch,
    tmp_path,
):
    settings = _configure(monkeypatch, tmp_path, auth_mode="private_team_lightweight_users")
    app.state.projects = ProjectStore(settings)
    identity = app.state.team_identity
    admin_principal = identity.authenticate("admin", "admin-weekly-password")
    assert admin_principal is not None
    reader_invitation = identity.create_invitation(principal=admin_principal, username="departing.reader", role="reader")
    departing = identity.accept_invitation(token=reader_invitation.token, password="departing-reader-password")
    maintainer_invitation = identity.create_invitation(principal=admin_principal, username="remaining.maintainer", role="maintainer")
    remaining = identity.accept_invitation(token=maintainer_invitation.token, password="remaining-maintainer-password")

    transport = ASGITransport(app=app)
    async with (
        AsyncClient(transport=transport, base_url="http://testserver") as admin,
        AsyncClient(transport=transport, base_url="http://testserver") as departing_client,
    ):
        assert (await admin.post("/auth/login", json={"username": "admin", "password": "admin-weekly-password"})).status_code == 200
        admin_csrf = (await admin.get("/auth/status")).json()["csrf_token"]
        headers = {ADMIN_CSRF_HEADER_NAME: admin_csrf}
        assert (await departing_client.post("/auth/login", json={"username": "departing.reader", "password": "departing-reader-password"})).status_code == 200

        project_now = datetime.now(timezone.utc)
        project = ProjectRecord(
            id="e" * 32,
            owner_id="local-admin",
            name="Responsibility fixture",
            source_file_id="d" * 32,
            source_filename="private.zip",
            source_sha256="c" * 64,
            source_snapshots=[ProjectSourceSnapshot(
                id="b" * 32,
                source_file_id="d" * 32,
                source_filename="private.zip",
                source_sha256="c" * 64,
                created_at=project_now,
            )],
            created_at=project_now,
            updated_at=project_now,
        )
        app.state.projects._save_unlocked(project)
        assigned_project = await admin.put(
            f"/projects/{project.id}/responsibility",
            json={
                "responsible_user_id": departing.user_id,
                "expected_updated_at": project.updated_at.isoformat(),
                "assignment_confirmed": True,
            },
            headers=headers,
        )
        assert assigned_project.status_code == 200, assigned_project.text
        assert assigned_project.json()["responsibility"]["responsible_user_id"] == departing.user_id
        assigned_updated_at = assigned_project.json()["updated_at"]
        departing_csrf = (await departing_client.get("/auth/status")).json()["csrf_token"]
        reader_forbidden = await departing_client.put(
            f"/projects/{project.id}/responsibility",
            json={
                "responsible_user_id": None,
                "expected_updated_at": assigned_updated_at,
                "assignment_confirmed": True,
            },
            headers={ADMIN_CSRF_HEADER_NAME: departing_csrf},
        )
        inactive_rejected = await admin.put(
            f"/projects/{project.id}/responsibility",
            json={
                "responsible_user_id": "absent-member",
                "expected_updated_at": assigned_updated_at,
                "assignment_confirmed": True,
            },
            headers=headers,
        )
        assert reader_forbidden.status_code == 403
        assert inactive_rejected.status_code == 422
        assert "absent-member" not in inactive_rejected.text

        first = (
            await admin.post(
                "/active/assets",
                json=_payload(value="sole.example.test", responsible_user_ids=[departing.user_id]),
                headers=headers,
            )
        ).json()
        second = (
            await admin.post(
                "/active/assets",
                json=_payload(value="shared.example.test", responsible_user_ids=[departing.user_id, remaining.user_id]),
                headers=headers,
            )
        ).json()
        impact = await admin.get(f"/organization/members/{departing.user_id}/responsibility-impact")
        assert impact.status_code == 200
        assert impact.json() == {
            "affected_asset_count": 2,
            "will_become_unassigned_count": 1,
            "will_keep_other_responsibles_count": 1,
            "affected_project_count": 1,
            "projects_requiring_reassignment_count": 1,
        }
        assert "departing.reader" not in impact.text
        assert "sole.example.test" not in impact.text

        order: list[str] = []
        original_invalidator = app.state.admin_sessions.invalidate_operator_organization_sessions
        original_unassign = app.state.active_assets.unassign_member
        original_project_unassign = app.state.projects.unassign_member

        def invalidate_sessions(user_id: str, organization_id: str):
            assert organization_id == "local-admin"
            order.append("sessions")
            return original_invalidator(user_id, organization_id)

        def unassign_member(user_id: str, *, organization_id: str, actor_id: str):
            assert order == ["sessions", "projects"]
            order.append("assets")
            return original_unassign(user_id, organization_id=organization_id, actor_id=actor_id)

        def unassign_project_member(user_id: str, *, owner_id: str, actor_id: str):
            assert order == ["sessions"]
            order.append("projects")
            return original_project_unassign(user_id, owner_id=owner_id, actor_id=actor_id)

        monkeypatch.setattr(
            app.state.admin_sessions,
            "invalidate_operator_organization_sessions",
            invalidate_sessions,
        )
        monkeypatch.setattr(app.state.active_assets, "unassign_member", unassign_member)
        monkeypatch.setattr(app.state.projects, "unassign_member", unassign_project_member)
        revoked = await admin.delete(f"/organization/members/{departing.user_id}", headers=headers)
        assert revoked.status_code == 204
        assert order == ["sessions", "projects", "assets"]
        assert (await departing_client.get("/active/assets")).status_code == 401

        first_after = (await admin.get(f"/active/assets/{first['id']}")).json()
        second_after = (await admin.get(f"/active/assets/{second['id']}")).json()
        project_after = (await admin.get(f"/projects/{project.id}")).json()["project"]

    assert first_after["responsible_user_ids"] == []
    assert second_after["responsible_user_ids"] == [remaining.user_id]
    for record in (first_after, second_after):
        latest = record["history"][-1]
        assert latest["kind"] == "responsibles_updated"
        assert latest["reason_code"] == "membership_revoked"
        history = json.dumps(record["history"])
        assert departing.user_id not in history
        assert "departing.reader" not in history
        assert record["canonical_value"] not in history
    assert project_after["responsibility"] == {
        "state": "unassigned_attention",
        "responsible_user_id": None,
        "revision": 2,
        "updated_at": project_after["updated_at"],
    }
    event = next(
        item for item in app.state.product_audit.list("local-admin", limit=50).items
        if item.action == "team.member_revoked"
    )
    assert event.metadata == {
        "affected_asset_count": 2,
        "unassigned_asset_count": 1,
        "affected_project_count": 1,
        "unassigned_project_count": 1,
    }


@pytest.mark.anyio
async def test_member_revocation_rolls_back_membership_but_keeps_invalidated_session_on_reconciliation_failure(
    monkeypatch,
    tmp_path,
):
    _configure(monkeypatch, tmp_path, auth_mode="private_team_lightweight_users")
    identity = app.state.team_identity
    admin_principal = identity.authenticate("admin", "admin-weekly-password")
    assert admin_principal is not None
    invitation = identity.create_invitation(principal=admin_principal, username="retry.reader", role="reader")
    reader = identity.accept_invitation(token=invitation.token, password="retry-reader-password")
    transport = ASGITransport(app=app)
    async with (
        AsyncClient(transport=transport, base_url="http://testserver") as admin,
        AsyncClient(transport=transport, base_url="http://testserver") as reader_client,
    ):
        assert (await admin.post("/auth/login", json={"username": "admin", "password": "admin-weekly-password"})).status_code == 200
        csrf = (await admin.get("/auth/status")).json()["csrf_token"]
        assert (await reader_client.post("/auth/login", json={"username": "retry.reader", "password": "retry-reader-password"})).status_code == 200

        def unavailable(*_args, **_kwargs):
            raise ActiveAssetStoreError("history_capacity_reached")

        monkeypatch.setattr(app.state.active_assets, "unassign_member", unavailable)
        failed = await admin.delete(
            f"/organization/members/{reader.user_id}",
            headers={ADMIN_CSRF_HEADER_NAME: csrf},
        )
        assert failed.status_code == 503
        assert failed.json() == {"detail": "Member revocation could not be reconciled safely."}
        assert (await reader_client.get("/active/assets")).status_code == 401
        assert identity.get_principal(reader.user_id, reader.organization_id) is not None
        assert (await reader_client.post("/auth/login", json={"username": "retry.reader", "password": "retry-reader-password"})).status_code == 200


def test_assignment_and_membership_revocation_are_serialized_without_orphan_reintroduction(monkeypatch, tmp_path):
    settings = _configure(monkeypatch, tmp_path, auth_mode="private_team_lightweight_users")
    identity = app.state.team_identity
    admin = identity.authenticate("admin", "admin-weekly-password")
    assert admin is not None
    invitation = identity.create_invitation(principal=admin, username="racing.reader", role="reader")
    reader = identity.accept_invitation(token=invitation.token, password="racing-reader-password")
    store = ActiveAssetStore(settings)
    asset = store.create(
        ActiveAssetCreateRequest.model_validate(_payload(responsible_user_ids=[])),
        organization_id=admin.organization_id,
        actor_id=admin.user_id,
    )
    operation_entered = threading.Event()
    permit_assignment = threading.Event()

    def assign_while_member_is_current():
        def assignment():
            operation_entered.set()
            assert permit_assignment.wait(timeout=2)
            return store.set_responsibles(
                asset.id,
                ActiveAssetResponsiblesUpdateRequest.model_validate(
                    {
                        "responsible_user_ids": [reader.user_id],
                        "expected_updated_at": asset.updated_at,
                        "assignment_confirmed": True,
                    }
                ),
                organization_id=admin.organization_id,
                actor_id=admin.user_id,
            )

        return identity.run_with_active_members(
            organization_id=admin.organization_id,
            user_ids=[reader.user_id],
            operation=assignment,
        )

    def revoke_and_reconcile():
        return identity.revoke_member(
            principal=admin,
            user_id=reader.user_id,
            on_membership_revoked=lambda: store.unassign_member(
                reader.user_id,
                organization_id=admin.organization_id,
                actor_id=admin.user_id,
            ),
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        assignment_future = executor.submit(assign_while_member_is_current)
        assert operation_entered.wait(timeout=2)
        revocation_future = executor.submit(revoke_and_reconcile)
        with pytest.raises(FutureTimeoutError):
            revocation_future.result(timeout=0.1)
        permit_assignment.set()
        assignment_future.result(timeout=2)
        impact = revocation_future.result(timeout=2)

    assert impact is not None and impact.affected_asset_count == 1
    assert identity.get_principal(reader.user_id, admin.organization_id) is None
    final = store.get(asset.id, organization_id=admin.organization_id)
    assert final.responsible_user_ids == []
    assert [item.reason_code for item in final.history[-2:]] == ["responsibles_assigned", "membership_revoked"]


@pytest.mark.anyio
async def test_responsible_reassignment_is_cas_guarded_and_does_not_create_authorization_revision(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path, auth_mode="private_team_lightweight_users")
    identity = app.state.team_identity
    admin_principal = identity.authenticate("admin", "admin-weekly-password")
    assert admin_principal is not None
    invitation = identity.create_invitation(principal=admin_principal, username="assigned.reader", role="reader")
    reader = identity.accept_invitation(token=invitation.token, password="assigned-reader-password")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        assert (await client.post("/auth/login", json={"username": "admin", "password": "admin-weekly-password"})).status_code == 200
        csrf = (await client.get("/auth/status")).json()["csrf_token"]
        headers = {ADMIN_CSRF_HEADER_NAME: csrf}
        asset = (await client.post("/active/assets", json=_payload(responsible_user_ids=[]), headers=headers)).json()
        assigned = await client.post(
            f"/active/assets/{asset['id']}/responsibles",
            json={
                "responsible_user_ids": [reader.user_id],
                "expected_updated_at": asset["updated_at"],
                "assignment_confirmed": True,
            },
            headers=headers,
        )
        stale = await client.post(
            f"/active/assets/{asset['id']}/responsibles",
            json={
                "responsible_user_ids": [],
                "expected_updated_at": asset["updated_at"],
                "assignment_confirmed": True,
            },
            headers=headers,
        )

    assert assigned.status_code == 200, assigned.text
    body = assigned.json()
    assert body["responsible_user_ids"] == [reader.user_id]
    assert body["authorization_revisions"] == asset["authorization_revisions"]
    assert body["history"][-1]["reason_code"] == "responsibles_assigned"
    assert reader.user_id not in json.dumps(body["history"])
    assert stale.status_code == 409
    assert stale.json() == {
        "detail": "Active asset changed while responsibilities were being reviewed. Reload and try again."
    }


@pytest.mark.anyio
async def test_trusted_local_active_responsibles_reject_arbitrary_opaque_ids(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        accepted = await client.post("/active/assets", json=_payload(responsible_user_ids=["local-admin"]))
        rejected = await client.post(
            "/active/assets",
            json=_payload(value="opaque.example.test", responsible_user_ids=["d" * 32]),
        )
    assert accepted.status_code == 201
    assert rejected.status_code == 422
    assert "d" * 32 not in rejected.text


@pytest.mark.anyio
async def test_asset_bound_standard_capabilities_cross_only_the_isolated_runner_interface(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path, all_standard_capabilities=True)
    runner = FixtureActiveCapabilityRunner(
        {
            "active_dns_inventory": {
                "capability": "active_dns_inventory", "result_status": "best_effort_inventory", "status": "best_effort_inventory",
                "records": {}, "security_records": {}, "execution": {"target_expansion_performed": False},
            },
            "active_dns_osint": {
                "capability": "active_dns_osint", "result_status": "osint_best_effort", "status": "osint_best_effort",
                "sources": {"certificate_transparency": {"status": "completed"}}, "observed_names": {"count": 0, "sample": []},
            },
            "active_http_basic_header_review": {
                "capability": "active_http_basic_header_review", "result_status": "observed", "status": "observed",
                "execution": {"network_requests_sent": 1}, "response": {"status_code": 200}, "header_indicators": {},
            },
            "active_tls_basic": {
                "capability": "active_tls_basic", "result_status": "handshake_succeeded", "status": "handshake_succeeded",
                "handshake": {"status": "succeeded", "protocol": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384"},
                "certificate": {"available": False}, "reason_codes": [],
            },
        }
    )
    app.state.active_capability_runner = runner
    cases = [
        (_payload(value="dns.example.test", capabilities=["active_dns_inventory"], notes=[]), "active_dns_inventory", None),
        (_payload(value="osint.example.test", capabilities=["active_dns_osint"], notes=[]), "active_dns_osint", None),
        (_payload(value="https://headers.example.test", asset_type="http_origin", capabilities=["active_http_basic_header_review"], allowed_protocols=["https"], notes=[]), "active_http_basic_header_review", None),
        (_payload(value="tls.example.test", asset_type="host", capabilities=["active_tls_basic"], allowed_protocols=["tls"], allowed_ports=[443], notes=[]), "active_tls_basic", 443),
    ]
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        jobs = []
        for asset_payload, capability, port in cases:
            asset_response = await client.post("/active/assets", json=asset_payload)
            assert asset_response.status_code == 201, asset_response.text
            body = {"capability": capability, "authorization_reconfirmed": True, "idempotency_key": f"{len(jobs) + 3:x}" * 32}
            if port is not None:
                body["port"] = port
            execution = await client.post(f"/active/assets/{asset_response.json()['id']}/executions", json=body)
            assert execution.status_code == 202, execution.text
            jobs.append((await client.get(f"/jobs/{execution.json()['id']}")).json())

    assert [call[0] for call in runner.calls] == [case[1] for case in cases]
    assert runner.calls[-1][2] == 443
    assert all(job["status"] == "completed" for job in jobs)
    serialized = json.dumps(jobs)
    for target in ("dns.example.test", "osint.example.test", "headers.example.test", "tls.example.test"):
        assert target not in serialized


@pytest.mark.anyio
async def test_active_asset_execution_rejects_user_scope_and_revoked_authorization(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        asset = (await client.post("/active/assets", json=_payload())).json()
        expanded = await client.post(
            f"/active/assets/{asset['id']}/executions",
            json={"capability": "active_dns_inventory", "authorization_reconfirmed": True, "idempotency_key": "7" * 32, "target": "other.example.test"},
        )
        assert expanded.status_code == 422
        assert "other.example.test" not in expanded.text
        await client.post(f"/active/assets/{asset['id']}/revoke", json={"reason_code": "authorization_withdrawn"})
        blocked = await client.post(
            f"/active/assets/{asset['id']}/executions",
            json={"capability": "active_dns_inventory", "authorization_reconfirmed": True, "idempotency_key": "8" * 32},
        )
        assert blocked.status_code == 409
        assert list((tmp_path / "results" / "jobs").glob("*.json")) == []


@pytest.mark.anyio
async def test_free_target_active_routes_are_retired_by_default(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        response = await client.post(
            "/active/network/dns-inventory",
            json={"domain": "unregistered.example.test"},
        )
    assert response.status_code == 410
    assert "unregistered.example.test" not in response.text
    assert list((tmp_path / "results" / "jobs").glob("*.json")) == []


@pytest.mark.anyio
async def test_revocation_cancels_an_admitted_nmap_operation_before_it_finishes(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)
    started = asyncio.Event()

    async def slow_lifecycle(*_args, **_kwargs):
        started.set()
        await asyncio.sleep(30)
        raise AssertionError("revocation should cancel the bounded runner call")

    monkeypatch.setattr(app.state, "active_nmap_basic_lifecycle_runner", slow_lifecycle, raising=False)
    monkeypatch.setattr(app.state, "active_nmap_basic_lifecycle_client", ActiveNmapBasicRouteNoLiveClient(), raising=False)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        asset = (
            await client.post(
                "/active/assets",
                json=_payload(
                    asset_type="ip",
                    value="127.0.0.1",
                    capabilities=["active_nmap_basic"],
                    allowed_ports=[443],
                    allowed_protocols=["tcp"],
                ),
            )
        ).json()
        execution = asyncio.create_task(
            client.post(
                f"/active/assets/{asset['id']}/executions",
                json={"capability": "active_nmap_basic", "authorization_reconfirmed": True, "idempotency_key": "9" * 32},
            )
        )
        await asyncio.wait_for(started.wait(), timeout=1)
        revoked = await client.post(
            f"/active/assets/{asset['id']}/revoke",
            json={"reason_code": "security_hold"},
        )
        assert revoked.status_code == 200
        result = await asyncio.wait_for(execution, timeout=2)
        assert result.status_code == 202
        assert result.json()["status"] == "queued"
        assert (await client.get(f"/jobs/{result.json()['id']}")).json()["status"] == "cancelled"
        assert result.json()["active_asset_id"] == asset["id"]
        assert app.state.active_asset_revocation_events == {}


@pytest.mark.anyio
async def test_revocation_cancels_an_admitted_standard_runner_operation(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)
    runner = SlowActiveCapabilityRunner()
    app.state.active_capability_runner = runner
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        asset = (await client.post("/active/assets", json=_payload())).json()
        execution = asyncio.create_task(
            client.post(
                f"/active/assets/{asset['id']}/executions",
                json={"capability": "active_dns_inventory", "authorization_reconfirmed": True, "idempotency_key": "a" * 32},
            )
        )
        await asyncio.wait_for(runner.started.wait(), timeout=1)
        revoked = await client.post(
            f"/active/assets/{asset['id']}/revoke",
            json={"reason_code": "security_hold"},
        )
        assert revoked.status_code == 200
        result = await asyncio.wait_for(execution, timeout=2)

    assert result.status_code == 202
    assert result.json()["status"] == "queued"
    persisted_job = app.state.jobs.get(result.json()["id"])
    assert persisted_job.status == "cancelled"
    assert result.json()["active_asset_id"] == asset["id"]
    assert result.json()["target_url"] == "[REDACTED_DOMAIN]"
    assert runner.cancelled.is_set()
    assert app.state.active_asset_revocation_events == {}
    persisted = "".join(path.read_text() for path in (tmp_path / "results" / "jobs").glob("*.json"))
    assert "example.test" not in persisted


@pytest.mark.anyio
async def test_active_posture_baseline_triage_and_report_are_owner_scoped_and_redacted(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        asset = (
            await client.post(
                "/active/assets",
                json=_payload(asset_type="ip", value="127.0.0.1", capabilities=["active_nmap_basic"], allowed_ports=[80, 443], allowed_protocols=["tcp"]),
            )
        ).json()
        base = app.state.jobs.create_active_nmap_basic_no_live_job(
            {"capability": "active_nmap_basic", "status": "completed", "port_observations": [{"port": 80, "protocol": "tcp", "state": "open"}], "limits": {}, "summary": {}},
            status="completed", owner_id="local-admin", active_asset_id=asset["id"], active_authorization_contract="2026-09-09.1",
        )
        target = app.state.jobs.create_active_nmap_basic_no_live_job(
            {"capability": "active_nmap_basic", "status": "completed", "port_observations": [{"port": 443, "protocol": "tcp", "state": "open"}], "limits": {}, "summary": {}},
            status="completed", owner_id="local-admin", active_asset_id=asset["id"], active_authorization_contract="2026-09-09.1",
        )
        baseline = await client.post(f"/active/assets/{asset['id']}/baseline", json={"execution_id": base.id, "baseline_confirmed": True})
        assert baseline.status_code == 200
        assert baseline.json()["baseline_execution_id"] == base.id

        posture = await client.get(f"/active/assets/{asset['id']}/posture")
        assert posture.status_code == 200
        comparison = posture.json()["posture"]["comparison"]
        assert comparison["base_execution_id"] == base.id
        assert comparison["target_execution_id"] == target.id
        assert {item["signal"] for item in comparison["changes"]} == {"tcp_port:80", "tcp_port:443"}

        triage = await client.post(f"/active/assets/{asset['id']}/triage", json={"observation_key": "tcp_port:443", "status": "expected_change", "comment_code": "planned_change"})
        assert triage.status_code == 200
        assert triage.json()["triage"][0]["observation_key"] == "tcp_port:443"
        assert "127.0.0.1" not in json.dumps(triage.json()["triage"])

        report = await client.get(f"/active/assets/{asset['id']}/report")
        assert report.status_code == 200
        assert report.headers["content-type"].startswith("text/markdown")
        assert "not a resolved-vulnerability claim" in report.text
        assert "confirmed vulnerabilities" in report.text
        assert "127.0.0.1" not in report.text
        assert "Exact target: withheld from export" in report.text
        assert "Current authorization revision: `r1`" in report.text


@pytest.mark.anyio
async def test_active_weekly_report_preflight_formats_staleness_and_redaction(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        asset = (
            await client.post(
                "/active/assets",
                json=_payload(
                    value="weekly-sensitive.example.test",
                    capabilities=["active_dns_inventory"],
                    notes=[{"kind": "scope_constraint", "value": "do-not-export-note"}],
                    authorization_reference="do-not-export-authorization-reference",
                ),
            )
        ).json()
        revision = asset["authorization_revisions"][-1]
        job, _ = app.state.jobs.create_active_asset_execution_job(
            "active_dns_inventory",
            owner_id="local-admin",
            active_asset_id=asset["id"],
            active_authorization_contract=asset["contract_version"],
            active_authorization_revision_id=revision["id"],
            active_authorization_revision_digest_sha256=revision["digest_sha256"],
            active_authorization_revision_sequence=revision["sequence"],
            active_execution_port=None,
            idempotency_key_sha256="9" * 64,
        )
        app.state.jobs.update(
            job.id,
            status="failed",
            error="redacted fixture failure",
            result={"raw_output": "do-not-export-runner-output"},
        )
        schedule, _ = app.state.active_recurrences.create(
            ActiveRecurrenceCreateRequest(
                capability="active_dns_inventory",
                interval_days=7,
                timezone_name="UTC",
                window_weekdays=list(ACTIVE_RECURRENCE_WEEKDAYS),
                window_start_hour=0,
                window_duration_hours=12,
                recurrence_confirmed=True,
                idempotency_key="8" * 32,
            ),
            organization_id="local-admin",
            asset_id=asset["id"],
            actor_id="local-admin",
            actor_role="administrator",
            authorization_revision_id=revision["id"],
            authorization_revision_digest_sha256=revision["digest_sha256"],
            authorization_revision_sequence=revision["sequence"],
            authorization_expires_at=datetime.fromisoformat(revision["expires_at"]),
            verification_id="7" * 32,
        )
        app.state.active_recurrences.pause(
            schedule.id,
            organization_id="local-admin",
            asset_id=asset["id"],
            expected_updated_at=schedule.updated_at,
        )

        preflight_response = await client.get(
            "/active/operations/weekly-report/preflight", params={"period": "7d"}
        )
        assert preflight_response.status_code == 200
        preflight = preflight_response.json()
        assert preflight["state"] == "ready"
        assert preflight["assets_total"] == preflight["assets_included"] == 1
        assert preflight["actions_total"] == preflight["actions_included"] == 1
        assert preflight["recurrence_attention_total"] == 1
        assert preflight["privacy"]["exact_targets_included"] is True
        assert preflight_response.headers["cache-control"] == "private, no-store"
        assert "weekly-sensitive.example.test" not in preflight_response.text

        payload = {
            "period": "7d",
            "state_at": preflight["state_at"],
            "snapshot_digest": preflight["snapshot_digest"],
            "sensitive_targets_confirmed": True,
        }
        json_report = await client.post(
            "/active/operations/weekly-report",
            json=payload | {"report_format": "json"},
        )
        markdown_report = await client.post(
            "/active/operations/weekly-report",
            json=payload | {"report_format": "markdown"},
        )
        assert json_report.status_code == markdown_report.status_code == 200
        assert json_report.json()["snapshot_digest"] == preflight["snapshot_digest"]
        assert json_report.headers["x-inspectra-snapshot-sha256"] == preflight["snapshot_digest"]
        assert markdown_report.headers["x-inspectra-snapshot-sha256"] == preflight["snapshot_digest"]
        assert json_report.headers["cache-control"] == "private, no-store"
        assert "weekly-sensitive.example.test" in json_report.text
        assert "weekly-sensitive.example.test" in markdown_report.text
        assert "## Recent execution window" in markdown_report.text
        assert "- Failed: 1." in markdown_report.text
        assert "## Comparable changes" in markdown_report.text
        assert "- Assets compared: 0." in markdown_report.text
        assert json_report.json()["execution_window"]["counts"]["failed"] == 1
        assert json_report.json()["changes"]["assets_compared"] == 0
        combined = json_report.text + markdown_report.text
        for forbidden in (
            "do-not-export-note",
            "do-not-export-authorization-reference",
            "do-not-export-runner-output",
            revision["digest_sha256"],
            "redacted fixture failure",
        ):
            assert forbidden not in combined
        export_events = [
            event
            for event in app.state.product_audit.list("local-admin", limit=20).items
            if event.action == "active_asset.weekly_report_exported"
        ]
        assert len(export_events) == 2
        assert {tuple(sorted(event.metadata.items())) for event in export_events} == {
            (("report_format", "json"), ("review_period", "7d")),
            (("report_format", "markdown"), ("review_period", "7d")),
        }
        assert "weekly-sensitive.example.test" not in str(export_events)
        assert "do-not-export" not in str(export_events)
        assert (await client.post(
            "/active/operations/weekly-report",
            json=payload | {"report_format": "json", "sensitive_targets_confirmed": False},
        )).status_code == 422

        app.state.active_assets.revoke(
            asset["id"],
            organization_id="local-admin",
            actor_id="local-admin",
            reason_code="security_hold",
        )
        stale = await client.post(
            "/active/operations/weekly-report",
            json=payload | {"report_format": "json"},
        )
        assert stale.status_code == 409
        assert "weekly-sensitive.example.test" not in stale.text
        expired_preflight = await client.post(
            "/active/operations/weekly-report",
            json=payload | {
                "report_format": "json",
                "state_at": (datetime.now(timezone.utc) - timedelta(minutes=6)).isoformat(),
            },
        )
        assert expired_preflight.status_code == 409
        assert "preflight expired" in expired_preflight.json()["detail"]


@pytest.mark.anyio
async def test_active_execution_history_pages_and_resolves_an_old_baseline_owner_scoped(
    monkeypatch, tmp_path
):
    _configure(monkeypatch, tmp_path)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        asset = (
            await client.post(
                "/active/assets",
                json=_payload(value="history-page.example.test", capabilities=["active_dns_inventory"]),
            )
        ).json()
        revision = asset["authorization_revisions"][-1]
        created = []
        for index in range(505):
            job, _ = app.state.jobs.create_active_asset_execution_job(
                "active_dns_inventory",
                owner_id="local-admin",
                active_asset_id=asset["id"],
                active_authorization_contract=asset["contract_version"],
                active_authorization_revision_id=revision["id"],
                active_authorization_revision_digest_sha256=revision["digest_sha256"],
                active_authorization_revision_sequence=revision["sequence"],
                active_execution_port=None,
                idempotency_key_sha256=f"{index + 1:064x}",
            )
            created.append(
                app.state.jobs.update(
                    job.id,
                    status="completed",
                    active_execution_phase="terminal",
                    result={"status": "best_effort_inventory", "records": {}},
                )
            )
        baseline = await client.post(
            f"/active/assets/{asset['id']}/baseline",
            json={"execution_id": created[0].id, "baseline_confirmed": True},
        )
        posture = await client.get(f"/active/assets/{asset['id']}/posture")
        first = posture.json()
        assert posture.status_code == 200
        assert len(first["executions"]) == 50
        assert first["history"] == {
            "returned_count": 50,
            "total_count": 505,
            "has_more": True,
            "next_cursor": first["history"]["next_cursor"],
            "posture_records_considered": 501,
            "posture_incomplete": True,
        }
        assert first["history"]["next_cursor"]
        assert first["baseline_execution"]["id"] == created[0].id
        assert baseline.status_code == 200

        first_cursor = first["history"]["next_cursor"]
        all_items = list(first["executions"])
        cursor = first_cursor
        page_sizes = []
        while cursor is not None:
            page = await client.post(
                f"/active/assets/{asset['id']}/executions/search",
                json={"page_size": 50, "cursor": cursor},
            )
            assert page.status_code == 200
            page_payload = page.json()
            assert page_payload["total_count"] == 505
            page_sizes.append(len(page_payload["items"]))
            all_items.extend(page_payload["items"])
            cursor = page_payload["next_cursor"]
        direct = await client.get(
            f"/active/assets/{asset['id']}/executions/{created[0].id}"
        )
        report = await client.get(f"/active/assets/{asset['id']}/report")
        evidence = await client.get(
            f"/active/assets/{asset['id']}/evidence-bundle?period=all"
        )
        other = (
            await client.post(
                "/active/assets",
                json=_payload(value="history-other.example.test", capabilities=["active_dns_inventory"]),
            )
        ).json()
        rebound = await client.post(
            f"/active/assets/{other['id']}/executions/search",
            json={"page_size": 50, "cursor": first_cursor},
        )
        tampered_cursor = first_cursor[:-1] + ("A" if first_cursor[-1] != "A" else "B")
        tampered = await client.post(
            f"/active/assets/{asset['id']}/executions/search",
            json={"page_size": 50, "cursor": tampered_cursor},
        )
        foreign = await client.get(
            f"/active/assets/{other['id']}/executions/{created[0].id}"
        )

    assert direct.status_code == report.status_code == evidence.status_code == 200
    assert page_sizes == [50] * 9 + [5]
    all_ids = {item["id"] for item in all_items}
    assert len(all_ids) == 505
    assert direct.json()["id"] == created[0].id
    assert "result" not in direct.json()
    assert "Executions retained: 505" in report.text
    with tarfile.open(fileobj=BytesIO(evidence.content), mode="r:") as archive:
        manifest = json.loads(archive.extractfile("manifest.json").read())
    assert manifest["scope"]["execution_records_in_period"] == 505
    assert manifest["scope"]["execution_records_included"] == 100
    assert manifest["scope"]["execution_records_truncated"] is True
    assert manifest["scope"]["source_selection_incomplete"] is False
    assert rebound.status_code == 400
    assert tampered.status_code == 400
    assert foreign.status_code == 404


@pytest.mark.anyio
async def test_active_evidence_bundle_is_deterministic_bounded_owner_scoped_and_redacted(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)
    target_canary = "evidence-target-canary.example.test"
    reference_canary = "case-sensitive-private-reference"
    note_canary = "private-note-canary"
    raw_canary = "raw-runner-secret-canary"
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        created = await client.post(
            "/active/assets",
            json=_payload(
                value=target_canary,
                authorization_reference=reference_canary,
                notes=[{"kind": "scope_constraint", "value": note_canary}],
                capabilities=["active_dns_inventory"],
            ),
        )
        assert created.status_code == 201
        asset = created.json()
        revision = asset["authorization_revisions"][-1]
        job, _ = app.state.jobs.create_active_asset_execution_job(
            "active_dns_inventory",
            owner_id="local-admin",
            active_asset_id=asset["id"],
            active_authorization_contract=asset["contract_version"],
            active_authorization_revision_id=revision["id"],
            active_authorization_revision_digest_sha256=revision["digest_sha256"],
            active_authorization_revision_sequence=revision["sequence"],
            active_execution_port=None,
            idempotency_key_sha256="9" * 64,
        )
        app.state.jobs.update(
            job.id,
            status="completed",
            active_execution_phase="terminal",
            result={
                "status": "best_effort_inventory",
                "records": {"A": {"count": 2}},
                "security_records": {"dmarc": {"present": True}},
                "raw_output": raw_canary,
                "target": target_canary,
            },
        )

        first = await client.get(f"/active/assets/{asset['id']}/evidence-bundle?period=all")
        second = await client.get(f"/active/assets/{asset['id']}/evidence-bundle?period=all")
        invalid_period = await client.get(f"/active/assets/{asset['id']}/evidence-bundle?period=7d")

        other = app.state.active_assets.create(
            ActiveAssetCreateRequest.model_validate(
                _payload(value="other-owner.example.test", responsible_user_ids=[], notes=[])
            ),
            organization_id="b" * 32,
            actor_id="b" * 32,
        )
        denied = await client.get(f"/active/assets/{other.id}/evidence-bundle")

    assert first.status_code == second.status_code == 200
    assert first.content == second.content
    assert first.headers["content-type"].startswith("application/x-tar")
    assert first.headers["cache-control"] == "private, no-store"
    assert first.headers["x-content-type-options"] == "nosniff"
    assert first.headers["x-inspectra-evidence-sha256"] == hashlib.sha256(first.content).hexdigest()
    validated = validate_active_evidence_bundle(first.content)
    assert validated == {
        "valid": True,
        "contract_version": ACTIVE_EVIDENCE_BUNDLE_CONTRACT_VERSION,
        "bundle_sha256": hashlib.sha256(first.content).hexdigest(),
        "asset_reference": f"active-{asset['id'][:12]}",
        "state_at": validated["state_at"],
        "entries": 6,
    }
    with tarfile.open(fileobj=BytesIO(first.content), mode="r:") as archive:
        assert archive.getnames() == [
            "manifest.json", "active-asset.json", "executions.json", "posture.json", "report.md", "SHA256SUMS"
        ]
        extracted = {member.name: archive.extractfile(member).read() for member in archive.getmembers()}
    manifest = json.loads(extracted["manifest.json"])
    assert manifest["period"]["kind"] == "all"
    assert manifest["scope"]["execution_records_included"] == 1
    assert set(manifest["privacy"].values()) == {False}
    execution = json.loads(extracted["executions.json"])["items"][0]
    assert execution["observation"]["signals"] == {
        "dns_count:A": 2,
        "dns_indicator:dmarc": True,
    }
    assert execution["raw_result_included"] is False
    combined = b"\n".join(extracted.values()).decode("utf-8")
    for forbidden in (target_canary, reference_canary, note_canary, raw_canary, "local-admin"):
        assert forbidden not in combined
    assert invalid_period.status_code == 422
    assert denied.status_code == 404
    exports = [event for event in app.state.product_audit.list("local-admin", limit=20).items if event.action == "active_asset.evidence_bundle_exported"]
    assert len(exports) == 2
    assert all(event.metadata == {"report_format": "active_evidence_tar"} for event in exports)


@pytest.mark.anyio
async def test_active_audit_export_preflight_json_csv_are_scoped_bounded_and_target_free(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)
    target_canary = "audit-export-target.example.test"
    reference_canary = "audit-export-private-reference"
    note_canary = "audit-export-private-note"
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        created = await client.post(
            "/active/assets",
            json=_payload(
                value=target_canary,
                authorization_reference=reference_canary,
                notes=[{"kind": "scope_constraint", "value": note_canary}],
                capabilities=["active_dns_inventory"],
            ),
        )
        assert created.status_code == 201
        asset = created.json()
        other = app.state.active_assets.create(
            ActiveAssetCreateRequest.model_validate(
                _payload(value="other-audit-owner.example.test", responsible_user_ids=[], notes=[])
            ),
            organization_id="b" * 32,
            actor_id="b" * 32,
        )

        preflight = await client.get(
            "/audit/active-export/preflight",
            params={"period": "30d", "asset_id": asset["id"]},
        )
        exported_json = await client.get(
            "/audit/active-export",
            params={"period": "30d", "asset_id": asset["id"], "format": "json"},
        )
        exported_csv = await client.get(
            "/audit/active-export",
            params={"period": "30d", "asset_id": asset["id"], "format": "csv"},
        )
        denied = await client.get(
            "/audit/active-export/preflight",
            params={"asset_id": other.id},
        )
        invalid_period = await client.get("/audit/active-export/preflight", params={"period": "all"})
        invalid_format = await client.get("/audit/active-export", params={"format": "xml"})

    assert preflight.status_code == 200
    assert preflight.json()["state"] == "ready"
    assert preflight.json()["asset_filter_applied"] is True
    assert preflight.json()["total_events"] == preflight.json()["included_events"] == 1
    assert preflight.json()["truncated"] is False
    assert set(preflight.json()["privacy"].values()) == {False}

    assert exported_json.status_code == 200
    assert exported_json.headers["cache-control"] == "private, no-store"
    assert exported_json.headers["content-disposition"] == 'attachment; filename="inspectra-active-audit.json"'
    document = exported_json.json()
    assert document["contract_version"] == "2026-09-08.1"
    assert len(document["events"]) == 1
    event = document["events"][0]
    assert event["action"] == "active_asset.registered"
    assert event["authorization_revision_id"] == asset["authorization_revisions"][0]["id"]
    assert event["authorization_revision_sequence"] == 1
    assert event["actor_reference"].startswith("actor-")
    assert event["resource_reference"].startswith("resource-")

    assert exported_csv.status_code == 200
    assert exported_csv.headers["content-type"].startswith("text/csv")
    csv_lines = exported_csv.text.splitlines()
    assert csv_lines[0].startswith("record_type,contract_version,period")
    assert csv_lines[1].startswith("manifest,2026-09-08.1,30d")
    assert any("active_asset.registered" in line for line in csv_lines[2:])
    assert any("active_asset.audit_exported" in line for line in csv_lines[2:])

    combined = exported_json.content + exported_csv.content
    for forbidden in (target_canary, reference_canary, note_canary, asset["id"], "local-admin"):
        assert forbidden.encode() not in combined
    assert denied.status_code == 404
    assert invalid_period.status_code == invalid_format.status_code == 422
    audit_exports = [event for event in app.state.product_audit.list("local-admin", limit=20).items if event.action == "active_asset.audit_exported"]
    assert len(audit_exports) == 2
    assert {event.metadata["report_format"] for event in audit_exports} == {"json", "csv"}


def test_active_evidence_bundle_limits_history_detects_tampering_and_validates_offline(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)
    asset = app.state.active_assets.create(
        ActiveAssetCreateRequest.model_validate(
            _payload(value="bundle-limit.example.test", capabilities=["active_dns_inventory"], notes=[])
        ),
        organization_id="local-admin",
        actor_id="local-admin",
    )
    revision = asset.authorization_revisions[-1]
    original, _ = app.state.jobs.create_active_asset_execution_job(
        "active_dns_inventory",
        owner_id="local-admin",
        active_asset_id=asset.id,
        active_authorization_contract=asset.contract_version,
        active_authorization_revision_id=revision.id,
        active_authorization_revision_digest_sha256=revision.digest_sha256,
        active_authorization_revision_sequence=revision.sequence,
        active_execution_port=None,
        idempotency_key_sha256="a" * 64,
    )
    original = app.state.jobs.update(
        original.id,
        status="completed",
        active_execution_phase="terminal",
        result={"status": "best_effort_inventory", "records": {}},
    )
    jobs = [
        original.model_copy(
            update={
                "id": f"{index:032x}",
                "created_at": original.created_at + timedelta(seconds=index),
                "updated_at": original.updated_at + timedelta(seconds=index),
                "finished_at": original.finished_at + timedelta(seconds=index),
            }
        )
        for index in range(1, ACTIVE_EVIDENCE_BUNDLE_MAX_EXECUTIONS + 3)
    ]
    jobs[-1] = jobs[-1].model_copy(
        update={
            "audit_type": "active_tls_basic",
            "result": {
                "result_status": "handshake_succeeded",
                "handshake": {"protocol": "protocol-secret-canary"},
                "certificate": {"available": True, "days_until_expiry": 20},
            },
        }
    )
    jobs[-2] = jobs[-2].model_copy(
        update={
            "audit_type": "active_http_basic_header_review",
            "result": {
                "result_status": "observed",
                "header_indicators": {"hsts_present": True, "secret-header-canary": True},
            },
        }
    )
    bundle = build_active_evidence_bundle(asset, jobs, period="all", source_selection_incomplete=True)
    with tarfile.open(fileobj=BytesIO(bundle.payload), mode="r:") as archive:
        manifest = json.loads(archive.extractfile("manifest.json").read())
        executions = json.loads(archive.extractfile("executions.json").read())
    assert manifest["scope"]["execution_records_in_period"] == ACTIVE_EVIDENCE_BUNDLE_MAX_EXECUTIONS + 2
    assert manifest["scope"]["execution_records_truncated"] is True
    assert manifest["scope"]["source_selection_incomplete"] is True
    assert len(executions["items"]) == ACTIVE_EVIDENCE_BUNDLE_MAX_EXECUTIONS
    assert executions["source_selection_incomplete"] is True
    assert b"protocol-secret-canary" not in bundle.payload
    assert b"secret-header-canary" not in bundle.payload
    assert b"http_header:hsts_present" in bundle.payload

    tampered = bytearray(bundle.payload)
    marker = b"bounded observations"
    offset = tampered.find(marker)
    assert offset >= 0
    tampered[offset : offset + len(marker)] = b"X" * len(marker)
    with pytest.raises(ActiveEvidenceBundleError, match="checksum_mismatch"):
        validate_active_evidence_bundle(bytes(tampered))

    bundle_path = tmp_path / "active-evidence.tar"
    bundle_path.write_bytes(bundle.payload)
    environment = {**os.environ, "PYTHONPATH": str((Path(__file__).parents[1]).resolve())}
    process = subprocess.run(
        [sys.executable, "-m", "app.active_evidence_bundle", str(bundle_path)],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
        timeout=10,
    )
    assert process.returncode == 0, process.stderr
    assert json.loads(process.stdout)["bundle_sha256"] == bundle.sha256


@pytest.mark.anyio
async def test_active_verification_is_disabled_by_default_without_persisting_a_challenge(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        asset = (await client.post("/active/assets", json=_payload())).json()
        configuration = await client.get("/active/verification/configuration")
        assert configuration.status_code == 200
        assert configuration.json()["enabled"] is False
        response = await client.post(
            f"/active/assets/{asset['id']}/verification/challenge",
            json={"method": "manual_attestation", "valid_for_days": 30, "control_check_confirmed": True},
        )
    assert response.status_code == 403
    assert list((tmp_path / "results" / "active_asset_verifications").glob("**/*.json")) == []


@pytest.mark.anyio
async def test_remote_verification_requires_both_backend_and_isolated_runner_gates(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path, verification_enabled=True)

    async def runner_gate_disabled(_base_url, *, timeout_seconds):
        health = await healthy_active_tools(_base_url, timeout_seconds=timeout_seconds)
        health["capabilities"]["active_asset_verification"]["execution_enabled"] = False
        return health

    app.state.active_tools_health_checker = runner_gate_disabled
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        asset = (await client.post("/active/assets", json=_payload())).json()
        configuration = await client.get("/active/verification/configuration")
        rejected = await client.post(
            f"/active/assets/{asset['id']}/verification/challenge",
            json={"method": "dns_txt", "control_check_confirmed": True},
        )

    assert configuration.json()["methods"] == {
        "manual_attestation": True,
        "dns_txt": False,
        "http_well_known": False,
        "managed_private": False,
    }
    assert rejected.status_code == 503
    assert rejected.json() == {"detail": "Isolated Active verification is temporarily unavailable."}
    assert list((tmp_path / "results" / "active_asset_verifications").glob("**/*.json")) == []


@pytest.mark.anyio
async def test_verification_revocation_cancels_isolated_runner_and_discards_token(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path, verification_enabled=True)
    runner = SlowVerificationRunner()
    app.state.active_asset_verification_runner = runner
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        asset = (await client.post("/active/assets", json=_payload())).json()
        challenge = (await client.post(
            f"/active/assets/{asset['id']}/verification/challenge",
            json={"method": "dns_txt", "control_check_confirmed": True},
        )).json()
        check_task = asyncio.create_task(client.post(
            f"/active/assets/{asset['id']}/verification/check",
            json={"verification_id": challenge["verification"]["id"], "challenge_token": challenge["challenge_token"]},
        ))
        await asyncio.wait_for(runner.started.wait(), timeout=1)
        revoked = await client.post(
            f"/active/assets/{asset['id']}/verification/revoke",
            json={"verification_id": challenge["verification"]["id"], "revocation_confirmed": True},
        )
        checked = await asyncio.wait_for(check_task, timeout=2)

    assert revoked.status_code == 200
    assert revoked.json()["status"] == "revoked"
    assert checked.status_code == 409
    assert runner.cancelled.is_set()
    persisted = "".join(path.read_text() for path in tmp_path.rglob("*.json"))
    assert challenge["challenge_token"] not in persisted


@pytest.mark.anyio
async def test_manual_verification_is_one_time_expiring_revocable_and_never_persists_token(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path, verification_enabled=True)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        asset = (await client.post("/active/assets", json=_payload())).json()
        started = await client.post(
            f"/active/assets/{asset['id']}/verification/challenge",
            json={"method": "manual_attestation", "valid_for_days": 30, "control_check_confirmed": True},
        )
        assert started.status_code == 201
        challenge = started.json()
        token = challenge["challenge_token"]
        assert challenge["one_time_display"] is True
        assert challenge["legal_authorization_established"] is False
        persisted = next((tmp_path / "results" / "active_asset_verifications").glob("**/*.json")).read_text()
        assert token not in persisted
        assert "challenge_sha256" in persisted

        completed = await client.post(
            f"/active/assets/{asset['id']}/verification/check",
            json={"verification_id": challenge["verification"]["id"], "challenge_token": token, "manual_attestation_confirmed": True},
        )
        assert completed.status_code == 200
        assert completed.json()["status"] == "verified"
        assert "challenge_sha256" not in completed.text
        assert datetime.fromisoformat(completed.json()["verification_expires_at"]) <= datetime.fromisoformat(asset["expires_at"])

        replay = await client.post(
            f"/active/assets/{asset['id']}/verification/check",
            json={"verification_id": challenge["verification"]["id"], "challenge_token": token, "manual_attestation_confirmed": True},
        )
        assert replay.status_code == 409
        revoked = await client.post(
            f"/active/assets/{asset['id']}/verification/revoke",
            json={"verification_id": challenge["verification"]["id"], "revocation_confirmed": True},
        )
        assert revoked.status_code == 200
        assert revoked.json()["status"] == "revoked"
        latest = await client.get(f"/active/assets/{asset['id']}/verification")
        assert latest.json()["status"] == "revoked"
        assert token not in json.dumps((await client.get(f"/active/assets/{asset['id']}")).json())


@pytest.mark.anyio
async def test_active_recurrence_api_requires_current_verification_and_exposes_no_sensitive_scope(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_ACTIVE_RECURRENCE_ENABLED", "true")
    _configure(monkeypatch, tmp_path, verification_enabled=True)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        asset = (await client.post(
            "/active/assets",
            json=_payload(value="recurring-api.example.test", capabilities=["active_dns_inventory"], notes=[]),
        )).json()
        recurrence_payload = {
            "capability": "active_dns_inventory",
            "interval_days": 7,
            "timezone_name": "Europe/Madrid",
            "window_weekdays": ["monday", "wednesday", "friday"],
            "window_start_hour": 9,
            "window_duration_hours": 4,
            "recurrence_confirmed": True,
            "idempotency_key": "9" * 32,
        }
        blocked = await client.post(f"/active/assets/{asset['id']}/recurrences", json=recurrence_payload)
        assert blocked.status_code == 409

        challenge = (await client.post(
            f"/active/assets/{asset['id']}/verification/challenge",
            json={"method": "manual_attestation", "valid_for_days": 30, "control_check_confirmed": True},
        )).json()
        verified = await client.post(
            f"/active/assets/{asset['id']}/verification/check",
            json={
                "verification_id": challenge["verification"]["id"],
                "challenge_token": challenge["challenge_token"],
                "manual_attestation_confirmed": True,
            },
        )
        assert verified.status_code == 200

        created = await client.post(f"/active/assets/{asset['id']}/recurrences", json=recurrence_payload)
        assert created.status_code == 201, created.text
        schedule = created.json()
        public_text = created.text
        assert "organization_id" not in schedule and "actor_id" not in schedule
        assert "authorization_revision_digest_sha256" not in schedule
        assert "recurring-api.example.test" not in public_text
        assert schedule["status"] == "active" and schedule["interval_days"] == 7

        listed = await client.get(f"/active/assets/{asset['id']}/recurrences")
        assert listed.status_code == 200
        assert listed.json()["enabled"] is True
        assert [item["id"] for item in listed.json()["items"]] == [schedule["id"]]
        renewed = await client.post(f"/active/assets/{asset['id']}/renew", json=_renewal_payload(asset))
        assert renewed.status_code == 200
        suspended = (await client.get(f"/active/assets/{asset['id']}/recurrences")).json()["items"][0]
        assert suspended["status"] == "suspended"
        assert suspended["reason_code"] == "authorization_revision_changed"
        rebound = await client.post(
            f"/active/assets/{asset['id']}/recurrences/{schedule['id']}/resume",
            json={"expected_updated_at": suspended["updated_at"]},
        )
        assert rebound.status_code == 200
        assert rebound.json()["authorization_revision_sequence"] == 2
        schedule = rebound.json()
        paused = await client.post(
            f"/active/assets/{asset['id']}/recurrences/{schedule['id']}/pause",
            json={"expected_updated_at": schedule["updated_at"]},
        )
        assert paused.status_code == 200 and paused.json()["status"] == "paused"
        resumed = await client.post(
            f"/active/assets/{asset['id']}/recurrences/{schedule['id']}/resume",
            json={"expected_updated_at": paused.json()["updated_at"]},
        )
        assert resumed.status_code == 200 and resumed.json()["status"] == "active"
        deleted = await client.request(
            "DELETE",
            f"/active/assets/{asset['id']}/recurrences/{schedule['id']}",
            json={"confirmation": "DELETE ACTIVE SCHEDULE"},
        )
        assert deleted.status_code == 204
        assert (await client.get(f"/active/assets/{asset['id']}/recurrences")).json()["items"] == []

    persisted = "\n".join(path.read_text(encoding="utf-8") for path in tmp_path.rglob("*.json"))
    assert challenge["challenge_token"] not in persisted


@pytest.mark.anyio
async def test_dns_and_http_verification_use_only_fixed_asset_derived_destinations(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path, verification_enabled=True)
    transport = FakeVerificationTransport()
    app.state.active_asset_verification_transport = transport
    app.state.active_asset_verification_runner = transport
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        dns_asset = (await client.post("/active/assets", json=_payload())).json()
        dns_started = (await client.post(
            f"/active/assets/{dns_asset['id']}/verification/challenge",
            json={"method": "dns_txt", "control_check_confirmed": True},
        )).json()
        bad_token = "iv1_" + "z" * 32
        rejected = await client.post(
            f"/active/assets/{dns_asset['id']}/verification/check",
            json={"verification_id": dns_started["verification"]["id"], "challenge_token": bad_token},
        )
        assert rejected.status_code == 422
        assert transport.calls == []
        dns_checked = await client.post(
            f"/active/assets/{dns_asset['id']}/verification/check",
            json={"verification_id": dns_started["verification"]["id"], "challenge_token": dns_started["challenge_token"]},
        )
        assert dns_checked.status_code == 200
        assert transport.calls[0][:2] == ("dns_txt", "_inspectra-verification.example.test")

        http_asset = (await client.post(
            "/active/assets",
            json=_payload(
                asset_type="http_origin",
                value="https://portal.example.test",
                capabilities=["active_http_basic_header_review"],
                allowed_protocols=["https"],
            ),
        )).json()
        http_started = (await client.post(
            f"/active/assets/{http_asset['id']}/verification/challenge",
            json={"method": "http_well_known", "control_check_confirmed": True},
        )).json()
        http_checked = await client.post(
            f"/active/assets/{http_asset['id']}/verification/check",
            json={"verification_id": http_started["verification"]["id"], "challenge_token": http_started["challenge_token"]},
        )
        assert http_checked.status_code == 200
        assert transport.calls[1][:2] == ("http_well_known", "https://portal.example.test")
        persisted = "".join(path.read_text() for path in (tmp_path / "results" / "active_asset_verifications").glob("**/*.json"))
        assert "portal.example.test" not in persisted
        assert dns_started["challenge_token"] not in persisted
        assert http_started["challenge_token"] not in persisted


def test_verification_store_is_owner_scoped_materializes_expiry_and_rejects_incompatible_method(monkeypatch, tmp_path):
    settings = _configure(monkeypatch, tmp_path, verification_enabled=True)
    now = datetime.now(timezone.utc)
    mutable_now = [now]
    assets = ActiveAssetStore(settings, now_func=lambda: mutable_now[0])
    verifications = ActiveAssetVerificationStore(settings, now_func=lambda: mutable_now[0])
    organization_a = "a" * 32
    organization_b = "b" * 32
    asset = assets.create(ActiveAssetCreateRequest.model_validate(_payload()), organization_id=organization_a, actor_id=organization_a)
    record, token = verifications.start(
        asset,
        ActiveAssetVerificationStartRequest(method="dns_txt", control_check_confirmed=True),
        organization_id=organization_a,
        actor_id=organization_a,
    )
    assert token not in record.model_dump_json()
    with pytest.raises(Exception, match="verification_not_found"):
        verifications.get(record.id, asset_id=asset.id, organization_id=organization_b)
    mutable_now[0] = record.challenge_expires_at + timedelta(seconds=1)
    assert verifications.get(record.id, asset_id=asset.id, organization_id=organization_a).status == "expired"

    ip_asset = assets.create(
        ActiveAssetCreateRequest.model_validate(_payload(asset_type="ip", value="127.0.0.1", capabilities=["active_nmap_basic"], allowed_ports=[443], allowed_protocols=["tcp"])),
        organization_id=organization_a,
        actor_id=organization_a,
    )
    with pytest.raises(Exception, match="verification_method_incompatible"):
        verifications.start(
            ip_asset,
            ActiveAssetVerificationStartRequest(method="http_well_known", control_check_confirmed=True),
            organization_id=organization_a,
            actor_id=organization_a,
        )


@pytest.mark.anyio
async def test_active_operations_summary_is_owner_scoped_bounded_and_actionable(monkeypatch, tmp_path):
    settings = _configure(monkeypatch, tmp_path, verification_enabled=True)
    other_organization = "b" * 32
    app.state.active_assets.create(
        ActiveAssetCreateRequest.model_validate(_payload(value="private-other.test")),
        organization_id=other_organization,
        actor_id=other_organization,
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        asset = (await client.post(
            "/active/assets",
            json=_payload(asset_type="ip", value="127.0.0.1", capabilities=["active_nmap_basic"], allowed_ports=[80, 443], allowed_protocols=["tcp"]),
        )).json()
        app.state.jobs.create_active_nmap_basic_no_live_job(
            {"capability": "active_nmap_basic", "status": "completed", "port_observations": [{"port": 80, "protocol": "tcp", "state": "open"}], "limits": {}, "summary": {}},
            status="completed", owner_id="local-admin", active_asset_id=asset["id"], active_authorization_contract="2026-09-09.1",
        )
        app.state.jobs.create_active_nmap_basic_no_live_job(
            {"capability": "active_nmap_basic", "status": "completed", "port_observations": [{"port": 443, "protocol": "tcp", "state": "open"}], "limits": {}, "summary": {}},
            status="completed", owner_id="local-admin", active_asset_id=asset["id"], active_authorization_contract="2026-09-09.1",
        )
        app.state.jobs.create_active_nmap_basic_no_live_job(
            {"capability": "active_nmap_basic", "status": "failed", "port_observations": [], "limits": {}, "summary": {}},
            status="failed", owner_id="local-admin", active_asset_id=asset["id"], active_authorization_contract="2026-09-09.1",
        )
        summary = await client.get("/active/operations/summary")
    assert summary.status_code == 200
    payload = summary.json()
    assert payload["assets"] == {"total": 1, "active": 1, "expired": 0, "revoked": 0, "expiring_14_days": 0, "duplicate_identity_groups": 0, "duplicate_identity_records": 0}
    assert payload["jobs"]["total"] == 3
    assert payload["jobs"]["failed"] == 1
    assert payload["actions"]["total"] >= 1
    assert payload["contract_version"] == "2026-09-09.4"
    assert payload["action_queue"]["returned"] == payload["action_queue"]["total"]
    assert payload["action_queue"]["source_incomplete"] is False
    failed_action = next(item for item in payload["action_queue"]["items"] if item["kind"] == "execution_failed")
    assert failed_action["asset_id"] == asset["id"]
    assert failed_action["action_code"] == "retry_execution"
    assert set(failed_action) == {"id", "kind", "urgency", "action_code", "asset_id", "job_id", "reference_at", "due_at", "occurrence_count"}
    assert payload["configuration"] == {"verification_enabled": True, "recurrence_enabled": False, "four_eyes_enabled": False, "legacy_free_targets_enabled": False, "all_live_capabilities_disabled": False}
    assert payload["limits"]["incomplete"] is False
    assert payload["limits"]["selection_strategy"] == "priority_then_recency"
    assert payload["limits"]["priority_candidates"] == 1
    serialized = json.dumps(payload)
    assert "127.0.0.1" not in serialized
    assert "private-other.test" not in serialized


@pytest.mark.anyio
async def test_active_operations_summary_reports_effective_runner_state_and_degrades_without_failing_assets(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)
    app.state.settings = app.state.settings.__class__(
        **{**app.state.settings.__dict__, "active_tools_url": "http://active-tools:8080", "active_tools_health_timeout_seconds": 7.0}
    )
    asset = app.state.active_assets.create(
        ActiveAssetCreateRequest.model_validate(_payload()),
        organization_id="local-admin",
        actor_id="local-admin",
    )
    calls = []

    async def disabled_runner(_base_url, *, timeout_seconds):
        calls.append(timeout_seconds)
        return {
            "available": True,
            "error_code": None,
            "capabilities": {
                capability: {
                    "status": "disabled_no_scan",
                    "execution_enabled": False,
                    "target_input_allowed": False,
                }
                for capability in (
                    "active_dns_inventory",
                    "active_dns_osint",
                    "active_http_basic_header_review",
                    "active_nmap_basic",
                    "active_tls_basic",
                )
            },
        }

    app.state.active_tools_health_checker = disabled_runner
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        degraded = await client.get("/active/operations/summary")
        asset_response = await client.get(f"/active/assets/{asset.id}")

        async def failed_checker(*_args, **_kwargs):
            raise RuntimeError("sensitive internal topology should not escape")

        app.state.active_tools_health_checker = failed_checker
        unavailable = await client.get("/active/operations/summary")

    assert calls == [2.0]
    assert degraded.status_code == 200
    dns = next(item for item in degraded.json()["capabilities"] if item["capability"] == "active_dns_inventory")
    assert dns["readiness"] == "degraded"
    assert dns["reason_code"] == "runner_gate_disabled"
    assert dns["backend_enabled"] is True and dns["runner_enabled"] is False and dns["enabled"] is False
    assert asset_response.status_code == 200
    unavailable_dns = next(item for item in unavailable.json()["capabilities"] if item["capability"] == "active_dns_inventory")
    assert unavailable_dns["readiness"] == "unavailable"
    assert unavailable_dns["reason_code"] == "runner_unavailable"
    serialized = degraded.text + unavailable.text
    assert "active-tools:8080" not in serialized
    assert "sensitive internal topology" not in serialized


def test_active_asset_batch_parser_reports_invalid_duplicate_and_existing_rows(monkeypatch, tmp_path):
    settings = _configure(monkeypatch, tmp_path)
    source = json.dumps(
        [
            _payload(value="Batch-One.Example.Test.", responsible_user_ids=["local-admin"], capabilities=["active_dns_inventory"], allowed_protocols=["dns"], notes=[]),
            _payload(value="batch-one.example.test", responsible_user_ids=["local-admin"], capabilities=["active_dns_inventory"], allowed_protocols=["dns"], notes=[]),
            {"asset_type": "domain", "value": "missing-contract.example.test"},
        ]
    ).encode("utf-8")
    parsed = parse_active_asset_batch(source, "authorized-assets.json")
    assert [row.status for row in parsed.rows] == ["ready", "duplicate_in_batch", "invalid"]
    assert parsed.rows[0].request is not None and parsed.rows[0].request.value == "batch-one.example.test"
    assert parsed.rows[2].request is None

    existing = ActiveAssetStore(settings).create(
        ActiveAssetCreateRequest.model_validate(
            _payload(value="batch-one.example.test", responsible_user_ids=["local-admin"], capabilities=["active_dns_inventory"], allowed_protocols=["dns"], notes=[])
        ),
        organization_id="local-admin",
        actor_id="local-admin",
    )
    conflicted = mark_existing_active_asset_conflicts(parsed, [existing])
    assert [row.status for row in conflicted.rows] == ["already_registered", "duplicate_in_batch", "invalid"]

    csv_source = (
        "asset_type,value,responsible_user_ids,capabilities,allowed_ports,allowed_protocols,authorization_method,authorization_reference,authorized_at,expires_at,notes\n"
        f"domain,csv.example.test,local-admin,active_dns_inventory,,dns,manual_attestation,change-ticket SEC-42,{_payload()['authorized_at']},{_payload()['expires_at']},[]\n"
    ).encode("utf-8")
    csv_parsed = parse_active_asset_batch(csv_source, "authorized-assets.csv")
    assert csv_parsed.format == "csv"
    assert csv_parsed.rows[0].status == "ready"
    assert csv_parsed.rows[0].request is not None and csv_parsed.rows[0].request.value == "csv.example.test"


def test_active_asset_batch_store_rolls_back_and_recovers_interrupted_writes(monkeypatch, tmp_path):
    settings = _configure(monkeypatch, tmp_path)
    requests = [
        ActiveAssetCreateRequest.model_validate(_payload(value=value, responsible_user_ids=["local-admin"], capabilities=["active_dns_inventory"], allowed_protocols=["dns"], notes=[]))
        for value in ("atomic-one.example.test", "atomic-two.example.test")
    ]
    store = ActiveAssetStore(settings)
    original_write = active_assets_module._atomic_write
    writes = 0

    def fail_second(path, record):
        nonlocal writes
        writes += 1
        if writes == 2:
            raise OSError("synthetic bounded write failure")
        return original_write(path, record)

    monkeypatch.setattr(active_assets_module, "_atomic_write", fail_second)
    with pytest.raises(ActiveAssetStoreError, match="asset_store_invalid"):
        store.create_many(
            requests,
            organization_id="local-admin",
            actor_id="local-admin",
            normalized_digest_sha256="a" * 64,
            idempotency_key="b" * 32,
        )
    assert store.list(organization_id="local-admin") == []
    assert not list((tmp_path / "results" / "active_asset_batches").rglob(".pending-*.json"))

    writes = 0

    def interrupt_second(path, record):
        nonlocal writes
        writes += 1
        if writes == 2:
            raise KeyboardInterrupt("synthetic process interruption")
        return original_write(path, record)

    monkeypatch.setattr(active_assets_module, "_atomic_write", interrupt_second)
    with pytest.raises(KeyboardInterrupt):
        store.create_many(
            requests,
            organization_id="local-admin",
            actor_id="local-admin",
            normalized_digest_sha256="c" * 64,
            idempotency_key="d" * 32,
        )
    assert list((tmp_path / "results" / "active_asset_batches").rglob(".pending-*.json"))
    monkeypatch.setattr(active_assets_module, "_atomic_write", original_write)
    recovered = ActiveAssetStore(settings)
    assert recovered.list(organization_id="local-admin") == []
    assert not list((tmp_path / "results" / "active_asset_batches").rglob(".pending-*.json"))

    original_json_write = active_assets_module._atomic_write_json

    def interrupt_receipt(path, payload):
        if path.parent.parent.name == "active_asset_batches" and path.name.endswith(".json") and not path.name.startswith(".pending-"):
            raise KeyboardInterrupt("synthetic interruption after committed journal")
        return original_json_write(path, payload)

    monkeypatch.setattr(active_assets_module, "_atomic_write_json", interrupt_receipt)
    with pytest.raises(KeyboardInterrupt):
        recovered.create_many(
            requests,
            organization_id="local-admin",
            actor_id="local-admin",
            normalized_digest_sha256="f" * 64,
            idempotency_key="1" * 32,
        )
    monkeypatch.setattr(active_assets_module, "_atomic_write_json", original_json_write)
    finalized = ActiveAssetStore(settings)
    assert len(finalized.list(organization_id="local-admin")) == 2
    replayed, was_replayed, _batch_id = finalized.create_many(
        requests,
        organization_id="local-admin",
        actor_id="local-admin",
        normalized_digest_sha256="f" * 64,
        idempotency_key="1" * 32,
    )
    assert was_replayed is True
    assert len(replayed) == 2


@pytest.mark.anyio
async def test_active_asset_batch_preflight_commit_replay_and_conflicts(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)
    source = _batch_json("batch-a.example.test", "batch-b.example.test")
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        preflight = await client.post(
            "/active/assets/batch/preflight",
            files={"file": ("authorized-assets.json", source, "application/json")},
        )
        assert preflight.status_code == 200, preflight.text
        review = preflight.json()
        assert review["state"] == "ready"
        assert review["input_count"] == review["ready_count"] == 2
        assert review["invalid_count"] == review["duplicate_count"] == review["conflict_count"] == 0
        assert review["can_confirm"] is True
        assert review["preflight_token"] and review["expires_at"]
        assert [row["canonical_value"] for row in review["rows"]] == ["batch-a.example.test", "batch-b.example.test"]

        form = {
            "preflight_token": review["preflight_token"],
            "idempotency_key": "e" * 32,
            "batch_confirmed": "true",
        }
        created = await client.post(
            "/active/assets/batch",
            data=form,
            files={"file": ("authorized-assets.json", source, "application/json")},
        )
        replayed = await client.post(
            "/active/assets/batch",
            data=form,
            files={"file": ("authorized-assets.json", source, "application/json")},
        )
        assert created.status_code == replayed.status_code == 201
        assert created.json()["created_count"] == 2 and created.json()["replayed"] is False
        assert replayed.json()["replayed"] is True
        assert [item["id"] for item in replayed.json()["assets"]] == [item["id"] for item in created.json()["assets"]]
        assert len((await client.post("/active/assets/search", json={"page_size": 24})).json()["items"]) == 2

        conflicting_preflight = await client.post(
            "/active/assets/batch/preflight",
            files={"file": ("authorized-assets.json", source, "application/json")},
        )
        assert conflicting_preflight.status_code == 200
        assert conflicting_preflight.json()["state"] == "needs_correction"
        assert conflicting_preflight.json()["conflict_count"] == 2
        assert conflicting_preflight.json()["preflight_token"] is None

        changed = _batch_json("changed.example.test")
        changed_commit = await client.post(
            "/active/assets/batch",
            data=form,
            files={"file": ("authorized-assets.json", changed, "application/json")},
        )
        assert changed_commit.status_code == 409
        assert "changed after preflight" in changed_commit.json()["detail"]

    persisted = "\n".join(path.read_text(encoding="utf-8") for path in tmp_path.rglob("*.json"))
    assert source.decode("utf-8") not in persisted
    assert "preflight_token" not in persisted
    assert "e" * 32 not in persisted


@pytest.mark.anyio
async def test_active_asset_batch_enforces_size_csrf_roles_and_redacted_errors(monkeypatch, tmp_path, caplog):
    _configure(monkeypatch, tmp_path, auth_mode="private_team_lightweight_users")
    caplog.set_level("INFO", logger="inspectra.audit")
    transport = ASGITransport(app=app)
    source = _batch_json("private-batch.example.test")
    async with AsyncClient(transport=transport, base_url="http://testserver") as admin:
        assert (await admin.post("/auth/login", json={"username": "admin", "password": "admin-weekly-password"})).status_code == 200
        csrf = (await admin.get("/auth/status")).json()["csrf_token"]
        no_csrf = await admin.post(
            "/active/assets/batch/preflight",
            files={"file": ("authorized-assets.json", source, "application/json")},
        )
        assert no_csrf.status_code == 403
        oversized_canary = b"private-batch-canary-" + b"x" * ACTIVE_ASSET_BATCH_MAX_BYTES
        oversized = await admin.post(
            "/active/assets/batch/preflight",
            files={"file": ("authorized-assets.json", oversized_canary, "application/json")},
            headers={ADMIN_CSRF_HEADER_NAME: csrf},
        )
        assert oversized.status_code == 413
        assert b"private-batch-canary" not in oversized.content

        reader_invitation = await admin.post(
            "/organization/invitations",
            json={"username": "batch.reader", "role": "reader"},
            headers={ADMIN_CSRF_HEADER_NAME: csrf},
        )
        assert reader_invitation.status_code == 201
        async with AsyncClient(transport=transport, base_url="http://testserver") as reader:
            assert (await reader.post(
                "/auth/invitations/accept",
                json={"token": reader_invitation.json()["token"], "password": "reader-batch-password"},
            )).status_code == 200
            assert (await reader.post(
                "/auth/login",
                json={"username": "batch.reader", "password": "reader-batch-password"},
            )).status_code == 200
            reader_csrf = (await reader.get("/auth/status")).json()["csrf_token"]
            denied = await reader.post(
                "/active/assets/batch/preflight",
                files={"file": ("authorized-assets.json", source, "application/json")},
                headers={ADMIN_CSRF_HEADER_NAME: reader_csrf},
            )
            assert denied.status_code == 403

    logged = "\n".join(record.getMessage() for record in caplog.records)
    assert "private-batch-canary" not in logged
    assert "private-batch.example.test" not in logged


@pytest.mark.anyio
async def test_active_weekly_team_flow_two_cycles_and_role_boundaries(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path, verification_enabled=True, auth_mode="private_team_lightweight_users")
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as admin:
        assert (await admin.post("/auth/login", json={"username": "admin", "password": "admin-weekly-password"})).status_code == 200
        admin_status = (await admin.get("/auth/status")).json()
        admin_headers = {ADMIN_CSRF_HEADER_NAME: admin_status["csrf_token"]}

        maintainer_invitation = await admin.post(
            "/organization/invitations",
            json={"username": "active.maintainer", "role": "maintainer"},
            headers=admin_headers,
        )
        reader_invitation = await admin.post(
            "/organization/invitations",
            json={"username": "active.reader", "role": "reader"},
            headers=admin_headers,
        )
        assert maintainer_invitation.status_code == reader_invitation.status_code == 201

        created = await admin.post(
            "/active/assets",
            json=_payload(value="weekly.example.test", responsible_user_ids=["team-admin"], capabilities=["active_dns_inventory"], notes=[]),
            headers=admin_headers,
        )
        assert created.status_code == 201, created.text
        asset_id = created.json()["id"]
        organization_id = created.json()["organization_id"]
        challenge = await admin.post(
            f"/active/assets/{asset_id}/verification/challenge",
            json={"method": "manual_attestation", "valid_for_days": 30, "control_check_confirmed": True},
            headers=admin_headers,
        )
        assert challenge.status_code == 201
        challenge_payload = challenge.json()
        verified = await admin.post(
            f"/active/assets/{asset_id}/verification/check",
            json={
                "verification_id": challenge_payload["verification"]["id"],
                "challenge_token": challenge_payload["challenge_token"],
                "manual_attestation_confirmed": True,
            },
            headers=admin_headers,
        )
        assert verified.status_code == 200
        assert verified.json()["status"] == "verified"

        async with AsyncClient(transport=transport, base_url="http://testserver") as maintainer:
            assert (await maintainer.post(
                "/auth/invitations/accept",
                json={"token": maintainer_invitation.json()["token"], "password": "maintainer-weekly-password"},
            )).status_code == 200
            assert (await maintainer.post(
                "/auth/login",
                json={"username": "active.maintainer", "password": "maintainer-weekly-password"},
            )).status_code == 200
            maintainer_headers = {ADMIN_CSRF_HEADER_NAME: (await maintainer.get("/auth/status")).json()["csrf_token"]}
            cycles = []
            for cycle_index in range(2):
                create_cycle_key = f"{cycle_index + 11:x}" * 32
                cycle = await maintainer.post(
                    f"/active/assets/{asset_id}/executions",
                    json={"capability": "active_dns_inventory", "authorization_reconfirmed": True, "idempotency_key": create_cycle_key},
                    headers=maintainer_headers,
                )
                assert cycle.status_code == 202
                assert cycle.json()["status"] == "queued"
                cycles.append((await maintainer.get(f"/jobs/{cycle.json()['id']}")).json())

            posture = await maintainer.get(f"/active/assets/{asset_id}/posture")
            assert posture.status_code == 200
            assert posture.json()["posture"]["execution_count"] == 2
            assert posture.json()["posture"]["comparison"]["state"] == "ready"
            baseline = await maintainer.post(
                f"/active/assets/{asset_id}/baseline",
                json={"execution_id": cycles[0]["id"], "baseline_confirmed": True},
                headers=maintainer_headers,
            )
            triage = await maintainer.post(
                f"/active/assets/{asset_id}/triage",
                json={"observation_key": "dns_count:A", "status": "acknowledged", "comment_code": "expected_service"},
                headers=maintainer_headers,
            )
            report = await maintainer.get(f"/active/assets/{asset_id}/report")
            assert baseline.status_code == triage.status_code == report.status_code == 200
            assert "bounded observations" in report.text
            assert "weekly.example.test" not in report.text
            assert "Exact target: withheld from export" in report.text
            weekly_preflight = await maintainer.get(
                "/active/operations/weekly-report/preflight", params={"period": "7d"}
            )
            assert weekly_preflight.status_code == 200
            maintainer_weekly = await maintainer.post(
                "/active/operations/weekly-report",
                json={
                    "period": "7d",
                    "report_format": "markdown",
                    "state_at": weekly_preflight.json()["state_at"],
                    "snapshot_digest": weekly_preflight.json()["snapshot_digest"],
                    "sensitive_targets_confirmed": True,
                },
                headers=maintainer_headers,
            )
            assert maintainer_weekly.status_code == 200
            assert "weekly.example.test" in maintainer_weekly.text
            assert "change-ticket SEC-42" not in maintainer_weekly.text
            review_digest = weekly_preflight.json()["snapshot_digest"]
            triage_before_review = (await maintainer.get(f"/active/assets/{asset_id}")).json()["triage"]
            review_payload = {
                "period": "7d",
                "state_at": weekly_preflight.json()["state_at"],
                "snapshot_digest": review_digest,
                "outcome": "follow_up_required",
                "expected_revision": 0,
                "idempotency_key": "weekly-review-team-cycle-001",
                "review_confirmed": True,
            }
            review = await maintainer.post(
                "/active/operations/weekly-review-receipts",
                json=review_payload,
                headers=maintainer_headers,
            )
            assert review.status_code == 201, review.text
            receipt = review.json()["receipt"]
            receipt_id = receipt["id"]
            assert review.json()["replayed"] is False
            assert receipt["outcome"] == "follow_up_required"
            assert receipt["snapshot_hmac_sha256"] != review_digest
            assert set(receipt) == {
                "contract_version", "id", "report_contract_version", "period",
                "starts_at", "state_at", "outcome", "coverage_state",
                "coverage_incomplete", "snapshot_hmac_sha256", "reviewed_at", "privacy",
            }
            replay = await maintainer.post(
                "/active/operations/weekly-review-receipts",
                json=review_payload,
                headers=maintainer_headers,
            )
            assert replay.status_code == 201
            assert replay.json()["replayed"] is True
            assert replay.json()["receipt"]["id"] == receipt_id
            stale = await maintainer.post(
                "/active/operations/weekly-review-receipts",
                json=review_payload | {"idempotency_key": "weekly-review-team-cycle-002"},
                headers=maintainer_headers,
            )
            assert stale.status_code == 409
            triage_after_review = (await maintainer.get(f"/active/assets/{asset_id}")).json()["triage"]
            assert triage_after_review == triage_before_review

        async with AsyncClient(transport=transport, base_url="http://testserver") as reader:
            assert (await reader.post(
                "/auth/invitations/accept",
                json={"token": reader_invitation.json()["token"], "password": "reader-weekly-password"},
            )).status_code == 200
            assert (await reader.post(
                "/auth/login",
                json={"username": "active.reader", "password": "reader-weekly-password"},
            )).status_code == 200
            reader_headers = {ADMIN_CSRF_HEADER_NAME: (await reader.get("/auth/status")).json()["csrf_token"]}
            assert (await reader.get("/active/operations/summary")).status_code == 200
            assert (await reader.get(f"/active/assets/{asset_id}/posture")).status_code == 200
            assert (await reader.get(f"/active/assets/{asset_id}/report")).status_code == 200
            weekly_preflight = await reader.get(
                "/active/operations/weekly-report/preflight", params={"period": "7d"}
            )
            assert weekly_preflight.status_code == 200
            receipts = await reader.get("/active/operations/weekly-review-receipts")
            assert receipts.status_code == 200
            assert receipts.headers["cache-control"] == "private, no-store"
            assert [item["id"] for item in receipts.json()["items"]] == [receipt_id]
            assert "weekly.example.test" not in receipts.text
            assert "active.maintainer" not in receipts.text
            verification = await reader.post(
                "/active/operations/weekly-review-receipts/verify",
                json={"receipt_id": receipt_id, "snapshot_digest": review_digest},
                headers=reader_headers,
            )
            assert verification.status_code == 200
            assert verification.json()["valid"] is True
            wrong_digest = await reader.post(
                "/active/operations/weekly-review-receipts/verify",
                json={"receipt_id": receipt_id, "snapshot_digest": "f" * 64},
                headers=reader_headers,
            )
            assert wrong_digest.status_code == 200
            assert wrong_digest.json()["valid"] is False
            reader_create = await reader.post(
                "/active/operations/weekly-review-receipts",
                json={
                    "period": "7d",
                    "state_at": weekly_preflight.json()["state_at"],
                    "snapshot_digest": weekly_preflight.json()["snapshot_digest"],
                    "outcome": "reviewed",
                    "expected_revision": 1,
                    "idempotency_key": "weekly-review-reader-denied-001",
                    "review_confirmed": True,
                },
                headers=reader_headers,
            )
            assert reader_create.status_code == 403
            weekly_payload = {
                "period": "7d",
                "report_format": "markdown",
                "state_at": weekly_preflight.json()["state_at"],
                "snapshot_digest": weekly_preflight.json()["snapshot_digest"],
                "sensitive_targets_confirmed": True,
            }
            assert (await reader.post(
                "/active/operations/weekly-report", json=weekly_payload
            )).status_code == 403
            reader_weekly = await reader.post(
                "/active/operations/weekly-report",
                json=weekly_payload,
                headers=reader_headers,
            )
            assert reader_weekly.status_code == 403
            assert "weekly.example.test" not in reader_weekly.text
            denied = await reader.post(
                f"/active/assets/{asset_id}/executions",
                json={"capability": "active_dns_inventory", "authorization_reconfirmed": True, "idempotency_key": "d" * 32},
                headers=reader_headers,
            )
            assert denied.status_code == 403
            assert denied.json() == {"detail": "This role cannot modify workspace data."}

        revoked = await admin.post(
            f"/active/assets/{asset_id}/revoke",
            json={"reason_code": "authorization_withdrawn"},
            headers=admin_headers,
        )
        assert revoked.status_code == 200
        blocked_after_revoke = await admin.post(
            f"/active/assets/{asset_id}/executions",
            json={"capability": "active_dns_inventory", "authorization_reconfirmed": True, "idempotency_key": "e" * 32},
            headers=admin_headers,
        )
        assert blocked_after_revoke.status_code == 409
        assert blocked_after_revoke.json() == {"detail": "Active asset authorization is not current."}

    persisted = "\n".join(path.read_text(encoding="utf-8") for path in tmp_path.rglob("*.json"))
    for forbidden in ("admin-weekly-password", "maintainer-weekly-password", "reader-weekly-password", challenge_payload["challenge_token"]):
        assert forbidden not in persisted
    receipt_store = tmp_path / "results" / "active_weekly_review_receipts"
    receipt_payload = "\n".join(path.read_text(encoding="utf-8") for path in receipt_store.glob("*.json"))
    for forbidden in (review_digest, "weekly.example.test", "active.maintainer", "change-ticket SEC-42"):
        assert forbidden not in receipt_payload
    review_events = [
        event for event in app.state.product_audit.list(organization_id, limit=100).items
        if event.action == "active_asset.weekly_review_recorded"
    ]
    assert len(review_events) == 2
    assert all(set(event.metadata) == {"decision_status", "review_period", "replayed"} for event in review_events)
    assert "weekly.example.test" not in str(review_events)
    assert review_digest not in str(review_events)
