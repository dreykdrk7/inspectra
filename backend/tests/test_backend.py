from datetime import datetime, timedelta, timezone
import hashlib
from http.cookies import SimpleCookie
import io
import json
from pathlib import Path
import sqlite3
import tarfile
import threading
from xml.etree import ElementTree
import zipfile

import pytest
from fastapi import HTTPException
from httpx import ASGITransport, AsyncClient, ConnectError, MockTransport, ReadTimeout, Response

from app.auth import (
    ADMIN_PASSWORD_HASH_SCHEME,
    ADMIN_SESSION_COOKIE_NAME,
    ADMIN_SESSION_COOKIE_SAMESITE,
    AdminSessionStore,
    LoginAttemptStore,
    MIN_ADMIN_PASSWORD_HASH_ITERATIONS,
    build_session_cookie_settings,
    is_supported_admin_password_hash,
    verify_admin_password,
)
from app.auth_state_sqlite import (
    SQLiteAdminSessionStore,
    SQLiteAuthStateError,
    SQLiteAuthStateStore,
    SQLiteLoginAttemptStore,
)
from app.config import (
    DEFAULT_ACTIVE_DNS_INVENTORY_ENABLED,
    DEFAULT_ACTIVE_NMAP_BASIC_ENABLED,
    DEFAULT_ACTIVE_TLS_BASIC_ENABLED,
    DEFAULT_ACTIVE_TOOLS_HEALTH_TIMEOUT_SECONDS,
    DEFAULT_ACTIVE_TOOLS_URL,
    DEFAULT_AUTH_STATE_STORE,
    DEFAULT_AUTH_MODE,
    DEFAULT_LOGIN_ATTEMPT_MAX_FAILURES,
    DEFAULT_LOGIN_ATTEMPT_MAX_KEYS,
    DEFAULT_LOGIN_ATTEMPT_WINDOW_SECONDS,
    DEFAULT_LOGIN_LOCKOUT_SECONDS,
    DEFAULT_LOCAL_OPERATOR,
    DEFAULT_SESSION_TTL_SECONDS,
    get_auth_mode,
    get_current_operator_for_trusted_local,
    is_single_admin_auth_configured,
    load_settings,
)
from app.active_tools_client import check_active_tools_health, run_active_nmap_basic
from app.domain_security import normalize_domain, normalize_subdomain_candidate
from app.active_nmap_boundary import (
    build_active_nmap_basic_boundary_request,
    map_active_nmap_basic_boundary_error,
    validate_active_nmap_basic_boundary_response,
)
from app.active_nmap_handoff import build_active_nmap_basic_handoff_plan
from app.active_nmap_lifecycle import ActiveNmapBasicRouteNoLiveClient, run_active_nmap_basic_lifecycle_skeleton
from app.active_dns_inventory import (
    ActiveDnsInventoryContract,
    ActiveDnsInventoryQueryResult,
    ActiveDnsInventoryRecord,
    ActiveDnsInventoryZoneTransferResult,
    run_active_dns_inventory,
)
from app.active_tls_basic import ActiveTlsBasicConnectionSnapshot
from app.main import AUTH_REQUIRED_DETAIL, CSRF_REQUIRED_DETAIL, RATE_LIMITED_DETAIL, app, login_client_key_for_request
from app.models import JobRecord
from app.reporting import markdown_block_value, markdown_inline_value
from app.sbom import extract_components_from_job, generate_cyclonedx_json, generate_spdx_json
from app.services import (
    ArchiveAuditService,
    ActiveHttpHeaderProbeService,
    ActiveNmapBasicService,
    ActiveNetworkDryRunService,
    CiCdConfigAuditService,
    ComposeConfigAuditService,
    DatabaseConfigAuditService,
    DjangoConfigAuditService,
    DomainAuditService,
    DockerConfigAuditService,
    ImageAuditService,
    K8sConfigAuditService,
    ManifestAuditService,
    NodePackageConfigAuditService,
    NginxConfigAuditService,
    PdfAuditService,
    ProjectArchiveAuditService,
    RedisConfigAuditService,
    SecretsReviewAuditService,
    SqlDatabaseConfigAuditService,
    SubdomainInventoryAuditService,
    TerraformConfigAuditService,
    WebAuditService,
    calculate_domain_runner_timeout_seconds,
    calculate_subdomain_inventory_runner_timeout_seconds,
)
from app.storage import FileStore, JobStore
from app import main as backend_main
from app import services as audit_services
from app import web_security
from active_runner.nmap_basic.parser import parse_active_nmap_basic_xml
from active_runner.nmap_basic.result import build_active_nmap_basic_result_payload


SAMPLE_PNG = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde"
SAMPLE_PACKAGE_JSON = b'{"name":"demo","version":"1.0.0","dependencies":{"react":"^18.3.1"}}'
SAMPLE_REQUIREMENTS = b"fastapi==0.115.0\nhttpx>=0.27\n"
SAMPLE_PYPROJECT = b'[project]\nname = "demo"\nversion = "1.0.0"\ndependencies = ["fastapi>=0.115"]\n'
SQL_DATABASE_SECRET_FIXTURES = (
    "super-secret-password",
    "raw-db-password-123456",
    "postgres://user:pass@example.com/db",
    "mysql://user:pass@example.com/db",
    "replication_password_should_not_render",
    "PGPASSWORD=super-secret-password",
    "MYSQL_PWD=super-secret-password",
    "PRIVATE KEY",
    "db_password_plaintext",
    "dump_row_secret_should_not_render",
    "pgpass_secret_should_not_render",
    "mycnf_secret_should_not_render",
)
ADMIN_PASSWORD_FIXTURE = "correct-admin-password"
ADMIN_PASSWORD_FIXTURE_SALT = "localAdminSaltForTests"


def make_admin_password_hash(password: str = ADMIN_PASSWORD_FIXTURE, salt: str = ADMIN_PASSWORD_FIXTURE_SALT) -> str:
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        MIN_ADMIN_PASSWORD_HASH_ITERATIONS,
    ).hex()
    return f"{ADMIN_PASSWORD_HASH_SCHEME}${MIN_ADMIN_PASSWORD_HASH_ITERATIONS}${salt}${digest}"


def session_cookie_value(response) -> str:
    cookie = SimpleCookie()
    cookie.load(response.headers.get("set-cookie", ""))
    return cookie[ADMIN_SESSION_COOKIE_NAME].value


class NoopAuditService:
    async def run_pdf_analysis(self, job_id: str) -> None:
        return None

    async def run_image_analysis(self, job_id: str) -> None:
        return None

    async def run_manifest_analysis(self, job_id: str) -> None:
        return None

    async def run_archive_analysis(self, job_id: str) -> None:
        return None

    async def run_project_archive_analysis(self, job_id: str) -> None:
        return None

    async def run_django_config_analysis(self, job_id: str) -> None:
        return None

    async def run_docker_config_analysis(self, job_id: str) -> None:
        return None

    async def run_secrets_review_analysis(self, job_id: str) -> None:
        return None

    async def run_node_package_config_analysis(self, job_id: str) -> None:
        return None

    async def run_ci_cd_config_analysis(self, job_id: str) -> None:
        return None

    async def run_k8s_config_analysis(self, job_id: str) -> None:
        return None

    async def run_terraform_config_analysis(self, job_id: str) -> None:
        return None

    async def run_nginx_config_analysis(self, job_id: str) -> None:
        return None

    async def run_compose_config_analysis(self, job_id: str) -> None:
        return None

    async def run_database_config_analysis(self, job_id: str) -> None:
        return None

    async def run_sql_database_config_analysis(self, job_id: str) -> None:
        return None

    async def run_redis_config_analysis(self, job_id: str) -> None:
        return None

    async def run_active_network_dry_run_analysis(self, job_id: str, active_request=None) -> None:
        return None

    async def run_active_http_header_probe_analysis(self, job_id: str, active_request=None) -> None:
        return None

    async def run_active_nmap_basic_analysis(self, job_id: str, handoff_plan=None) -> None:
        return None

    async def run_web_analysis(self, job_id: str, request_url: str | None = None) -> None:
        return None

    async def run_domain_analysis(self, job_id: str) -> None:
        return None

    async def run_subdomain_inventory_analysis(self, job_id: str, candidates: list[str] | None = None) -> None:
        return None


class CapturingWebAuditService:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str | None]] = []

    async def run_web_analysis(self, job_id: str, request_url: str | None = None) -> None:
        self.calls.append((job_id, request_url))


class CapturingSubdomainInventoryAuditService:
    def __init__(self) -> None:
        self.calls: list[tuple[str, list[str] | None]] = []

    async def run_subdomain_inventory_analysis(self, job_id: str, candidates: list[str] | None = None) -> None:
        self.calls.append((job_id, candidates))


class FakeRunnerResponse:
    def __init__(self, payload: dict) -> None:
        self._payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict:
        return self._payload


class FakeActiveNmapBasicExecutorAdapter:
    adapter_name = "mocked_executor"

    def __init__(self, results: list[dict]) -> None:
        self.results = results
        self.calls = []

    def execute(self, unit) -> dict:
        self.calls.append(unit)
        if not self.results:
            raise AssertionError("unexpected active_nmap_basic executor call")
        if len(self.results) == 1:
            return self.results[0]
        return self.results.pop(0)


class FakeActiveToolsNmapBasicClient:
    client_mode = "fake_no_live"

    def __init__(self, result: dict | None = None) -> None:
        self.result = result
        self.calls: list[dict] = []

    async def __call__(self, base_url, request_payload, *, timeout_seconds):
        self.calls.append({"base_url": base_url, "request_payload": request_payload, "timeout_seconds": timeout_seconds})
        return dict(self.result or make_active_tools_nmap_basic_client_result())


class FakeActiveToolsRealNmapBasicClient:
    client_mode = "active_tools_real"

    def __init__(self, result: dict | None = None) -> None:
        self.result = result
        self.calls: list[dict] = []

    async def __call__(self, base_url, request_payload, *, timeout_seconds):
        self.calls.append({"base_url": base_url, "request_payload": request_payload, "timeout_seconds": timeout_seconds})
        return dict(self.result or make_active_tools_nmap_basic_real_client_result())


class FakeActiveNmapBasicLifecycleRunner:
    def __init__(self, result: dict | None = None) -> None:
        self.result = result
        self.calls: list[dict] = []

    async def __call__(
        self,
        settings,
        handoff_plan,
        *,
        client,
        internal_approval_confirmed,
        fake_client_approved,
        active_tools_real_client_approved=False,
    ):
        self.calls.append(
            {
                "settings": settings,
                "handoff_plan": handoff_plan,
                "client_mode": getattr(client, "client_mode", None),
                "internal_approval_confirmed": internal_approval_confirmed,
                "fake_client_approved": fake_client_approved,
                "active_tools_real_client_approved": active_tools_real_client_approved,
            }
        )
        if self.result is not None:
            return dict(self.result)
        return await run_active_nmap_basic_lifecycle_skeleton(
            settings,
            handoff_plan,
            client=client,
            internal_approval_confirmed=internal_approval_confirmed,
            fake_client_approved=fake_client_approved,
            active_tools_real_client_approved=active_tools_real_client_approved,
        )


class FakeActiveTlsBasicConnector:
    def __init__(self, snapshot: ActiveTlsBasicConnectionSnapshot | None = None, exc: Exception | None = None) -> None:
        self.snapshot = snapshot or ActiveTlsBasicConnectionSnapshot(
            protocol="TLSv1.3",
            cipher=("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
            certificate={
                "subject": ((("commonName", "192.168.56.10"),),),
                "issuer": ((("commonName", "Inspectra Test CA"),),),
                "notBefore": "Jan  1 00:00:00 2026 GMT",
                "notAfter": "Jan 31 00:00:00 2026 GMT",
                "subjectAltName": (
                    ("DNS", "192.168.56.10"),
                    ("DNS", "nas-01.local"),
                    ("DNS", "secret-lab.internal"),
                    ("DNS", "extra.internal"),
                ),
            },
        )
        self.exc = exc
        self.calls = []

    def __call__(self, request):
        self.calls.append(request)
        if self.exc is not None:
            raise self.exc
        return self.snapshot


class FakeActiveDnsInventoryResolver:
    def __init__(self, responses: dict[tuple[str, str], ActiveDnsInventoryQueryResult | list[ActiveDnsInventoryRecord]] | None = None) -> None:
        self.responses = responses or {}
        self.calls: list[tuple[str, str]] = []

    def query(self, name: str, record_type: str):
        self.calls.append((name, record_type))
        response = self.responses.get((name, record_type))
        if response is None:
            return ActiveDnsInventoryQueryResult(status="noerror_empty")
        return response


class FakeActiveDnsInventoryAxfrTransport:
    def __init__(
        self,
        response: ActiveDnsInventoryZoneTransferResult | list[ActiveDnsInventoryRecord] | Exception | None = None,
    ) -> None:
        self.response = response if response is not None else ActiveDnsInventoryZoneTransferResult(status="refused", reason_code="zone_transfer_refused")
        self.calls: list[tuple[str, str]] = []

    def transfer(self, domain: str, nameserver: str):
        self.calls.append((domain, nameserver))
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def dns_record(name: str, record_type: str, value: str, *, ttl: int = 300, priority: int | None = None) -> ActiveDnsInventoryRecord:
    return ActiveDnsInventoryRecord(name=name, record_type=record_type, value=value, ttl=ttl, priority=priority)


def make_active_dns_inventory_fake_resolver(
    *,
    include_subdomain_records: bool = True,
    partial_timeout: bool = False,
    empty_domain: bool = False,
) -> FakeActiveDnsInventoryResolver:
    if empty_domain:
        return FakeActiveDnsInventoryResolver()
    responses: dict[tuple[str, str], ActiveDnsInventoryQueryResult | list[ActiveDnsInventoryRecord]] = {
        ("example.com", "A"): [dns_record("example.com", "A", "192.0.2.10")],
        ("example.com", "AAAA"): [dns_record("example.com", "AAAA", "2001:db8::10")],
        ("example.com", "CNAME"): ActiveDnsInventoryQueryResult(status="noerror_empty"),
        ("example.com", "MX"): [dns_record("example.com", "MX", "mail.example.com", priority=10)],
        ("example.com", "TXT"): [
            dns_record("example.com", "TXT", "v=spf1 include:_spf.example.net -all"),
            dns_record("example.com", "TXT", "token_should_never_render"),
        ],
        ("example.com", "NS"): [dns_record("example.com", "NS", "ns1.example.net")],
        ("example.com", "SOA"): [dns_record("example.com", "SOA", "mname=ns1.example.net;rname=hostmaster.example.com;serial=1")],
        ("example.com", "CAA"): [dns_record("example.com", "CAA", "issue ca.example.net")],
        ("_dmarc.example.com", "TXT"): [dns_record("_dmarc.example.com", "TXT", "v=DMARC1; p=quarantine")],
    }
    if include_subdomain_records:
        responses[("www.example.com", "A")] = [dns_record("www.example.com", "A", "192.0.2.20")]
        responses[("api.example.com", "CNAME")] = [dns_record("api.example.com", "CNAME", "edge.example.net")]
    if partial_timeout:
        responses[("example.com", "MX")] = ActiveDnsInventoryQueryResult(status="timeout", error_code="dns_query_timeout")
    return FakeActiveDnsInventoryResolver(responses)


def configure_test_state(monkeypatch, tmp_path, max_upload_bytes=None):
    monkeypatch.setenv("INSPECTRA_DATA_DIR", str(tmp_path))
    if max_upload_bytes is not None:
        monkeypatch.setenv("INSPECTRA_MAX_UPLOAD_BYTES", str(max_upload_bytes))
    settings = load_settings()
    settings.ensure_directories()
    file_store = FileStore(settings)
    job_store = JobStore(settings)
    app.state.settings = settings
    app.state.auth_mode = get_auth_mode(settings)
    app.state.default_local_operator = get_current_operator_for_trusted_local(settings)
    app.state.single_admin_auth_configured = is_single_admin_auth_configured(settings)
    app.state.admin_sessions = backend_main.create_admin_session_store(settings)
    app.state.login_attempts = backend_main.create_login_attempt_store(settings)
    app.state.session_cookie_settings = build_session_cookie_settings(settings.session_ttl_seconds)
    app.state.files = file_store
    app.state.jobs = job_store
    app.state.pdf_audits = PdfAuditService(settings, file_store, job_store)
    app.state.image_audits = ImageAuditService(settings, file_store, job_store)
    app.state.manifest_audits = ManifestAuditService(settings, file_store, job_store)
    app.state.archive_audits = ArchiveAuditService(settings, file_store, job_store)
    app.state.project_archive_audits = ProjectArchiveAuditService(settings, file_store, job_store)
    app.state.django_config_audits = DjangoConfigAuditService(settings, file_store, job_store)
    app.state.docker_config_audits = DockerConfigAuditService(settings, file_store, job_store)
    app.state.secrets_review_audits = SecretsReviewAuditService(settings, file_store, job_store)
    app.state.node_package_config_audits = NodePackageConfigAuditService(settings, file_store, job_store)
    app.state.ci_cd_config_audits = CiCdConfigAuditService(settings, file_store, job_store)
    app.state.k8s_config_audits = K8sConfigAuditService(settings, file_store, job_store)
    app.state.terraform_config_audits = TerraformConfigAuditService(settings, file_store, job_store)
    app.state.nginx_config_audits = NginxConfigAuditService(settings, file_store, job_store)
    app.state.compose_config_audits = ComposeConfigAuditService(settings, file_store, job_store)
    app.state.database_config_audits = DatabaseConfigAuditService(settings, file_store, job_store)
    app.state.sql_database_config_audits = SqlDatabaseConfigAuditService(settings, file_store, job_store)
    app.state.redis_config_audits = RedisConfigAuditService(settings, file_store, job_store)
    app.state.active_network_dry_runs = ActiveNetworkDryRunService(settings, job_store)
    app.state.active_http_header_probes = ActiveHttpHeaderProbeService(settings, job_store)
    app.state.active_nmap_basic_service = ActiveNmapBasicService(settings, job_store)
    app.state.active_tools_health_checker = backend_main.check_active_tools_health
    app.state.active_nmap_basic_lifecycle_client = ActiveNmapBasicRouteNoLiveClient()
    app.state.active_tls_basic_connector = None
    app.state.active_tls_basic_now = None
    app.state.active_dns_inventory_resolver = None
    app.state.web_audits = WebAuditService(settings, file_store, job_store)
    app.state.domain_audits = DomainAuditService(settings, file_store, job_store)
    app.state.subdomain_inventory_audits = SubdomainInventoryAuditService(settings, file_store, job_store)


@pytest.mark.anyio
async def test_health(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "inspectra-backend"}


@pytest.mark.anyio
async def test_active_tools_health_runtime_surface_defaults_to_controlled_unconfigured(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/health/active-tools")
        jobs_response = await client.get("/jobs")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "inspectra-backend",
        "active_tools": {
            "available": False,
            "status": None,
            "active_nmap_basic_status": None,
            "execution_enabled": None,
            "target_input_allowed": None,
            "network_requests_sent": None,
            "nmap_executed": None,
            "error_code": "active_tools_unconfigured",
        },
    }
    assert jobs_response.json() == []


@pytest.mark.anyio
async def test_active_tools_health_runtime_surface_uses_configured_checker_without_target_input(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_ACTIVE_TOOLS_URL", "http://active-tools:8080")
    monkeypatch.setenv("INSPECTRA_ACTIVE_TOOLS_HEALTH_TIMEOUT_SECONDS", "1.25")
    configure_test_state(monkeypatch, tmp_path)
    calls = []

    async def fake_checker(base_url, *, timeout_seconds):
        calls.append((base_url, timeout_seconds))
        return {
            "available": True,
            "status": "scaffold_ready",
            "active_nmap_basic_status": "disabled_no_scan",
            "execution_enabled": False,
            "target_input_allowed": False,
            "network_requests_sent": 0,
            "nmap_executed": False,
            "error_code": None,
        }

    app.state.active_tools_health_checker = fake_checker
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/health/active-tools")
        jobs_response = await client.get("/jobs")

    assert response.status_code == 200
    payload = response.json()
    assert payload["service"] == "inspectra-backend"
    assert payload["active_tools"] == {
        "available": True,
        "status": "scaffold_ready",
        "active_nmap_basic_status": "disabled_no_scan",
        "execution_enabled": False,
        "target_input_allowed": False,
        "network_requests_sent": 0,
        "nmap_executed": False,
        "error_code": None,
    }
    assert calls == [("http://active-tools:8080", 1.25)]
    assert jobs_response.json() == []


@pytest.mark.anyio
async def test_active_tools_health_runtime_surface_returns_controlled_unavailable(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_ACTIVE_TOOLS_URL", "http://active-tools:8080")
    configure_test_state(monkeypatch, tmp_path)

    async def fake_checker(base_url, *, timeout_seconds):
        return {
            "available": False,
            "status": None,
            "active_nmap_basic_status": None,
            "execution_enabled": None,
            "target_input_allowed": None,
            "network_requests_sent": None,
            "nmap_executed": None,
            "error_code": "active_tools_unavailable",
        }

    app.state.active_tools_health_checker = fake_checker
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/health/active-tools")

    assert response.status_code == 200
    assert response.json()["active_tools"]["available"] is False
    assert response.json()["active_tools"]["error_code"] == "active_tools_unavailable"


@pytest.mark.anyio
async def test_active_tools_health_runtime_surface_rejects_query_and_body_inputs_without_leaking_values(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        query_response = await client.get("/health/active-tools", params={"target": "token_should_never_render"})
        body_response = await client.request(
            "GET",
            "/health/active-tools",
            content=b'{"target":"token_should_never_render"}',
        )

    assert query_response.status_code == 400
    assert body_response.status_code == 400
    assert query_response.json()["detail"] == "active_tools health status does not accept query parameters."
    assert body_response.json()["detail"] == "active_tools health status does not accept a request body."
    assert "token_should_never_render" not in query_response.text
    assert "token_should_never_render" not in body_response.text


@pytest.mark.anyio
async def test_active_tools_health_runtime_surface_auth_required_anonymous_fails_before_input_validation(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setenv("INSPECTRA_AUTH_MODE", "self_hosted_single_admin")
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/health/active-tools", params={"target": "token_should_never_render"})

    assert response.status_code == 401
    assert response.json()["detail"] == AUTH_REQUIRED_DETAIL
    assert "token_should_never_render" not in response.text


@pytest.mark.anyio
async def test_cors_preflight_allows_credentials_for_configured_origin(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.options(
            "/files",
            headers={
                "origin": "http://localhost:5173",
                "access-control-request-method": "GET",
            },
        )

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://localhost:5173"
    assert response.headers["access-control-allow-credentials"] == "true"


def test_verify_admin_password_accepts_supported_pbkdf2_hash():
    password_hash = make_admin_password_hash()

    assert is_supported_admin_password_hash(password_hash) is True
    assert verify_admin_password(ADMIN_PASSWORD_FIXTURE, password_hash) is True


@pytest.mark.parametrize(
    ("password", "password_hash"),
    [
        ("wrong-admin-password", make_admin_password_hash()),
        ("", make_admin_password_hash()),
        (None, make_admin_password_hash()),
        (ADMIN_PASSWORD_FIXTURE, ""),
        (ADMIN_PASSWORD_FIXTURE, None),
        (ADMIN_PASSWORD_FIXTURE, "argon2id$unsupported-format"),
        (ADMIN_PASSWORD_FIXTURE, "pbkdf2_sha256$1000$localAdminSaltForTests$00"),
        (ADMIN_PASSWORD_FIXTURE, "pbkdf2_sha256$600000$short$00"),
        (ADMIN_PASSWORD_FIXTURE, "pbkdf2_sha256$600000$localAdminSaltForTests$not-hex"),
    ],
)
def test_verify_admin_password_fails_closed_for_invalid_inputs(password, password_hash):
    assert verify_admin_password(password, password_hash) is False


def test_verify_admin_password_does_not_log_password_or_hash(caplog):
    password_hash = make_admin_password_hash()

    assert verify_admin_password("wrong-admin-password", password_hash) is False

    serialized_logs = "\n".join(record.getMessage() for record in caplog.records)
    assert ADMIN_PASSWORD_FIXTURE not in serialized_logs
    assert "wrong-admin-password" not in serialized_logs
    assert password_hash not in serialized_logs


def test_supported_admin_password_hash_rejects_missing_or_unsupported_formats():
    assert is_supported_admin_password_hash(make_admin_password_hash()) is True
    assert is_supported_admin_password_hash("") is False
    assert is_supported_admin_password_hash(None) is False
    assert is_supported_admin_password_hash("argon2id$unsupported-format") is False
    assert is_supported_admin_password_hash("pbkdf2_sha256$1000$localAdminSaltForTests$00") is False


def test_admin_session_store_creates_opaque_local_admin_session():
    store = AdminSessionStore(ttl_seconds=60)

    session = store.create_admin_session(DEFAULT_LOCAL_OPERATOR.id)
    second_session = store.create_admin_session(DEFAULT_LOCAL_OPERATOR.id)

    assert session.operator_id == "local-admin"
    assert session.auth_mode == "self_hosted_single_admin"
    assert isinstance(session.session_id, str)
    assert isinstance(session.csrf_token, str)
    assert len(session.session_id) >= 32
    assert len(session.csrf_token) >= 32
    assert session.session_id != second_session.session_id
    assert session.csrf_token != second_session.csrf_token
    assert session.expires_at > session.created_at
    assert store.get_session(session.session_id) == session
    assert store.is_session_valid(session) is True


def test_admin_session_store_expires_and_invalidates_sessions():
    current_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
    store = AdminSessionStore(ttl_seconds=30, now_func=lambda: current_time)
    session = store.create_admin_session(DEFAULT_LOCAL_OPERATOR.id)

    assert store.get_session(session.session_id) == session

    current_time = current_time + timedelta(seconds=31)

    assert store.get_session(session.session_id) is None
    assert store.is_session_valid(session) is False

    active_session = store.create_admin_session(DEFAULT_LOCAL_OPERATOR.id)
    assert store.invalidate_session(active_session.session_id) is True
    assert store.get_session(active_session.session_id) is None
    assert store.invalidate_session(active_session.session_id) is False


def test_admin_session_store_purges_expired_sessions():
    current_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
    store = AdminSessionStore(ttl_seconds=10, now_func=lambda: current_time)
    expired_session = store.create_admin_session(DEFAULT_LOCAL_OPERATOR.id)

    current_time = current_time + timedelta(seconds=11)
    active_session = store.create_admin_session(DEFAULT_LOCAL_OPERATOR.id)

    assert store.purge_expired_sessions() == 1
    assert store.get_session(expired_session.session_id) is None
    assert store.get_session(active_session.session_id) == active_session


def test_admin_session_does_not_store_password_or_hash_material():
    password_hash = make_admin_password_hash()
    store = AdminSessionStore(ttl_seconds=60)

    session = store.create_admin_session(DEFAULT_LOCAL_OPERATOR.id)
    serialized_session = json.dumps(session.__dict__, default=str, sort_keys=True)

    assert ADMIN_PASSWORD_FIXTURE not in serialized_session
    assert password_hash not in serialized_session
    assert "password" not in serialized_session.lower()
    assert "hash" not in serialized_session.lower()


def test_login_attempt_store_starts_unlocked_and_records_failures():
    current_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
    store = LoginAttemptStore(
        window_seconds=600,
        max_failures=3,
        lockout_seconds=900,
        max_keys=10,
        now_func=lambda: current_time,
    )

    assert store.is_locked("203.0.113.10") is False
    assert store.seconds_until_unlock("203.0.113.10") == 0
    assert store.failure_count("203.0.113.10") == 0

    first_record = store.record_failure("203.0.113.10")
    second_record = store.record_failure("203.0.113.10")

    assert first_record.failure_count == 1
    assert second_record.failure_count == 2
    assert store.failure_count("203.0.113.10") == 2
    assert store.is_locked("203.0.113.10") is False


def test_login_attempt_store_threshold_soft_locks_and_expires():
    current_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
    store = LoginAttemptStore(
        window_seconds=600,
        max_failures=3,
        lockout_seconds=900,
        max_keys=10,
        now_func=lambda: current_time,
    )

    store.record_failure("203.0.113.20")
    store.record_failure("203.0.113.20")
    locked_record = store.record_failure("203.0.113.20")

    assert locked_record.failure_count == 3
    assert locked_record.locked_until == current_time + timedelta(seconds=900)
    assert store.is_locked("203.0.113.20") is True
    assert store.seconds_until_unlock("203.0.113.20") == 900

    current_time = current_time + timedelta(seconds=901)

    assert store.is_locked("203.0.113.20") is False
    assert store.seconds_until_unlock("203.0.113.20") == 0
    assert store.failure_count("203.0.113.20") == 0


def test_login_attempt_store_single_failure_threshold_locks_immediately():
    current_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
    store = LoginAttemptStore(
        window_seconds=600,
        max_failures=1,
        lockout_seconds=900,
        max_keys=10,
        now_func=lambda: current_time,
    )

    record = store.record_failure("203.0.113.21")

    assert record.failure_count == 1
    assert record.locked_until == current_time + timedelta(seconds=900)
    assert store.is_locked("203.0.113.21") is True


def test_login_attempt_store_reset_success_clears_counter_and_lockout():
    current_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
    store = LoginAttemptStore(
        window_seconds=600,
        max_failures=2,
        lockout_seconds=900,
        max_keys=10,
        now_func=lambda: current_time,
    )

    store.record_failure("203.0.113.30")
    store.record_failure("203.0.113.30")

    assert store.is_locked("203.0.113.30") is True
    assert store.reset_success("203.0.113.30") is True
    assert store.is_locked("203.0.113.30") is False
    assert store.failure_count("203.0.113.30") == 0
    assert store.reset_success("203.0.113.30") is False


def test_login_attempt_store_purges_expired_records():
    current_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
    store = LoginAttemptStore(
        window_seconds=60,
        max_failures=3,
        lockout_seconds=900,
        max_keys=10,
        now_func=lambda: current_time,
    )

    store.record_failure("203.0.113.40")
    current_time = current_time + timedelta(seconds=61)
    store.record_failure("203.0.113.41")

    assert store.record_count() == 2
    assert store.purge_expired() == 1
    assert store.failure_count("203.0.113.40") == 0
    assert store.failure_count("203.0.113.41") == 1


def test_login_attempt_store_max_keys_evicts_oldest_records():
    current_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
    store = LoginAttemptStore(
        window_seconds=600,
        max_failures=3,
        lockout_seconds=900,
        max_keys=2,
        now_func=lambda: current_time,
    )

    store.record_failure("203.0.113.50")
    current_time = current_time + timedelta(seconds=1)
    store.record_failure("203.0.113.51")
    current_time = current_time + timedelta(seconds=1)
    store.record_failure("203.0.113.52")

    assert store.record_count() == 2
    assert store.failure_count("203.0.113.50") == 0
    assert store.failure_count("203.0.113.51") == 1
    assert store.failure_count("203.0.113.52") == 1


def test_login_attempt_store_does_not_store_secret_material():
    password_hash = make_admin_password_hash()
    store = LoginAttemptStore(
        window_seconds=600,
        max_failures=3,
        lockout_seconds=900,
        max_keys=10,
    )

    store.record_failure("203.0.113.60")
    serialized_records = json.dumps(
        [record.__dict__ for record in store._records.values()],
        default=str,
        sort_keys=True,
    )

    assert ADMIN_PASSWORD_FIXTURE not in serialized_records
    assert password_hash not in serialized_records
    assert "csrf" not in serialized_records.lower()
    assert "cookie" not in serialized_records.lower()
    assert "session" not in serialized_records.lower()
    assert "hash" not in serialized_records.lower()
    assert "password" not in serialized_records.lower()


def test_sqlite_auth_state_schema_initializes_idempotently(tmp_path):
    db_path = tmp_path / "runtime" / "auth_state.sqlite3"

    store = SQLiteAuthStateStore(db_path)
    second_store = SQLiteAuthStateStore(db_path)

    assert store.get_schema_version() == 1
    assert second_store.get_schema_version() == 1
    with sqlite3.connect(db_path) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        indexes = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'index'"
            ).fetchall()
        }

    assert {"auth_sessions", "auth_login_attempts", "auth_state_metadata"}.issubset(tables)
    assert "idx_auth_sessions_expires_at" in indexes
    assert "idx_auth_sessions_revoked_at" in indexes
    assert "idx_auth_sessions_operator_id" in indexes
    assert "idx_auth_login_attempts_locked_until" in indexes
    assert "idx_auth_login_attempts_updated_at" in indexes


def test_sqlite_auth_state_create_get_session_redacts_raw_tokens(tmp_path):
    db_path = tmp_path / "auth_state.sqlite3"
    store = SQLiteAuthStateStore(db_path)
    current_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
    session_id = "plain-session-id-should-not-render"
    csrf_token = "plain-csrf-token-should-not-render"

    created = store.create_session(
        session_id,
        csrf_token,
        DEFAULT_LOCAL_OPERATOR.id,
        expires_at=current_time + timedelta(seconds=60),
        now=current_time,
        client_key="203.0.113.70",
        user_agent="Inspectra Test Browser",
    )
    loaded = store.get_session(session_id, now=current_time)

    assert loaded == created
    assert loaded is not None
    assert loaded.operator_id == DEFAULT_LOCAL_OPERATOR.id
    assert loaded.auth_mode == "self_hosted_single_admin"
    assert loaded.expires_at == current_time + timedelta(seconds=60)
    serialized_loaded = json.dumps(loaded.__dict__, default=str, sort_keys=True)
    db_bytes = db_path.read_bytes()
    assert session_id not in serialized_loaded
    assert csrf_token not in serialized_loaded
    assert session_id.encode("utf-8") not in db_bytes
    assert csrf_token.encode("utf-8") not in db_bytes

    with sqlite3.connect(db_path) as connection:
        row = connection.execute(
            "SELECT session_id_hash, csrf_token_hash, client_key_hash, user_agent_hash FROM auth_sessions"
        ).fetchone()

    assert row is not None
    assert row[0] != session_id
    assert row[1] != csrf_token
    assert row[2] != "203.0.113.70"
    assert row[3] != "Inspectra Test Browser"
    assert len(row[0]) == 64
    assert len(row[1]) == 64


def test_sqlite_auth_state_expired_and_revoked_sessions_are_invalid(tmp_path):
    db_path = tmp_path / "auth_state.sqlite3"
    current_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
    store = SQLiteAuthStateStore(db_path)

    store.create_session(
        "expired-session-token",
        "expired-csrf-token",
        DEFAULT_LOCAL_OPERATOR.id,
        expires_at=current_time + timedelta(seconds=10),
        now=current_time,
    )
    store.create_session(
        "revoked-session-token",
        "revoked-csrf-token",
        DEFAULT_LOCAL_OPERATOR.id,
        expires_at=current_time + timedelta(seconds=120),
        now=current_time,
    )

    assert store.get_session("expired-session-token", now=current_time + timedelta(seconds=11)) is None
    assert store.revoke_session("revoked-session-token", "logout", now=current_time + timedelta(seconds=1)) is True
    assert store.get_session("revoked-session-token", now=current_time + timedelta(seconds=2)) is None

    restarted_store = SQLiteAuthStateStore(db_path)
    assert restarted_store.get_session("revoked-session-token", now=current_time + timedelta(seconds=2)) is None
    with sqlite3.connect(db_path) as connection:
        revoked_at = connection.execute(
            "SELECT revoked_at FROM auth_sessions WHERE revocation_reason = 'logout'"
        ).fetchone()[0]
    assert revoked_at is not None


def test_sqlite_auth_state_cleanup_removes_expired_and_old_revoked_sessions(tmp_path):
    db_path = tmp_path / "auth_state.sqlite3"
    current_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
    store = SQLiteAuthStateStore(db_path)

    store.create_session(
        "expired-cleanup-session",
        "expired-cleanup-csrf",
        DEFAULT_LOCAL_OPERATOR.id,
        expires_at=current_time - timedelta(seconds=1),
        now=current_time - timedelta(seconds=120),
    )
    store.create_session(
        "revoked-cleanup-session",
        "revoked-cleanup-csrf",
        DEFAULT_LOCAL_OPERATOR.id,
        expires_at=current_time + timedelta(seconds=120),
        now=current_time - timedelta(seconds=120),
    )
    store.create_session(
        "active-cleanup-session",
        "active-cleanup-csrf",
        DEFAULT_LOCAL_OPERATOR.id,
        expires_at=current_time + timedelta(seconds=120),
        now=current_time,
    )
    store.revoke_session("revoked-cleanup-session", "logout", now=current_time - timedelta(seconds=90))

    assert store.cleanup_sessions(now=current_time, revoked_retention_seconds=30) == 2
    assert store.get_session("active-cleanup-session", now=current_time) is not None
    with sqlite3.connect(db_path) as connection:
        row_count = connection.execute("SELECT COUNT(*) FROM auth_sessions").fetchone()[0]
    assert row_count == 1


def test_sqlite_auth_state_cleanup_retains_recent_revoked_session_row_but_rejects_it(tmp_path):
    db_path = tmp_path / "auth_state.sqlite3"
    current_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
    store = SQLiteAuthStateStore(db_path)

    store.create_session(
        "recent-revoked-session-token",
        "recent-revoked-csrf-token",
        DEFAULT_LOCAL_OPERATOR.id,
        expires_at=current_time + timedelta(seconds=120),
        now=current_time - timedelta(seconds=60),
    )
    store.create_session(
        "active-retained-session-token",
        "active-retained-csrf-token",
        DEFAULT_LOCAL_OPERATOR.id,
        expires_at=current_time + timedelta(seconds=120),
        now=current_time,
    )
    assert store.revoke_session(
        "recent-revoked-session-token",
        "logout",
        now=current_time - timedelta(seconds=5),
    )

    assert store.get_session("recent-revoked-session-token", now=current_time) is None
    assert store.cleanup_sessions(now=current_time, revoked_retention_seconds=30) == 0
    assert store.get_session("active-retained-session-token", now=current_time) is not None
    with sqlite3.connect(db_path) as connection:
        row_count = connection.execute("SELECT COUNT(*) FROM auth_sessions").fetchone()[0]
    assert row_count == 2

    assert store.cleanup_sessions(now=current_time + timedelta(seconds=26), revoked_retention_seconds=30) == 1
    assert store.get_session("active-retained-session-token", now=current_time + timedelta(seconds=26)) is not None
    with sqlite3.connect(db_path) as connection:
        row_count_after_retention = connection.execute("SELECT COUNT(*) FROM auth_sessions").fetchone()[0]
    assert row_count_after_retention == 1


def test_sqlite_auth_state_login_attempt_window_and_lockout(tmp_path):
    db_path = tmp_path / "auth_state.sqlite3"
    current_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
    store = SQLiteAuthStateStore(db_path)

    first = store.record_login_failure(
        "203.0.113.80",
        now=current_time,
        window_seconds=60,
        max_failures=3,
        lockout_seconds=900,
    )
    second = store.record_login_failure(
        "203.0.113.80",
        now=current_time + timedelta(seconds=10),
        window_seconds=60,
        max_failures=3,
        lockout_seconds=900,
    )
    locked = store.record_login_failure(
        "203.0.113.80",
        now=current_time + timedelta(seconds=20),
        window_seconds=60,
        max_failures=3,
        lockout_seconds=900,
    )
    reset_window = store.record_login_failure(
        "203.0.113.81",
        now=current_time + timedelta(seconds=90),
        window_seconds=60,
        max_failures=3,
        lockout_seconds=900,
    )

    assert first.failure_count == 1
    assert second.failure_count == 2
    assert locked.failure_count == 3
    assert locked.locked_until == current_time + timedelta(seconds=920)
    assert reset_window.failure_count == 1
    outside_window = store.record_login_failure(
        "203.0.113.81",
        now=current_time + timedelta(seconds=151),
        window_seconds=60,
        max_failures=3,
        lockout_seconds=900,
    )
    assert outside_window.failure_count == 1


def test_sqlite_auth_state_login_attempt_persists_and_resets(tmp_path):
    db_path = tmp_path / "auth_state.sqlite3"
    current_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
    store = SQLiteAuthStateStore(db_path)

    store.record_login_failure(
        "203.0.113.90",
        now=current_time,
        window_seconds=60,
        max_failures=1,
        lockout_seconds=900,
    )
    restarted_store = SQLiteAuthStateStore(db_path)
    persisted = restarted_store.get_login_attempt("203.0.113.90")

    assert persisted is not None
    assert persisted.failure_count == 1
    assert persisted.locked_until == current_time + timedelta(seconds=900)
    assert restarted_store.reset_login_attempt("203.0.113.90") is True
    assert store.get_login_attempt("203.0.113.90") is None


def test_sqlite_auth_state_multiple_instances_share_session_and_attempt_state(tmp_path):
    db_path = tmp_path / "auth_state.sqlite3"
    current_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
    first_store = SQLiteAuthStateStore(db_path)
    second_store = SQLiteAuthStateStore(db_path)

    first_store.create_session(
        "shared-session-token",
        "shared-csrf-token",
        DEFAULT_LOCAL_OPERATOR.id,
        expires_at=current_time + timedelta(seconds=60),
        now=current_time,
    )
    second_store.record_login_failure(
        "203.0.113.100",
        now=current_time,
        window_seconds=60,
        max_failures=2,
        lockout_seconds=900,
    )

    assert second_store.get_session("shared-session-token", now=current_time) is not None
    assert first_store.get_login_attempt("203.0.113.100").failure_count == 1
    assert second_store.touch_session("shared-session-token", now=current_time + timedelta(seconds=10)) is True
    assert first_store.get_session("shared-session-token", now=current_time + timedelta(seconds=10)).last_seen_at == (
        current_time + timedelta(seconds=10)
    )


def test_sqlite_auth_state_cleanup_login_attempts(tmp_path):
    db_path = tmp_path / "auth_state.sqlite3"
    current_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
    store = SQLiteAuthStateStore(db_path)

    store.record_login_failure(
        "203.0.113.110",
        now=current_time,
        window_seconds=60,
        max_failures=3,
        lockout_seconds=900,
    )
    store.record_login_failure(
        "203.0.113.111",
        now=current_time,
        window_seconds=60,
        max_failures=1,
        lockout_seconds=30,
    )

    assert store.cleanup_login_attempts(now=current_time + timedelta(seconds=61), window_seconds=60) == 2
    assert store.get_login_attempt("203.0.113.110") is None
    assert store.get_login_attempt("203.0.113.111") is None


def test_sqlite_login_attempt_store_matches_window_lockout_and_reset_semantics(tmp_path):
    db_path = tmp_path / "auth_state.sqlite3"
    current_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
    store = SQLiteLoginAttemptStore(
        db_path,
        window_seconds=60,
        max_failures=2,
        lockout_seconds=120,
        max_keys=10,
        now_func=lambda: current_time,
    )

    first = store.record_failure(" 203.0.113.120 ")
    second = store.record_failure("203.0.113.120")

    assert first.failure_count == 1
    assert first.client_key == "203.0.113.120"
    assert second.failure_count == 2
    assert store.is_locked("203.0.113.120") is True
    assert store.seconds_until_unlock("203.0.113.120") == 120

    restarted_store = SQLiteLoginAttemptStore(
        db_path,
        window_seconds=60,
        max_failures=2,
        lockout_seconds=120,
        max_keys=10,
        now_func=lambda: current_time,
    )

    assert restarted_store.is_locked("203.0.113.120") is True
    assert restarted_store.reset_success("203.0.113.120") is True
    assert store.failure_count("203.0.113.120") == 0

    current_time = current_time + timedelta(seconds=61)
    reset_window = store.record_failure("203.0.113.121")
    current_time = current_time + timedelta(seconds=61)
    outside_window = store.record_failure("203.0.113.121")

    assert reset_window.failure_count == 1
    assert outside_window.failure_count == 1


def test_sqlite_login_attempt_store_cleanup_and_pruning_are_bounded(tmp_path):
    db_path = tmp_path / "auth_state.sqlite3"
    current_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
    store = SQLiteLoginAttemptStore(
        db_path,
        window_seconds=60,
        max_failures=5,
        lockout_seconds=120,
        max_keys=2,
        now_func=lambda: current_time,
    )

    store.record_failure("203.0.113.130")
    current_time = current_time + timedelta(seconds=1)
    store.record_failure("203.0.113.131")
    current_time = current_time + timedelta(seconds=1)
    store.record_failure("203.0.113.132")

    assert store.record_count() == 2
    assert store.failure_count("203.0.113.130") == 0
    assert store.failure_count("203.0.113.131") == 1
    assert store.failure_count("203.0.113.132") == 1

    lockout_store = SQLiteLoginAttemptStore(
        db_path,
        window_seconds=60,
        max_failures=1,
        lockout_seconds=30,
        max_keys=10,
        now_func=lambda: current_time,
    )
    lockout_store.record_failure("203.0.113.133")
    assert lockout_store.is_locked("203.0.113.133") is True

    current_time = current_time + timedelta(seconds=31)

    assert lockout_store.purge_expired() >= 1
    assert lockout_store.is_locked("203.0.113.133") is False
    assert b"203.0.113.133" not in db_path.read_bytes()


def test_sqlite_login_attempt_pruning_keeps_active_lockout_under_row_pressure(tmp_path):
    db_path = tmp_path / "auth_state.sqlite3"
    current_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
    store = SQLiteLoginAttemptStore(
        db_path,
        window_seconds=120,
        max_failures=2,
        lockout_seconds=300,
        max_keys=2,
        now_func=lambda: current_time,
    )

    store.record_failure("203.0.113.150")
    current_time = current_time + timedelta(seconds=1)
    store.record_failure("203.0.113.150")
    assert store.is_locked("203.0.113.150") is True

    current_time = current_time + timedelta(seconds=1)
    store.record_failure("203.0.113.151")
    current_time = current_time + timedelta(seconds=1)
    store.record_failure("203.0.113.152")

    assert store.record_count() == 2
    assert store.is_locked("203.0.113.150") is True
    assert store.failure_count("203.0.113.151") == 0
    assert store.failure_count("203.0.113.152") == 1


def test_session_cookie_settings_are_safe_by_default():
    cookie_settings = build_session_cookie_settings(ttl_seconds=DEFAULT_SESSION_TTL_SECONDS)

    assert cookie_settings.name == ADMIN_SESSION_COOKIE_NAME
    assert cookie_settings.httponly is True
    assert cookie_settings.samesite == ADMIN_SESSION_COOKIE_SAMESITE
    assert cookie_settings.secure is False
    assert cookie_settings.max_age_seconds == DEFAULT_SESSION_TTL_SECONDS
    assert cookie_settings.path == "/"


def test_session_cookie_settings_can_require_secure_cookie():
    cookie_settings = build_session_cookie_settings(ttl_seconds=120, secure=True)

    assert cookie_settings.secure is True
    assert cookie_settings.max_age_seconds == 120


def test_session_ttl_config_defaults_and_env_override(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)

    assert app.state.settings.session_ttl_seconds == DEFAULT_SESSION_TTL_SECONDS
    assert app.state.session_cookie_settings.max_age_seconds == DEFAULT_SESSION_TTL_SECONDS

    monkeypatch.setenv("INSPECTRA_SESSION_TTL_SECONDS", "120")
    configure_test_state(monkeypatch, tmp_path)

    assert app.state.settings.session_ttl_seconds == 120
    assert app.state.admin_sessions.ttl_seconds == 120
    assert app.state.session_cookie_settings.max_age_seconds == 120


def test_login_attempt_config_defaults_and_env_override(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)

    assert app.state.settings.login_attempt_window_seconds == DEFAULT_LOGIN_ATTEMPT_WINDOW_SECONDS
    assert app.state.settings.login_attempt_max_failures == DEFAULT_LOGIN_ATTEMPT_MAX_FAILURES
    assert app.state.settings.login_lockout_seconds == DEFAULT_LOGIN_LOCKOUT_SECONDS
    assert app.state.settings.login_attempt_max_keys == DEFAULT_LOGIN_ATTEMPT_MAX_KEYS
    assert app.state.login_attempts.window_seconds == DEFAULT_LOGIN_ATTEMPT_WINDOW_SECONDS
    assert app.state.login_attempts.max_failures == DEFAULT_LOGIN_ATTEMPT_MAX_FAILURES
    assert app.state.login_attempts.lockout_seconds == DEFAULT_LOGIN_LOCKOUT_SECONDS
    assert app.state.login_attempts.max_keys == DEFAULT_LOGIN_ATTEMPT_MAX_KEYS

    monkeypatch.setenv("INSPECTRA_LOGIN_ATTEMPT_WINDOW_SECONDS", "120")
    monkeypatch.setenv("INSPECTRA_LOGIN_ATTEMPT_MAX_FAILURES", "2")
    monkeypatch.setenv("INSPECTRA_LOGIN_LOCKOUT_SECONDS", "300")
    monkeypatch.setenv("INSPECTRA_LOGIN_ATTEMPT_MAX_KEYS", "8")
    configure_test_state(monkeypatch, tmp_path)

    assert app.state.settings.login_attempt_window_seconds == 120
    assert app.state.settings.login_attempt_max_failures == 2
    assert app.state.settings.login_lockout_seconds == 300
    assert app.state.settings.login_attempt_max_keys == 8
    assert app.state.login_attempts.window_seconds == 120
    assert app.state.login_attempts.max_failures == 2
    assert app.state.login_attempts.lockout_seconds == 300
    assert app.state.login_attempts.max_keys == 8


def test_auth_state_store_config_defaults_and_sqlite_override(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)

    assert app.state.settings.auth_state_store == DEFAULT_AUTH_STATE_STORE
    assert app.state.settings.resolved_auth_state_db_path == tmp_path / "runtime" / "auth_state.sqlite3"
    assert isinstance(app.state.admin_sessions, AdminSessionStore)

    db_path = tmp_path / "custom-runtime" / "auth.sqlite3"
    monkeypatch.setenv("INSPECTRA_AUTH_MODE", "self_hosted_single_admin")
    monkeypatch.setenv("INSPECTRA_ADMIN_PASSWORD_HASH", make_admin_password_hash())
    monkeypatch.setenv("INSPECTRA_AUTH_STATE_STORE", "sqlite")
    monkeypatch.setenv("INSPECTRA_AUTH_STATE_DB_PATH", str(db_path))
    configure_test_state(monkeypatch, tmp_path)

    assert app.state.settings.auth_state_store == "sqlite"
    assert app.state.settings.resolved_auth_state_db_path == db_path
    assert isinstance(app.state.admin_sessions, SQLiteAdminSessionStore)
    assert isinstance(app.state.login_attempts, SQLiteLoginAttemptStore)
    assert db_path.exists()


def test_auth_state_store_sqlite_is_ignored_for_trusted_local(monkeypatch, tmp_path):
    db_path = tmp_path / "runtime" / "trusted-local-auth.sqlite3"
    monkeypatch.setenv("INSPECTRA_AUTH_STATE_STORE", "sqlite")
    monkeypatch.setenv("INSPECTRA_AUTH_STATE_DB_PATH", str(db_path))
    configure_test_state(monkeypatch, tmp_path)

    assert app.state.settings.auth_state_store == "sqlite"
    assert isinstance(app.state.admin_sessions, AdminSessionStore)
    assert not isinstance(app.state.admin_sessions, SQLiteAdminSessionStore)
    assert isinstance(app.state.login_attempts, LoginAttemptStore)
    assert not isinstance(app.state.login_attempts, SQLiteLoginAttemptStore)
    assert db_path.exists() is False


def test_auth_state_store_config_rejects_unknown_store(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("INSPECTRA_AUTH_STATE_STORE", "postgres")

    with pytest.raises(ValueError, match="INSPECTRA_AUTH_STATE_STORE"):
        load_settings()


def test_self_hosted_sqlite_session_store_init_failure_fails_closed(monkeypatch, tmp_path):
    db_path = tmp_path / "auth-state-directory"
    db_path.mkdir()
    monkeypatch.setenv("INSPECTRA_AUTH_MODE", "self_hosted_single_admin")
    monkeypatch.setenv("INSPECTRA_ADMIN_PASSWORD_HASH", make_admin_password_hash())
    monkeypatch.setenv("INSPECTRA_AUTH_STATE_STORE", "sqlite")
    monkeypatch.setenv("INSPECTRA_AUTH_STATE_DB_PATH", str(db_path))

    with pytest.raises(SQLiteAuthStateError, match="Unable to initialize"):
        configure_test_state(monkeypatch, tmp_path)


@pytest.mark.parametrize("raw_value", ["0", "-1", "not-a-number"])
def test_session_ttl_config_rejects_invalid_values(monkeypatch, tmp_path, raw_value):
    monkeypatch.setenv("INSPECTRA_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("INSPECTRA_SESSION_TTL_SECONDS", raw_value)

    with pytest.raises(ValueError, match="INSPECTRA_SESSION_TTL_SECONDS"):
        load_settings()


@pytest.mark.parametrize(
    ("env_name", "raw_value"),
    [
        ("INSPECTRA_LOGIN_ATTEMPT_WINDOW_SECONDS", "0"),
        ("INSPECTRA_LOGIN_ATTEMPT_MAX_FAILURES", "-1"),
        ("INSPECTRA_LOGIN_LOCKOUT_SECONDS", "not-a-number"),
        ("INSPECTRA_LOGIN_ATTEMPT_MAX_KEYS", "0"),
    ],
)
def test_login_attempt_config_rejects_invalid_values(monkeypatch, tmp_path, env_name, raw_value):
    monkeypatch.setenv("INSPECTRA_DATA_DIR", str(tmp_path))
    monkeypatch.setenv(env_name, raw_value)

    with pytest.raises(ValueError, match=env_name):
        load_settings()


def test_login_client_key_falls_back_to_unknown_without_request_client():
    request_without_client = type("RequestWithoutClient", (), {"client": None})()
    request_with_blank_client = type(
        "RequestWithBlankClient",
        (),
        {"client": type("Client", (), {"host": " "})()},
    )()

    assert login_client_key_for_request(request_without_client) == "unknown"
    assert login_client_key_for_request(request_with_blank_client) == "unknown"


@pytest.mark.anyio
async def test_auth_status_defaults_to_trusted_local_no_auth(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/auth/status")

    assert response.status_code == 200
    payload = response.json()
    assert payload == {
        "auth_mode": "trusted_local_no_auth",
        "auth_required": False,
        "configured": False,
        "trusted_local": True,
        "default_operator_id": "local-admin",
        "login_available": False,
        "authenticated": False,
        "operator_id": None,
        "csrf_required": False,
        "csrf_token": None,
    }


@pytest.mark.anyio
async def test_auth_status_self_hosted_single_admin_missing_credential(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_AUTH_MODE", "self_hosted_single_admin")
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/auth/status")

    assert response.status_code == 200
    payload = response.json()
    assert payload["auth_mode"] == "self_hosted_single_admin"
    assert payload["auth_required"] is True
    assert payload["configured"] is False
    assert payload["trusted_local"] is False
    assert payload["default_operator_id"] == "local-admin"
    assert payload["login_available"] is False
    assert payload["authenticated"] is False
    assert payload["operator_id"] is None
    assert payload["csrf_required"] is True
    assert payload["csrf_token"] is None


@pytest.mark.anyio
async def test_auth_status_self_hosted_configured_does_not_leak_hash(monkeypatch, tmp_path):
    admin_hash = "argon2id$admin-hash-should-not-render"
    monkeypatch.setenv("INSPECTRA_AUTH_MODE", "self_hosted_single_admin")
    monkeypatch.setenv("INSPECTRA_ADMIN_PASSWORD_HASH", admin_hash)
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/auth/status")

    assert response.status_code == 200
    payload = response.json()
    serialized = json.dumps(payload, sort_keys=True)
    assert payload["auth_mode"] == "self_hosted_single_admin"
    assert payload["auth_required"] is True
    assert payload["configured"] is True
    assert payload["trusted_local"] is False
    assert payload["login_available"] is False
    assert payload["authenticated"] is False
    assert payload["operator_id"] is None
    assert payload["csrf_required"] is True
    assert payload["csrf_token"] is None
    assert "INSPECTRA_ADMIN_PASSWORD_HASH" not in serialized
    assert "admin-hash-should-not-render" not in serialized
    assert admin_hash not in serialized


@pytest.mark.anyio
async def test_auth_status_supported_hash_reports_login_available_and_redacted(monkeypatch, tmp_path):
    admin_hash = make_admin_password_hash()
    monkeypatch.setenv("INSPECTRA_AUTH_MODE", "self_hosted_single_admin")
    monkeypatch.setenv("INSPECTRA_ADMIN_PASSWORD_HASH", admin_hash)
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/auth/status")

    assert response.status_code == 200
    payload = response.json()
    serialized = json.dumps(payload, sort_keys=True)
    assert payload["auth_mode"] == "self_hosted_single_admin"
    assert payload["auth_required"] is True
    assert payload["configured"] is True
    assert payload["trusted_local"] is False
    assert payload["login_available"] is True
    assert payload["authenticated"] is False
    assert payload["operator_id"] is None
    assert payload["csrf_required"] is True
    assert payload["csrf_token"] is None
    assert ADMIN_PASSWORD_FIXTURE not in serialized
    assert admin_hash not in serialized


@pytest.mark.anyio
async def test_self_hosted_login_unavailable_without_hash_fails_generic(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_AUTH_MODE", "self_hosted_single_admin")
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        status_response = await client.get("/auth/status")
        login_response = await client.post("/auth/login", json={"password": ADMIN_PASSWORD_FIXTURE})

    status_payload = status_response.json()
    assert status_payload["configured"] is False
    assert status_payload["login_available"] is False
    assert status_payload["csrf_required"] is True
    assert status_payload["csrf_token"] is None
    assert login_response.status_code == 401
    assert login_response.json() == {"detail": "Invalid credentials."}
    assert "set-cookie" not in login_response.headers
    assert app.state.login_attempts.record_count() == 1


@pytest.mark.anyio
async def test_self_hosted_login_unsupported_hash_fails_generic(monkeypatch, tmp_path):
    admin_hash = "argon2id$admin-hash-should-not-render"
    monkeypatch.setenv("INSPECTRA_AUTH_MODE", "self_hosted_single_admin")
    monkeypatch.setenv("INSPECTRA_ADMIN_PASSWORD_HASH", admin_hash)
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        status_response = await client.get("/auth/status")
        login_response = await client.post("/auth/login", json={"password": ADMIN_PASSWORD_FIXTURE})

    status_payload = status_response.json()
    login_serialized = json.dumps(login_response.json(), sort_keys=True)
    assert status_payload["configured"] is True
    assert status_payload["login_available"] is False
    assert status_payload["csrf_required"] is True
    assert status_payload["csrf_token"] is None
    assert login_response.status_code == 401
    assert login_response.json() == {"detail": "Invalid credentials."}
    assert "admin-hash-should-not-render" not in login_serialized
    assert admin_hash not in login_serialized
    assert "set-cookie" not in login_response.headers
    assert app.state.login_attempts.record_count() == 1


@pytest.mark.anyio
async def test_self_hosted_login_wrong_password_fails_generic(monkeypatch, tmp_path):
    admin_hash = make_admin_password_hash()
    monkeypatch.setenv("INSPECTRA_AUTH_MODE", "self_hosted_single_admin")
    monkeypatch.setenv("INSPECTRA_ADMIN_PASSWORD_HASH", admin_hash)
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        login_response = await client.post("/auth/login", json={"password": "wrong-admin-password"})

    serialized = json.dumps(login_response.json(), sort_keys=True)
    assert login_response.status_code == 401
    assert login_response.json() == {"detail": "Invalid credentials."}
    assert "wrong-admin-password" not in serialized
    assert admin_hash not in serialized
    assert "set-cookie" not in login_response.headers
    assert app.state.login_attempts.record_count() == 1


@pytest.mark.anyio
async def test_self_hosted_login_failures_trigger_rate_limit_and_retry_after(monkeypatch, tmp_path):
    admin_hash = make_admin_password_hash()
    monkeypatch.setenv("INSPECTRA_AUTH_MODE", "self_hosted_single_admin")
    monkeypatch.setenv("INSPECTRA_ADMIN_PASSWORD_HASH", admin_hash)
    monkeypatch.setenv("INSPECTRA_LOGIN_ATTEMPT_MAX_FAILURES", "2")
    monkeypatch.setenv("INSPECTRA_LOGIN_LOCKOUT_SECONDS", "120")
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        first_failure = await client.post("/auth/login", json={"password": "wrong-admin-password"})
        second_failure = await client.post("/auth/login", json={"password": "wrong-admin-password"})
        locked_response = await client.post("/auth/login", json={"password": ADMIN_PASSWORD_FIXTURE})
        status_response = await client.get("/auth/status")

    assert first_failure.status_code == 401
    assert first_failure.json() == {"detail": "Invalid credentials."}
    assert second_failure.status_code == 401
    assert second_failure.json() == {"detail": "Invalid credentials."}
    assert locked_response.status_code == 429
    assert locked_response.json() == {"detail": RATE_LIMITED_DETAIL}
    assert locked_response.headers["retry-after"] == "120"
    assert "set-cookie" not in locked_response.headers
    serialized = json.dumps(locked_response.json(), sort_keys=True)
    assert "wrong-admin-password" not in serialized
    assert ADMIN_PASSWORD_FIXTURE not in serialized
    assert admin_hash not in serialized
    assert "127.0.0.1" not in serialized
    assert "threshold" not in serialized.lower()
    assert status_response.status_code == 200
    assert RATE_LIMITED_DETAIL not in json.dumps(status_response.json(), sort_keys=True)


@pytest.mark.anyio
async def test_self_hosted_login_lockout_expires_and_success_resets(monkeypatch, tmp_path):
    current_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
    admin_hash = make_admin_password_hash()
    monkeypatch.setenv("INSPECTRA_AUTH_MODE", "self_hosted_single_admin")
    monkeypatch.setenv("INSPECTRA_ADMIN_PASSWORD_HASH", admin_hash)
    monkeypatch.setenv("INSPECTRA_LOGIN_ATTEMPT_MAX_FAILURES", "1")
    monkeypatch.setenv("INSPECTRA_LOGIN_LOCKOUT_SECONDS", "10")
    configure_test_state(monkeypatch, tmp_path)
    app.state.login_attempts = LoginAttemptStore(
        window_seconds=app.state.settings.login_attempt_window_seconds,
        max_failures=app.state.settings.login_attempt_max_failures,
        lockout_seconds=app.state.settings.login_lockout_seconds,
        max_keys=app.state.settings.login_attempt_max_keys,
        now_func=lambda: current_time,
    )
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        first_failure = await client.post("/auth/login", json={"password": "wrong-admin-password"})
        locked_success_response = await client.post("/auth/login", json={"password": ADMIN_PASSWORD_FIXTURE})
        current_time = current_time + timedelta(seconds=11)
        unlocked_success_response = await client.post("/auth/login", json={"password": ADMIN_PASSWORD_FIXTURE})

    assert first_failure.status_code == 401
    assert first_failure.json() == {"detail": "Invalid credentials."}
    assert locked_success_response.status_code == 429
    assert locked_success_response.json() == {"detail": RATE_LIMITED_DETAIL}
    assert locked_success_response.headers["retry-after"] == "10"
    assert unlocked_success_response.status_code == 200
    assert unlocked_success_response.json()["authenticated"] is True
    assert app.state.login_attempts.record_count() == 0


@pytest.mark.anyio
async def test_self_hosted_login_success_resets_failure_counter(monkeypatch, tmp_path):
    admin_hash = make_admin_password_hash()
    monkeypatch.setenv("INSPECTRA_AUTH_MODE", "self_hosted_single_admin")
    monkeypatch.setenv("INSPECTRA_ADMIN_PASSWORD_HASH", admin_hash)
    monkeypatch.setenv("INSPECTRA_LOGIN_ATTEMPT_MAX_FAILURES", "3")
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        first_failure = await client.post("/auth/login", json={"password": "wrong-admin-password"})
        assert first_failure.status_code == 401
        assert app.state.login_attempts.record_count() == 1

        success_response = await client.post("/auth/login", json={"password": ADMIN_PASSWORD_FIXTURE})
        assert success_response.status_code == 200
        assert success_response.json()["authenticated"] is True
        assert app.state.login_attempts.record_count() == 0

        second_failure = await client.post("/auth/login", json={"password": "wrong-admin-password"})

    assert second_failure.status_code == 401
    assert app.state.login_attempts.record_count() == 1


@pytest.mark.anyio
async def test_self_hosted_login_rate_limit_ignores_x_forwarded_for(monkeypatch, tmp_path):
    admin_hash = make_admin_password_hash()
    monkeypatch.setenv("INSPECTRA_AUTH_MODE", "self_hosted_single_admin")
    monkeypatch.setenv("INSPECTRA_ADMIN_PASSWORD_HASH", admin_hash)
    monkeypatch.setenv("INSPECTRA_LOGIN_ATTEMPT_MAX_FAILURES", "1")
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        first_failure = await client.post(
            "/auth/login",
            json={"password": "wrong-admin-password"},
            headers={"X-Forwarded-For": "198.51.100.10"},
        )
        locked_response = await client.post(
            "/auth/login",
            json={"password": ADMIN_PASSWORD_FIXTURE},
            headers={"X-Forwarded-For": "203.0.113.10"},
        )

    assert first_failure.status_code == 401
    assert locked_response.status_code == 429
    assert locked_response.json() == {"detail": RATE_LIMITED_DETAIL}
    assert "198.51.100.10" not in json.dumps(locked_response.json(), sort_keys=True)
    assert "203.0.113.10" not in json.dumps(locked_response.json(), sort_keys=True)


@pytest.mark.anyio
async def test_self_hosted_login_success_sets_http_only_session_cookie(monkeypatch, tmp_path):
    admin_hash = make_admin_password_hash()
    monkeypatch.setenv("INSPECTRA_AUTH_MODE", "self_hosted_single_admin")
    monkeypatch.setenv("INSPECTRA_ADMIN_PASSWORD_HASH", admin_hash)
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        login_response = await client.post("/auth/login", json={"password": ADMIN_PASSWORD_FIXTURE})

    payload = login_response.json()
    serialized = json.dumps(payload, sort_keys=True)
    set_cookie = login_response.headers.get("set-cookie", "")
    assert login_response.status_code == 200
    assert payload == {
        "authenticated": True,
        "operator_id": "local-admin",
        "auth_mode": "self_hosted_single_admin",
    }
    assert ADMIN_PASSWORD_FIXTURE not in serialized
    assert admin_hash not in serialized
    assert ADMIN_SESSION_COOKIE_NAME not in serialized
    assert ADMIN_SESSION_COOKIE_NAME in set_cookie
    assert "HttpOnly" in set_cookie
    assert "SameSite=lax" in set_cookie
    assert "Max-Age=3600" in set_cookie
    assert "Path=/" in set_cookie


@pytest.mark.anyio
async def test_self_hosted_login_rejects_non_admin_username(monkeypatch, tmp_path):
    admin_hash = make_admin_password_hash()
    monkeypatch.setenv("INSPECTRA_AUTH_MODE", "self_hosted_single_admin")
    monkeypatch.setenv("INSPECTRA_ADMIN_PASSWORD_HASH", admin_hash)
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        login_response = await client.post(
            "/auth/login",
            json={"username": "another-user", "password": ADMIN_PASSWORD_FIXTURE},
        )

    assert login_response.status_code == 401
    assert login_response.json() == {"detail": "Invalid credentials."}
    assert app.state.login_attempts.record_count() == 1


@pytest.mark.anyio
async def test_trusted_local_no_auth_login_is_not_rate_limited(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_LOGIN_ATTEMPT_MAX_FAILURES", "1")
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        first_response = await client.post("/auth/login", json={"password": "wrong-admin-password"})
        second_response = await client.post("/auth/login", json={"password": "wrong-admin-password"})
        status_response = await client.get("/auth/status")

    assert first_response.status_code == 401
    assert first_response.json() == {"detail": "Invalid credentials."}
    assert second_response.status_code == 401
    assert second_response.json() == {"detail": "Invalid credentials."}
    assert status_response.status_code == 200
    assert status_response.json()["trusted_local"] is True
    assert app.state.login_attempts.record_count() == 0


@pytest.mark.anyio
async def test_self_hosted_session_cookie_allows_protected_route_and_auth_status(monkeypatch, tmp_path):
    admin_hash = make_admin_password_hash()
    monkeypatch.setenv("INSPECTRA_AUTH_MODE", "self_hosted_single_admin")
    monkeypatch.setenv("INSPECTRA_ADMIN_PASSWORD_HASH", admin_hash)
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        denied_response = await client.get("/files")
        login_response = await client.post("/auth/login", json={"password": ADMIN_PASSWORD_FIXTURE})
        files_response = await client.get("/files")
        status_response = await client.get("/auth/status")

    assert denied_response.status_code == 401
    assert denied_response.json() == {"detail": AUTH_REQUIRED_DETAIL}
    assert login_response.status_code == 200
    assert files_response.status_code == 200
    assert files_response.json() == []
    status_payload = status_response.json()
    status_serialized = json.dumps(status_payload, sort_keys=True)
    assert status_payload["login_available"] is True
    assert status_payload["authenticated"] is True
    assert status_payload["operator_id"] == "local-admin"
    assert status_payload["csrf_required"] is True
    assert isinstance(status_payload["csrf_token"], str)
    assert len(status_payload["csrf_token"]) >= 32
    assert ADMIN_PASSWORD_FIXTURE not in status_serialized
    assert admin_hash not in status_serialized
    assert ADMIN_SESSION_COOKIE_NAME not in status_serialized


@pytest.mark.anyio
async def test_self_hosted_csrf_required_for_authenticated_mutating_routes(monkeypatch, tmp_path):
    admin_hash = make_admin_password_hash()
    monkeypatch.setenv("INSPECTRA_AUTH_MODE", "self_hosted_single_admin")
    monkeypatch.setenv("INSPECTRA_ADMIN_PASSWORD_HASH", admin_hash)
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        login_response = await client.post("/auth/login", json={"password": ADMIN_PASSWORD_FIXTURE})
        status_response = await client.get("/auth/status")
        csrf_token = status_response.json()["csrf_token"]
        get_files_response = await client.get("/files")
        missing_token_response = await client.post(
            "/files/pdf",
            files={"file": ("sample.pdf", b"%PDF-1.4\n%%EOF\n", "application/pdf")},
        )
        wrong_token_response = await client.post(
            "/files/pdf",
            headers={"X-CSRF-Token": "wrong-csrf-token"},
            files={"file": ("sample.pdf", b"%PDF-1.4\n%%EOF\n", "application/pdf")},
        )
        correct_token_response = await client.post(
            "/files/pdf",
            headers={"X-CSRF-Token": csrf_token},
            files={"file": ("sample.pdf", b"%PDF-1.4\n%%EOF\n", "application/pdf")},
        )
        files_after_response = await client.get("/files")

    assert login_response.status_code == 200
    assert status_response.status_code == 200
    assert isinstance(status_response.json()["csrf_token"], str)
    assert get_files_response.status_code == 200
    assert missing_token_response.status_code == 403
    assert missing_token_response.json() == {"detail": CSRF_REQUIRED_DETAIL}
    assert wrong_token_response.status_code == 403
    assert wrong_token_response.json() == {"detail": CSRF_REQUIRED_DETAIL}
    assert correct_token_response.status_code == 201
    assert correct_token_response.json()["owner_id"] == DEFAULT_LOCAL_OPERATOR.id
    assert csrf_token not in json.dumps(correct_token_response.json(), sort_keys=True)
    assert csrf_token not in json.dumps(files_after_response.json(), sort_keys=True)


@pytest.mark.anyio
async def test_self_hosted_logout_requires_csrf_and_clears_session(monkeypatch, tmp_path):
    admin_hash = make_admin_password_hash()
    monkeypatch.setenv("INSPECTRA_AUTH_MODE", "self_hosted_single_admin")
    monkeypatch.setenv("INSPECTRA_ADMIN_PASSWORD_HASH", admin_hash)
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        login_response = await client.post("/auth/login", json={"password": ADMIN_PASSWORD_FIXTURE})
        status_response = await client.get("/auth/status")
        missing_token_logout_response = await client.post("/auth/logout")
        wrong_token_logout_response = await client.post("/auth/logout", headers={"X-CSRF-Token": "wrong-csrf-token"})
        allowed_response = await client.get("/files")
        logout_response = await client.post(
            "/auth/logout",
            headers={"X-CSRF-Token": status_response.json()["csrf_token"]},
        )
        denied_response = await client.get("/files")
        second_logout_response = await client.post(
            "/auth/logout",
            headers={"X-CSRF-Token": status_response.json()["csrf_token"]},
        )

    assert login_response.status_code == 200
    assert status_response.status_code == 200
    assert missing_token_logout_response.status_code == 403
    assert missing_token_logout_response.json() == {"detail": CSRF_REQUIRED_DETAIL}
    assert wrong_token_logout_response.status_code == 403
    assert wrong_token_logout_response.json() == {"detail": CSRF_REQUIRED_DETAIL}
    assert allowed_response.status_code == 200
    assert logout_response.status_code == 200
    assert logout_response.json() == {
        "authenticated": False,
        "operator_id": None,
        "auth_mode": "self_hosted_single_admin",
    }
    assert "Max-Age=0" in logout_response.headers.get("set-cookie", "")
    assert denied_response.status_code == 401
    assert denied_response.json() == {"detail": AUTH_REQUIRED_DETAIL}
    assert second_logout_response.status_code == 401


@pytest.mark.anyio
async def test_self_hosted_sqlite_session_persists_auth_status_and_rotates_csrf_after_store_recreate(
    monkeypatch,
    tmp_path,
):
    admin_hash = make_admin_password_hash()
    db_path = tmp_path / "runtime" / "auth_state.sqlite3"
    monkeypatch.setenv("INSPECTRA_AUTH_MODE", "self_hosted_single_admin")
    monkeypatch.setenv("INSPECTRA_ADMIN_PASSWORD_HASH", admin_hash)
    monkeypatch.setenv("INSPECTRA_AUTH_STATE_STORE", "sqlite")
    monkeypatch.setenv("INSPECTRA_AUTH_STATE_DB_PATH", str(db_path))
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        login_response = await client.post("/auth/login", json={"password": ADMIN_PASSWORD_FIXTURE})
        first_status_response = await client.get("/auth/status")
        session_cookie = session_cookie_value(login_response)
        first_csrf_token = first_status_response.json()["csrf_token"]

        app.state.admin_sessions = backend_main.create_admin_session_store(app.state.settings)

        restarted_status_response = await client.get("/auth/status")
        restarted_csrf_token = restarted_status_response.json()["csrf_token"]
        upload_response = await client.post(
            "/files/pdf",
            headers={"X-CSRF-Token": restarted_csrf_token},
            files={"file": ("sample.pdf", b"%PDF-1.4\n%%EOF\n", "application/pdf")},
        )

    assert login_response.status_code == 200
    assert first_status_response.status_code == 200
    assert restarted_status_response.status_code == 200
    assert restarted_status_response.json()["authenticated"] is True
    assert restarted_status_response.json()["operator_id"] == "local-admin"
    assert isinstance(restarted_csrf_token, str)
    assert len(restarted_csrf_token) >= 32
    assert upload_response.status_code == 201
    db_bytes = db_path.read_bytes()
    assert session_cookie.encode("utf-8") not in db_bytes
    assert first_csrf_token.encode("utf-8") not in db_bytes
    assert restarted_csrf_token.encode("utf-8") not in db_bytes
    assert admin_hash.encode("utf-8") not in db_bytes


@pytest.mark.anyio
async def test_self_hosted_sqlite_session_accepts_existing_csrf_hash_after_store_recreate(monkeypatch, tmp_path):
    db_path = tmp_path / "runtime" / "auth_state.sqlite3"
    monkeypatch.setenv("INSPECTRA_AUTH_MODE", "self_hosted_single_admin")
    monkeypatch.setenv("INSPECTRA_ADMIN_PASSWORD_HASH", make_admin_password_hash())
    monkeypatch.setenv("INSPECTRA_AUTH_STATE_STORE", "sqlite")
    monkeypatch.setenv("INSPECTRA_AUTH_STATE_DB_PATH", str(db_path))
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        login_response = await client.post("/auth/login", json={"password": ADMIN_PASSWORD_FIXTURE})
        status_response = await client.get("/auth/status")
        csrf_token = status_response.json()["csrf_token"]

        app.state.admin_sessions = backend_main.create_admin_session_store(app.state.settings)

        upload_response = await client.post(
            "/files/pdf",
            headers={"X-CSRF-Token": csrf_token},
            files={"file": ("sample.pdf", b"%PDF-1.4\n%%EOF\n", "application/pdf")},
        )

    assert login_response.status_code == 200
    assert status_response.status_code == 200
    assert upload_response.status_code == 201
    assert csrf_token.encode("utf-8") not in db_path.read_bytes()


@pytest.mark.anyio
async def test_self_hosted_sqlite_logout_revokes_session_persistently(monkeypatch, tmp_path):
    db_path = tmp_path / "runtime" / "auth_state.sqlite3"
    monkeypatch.setenv("INSPECTRA_AUTH_MODE", "self_hosted_single_admin")
    monkeypatch.setenv("INSPECTRA_ADMIN_PASSWORD_HASH", make_admin_password_hash())
    monkeypatch.setenv("INSPECTRA_AUTH_STATE_STORE", "sqlite")
    monkeypatch.setenv("INSPECTRA_AUTH_STATE_DB_PATH", str(db_path))
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        login_response = await client.post("/auth/login", json={"password": ADMIN_PASSWORD_FIXTURE})
        session_cookie = session_cookie_value(login_response)
        status_response = await client.get("/auth/status")
        logout_response = await client.post(
            "/auth/logout",
            headers={"X-CSRF-Token": status_response.json()["csrf_token"]},
        )

    app.state.admin_sessions = backend_main.create_admin_session_store(app.state.settings)
    async with AsyncClient(
        transport=transport,
        base_url="http://testserver",
        headers={"Cookie": f"{ADMIN_SESSION_COOKIE_NAME}={session_cookie}"},
    ) as restarted_client:
        denied_response = await restarted_client.get("/files")
        restarted_status_response = await restarted_client.get("/auth/status")

    assert login_response.status_code == 200
    assert logout_response.status_code == 200
    assert denied_response.status_code == 401
    assert restarted_status_response.status_code == 200
    assert restarted_status_response.json()["authenticated"] is False
    with sqlite3.connect(db_path) as connection:
        row = connection.execute("SELECT revoked_at, revocation_reason FROM auth_sessions").fetchone()
    assert row is not None
    assert row[0] is not None
    assert row[1] == "logout"


@pytest.mark.anyio
async def test_self_hosted_sqlite_expired_session_is_rejected(monkeypatch, tmp_path):
    db_path = tmp_path / "runtime" / "auth_state.sqlite3"
    monkeypatch.setenv("INSPECTRA_AUTH_MODE", "self_hosted_single_admin")
    monkeypatch.setenv("INSPECTRA_ADMIN_PASSWORD_HASH", make_admin_password_hash())
    monkeypatch.setenv("INSPECTRA_AUTH_STATE_STORE", "sqlite")
    monkeypatch.setenv("INSPECTRA_AUTH_STATE_DB_PATH", str(db_path))
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        login_response = await client.post("/auth/login", json={"password": ADMIN_PASSWORD_FIXTURE})
        with sqlite3.connect(db_path) as connection:
            connection.execute("UPDATE auth_sessions SET expires_at = 0")
            connection.commit()
        app.state.admin_sessions = backend_main.create_admin_session_store(app.state.settings)
        denied_response = await client.get("/files")
        status_response = await client.get("/auth/status")

    assert login_response.status_code == 200
    assert denied_response.status_code == 401
    assert status_response.status_code == 200
    assert status_response.json()["authenticated"] is False


@pytest.mark.anyio
async def test_self_hosted_sqlite_login_attempts_record_failures_in_db_and_redact(monkeypatch, tmp_path):
    admin_hash = make_admin_password_hash()
    db_path = tmp_path / "runtime" / "auth_state.sqlite3"
    monkeypatch.setenv("INSPECTRA_AUTH_MODE", "self_hosted_single_admin")
    monkeypatch.setenv("INSPECTRA_ADMIN_PASSWORD_HASH", admin_hash)
    monkeypatch.setenv("INSPECTRA_AUTH_STATE_STORE", "sqlite")
    monkeypatch.setenv("INSPECTRA_AUTH_STATE_DB_PATH", str(db_path))
    monkeypatch.setenv("INSPECTRA_LOGIN_ATTEMPT_MAX_FAILURES", "3")
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        first_failure = await client.post("/auth/login", json={"password": "wrong-admin-password"})
        second_failure = await client.post("/auth/login", json={"password": "wrong-admin-password"})

    assert isinstance(app.state.admin_sessions, SQLiteAdminSessionStore)
    assert isinstance(app.state.login_attempts, SQLiteLoginAttemptStore)
    assert first_failure.status_code == 401
    assert second_failure.status_code == 401
    with sqlite3.connect(db_path) as connection:
        row = connection.execute(
            "SELECT client_key_hash, failure_count, locked_until FROM auth_login_attempts"
        ).fetchone()
    assert row is not None
    assert len(row[0]) == 64
    assert row[1] == 2
    assert row[2] is None
    db_bytes = db_path.read_bytes()
    assert b"127.0.0.1" not in db_bytes
    assert b"wrong-admin-password" not in db_bytes
    assert ADMIN_PASSWORD_FIXTURE.encode("utf-8") not in db_bytes
    assert admin_hash.encode("utf-8") not in db_bytes


@pytest.mark.anyio
async def test_self_hosted_sqlite_login_lockout_persists_after_store_recreate(monkeypatch, tmp_path):
    db_path = tmp_path / "runtime" / "auth_state.sqlite3"
    monkeypatch.setenv("INSPECTRA_AUTH_MODE", "self_hosted_single_admin")
    monkeypatch.setenv("INSPECTRA_ADMIN_PASSWORD_HASH", make_admin_password_hash())
    monkeypatch.setenv("INSPECTRA_AUTH_STATE_STORE", "sqlite")
    monkeypatch.setenv("INSPECTRA_AUTH_STATE_DB_PATH", str(db_path))
    monkeypatch.setenv("INSPECTRA_LOGIN_ATTEMPT_MAX_FAILURES", "1")
    monkeypatch.setenv("INSPECTRA_LOGIN_LOCKOUT_SECONDS", "120")
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        first_failure = await client.post("/auth/login", json={"password": "wrong-admin-password"})
        app.state.login_attempts = backend_main.create_login_attempt_store(app.state.settings)
        locked_response = await client.post("/auth/login", json={"password": ADMIN_PASSWORD_FIXTURE})

    assert first_failure.status_code == 401
    assert locked_response.status_code == 429
    assert locked_response.json() == {"detail": RATE_LIMITED_DETAIL}
    assert int(locked_response.headers["retry-after"]) > 0
    assert "set-cookie" not in locked_response.headers


@pytest.mark.anyio
async def test_self_hosted_sqlite_successful_login_resets_persistent_attempt(monkeypatch, tmp_path):
    db_path = tmp_path / "runtime" / "auth_state.sqlite3"
    monkeypatch.setenv("INSPECTRA_AUTH_MODE", "self_hosted_single_admin")
    monkeypatch.setenv("INSPECTRA_ADMIN_PASSWORD_HASH", make_admin_password_hash())
    monkeypatch.setenv("INSPECTRA_AUTH_STATE_STORE", "sqlite")
    monkeypatch.setenv("INSPECTRA_AUTH_STATE_DB_PATH", str(db_path))
    monkeypatch.setenv("INSPECTRA_LOGIN_ATTEMPT_MAX_FAILURES", "3")
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        first_failure = await client.post("/auth/login", json={"password": "wrong-admin-password"})
        with sqlite3.connect(db_path) as connection:
            before_success = connection.execute("SELECT COUNT(*) FROM auth_login_attempts").fetchone()[0]
        success_response = await client.post("/auth/login", json={"password": ADMIN_PASSWORD_FIXTURE})
        with sqlite3.connect(db_path) as connection:
            after_success = connection.execute("SELECT COUNT(*) FROM auth_login_attempts").fetchone()[0]

    assert first_failure.status_code == 401
    assert before_success == 1
    assert success_response.status_code == 200
    assert success_response.json()["authenticated"] is True
    assert after_success == 0


def test_self_hosted_sqlite_login_attempt_stores_share_lockout(monkeypatch, tmp_path):
    db_path = tmp_path / "runtime" / "auth_state.sqlite3"
    monkeypatch.setenv("INSPECTRA_AUTH_MODE", "self_hosted_single_admin")
    monkeypatch.setenv("INSPECTRA_ADMIN_PASSWORD_HASH", make_admin_password_hash())
    monkeypatch.setenv("INSPECTRA_AUTH_STATE_STORE", "sqlite")
    monkeypatch.setenv("INSPECTRA_AUTH_STATE_DB_PATH", str(db_path))
    monkeypatch.setenv("INSPECTRA_LOGIN_ATTEMPT_MAX_FAILURES", "1")
    configure_test_state(monkeypatch, tmp_path)

    first_store = backend_main.create_login_attempt_store(app.state.settings)
    second_store = backend_main.create_login_attempt_store(app.state.settings)

    assert isinstance(first_store, SQLiteLoginAttemptStore)
    assert isinstance(second_store, SQLiteLoginAttemptStore)
    first_store.record_failure("203.0.113.140")
    assert second_store.is_locked("203.0.113.140") is True
    assert second_store.seconds_until_unlock("203.0.113.140") > 0


@pytest.mark.anyio
async def test_self_hosted_sqlite_login_rate_limit_ignores_forwarded_headers(monkeypatch, tmp_path):
    db_path = tmp_path / "runtime" / "auth_state.sqlite3"
    monkeypatch.setenv("INSPECTRA_AUTH_MODE", "self_hosted_single_admin")
    monkeypatch.setenv("INSPECTRA_ADMIN_PASSWORD_HASH", make_admin_password_hash())
    monkeypatch.setenv("INSPECTRA_AUTH_STATE_STORE", "sqlite")
    monkeypatch.setenv("INSPECTRA_AUTH_STATE_DB_PATH", str(db_path))
    monkeypatch.setenv("INSPECTRA_LOGIN_ATTEMPT_MAX_FAILURES", "1")
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        first_failure = await client.post(
            "/auth/login",
            json={"password": "wrong-admin-password"},
            headers={
                "X-Forwarded-For": "198.51.100.10",
                "X-Forwarded-Proto": "https",
                "Forwarded": "for=198.51.100.10;proto=https",
            },
        )
        locked_response = await client.post(
            "/auth/login",
            json={"password": ADMIN_PASSWORD_FIXTURE},
            headers={
                "X-Forwarded-For": "203.0.113.10",
                "X-Forwarded-Proto": "https",
                "Forwarded": "for=203.0.113.10;proto=https",
            },
        )

    assert first_failure.status_code == 401
    assert locked_response.status_code == 429
    db_bytes = db_path.read_bytes()
    assert b"198.51.100.10" not in db_bytes
    assert b"203.0.113.10" not in db_bytes


@pytest.mark.anyio
async def test_self_hosted_sqlite_sessions_still_work_with_persistent_attempts(monkeypatch, tmp_path):
    db_path = tmp_path / "runtime" / "auth_state.sqlite3"
    monkeypatch.setenv("INSPECTRA_AUTH_MODE", "self_hosted_single_admin")
    monkeypatch.setenv("INSPECTRA_ADMIN_PASSWORD_HASH", make_admin_password_hash())
    monkeypatch.setenv("INSPECTRA_AUTH_STATE_STORE", "sqlite")
    monkeypatch.setenv("INSPECTRA_AUTH_STATE_DB_PATH", str(db_path))
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        login_response = await client.post("/auth/login", json={"password": ADMIN_PASSWORD_FIXTURE})
        app.state.admin_sessions = backend_main.create_admin_session_store(app.state.settings)
        app.state.login_attempts = backend_main.create_login_attempt_store(app.state.settings)
        status_response = await client.get("/auth/status")
        upload_response = await client.post(
            "/files/pdf",
            headers={"X-CSRF-Token": status_response.json()["csrf_token"]},
            files={"file": ("sample.pdf", b"%PDF-1.4\n%%EOF\n", "application/pdf")},
        )

    assert login_response.status_code == 200
    assert status_response.status_code == 200
    assert status_response.json()["authenticated"] is True
    assert upload_response.status_code == 201


@pytest.mark.anyio
async def test_self_hosted_single_admin_allows_anonymous_public_safe_routes(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_AUTH_MODE", "self_hosted_single_admin")
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        health_response = await client.get("/health")
        auth_response = await client.get("/auth/status")

    assert health_response.status_code == 200
    assert health_response.json() == {"status": "ok", "service": "inspectra-backend"}
    assert auth_response.status_code == 200
    assert auth_response.json()["auth_required"] is True


@pytest.mark.anyio
async def test_self_hosted_single_admin_denies_anonymous_logout_before_csrf(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_AUTH_MODE", "self_hosted_single_admin")
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post("/auth/logout")

    assert response.status_code == 401
    assert response.json() == {"detail": AUTH_REQUIRED_DETAIL}


@pytest.mark.anyio
async def test_self_hosted_single_admin_denies_anonymous_file_routes(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_AUTH_MODE", "self_hosted_single_admin")
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        responses = [
            await client.get("/files"),
            await client.get("/files/not-a-file-id"),
            await client.post(
                "/files/pdf",
                files={"file": ("sample.pdf", b"%PDF-1.4\n%%EOF\n", "application/pdf")},
            ),
            await client.delete("/files/not-a-file-id"),
        ]

    for response in responses:
        assert response.status_code == 401
        assert response.json() == {"detail": AUTH_REQUIRED_DETAIL}


@pytest.mark.anyio
async def test_self_hosted_single_admin_denies_anonymous_audit_job_and_export_routes(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_AUTH_MODE", "self_hosted_single_admin")
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        responses = [
            await client.post("/audits/pdf/not-a-file-id"),
            await client.get("/jobs"),
            await client.get("/jobs/not-a-job-id"),
            await client.get("/jobs/not-a-job-id/export/markdown"),
            await client.get("/jobs/not-a-job-id/sbom/cyclonedx-json"),
        ]

    for response in responses:
        assert response.status_code == 401
        assert response.json() == {"detail": AUTH_REQUIRED_DETAIL}


@pytest.mark.anyio
async def test_self_hosted_single_admin_denies_anonymous_target_and_active_routes(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_AUTH_MODE", "self_hosted_single_admin")
    monkeypatch.setenv("INSPECTRA_ACTIVE_DRY_RUN_ENABLED", "true")
    monkeypatch.setenv("INSPECTRA_ACTIVE_HTTP_HEADER_PROBE_ENABLED", "true")
    monkeypatch.setenv("INSPECTRA_ACTIVE_NMAP_BASIC_ENABLED", "true")
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        responses = [
            await client.post("/audits/web/basic", json={}),
            await client.post("/audits/domain/basic", json={}),
            await client.post("/audits/subdomains/basic", json={}),
            await client.post("/active/network/dry-run", json={}),
            await client.post("/active/network/http-header-probe", json={}),
            await client.post("/active/network/nmap-basic", json={}),
        ]

    for response in responses:
        assert response.status_code == 401
        assert response.json() == {"detail": AUTH_REQUIRED_DETAIL}


@pytest.mark.anyio
async def test_trusted_local_uploads_write_owner_metadata(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        pdf_response = await client.post(
            "/files/pdf",
            files={"file": ("sample.pdf", b"%PDF-1.4\n%%EOF\n", "application/pdf")},
        )
        manifest_response = await client.post(
            "/files/manifest",
            files={"file": ("package.json", SAMPLE_PACKAGE_JSON, "application/json")},
        )
        archive_response = await client.post(
            "/files/archive",
            files={"file": ("sample.zip", make_zip_bytes({"README.md": b"hello"}), "application/zip")},
        )
        list_response = await client.get("/files")

    for response in (pdf_response, manifest_response, archive_response):
        assert response.status_code in {201, 202}
        payload = response.json()
        assert payload["owner_id"] == DEFAULT_LOCAL_OPERATOR.id
        stored = app.state.files.get(payload["id"])
        assert stored.owner_id == DEFAULT_LOCAL_OPERATOR.id
    assert {item["owner_id"] for item in list_response.json()} == {DEFAULT_LOCAL_OPERATOR.id}


@pytest.mark.anyio
async def test_trusted_local_file_based_jobs_write_and_preserve_owner_metadata(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    app.state.pdf_audits = NoopAuditService()
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        file_response = await client.post(
            "/files/pdf",
            files={"file": ("sample.pdf", b"%PDF-1.4\n%%EOF\n", "application/pdf")},
        )
        job_response = await client.post(f"/audits/pdf/{file_response.json()['id']}")
        jobs_response = await client.get("/jobs")

    job_id = job_response.json()["id"]
    assert job_response.status_code == 202
    assert job_response.json()["owner_id"] == DEFAULT_LOCAL_OPERATOR.id
    assert app.state.jobs.get(job_id).owner_id == DEFAULT_LOCAL_OPERATOR.id
    assert next(item for item in jobs_response.json() if item["id"] == job_id)["owner_id"] == DEFAULT_LOCAL_OPERATOR.id

    updated = app.state.jobs.update(job_id, status="completed", result={"analyzer": "pdf_basic", "summary": {}})
    assert updated.owner_id == DEFAULT_LOCAL_OPERATOR.id
    assert app.state.jobs.get(job_id).owner_id == DEFAULT_LOCAL_OPERATOR.id


@pytest.mark.anyio
async def test_trusted_local_target_based_jobs_write_owner_metadata(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    app.state.web_audits = NoopAuditService()
    app.state.domain_audits = NoopAuditService()
    app.state.subdomain_inventory_audits = NoopAuditService()
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        web_response = await client.post(
            "/audits/web/basic",
            json={"url": "https://example.com/status", "authorization_confirmed": True},
        )
        domain_response = await client.post(
            "/audits/domain/basic",
            json={"domain": "example.com", "authorization_confirmed": True},
        )
        subdomain_response = await client.post(
            "/audits/subdomains/basic",
            json={"root_domain": "example.com", "subdomains": ["www"], "authorization_confirmed": True},
        )
        jobs_response = await client.get("/jobs")

    for response in (web_response, domain_response, subdomain_response):
        assert response.status_code == 202
        payload = response.json()
        assert payload["file_id"] is None
        assert payload["owner_id"] == DEFAULT_LOCAL_OPERATOR.id
        assert app.state.jobs.get(payload["id"]).owner_id == DEFAULT_LOCAL_OPERATOR.id
    assert {item["owner_id"] for item in jobs_response.json()} == {DEFAULT_LOCAL_OPERATOR.id}


@pytest.mark.anyio
async def test_trusted_local_active_jobs_write_owner_metadata_without_live_probe(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_ACTIVE_DRY_RUN_ENABLED", "true")
    monkeypatch.setenv("INSPECTRA_ACTIVE_HTTP_HEADER_PROBE_ENABLED", "true")
    configure_test_state(monkeypatch, tmp_path)
    app.state.active_network_dry_runs = NoopAuditService()
    app.state.active_http_header_probes = NoopAuditService()
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        dry_run_response = await client.post("/active/network/dry-run", json=make_active_dry_run_payload())
        header_response = await client.post(
            "/active/network/http-header-probe",
            json=make_active_http_header_probe_payload("http://10.0.0.1/"),
        )
        jobs_response = await client.get("/jobs")

    for response in (dry_run_response, header_response):
        assert response.status_code == 202
        payload = response.json()
        assert payload["file_id"] is None
        assert payload["owner_id"] == DEFAULT_LOCAL_OPERATOR.id
        assert app.state.jobs.get(payload["id"]).owner_id == DEFAULT_LOCAL_OPERATOR.id
    assert {item["owner_id"] for item in jobs_response.json()} == {DEFAULT_LOCAL_OPERATOR.id}


@pytest.mark.anyio
async def test_trusted_local_legacy_ownerless_records_remain_compatible(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    created_at = datetime.now(timezone.utc).isoformat()
    file_id = "1" * 32
    job_id = "2" * 32
    target_job_id = "3" * 32
    (app.state.settings.upload_dir / f"{file_id}.json").write_text(
        json.dumps(
            {
                "id": file_id,
                "kind": "pdf",
                "original_filename": "legacy.pdf",
                "stored_filename": f"{file_id}.pdf",
                "content_type": "application/pdf",
                "size_bytes": 11,
                "sha256": "0" * 64,
                "created_at": created_at,
            }
        ),
        encoding="utf-8",
    )
    (app.state.settings.jobs_dir / f"{job_id}.json").write_text(
        json.dumps(
            {
                "id": job_id,
                "audit_type": "pdf_basic",
                "file_id": file_id,
                "status": "queued",
                "created_at": created_at,
                "updated_at": created_at,
            }
        ),
        encoding="utf-8",
    )
    (app.state.settings.jobs_dir / f"{target_job_id}.json").write_text(
        json.dumps(
            {
                "id": target_job_id,
                "audit_type": "web_basic",
                "file_id": None,
                "target_url": "https://example.com/status",
                "status": "queued",
                "created_at": created_at,
                "updated_at": created_at,
            }
        ),
        encoding="utf-8",
    )
    manifest_job = save_export_fixture_job()
    updated = app.state.jobs.update(job_id, status="completed", result={"analyzer": "pdf_basic", "summary": {}})
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        file_response = await client.get(f"/files/{file_id}")
        files_response = await client.get("/files")
        job_response = await client.get(f"/jobs/{job_id}")
        target_job_response = await client.get(f"/jobs/{target_job_id}")
        manifest_job_response = await client.get(f"/jobs/{manifest_job.id}")
        jobs_response = await client.get("/jobs")
        export_response = await client.get(f"/jobs/{job_id}/export/markdown")
        sbom_response = await client.get(f"/jobs/{manifest_job.id}/sbom/cyclonedx-json")

    assert file_response.status_code == 200
    assert file_response.json()["owner_id"] == DEFAULT_LOCAL_OPERATOR.id
    assert files_response.json()[0]["owner_id"] == DEFAULT_LOCAL_OPERATOR.id
    assert job_response.status_code == 200
    assert job_response.json()["owner_id"] == DEFAULT_LOCAL_OPERATOR.id
    assert target_job_response.status_code == 200
    assert target_job_response.json()["owner_id"] == DEFAULT_LOCAL_OPERATOR.id
    assert manifest_job_response.status_code == 200
    assert manifest_job_response.json()["owner_id"] == DEFAULT_LOCAL_OPERATOR.id
    listed_jobs = {item["id"]: item for item in jobs_response.json()}
    assert listed_jobs[job_id]["owner_id"] == DEFAULT_LOCAL_OPERATOR.id
    assert listed_jobs[target_job_id]["owner_id"] == DEFAULT_LOCAL_OPERATOR.id
    assert listed_jobs[manifest_job.id]["owner_id"] == DEFAULT_LOCAL_OPERATOR.id
    assert updated.owner_id == DEFAULT_LOCAL_OPERATOR.id
    saved_payload = json.loads((app.state.settings.jobs_dir / f"{job_id}.json").read_text(encoding="utf-8"))
    assert saved_payload["owner_id"] == DEFAULT_LOCAL_OPERATOR.id
    assert export_response.status_code == 200
    assert sbom_response.status_code == 200


@pytest.mark.anyio
async def test_owner_scoped_reads_filter_and_deny_wrong_owner_resources(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    created_at = datetime.now(timezone.utc).isoformat()
    local_file_id = "4" * 32
    legacy_file_id = "5" * 32
    other_file_id = "6" * 32
    local_job_id = "7" * 32
    legacy_job_id = "8" * 32
    other_job_id = "9" * 32
    other_target_job_id = "a" * 32
    other_failed_job_id = "b" * 32

    def write_file(file_id: str, *, owner_id: str | None = DEFAULT_LOCAL_OPERATOR.id) -> None:
        payload = {
            "id": file_id,
            "kind": "pdf",
            "original_filename": f"{file_id}.pdf",
            "stored_filename": f"{file_id}.pdf",
            "content_type": "application/pdf",
            "size_bytes": 11,
            "sha256": "0" * 64,
            "created_at": created_at,
        }
        if owner_id is not None:
            payload["owner_id"] = owner_id
        (app.state.settings.upload_dir / f"{file_id}.json").write_text(json.dumps(payload), encoding="utf-8")

    def write_job(
        job_id: str,
        *,
        owner_id: str | None = DEFAULT_LOCAL_OPERATOR.id,
        audit_type: str = "pdf_basic",
        file_id: str | None = local_file_id,
        status: str = "queued",
        target_url: str | None = None,
        result: dict | None = None,
        error: str | None = None,
    ) -> None:
        payload = {
            "id": job_id,
            "audit_type": audit_type,
            "file_id": file_id,
            "target_url": target_url,
            "status": status,
            "created_at": created_at,
            "updated_at": created_at,
            "result": result,
            "error": error,
        }
        if owner_id is not None:
            payload["owner_id"] = owner_id
        (app.state.settings.jobs_dir / f"{job_id}.json").write_text(json.dumps(payload), encoding="utf-8")

    write_file(local_file_id)
    write_file(legacy_file_id, owner_id=None)
    write_file(other_file_id, owner_id="other-owner")
    write_job(local_job_id, result={"analyzer": "pdf_basic", "summary": {}})
    write_job(legacy_job_id, owner_id=None, file_id=legacy_file_id)
    write_job(other_job_id, owner_id="other-owner", file_id=other_file_id)
    write_job(
        other_target_job_id,
        owner_id="other-owner",
        audit_type="web_basic",
        file_id=None,
        target_url="https://other.example/status",
    )
    write_job(
        other_failed_job_id,
        owner_id="other-owner",
        audit_type="pdf_basic",
        file_id=other_file_id,
        status="failed",
        error="controlled wrong-owner failure",
    )
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        files_response = await client.get("/files")
        jobs_response = await client.get("/jobs")
        local_file_response = await client.get(f"/files/{local_file_id}")
        legacy_file_response = await client.get(f"/files/{legacy_file_id}")
        other_file_response = await client.get(f"/files/{other_file_id}")
        local_job_response = await client.get(f"/jobs/{local_job_id}")
        legacy_job_response = await client.get(f"/jobs/{legacy_job_id}")
        other_job_response = await client.get(f"/jobs/{other_job_id}")
        other_target_job_response = await client.get(f"/jobs/{other_target_job_id}")
        other_failed_job_response = await client.get(f"/jobs/{other_failed_job_id}")
        other_file_audit_response = await client.post(f"/audits/pdf/{other_file_id}")

    visible_file_ids = {item["id"] for item in files_response.json()}
    visible_job_ids = {item["id"] for item in jobs_response.json()}
    assert visible_file_ids == {local_file_id, legacy_file_id}
    assert visible_job_ids == {local_job_id, legacy_job_id}
    assert local_file_response.status_code == 200
    assert legacy_file_response.status_code == 200
    assert local_file_response.json()["owner_id"] == DEFAULT_LOCAL_OPERATOR.id
    assert legacy_file_response.json()["owner_id"] == DEFAULT_LOCAL_OPERATOR.id
    assert other_file_response.status_code == 404
    assert other_file_response.json()["detail"] == "File not found."
    assert local_job_response.status_code == 200
    assert legacy_job_response.status_code == 200
    assert local_job_response.json()["owner_id"] == DEFAULT_LOCAL_OPERATOR.id
    assert legacy_job_response.json()["owner_id"] == DEFAULT_LOCAL_OPERATOR.id
    for response in (other_job_response, other_target_job_response, other_failed_job_response):
        assert response.status_code == 404
        assert response.json()["detail"] == "Job not found."
    assert other_file_audit_response.status_code == 404
    assert other_file_audit_response.json()["detail"] == "File not found."


@pytest.mark.anyio
async def test_owner_scoped_exports_and_sbom_deny_wrong_owner_before_render(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    now = datetime.now(timezone.utc)
    wrong_job = JobRecord(
        id="c" * 32,
        owner_id="other-owner",
        audit_type="manifest_basic",
        file_id="d" * 32,
        status="completed",
        created_at=now,
        updated_at=now,
        result={
            "analyzer": "manifest_basic",
            "manifest_type": "package_json",
            "parsed": {
                "project": {"name": "wrong-owner"},
                "dependencies": {"dependencies": [{"name": "fastapi", "specifier": "0.115.0"}]},
            },
        },
    )
    app.state.jobs.save(wrong_job)

    def fail_render(*args, **kwargs):
        raise AssertionError("wrong-owner export rendered before owner check")

    def fail_sbom(*args, **kwargs):
        raise AssertionError("wrong-owner SBOM generated before owner check")

    monkeypatch.setattr(backend_main, "render_markdown_report", fail_render)
    monkeypatch.setattr(backend_main, "render_html_report", fail_render)
    monkeypatch.setattr(backend_main, "render_xml_report", fail_render)
    monkeypatch.setattr(backend_main, "render_pdf_report", fail_render)
    monkeypatch.setattr(backend_main, "generate_cyclonedx_json", fail_sbom)
    monkeypatch.setattr(backend_main, "generate_spdx_json", fail_sbom)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        export_responses = [
            await client.get(f"/jobs/{wrong_job.id}/export/{report_format}")
            for report_format in ("markdown", "html", "xml", "pdf")
        ]
        sbom_responses = [
            await client.get(f"/jobs/{wrong_job.id}/sbom/cyclonedx-json"),
            await client.get(f"/jobs/{wrong_job.id}/sbom/spdx-json"),
        ]

    for response in export_responses + sbom_responses:
        assert response.status_code == 404
        assert response.json()["detail"] == "Job not found."


@pytest.mark.anyio
async def test_self_hosted_single_admin_denies_anonymous_writes_before_owner_metadata(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_AUTH_MODE", "self_hosted_single_admin")
    monkeypatch.setenv("INSPECTRA_ACTIVE_DRY_RUN_ENABLED", "true")
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        upload_response = await client.post(
            "/files/pdf",
            files={"file": ("sample.pdf", b"%PDF-1.4\n%%EOF\n", "application/pdf")},
        )
        target_response = await client.post(
            "/audits/web/basic",
            json={"url": "https://example.com/status", "authorization_confirmed": True},
        )
        active_response = await client.post("/active/network/dry-run", json=make_active_dry_run_payload())

    assert upload_response.status_code == 401
    assert target_response.status_code == 401
    assert active_response.status_code == 401
    assert app.state.files.list() == []
    assert app.state.jobs.list() == []


@pytest.mark.anyio
async def test_pdf_upload_creates_record(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    sample_pdf = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\n%%EOF\n"
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/files/pdf",
            files={"file": ("sample.pdf", sample_pdf, "application/pdf")},
        )

    assert response.status_code == 201
    payload = response.json()
    assert payload["original_filename"] == "sample.pdf"
    assert payload["kind"] == "pdf"
    assert payload["stored_filename"].endswith(".pdf")
    assert (tmp_path / "uploads" / payload["stored_filename"]).exists()


@pytest.mark.anyio
async def test_image_upload_creates_record(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/files/image",
            files={"file": ("pixel.png", SAMPLE_PNG, "image/png")},
        )

    assert response.status_code == 201
    payload = response.json()
    assert payload["kind"] == "image"
    assert payload["content_type"] == "image/png"
    assert payload["stored_filename"].endswith(".png")
    assert (tmp_path / "uploads" / payload["stored_filename"]).exists()


@pytest.mark.anyio
async def test_image_upload_rejects_unsupported_format(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/files/image",
            files={"file": ("note.txt", b"not an image", "text/plain")},
        )

    assert response.status_code == 400
    assert "JPEG, PNG, and WebP" in response.json()["detail"]


@pytest.mark.anyio
async def test_manifest_upload_accepts_package_json(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/files/manifest",
            files={"file": ("package.json", SAMPLE_PACKAGE_JSON, "application/json")},
        )
        list_response = await client.get("/files")

    assert response.status_code == 201
    payload = response.json()
    assert payload["kind"] == "manifest"
    assert payload["content_type"] == "application/json"
    assert payload["stored_filename"].endswith("-package.json")
    assert (tmp_path / "uploads" / payload["stored_filename"]).exists()
    assert list_response.status_code == 200
    files_payload = list_response.json()
    assert len(files_payload) == 1
    assert files_payload[0]["id"] == payload["id"]
    assert files_payload[0]["kind"] == "manifest"
    assert files_payload[0]["original_filename"] == "package.json"


@pytest.mark.anyio
async def test_manifest_upload_accepts_requirements_txt(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/files/manifest",
            files={"file": ("requirements.txt", SAMPLE_REQUIREMENTS, "text/plain")},
        )

    assert response.status_code == 201
    payload = response.json()
    assert payload["kind"] == "manifest"
    assert payload["content_type"] == "text/plain"
    assert payload["stored_filename"].endswith("-requirements.txt")


@pytest.mark.anyio
async def test_manifest_upload_accepts_pyproject_toml(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/files/manifest",
            files={"file": ("pyproject.toml", SAMPLE_PYPROJECT, "application/toml")},
        )

    assert response.status_code == 201
    payload = response.json()
    assert payload["kind"] == "manifest"
    assert payload["content_type"] == "application/toml"
    assert payload["stored_filename"].endswith("-pyproject.toml")


@pytest.mark.anyio
async def test_manifest_upload_rejects_unsupported_file(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/files/manifest",
            files={"file": ("setup.py", b"print('nope')\n", "text/x-python")},
        )

    assert response.status_code == 400
    assert "package.json, requirements.txt, and pyproject.toml" in response.json()["detail"]


@pytest.mark.anyio
async def test_archive_upload_accepts_zip(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    sample_zip = make_zip_bytes({"src/app.py": b"print('hello')\n", "package.json": SAMPLE_PACKAGE_JSON})
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/files/archive",
            files={"file": ("project.zip", sample_zip, "application/zip")},
        )
        list_response = await client.get("/files")

    assert response.status_code == 201
    payload = response.json()
    assert payload["kind"] == "archive"
    assert payload["content_type"] == "application/zip"
    assert payload["stored_filename"].endswith(".zip")
    assert (tmp_path / "uploads" / payload["stored_filename"]).exists()
    assert list_response.json()[0]["kind"] == "archive"


@pytest.mark.anyio
async def test_archive_upload_accepts_tar_gz(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    sample_tar_gz = make_tar_bytes({"README.md": b"# demo\n"}, gzipped=True)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/files/archive",
            files={"file": ("project.tar.gz", sample_tar_gz, "application/gzip")},
        )

    assert response.status_code == 201
    payload = response.json()
    assert payload["kind"] == "archive"
    assert payload["content_type"] == "application/gzip"
    assert payload["stored_filename"].endswith(".tar.gz")


@pytest.mark.anyio
async def test_archive_upload_rejects_unsupported_file(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/files/archive",
            files={"file": ("project.rar", b"not supported", "application/octet-stream")},
        )

    assert response.status_code == 400
    assert ".zip, .tar, .tar.gz, and .tgz" in response.json()["detail"]


@pytest.mark.anyio
async def test_manifest_upload_size_limit_returns_clear_error(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path, max_upload_bytes=10)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/files/manifest",
            files={"file": ("requirements.txt", SAMPLE_REQUIREMENTS, "text/plain")},
        )

    assert response.status_code == 413
    assert "Maximum allowed size is 10 bytes" in response.json()["detail"]


@pytest.mark.anyio
async def test_list_files_does_not_expose_absolute_paths(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        await client.post("/files/pdf", files={"file": ("a.pdf", b"%PDF-1.4\n%%EOF\n", "application/pdf")})
        await client.post("/files/pdf", files={"file": ("b.pdf", b"%PDF-1.4\n%%EOF\n", "application/pdf")})
        response = await client.get("/files")

    assert response.status_code == 200
    payload = response.json()
    assert len(payload) == 2
    assert "path" not in payload[0]
    assert all(not value.startswith("/") for item in payload for value in item.values() if isinstance(value, str))


@pytest.mark.anyio
async def test_legacy_file_metadata_without_kind_defaults_to_pdf(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    file_id = "c" * 32
    legacy_payload = {
        "id": file_id,
        "original_filename": "legacy.pdf",
        "stored_filename": f"{file_id}.pdf",
        "content_type": "application/pdf",
        "size_bytes": 10,
        "sha256": "abc",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    (tmp_path / "uploads" / f"{file_id}.json").write_text(json.dumps(legacy_payload), encoding="utf-8")
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get(f"/files/{file_id}")

    assert response.status_code == 200
    assert response.json()["kind"] == "pdf"


@pytest.mark.anyio
async def test_upload_size_limit_returns_clear_error(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path, max_upload_bytes=10)
    transport = ASGITransport(app=app)
    oversized_pdf = b"%PDF-1.4\n" + b"x" * 20

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/files/pdf",
            files={"file": ("large.pdf", oversized_pdf, "application/pdf")},
        )

    assert response.status_code == 413
    assert "Maximum allowed size is 10 bytes" in response.json()["detail"]


@pytest.mark.anyio
async def test_image_upload_size_limit_returns_clear_error(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path, max_upload_bytes=10)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/files/image",
            files={"file": ("large.png", SAMPLE_PNG + b"x" * 20, "image/png")},
        )

    assert response.status_code == 413
    assert "Maximum allowed size is 10 bytes" in response.json()["detail"]


@pytest.mark.anyio
async def test_image_audit_job_creation_and_cross_type_rejections(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    noop = NoopAuditService()
    app.state.pdf_audits = noop
    app.state.image_audits = noop
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        pdf_response = await client.post("/files/pdf", files={"file": ("sample.pdf", b"%PDF-1.4\n%%EOF\n", "application/pdf")})
        image_response = await client.post("/files/image", files={"file": ("pixel.png", SAMPLE_PNG, "image/png")})
        pdf_file = pdf_response.json()
        image_file = image_response.json()

        image_job_response = await client.post(f"/audits/image/{image_file['id']}")
        image_as_pdf_response = await client.post(f"/audits/pdf/{image_file['id']}")
        pdf_as_image_response = await client.post(f"/audits/image/{pdf_file['id']}")

    assert image_job_response.status_code == 202
    assert image_job_response.json()["audit_type"] == "image_basic"
    assert image_as_pdf_response.status_code == 400
    assert image_as_pdf_response.json()["detail"] == "File is not a PDF."
    assert pdf_as_image_response.status_code == 400
    assert pdf_as_image_response.json()["detail"] == "File is not an image."


@pytest.mark.anyio
async def test_manifest_audit_job_creation_and_cross_type_rejections(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    noop = NoopAuditService()
    app.state.pdf_audits = noop
    app.state.image_audits = noop
    app.state.manifest_audits = noop
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        pdf_response = await client.post("/files/pdf", files={"file": ("sample.pdf", b"%PDF-1.4\n%%EOF\n", "application/pdf")})
        image_response = await client.post("/files/image", files={"file": ("pixel.png", SAMPLE_PNG, "image/png")})
        manifest_response = await client.post(
            "/files/manifest",
            files={"file": ("package.json", SAMPLE_PACKAGE_JSON, "application/json")},
        )
        pdf_file = pdf_response.json()
        image_file = image_response.json()
        manifest_file = manifest_response.json()

        manifest_job_response = await client.post(f"/audits/manifest/{manifest_file['id']}")
        manifest_as_pdf_response = await client.post(f"/audits/pdf/{manifest_file['id']}")
        manifest_as_image_response = await client.post(f"/audits/image/{manifest_file['id']}")
        pdf_as_manifest_response = await client.post(f"/audits/manifest/{pdf_file['id']}")
        image_as_manifest_response = await client.post(f"/audits/manifest/{image_file['id']}")

    assert manifest_job_response.status_code == 202
    assert manifest_job_response.json()["audit_type"] == "manifest_basic"
    assert manifest_as_pdf_response.status_code == 400
    assert manifest_as_pdf_response.json()["detail"] == "File is not a PDF."
    assert manifest_as_image_response.status_code == 400
    assert manifest_as_image_response.json()["detail"] == "File is not an image."
    assert pdf_as_manifest_response.status_code == 400
    assert pdf_as_manifest_response.json()["detail"] == "File is not a manifest."
    assert image_as_manifest_response.status_code == 400
    assert image_as_manifest_response.json()["detail"] == "File is not a manifest."


@pytest.mark.anyio
async def test_archive_audit_job_creation_and_cross_type_rejections(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    noop = NoopAuditService()
    app.state.pdf_audits = noop
    app.state.image_audits = noop
    app.state.manifest_audits = noop
    app.state.archive_audits = noop
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        pdf_response = await client.post("/files/pdf", files={"file": ("sample.pdf", b"%PDF-1.4\n%%EOF\n", "application/pdf")})
        image_response = await client.post("/files/image", files={"file": ("pixel.png", SAMPLE_PNG, "image/png")})
        manifest_response = await client.post(
            "/files/manifest",
            files={"file": ("package.json", SAMPLE_PACKAGE_JSON, "application/json")},
        )
        archive_response = await client.post(
            "/files/archive",
            files={"file": ("project.zip", make_zip_bytes({"package.json": SAMPLE_PACKAGE_JSON}), "application/zip")},
        )
        pdf_file = pdf_response.json()
        image_file = image_response.json()
        manifest_file = manifest_response.json()
        archive_file = archive_response.json()

        archive_job_response = await client.post(f"/audits/archive/{archive_file['id']}")
        archive_as_pdf_response = await client.post(f"/audits/pdf/{archive_file['id']}")
        archive_as_image_response = await client.post(f"/audits/image/{archive_file['id']}")
        archive_as_manifest_response = await client.post(f"/audits/manifest/{archive_file['id']}")
        pdf_as_archive_response = await client.post(f"/audits/archive/{pdf_file['id']}")
        image_as_archive_response = await client.post(f"/audits/archive/{image_file['id']}")
        manifest_as_archive_response = await client.post(f"/audits/archive/{manifest_file['id']}")

    assert archive_job_response.status_code == 202
    assert archive_job_response.json()["audit_type"] == "archive_basic"
    assert archive_as_pdf_response.status_code == 400
    assert archive_as_pdf_response.json()["detail"] == "File is not a PDF."
    assert archive_as_image_response.status_code == 400
    assert archive_as_image_response.json()["detail"] == "File is not an image."
    assert archive_as_manifest_response.status_code == 400
    assert archive_as_manifest_response.json()["detail"] == "File is not a manifest."
    assert pdf_as_archive_response.status_code == 400
    assert pdf_as_archive_response.json()["detail"] == "File is not an archive."
    assert image_as_archive_response.status_code == 400
    assert image_as_archive_response.json()["detail"] == "File is not an archive."
    assert manifest_as_archive_response.status_code == 400
    assert manifest_as_archive_response.json()["detail"] == "File is not an archive."


@pytest.mark.anyio
async def test_project_archive_audit_job_creation_and_rejections(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    noop = NoopAuditService()
    app.state.project_archive_audits = noop
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        pdf_response = await client.post("/files/pdf", files={"file": ("sample.pdf", b"%PDF-1.4\n%%EOF\n", "application/pdf")})
        archive_response = await client.post(
            "/files/archive",
            files={"file": ("project.zip", make_zip_bytes({"package.json": SAMPLE_PACKAGE_JSON}), "application/zip")},
        )
        pdf_file = pdf_response.json()
        archive_file = archive_response.json()

        project_archive_response = await client.post(f"/audits/project-archive/{archive_file['id']}")
        pdf_as_project_archive_response = await client.post(f"/audits/project-archive/{pdf_file['id']}")
        invalid_response = await client.post("/audits/project-archive/not-a-file-id")

    assert project_archive_response.status_code == 202
    assert project_archive_response.json()["audit_type"] == "project_archive_basic"
    assert pdf_as_project_archive_response.status_code == 400
    assert pdf_as_project_archive_response.json()["detail"] == "File is not an archive."
    assert invalid_response.status_code == 400


@pytest.mark.anyio
async def test_django_config_audit_job_creation_and_rejections(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    noop = NoopAuditService()
    app.state.django_config_audits = noop
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        pdf_response = await client.post("/files/pdf", files={"file": ("sample.pdf", b"%PDF-1.4\n%%EOF\n", "application/pdf")})
        archive_response = await client.post(
            "/files/archive",
            files={"file": ("django.zip", make_zip_bytes({"project/settings.py": b"DEBUG=True\n"}), "application/zip")},
        )
        pdf_file = pdf_response.json()
        archive_file = archive_response.json()

        django_response = await client.post(f"/audits/django-config/{archive_file['id']}")
        pdf_as_django_response = await client.post(f"/audits/django-config/{pdf_file['id']}")
        invalid_response = await client.post("/audits/django-config/not-a-file-id")

    assert django_response.status_code == 202
    assert django_response.json()["audit_type"] == "django_config_basic"
    assert pdf_as_django_response.status_code == 400
    assert pdf_as_django_response.json()["detail"] == "File is not an archive."
    assert invalid_response.status_code == 400


@pytest.mark.anyio
async def test_docker_config_audit_job_creation_and_rejections(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    noop = NoopAuditService()
    app.state.docker_config_audits = noop
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        pdf_response = await client.post("/files/pdf", files={"file": ("sample.pdf", b"%PDF-1.4\n%%EOF\n", "application/pdf")})
        archive_response = await client.post(
            "/files/archive",
            files={"file": ("docker.zip", make_zip_bytes({"Dockerfile": b"FROM python:latest\n"}), "application/zip")},
        )
        pdf_file = pdf_response.json()
        archive_file = archive_response.json()

        docker_response = await client.post(f"/audits/docker-config/{archive_file['id']}")
        pdf_as_docker_response = await client.post(f"/audits/docker-config/{pdf_file['id']}")
        invalid_response = await client.post("/audits/docker-config/not-a-file-id")

    assert docker_response.status_code == 202
    assert docker_response.json()["audit_type"] == "docker_config_basic"
    assert pdf_as_docker_response.status_code == 400
    assert pdf_as_docker_response.json()["detail"] == "File is not an archive."
    assert invalid_response.status_code == 400


@pytest.mark.anyio
async def test_docker_config_service_calls_runner_endpoint(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        archive_response = await client.post(
            "/files/archive",
            files={"file": ("docker.zip", make_zip_bytes({"Dockerfile": b"FROM python:latest\n"}), "application/zip")},
        )
    archive = app.state.files.get(archive_response.json()["id"])
    job = app.state.jobs.create_docker_config_job(archive.id)
    calls: list[dict] = []

    class FakeAsyncClient:
        def __init__(self, timeout: float) -> None:
            self.timeout = timeout

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

        async def post(self, url: str, json: dict):
            calls.append({"url": url, "json": json, "timeout": self.timeout})
            return FakeRunnerResponse(
                {
                    "analyzer": "docker_config_basic",
                    "archive_type": "zip",
                    "summary": {
                        "files_reviewed": 1,
                        "dockerfiles_detected": 1,
                        "compose_files_detected": 0,
                        "findings_count": 1,
                        "secrets_redacted_count": 0,
                        "truncated": False,
                    },
                    "compose_services": [],
                    "findings": [{"id": "docker_latest_tag", "title": "latest", "level": "low"}],
                    "errors": [],
                }
            )

    monkeypatch.setattr(audit_services.httpx, "AsyncClient", FakeAsyncClient)

    await app.state.docker_config_audits.run_docker_config_analysis(job.id)

    updated = app.state.jobs.get(job.id)
    assert updated.status == "completed"
    assert updated.result["analyzer"] == "docker_config_basic"
    assert calls[0]["url"] == f"{app.state.settings.tool_runner_url}/analyze/docker-config"
    assert calls[0]["json"]["file_id"] == archive.id
    assert calls[0]["json"]["original_filename"] == "docker.zip"
    assert calls[0]["json"]["max_files"] == app.state.settings.docker_config_max_files
    assert calls[0]["json"]["max_file_bytes"] == app.state.settings.docker_config_max_file_bytes
    assert calls[0]["json"]["max_total_bytes"] == app.state.settings.docker_config_max_total_bytes


@pytest.mark.anyio
async def test_secrets_review_audit_job_creation_and_rejections(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    noop = NoopAuditService()
    app.state.secrets_review_audits = noop
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        pdf_response = await client.post("/files/pdf", files={"file": ("sample.pdf", b"%PDF-1.4\n%%EOF\n", "application/pdf")})
        archive_response = await client.post(
            "/files/archive",
            files={"file": ("secrets.zip", make_zip_bytes({".env.example": b"SECRET_KEY=fixture\n"}), "application/zip")},
        )
        pdf_file = pdf_response.json()
        archive_file = archive_response.json()

        secrets_response = await client.post(f"/audits/secrets-review/{archive_file['id']}")
        pdf_as_secrets_response = await client.post(f"/audits/secrets-review/{pdf_file['id']}")
        invalid_response = await client.post("/audits/secrets-review/not-a-file-id")

    assert secrets_response.status_code == 202
    assert secrets_response.json()["audit_type"] == "secrets_review_basic"
    assert pdf_as_secrets_response.status_code == 400
    assert pdf_as_secrets_response.json()["detail"] == "File is not an archive."
    assert invalid_response.status_code == 400


@pytest.mark.anyio
async def test_secrets_review_service_calls_runner_endpoint(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        archive_response = await client.post(
            "/files/archive",
            files={"file": ("secrets.zip", make_zip_bytes({".env.example": b"SECRET_KEY=fixture\n"}), "application/zip")},
        )
    archive = app.state.files.get(archive_response.json()["id"])
    job = app.state.jobs.create_secrets_review_job(archive.id)
    calls: list[dict] = []

    class FakeAsyncClient:
        def __init__(self, timeout: float) -> None:
            self.timeout = timeout

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

        async def post(self, url: str, json: dict):
            calls.append({"url": url, "json": json, "timeout": self.timeout})
            return FakeRunnerResponse(
                {
                    "analyzer": "secrets_review_basic",
                    "archive_type": "zip",
                    "summary": {
                        "files_considered": 1,
                        "files_reviewed": 1,
                        "sensitive_files_detected": 0,
                        "findings_count": 1,
                        "high_confidence_count": 0,
                        "redacted_values_count": 1,
                        "truncated": False,
                    },
                    "findings": [{"id": "secret_like_assignment", "title": "Secret-like assignment", "level": "medium"}],
                    "errors": [],
                }
            )

    monkeypatch.setattr(audit_services.httpx, "AsyncClient", FakeAsyncClient)

    await app.state.secrets_review_audits.run_secrets_review_analysis(job.id)

    updated = app.state.jobs.get(job.id)
    assert updated.status == "completed"
    assert updated.result["analyzer"] == "secrets_review_basic"
    assert calls[0]["url"] == f"{app.state.settings.tool_runner_url}/analyze/secrets-review"
    assert calls[0]["json"]["file_id"] == archive.id
    assert calls[0]["json"]["original_filename"] == "secrets.zip"
    assert calls[0]["json"]["max_files"] == app.state.settings.secrets_review_max_files
    assert calls[0]["json"]["max_file_bytes"] == app.state.settings.secrets_review_max_file_bytes
    assert calls[0]["json"]["max_total_bytes"] == app.state.settings.secrets_review_max_total_bytes


@pytest.mark.anyio
async def test_node_package_config_audit_job_creation_and_rejections(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    noop = NoopAuditService()
    app.state.node_package_config_audits = noop
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        pdf_response = await client.post("/files/pdf", files={"file": ("sample.pdf", b"%PDF-1.4\n%%EOF\n", "application/pdf")})
        archive_response = await client.post(
            "/files/archive",
            files={"file": ("node.zip", make_zip_bytes({"package.json": SAMPLE_PACKAGE_JSON}), "application/zip")},
        )
        pdf_file = pdf_response.json()
        archive_file = archive_response.json()

        node_response = await client.post(f"/audits/node-package-config/{archive_file['id']}")
        pdf_as_node_response = await client.post(f"/audits/node-package-config/{pdf_file['id']}")
        invalid_response = await client.post("/audits/node-package-config/not-a-file-id")

    assert node_response.status_code == 202
    assert node_response.json()["audit_type"] == "node_package_config_basic"
    assert pdf_as_node_response.status_code == 400
    assert pdf_as_node_response.json()["detail"] == "File is not an archive."
    assert invalid_response.status_code == 400


@pytest.mark.anyio
async def test_node_package_config_service_calls_runner_endpoint(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        archive_response = await client.post(
            "/files/archive",
            files={"file": ("node.zip", make_zip_bytes({"package.json": SAMPLE_PACKAGE_JSON}), "application/zip")},
        )
    archive = app.state.files.get(archive_response.json()["id"])
    job = app.state.jobs.create_node_package_config_job(archive.id)
    calls: list[dict] = []

    class FakeAsyncClient:
        def __init__(self, timeout: float) -> None:
            self.timeout = timeout

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

        async def post(self, url: str, json: dict):
            calls.append({"url": url, "json": json, "timeout": self.timeout})
            return FakeRunnerResponse(
                {
                    "analyzer": "node_package_config_basic",
                    "archive_type": "zip",
                    "summary": {
                        "files_considered": 2,
                        "files_reviewed": 2,
                        "package_manifests_detected": 1,
                        "lockfiles_detected": 1,
                        "package_manager_configs_detected": 0,
                        "packages_detected": 1,
                        "scripts_detected": 1,
                        "findings_count": 1,
                        "redacted_values_count": 0,
                        "truncated": False,
                    },
                    "findings": [{"id": "postinstall_script_present", "title": "postinstall", "level": "low"}],
                    "errors": [],
                }
            )

    monkeypatch.setattr(audit_services.httpx, "AsyncClient", FakeAsyncClient)

    await app.state.node_package_config_audits.run_node_package_config_analysis(job.id)

    updated = app.state.jobs.get(job.id)
    assert updated.status == "completed"
    assert updated.result["analyzer"] == "node_package_config_basic"
    assert calls[0]["url"] == f"{app.state.settings.tool_runner_url}/analyze/node-package-config"
    assert calls[0]["json"]["file_id"] == archive.id
    assert calls[0]["json"]["original_filename"] == "node.zip"
    assert calls[0]["json"]["max_files"] == app.state.settings.node_package_config_max_files
    assert calls[0]["json"]["max_file_bytes"] == app.state.settings.node_package_config_max_file_bytes
    assert calls[0]["json"]["max_total_bytes"] == app.state.settings.node_package_config_max_total_bytes


@pytest.mark.anyio
async def test_ci_cd_config_audit_job_creation_and_rejections(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    noop = NoopAuditService()
    app.state.ci_cd_config_audits = noop
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        pdf_response = await client.post("/files/pdf", files={"file": ("sample.pdf", b"%PDF-1.4\n%%EOF\n", "application/pdf")})
        archive_response = await client.post(
            "/files/archive",
            files={"file": ("ci.zip", make_zip_bytes({".github/workflows/ci.yml": b"name: ci\non: push\n"}), "application/zip")},
        )
        pdf_file = pdf_response.json()
        archive_file = archive_response.json()

        ci_response = await client.post(f"/audits/ci-cd-config/{archive_file['id']}")
        pdf_as_ci_response = await client.post(f"/audits/ci-cd-config/{pdf_file['id']}")
        invalid_response = await client.post("/audits/ci-cd-config/not-a-file-id")

    assert ci_response.status_code == 202
    assert ci_response.json()["audit_type"] == "ci_cd_config_basic"
    assert pdf_as_ci_response.status_code == 400
    assert pdf_as_ci_response.json()["detail"] == "File is not an archive."
    assert invalid_response.status_code == 400


@pytest.mark.anyio
async def test_ci_cd_config_service_calls_runner_endpoint(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        archive_response = await client.post(
            "/files/archive",
            files={"file": ("ci.zip", make_zip_bytes({".github/workflows/ci.yml": b"name: ci\non: push\n"}), "application/zip")},
        )
    archive = app.state.files.get(archive_response.json()["id"])
    job = app.state.jobs.create_ci_cd_config_job(archive.id)
    calls: list[dict] = []

    class FakeAsyncClient:
        def __init__(self, timeout: float) -> None:
            self.timeout = timeout

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

        async def post(self, url: str, json: dict):
            calls.append({"url": url, "json": json, "timeout": self.timeout})
            return FakeRunnerResponse(
                {
                    "analyzer": "ci_cd_config_basic",
                    "archive_type": "zip",
                    "summary": {
                        "files_considered": 1,
                        "files_reviewed": 1,
                        "workflow_files_detected": 1,
                        "jobs_detected": 1,
                        "steps_detected": 2,
                        "triggers_detected": 1,
                        "findings_count": 1,
                        "redacted_values_count": 0,
                        "truncated": False,
                    },
                    "jobs": [
                        {
                            "file_path": ".github/workflows/deploy.yml",
                            "provider": "github_actions",
                            "job": "deploy",
                            "script": 'echo "Authorization: Bearer token_should_never_render"',
                        }
                    ],
                    "findings": [
                        {
                            "id": "github_permissions_missing",
                            "title": "permissions missing",
                            "level": "low",
                            "description": "TOKEN=fixture-token",
                            "evidence": "API_KEY=fixture-key Authorization: Bearer token_should_never_render",
                            "recommendation": 'Remove "Bearer token_should_never_render" from scripts.',
                        }
                    ],
                    "errors": ["Authorization: Bearer token_should_never_render"],
                }
            )

    monkeypatch.setattr(audit_services.httpx, "AsyncClient", FakeAsyncClient)

    await app.state.ci_cd_config_audits.run_ci_cd_config_analysis(job.id)

    updated = app.state.jobs.get(job.id)
    assert updated.status == "completed"
    assert updated.result["analyzer"] == "ci_cd_config_basic"
    serialized_result = json.dumps(updated.result)
    assert "[REDACTED]" in serialized_result
    for secret in ("fixture-token", "fixture-key", "token_should_never_render", "Authorization: Bearer token_should_never_render"):
        assert secret not in serialized_result
    assert calls[0]["url"] == f"{app.state.settings.tool_runner_url}/analyze/ci-cd-config"
    assert calls[0]["json"]["file_id"] == archive.id
    assert calls[0]["json"]["original_filename"] == "ci.zip"
    assert calls[0]["json"]["max_files"] == app.state.settings.ci_cd_config_max_files
    assert calls[0]["json"]["max_file_bytes"] == app.state.settings.ci_cd_config_max_file_bytes
    assert calls[0]["json"]["max_total_bytes"] == app.state.settings.ci_cd_config_max_total_bytes


@pytest.mark.anyio
async def test_k8s_config_audit_job_creation_and_rejections(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    noop = NoopAuditService()
    app.state.k8s_config_audits = noop
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        pdf_response = await client.post("/files/pdf", files={"file": ("sample.pdf", b"%PDF-1.4\n%%EOF\n", "application/pdf")})
        archive_response = await client.post(
            "/files/archive",
            files={"file": ("k8s.zip", make_zip_bytes({"k8s/deployment.yaml": b"apiVersion: apps/v1\nkind: Deployment\n"}), "application/zip")},
        )
        pdf_file = pdf_response.json()
        archive_file = archive_response.json()

        k8s_response = await client.post(f"/audits/k8s-config/{archive_file['id']}")
        pdf_as_k8s_response = await client.post(f"/audits/k8s-config/{pdf_file['id']}")
        invalid_response = await client.post("/audits/k8s-config/not-a-file-id")

    assert k8s_response.status_code == 202
    assert k8s_response.json()["audit_type"] == "k8s_config_basic"
    assert pdf_as_k8s_response.status_code == 400
    assert pdf_as_k8s_response.json()["detail"] == "File is not an archive."
    assert invalid_response.status_code == 400


@pytest.mark.anyio
async def test_k8s_config_service_calls_runner_endpoint(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        archive_response = await client.post(
            "/files/archive",
            files={"file": ("k8s.zip", make_zip_bytes({"k8s/deployment.yaml": b"apiVersion: apps/v1\nkind: Deployment\n"}), "application/zip")},
        )
    archive = app.state.files.get(archive_response.json()["id"])
    job = app.state.jobs.create_k8s_config_job(archive.id)
    calls: list[dict] = []

    class FakeAsyncClient:
        def __init__(self, timeout: float) -> None:
            self.timeout = timeout

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

        async def post(self, url: str, json: dict):
            calls.append({"url": url, "json": json, "timeout": self.timeout})
            return FakeRunnerResponse(
                {
                    "analyzer": "k8s_config_basic",
                    "archive_type": "zip",
                    "summary": {
                        "files_considered": 1,
                        "files_reviewed": 1,
                        "manifest_files_detected": 1,
                        "resources_detected": 1,
                        "workloads_detected": 1,
                        "services_detected": 0,
                        "secrets_detected": 0,
                        "rbac_resources_detected": 0,
                        "findings_count": 1,
                        "redacted_values_count": 0,
                        "truncated": False,
                    },
                    "resources": [{"kind": "Deployment", "name": "app", "path": "k8s/deployment.yaml"}],
                    "containers": [{"container": "app", "image": "registry-user:registry-pass/k8s-app:latest"}],
                    "secrets": [{"kind": "Secret", "stringData": {"password": "super-secret-password"}}],
                    "findings": [{"id": "resource_limits_missing", "title": "resources missing", "level": "low", "evidence": "API_KEY=raw-api-key-123456"}],
                    "errors": ["TOKEN=token_should_never_render"],
                }
            )

    monkeypatch.setattr(audit_services.httpx, "AsyncClient", FakeAsyncClient)

    await app.state.k8s_config_audits.run_k8s_config_analysis(job.id)

    updated = app.state.jobs.get(job.id)
    serialized_result = json.dumps(updated.result)
    assert updated.status == "completed"
    assert updated.result["analyzer"] == "k8s_config_basic"
    assert "[REDACTED]" in serialized_result
    for secret in ("super-secret-password", "raw-api-key-123456", "token_should_never_render", "registry-user:registry-pass"):
        assert secret not in serialized_result
    assert calls[0]["url"] == f"{app.state.settings.tool_runner_url}/analyze/k8s-config"
    assert calls[0]["json"]["file_id"] == archive.id
    assert calls[0]["json"]["original_filename"] == "k8s.zip"
    assert calls[0]["json"]["max_files"] == app.state.settings.k8s_config_max_files
    assert calls[0]["json"]["max_file_bytes"] == app.state.settings.k8s_config_max_file_bytes
    assert calls[0]["json"]["max_total_bytes"] == app.state.settings.k8s_config_max_total_bytes


@pytest.mark.anyio
async def test_terraform_config_audit_job_creation_and_rejections(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    noop = NoopAuditService()
    app.state.terraform_config_audits = noop
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        pdf_response = await client.post("/files/pdf", files={"file": ("sample.pdf", b"%PDF-1.4\n%%EOF\n", "application/pdf")})
        archive_response = await client.post(
            "/files/archive",
            files={"file": ("tf.zip", make_zip_bytes({"infra/main.tf": b'resource "aws_s3_bucket" "app" {}\n'}), "application/zip")},
        )
        pdf_file = pdf_response.json()
        archive_file = archive_response.json()

        terraform_response = await client.post(f"/audits/terraform-config/{archive_file['id']}")
        pdf_as_terraform_response = await client.post(f"/audits/terraform-config/{pdf_file['id']}")
        invalid_response = await client.post("/audits/terraform-config/not-a-file-id")

    assert terraform_response.status_code == 202
    assert terraform_response.json()["audit_type"] == "terraform_config_basic"
    assert pdf_as_terraform_response.status_code == 400
    assert pdf_as_terraform_response.json()["detail"] == "File is not an archive."
    assert invalid_response.status_code == 400


@pytest.mark.anyio
async def test_terraform_config_service_calls_runner_endpoint(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        archive_response = await client.post(
            "/files/archive",
            files={"file": ("tf.zip", make_zip_bytes({"infra/main.tf": b'resource "aws_s3_bucket" "app" {}\n'}), "application/zip")},
        )
    archive = app.state.files.get(archive_response.json()["id"])
    job = app.state.jobs.create_terraform_config_job(archive.id)
    calls: list[dict] = []

    class FakeAsyncClient:
        def __init__(self, timeout: float) -> None:
            self.timeout = timeout

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

        async def post(self, url: str, json: dict):
            calls.append({"url": url, "json": json, "timeout": self.timeout})
            return FakeRunnerResponse(
                {
                    "analyzer": "terraform_config_basic",
                    "archive_type": "zip",
                    "summary": {
                        "files_considered": 2,
                        "files_reviewed": 1,
                        "terraform_files_detected": 1,
                        "tfvars_files_detected": 1,
                        "state_files_detected": 0,
                        "providers_detected": 1,
                        "backends_detected": 1,
                        "modules_detected": 0,
                        "resources_detected": 1,
                        "findings_count": 1,
                        "redacted_values_count": 1,
                        "truncated": False,
                    },
                    "variables": [{"name": "password", "default": "super-secret-password"}],
                    "findings": [
                        {
                            "id": "terraform_variable_default_secret_like",
                            "title": "Variable default contains secret-like value",
                            "level": "medium",
                            "evidence": "password=super-secret-password",
                        }
                    ],
                    "errors": ["API_KEY=raw-api-key-123456", "registry-user:registry-pass"],
                }
            )

    monkeypatch.setattr(audit_services.httpx, "AsyncClient", FakeAsyncClient)

    await app.state.terraform_config_audits.run_terraform_config_analysis(job.id)

    updated = app.state.jobs.get(job.id)
    serialized_result = json.dumps(updated.result)
    assert updated.status == "completed"
    assert updated.result["analyzer"] == "terraform_config_basic"
    assert "[REDACTED]" in serialized_result
    for secret in ("super-secret-password", "raw-api-key-123456", "registry-user:registry-pass"):
        assert secret not in serialized_result
    assert calls[0]["url"] == f"{app.state.settings.tool_runner_url}/analyze/terraform-config"
    assert calls[0]["json"]["file_id"] == archive.id
    assert calls[0]["json"]["original_filename"] == "tf.zip"
    assert calls[0]["json"]["max_files"] == app.state.settings.terraform_config_max_files
    assert calls[0]["json"]["max_file_bytes"] == app.state.settings.terraform_config_max_file_bytes
    assert calls[0]["json"]["max_total_bytes"] == app.state.settings.terraform_config_max_total_bytes


@pytest.mark.anyio
async def test_nginx_config_audit_job_creation_and_rejections(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    noop = NoopAuditService()
    app.state.nginx_config_audits = noop
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        pdf_response = await client.post("/files/pdf", files={"file": ("sample.pdf", b"%PDF-1.4\n%%EOF\n", "application/pdf")})
        archive_response = await client.post(
            "/files/archive",
            files={"file": ("nginx.zip", make_zip_bytes({"nginx/default.conf": b"server { listen 80; }\n"}), "application/zip")},
        )
        pdf_file = pdf_response.json()
        archive_file = archive_response.json()

        nginx_response = await client.post(f"/audits/nginx-config/{archive_file['id']}")
        pdf_as_nginx_response = await client.post(f"/audits/nginx-config/{pdf_file['id']}")
        invalid_response = await client.post("/audits/nginx-config/not-a-file-id")

    assert nginx_response.status_code == 202
    assert nginx_response.json()["audit_type"] == "nginx_config_basic"
    assert pdf_as_nginx_response.status_code == 400
    assert pdf_as_nginx_response.json()["detail"] == "File is not an archive."
    assert invalid_response.status_code == 400


@pytest.mark.anyio
async def test_nginx_config_service_calls_runner_endpoint(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        archive_response = await client.post(
            "/files/archive",
            files={"file": ("nginx.zip", make_zip_bytes({"nginx/default.conf": b"server { listen 80; }\n"}), "application/zip")},
        )
    archive = app.state.files.get(archive_response.json()["id"])
    job = app.state.jobs.create_nginx_config_job(archive.id)
    calls: list[dict] = []

    class FakeAsyncClient:
        def __init__(self, timeout: float) -> None:
            self.timeout = timeout

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

        async def post(self, url: str, json: dict):
            calls.append({"url": url, "json": json, "timeout": self.timeout})
            return FakeRunnerResponse(
                {
                    "analyzer": "nginx_config_basic",
                    "archive_type": "zip",
                    "summary": {
                        "files_considered": 1,
                        "files_reviewed": 1,
                        "nginx_files_detected": 1,
                        "server_blocks_detected": 1,
                        "location_blocks_detected": 1,
                        "upstream_blocks_detected": 0,
                        "includes_detected": 1,
                        "tls_servers_detected": 0,
                        "findings_count": 1,
                        "redacted_values_count": 1,
                        "truncated": False,
                    },
                    "includes": [{"target": "/etc/nginx/secrets.conf", "resolved": False}],
                    "directives": [
                        {"directive": "proxy_set_header", "arguments": "Authorization: Bearer token_should_never_render"},
                        {"directive": "auth_basic", "arguments": "super-secret-password"},
                    ],
                    "findings": [
                        {
                            "id": "nginx_proxy_pass_credentials_hint",
                            "title": "proxy credentials",
                            "level": "medium",
                            "evidence": "proxy_pass http://user:pass@example.com",
                        }
                    ],
                    "errors": ["API_KEY=raw-api-key-123456", "registry-user:registry-pass"],
                }
            )

    monkeypatch.setattr(audit_services.httpx, "AsyncClient", FakeAsyncClient)

    await app.state.nginx_config_audits.run_nginx_config_analysis(job.id)

    updated = app.state.jobs.get(job.id)
    serialized_result = json.dumps(updated.result)
    assert updated.status == "completed"
    assert updated.result["analyzer"] == "nginx_config_basic"
    assert "[REDACTED]" in serialized_result
    for secret in (
        "raw-api-key-123456",
        "super-secret-password",
        "token_should_never_render",
        "http://user:pass@example.com",
        "registry-user:registry-pass",
    ):
        assert secret not in serialized_result
    assert calls[0]["url"] == f"{app.state.settings.tool_runner_url}/analyze/nginx-config"
    assert calls[0]["json"]["file_id"] == archive.id
    assert calls[0]["json"]["original_filename"] == "nginx.zip"
    assert calls[0]["json"]["max_files"] == app.state.settings.nginx_config_max_files
    assert calls[0]["json"]["max_file_bytes"] == app.state.settings.nginx_config_max_file_bytes
    assert calls[0]["json"]["max_total_bytes"] == app.state.settings.nginx_config_max_total_bytes


@pytest.mark.anyio
async def test_compose_config_audit_job_creation_and_rejections(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    noop = NoopAuditService()
    app.state.compose_config_audits = noop
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        pdf_response = await client.post("/files/pdf", files={"file": ("sample.pdf", b"%PDF-1.4\n%%EOF\n", "application/pdf")})
        archive_response = await client.post(
            "/files/archive",
            files={"file": ("compose.zip", make_zip_bytes({"docker-compose.yml": b"services:\n  web:\n    image: nginx:latest\n"}), "application/zip")},
        )
        pdf_file = pdf_response.json()
        archive_file = archive_response.json()

        compose_response = await client.post(f"/audits/compose-config/{archive_file['id']}")
        pdf_as_compose_response = await client.post(f"/audits/compose-config/{pdf_file['id']}")
        invalid_response = await client.post("/audits/compose-config/not-a-file-id")

    assert compose_response.status_code == 202
    assert compose_response.json()["audit_type"] == "compose_config_basic"
    assert pdf_as_compose_response.status_code == 400
    assert pdf_as_compose_response.json()["detail"] == "File is not an archive."
    assert invalid_response.status_code == 400


@pytest.mark.anyio
async def test_compose_config_service_calls_runner_endpoint(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        archive_response = await client.post(
            "/files/archive",
            files={"file": ("compose.zip", make_zip_bytes({"docker-compose.yml": b"services:\n  db:\n    image: postgres:latest\n"}), "application/zip")},
        )
    archive = app.state.files.get(archive_response.json()["id"])
    job = app.state.jobs.create_compose_config_job(archive.id)
    calls: list[dict] = []

    class FakeAsyncClient:
        def __init__(self, timeout: float) -> None:
            self.timeout = timeout

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

        async def post(self, url: str, json: dict):
            calls.append({"url": url, "json": json, "timeout": self.timeout})
            return FakeRunnerResponse(
                {
                    "analyzer": "compose_config_basic",
                    "archive_type": "zip",
                    "summary": {
                        "files_considered": 2,
                        "files_reviewed": 1,
                        "compose_files_detected": 1,
                        "services_detected": 1,
                        "networks_detected": 1,
                        "volumes_detected": 1,
                        "secrets_detected": 1,
                        "published_ports_detected": 1,
                        "env_files_detected": 1,
                        "findings_count": 1,
                        "redacted_values_count": 1,
                        "truncated": False,
                    },
                    "services": [{"name": "db", "environment": {"POSTGRES_PASSWORD": "super-secret-password"}}],
                    "env_files": [{"path": ".env", "read": False, "content": "POSTGRES_PASSWORD=super-secret-password compose_secret_file_should_not_render"}],
                    "secrets": [{"name": "db_password", "file": "./secrets/db_password.txt", "content": "compose_secret_file_should_not_render"}],
                    "findings": [
                        {
                            "id": "compose_environment_secret_like_value",
                            "title": "environment secret",
                            "level": "medium",
                            "evidence": "POSTGRES_PASSWORD=super-secret-password",
                        }
                    ],
                    "errors": ["DATABASE_URL=postgres://user:pass@example.com/db", "registry-user:registry-pass"],
                }
            )

    monkeypatch.setattr(audit_services.httpx, "AsyncClient", FakeAsyncClient)

    await app.state.compose_config_audits.run_compose_config_analysis(job.id)

    updated = app.state.jobs.get(job.id)
    serialized_result = json.dumps(updated.result)
    assert updated.status == "completed"
    assert updated.result["analyzer"] == "compose_config_basic"
    assert "[REDACTED]" in serialized_result
    for secret in (
        "super-secret-password",
        "postgres://user:pass@example.com/db",
        "registry-user:registry-pass",
        "compose_secret_file_should_not_render",
    ):
        assert secret not in serialized_result
    assert calls[0]["url"] == f"{app.state.settings.tool_runner_url}/analyze/compose-config"
    assert calls[0]["json"]["file_id"] == archive.id
    assert calls[0]["json"]["original_filename"] == "compose.zip"
    assert calls[0]["json"]["max_files"] == app.state.settings.compose_config_max_files
    assert calls[0]["json"]["max_file_bytes"] == app.state.settings.compose_config_max_file_bytes
    assert calls[0]["json"]["max_total_bytes"] == app.state.settings.compose_config_max_total_bytes


@pytest.mark.anyio
async def test_database_config_audit_job_creation_and_rejections(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    noop = NoopAuditService()
    app.state.database_config_audits = noop
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        pdf_response = await client.post("/files/pdf", files={"file": ("sample.pdf", b"%PDF-1.4\n%%EOF\n", "application/pdf")})
        archive_response = await client.post(
            "/files/archive",
            files={"file": ("database.zip", make_zip_bytes({"postgresql.conf": b"listen_addresses = 'localhost'\n"}), "application/zip")},
        )
        pdf_file = pdf_response.json()
        archive_file = archive_response.json()

        database_response = await client.post(f"/audits/database-config/{archive_file['id']}")
        pdf_as_database_response = await client.post(f"/audits/database-config/{pdf_file['id']}")
        invalid_response = await client.post("/audits/database-config/not-a-file-id")

    assert database_response.status_code == 202
    assert database_response.json()["audit_type"] == "database_config_basic"
    assert pdf_as_database_response.status_code == 400
    assert pdf_as_database_response.json()["detail"] == "File is not an archive."
    assert invalid_response.status_code == 400


@pytest.mark.anyio
async def test_database_config_service_calls_runner_endpoint(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        archive_response = await client.post(
            "/files/archive",
            files={"file": ("database.zip", make_zip_bytes({"postgresql.conf": b"password = 'x'\n"}), "application/zip")},
        )
    archive = app.state.files.get(archive_response.json()["id"])
    job = app.state.jobs.create_database_config_job(archive.id)
    calls: list[dict] = []

    class FakeAsyncClient:
        def __init__(self, timeout: float) -> None:
            self.timeout = timeout

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

        async def post(self, url: str, json: dict):
            calls.append({"url": url, "json": json, "timeout": self.timeout})
            return FakeRunnerResponse(
                {
                    "analyzer": "database_config_basic",
                    "archive_type": "zip",
                    "summary": {
                        "files_considered": 3,
                        "files_reviewed": 2,
                        "database_files_detected": 2,
                        "postgres_files_detected": 1,
                        "mysql_files_detected": 1,
                        "mariadb_files_detected": 0,
                        "pg_hba_files_detected": 0,
                        "dump_or_backup_files_detected": 1,
                        "engines_detected": 2,
                        "findings_count": 1,
                        "redacted_values_count": 1,
                        "truncated": False,
                    },
                    "postgres_settings": [{"setting": "primary_conninfo", "value": "postgres://user:pass@example.com/db"}],
                    "mysql_settings": [{"setting": "password", "value": "raw-db-password-123456"}],
                    "dump_or_backup_files": [{"path": "db/prod.sql", "read": False, "content": "db_password_plaintext"}],
                    "findings": [
                        {
                            "id": "database_password_like_value",
                            "title": "Database password",
                            "level": "medium",
                            "evidence": "PGPASSWORD=super-secret-password",
                        }
                    ],
                    "errors": ["MYSQL_PWD=super-secret-password", "-----BEGIN PRIVATE KEY----- PRIVATE KEY -----END PRIVATE KEY-----"],
                }
            )

    monkeypatch.setattr(audit_services.httpx, "AsyncClient", FakeAsyncClient)

    await app.state.database_config_audits.run_database_config_analysis(job.id)

    updated = app.state.jobs.get(job.id)
    serialized_result = json.dumps(updated.result)
    assert updated.status == "completed"
    assert updated.result["analyzer"] == "database_config_basic"
    assert "[REDACTED]" in serialized_result
    for secret in (
        "super-secret-password",
        "raw-db-password-123456",
        "postgres://user:pass@example.com/db",
        "MYSQL_PWD=super-secret-password",
        "PRIVATE KEY",
        "db_password_plaintext",
    ):
        assert secret not in serialized_result
    assert calls[0]["url"] == f"{app.state.settings.tool_runner_url}/analyze/database-config"
    assert calls[0]["json"]["file_id"] == archive.id
    assert calls[0]["json"]["original_filename"] == "database.zip"
    assert calls[0]["json"]["max_files"] == app.state.settings.database_config_max_files
    assert calls[0]["json"]["max_file_bytes"] == app.state.settings.database_config_max_file_bytes
    assert calls[0]["json"]["max_total_bytes"] == app.state.settings.database_config_max_total_bytes


@pytest.mark.anyio
async def test_sql_database_config_audit_job_creation_and_rejections(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    noop = NoopAuditService()
    app.state.sql_database_config_audits = noop
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        pdf_response = await client.post("/files/pdf", files={"file": ("sample.pdf", b"%PDF-1.4\n%%EOF\n", "application/pdf")})
        archive_response = await client.post(
            "/files/archive",
            files={"file": ("sql-db.zip", make_zip_bytes({"postgresql.conf": b"listen_addresses = 'localhost'\n"}), "application/zip")},
        )
        pdf_file = pdf_response.json()
        archive_file = archive_response.json()

        sql_response = await client.post(f"/audits/sql-database-config/{archive_file['id']}")
        pdf_as_sql_response = await client.post(f"/audits/sql-database-config/{pdf_file['id']}")
        invalid_response = await client.post("/audits/sql-database-config/not-a-file-id")

    assert sql_response.status_code == 202
    assert sql_response.json()["audit_type"] == "sql_database_config_basic"
    assert pdf_as_sql_response.status_code == 400
    assert pdf_as_sql_response.json()["detail"] == "File is not an archive."
    assert invalid_response.status_code == 400


@pytest.mark.anyio
async def test_sql_database_config_service_calls_runner_endpoint_and_redacts(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        archive_response = await client.post(
            "/files/archive",
            files={"file": ("sql-db.zip", make_zip_bytes({"postgresql.conf": b"password = 'x'\n"}), "application/zip")},
        )
    archive = app.state.files.get(archive_response.json()["id"])
    job = app.state.jobs.create_sql_database_config_job(archive.id)
    calls: list[dict] = []

    class FakeAsyncClient:
        def __init__(self, timeout: float) -> None:
            self.timeout = timeout

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

        async def post(self, url: str, json: dict):
            calls.append({"url": url, "json": json, "timeout": self.timeout})
            return FakeRunnerResponse(
                {
                    "analyzer": "sql_database_config_basic",
                    "archive_type": "zip",
                    "summary": {
                        "files_considered": 6,
                        "files_reviewed": 3,
                        "postgres_configs_detected": 1,
                        "postgres_hba_files_detected": 1,
                        "mysql_configs_detected": 1,
                        "mariadb_configs_detected": 0,
                        "dump_or_backup_files_detected": 1,
                        "data_files_detected": 1,
                        "findings_count": 1,
                        "redacted_values_count": 1,
                        "truncated": False,
                    },
                    "postgres_configs": [{"file_path": "postgresql.conf", "setting": "primary_conninfo", "value": "postgres://user:pass@example.com/db"}],
                    "postgres_hba_rules": [{"database": "all", "user": "all", "address": "0.0.0.0/0", "auth_method": "trust"}],
                    "mysql_configs": [{"file_path": "my.cnf", "setting": "password", "value": "raw-db-password-123456"}],
                    "database_settings": [{"setting": "db_password", "value": "super-secret-password"}],
                    "sensitive_files": [{"path": ".pgpass", "read": False, "content": "pgpass_secret_should_not_render"}],
                    "dump_or_backup_files": [{"path": "db/prod.sql", "read": False, "content": "dump_row_secret_should_not_render"}],
                    "data_files": [{"path": "pg_wal/0001", "read": False, "content": "db_password_plaintext"}],
                    "findings": [
                        {
                            "id": "sql_database_password_like_value",
                            "title": "SQL database password-like value",
                            "level": "medium",
                            "evidence": "PGPASSWORD=super-secret-password postgres://user:pass@example.com/db",
                        }
                    ],
                    "errors": ["MYSQL_PWD=super-secret-password", "-----BEGIN PRIVATE KEY----- PRIVATE KEY -----END PRIVATE KEY-----"],
                }
            )

    monkeypatch.setattr(audit_services.httpx, "AsyncClient", FakeAsyncClient)

    await app.state.sql_database_config_audits.run_sql_database_config_analysis(job.id)

    updated = app.state.jobs.get(job.id)
    serialized_result = json.dumps(updated.result)
    assert updated.status == "completed"
    assert updated.result["analyzer"] == "sql_database_config_basic"
    assert "[REDACTED]" in serialized_result
    for secret in SQL_DATABASE_SECRET_FIXTURES:
        assert secret not in serialized_result
    assert calls[0]["url"] == f"{app.state.settings.tool_runner_url}/analyze/sql-database-config"
    assert calls[0]["json"]["file_id"] == archive.id
    assert calls[0]["json"]["original_filename"] == "sql-db.zip"
    assert calls[0]["json"]["max_files"] == app.state.settings.sql_database_config_max_files
    assert calls[0]["json"]["max_file_bytes"] == app.state.settings.sql_database_config_max_file_bytes
    assert calls[0]["json"]["max_total_bytes"] == app.state.settings.sql_database_config_max_total_bytes


@pytest.mark.anyio
async def test_sql_database_config_api_background_job_stores_and_exposes_redacted_result(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    calls: list[dict] = []

    class FakeAsyncClient:
        def __init__(self, timeout: float) -> None:
            self.timeout = timeout

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

        async def post(self, url: str, json: dict):
            calls.append({"url": url, "json": json, "timeout": self.timeout})
            return FakeRunnerResponse(
                {
                    "analyzer": "sql_database_config_basic",
                    "archive_type": "zip",
                    "summary": {
                        "files_considered": 7,
                        "files_reviewed": 3,
                        "postgres_configs_detected": 1,
                        "postgres_hba_files_detected": 1,
                        "mysql_configs_detected": 1,
                        "mariadb_configs_detected": 1,
                        "dump_or_backup_files_detected": 1,
                        "data_files_detected": 1,
                        "findings_count": 1,
                        "redacted_values_count": 1,
                        "truncated": False,
                    },
                    "postgres_configs": [{"file_path": "deploy/db/postgresql.conf", "content": "primary_conninfo=postgres://user:pass@example.com/db"}],
                    "postgres_hba_rules": [{"database": "all", "user": "all", "address": "0.0.0.0/0", "auth_method": "trust"}],
                    "mysql_configs": [{"file_path": "deploy/db/my.cnf", "content": "password=raw-db-password-123456"}],
                    "database_settings": [{"setting": "primary_conninfo", "value": "postgres://user:pass@example.com/db"}],
                    "includes": [{"target": "/etc/postgresql/secret.conf", "resolved": False, "content": "replication_password_should_not_render"}],
                    "sensitive_files": [{"path": ".pgpass", "read": False, "content": "pgpass_secret_should_not_render"}],
                    "dump_or_backup_files": [{"path": "db/prod.sql", "read": False, "sql": "dump_row_secret_should_not_render"}],
                    "data_files": [{"path": "db/postgres/pg_wal/0001", "read": False, "content": "db_password_plaintext"}],
                    "findings": [
                        {
                            "id": "postgres_hba_trust_auth_hint",
                            "title": "PostgreSQL pg_hba trust auth configured",
                            "level": "medium",
                            "confidence": "high",
                            "category": "auth",
                            "evidence": "PGPASSWORD=super-secret-password postgres://user:pass@example.com/db",
                            "recommendation": "Review trust auth without changing password encryption wording.",
                        }
                    ],
                    "errors": [
                        "MYSQL_PWD=super-secret-password",
                        "mysql://user:pass@example.com/db",
                        "-----BEGIN PRIVATE KEY----- PRIVATE KEY -----END PRIVATE KEY-----",
                    ],
                }
            )

    monkeypatch.setattr(audit_services.httpx, "AsyncClient", FakeAsyncClient)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        archive_response = await client.post(
            "/files/archive",
            files={"file": ("sql-db.zip", make_zip_bytes({"deploy/db/postgresql.conf": b"password = 'x'\n"}), "application/zip")},
        )
        archive = archive_response.json()
        launch_response = await client.post(f"/audits/sql-database-config/{archive['id']}")
        job_id = launch_response.json()["id"]
        job_response = await client.get(f"/jobs/{job_id}")
        jobs_response = await client.get("/jobs")

    stored = app.state.jobs.get(job_id)
    stored_serialized = json.dumps(stored.result, sort_keys=True)
    public_serialized = json.dumps(job_response.json(), sort_keys=True)
    assert launch_response.status_code == 202
    assert stored.status == "completed"
    assert stored.result["analyzer"] == "sql_database_config_basic"
    assert job_response.status_code == 200
    assert job_response.json()["status"] == "completed"
    assert job_response.json()["result"]["analyzer"] == "sql_database_config_basic"
    assert "[REDACTED]" in stored_serialized
    assert "[REDACTED]" in public_serialized
    assert "password encryption wording" in public_serialized
    for secret in SQL_DATABASE_SECRET_FIXTURES:
        assert secret not in stored_serialized
        assert secret not in public_serialized
    summary = next(item for item in jobs_response.json() if item["id"] == job_id)["summary"]
    assert summary["analyzer"] == "sql_database_config_basic"
    assert summary["files_reviewed"] == 3
    assert summary["postgres_configs_detected"] == 1
    assert summary["postgres_hba_files_detected"] == 1
    assert summary["mysql_configs_detected"] == 1
    assert summary["mariadb_configs_detected"] == 1
    assert summary["data_files_detected"] == 1
    assert summary["errors_count"] == 3
    assert calls[0]["url"] == f"{app.state.settings.tool_runner_url}/analyze/sql-database-config"
    assert calls[0]["json"]["file_id"] == archive["id"]
    assert calls[0]["json"]["max_files"] == app.state.settings.sql_database_config_max_files
    assert calls[0]["json"]["max_file_bytes"] == app.state.settings.sql_database_config_max_file_bytes
    assert calls[0]["json"]["max_total_bytes"] == app.state.settings.sql_database_config_max_total_bytes


@pytest.mark.anyio
async def test_sql_database_config_service_records_runner_failure(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        archive_response = await client.post(
            "/files/archive",
            files={"file": ("sql-db.zip", make_zip_bytes({"postgresql.conf": b"port = 5432\n"}), "application/zip")},
        )
    archive = app.state.files.get(archive_response.json()["id"])
    job = app.state.jobs.create_sql_database_config_job(archive.id)

    class FailingAsyncClient:
        def __init__(self, timeout: float) -> None:
            self.timeout = timeout

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

        async def post(self, url: str, json: dict):
            raise audit_services.httpx.HTTPError("runner unavailable PGPASSWORD=super-secret-password")

    monkeypatch.setattr(audit_services.httpx, "AsyncClient", FailingAsyncClient)

    await app.state.sql_database_config_audits.run_sql_database_config_analysis(job.id)

    updated = app.state.jobs.get(job.id)
    assert updated.status == "failed"
    assert "Tool runner request failed: runner unavailable" in updated.error
    assert "super-secret-password" not in updated.error
    assert "[REDACTED]" in updated.error


@pytest.mark.anyio
async def test_redis_config_audit_job_creation_and_rejections(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    noop = NoopAuditService()
    app.state.redis_config_audits = noop
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        pdf_response = await client.post("/files/pdf", files={"file": ("sample.pdf", b"%PDF-1.4\n%%EOF\n", "application/pdf")})
        archive_response = await client.post(
            "/files/archive",
            files={"file": ("redis.zip", make_zip_bytes({"redis.conf": b"port 6379\n"}), "application/zip")},
        )
        pdf_file = pdf_response.json()
        archive_file = archive_response.json()

        redis_response = await client.post(f"/audits/redis-config/{archive_file['id']}")
        pdf_as_redis_response = await client.post(f"/audits/redis-config/{pdf_file['id']}")
        invalid_response = await client.post("/audits/redis-config/not-a-file-id")

    assert redis_response.status_code == 202
    assert redis_response.json()["audit_type"] == "redis_config_basic"
    assert pdf_as_redis_response.status_code == 400
    assert pdf_as_redis_response.json()["detail"] == "File is not an archive."
    assert invalid_response.status_code == 400


@pytest.mark.anyio
async def test_redis_config_service_calls_runner_endpoint_and_redacts(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        archive_response = await client.post(
            "/files/archive",
            files={"file": ("redis.zip", make_zip_bytes({"redis.conf": b"requirepass x\n"}), "application/zip")},
        )
    archive = app.state.files.get(archive_response.json()["id"])
    job = app.state.jobs.create_redis_config_job(archive.id)
    calls: list[dict] = []

    class FakeAsyncClient:
        def __init__(self, timeout: float) -> None:
            self.timeout = timeout

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

        async def post(self, url: str, json: dict):
            calls.append({"url": url, "json": json, "timeout": self.timeout})
            return FakeRunnerResponse(
                {
                    "analyzer": "redis_config_basic",
                    "archive_type": "zip",
                    "summary": {
                        "files_considered": 4,
                        "files_reviewed": 2,
                        "redis_files_detected": 1,
                        "sentinel_files_detected": 1,
                        "acl_files_detected": 1,
                        "dump_or_aof_files_detected": 1,
                        "configs_detected": 2,
                        "findings_count": 1,
                        "redacted_values_count": 1,
                        "truncated": False,
                    },
                    "redis_settings": [{"setting": "requirepass", "value": "super-secret-password"}],
                    "sentinel_settings": [{"setting": "sentinel auth-pass", "value": "sentinel_auth_should_not_render"}],
                    "acl_files": [{"path": "users.acl", "read": False, "content": "acl_password_hash_should_not_render"}],
                    "dump_or_aof_files": [{"path": "dump.rdb", "read": False, "content": "dump_value_should_not_render"}],
                    "findings": [
                        {
                            "id": "redis_requirepass_present_redacted",
                            "title": "Redis requirepass",
                            "level": "medium",
                            "evidence": "requirepass super-secret-password redis://:super-secret-password@redis:6379/0",
                        }
                    ],
                    "errors": [
                        "masterauth masterauth_secret_should_not_render",
                        "-----BEGIN PRIVATE KEY----- PRIVATE KEY -----END PRIVATE KEY-----",
                    ],
                }
            )

    monkeypatch.setattr(audit_services.httpx, "AsyncClient", FakeAsyncClient)

    await app.state.redis_config_audits.run_redis_config_analysis(job.id)

    updated = app.state.jobs.get(job.id)
    serialized_result = json.dumps(updated.result)
    assert updated.status == "completed"
    assert updated.result["analyzer"] == "redis_config_basic"
    assert "[REDACTED]" in serialized_result
    for secret in (
        "super-secret-password",
        "redis://:super-secret-password@redis:6379/0",
        "masterauth_secret_should_not_render",
        "sentinel_auth_should_not_render",
        "acl_password_hash_should_not_render",
        "dump_value_should_not_render",
        "PRIVATE KEY",
    ):
        assert secret not in serialized_result
    assert calls[0]["url"] == f"{app.state.settings.tool_runner_url}/analyze/redis-config"
    assert calls[0]["json"]["file_id"] == archive.id
    assert calls[0]["json"]["original_filename"] == "redis.zip"
    assert calls[0]["json"]["max_files"] == app.state.settings.redis_config_max_files
    assert calls[0]["json"]["max_file_bytes"] == app.state.settings.redis_config_max_file_bytes
    assert calls[0]["json"]["max_total_bytes"] == app.state.settings.redis_config_max_total_bytes


@pytest.mark.anyio
async def test_redis_config_api_background_job_stores_and_exposes_redacted_result(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    calls: list[dict] = []

    class FakeAsyncClient:
        def __init__(self, timeout: float) -> None:
            self.timeout = timeout

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

        async def post(self, url: str, json: dict):
            calls.append({"url": url, "json": json, "timeout": self.timeout})
            return FakeRunnerResponse(
                {
                    "analyzer": "redis_config_basic",
                    "archive_type": "zip",
                    "summary": {
                        "files_considered": 5,
                        "files_reviewed": 2,
                        "redis_files_detected": 1,
                        "sentinel_files_detected": 1,
                        "acl_files_detected": 1,
                        "dump_or_aof_files_detected": 1,
                        "configs_detected": 2,
                        "findings_count": 1,
                        "redacted_values_count": 1,
                        "truncated": False,
                    },
                    "configs": [{"path": "deploy/redis/redis.conf", "content": "requirepass super-secret-password"}],
                    "redis_settings": [{"setting": "requirepass", "value": "super-secret-password"}],
                    "sentinel_settings": [{"setting": "sentinel auth-pass", "value": "token_should_never_render"}],
                    "includes": [{"target": "/etc/redis/secrets.conf", "resolved": False, "content": "raw-api-key-123456"}],
                    "acl_files": [{"path": "deploy/redis/users.acl", "read": False, "content": "acl_password_hash_should_not_render"}],
                    "dump_or_aof_files": [{"path": "deploy/redis/dump.rdb", "read": False, "content": "dump_value_should_not_render"}],
                    "findings": [
                        {
                            "id": "redis_requirepass_present_redacted",
                            "title": "Redis requirepass is present",
                            "level": "medium",
                            "confidence": "high",
                            "category": "secrets",
                            "evidence": "requirepass super-secret-password redis://:super-secret-password@redis:6379/0",
                            "recommendation": "Authorization: Bearer token_should_never_render",
                        }
                    ],
                    "errors": [
                        "requirepass super-secret-password",
                        "redis://:super-secret-password@redis:6379/0",
                        "-----BEGIN PRIVATE KEY----- PRIVATE KEY -----END PRIVATE KEY-----",
                    ],
                }
            )

    monkeypatch.setattr(audit_services.httpx, "AsyncClient", FakeAsyncClient)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        archive_response = await client.post(
            "/files/archive",
            files={"file": ("redis.zip", make_zip_bytes({"deploy/redis/redis.conf": b"requirepass x\n"}), "application/zip")},
        )
        archive = archive_response.json()
        launch_response = await client.post(f"/audits/redis-config/{archive['id']}")
        job_id = launch_response.json()["id"]
        job_response = await client.get(f"/jobs/{job_id}")
        jobs_response = await client.get("/jobs")

    stored = app.state.jobs.get(job_id)
    stored_serialized = json.dumps(stored.result, sort_keys=True)
    public_serialized = json.dumps(job_response.json(), sort_keys=True)
    forbidden = (
        "super-secret-password",
        "raw-api-key-123456",
        "token_should_never_render",
        "redis://:super-secret-password@redis:6379/0",
        "acl_password_hash_should_not_render",
        "dump_value_should_not_render",
        "PRIVATE KEY",
    )
    assert launch_response.status_code == 202
    assert stored.status == "completed"
    assert stored.result["analyzer"] == "redis_config_basic"
    assert job_response.status_code == 200
    assert job_response.json()["status"] == "completed"
    assert job_response.json()["result"]["analyzer"] == "redis_config_basic"
    assert "[REDACTED]" in stored_serialized
    assert "[REDACTED]" in public_serialized
    assert "Redis requirepass is present" in public_serialized
    for secret in forbidden:
        assert secret not in stored_serialized
        assert secret not in public_serialized
    summary = next(item for item in jobs_response.json() if item["id"] == job_id)["summary"]
    assert summary["analyzer"] == "redis_config_basic"
    assert summary["files_reviewed"] == 2
    assert summary["configs_detected"] == 2
    assert summary["errors_count"] == 3
    assert calls[0]["url"] == f"{app.state.settings.tool_runner_url}/analyze/redis-config"
    assert calls[0]["json"]["file_id"] == archive["id"]
    assert calls[0]["json"]["max_files"] == app.state.settings.redis_config_max_files
    assert calls[0]["json"]["max_file_bytes"] == app.state.settings.redis_config_max_file_bytes
    assert calls[0]["json"]["max_total_bytes"] == app.state.settings.redis_config_max_total_bytes


@pytest.mark.anyio
async def test_redis_config_service_records_runner_failure(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        archive_response = await client.post(
            "/files/archive",
            files={"file": ("redis.zip", make_zip_bytes({"redis.conf": b"port 6379\n"}), "application/zip")},
        )
    archive = app.state.files.get(archive_response.json()["id"])
    job = app.state.jobs.create_redis_config_job(archive.id)

    class FailingAsyncClient:
        def __init__(self, timeout: float) -> None:
            self.timeout = timeout

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

        async def post(self, url: str, json: dict):
            raise audit_services.httpx.HTTPError("runner unavailable")

    monkeypatch.setattr(audit_services.httpx, "AsyncClient", FailingAsyncClient)

    await app.state.redis_config_audits.run_redis_config_analysis(job.id)

    updated = app.state.jobs.get(job.id)
    assert updated.status == "failed"
    assert updated.error == "Tool runner request failed: runner unavailable"


def make_active_dry_run_payload(target: str = "https://example.test/path?ok=value", **overrides) -> dict:
    payload = {
        "target": target,
        "authorization": {
            "confirmed": True,
            "statement": "I confirm I own or am authorized to test this target.",
            "scope": "single-target",
        },
        "mode": "dry_run",
        "profile": "http_header_probe_preview",
        "limits": {
            "max_requests": 0,
            "timeout_seconds": 0,
            "max_redirects": 0,
            "response_size_bytes": 0,
        },
    }
    payload.update(overrides)
    return payload


def make_active_http_header_probe_payload(target: str = "https://example.test/path?ok=value", **overrides) -> dict:
    payload = {
        "target": target,
        "authorization": {
            "confirmed": True,
            "live_traffic_confirmed": True,
            "statement": "I confirm I own or am authorized to test this target.",
            "scope": "single-target",
        },
        "mode": "live_header_probe",
        "profile": "http_header_probe",
        "limits": {
            "max_targets": 1,
            "max_requests": 1,
            "timeout_seconds": 3,
            "max_redirects": 0,
            "response_body_bytes": 0,
            "max_response_header_bytes": 32768,
            "max_dns_answers": 8,
            "retries": 0,
            "concurrency": 1,
        },
    }
    payload.update(overrides)
    return payload


def make_active_nmap_basic_payload(**overrides) -> dict:
    payload = {
        "mode": "live_nmap_basic",
        "profile": "tcp_connect_small",
        "targets": ["192.168.56.10"],
        "ports": [22, 80, 443],
        "authorization_confirmed": True,
        "local_private_scope_confirmed": True,
        "live_traffic_confirmed": True,
    }
    payload.update(overrides)
    return payload


def make_active_tls_basic_payload(**overrides) -> dict:
    payload = {
        "mode": "live_tls_basic",
        "profile": "tls_handshake_summary",
        "target": "192.168.56.10",
        "port": 443,
        "authorization_confirmed": True,
        "local_private_scope_confirmed": True,
        "live_traffic_confirmed": True,
    }
    payload.update(overrides)
    return payload


def make_active_dns_inventory_payload(**overrides) -> dict:
    payload = {
        "mode": "live_dns_inventory",
        "profile": "dns_inventory_authorized",
        "domain": "example.com",
        "record_types": ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "CAA"],
        "include_security_records": True,
        "include_subdomain_discovery": True,
        "attempt_zone_transfer": False,
        "authorization_confirmed": True,
        "local_private_or_owned_scope_confirmed": True,
        "live_dns_queries_confirmed": True,
    }
    payload.update(overrides)
    return payload


ACTIVE_NMAP_BASIC_NO_LIVE_FORBIDDEN_STRINGS = (
    "192.168.56.10",
    "nas-01.local",
    "secret-lab.internal",
    "PrivateServer",
    "9.9.9",
    "nmap -sT",
    "<nmaprun",
    "stdout with",
    "stderr for",
    "token_should_never_render",
    "confirmed " + "vulnerability",
    "exploit" + "able",
    "target is " + "safe",
    "all ports " + "found",
)


def assert_active_nmap_basic_no_live_job_payload(job_payload: dict, *, expected_lifecycle_state: str) -> None:
    assert job_payload["audit_type"] == "active_nmap_basic"
    assert job_payload["file_id"] is None
    assert job_payload["target_url"] == "[REDACTED_TARGET]"
    assert job_payload["target_domain"] is None
    result = job_payload["result"]
    assert result["audit_type"] == "active_nmap_basic"
    assert result["capability"] == "active_nmap_basic"
    assert result["mode"] == "live_nmap_basic"
    assert result["profile"] == "tcp_connect_small"
    assert result["status"] == "not_executed"
    assert result["lifecycle_state"] == expected_lifecycle_state
    assert result["summary"]["observation_count"] == 0
    assert result["summary"]["manual_validation_required"] is True
    assert result["execution"] == {
        "nmap_executed": False,
        "network_requests_sent": 0,
        "dns_queries_sent": 0,
        "subprocess_invoked": False,
        "active_tools_real_call_allowed": False,
        "target_expansion_performed": False,
        "evidence_available": False,
    }
    assert result["authorization"]["authorization_confirmed"] is True
    assert result["authorization"]["local_private_scope_confirmed"] is True
    assert result["authorization"]["live_traffic_confirmed"] is True
    assert result["authorization"]["authorization_is_ownership_proof"] is False
    assert result["policy"]["target_values_stored"] is False
    for forbidden_key in (
        "target",
        "raw_target",
        "raw_payload",
        "command",
        "stdout",
        "stderr",
        "xml",
        "raw_xml",
        "ptr",
        "resolved_ip",
        "banner",
        "version",
        "service_details",
        "credentials",
        "headers",
        "cookies",
        "tokens",
        "observations",
        "evidence",
        "port_observations",
    ):
        assert forbidden_key not in result


def assert_active_nmap_basic_real_minimal_job_payload(job_payload: dict) -> None:
    assert job_payload["audit_type"] == "active_nmap_basic"
    assert job_payload["file_id"] is None
    assert job_payload["target_url"] == "[REDACTED_TARGET]"
    assert job_payload["target_domain"] is None
    result = job_payload["result"]
    assert result["audit_type"] == "active_nmap_basic"
    assert result["capability"] == "active_nmap_basic"
    assert result["mode"] == "live_nmap_basic"
    assert result["profile"] == "tcp_connect_small"
    assert result["status"] == "completed"
    assert result["lifecycle_state"] == "completed_real_minimal"
    assert result["reason"] == "active_tools_real_result"
    assert result["manual_validation_required"] is True
    assert result["result_interpretation"] == "observed_exposure_review_indicator"
    assert result["summary"]["observation_count"] == 1
    assert result["summary"]["manual_validation_required"] is True
    assert result["summary"]["open_tcp_observations_count"] == 1
    assert result["execution"]["nmap_executed"] is True
    assert result["execution"]["network_requests_sent"] == 1
    assert result["execution"]["dns_queries_sent"] == 0
    assert result["execution"]["subprocess_invoked"] is False
    assert result["execution"]["subprocess_invoked_inside_active_tools"] is True
    assert result["execution"]["active_tools_real_call_allowed"] is True
    assert result["execution"]["target_expansion_performed"] is False
    assert result["execution"]["evidence_available"] is True
    assert result["port_observations"] == [
        {
            "port": 443,
            "protocol": "tcp",
            "state": "open",
            "manual_validation_required": True,
            "result_interpretation": "observed_exposure_review_indicator",
            "reason": "syn-ack",
        }
    ]
    assert result["policy"]["target_values_stored"] is False
    for forbidden_key in (
        "target",
        "raw_target",
        "raw_payload",
        "command",
        "argv",
        "stdout",
        "stderr",
        "xml",
        "raw_xml",
        "ptr",
        "resolved_ip",
        "banner",
        "version",
        "service_details",
        "credentials",
        "headers",
        "cookies",
        "tokens",
        "observations",
        "evidence",
    ):
        assert forbidden_key not in result


def assert_no_active_nmap_basic_no_live_leaks(value: object) -> None:
    serialized = json.dumps(value, sort_keys=True)
    for forbidden in ACTIVE_NMAP_BASIC_NO_LIVE_FORBIDDEN_STRINGS:
        assert forbidden not in serialized


ACTIVE_NMAP_BASIC_NO_LIVE_CAVEATS = (
    "No Nmap executed",
    "No network requests",
    "No DNS queries",
    "No evidence collected",
    "No observations available",
    "Manual validation required",
    "No-live lifecycle record, not a target finding",
)


def assert_active_nmap_basic_no_live_caveats(value: object) -> None:
    serialized = json.dumps(value, sort_keys=True) if not isinstance(value, str) else value
    for caveat in ACTIVE_NMAP_BASIC_NO_LIVE_CAVEATS:
        assert caveat in serialized


def install_active_nmap_basic_fake_executor(results: list[dict]) -> FakeActiveNmapBasicExecutorAdapter:
    adapter = FakeActiveNmapBasicExecutorAdapter(results)
    app.state.active_nmap_basic_service = ActiveNmapBasicService(app.state.settings, app.state.jobs, adapter)
    return adapter


def mocked_nmap_completed_xml() -> str:
    return """
    <nmaprun args="nmap -sT -p 443 192.168.56.10">
      <host>
        <address addr="192.168.56.10"/>
        <hostnames><hostname name="secret-lab.internal"/></hostnames>
        <ports>
          <port protocol="tcp" portid="443">
            <state state="open" reason="syn-ack"/>
            <service name="https" product="PrivateServer" version="9.9.9"/>
          </port>
        </ports>
      </host>
    </nmaprun>
    """


def make_active_tools_health_payload(**overrides) -> dict:
    payload = {
        "service": "active-tools",
        "status": "scaffold_ready",
        "capabilities": {
            "active_nmap_basic": {
                "status": "disabled_no_scan",
                "execution_enabled": False,
                "target_input_allowed": False,
            }
        },
        "network_requests_sent": 0,
        "nmap_executed": False,
    }
    active_nmap_basic = overrides.pop("active_nmap_basic", None)
    payload.update(overrides)
    if active_nmap_basic is not None:
        payload["capabilities"]["active_nmap_basic"].update(active_nmap_basic)
    return payload


def make_active_tools_nmap_basic_request(**overrides) -> dict:
    payload = {
        "mode": "live_nmap_basic",
        "profile": "tcp_connect_small",
        "request_id": "request-123",
        "job_id": "job-123",
        "correlation_id": "corr-123",
        "target_unit": {
            "target": "example.invalid",
            "target_kind": "private_hostname",
            "accepted_ports": [443],
        },
        "confirmations_verified_by_backend": True,
        "limits": {
            "process_timeout_seconds": 5,
            "stdout_max_bytes": 8192,
            "stderr_max_bytes": 2048,
            "response_max_bytes": 32768,
        },
    }
    payload.update(overrides)
    return payload


def make_active_tools_nmap_basic_response(**overrides) -> dict:
    payload = {
        "service": "active-tools",
        "status": "not_executed",
        "capability": "active_nmap_basic",
        "mode": "live_nmap_basic",
        "profile": "tcp_connect_small",
        "execution_enabled": False,
        "target_input_allowed": False,
        "manual_validation_required": True,
        "reason": "active_tools_internal_service_skeleton_no_scan",
        "observations": [],
        "job_created": False,
        "target_expansion_performed": False,
        "network_requests_sent": 0,
        "summary": {
            "target_count": 1,
            "port_count": 1,
            "nmap_executed": False,
            "evidence_available": False,
        },
        "warnings": ["no_scan_service_skeleton"],
        "errors": [],
    }
    summary = overrides.pop("summary", None)
    payload.update(overrides)
    if summary is not None:
        payload["summary"].update(summary)
    return payload


def make_active_tools_nmap_basic_real_response(**overrides) -> dict:
    payload = {
        "service": "active-tools",
        "status": "completed",
        "capability": "active_nmap_basic",
        "mode": "live_nmap_basic",
        "profile": "tcp_connect_small",
        "target_kind": "private_hostname",
        "execution_enabled": True,
        "target_input_allowed": False,
        "manual_validation_required": True,
        "result_interpretation": "observed_exposure_review_indicator",
        "observations": [
            {
                "port": 443,
                "protocol": "tcp",
                "state": "open",
                "reason": "syn-ack",
                "manual_validation_required": True,
                "result_interpretation": "observed_exposure_review_indicator",
            }
        ],
        "output_truncated": False,
        "job_created": False,
        "target_expansion_performed": False,
        "network_requests_sent": 1,
        "execution_metadata": {
            "executor": "active_nmap_basic",
            "nmap_invoked": True,
            "subprocess_invoked_inside_active_tools": True,
        },
        "summary": {
            "target_count": 1,
            "port_count": 1,
            "nmap_executed": True,
            "evidence_available": True,
        },
        "warnings": [],
        "errors": [],
    }
    summary = overrides.pop("summary", None)
    payload.update(overrides)
    if summary is not None:
        payload["summary"].update(summary)
    return payload


def make_active_nmap_lifecycle_plan(**overrides):
    payload = make_active_nmap_basic_payload(targets=["example.invalid"], ports=[443])
    payload.update(overrides)
    return build_active_nmap_basic_handoff_plan(payload)


def make_active_tools_nmap_basic_client_result(**overrides):
    payload = {
        "available": True,
        "status": "not_executed",
        "service": "active-tools",
        "capability": "active_nmap_basic",
        "mode": "live_nmap_basic",
        "profile": "tcp_connect_small",
        "execution_enabled": False,
        "target_input_allowed": False,
        "manual_validation_required": True,
        "job_created": False,
        "target_expansion_performed": False,
        "network_requests_sent": 0,
        "nmap_executed": False,
        "evidence_available": False,
        "observations": [],
        "warnings": ["no_scan_service_skeleton"],
        "errors": [],
        "error_code": None,
    }
    payload.update(overrides)
    return payload


def make_active_tools_nmap_basic_real_client_result(**overrides):
    payload = {
        "available": True,
        "status": "completed",
        "service": "active-tools",
        "capability": "active_nmap_basic",
        "mode": "live_nmap_basic",
        "profile": "tcp_connect_small",
        "target_kind": "private_ip",
        "execution_enabled": True,
        "target_input_allowed": False,
        "manual_validation_required": True,
        "job_created": False,
        "target_expansion_performed": False,
        "network_requests_sent": 1,
        "nmap_executed": True,
        "evidence_available": True,
        "observations": [
            {
                "port": 443,
                "protocol": "tcp",
                "state": "open",
                "reason": "syn-ack",
                "manual_validation_required": True,
                "result_interpretation": "observed_exposure_review_indicator",
            }
        ],
        "output_truncated": False,
        "execution_metadata": {
            "executor": "active_nmap_basic",
            "nmap_invoked": True,
            "subprocess_invoked_inside_active_tools": True,
            "duration_ms": 12,
        },
        "result_interpretation": "observed_exposure_review_indicator",
        "warnings": [],
        "errors": [],
        "error_code": None,
    }
    payload.update(overrides)
    return payload


def test_active_nmap_basic_boundary_request_builder_produces_single_safe_handoff_unit():
    plan = build_active_nmap_basic_handoff_plan(make_active_nmap_basic_payload(targets=["192.168.56.10"], ports=[443]))
    assert len(plan.units) == 1

    request = build_active_nmap_basic_boundary_request(
        plan.units[0],
        job_id="job-123",
        request_id="request-123",
        correlation_id="corr-123",
    )

    assert request["mode"] == "live_nmap_basic"
    assert request["profile"] == "tcp_connect_small"
    assert request["request_id"] == "request-123"
    assert request["job_id"] == "job-123"
    assert request["correlation_id"] == "corr-123"
    assert request["confirmations_verified_by_backend"] is True
    assert request["target_unit"] == {
        "target": "192.168.56.10",
        "target_kind": "private_ip",
        "accepted_ports": [443],
    }
    assert request["limits"]["process_timeout_seconds"] > 0
    assert request["limits"]["stdout_max_bytes"] > 0
    assert request["limits"]["stderr_max_bytes"] > 0
    assert request["limits"]["response_max_bytes"] > 0
    serialized = json.dumps(request, sort_keys=True)
    for forbidden in (
        "raw_flags",
        "extra_args",
        "scripts",
        "credentials",
        "headers",
        "cookies",
        "tokens",
        "target_files",
        "shell_command",
        "--script",
        "nmap -sT",
    ):
        assert forbidden not in serialized


def test_active_nmap_basic_boundary_request_builder_sanitizes_neutral_ids_without_target_leak():
    plan = build_active_nmap_basic_handoff_plan(make_active_nmap_basic_payload(targets=["lab.internal"], ports=[22]))

    request = build_active_nmap_basic_boundary_request(
        plan.units[0],
        job_id="job id with spaces 192.168.56.10",
        request_id="request/id?with#markers",
        correlation_id="corr token 192.168.56.10",
    )

    assert request["request_id"] == "request-id-with-markers"
    assert " " not in request["job_id"]
    assert " " not in request["correlation_id"]
    assert "192.168.56.10" not in request["job_id"]
    assert "192.168.56.10" not in request["correlation_id"]
    assert request["target_unit"]["target"] == "lab.internal"
    assert request["target_unit"]["target_kind"] == "private_hostname"


def test_active_nmap_basic_boundary_response_validator_accepts_minimal_completed_observation():
    response = validate_active_nmap_basic_boundary_response(
        {
            "status": "completed",
            "profile": "tcp_connect_small",
            "target_kind": "private_ip",
            "manual_validation_required": True,
            "result_interpretation": "observed_exposure_review_indicator",
            "observations": [
                {
                    "port": 443,
                    "protocol": "tcp",
                    "state": "open",
                    "reason": "syn-ack",
                    "manual_validation_required": True,
                    "result_interpretation": "observed_exposure_review_indicator",
                }
            ],
            "output_truncated": False,
            "execution_metadata": {
                "executor": "active_nmap_basic",
                "nmap_invoked": True,
                "subprocess_invoked_inside_active_tools": True,
                "duration_ms": 1234,
            },
            "warnings": [],
            "errors": [],
        },
        accepted_ports=(443,),
    )

    assert response["status"] == "completed"
    assert response["profile"] == "tcp_connect_small"
    assert response["target_kind"] == "private_ip"
    assert response["manual_validation_required"] is True
    assert response["result_interpretation"] == "observed_exposure_review_indicator"
    assert response["observations"] == [
        {
            "port": 443,
            "protocol": "tcp",
            "state": "open",
            "manual_validation_required": True,
            "result_interpretation": "observed_exposure_review_indicator",
            "reason": "syn-ack",
        }
    ]
    assert response["execution_metadata"]["executor"] == "active_nmap_basic"


def test_active_nmap_basic_boundary_response_validator_rejects_sensitive_unexpected_fields():
    response = validate_active_nmap_basic_boundary_response(
        {
            "status": "completed",
            "profile": "tcp_connect_small",
            "manual_validation_required": False,
            "result_interpretation": "confirmed vulnerability",
            "observations": [{"port": 443, "protocol": "tcp", "state": "open"}],
            "raw_xml": "<nmaprun args='nmap -sT 203.0.113.10' />",
            "ptr_hostname": "redacted-ptr.example.internal",
            "resolved_ip": "203.0.113.10",
            "stdout": "stdout token_should_never_render",
            "stderr": "stderr token_should_never_render",
            "command": "nmap -sT --script default",
            "service": "https",
            "banner": "SyntheticPrivateServer",
            "version": "9.9.9",
            "script_output": "synthetic NSE-like output",
            "credentials": {"password": "super-secret-password"},
            "headers": {"Authorization": "Bearer token_should_never_render"},
            "cookies": {"session": "secret-session-cookie"},
            "tokens": ["token_should_never_render"],
        },
        accepted_ports=(443,),
    )

    assert response["status"] == "blocked"
    assert response["manual_validation_required"] is True
    assert response["result_interpretation"] == "observed_exposure_review_indicator"
    assert response["errors"] == ["unexpected_fields"]
    serialized = json.dumps(response, sort_keys=True)
    for forbidden in (
        "203.0.113.10",
        "redacted-ptr.example.internal",
        "<nmaprun",
        "nmap -sT",
        "stdout token_should_never_render",
        "stderr token_should_never_render",
        "SyntheticPrivateServer",
        "9.9.9",
        "synthetic NSE-like output",
        "super-secret-password",
        "token_should_never_render",
        "secret-session-cookie",
        "confirmed vulnerability",
    ):
        assert forbidden not in serialized


def test_active_nmap_basic_boundary_response_validator_detects_policy_drift_port():
    response = validate_active_nmap_basic_boundary_response(
        {
            "status": "completed",
            "profile": "tcp_connect_small",
            "manual_validation_required": True,
            "result_interpretation": "observed_exposure_review_indicator",
            "observations": [{"port": 8443, "protocol": "tcp", "state": "open", "reason": "syn-ack"}],
        },
        accepted_ports=(443,),
    )

    assert response["status"] == "blocked"
    assert response["errors"] == ["policy_drift"]
    assert response["observations"] == []


def test_active_nmap_basic_boundary_response_validator_rejects_unallowlisted_state_and_reason():
    for observation in (
        {"port": 443, "protocol": "tcp", "state": "confirmed vulnerability", "reason": "syn-ack"},
        {"port": 443, "protocol": "tcp", "state": "open", "reason": "service banner token_should_never_render"},
    ):
        response = validate_active_nmap_basic_boundary_response(
            {
                "status": "completed",
                "profile": "tcp_connect_small",
                "manual_validation_required": True,
                "result_interpretation": "observed_exposure_review_indicator",
                "observations": [observation],
            },
            accepted_ports=(443,),
        )

        assert response["status"] == "malformed"
        assert response["errors"] == ["malformed_output"]
        assert response["observations"] == []
        serialized = json.dumps(response, sort_keys=True)
        assert "confirmed vulnerability" not in serialized
        assert "token_should_never_render" not in serialized


def test_active_nmap_basic_boundary_response_validator_blocks_oversized_payload():
    response = validate_active_nmap_basic_boundary_response(
        {
            "status": "completed",
            "profile": "tcp_connect_small",
            "manual_validation_required": True,
            "result_interpretation": "observed_exposure_review_indicator",
            "observations": [],
            "warnings": ["active_tools_unavailable"],
            "errors": ["network_failure"],
            "padding": "x" * 40_000,
        },
        accepted_ports=(443,),
    )

    assert response["status"] == "failed"
    assert response["errors"] == ["result_too_large"]
    assert response["output_truncated"] is True
    assert response["observations"] == []


def test_active_nmap_basic_boundary_error_mapping_covers_controlled_states():
    expected = {
        "active_tools_unavailable": "failed",
        "active_tools_timeout": "timed_out",
        "nmap_missing": "nmap_missing",
        "malformed_output": "malformed",
        "unsupported_shape": "unsupported_shape",
        "policy_drift": "blocked",
        "result_too_large": "failed",
        "unexpected_fields": "blocked",
        "network_failure": "failed",
        "fqdn_resolution_failed": "failed",
    }

    for error_code, status in expected.items():
        response = map_active_nmap_basic_boundary_error(error_code)
        assert response["status"] == status
        assert response["errors"] == [error_code]
        assert response["manual_validation_required"] is True
        assert response["result_interpretation"] == "observed_exposure_review_indicator"
        assert "target" not in json.dumps(response, sort_keys=True)


@pytest.mark.anyio
async def test_active_nmap_basic_boundary_policy_drift_job_is_redacted_and_wrong_owner_generic(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    now = datetime.now(timezone.utc)
    result = validate_active_nmap_basic_boundary_response(
        {
            "status": "blocked",
            "profile": "tcp_connect_small",
            "manual_validation_required": True,
            "result_interpretation": "observed_exposure_review_indicator",
            "observations": [],
            "errors": ["policy_drift"],
            "warnings": [],
            "execution_metadata": {"executor": "active_nmap_basic", "duration_ms": 12},
        },
        accepted_ports=(443,),
    )
    job = JobRecord(
        id="b" * 31 + "1",
        audit_type="active_nmap_basic",
        file_id=None,
        target_url="192.168.56.10",
        status="completed",
        created_at=now,
        updated_at=now,
        result=result,
        error="policy_drift for 192.168.56.10 redacted-ptr.example.internal",
    )
    wrong_owner_job = JobRecord(
        id="b" * 31 + "2",
        owner_id="other-owner",
        audit_type="active_nmap_basic",
        file_id=None,
        target_url="redacted-ptr.example.internal",
        status="completed",
        created_at=now,
        updated_at=now,
        result=result,
        error="policy_drift for redacted-ptr.example.internal",
    )
    app.state.jobs.save(job)
    app.state.jobs.save(wrong_owner_job)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        job_response = await client.get(f"/jobs/{job.id}")
        wrong_owner_response = await client.get(f"/jobs/{wrong_owner_job.id}")
        exports = {
            report_format: await client.get(f"/jobs/{job.id}/export/{report_format}")
            for report_format in ("markdown", "html", "xml", "pdf")
        }

    assert job_response.status_code == 200
    assert job_response.json()["result"]["status"] == "blocked"
    assert job_response.json()["result"]["errors"] == ["policy_drift"]
    assert wrong_owner_response.status_code == 404
    combined = json.dumps(job_response.json(), sort_keys=True)
    combined += "\n" + "\n".join(
        response.text if report_format != "pdf" else response.content.decode("latin1", errors="ignore")
        for report_format, response in exports.items()
    )
    assert "policy_drift" in combined
    assert "Observed TCP exposure" in combined
    assert "Review indicator" in combined
    assert "Manual validation required" in combined
    for forbidden in ("192.168.56.10", "redacted-ptr.example.internal", "confirmed vulnerability", "exploitable", "target is safe"):
        assert forbidden not in combined


def test_active_nmap_basic_boundary_source_has_no_live_endpoint_archive_or_runner_integration():
    boundary_source = Path("backend/app/active_nmap_boundary.py").read_text(encoding="utf-8")
    runner_source = Path("tools/runner/main.py").read_text(encoding="utf-8")
    archive_source = Path("backend/app/main.py").read_text(encoding="utf-8")

    for forbidden in (
        "import " + "subprocess",
        "subprocess.",
        "shell" + "=True",
        "os." + "system",
        "po" + "pen",
        "P" + "open(",
        "httpx.",
        "docker",
        "compose",
        "curl",
    ):
        assert forbidden not in boundary_source.lower()
    assert "active_nmap_basic" not in runner_source
    assert "nmap_basic" not in runner_source
    assert "active_nmap_basic" not in archive_source[archive_source.find("async def launch_archive_audit") : archive_source.find("async def launch_manifest_audit")]


def test_active_tools_health_client_config_defaults_to_unconfigured_and_allows_explicit_internal_url(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_DATA_DIR", str(tmp_path))

    settings = load_settings()

    assert DEFAULT_ACTIVE_TOOLS_URL == ""
    assert settings.active_tools_url == ""
    assert settings.active_tools_health_timeout_seconds == DEFAULT_ACTIVE_TOOLS_HEALTH_TIMEOUT_SECONDS

    monkeypatch.setenv("INSPECTRA_ACTIVE_TOOLS_URL", " http://active-tools:8080/ ")
    monkeypatch.setenv("INSPECTRA_ACTIVE_TOOLS_HEALTH_TIMEOUT_SECONDS", "1.25")

    configured = load_settings()

    assert configured.active_tools_url == "http://active-tools:8080"
    assert configured.active_tools_health_timeout_seconds == 1.25


@pytest.mark.anyio
async def test_active_tools_health_client_unconfigured_returns_controlled_error():
    result = await check_active_tools_health("")

    assert result == {
        "available": False,
        "status": None,
        "active_nmap_basic_status": None,
        "execution_enabled": None,
        "target_input_allowed": None,
        "network_requests_sent": None,
        "nmap_executed": None,
        "error_code": "active_tools_unconfigured",
    }


@pytest.mark.anyio
async def test_active_tools_health_client_rejects_non_internal_url_without_request():
    calls = []

    def handler(request):
        calls.append(str(request.url))
        return Response(200, json=make_active_tools_health_payload())

    for url in (
        "https://example.com",
        "http://active-tools:8080/private/path",
        "http://user:pass@active-tools:8080",
    ):
        result = await check_active_tools_health(url, transport=MockTransport(handler))
        assert result["available"] is False
        assert result["error_code"] == "active_tools_unconfigured"

    assert calls == []


@pytest.mark.anyio
async def test_active_tools_health_client_valid_fake_health_returns_available_true():
    paths = []

    def handler(request):
        paths.append(request.url.path)
        assert request.method == "GET"
        return Response(200, json=make_active_tools_health_payload())

    result = await check_active_tools_health(
        "http://active-tools:8080",
        timeout_seconds=0.25,
        transport=MockTransport(handler),
    )

    assert paths == ["/health"]
    assert result == {
        "available": True,
        "status": "scaffold_ready",
        "active_nmap_basic_status": "disabled_no_scan",
        "execution_enabled": False,
        "target_input_allowed": False,
        "network_requests_sent": 0,
        "nmap_executed": False,
        "error_code": None,
    }


@pytest.mark.anyio
async def test_active_tools_health_client_preserves_disabled_no_scan_state_without_enabling_targets():
    def handler(request):
        return Response(200, json=make_active_tools_health_payload())

    result = await check_active_tools_health(
        "http://active-tools:8080/",
        transport=MockTransport(handler),
    )

    assert result["active_nmap_basic_status"] == "disabled_no_scan"
    assert result["execution_enabled"] is False
    assert result["target_input_allowed"] is False
    assert result["network_requests_sent"] == 0
    assert result["nmap_executed"] is False
    assert result["available"] is True


@pytest.mark.anyio
async def test_active_tools_health_client_rejects_nmap_executed_true_as_invalid_response():
    def handler(request):
        return Response(200, json=make_active_tools_health_payload(nmap_executed=True))

    result = await check_active_tools_health("http://active-tools:8080", transport=MockTransport(handler))

    assert result["available"] is False
    assert result["nmap_executed"] is True
    assert result["error_code"] == "active_tools_invalid_response"


@pytest.mark.anyio
async def test_active_tools_health_client_rejects_nonzero_network_requests_as_invalid_response():
    def handler(request):
        return Response(200, json=make_active_tools_health_payload(network_requests_sent=1))

    result = await check_active_tools_health("http://active-tools:8080", transport=MockTransport(handler))

    assert result["available"] is False
    assert result["network_requests_sent"] == 1
    assert result["error_code"] == "active_tools_invalid_response"


@pytest.mark.anyio
async def test_active_tools_health_client_does_not_reflect_dangerous_unexpected_fields():
    payload = make_active_tools_health_payload()
    payload["raw_xml"] = "<nmaprun args='nmap -sT token_should_never_render' />"
    payload["credentials"] = {"password": "token_should_never_render"}
    payload["capabilities"]["active_nmap_basic"]["command"] = "nmap -sT --script default token_should_never_render"

    def handler(request):
        return Response(200, json=payload)

    result = await check_active_tools_health("http://active-tools:8080", transport=MockTransport(handler))

    assert result["available"] is False
    assert result["error_code"] == "active_tools_unexpected_fields"
    serialized = json.dumps(result, sort_keys=True)
    for forbidden in ("token_should_never_render", "<nmaprun", "nmap -sT", "--script", "credentials", "raw_xml"):
        assert forbidden not in serialized


@pytest.mark.anyio
async def test_active_tools_health_client_timeout_maps_to_controlled_error():
    def handler(request):
        raise ReadTimeout("active-tools health timed out", request=request)

    result = await check_active_tools_health("http://active-tools:8080", transport=MockTransport(handler))

    assert result["available"] is False
    assert result["error_code"] == "active_tools_timeout"


@pytest.mark.anyio
async def test_active_tools_health_client_connection_error_maps_to_unavailable():
    def handler(request):
        raise ConnectError("active-tools unavailable", request=request)

    result = await check_active_tools_health("http://active-tools:8080", transport=MockTransport(handler))

    assert result["available"] is False
    assert result["error_code"] == "active_tools_unavailable"


@pytest.mark.anyio
async def test_active_tools_health_client_invalid_json_maps_to_invalid_response():
    def handler(request):
        return Response(200, content=b"{not-json")

    result = await check_active_tools_health("http://active-tools:8080", transport=MockTransport(handler))

    assert result["available"] is False
    assert result["error_code"] == "active_tools_invalid_response"


@pytest.mark.anyio
async def test_active_tools_health_client_only_calls_health_not_nmap_basic():
    paths = []

    def handler(request):
        paths.append(request.url.path)
        if request.url.path == "/active/nmap-basic":
            raise AssertionError("backend health client must not call active nmap basic")
        return Response(200, json=make_active_tools_health_payload())

    result = await check_active_tools_health("http://active-tools:8080", transport=MockTransport(handler))

    assert result["available"] is True
    assert paths == ["/health"]
    assert "/active/nmap-basic" not in paths


@pytest.mark.anyio
async def test_active_tools_nmap_basic_client_success_contract_uses_post_only_and_redacts_target():
    paths = []
    request_payload = make_active_tools_nmap_basic_request()

    def handler(request):
        paths.append(request.url.path)
        sent_payload = json.loads(request.content.decode("utf-8"))
        assert request.method == "POST"
        assert request.url.path == "/active/nmap-basic"
        assert sent_payload == request_payload
        return Response(200, json=make_active_tools_nmap_basic_response())

    result = await run_active_nmap_basic(
        "http://active-tools:8080",
        request_payload,
        timeout_seconds=0.25,
        transport=MockTransport(handler),
    )

    assert paths == ["/active/nmap-basic"]
    assert result == {
        "available": True,
        "status": "not_executed",
        "service": "active-tools",
        "capability": "active_nmap_basic",
        "mode": "live_nmap_basic",
        "profile": "tcp_connect_small",
        "execution_enabled": False,
        "target_input_allowed": False,
        "manual_validation_required": True,
        "job_created": False,
        "target_expansion_performed": False,
        "network_requests_sent": 0,
        "nmap_executed": False,
        "evidence_available": False,
        "observations": [],
        "warnings": ["no_scan_service_skeleton"],
        "errors": [],
        "error_code": None,
    }
    assert "example.invalid" not in json.dumps(result, sort_keys=True)


@pytest.mark.anyio
async def test_active_tools_nmap_basic_client_accepts_real_minimal_contract_and_redacts_target():
    request_payload = make_active_tools_nmap_basic_request()

    def handler(request):
        sent_payload = json.loads(request.content.decode("utf-8"))
        assert request.method == "POST"
        assert request.url.path == "/active/nmap-basic"
        assert sent_payload == request_payload
        return Response(200, json=make_active_tools_nmap_basic_real_response())

    result = await run_active_nmap_basic(
        "http://active-tools:8080",
        request_payload,
        timeout_seconds=0.25,
        transport=MockTransport(handler),
    )

    assert result["available"] is True
    assert result["status"] == "completed"
    assert result["execution_enabled"] is True
    assert result["target_input_allowed"] is False
    assert result["job_created"] is False
    assert result["target_expansion_performed"] is False
    assert result["network_requests_sent"] == 1
    assert result["nmap_executed"] is True
    assert result["evidence_available"] is True
    assert result["observations"] == [
        {
            "port": 443,
            "protocol": "tcp",
            "state": "open",
            "reason": "syn-ack",
            "manual_validation_required": True,
            "result_interpretation": "observed_exposure_review_indicator",
        }
    ]
    assert result["execution_metadata"]["executor"] == "active_nmap_basic"
    assert result["execution_metadata"]["subprocess_invoked_inside_active_tools"] is True
    assert result["result_interpretation"] == "observed_exposure_review_indicator"
    serialized = json.dumps(result, sort_keys=True)
    for forbidden in ("example.invalid", "nmap -sT", "<nmaprun", "stdout", "stderr", "PrivateServer", "9.9.9"):
        assert forbidden not in serialized


@pytest.mark.anyio
async def test_active_tools_nmap_basic_client_rejects_real_response_policy_drift_or_raw_output():
    dangerous_responses = [
        make_active_tools_nmap_basic_real_response(observations=[{"port": 22, "protocol": "tcp", "state": "open"}]),
        make_active_tools_nmap_basic_real_response(
            observations=[
                {
                    "port": 443,
                    "protocol": "tcp",
                    "state": "confirmed vulnerability",
                    "reason": "syn-ack",
                    "manual_validation_required": True,
                    "result_interpretation": "observed_exposure_review_indicator",
                }
            ]
        ),
        make_active_tools_nmap_basic_real_response(raw_xml="<nmaprun args='nmap -sT example.invalid'/>"),
        make_active_tools_nmap_basic_real_response(execution_metadata={"executor": "active_nmap_basic", "raw_command": "nmap -sT example.invalid"}),
        make_active_tools_nmap_basic_real_response(target_input_allowed=True),
        make_active_tools_nmap_basic_real_response(target_expansion_performed=True),
        make_active_tools_nmap_basic_real_response(job_created=True),
    ]

    for response_payload in dangerous_responses:
        def handler(request, response_payload=response_payload):
            return Response(200, json=response_payload)

        result = await run_active_nmap_basic(
            "http://active-tools:8080",
            make_active_tools_nmap_basic_request(),
            transport=MockTransport(handler),
        )

        assert result["available"] is False
        assert result["error_code"] in {"active_tools_invalid_response", "active_tools_unexpected_fields"}
        serialized = json.dumps(result, sort_keys=True)
        assert "example.invalid" not in serialized
        assert "<nmaprun" not in serialized
        assert "nmap -sT" not in serialized


@pytest.mark.anyio
async def test_active_tools_nmap_basic_client_rejects_invalid_request_without_calling_transport():
    calls = []
    request_payload = make_active_tools_nmap_basic_request(raw_command="nmap -sT example.invalid")

    def handler(request):
        calls.append(request.url.path)
        return Response(200, json=make_active_tools_nmap_basic_response())

    result = await run_active_nmap_basic(
        "http://active-tools:8080",
        request_payload,
        transport=MockTransport(handler),
    )

    assert calls == []
    assert result["available"] is False
    assert result["status"] == "blocked"
    assert result["error_code"] == "active_tools_unexpected_fields"
    serialized = json.dumps(result, sort_keys=True)
    assert "example.invalid" not in serialized
    assert "nmap -sT" not in serialized


@pytest.mark.anyio
async def test_active_tools_nmap_basic_client_unconfigured_returns_controlled_error_without_leaking_target():
    request_payload = make_active_tools_nmap_basic_request()

    result = await run_active_nmap_basic("", request_payload)

    assert result["available"] is False
    assert result["status"] == "failed"
    assert result["error_code"] == "active_tools_unconfigured"
    assert "example.invalid" not in json.dumps(result, sort_keys=True)


@pytest.mark.anyio
async def test_active_tools_nmap_basic_client_rejects_non_internal_url_without_request():
    calls = []

    def handler(request):
        calls.append(str(request.url))
        return Response(200, json=make_active_tools_nmap_basic_response())

    for url in (
        "https://example.com",
        "http://active-tools:8080/private/path",
        "http://user:pass@active-tools:8080",
    ):
        result = await run_active_nmap_basic(
            url,
            make_active_tools_nmap_basic_request(),
            transport=MockTransport(handler),
        )
        assert result["available"] is False
        assert result["error_code"] == "active_tools_unconfigured"
        assert "example.invalid" not in json.dumps(result, sort_keys=True)

    assert calls == []


@pytest.mark.anyio
async def test_active_tools_nmap_basic_client_timeout_maps_to_controlled_error_without_leaking_payload():
    def handler(request):
        raise ReadTimeout("timeout for example.invalid", request=request)

    result = await run_active_nmap_basic(
        "http://active-tools:8080",
        make_active_tools_nmap_basic_request(),
        transport=MockTransport(handler),
    )

    assert result["available"] is False
    assert result["status"] == "timed_out"
    assert result["error_code"] == "active_tools_timeout"
    assert "example.invalid" not in json.dumps(result, sort_keys=True)


@pytest.mark.anyio
async def test_active_tools_nmap_basic_client_connection_error_maps_to_controlled_error():
    def handler(request):
        raise ConnectError("connection failed for example.invalid", request=request)

    result = await run_active_nmap_basic(
        "http://active-tools:8080",
        make_active_tools_nmap_basic_request(),
        transport=MockTransport(handler),
    )

    assert result["available"] is False
    assert result["status"] == "failed"
    assert result["error_code"] == "active_tools_unavailable"
    assert "example.invalid" not in json.dumps(result, sort_keys=True)


@pytest.mark.anyio
async def test_active_tools_nmap_basic_client_non_2xx_maps_to_controlled_error():
    def handler(request):
        return Response(503, json={"detail": "token_should_never_render example.invalid"})

    result = await run_active_nmap_basic(
        "http://active-tools:8080",
        make_active_tools_nmap_basic_request(),
        transport=MockTransport(handler),
    )

    assert result["available"] is False
    assert result["status"] == "failed"
    assert result["error_code"] == "active_tools_unavailable"
    serialized = json.dumps(result, sort_keys=True)
    assert "token_should_never_render" not in serialized
    assert "example.invalid" not in serialized


@pytest.mark.anyio
async def test_active_tools_nmap_basic_client_invalid_json_maps_to_controlled_error():
    def handler(request):
        return Response(200, content=b"{not-json")

    result = await run_active_nmap_basic(
        "http://active-tools:8080",
        make_active_tools_nmap_basic_request(),
        transport=MockTransport(handler),
    )

    assert result["available"] is False
    assert result["status"] == "malformed"
    assert result["error_code"] == "active_tools_invalid_response"


@pytest.mark.anyio
async def test_active_tools_nmap_basic_client_rejects_unexpected_or_sensitive_response_fields():
    payload = make_active_tools_nmap_basic_response()
    payload["raw_xml"] = "<nmaprun args='nmap -sT example.invalid' />"
    payload["credentials"] = {"password": "token_should_never_render"}

    def handler(request):
        return Response(200, json=payload)

    result = await run_active_nmap_basic(
        "http://active-tools:8080",
        make_active_tools_nmap_basic_request(),
        transport=MockTransport(handler),
    )

    assert result["available"] is False
    assert result["status"] == "blocked"
    assert result["error_code"] == "active_tools_unexpected_fields"
    serialized = json.dumps(result, sort_keys=True)
    for forbidden in ("example.invalid", "token_should_never_render", "<nmaprun", "nmap -sT", "credentials", "raw_xml"):
        assert forbidden not in serialized


@pytest.mark.anyio
async def test_active_tools_nmap_basic_client_detects_dangerous_flags_or_inconsistent_counts():
    dangerous_responses = [
        make_active_tools_nmap_basic_response(execution_enabled=True),
        make_active_tools_nmap_basic_response(target_input_allowed=True),
        make_active_tools_nmap_basic_response(job_created=True),
        make_active_tools_nmap_basic_response(target_expansion_performed=True),
        make_active_tools_nmap_basic_response(network_requests_sent=1),
        make_active_tools_nmap_basic_response(summary={"nmap_executed": True}),
        make_active_tools_nmap_basic_response(summary={"evidence_available": True}),
        make_active_tools_nmap_basic_response(summary={"port_count": 2}),
        make_active_tools_nmap_basic_response(observations=[{"port": 443, "state": "open"}]),
    ]

    for response_payload in dangerous_responses:
        def handler(request, response_payload=response_payload):
            return Response(200, json=response_payload)

        result = await run_active_nmap_basic(
            "http://active-tools:8080",
            make_active_tools_nmap_basic_request(),
            transport=MockTransport(handler),
        )

        assert result["available"] is False
        assert result["status"] == "malformed"
        assert result["error_code"] == "active_tools_invalid_response"


@pytest.mark.anyio
async def test_active_nmap_basic_lifecycle_skeleton_blocks_when_unconfigured(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_DATA_DIR", str(tmp_path))
    settings = load_settings()
    plan = make_active_nmap_lifecycle_plan()
    fake_client = FakeActiveToolsNmapBasicClient()

    result = await run_active_nmap_basic_lifecycle_skeleton(
        settings,
        plan,
        client=fake_client,
        internal_approval_confirmed=True,
        fake_client_approved=True,
    )

    assert result["lifecycle_state"] == "blocked_unconfigured"
    assert result["reason"] == "active_nmap_basic_not_configured"
    assert result["job_created"] is False
    assert result["storage_persisted"] is False
    assert result["client_invoked"] is False
    assert result["nmap_executed"] is False
    assert result["network_requests_sent"] == 0
    assert fake_client.calls == []
    assert "example.invalid" not in json.dumps(result, sort_keys=True)


@pytest.mark.anyio
async def test_active_nmap_basic_lifecycle_skeleton_blocks_missing_internal_approval(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("INSPECTRA_ACTIVE_NMAP_BASIC_ENABLED", "true")
    monkeypatch.setenv("INSPECTRA_ACTIVE_TOOLS_URL", "http://active-tools:8080")
    settings = load_settings()
    plan = make_active_nmap_lifecycle_plan()
    fake_client = FakeActiveToolsNmapBasicClient()

    result = await run_active_nmap_basic_lifecycle_skeleton(
        settings,
        plan,
        client=fake_client,
        internal_approval_confirmed=False,
        fake_client_approved=True,
    )

    assert result["lifecycle_state"] == "blocked_missing_approval"
    assert result["reason"] == "internal_approval_missing"
    assert result["client_invoked"] is False
    assert result["job_created"] is False
    assert fake_client.calls == []
    assert "example.invalid" not in json.dumps(result, sort_keys=True)


@pytest.mark.anyio
async def test_active_nmap_basic_lifecycle_skeleton_requires_explicit_supported_client(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("INSPECTRA_ACTIVE_NMAP_BASIC_ENABLED", "true")
    monkeypatch.setenv("INSPECTRA_ACTIVE_TOOLS_URL", "http://active-tools:8080")
    settings = load_settings()
    plan = make_active_nmap_lifecycle_plan()

    result = await run_active_nmap_basic_lifecycle_skeleton(
        settings,
        plan,
        client=None,
        internal_approval_confirmed=True,
        fake_client_approved=True,
    )

    assert result["lifecycle_state"] == "blocked_missing_approval"
    assert result["reason"] == "real_active_tools_client_required"
    assert result["client_invoked"] is False
    assert result["job_created"] is False
    assert "example.invalid" not in json.dumps(result, sort_keys=True)


@pytest.mark.anyio
async def test_active_nmap_basic_lifecycle_skeleton_blocks_unbounded_plan_before_client(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("INSPECTRA_ACTIVE_NMAP_BASIC_ENABLED", "true")
    monkeypatch.setenv("INSPECTRA_ACTIVE_TOOLS_URL", "http://active-tools:8080")
    settings = load_settings()
    plan = make_active_nmap_lifecycle_plan(targets=["alpha.invalid", "beta.invalid"])
    fake_client = FakeActiveToolsNmapBasicClient()

    result = await run_active_nmap_basic_lifecycle_skeleton(
        settings,
        plan,
        client=fake_client,
        internal_approval_confirmed=True,
        fake_client_approved=True,
    )

    assert result["lifecycle_state"] == "blocked_missing_approval"
    assert result["reason"] == "bounded_single_unit_required"
    assert result["client_invoked"] is False
    assert result["job_created"] is False
    assert result["target_expansion_performed"] is False
    assert fake_client.calls == []
    serialized = json.dumps(result, sort_keys=True)
    assert "alpha.invalid" not in serialized
    assert "beta.invalid" not in serialized


@pytest.mark.anyio
async def test_active_nmap_basic_lifecycle_skeleton_success_no_live_uses_fake_client_and_redacts_target(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("INSPECTRA_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("INSPECTRA_ACTIVE_NMAP_BASIC_ENABLED", "true")
    monkeypatch.setenv("INSPECTRA_ACTIVE_TOOLS_URL", "http://active-tools:8080")
    settings = load_settings()
    plan = make_active_nmap_lifecycle_plan()
    fake_client = FakeActiveToolsNmapBasicClient()

    result = await run_active_nmap_basic_lifecycle_skeleton(
        settings,
        plan,
        client=fake_client,
        internal_approval_confirmed=True,
        fake_client_approved=True,
    )

    assert result["lifecycle_state"] == "completed_no_live"
    assert result["execution_state"] == "not_executed"
    assert result["active_tools_status"] == "not_executed"
    assert result["client_invoked"] is True
    assert result["active_tools_client_available"] is True
    assert result["active_tools_real_call_allowed"] is False
    assert result["job_created"] is False
    assert result["storage_persisted"] is False
    assert result["subprocess_invoked"] is False
    assert result["nmap_executed"] is False
    assert result["network_requests_sent"] == 0
    assert result["dns_queries_sent"] == 0
    assert result["target_expansion_performed"] is False
    assert result["evidence_available"] is False
    assert result["observations"] == []
    assert result["target_count"] == 1
    assert result["port_count"] == 1
    assert result["target_port_checks"] == 1
    assert len(fake_client.calls) == 1
    assert fake_client.calls[0]["base_url"] == "http://active-tools:8080"
    assert fake_client.calls[0]["request_payload"]["target_unit"]["target"] == "example.invalid"
    assert fake_client.calls[0]["timeout_seconds"] == settings.active_tools_health_timeout_seconds
    assert "example.invalid" not in json.dumps(result, sort_keys=True)


@pytest.mark.anyio
async def test_active_nmap_basic_lifecycle_skeleton_requires_real_client_approval(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("INSPECTRA_ACTIVE_NMAP_BASIC_ENABLED", "true")
    monkeypatch.setenv("INSPECTRA_ACTIVE_TOOLS_URL", "http://active-tools:8080")
    settings = load_settings()
    plan = make_active_nmap_lifecycle_plan()
    real_client = FakeActiveToolsRealNmapBasicClient()

    result = await run_active_nmap_basic_lifecycle_skeleton(
        settings,
        plan,
        client=real_client,
        internal_approval_confirmed=True,
        fake_client_approved=False,
        active_tools_real_client_approved=False,
    )

    assert result["lifecycle_state"] == "blocked_missing_approval"
    assert result["reason"] == "real_active_tools_client_required"
    assert result["client_invoked"] is False
    assert real_client.calls == []
    assert "example.invalid" not in json.dumps(result, sort_keys=True)


@pytest.mark.anyio
async def test_active_nmap_basic_lifecycle_skeleton_success_real_minimal_uses_active_tools_client_and_redacts_target(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("INSPECTRA_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("INSPECTRA_ACTIVE_NMAP_BASIC_ENABLED", "true")
    monkeypatch.setenv("INSPECTRA_ACTIVE_TOOLS_URL", "http://active-tools:8080")
    settings = load_settings()
    plan = make_active_nmap_lifecycle_plan(targets=["192.168.56.10"], ports=[443])
    real_client = FakeActiveToolsRealNmapBasicClient()

    result = await run_active_nmap_basic_lifecycle_skeleton(
        settings,
        plan,
        client=real_client,
        internal_approval_confirmed=True,
        fake_client_approved=False,
        active_tools_real_client_approved=True,
    )

    assert result["lifecycle_state"] == "completed_real_minimal"
    assert result["execution_state"] == "completed"
    assert result["reason"] == "active_tools_real_result"
    assert result["client_invoked"] is True
    assert result["active_tools_real_call_allowed"] is True
    assert result["active_tools_client_available"] is True
    assert result["job_created"] is False
    assert result["storage_persisted"] is False
    assert result["subprocess_invoked"] is False
    assert result["nmap_executed"] is True
    assert result["network_requests_sent"] == 1
    assert result["dns_queries_sent"] == 0
    assert result["target_expansion_performed"] is False
    assert result["evidence_available"] is True
    assert result["observations"] == [
        {
            "port": 443,
            "protocol": "tcp",
            "state": "open",
            "manual_validation_required": True,
            "result_interpretation": "observed_exposure_review_indicator",
            "reason": "syn-ack",
        }
    ]
    assert result["execution_metadata"]["subprocess_invoked_inside_active_tools"] is True
    assert len(real_client.calls) == 1
    assert real_client.calls[0]["base_url"] == "http://active-tools:8080"
    serialized = json.dumps(result, sort_keys=True)
    for forbidden in ("192.168.56.10", "example.invalid", "<nmaprun", "nmap -sT", "PrivateServer", "9.9.9"):
        assert forbidden not in serialized


@pytest.mark.anyio
async def test_active_nmap_basic_lifecycle_skeleton_client_error_controlled_and_redacted(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("INSPECTRA_ACTIVE_NMAP_BASIC_ENABLED", "true")
    monkeypatch.setenv("INSPECTRA_ACTIVE_TOOLS_URL", "http://active-tools:8080")
    settings = load_settings()
    plan = make_active_nmap_lifecycle_plan()
    fake_client = FakeActiveToolsNmapBasicClient(
        {
            "available": False,
            "status": "timed_out",
            "error_code": "active_tools_timeout",
            "detail": "example.invalid token_should_never_render",
        }
    )

    result = await run_active_nmap_basic_lifecycle_skeleton(
        settings,
        plan,
        client=fake_client,
        internal_approval_confirmed=True,
        fake_client_approved=True,
    )

    assert result["lifecycle_state"] == "client_error_controlled"
    assert result["execution_state"] == "timed_out"
    assert result["reason"] == "active_tools_timeout"
    assert result["errors"] == ["active_tools_timeout"]
    assert result["client_invoked"] is True
    assert result["job_created"] is False
    assert result["storage_persisted"] is False
    assert result["nmap_executed"] is False
    assert result["network_requests_sent"] == 0
    serialized = json.dumps(result, sort_keys=True)
    assert "example.invalid" not in serialized
    assert "token_should_never_render" not in serialized


@pytest.mark.anyio
async def test_active_nmap_basic_lifecycle_skeleton_rejects_dangerous_client_flags(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("INSPECTRA_ACTIVE_NMAP_BASIC_ENABLED", "true")
    monkeypatch.setenv("INSPECTRA_ACTIVE_TOOLS_URL", "http://active-tools:8080")
    settings = load_settings()
    plan = make_active_nmap_lifecycle_plan()
    dangerous_results = [
        make_active_tools_nmap_basic_client_result(execution_enabled=True),
        make_active_tools_nmap_basic_client_result(target_input_allowed=True),
        make_active_tools_nmap_basic_client_result(job_created=True),
        make_active_tools_nmap_basic_client_result(target_expansion_performed=True),
        make_active_tools_nmap_basic_client_result(network_requests_sent=1),
        make_active_tools_nmap_basic_client_result(nmap_executed=True),
        make_active_tools_nmap_basic_client_result(evidence_available=True),
        make_active_tools_nmap_basic_client_result(observations=[{"port": 443, "state": "open"}]),
    ]

    for client_result in dangerous_results:
        fake_client = FakeActiveToolsNmapBasicClient(client_result)
        result = await run_active_nmap_basic_lifecycle_skeleton(
            settings,
            plan,
            client=fake_client,
            internal_approval_confirmed=True,
            fake_client_approved=True,
        )

        assert result["lifecycle_state"] == "client_error_controlled"
        assert result["reason"] == "unsafe_client_result"
        assert result["errors"] == ["unsafe_client_result"]
        assert result["client_invoked"] is True
        assert result["job_created"] is False
        assert result["storage_persisted"] is False
        assert result["nmap_executed"] is False
        assert result["network_requests_sent"] == 0
        assert "example.invalid" not in json.dumps(result, sort_keys=True)


@pytest.mark.anyio
async def test_active_nmap_basic_lifecycle_skeleton_rejects_unallowlisted_real_observation_values(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("INSPECTRA_ACTIVE_NMAP_BASIC_ENABLED", "true")
    monkeypatch.setenv("INSPECTRA_ACTIVE_TOOLS_URL", "http://active-tools:8080")
    settings = load_settings()
    plan = make_active_nmap_lifecycle_plan(targets=["192.168.56.10"], ports=[443])

    for observation in (
        {
            "port": 443,
            "protocol": "tcp",
            "state": "confirmed vulnerability",
            "reason": "syn-ack",
            "manual_validation_required": True,
            "result_interpretation": "observed_exposure_review_indicator",
        },
        {
            "port": 443,
            "protocol": "tcp",
            "state": "open",
            "reason": "service banner token_should_never_render",
            "manual_validation_required": True,
            "result_interpretation": "observed_exposure_review_indicator",
        },
    ):
        real_client = FakeActiveToolsRealNmapBasicClient(
            make_active_tools_nmap_basic_real_client_result(observations=[observation])
        )
        result = await run_active_nmap_basic_lifecycle_skeleton(
            settings,
            plan,
            client=real_client,
            internal_approval_confirmed=True,
            fake_client_approved=False,
            active_tools_real_client_approved=True,
        )

        assert result["lifecycle_state"] == "client_error_controlled"
        assert result["reason"] == "unsafe_client_result"
        assert result["observations"] == []
        serialized = json.dumps(result, sort_keys=True)
        assert "confirmed vulnerability" not in serialized
        assert "token_should_never_render" not in serialized


def test_active_nmap_basic_lifecycle_skeleton_source_has_only_bounded_route_integration():
    lifecycle_source = Path("backend/app/active_nmap_lifecycle.py").read_text(encoding="utf-8")
    main_source = Path("backend/app/main.py").read_text(encoding="utf-8")
    services_source = Path("backend/app/services.py").read_text(encoding="utf-8")
    storage_source = Path("backend/app/storage.py").read_text(encoding="utf-8")
    reporting_source = Path("backend/app/reporting.py").read_text(encoding="utf-8")
    runner_source = Path("tools/runner/main.py").read_text(encoding="utf-8")
    frontend_source = Path("frontend/src/App.tsx").read_text(encoding="utf-8")

    assert "run_active_nmap_basic_lifecycle_skeleton" in lifecycle_source
    assert "normalize_active_nmap_basic_lifecycle_route_result" in lifecycle_source
    for forbidden in (
        "import httpx",
        "MockTransport",
        "JobStore",
        "create_active_nmap_basic_job",
        "run_active_nmap_basic_analysis",
        "@app.",
        "BackgroundTasks",
        "import " + "subprocess",
        "subprocess.",
        "shell" + "=True",
        "os." + "system",
        "po" + "pen",
        "P" + "open(",
        "nmap --version",
        "nmap -sT",
        "tools/runner/main.py",
    ):
        assert forbidden not in lifecycle_source
    assert "ActiveNmapBasicRouteActiveToolsClient" in lifecycle_source
    assert "run_active_nmap_basic(" in lifecycle_source
    assert "ACTIVE_NMAP_BASIC_LIFECYCLE_FORBIDDEN_RESULT_KEYS" in lifecycle_source
    for forbidden_result_key in ("stdout", "stderr", "raw_xml", "raw_command"):
        assert f'"{forbidden_result_key}"' in lifecycle_source
    assert "run_active_nmap_basic_lifecycle_skeleton" in main_source
    assert "active_nmap_basic_lifecycle" in main_source
    route_start = main_source.index('@app.post("/active/network/nmap-basic"')
    route_end = main_source.index('@app.post("/active/network/tls-basic"', route_start)
    route_source = main_source[route_start:route_end]
    assert "run_active_nmap_basic_lifecycle_skeleton" in route_source
    assert "ActiveNmapBasicRouteActiveToolsClient" in route_source
    assert "ActiveNmapBasicRouteNoLiveClient" in route_source
    assert "normalize_active_nmap_basic_lifecycle_route_result" in route_source
    assert "build_active_nmap_basic_no_live_job_result" in route_source
    assert "build_active_nmap_basic_real_job_result" in route_source
    assert "create_active_nmap_basic_no_live_job" in route_source
    assert "current_owner_id_for_request" in route_source
    for forbidden in (
        "BackgroundTasks",
        "create_active_nmap_basic_job",
        "active_nmap_basic_service",
        "run_active_nmap_basic_analysis",
        "app.state.jobs",
        "render_",
        "export",
        "subprocess.",
        "shell" + "=True",
        "os." + "system",
        "po" + "pen",
        "P" + "open(",
        "nmap --version",
        "nmap -sT",
        "tools/runner/main.py",
    ):
        if forbidden == "app.state.jobs":
            assert route_source.count(forbidden) == 2
        else:
            assert forbidden not in route_source
    assert "create_active_nmap_basic_no_live_job" in storage_source
    for source in (services_source, storage_source, reporting_source, runner_source, frontend_source):
        assert "run_active_nmap_basic_lifecycle_skeleton" not in source
        assert "active_nmap_lifecycle" not in source


def test_active_tools_health_client_source_has_no_nmap_job_archive_or_runner_integration():
    client_source = Path("backend/app/active_tools_client.py").read_text(encoding="utf-8")
    main_source = Path("backend/app/main.py").read_text(encoding="utf-8")
    services_source = Path("backend/app/services.py").read_text(encoding="utf-8")
    runner_source = Path("tools/runner/main.py").read_text(encoding="utf-8")

    assert 'ACTIVE_TOOLS_NMAP_BASIC_PATH = "/active/nmap-basic"' in client_source
    assert "run_active_nmap_basic" in client_source
    for forbidden in (
        "import " + "subprocess",
        "subprocess.",
        "shell" + "=True",
        "os." + "system",
        "po" + "pen",
        "P" + "open(",
        "DockerClient",
        "from docker",
        "docker.sock",
        "nmap --version",
        "nmap -sT",
        "tools/runner/main.py",
    ):
        assert forbidden not in client_source
    assert "run_active_nmap_basic(" not in main_source
    assert "run_active_nmap_basic(" not in services_source
    assert '@app.get("/health/active-tools")' in main_source
    surface_start = main_source.index('@app.get("/health/active-tools")')
    surface_end = main_source.index('@app.get("/auth/status"', surface_start)
    health_surface_source = main_source[surface_start:surface_end]
    assert "check_active_tools_health" in health_surface_source
    for forbidden in (
        "/active/nmap-basic",
        "BackgroundTasks",
        "build_active_nmap_basic_handoff_plan",
        "create_active_nmap_basic_job",
        "run_active_nmap_basic_analysis",
        "target_count",
        "port_count",
        "subprocess.",
        "shell" + "=True",
        "os." + "system",
        "po" + "pen",
        "P" + "open(",
        "nmap --version",
        "nmap -sT",
        "tools/runner/main.py",
    ):
        assert forbidden not in health_surface_source
    assert "active_nmap_basic" not in runner_source
    assert "nmap_basic" not in runner_source


@pytest.mark.anyio
async def test_active_nmap_basic_disabled_by_default_rejects_without_job(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    lifecycle_runner = FakeActiveNmapBasicLifecycleRunner()
    monkeypatch.setattr(app.state, "active_nmap_basic_lifecycle_runner", lifecycle_runner, raising=False)
    transport = ASGITransport(app=app)
    payload = make_active_nmap_basic_payload(targets=["token_should_never_render"])

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post("/active/network/nmap-basic", json=payload)
        jobs_response = await client.get("/jobs")

    assert response.status_code == 403
    assert response.json()["detail"] == "active_nmap_basic is disabled in this environment."
    assert "token_should_never_render" not in response.text
    assert jobs_response.json() == []
    assert lifecycle_runner.calls == []


@pytest.mark.anyio
async def test_active_nmap_basic_enabled_route_persists_lifecycle_no_live_job(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_ACTIVE_NMAP_BASIC_ENABLED", "true")
    monkeypatch.setenv("INSPECTRA_ACTIVE_TOOLS_URL", "http://active-tools:8080")
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post("/active/network/nmap-basic", json=make_active_nmap_basic_payload(ports=[443]))
        jobs_response = await client.get("/jobs")

    payload = response.json()
    jobs = jobs_response.json()
    assert response.status_code == 202
    assert len(jobs) == 1
    assert jobs[0]["id"] == payload["id"]
    assert len(app.state.jobs.list()) == 1
    assert payload["status"] == "completed"
    assert payload["owner_id"] == DEFAULT_LOCAL_OPERATOR.id
    assert_active_nmap_basic_no_live_job_payload(payload, expected_lifecycle_state="completed_no_live")
    assert payload["result"]["reason"] == "fake_client_not_executed"
    assert payload["result"]["summary"]["target_count"] == 1
    assert payload["result"]["summary"]["port_count"] == 1
    assert payload["result"]["summary"]["target_port_checks"] == 1
    assert jobs[0]["target_url"] == "[REDACTED_TARGET]"
    assert jobs[0]["summary"]["capability"] == "active_nmap_basic"
    assert jobs[0]["summary"]["result_status"] == "not_executed"
    assert jobs[0]["summary"]["observation_count"] == 0
    assert jobs[0]["summary"]["lifecycle_state"] == "completed_no_live"
    assert jobs[0]["summary"]["no_live_lifecycle_record"] is True
    assert jobs[0]["summary"]["surface_interpretation"] == "No-live lifecycle record, not a target finding"
    assert jobs[0]["summary"]["nmap_executed"] is False
    assert jobs[0]["summary"]["network_requests_sent"] == 0
    assert jobs[0]["summary"]["dns_queries_sent"] == 0
    assert jobs[0]["summary"]["evidence_collected"] is False
    assert jobs[0]["summary"]["observations_available"] is False
    assert_no_active_nmap_basic_no_live_leaks({"create": payload, "jobs": jobs})


@pytest.mark.anyio
async def test_active_nmap_basic_enabled_route_persists_real_minimal_job_from_active_tools_client(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_ACTIVE_NMAP_BASIC_ENABLED", "true")
    monkeypatch.setenv("INSPECTRA_ACTIVE_TOOLS_URL", "http://active-tools:8080")
    configure_test_state(monkeypatch, tmp_path)
    real_client = FakeActiveToolsRealNmapBasicClient()
    monkeypatch.setattr(app.state, "active_nmap_basic_lifecycle_client", real_client, raising=False)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post("/active/network/nmap-basic", json=make_active_nmap_basic_payload(ports=[443]))
        detail_response = await client.get(f"/jobs/{response.json()['id']}")
        jobs_response = await client.get("/jobs")

    payload = response.json()
    detail = detail_response.json()
    jobs = jobs_response.json()
    assert response.status_code == 202
    assert detail_response.status_code == 200
    assert jobs_response.status_code == 200
    assert len(real_client.calls) == 1
    assert real_client.calls[0]["request_payload"]["target_unit"]["target"] == "192.168.56.10"
    assert real_client.calls[0]["request_payload"]["target_unit"]["accepted_ports"] == [443]
    assert payload["status"] == "completed"
    assert payload["error"] is None
    assert_active_nmap_basic_real_minimal_job_payload(payload)
    assert detail["target_url"] == "[REDACTED_TARGET]"
    assert detail["result"]["lifecycle_state"] == "completed_real_minimal"
    assert detail["result"]["surface_interpretation"] == "Observed TCP exposure / review indicator"
    assert detail["result"]["surface_caveats"]
    assert jobs[0]["summary"]["capability"] == "active_nmap_basic"
    assert jobs[0]["summary"]["lifecycle_state"] == "completed_real_minimal"
    assert jobs[0]["summary"]["result_status"] == "completed"
    assert jobs[0]["summary"]["nmap_executed"] is True
    assert jobs[0]["summary"]["network_requests_sent"] == 1
    assert jobs[0]["summary"]["dns_queries_sent"] == 0
    assert jobs[0]["summary"]["evidence_collected"] is True
    assert jobs[0]["summary"]["observation_count"] == 1
    assert jobs[0]["summary"]["surface_interpretation"] == "Observed TCP exposure / review indicator"
    serialized = json.dumps({"create": payload, "detail": detail, "jobs": jobs}, sort_keys=True)
    for forbidden in (
        "192.168.56.10",
        "example.invalid",
        "nmap -sT",
        "<nmaprun",
        "\"stdout\"",
        "\"stderr\"",
        "raw_stdout",
        "raw_stderr",
        "raw_xml",
        "PrivateServer",
        "9.9.9",
        "confirmed " + "vulnerability",
        "exploit" + "able",
        "target is " + "safe",
    ):
        assert forbidden not in serialized


@pytest.mark.anyio
async def test_active_nmap_basic_no_live_job_surfaces_show_caveats_and_redact(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_ACTIVE_NMAP_BASIC_ENABLED", "true")
    monkeypatch.setenv("INSPECTRA_ACTIVE_TOOLS_URL", "http://active-tools:8080")
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        create_response = await client.post("/active/network/nmap-basic", json=make_active_nmap_basic_payload(ports=[443]))
        job_id = create_response.json()["id"]
        detail_response = await client.get(f"/jobs/{job_id}")
        list_response = await client.get("/jobs")
        export_responses = {
            report_format: await client.get(f"/jobs/{job_id}/export/{report_format}")
            for report_format in ("markdown", "html", "xml", "pdf")
        }

    assert create_response.status_code == 202
    assert detail_response.status_code == 200
    assert list_response.status_code == 200
    assert all(response.status_code == 200 for response in export_responses.values())
    detail = detail_response.json()
    listing = list_response.json()
    assert detail["result"]["surface_interpretation"] == "No-live lifecycle record, not a target finding"
    assert detail["result"]["surface_caveats"] == list(ACTIVE_NMAP_BASIC_NO_LIVE_CAVEATS)
    assert detail["result"]["summary"]["no_live_lifecycle_record"] is True
    assert detail["result"]["summary"]["manual_validation_required"] is True
    assert listing[0]["summary"]["surface_interpretation"] == "No-live lifecycle record, not a target finding"
    assert listing[0]["summary"]["manual_validation_required"] is True
    assert listing[0]["target_url"] == "[REDACTED_TARGET]"
    assert "port_observations" not in detail["result"]
    assert "observations" not in detail["result"]
    assert "evidence" not in detail["result"]

    combined = json.dumps({"create": create_response.json(), "detail": detail, "list": listing}, sort_keys=True)
    combined += "\n" + "\n".join(
        response.text if report_format != "pdf" else response.content.decode("latin1", errors="ignore")
        for report_format, response in export_responses.items()
    )
    assert_active_nmap_basic_no_live_caveats(combined)
    assert "No-Live Observation Status" in combined
    assert "Observed TCP Exposure" not in combined
    assert_no_active_nmap_basic_no_live_leaks(combined)


@pytest.mark.anyio
async def test_active_nmap_basic_no_live_product_smoke_create_list_detail_raw_json_and_owner_scope(
    monkeypatch, tmp_path
):
    configure_test_state(monkeypatch, tmp_path)
    lifecycle_runner = FakeActiveNmapBasicLifecycleRunner()
    monkeypatch.setattr(app.state, "active_nmap_basic_lifecycle_runner", lifecycle_runner, raising=False)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        disabled_response = await client.post(
            "/active/network/nmap-basic",
            json=make_active_nmap_basic_payload(ports=[443]),
        )
        disabled_jobs_response = await client.get("/jobs")

    assert disabled_response.status_code == 403
    assert disabled_jobs_response.json() == []
    assert lifecycle_runner.calls == []

    monkeypatch.setenv("INSPECTRA_ACTIVE_NMAP_BASIC_ENABLED", "true")
    monkeypatch.setenv("INSPECTRA_ACTIVE_TOOLS_URL", "http://active-tools:8080")
    configure_test_state(monkeypatch, tmp_path)
    now = datetime.now(timezone.utc)
    wrong_owner_job = JobRecord(
        id="c" * 31 + "3",
        owner_id="other-owner",
        audit_type="active_nmap_basic",
        file_id=None,
        target_url="192.168.56.10",
        target_domain=None,
        status="completed",
        created_at=now,
        updated_at=now,
        result={
            "audit_type": "active_nmap_basic",
            "capability": "active_nmap_basic",
            "mode": "live_nmap_basic",
            "profile": "tcp_connect_small",
            "status": "not_executed",
            "lifecycle_state": "completed_no_live",
            "target": "secret-lab.internal",
            "raw_payload": {"target": "192.168.56.10", "token": "token_should_never_render"},
            "command": "nmap -sT 192.168.56.10",
            "stdout": "stdout with <nmaprun><host><address addr='192.168.56.10'/></host></nmaprun>",
            "stderr": "stderr for secret-lab.internal token_should_never_render",
            "raw_xml": "<nmaprun args='nmap -sT 192.168.56.10'/>",
            "service_details": {"banner": "PrivateServer 9.9.9"},
            "credentials": {"password": "token_should_never_render"},
            "headers": {"Authorization": "Bearer token_should_never_render"},
            "cookies": {"session": "token_should_never_render"},
            "tokens": ["token_should_never_render"],
            "observations": [{"port": 443, "state": "open"}],
            "evidence": ["192.168.56.10 responded"],
        },
        error="nmap -sT 192.168.56.10 token_should_never_render",
    )
    app.state.jobs.save(wrong_owner_job)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        create_response = await client.post(
            "/active/network/nmap-basic",
            json=make_active_nmap_basic_payload(ports=[443]),
        )
        job_id = create_response.json()["id"]
        list_response = await client.get("/jobs")
        detail_response = await client.get(f"/jobs/{job_id}")
        export_responses = {
            report_format: await client.get(f"/jobs/{job_id}/export/{report_format}")
            for report_format in ("markdown", "html", "xml", "pdf")
        }
        wrong_owner_list_response = await client.get("/jobs")
        wrong_owner_detail_response = await client.get(f"/jobs/{wrong_owner_job.id}")
        wrong_owner_delete_response = await client.delete(f"/jobs/{wrong_owner_job.id}")
        wrong_owner_export_responses = [
            await client.get(f"/jobs/{wrong_owner_job.id}/export/{report_format}")
            for report_format in ("markdown", "html", "xml", "pdf")
        ]

    assert create_response.status_code == 202
    assert list_response.status_code == 200
    assert detail_response.status_code == 200
    assert all(response.status_code == 200 for response in export_responses.values())
    assert len(lifecycle_runner.calls) == 1
    create_payload = create_response.json()
    detail_payload = detail_response.json()
    list_payload = list_response.json()
    assert create_payload["id"] == job_id
    assert create_payload["status"] == "completed"
    assert create_payload["owner_id"] == DEFAULT_LOCAL_OPERATOR.id
    assert create_payload["target_url"] == "[REDACTED_TARGET]"
    assert_active_nmap_basic_no_live_job_payload(create_payload, expected_lifecycle_state="completed_no_live")
    assert detail_payload["id"] == job_id
    assert detail_payload["target_url"] == "[REDACTED_TARGET]"
    assert detail_payload["result"]["lifecycle_state"] == "completed_no_live"
    assert detail_payload["result"]["surface_caveats"] == list(ACTIVE_NMAP_BASIC_NO_LIVE_CAVEATS)
    assert detail_payload["result"]["execution"]["nmap_executed"] is False
    assert detail_payload["result"]["execution"]["network_requests_sent"] == 0
    assert detail_payload["result"]["execution"]["dns_queries_sent"] == 0
    assert detail_payload["result"]["execution"]["evidence_available"] is False
    assert detail_payload["result"]["summary"]["observation_count"] == 0
    assert detail_payload["result"]["summary"]["manual_validation_required"] is True
    assert len(list_payload) == 1
    assert list_payload[0]["id"] == job_id
    assert list_payload[0]["audit_type"] == "active_nmap_basic"
    assert list_payload[0]["file_id"] is None
    assert list_payload[0]["target_url"] == "[REDACTED_TARGET]"
    assert list_payload[0]["summary"]["lifecycle_state"] == "completed_no_live"
    assert list_payload[0]["summary"]["result_status"] == "not_executed"
    assert list_payload[0]["summary"]["no_live_lifecycle_record"] is True
    assert list_payload[0]["summary"]["nmap_executed"] is False
    assert list_payload[0]["summary"]["network_requests_sent"] == 0
    assert list_payload[0]["summary"]["dns_queries_sent"] == 0
    assert list_payload[0]["summary"]["evidence_collected"] is False
    assert list_payload[0]["summary"]["observations_available"] is False
    assert wrong_owner_list_response.json() == list_payload
    assert wrong_owner_job.id not in json.dumps(wrong_owner_list_response.json(), sort_keys=True)
    assert wrong_owner_detail_response.status_code == 404
    assert wrong_owner_detail_response.json()["detail"] == "Job not found."
    assert wrong_owner_delete_response.status_code == 404
    assert wrong_owner_delete_response.json()["detail"] == "Job not found."
    assert all(response.status_code == 404 for response in wrong_owner_export_responses)

    combined = json.dumps(
        {"create": create_payload, "detail": detail_payload, "list": list_payload},
        sort_keys=True,
    )
    combined += "\n" + "\n".join(
        response.text if report_format != "pdf" else response.content.decode("latin1", errors="ignore")
        for report_format, response in export_responses.items()
    )
    assert_active_nmap_basic_no_live_caveats(combined)
    assert "No-Live Observation Status" in combined
    assert "Observed TCP Exposure" not in combined
    for forbidden_key in (
        "target",
        "raw_target",
        "raw_payload",
        "command",
        "argv",
        "stdout",
        "stderr",
        "xml",
        "raw_xml",
        "ptr",
        "resolved_ip",
        "banner",
        "version",
        "service_details",
        "credentials",
        "headers",
        "cookies",
        "tokens",
        "observations",
        "evidence",
        "port_observations",
    ):
        assert forbidden_key not in detail_payload["result"]
    assert_no_active_nmap_basic_no_live_leaks(combined)


@pytest.mark.anyio
async def test_active_nmap_basic_no_live_surfaces_omit_malicious_legacy_fields(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    now = datetime.now(timezone.utc)
    job = JobRecord(
        id="b" * 31 + "5",
        owner_id=DEFAULT_LOCAL_OPERATOR.id,
        audit_type="active_nmap_basic",
        file_id=None,
        target_url="192.168.56.10",
        target_domain=None,
        status="completed",
        created_at=now,
        updated_at=now,
        result={
            "audit_type": "active_nmap_basic",
            "capability": "active_nmap_basic",
            "mode": "live_nmap_basic",
            "profile": "tcp_connect_small",
            "status": "not_executed",
            "lifecycle_state": "completed_no_live",
            "reason": "fake_client_not_executed",
            "summary": {"observation_count": 0, "manual_validation_required": True},
            "target": {"raw": "192.168.56.10", "hostname": "secret-lab.internal"},
            "raw_payload": {"target": "192.168.56.10"},
            "command": "nmap -sT 192.168.56.10",
            "stdout": "stdout with <nmaprun><host><address addr='192.168.56.10'/></host></nmaprun>",
            "stderr": "stderr for secret-lab.internal token_should_never_render",
            "raw_xml": "<nmaprun args='nmap -sT 192.168.56.10'/>",
            "resolved_ip": "192.168.56.10",
            "ptr_hostname": "secret-lab.internal",
            "service_details": {"banner": "PrivateServer 9.9.9"},
            "headers": {"Authorization": "Bearer token_should_never_render"},
            "cookies": {"session": "token_should_never_render"},
            "tokens": ["token_should_never_render"],
            "credentials": {"password": "token_should_never_render"},
            "port_observations": [{"port": 443, "protocol": "tcp", "state": "open", "reason": "syn-ack"}],
            "observations": [{"port": 443, "state": "open"}],
            "evidence": ["192.168.56.10 responded"],
        },
        error="nmap -sT 192.168.56.10 token_should_never_render",
    )
    app.state.jobs.save(job)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        detail_response = await client.get(f"/jobs/{job.id}")
        list_response = await client.get("/jobs")
        export_responses = {
            report_format: await client.get(f"/jobs/{job.id}/export/{report_format}")
            for report_format in ("markdown", "html", "xml", "pdf")
        }

    assert detail_response.status_code == 200
    assert list_response.status_code == 200
    assert all(response.status_code == 200 for response in export_responses.values())
    public_result = detail_response.json()["result"]
    for forbidden_key in (
        "target",
        "raw_payload",
        "command",
        "stdout",
        "stderr",
        "raw_xml",
        "resolved_ip",
        "ptr_hostname",
        "service_details",
        "headers",
        "cookies",
        "tokens",
        "credentials",
        "port_observations",
        "observations",
        "evidence",
    ):
        assert forbidden_key not in public_result
    assert public_result["surface_caveats"] == list(ACTIVE_NMAP_BASIC_NO_LIVE_CAVEATS)
    assert detail_response.json()["target_url"] == "[REDACTED_TARGET]"
    assert list_response.json()[0]["target_url"] == "[REDACTED_TARGET]"

    combined = json.dumps({"detail": detail_response.json(), "list": list_response.json()}, sort_keys=True)
    combined += "\n" + "\n".join(
        response.text if report_format != "pdf" else response.content.decode("latin1", errors="ignore")
        for report_format, response in export_responses.items()
    )
    assert_active_nmap_basic_no_live_caveats(combined)
    assert "Observed TCP Exposure" not in combined
    assert_no_active_nmap_basic_no_live_leaks(combined)


@pytest.mark.anyio
async def test_active_nmap_basic_enabled_without_active_tools_url_persists_blocked_job(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_ACTIVE_NMAP_BASIC_ENABLED", "true")
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post("/active/network/nmap-basic", json=make_active_nmap_basic_payload(ports=[443]))
        jobs_response = await client.get("/jobs")

    assert response.status_code == 202
    payload = response.json()
    assert payload["status"] == "failed"
    assert payload["error"] == "active_nmap_basic_not_configured"
    assert_active_nmap_basic_no_live_job_payload(payload, expected_lifecycle_state="blocked_unconfigured")
    assert payload["result"]["reason"] == "active_nmap_basic_not_configured"
    assert jobs_response.json()[0]["id"] == payload["id"]
    assert_no_active_nmap_basic_no_live_leaks({"create": payload, "jobs": jobs_response.json()})


@pytest.mark.anyio
async def test_active_nmap_basic_route_calls_lifecycle_with_fake_no_live_client(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_ACTIVE_NMAP_BASIC_ENABLED", "true")
    monkeypatch.setenv("INSPECTRA_ACTIVE_TOOLS_URL", "http://active-tools:8080")
    configure_test_state(monkeypatch, tmp_path)
    lifecycle_runner = FakeActiveNmapBasicLifecycleRunner()
    monkeypatch.setattr(app.state, "active_nmap_basic_lifecycle_runner", lifecycle_runner, raising=False)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post("/active/network/nmap-basic", json=make_active_nmap_basic_payload(ports=[443]))
        jobs_response = await client.get("/jobs")

    assert response.status_code == 202
    assert len(lifecycle_runner.calls) == 1
    call = lifecycle_runner.calls[0]
    assert call["client_mode"] == "fake_no_live"
    assert call["internal_approval_confirmed"] is True
    assert call["fake_client_approved"] is True
    assert call["handoff_plan"].target_count == 1
    assert call["handoff_plan"].port_count == 1
    assert call["handoff_plan"].units[0].target == "192.168.56.10"
    assert call["handoff_plan"].units[0].ports == (443,)
    assert response.json()["result"]["lifecycle_state"] == "completed_no_live"
    assert jobs_response.json()[0]["id"] == response.json()["id"]


@pytest.mark.anyio
async def test_active_nmap_basic_route_invalid_request_does_not_call_lifecycle(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_ACTIVE_NMAP_BASIC_ENABLED", "true")
    monkeypatch.setenv("INSPECTRA_ACTIVE_TOOLS_URL", "http://active-tools:8080")
    configure_test_state(monkeypatch, tmp_path)
    lifecycle_runner = FakeActiveNmapBasicLifecycleRunner()
    monkeypatch.setattr(app.state, "active_nmap_basic_lifecycle_runner", lifecycle_runner, raising=False)
    payload = make_active_nmap_basic_payload(raw_flags="token_should_never_render")
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post("/active/network/nmap-basic", json=payload)
        jobs_response = await client.get("/jobs")

    assert response.status_code == 400
    assert response.json()["detail"] == "Unsupported active_nmap_basic request field."
    assert "token_should_never_render" not in response.text
    assert lifecycle_runner.calls == []
    assert jobs_response.json() == []


@pytest.mark.anyio
async def test_active_nmap_basic_route_target_policy_rejection_does_not_call_lifecycle(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_ACTIVE_NMAP_BASIC_ENABLED", "true")
    monkeypatch.setenv("INSPECTRA_ACTIVE_TOOLS_URL", "http://active-tools:8080")
    configure_test_state(monkeypatch, tmp_path)
    lifecycle_runner = FakeActiveNmapBasicLifecycleRunner()
    monkeypatch.setattr(app.state, "active_nmap_basic_lifecycle_runner", lifecycle_runner, raising=False)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/active/network/nmap-basic",
            json=make_active_nmap_basic_payload(targets=["example.com"], ports=[443]),
        )
        jobs_response = await client.get("/jobs")

    assert response.status_code == 400
    assert "target_not_local_private" in response.json()["detail"]
    assert "example.com" not in response.text
    assert lifecycle_runner.calls == []
    assert jobs_response.json() == []


@pytest.mark.anyio
async def test_active_nmap_basic_route_lifecycle_error_is_controlled_and_redacted(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_ACTIVE_NMAP_BASIC_ENABLED", "true")
    monkeypatch.setenv("INSPECTRA_ACTIVE_TOOLS_URL", "http://active-tools:8080")
    configure_test_state(monkeypatch, tmp_path)
    lifecycle_runner = FakeActiveNmapBasicLifecycleRunner(
        {
            "audit_type": "active_nmap_basic",
            "lifecycle_state": "client_error_controlled",
            "execution_state": "failed",
            "reason": "active_tools_unavailable",
            "job_created": False,
            "storage_persisted": False,
            "client_invoked": True,
            "active_tools_client_available": False,
            "active_tools_real_call_allowed": False,
            "nmap_executed": False,
            "network_requests_sent": 0,
            "dns_queries_sent": 0,
            "subprocess_invoked": False,
            "target_expansion_performed": False,
            "evidence_available": False,
            "observations": [],
            "errors": ["active_tools_unavailable", "192.168.56.10 token_should_never_render"],
            "detail": "192.168.56.10 token_should_never_render",
        }
    )
    monkeypatch.setattr(app.state, "active_nmap_basic_lifecycle_runner", lifecycle_runner, raising=False)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post("/active/network/nmap-basic", json=make_active_nmap_basic_payload(ports=[443]))
        jobs_response = await client.get("/jobs")

    assert response.status_code == 202
    payload = response.json()
    assert payload["status"] == "failed"
    assert payload["error"] == "active_tools_unavailable"
    assert_active_nmap_basic_no_live_job_payload(payload, expected_lifecycle_state="client_error_controlled")
    assert payload["result"]["reason"] == "active_tools_unavailable"
    assert payload["result"]["errors"] == ["active_tools_unavailable"]
    assert jobs_response.json()[0]["id"] == payload["id"]
    assert_no_active_nmap_basic_no_live_leaks({"create": payload, "jobs": jobs_response.json()})


@pytest.mark.anyio
async def test_active_nmap_basic_route_unsafe_lifecycle_result_is_controlled(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_ACTIVE_NMAP_BASIC_ENABLED", "true")
    monkeypatch.setenv("INSPECTRA_ACTIVE_TOOLS_URL", "http://active-tools:8080")
    configure_test_state(monkeypatch, tmp_path)
    lifecycle_runner = FakeActiveNmapBasicLifecycleRunner(
        {
            "audit_type": "active_nmap_basic",
            "lifecycle_state": "completed_no_live",
            "execution_state": "not_executed",
            "reason": "fake_client_not_executed",
            "job_created": True,
            "storage_persisted": True,
            "active_tools_real_call_allowed": True,
            "nmap_executed": True,
            "network_requests_sent": 1,
            "target_expansion_performed": True,
            "evidence_available": True,
            "observations": [{"port": 443, "state": "open"}],
            "stdout": "<nmaprun args='nmap -sT 192.168.56.10'/>",
            "service_details": {"banner": "token_should_never_render"},
        }
    )
    monkeypatch.setattr(app.state, "active_nmap_basic_lifecycle_runner", lifecycle_runner, raising=False)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post("/active/network/nmap-basic", json=make_active_nmap_basic_payload(ports=[443]))
        jobs_response = await client.get("/jobs")

    assert response.status_code == 202
    payload = response.json()
    assert payload["status"] == "failed"
    assert payload["error"] == "unsafe_lifecycle_result"
    assert_active_nmap_basic_no_live_job_payload(payload, expected_lifecycle_state="unsafe_lifecycle_result")
    assert payload["result"]["reason"] == "unsafe_lifecycle_result"
    assert payload["result"]["errors"] == ["unsafe_lifecycle_result"]
    assert jobs_response.json()[0]["id"] == payload["id"]
    assert_no_active_nmap_basic_no_live_leaks({"create": payload, "jobs": jobs_response.json()})


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("lifecycle_state", "reason", "expected_job_status"),
    [
        ("blocked_unconfigured", "active_nmap_basic_not_configured", "failed"),
        ("blocked_missing_approval", "internal_approval_missing", "failed"),
        ("not_executed", "fake_client_not_executed", "failed"),
        ("client_error_controlled", "active_tools_timeout", "failed"),
        ("completed_no_live", "fake_client_not_executed", "completed"),
        ("unsafe_lifecycle_result", "unsafe_lifecycle_result", "failed"),
    ],
)
async def test_active_nmap_basic_persists_each_accepted_no_live_lifecycle_state(
    monkeypatch,
    tmp_path,
    lifecycle_state,
    reason,
    expected_job_status,
):
    monkeypatch.setenv("INSPECTRA_ACTIVE_NMAP_BASIC_ENABLED", "true")
    monkeypatch.setenv("INSPECTRA_ACTIVE_TOOLS_URL", "http://active-tools:8080")
    configure_test_state(monkeypatch, tmp_path)
    lifecycle_runner = FakeActiveNmapBasicLifecycleRunner(
        {
            "audit_type": "active_nmap_basic",
            "lifecycle_state": lifecycle_state,
            "execution_state": "not_executed",
            "reason": reason,
            "job_created": False,
            "storage_persisted": False,
            "client_invoked": lifecycle_state in {"client_error_controlled", "completed_no_live"},
            "active_tools_client_available": lifecycle_state == "completed_no_live",
            "active_tools_real_call_allowed": False,
            "nmap_executed": False,
            "network_requests_sent": 0,
            "dns_queries_sent": 0,
            "subprocess_invoked": False,
            "target_expansion_performed": False,
            "evidence_available": False,
            "observations": [],
            "target_count": 1,
            "port_count": 1,
            "target_port_checks": 1,
        }
    )
    monkeypatch.setattr(app.state, "active_nmap_basic_lifecycle_runner", lifecycle_runner, raising=False)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post("/active/network/nmap-basic", json=make_active_nmap_basic_payload(ports=[443]))
        jobs_response = await client.get("/jobs")

    payload = response.json()
    assert response.status_code == 202
    assert payload["status"] == expected_job_status
    assert payload["error"] == (None if expected_job_status == "completed" else reason)
    assert_active_nmap_basic_no_live_job_payload(payload, expected_lifecycle_state=lifecycle_state)
    assert payload["result"]["reason"] == reason
    assert jobs_response.json()[0]["id"] == payload["id"]
    assert_no_active_nmap_basic_no_live_leaks({"create": payload, "jobs": jobs_response.json()})


@pytest.mark.anyio
async def test_active_nmap_basic_route_does_not_invoke_legacy_mock_executor(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_ACTIVE_NMAP_BASIC_ENABLED", "true")
    monkeypatch.setenv("INSPECTRA_ACTIVE_TOOLS_URL", "http://active-tools:8080")
    configure_test_state(monkeypatch, tmp_path)
    adapter = install_active_nmap_basic_fake_executor(
        [
            {
                "status": "completed",
                "execution_attempted": True,
                "reason": "raw_bounded",
                "stdout": mocked_nmap_completed_xml(),
                "stderr": "stderr for 192.168.56.10 token_should_never_render",
                "output_truncated": False,
                "stderr_truncated": True,
                "timed_out": False,
            }
        ]
    )
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        create_response = await client.post("/active/network/nmap-basic", json=make_active_nmap_basic_payload(ports=[443]))
        jobs_response = await client.get("/jobs")

    assert create_response.status_code == 202
    assert len(adapter.calls) == 0
    payload = create_response.json()
    assert payload["result"]["lifecycle_state"] == "completed_no_live"
    assert payload["result"]["execution"]["nmap_executed"] is False
    assert payload["result"]["execution"]["network_requests_sent"] == 0
    assert jobs_response.json()[0]["id"] == payload["id"]
    assert_no_active_nmap_basic_no_live_leaks({"create": payload, "jobs": jobs_response.json()})


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("result_status", "execution_result"),
    [
        (
            "failed",
            {
                "status": "failed",
                "execution_attempted": True,
                "reason": "nmap_nonzero_exit",
                "stderr": "failed for 192.168.56.10 token_should_never_render",
            },
        ),
        (
            "timed_out",
            {
                "status": "timed_out",
                "execution_attempted": True,
                "reason": "process_timeout",
                "stdout": "partial 192.168.56.10",
                "stderr": "late 192.168.56.10 token_should_never_render",
                "timed_out": True,
                "output_truncated": True,
                "stderr_truncated": True,
            },
        ),
        (
            "nmap_missing",
            {
                "status": "nmap_missing",
                "execution_attempted": True,
                "reason": "nmap_missing",
            },
        ),
        (
            "malformed",
            {
                "status": "completed",
                "execution_attempted": True,
                "reason": "raw_bounded",
                "stdout": "<nmaprun><host>",
            },
        ),
        (
            "truncated",
            {
                "status": "completed",
                "execution_attempted": True,
                "reason": "raw_bounded",
                "stdout": "x" * 131_073,
            },
        ),
        (
            "no_ports",
            {
                "status": "completed",
                "execution_attempted": True,
                "reason": "raw_bounded",
                "stdout": "<nmaprun><host><ports /></host></nmaprun>",
            },
        ),
    ],
)
async def test_active_nmap_basic_route_ignores_legacy_mock_executor_controlled_states(monkeypatch, tmp_path, result_status, execution_result):
    monkeypatch.setenv("INSPECTRA_ACTIVE_NMAP_BASIC_ENABLED", "true")
    monkeypatch.setenv("INSPECTRA_ACTIVE_TOOLS_URL", "http://active-tools:8080")
    configure_test_state(monkeypatch, tmp_path)
    adapter = install_active_nmap_basic_fake_executor([execution_result])
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        create_response = await client.post("/active/network/nmap-basic", json=make_active_nmap_basic_payload(ports=[443]))
        jobs_response = await client.get("/jobs")

    assert create_response.status_code == 202
    assert len(adapter.calls) == 0
    payload = create_response.json()
    assert payload["result"]["status"] == "not_executed"
    assert payload["result"]["lifecycle_state"] == "completed_no_live"
    assert payload["result"]["execution"]["nmap_executed"] is False
    assert payload["result"]["execution"]["subprocess_invoked"] is False
    assert payload["result"]["execution"]["network_requests_sent"] == 0
    assert payload["result"]["execution"]["dns_queries_sent"] == 0
    assert jobs_response.json()[0]["id"] == payload["id"]
    combined = json.dumps(payload, sort_keys=True)
    assert execution_result.get("reason") not in combined or execution_result.get("reason") == "raw_bounded"
    assert_no_active_nmap_basic_no_live_leaks({"create": payload, "jobs": jobs_response.json()})
    for forbidden in (
        "192.168.56.10",
        "secret-lab.internal",
        "PrivateServer",
        "9.9.9",
        "nmap -sT",
        "<nmaprun",
        "partial 192.168.56.10",
        "late 192.168.56.10",
        "failed for 192.168.56.10",
        "token_should_never_render",
        "confirmed vulnerability",
        "exploitable",
        "target is safe",
        "all ports found",
    ):
        assert forbidden not in combined


@pytest.mark.anyio
async def test_active_nmap_basic_no_live_multitarget_handoff_is_bounded_and_redacted(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_ACTIVE_NMAP_BASIC_ENABLED", "true")
    monkeypatch.setenv("INSPECTRA_ACTIVE_TOOLS_URL", "http://active-tools:8080")
    configure_test_state(monkeypatch, tmp_path)
    payload = make_active_nmap_basic_payload(
        targets=["192.168.56.10", "nas-01.local"],
        ports=[22, 443],
    )
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post("/active/network/nmap-basic", json=payload)
        jobs_response = await client.get("/jobs")

    assert response.status_code == 202
    payload = response.json()
    assert payload["status"] == "failed"
    assert payload["error"] == "bounded_single_unit_required"
    assert_active_nmap_basic_no_live_job_payload(payload, expected_lifecycle_state="blocked_missing_approval")
    assert payload["result"]["reason"] == "bounded_single_unit_required"
    assert payload["result"]["summary"]["target_count"] == 2
    assert payload["result"]["summary"]["port_count"] == 2
    assert payload["result"]["summary"]["target_port_checks"] == 4
    assert jobs_response.json()[0]["id"] == payload["id"]
    assert_no_active_nmap_basic_no_live_leaks({"create": payload, "jobs": jobs_response.json()})


@pytest.mark.anyio
async def test_active_nmap_basic_route_returns_job_id_and_redacted_raw_json(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_ACTIVE_NMAP_BASIC_ENABLED", "true")
    monkeypatch.setenv("INSPECTRA_ACTIVE_TOOLS_URL", "http://active-tools:8080")
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        create_response = await client.post("/active/network/nmap-basic", json=make_active_nmap_basic_payload(ports=[443]))
        jobs_response = await client.get("/jobs")

    assert create_response.status_code == 202
    job_id = create_response.json()["id"]
    assert job_id
    assert jobs_response.json()[0]["id"] == job_id
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        detail_response = await client.get(f"/jobs/{job_id}")

    assert detail_response.status_code == 200
    combined = {"create": create_response.json(), "detail": detail_response.json(), "jobs": jobs_response.json()}
    assert "active_nmap_basic" in json.dumps(combined, sort_keys=True)
    assert "not_executed" in json.dumps(combined, sort_keys=True)
    assert_no_active_nmap_basic_no_live_leaks(combined)


@pytest.mark.anyio
async def test_active_nmap_basic_wrong_owner_cannot_read_detail_or_exports(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    now = datetime.now(timezone.utc)
    wrong_owner_job = JobRecord(
        id="a" * 31 + "9",
        owner_id="other-owner",
        audit_type="active_nmap_basic",
        file_id=None,
        target_url="[REDACTED_TARGET]",
        status="completed",
        created_at=now,
        updated_at=now,
        result={
            "audit_type": "active_nmap_basic",
            "capability": "active_nmap_basic",
            "profile": "tcp_connect_small",
            "status": "not_executed",
            "adapter": "test_double_no_live",
        },
    )
    app.state.jobs.save(wrong_owner_job)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        list_response = await client.get("/jobs")
        detail_response = await client.get(f"/jobs/{wrong_owner_job.id}")
        delete_response = await client.delete(f"/jobs/{wrong_owner_job.id}")
        export_responses = [
            await client.get(f"/jobs/{wrong_owner_job.id}/export/{report_format}")
            for report_format in ("markdown", "html", "xml", "pdf")
        ]

    assert list_response.json() == []
    assert detail_response.status_code == 404
    assert delete_response.status_code == 404
    assert all(response.status_code == 404 for response in export_responses)


@pytest.mark.anyio
async def test_archive_audit_path_cannot_create_active_nmap_basic_job(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_ACTIVE_NMAP_BASIC_ENABLED", "true")
    configure_test_state(monkeypatch, tmp_path)
    app.state.archive_audits = NoopAuditService()
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        upload_response = await client.post(
            "/files/archive",
            files={"file": ("sample.zip", make_zip_bytes({"README.md": b"hello"}), "application/zip")},
        )
        launch_response = await client.post(f"/audits/archive/{upload_response.json()['id']}")
        jobs_response = await client.get("/jobs")

    assert upload_response.status_code == 201
    assert launch_response.status_code == 202
    assert launch_response.json()["audit_type"] == "archive_basic"
    assert {job["audit_type"] for job in jobs_response.json()} == {"archive_basic"}


@pytest.mark.anyio
async def test_active_nmap_basic_enabled_requires_mode_and_profile(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_ACTIVE_NMAP_BASIC_ENABLED", "true")
    configure_test_state(monkeypatch, tmp_path)
    payloads = [
        make_active_nmap_basic_payload(mode="dry_run"),
        make_active_nmap_basic_payload(profile="nmap_plan"),
        make_active_nmap_basic_payload(),
        make_active_nmap_basic_payload(),
    ]
    payloads[2].pop("mode")
    payloads[3].pop("profile")
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        responses = [await client.post("/active/network/nmap-basic", json=payload) for payload in payloads]
        jobs_response = await client.get("/jobs")

    assert [response.status_code for response in responses] == [400, 400, 400, 400]
    assert jobs_response.json() == []


@pytest.mark.anyio
async def test_active_nmap_basic_requires_authorization_confirmations(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_ACTIVE_NMAP_BASIC_ENABLED", "true")
    configure_test_state(monkeypatch, tmp_path)
    confirmation_fields = [
        "authorization_confirmed",
        "local_private_scope_confirmed",
        "live_traffic_confirmed",
    ]
    payloads = []
    for field_name in confirmation_fields:
        payloads.append(make_active_nmap_basic_payload(**{field_name: False}))
        missing_payload = make_active_nmap_basic_payload()
        missing_payload.pop(field_name)
        payloads.append(missing_payload)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        responses = [await client.post("/active/network/nmap-basic", json=payload) for payload in payloads]
        jobs_response = await client.get("/jobs")

    assert [response.status_code for response in responses] == [400] * len(payloads)
    assert jobs_response.json() == []


@pytest.mark.anyio
@pytest.mark.parametrize(
    "field_name",
    [
        "raw_flags",
        "extra_args",
        "scripts",
        "credentials",
        "cookies",
        "tokens",
        "headers",
        "target_files",
        "shell_command",
        "custom_profile",
        "command",
        "args",
    ],
)
async def test_active_nmap_basic_rejects_arbitrary_execution_fields_without_job(monkeypatch, tmp_path, field_name):
    monkeypatch.setenv("INSPECTRA_ACTIVE_NMAP_BASIC_ENABLED", "true")
    configure_test_state(monkeypatch, tmp_path)
    payload = make_active_nmap_basic_payload(**{field_name: "token_should_never_render"})
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post("/active/network/nmap-basic", json=payload)
        jobs_response = await client.get("/jobs")

    assert response.status_code == 400
    assert response.json()["detail"] == "Unsupported active_nmap_basic request field."
    assert "token_should_never_render" not in response.text
    assert jobs_response.json() == []


@pytest.mark.anyio
@pytest.mark.parametrize(
    "override",
    [
        {"targets": None},
        {"targets": []},
        {"targets": "192.168.56.10"},
        {"targets": [""]},
        {"targets": [42]},
        {"targets": ["a" * 254]},
        {"targets": ["192.168.56.0/24"]},
        {"targets": ["192.168.1.1-254"]},
        {"targets": ["*.example.test"]},
        {"targets": ["http://192.168.56.10"]},
        {"targets": ["lab.internal/path"]},
        {"targets": ["lab.internal?debug=true"]},
        {"targets": ["lab.internal#fragment"]},
        {"targets": ["user:pass@lab.internal"]},
        {"targets": ["169.254.169.254"]},
        {"targets": ["metadata.google.internal"]},
        {"targets": ["example.com"]},
        {"targets": ["lab.internal."]},
        {"targets": ["192.168.56.10,192.168.56.11"]},
        {"targets": ["192.168.56.10 192.168.56.11"]},
        {"targets": ["192.168.56.10", "192.168.56.11", "192.168.56.12", "192.168.56.13"]},
        {"ports": None},
        {"ports": []},
        {"ports": "22"},
        {"ports": ["22"]},
        {"ports": [True]},
        {"ports": [0]},
        {"ports": [65536]},
        {"ports": list(range(1, 34))},
    ],
)
async def test_active_nmap_basic_rejects_malformed_targets_and_ports(monkeypatch, tmp_path, override):
    monkeypatch.setenv("INSPECTRA_ACTIVE_NMAP_BASIC_ENABLED", "true")
    configure_test_state(monkeypatch, tmp_path)
    payload = make_active_nmap_basic_payload(**override)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post("/active/network/nmap-basic", json=payload)
        jobs_response = await client.get("/jobs")

    assert response.status_code == 400
    assert jobs_response.json() == []


@pytest.mark.anyio
async def test_active_nmap_basic_auth_required_anonymous_fails_before_validation(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_AUTH_MODE", "self_hosted_single_admin")
    monkeypatch.setenv("INSPECTRA_ACTIVE_NMAP_BASIC_ENABLED", "true")
    configure_test_state(monkeypatch, tmp_path)
    payload = make_active_nmap_basic_payload(raw_flags="token_should_never_render")
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post("/active/network/nmap-basic", json=payload)

    assert response.status_code == 401
    assert response.json() == {"detail": AUTH_REQUIRED_DETAIL}
    assert "Unsupported active_nmap_basic request field" not in response.text
    assert "token_should_never_render" not in response.text
    assert app.state.jobs.list() == []


@pytest.mark.anyio
async def test_active_tls_basic_disabled_by_default_no_job(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    fake_connector = FakeActiveTlsBasicConnector()
    app.state.active_tls_basic_connector = fake_connector
    payload = make_active_tls_basic_payload(target="secret-lab.internal", raw_flags="token_should_never_render")
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post("/active/network/tls-basic", json=payload)
        jobs_response = await client.get("/jobs")

    assert response.status_code == 403
    assert response.json()["detail"] == "active_tls_basic is disabled in this environment."
    assert "secret-lab.internal" not in response.text
    assert "token_should_never_render" not in response.text
    assert jobs_response.json() == []
    assert fake_connector.calls == []


@pytest.mark.anyio
async def test_active_tls_basic_enabled_valid_request_creates_redacted_handshake_job(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_ACTIVE_TLS_BASIC_ENABLED", "true")
    configure_test_state(monkeypatch, tmp_path)
    fake_connector = FakeActiveTlsBasicConnector()
    app.state.active_tls_basic_connector = fake_connector
    app.state.active_tls_basic_now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post("/active/network/tls-basic", json=make_active_tls_basic_payload())
        job_id = response.json()["id"]
        jobs_response = await client.get("/jobs")
        detail_response = await client.get(f"/jobs/{job_id}")
        export_responses = {
            report_format: await client.get(f"/jobs/{job_id}/export/{report_format}")
            for report_format in ("markdown", "html", "xml", "pdf")
        }

    assert response.status_code == 202
    assert detail_response.status_code == 200
    assert all(export_response.status_code == 200 for export_response in export_responses.values())
    payload = response.json()
    detail_payload = detail_response.json()
    list_payload = jobs_response.json()
    assert len(fake_connector.calls) == 1
    assert fake_connector.calls[0].target == "192.168.56.10"
    assert fake_connector.calls[0].port == 443
    assert payload["audit_type"] == "active_tls_basic"
    assert payload["file_id"] is None
    assert payload["owner_id"] == DEFAULT_LOCAL_OPERATOR.id
    assert payload["status"] == "completed"
    assert payload["target_url"] == "[REDACTED_TARGET]"
    assert payload["result"]["audit_type"] == "active_tls_basic"
    assert payload["result"]["capability"] == "active_tls_basic"
    assert payload["result"]["status"] == "handshake_succeeded"
    assert payload["result"]["result_status"] == "handshake_succeeded"
    assert payload["result"]["target"] == "[REDACTED_TARGET]"
    assert payload["result"]["port"] == 443
    assert payload["result"]["handshake"]["status"] == "succeeded"
    assert payload["result"]["handshake"]["protocol"] == "TLSv1.3"
    assert payload["result"]["handshake"]["cipher"] == "TLS_AES_256_GCM_SHA384"
    assert payload["result"]["certificate"]["subject"] == "commonName=[REDACTED_TARGET]"
    assert payload["result"]["certificate"]["issuer"] == "commonName=Inspectra Test CA"
    assert payload["result"]["certificate"]["san_count"] == 4
    assert payload["result"]["certificate"]["san_sample"] == [
        {"type": "DNS", "value": "[REDACTED_SAN]"},
        {"type": "DNS", "value": "[REDACTED_SAN]"},
        {"type": "DNS", "value": "[REDACTED_SAN]"},
    ]
    assert payload["result"]["certificate"]["not_before"] == "2026-01-01T00:00:00Z"
    assert payload["result"]["certificate"]["not_after"] == "2026-01-31T00:00:00Z"
    assert payload["result"]["certificate"]["days_until_expiry"] == 30
    assert payload["result"]["manual_validation_required"] is True
    assert payload["result"]["result_interpretation"] == "tls_configuration_review_indicator"
    assert payload["result"]["execution"]["tls_handshake_attempted"] is True
    assert payload["result"]["execution"]["network_requests_sent"] == 1
    assert payload["result"]["execution"]["http_requests_sent"] == 0
    assert payload["result"]["execution"]["target_expansion_performed"] is False
    assert detail_payload["target_url"] == "[REDACTED_TARGET]"
    assert detail_payload["result"]["certificate"]["san_sample"][0]["value"] == "[REDACTED_SAN]"
    assert list_payload[0]["audit_type"] == "active_tls_basic"
    assert list_payload[0]["file_id"] is None
    assert list_payload[0]["target_url"] == "[REDACTED_TARGET]"
    assert list_payload[0]["summary"]["result_status"] == "handshake_succeeded"
    assert list_payload[0]["summary"]["days_until_expiry"] == 30

    combined = json.dumps({"create": payload, "detail": detail_payload, "list": list_payload}, sort_keys=True)
    combined += "\n" + "\n".join(
        export.text if report_format != "pdf" else export.content.decode("latin1", errors="ignore")
        for report_format, export in export_responses.items()
    )
    assert "TLS configuration review indicator" in combined
    assert "Manual validation required" in combined
    assert "No raw certificate PEM or DER stored" in combined
    for forbidden in (
        "192.168.56.10",
        "nas-01.local",
        "secret-lab.internal",
        "extra.internal",
        "BEGIN CERTIFICATE",
        "certificate_pem",
        "certificate_der",
        "token_should_never_render",
        "confirmed vulnerability",
        "exploitable",
        "target is safe",
    ):
        assert forbidden not in combined


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("exc", "expected_status", "expected_reason"),
    [
        (TimeoutError("timeout against 192.168.56.10 token_should_never_render"), "timed_out", "timeout"),
        (RuntimeError("tls failure for 192.168.56.10 token_should_never_render"), "tls_error_controlled", "unexpected_tls_error"),
    ],
)
async def test_active_tls_basic_controlled_errors_are_persisted_redacted(monkeypatch, tmp_path, exc, expected_status, expected_reason):
    monkeypatch.setenv("INSPECTRA_ACTIVE_TLS_BASIC_ENABLED", "true")
    configure_test_state(monkeypatch, tmp_path)
    fake_connector = FakeActiveTlsBasicConnector(exc=exc)
    app.state.active_tls_basic_connector = fake_connector
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post("/active/network/tls-basic", json=make_active_tls_basic_payload())
        job_id = response.json()["id"]
        detail_response = await client.get(f"/jobs/{job_id}")
        export_response = await client.get(f"/jobs/{job_id}/export/markdown")

    assert response.status_code == 202
    assert len(fake_connector.calls) == 1
    payload = response.json()
    detail_payload = detail_response.json()
    assert payload["status"] == "failed"
    assert payload["error"] == expected_reason
    assert payload["target_url"] == "[REDACTED_TARGET]"
    assert payload["result"]["result_status"] == expected_status
    assert payload["result"]["reason_codes"] == [expected_reason]
    assert payload["result"]["errors"] == [{"code": expected_reason}]
    assert detail_payload["error"] == expected_reason
    assert detail_payload["result"]["certificate"]["available"] is False
    combined = json.dumps({"create": payload, "detail": detail_payload}, sort_keys=True) + "\n" + export_response.text
    assert expected_reason in combined
    for forbidden in ("192.168.56.10", "token_should_never_render", "RuntimeError", "TimeoutError"):
        assert forbidden not in combined


@pytest.mark.anyio
async def test_active_tls_basic_wrong_owner_cannot_read_detail_delete_or_exports(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_ACTIVE_TLS_BASIC_ENABLED", "true")
    configure_test_state(monkeypatch, tmp_path)
    wrong_owner_job = app.state.jobs.create_active_tls_basic_job(
        {
            "audit_type": "active_tls_basic",
            "capability": "active_tls_basic",
            "mode": "live_tls_basic",
            "profile": "tls_handshake_summary",
            "status": "handshake_succeeded",
            "result_status": "handshake_succeeded",
            "target": "[REDACTED_TARGET]",
            "port": 443,
            "handshake": {"status": "succeeded", "protocol": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384"},
            "certificate": {"available": True, "subject": "commonName=[REDACTED_TARGET]", "issuer": "commonName=Test CA", "san_count": 0, "san_sample": [], "not_before": None, "not_after": None, "days_until_expiry": None},
            "summary": {"manual_validation_required": True, "result_interpretation": "tls_configuration_review_indicator"},
            "execution": {"tls_handshake_attempted": True, "network_requests_sent": 1, "http_requests_sent": 0, "target_expansion_performed": False, "dns_expansion_performed": False},
            "manual_validation_required": True,
            "result_interpretation": "tls_configuration_review_indicator",
            "limits": {"raw_certificate_persisted": False, "raw_target_persisted": False},
        },
        status="completed",
        owner_id="other-owner",
    )
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        detail_response = await client.get(f"/jobs/{wrong_owner_job.id}")
        delete_response = await client.delete(f"/jobs/{wrong_owner_job.id}")
        export_responses = [
            await client.get(f"/jobs/{wrong_owner_job.id}/export/{report_format}")
            for report_format in ("markdown", "html", "xml", "pdf")
        ]

    assert detail_response.status_code == 404
    assert detail_response.json()["detail"] == "Job not found."
    assert delete_response.status_code == 404
    assert delete_response.json()["detail"] == "Job not found."
    assert all(response.status_code == 404 for response in export_responses)


@pytest.mark.anyio
async def test_active_tls_basic_legacy_raw_payload_is_redacted_in_detail_list_and_exports(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    job = app.state.jobs.create_active_tls_basic_job(
        {
            "audit_type": "active_tls_basic",
            "capability": "active_tls_basic",
            "mode": "live_tls_basic",
            "profile": "tls_handshake_summary",
            "status": "handshake_succeeded",
            "result_status": "handshake_succeeded",
            "target": "192.168.56.10",
            "raw_target": "secret-lab.internal",
            "port": 443,
            "handshake": {"status": "succeeded", "protocol": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384"},
            "certificate": {
                "available": True,
                "subject": "CN=secret-lab.internal",
                "issuer": "CN=Inspectra Test CA",
                "san_count": 2,
                "san_sample": [{"type": "DNS", "value": "secret-lab.internal"}],
                "not_before": "2026-01-01T00:00:00Z",
                "not_after": "2026-01-31T00:00:00Z",
                "days_until_expiry": 30,
                "certificate_pem": "-----BEGIN CERTIFICATE-----token_should_never_render-----END CERTIFICATE-----",
                "certificate_der": "raw_der_should_not_render",
            },
            "raw_exception": "failure for 192.168.56.10 token_should_never_render",
            "headers": {"Authorization": "Bearer token_should_never_render"},
            "cookies": {"session": "token_should_never_render"},
            "credentials": {"password": "token_should_never_render"},
            "tokens": ["token_should_never_render"],
            "summary": {"manual_validation_required": True, "result_interpretation": "tls_configuration_review_indicator"},
            "execution": {"tls_handshake_attempted": True, "network_requests_sent": 1, "http_requests_sent": 0, "target_expansion_performed": False, "dns_expansion_performed": False},
            "manual_validation_required": True,
            "result_interpretation": "tls_configuration_review_indicator",
            "limits": {"raw_certificate_persisted": False, "raw_target_persisted": False},
        },
        status="completed",
        error="legacy error for 192.168.56.10 token_should_never_render",
        owner_id=DEFAULT_LOCAL_OPERATOR.id,
    )
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        list_response = await client.get("/jobs")
        detail_response = await client.get(f"/jobs/{job.id}")
        export_responses = {
            report_format: await client.get(f"/jobs/{job.id}/export/{report_format}")
            for report_format in ("markdown", "html", "xml", "pdf")
        }

    assert list_response.status_code == 200
    assert detail_response.status_code == 200
    assert all(response.status_code == 200 for response in export_responses.values())
    combined = json.dumps({"list": list_response.json(), "detail": detail_response.json()}, sort_keys=True)
    combined += "\n" + "\n".join(
        response.text if report_format != "pdf" else response.content.decode("latin1", errors="ignore")
        for report_format, response in export_responses.items()
    )
    assert "[REDACTED_TARGET]" in combined
    assert "TLS configuration review indicator" in combined
    for forbidden in (
        "192.168.56.10",
        "secret-lab.internal",
        "BEGIN CERTIFICATE",
        "raw_der_should_not_render",
        "token_should_never_render",
        "certificate_pem",
        "certificate_der",
        "raw_exception",
        "Bearer",
        "session",
        "password",
        "confirmed vulnerability",
        "exploitable",
        "target is safe",
    ):
        assert forbidden not in combined


@pytest.mark.anyio
async def test_active_tls_basic_enabled_requires_mode_and_profile(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_ACTIVE_TLS_BASIC_ENABLED", "true")
    configure_test_state(monkeypatch, tmp_path)
    fake_connector = FakeActiveTlsBasicConnector()
    app.state.active_tls_basic_connector = fake_connector
    payloads = [
        make_active_tls_basic_payload(mode="dry_run"),
        make_active_tls_basic_payload(profile="tls_full_scan"),
        make_active_tls_basic_payload(),
        make_active_tls_basic_payload(),
    ]
    payloads[2].pop("mode")
    payloads[3].pop("profile")
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        responses = [await client.post("/active/network/tls-basic", json=payload) for payload in payloads]
        jobs_response = await client.get("/jobs")

    assert [response.status_code for response in responses] == [400, 400, 400, 400]
    assert jobs_response.json() == []
    assert fake_connector.calls == []


@pytest.mark.anyio
async def test_active_tls_basic_requires_authorization_confirmations(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_ACTIVE_TLS_BASIC_ENABLED", "true")
    configure_test_state(monkeypatch, tmp_path)
    fake_connector = FakeActiveTlsBasicConnector()
    app.state.active_tls_basic_connector = fake_connector
    confirmation_fields = [
        "authorization_confirmed",
        "local_private_scope_confirmed",
        "live_traffic_confirmed",
    ]
    payloads = []
    for field_name in confirmation_fields:
        payloads.append(make_active_tls_basic_payload(**{field_name: False}))
        missing_payload = make_active_tls_basic_payload()
        missing_payload.pop(field_name)
        payloads.append(missing_payload)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        responses = [await client.post("/active/network/tls-basic", json=payload) for payload in payloads]
        jobs_response = await client.get("/jobs")

    assert [response.status_code for response in responses] == [400] * len(payloads)
    assert jobs_response.json() == []
    assert fake_connector.calls == []


@pytest.mark.anyio
@pytest.mark.parametrize(
    "field_name",
    [
        "raw_flags",
        "headers",
        "cookies",
        "tokens",
        "credentials",
        "client_certificates",
        "client_certificate",
        "client_key",
        "sni_overrides",
        "sni_override_list",
        "cipher_brute_force",
        "protocol_fuzzing",
        "http_request",
        "crawl",
        "urls",
    ],
)
async def test_active_tls_basic_rejects_dangerous_extra_fields_without_job(monkeypatch, tmp_path, field_name):
    monkeypatch.setenv("INSPECTRA_ACTIVE_TLS_BASIC_ENABLED", "true")
    configure_test_state(monkeypatch, tmp_path)
    fake_connector = FakeActiveTlsBasicConnector()
    app.state.active_tls_basic_connector = fake_connector
    payload = make_active_tls_basic_payload(**{field_name: "token_should_never_render"})
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post("/active/network/tls-basic", json=payload)
        jobs_response = await client.get("/jobs")

    assert response.status_code == 400
    assert response.json()["detail"] == "Unsupported active_tls_basic request field."
    assert "token_should_never_render" not in response.text
    assert jobs_response.json() == []
    assert fake_connector.calls == []


@pytest.mark.anyio
@pytest.mark.parametrize(
    "override",
    [
        {"target": None},
        {"target": ""},
        {"target": ["192.168.56.10"]},
        {"target": 42},
        {"target": "a" * 254},
        {"target": "192.168.56.0/24"},
        {"target": "192.168.1.1-254"},
        {"target": "*.example.test"},
        {"target": "http://192.168.56.10"},
        {"target": "lab.internal/path"},
        {"target": "lab.internal?debug=true"},
        {"target": "lab.internal#fragment"},
        {"target": "user:pass@lab.internal"},
        {"target": "169.254.169.254"},
        {"target": "metadata.google.internal"},
        {"target": "example.com"},
        {"target": "lab.internal."},
        {"target": "192.168.56.10,192.168.56.11"},
        {"target": "192.168.56.10 192.168.56.11"},
        {"port": None},
        {"port": "443"},
        {"port": True},
        {"port": 0},
        {"port": 65536},
        {"port": 80},
    ],
)
async def test_active_tls_basic_rejects_malformed_target_and_port(monkeypatch, tmp_path, override):
    monkeypatch.setenv("INSPECTRA_ACTIVE_TLS_BASIC_ENABLED", "true")
    configure_test_state(monkeypatch, tmp_path)
    fake_connector = FakeActiveTlsBasicConnector()
    app.state.active_tls_basic_connector = fake_connector
    payload = make_active_tls_basic_payload(**override)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post("/active/network/tls-basic", json=payload)
        jobs_response = await client.get("/jobs")

    assert response.status_code == 400
    assert "192.168.56.10" not in response.text
    assert jobs_response.json() == []
    assert fake_connector.calls == []


@pytest.mark.anyio
async def test_active_tls_basic_error_output_does_not_reflect_target_or_payload(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_ACTIVE_TLS_BASIC_ENABLED", "true")
    configure_test_state(monkeypatch, tmp_path)
    payload = make_active_tls_basic_payload(
        target="secret-lab.internal/path?token=token_should_never_render",
        port=443,
    )
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post("/active/network/tls-basic", json=payload)

    assert response.status_code == 400
    assert "secret-lab.internal" not in response.text
    assert "token_should_never_render" not in response.text


@pytest.mark.anyio
async def test_active_tls_basic_auth_required_anonymous_fails_before_validation(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_AUTH_MODE", "self_hosted_single_admin")
    monkeypatch.setenv("INSPECTRA_ACTIVE_TLS_BASIC_ENABLED", "true")
    configure_test_state(monkeypatch, tmp_path)
    payload = make_active_tls_basic_payload(raw_flags="token_should_never_render")
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post("/active/network/tls-basic", json=payload)

    assert response.status_code == 401
    assert response.json() == {"detail": AUTH_REQUIRED_DETAIL}
    assert "Unsupported active_tls_basic request field" not in response.text
    assert "token_should_never_render" not in response.text
    assert app.state.jobs.list() == []


@pytest.mark.anyio
async def test_active_dns_inventory_disabled_by_default_no_job(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    fake_resolver = make_active_dns_inventory_fake_resolver()
    fake_axfr = FakeActiveDnsInventoryAxfrTransport()
    app.state.active_dns_inventory_resolver = fake_resolver
    app.state.active_dns_inventory_axfr_transport = fake_axfr
    payload = make_active_dns_inventory_payload(
        domain="secret.example.com",
        attempt_zone_transfer=True,
        zone_transfer_authorized_confirmed=True,
        resolver_override="token_should_never_render",
    )
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post("/active/network/dns-inventory", json=payload)
        jobs_response = await client.get("/jobs")

    assert response.status_code == 403
    assert response.json()["detail"] == "active_dns_inventory is disabled in this environment."
    assert "secret.example.com" not in response.text
    assert "token_should_never_render" not in response.text
    assert jobs_response.json() == []
    assert fake_resolver.calls == []
    assert fake_axfr.calls == []


@pytest.mark.anyio
async def test_active_dns_inventory_enabled_valid_request_creates_redacted_inventory_job(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_ACTIVE_DNS_INVENTORY_ENABLED", "true")
    configure_test_state(monkeypatch, tmp_path)
    fake_resolver = make_active_dns_inventory_fake_resolver()
    app.state.active_dns_inventory_resolver = fake_resolver
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post("/active/network/dns-inventory", json=make_active_dns_inventory_payload())
        job_id = response.json()["id"]
        jobs_response = await client.get("/jobs")
        detail_response = await client.get(f"/jobs/{job_id}")
        export_responses = {
            report_format: await client.get(f"/jobs/{job_id}/export/{report_format}")
            for report_format in ("markdown", "html", "xml", "pdf")
        }

    assert response.status_code == 202
    assert detail_response.status_code == 200
    assert all(export_response.status_code == 200 for export_response in export_responses.values())
    payload = response.json()
    detail_payload = detail_response.json()
    list_payload = jobs_response.json()
    assert payload["audit_type"] == "active_dns_inventory"
    assert payload["file_id"] is None
    assert payload["owner_id"] == DEFAULT_LOCAL_OPERATOR.id
    assert payload["status"] == "completed"
    assert payload["target_url"] == "[REDACTED_DOMAIN]"
    assert payload["target_domain"] is None
    assert payload["result"]["status"] == "best_effort_inventory"
    assert payload["result"]["coverage_level"] == "best_effort_inventory"
    assert payload["result"]["domain"] == "[REDACTED_DOMAIN]"
    assert payload["result"]["records"]["A"]["count"] == 1
    assert payload["result"]["records"]["TXT"]["count"] == 2
    assert payload["result"]["records"]["MX"]["sample"][0]["priority"] == 10
    assert payload["result"]["security_records"]["spf"]["present"] is True
    assert payload["result"]["security_records"]["dmarc"]["present"] is True
    assert payload["result"]["security_records"]["caa"]["present"] is True
    assert payload["result"]["security_records"]["dkim"]["checked"] is False
    assert payload["result"]["zone_transfer"] == {
        "attempted": False,
        "status": "not_attempted",
        "nameservers_considered": 0,
        "nameservers_attempted": 0,
        "records_received_count": 0,
        "records_retained_count": 0,
        "truncated": False,
    }
    assert payload["result"]["provider_import"] == {"attempted": False, "status": "not_attempted"}
    assert payload["result"]["subdomains"]["enabled"] is True
    assert payload["result"]["subdomains"]["candidates_checked"] == 12
    assert payload["result"]["subdomains"]["count"] == 2
    assert payload["result"]["subdomain_queries_sent"] == 36
    assert payload["result"]["dns_queries_sent"] == 45
    assert len(fake_resolver.calls) == 45
    assert ("example.com", "A") in fake_resolver.calls
    assert ("_dmarc.example.com", "TXT") in fake_resolver.calls
    assert ("www.example.com", "A") in fake_resolver.calls
    assert list_payload[0]["target_url"] == "[REDACTED_DOMAIN]"
    assert list_payload[0]["summary"]["coverage_level"] == "best_effort_inventory"
    assert detail_payload["target_url"] == "[REDACTED_DOMAIN]"
    assert detail_payload["result"]["domain"] == "[REDACTED_DOMAIN]"
    assert detail_payload["result"]["records"]["A"]["sample"][0]["value"] == "[REDACTED_DNS_VALUE]"
    combined = json.dumps({"create": payload, "detail": detail_payload, "list": list_payload}, sort_keys=True)
    combined += "\n" + "\n".join(
        export.text if report_format != "pdf" else export.content.decode("latin1", errors="ignore")
        for report_format, export in export_responses.items()
    )
    assert "DNS configuration review indicator" in combined
    assert "[REDACTED_DOMAIN]" in combined
    assert "[REDACTED_DNS_VALUE]" in combined
    for forbidden in (
        "example.com",
        "192.0.2.10",
        "2001:db8::10",
        "mail.example.com",
        "_spf.example.net",
        "token_should_never_render",
        "raw_dns_packet",
        "provider_api_token",
    ):
        assert forbidden not in combined


@pytest.mark.anyio
async def test_active_dns_inventory_subdomain_discovery_can_be_disabled(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_ACTIVE_DNS_INVENTORY_ENABLED", "true")
    configure_test_state(monkeypatch, tmp_path)
    fake_resolver = make_active_dns_inventory_fake_resolver()
    app.state.active_dns_inventory_resolver = fake_resolver
    payload = make_active_dns_inventory_payload(include_subdomain_discovery=False)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post("/active/network/dns-inventory", json=payload)

    assert response.status_code == 202
    result = response.json()["result"]
    assert result["subdomains"]["enabled"] is False
    assert result["subdomains"]["candidates_checked"] == 0
    assert result["subdomain_queries_sent"] == 0
    assert result["dns_queries_sent"] == 9
    assert all(not call[0].startswith("www.") for call in fake_resolver.calls)


@pytest.mark.anyio
async def test_active_dns_inventory_partial_timeout_remains_controlled_and_redacted(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_ACTIVE_DNS_INVENTORY_ENABLED", "true")
    configure_test_state(monkeypatch, tmp_path)
    fake_resolver = make_active_dns_inventory_fake_resolver(partial_timeout=True)
    app.state.active_dns_inventory_resolver = fake_resolver
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post("/active/network/dns-inventory", json=make_active_dns_inventory_payload(include_subdomain_discovery=False))
        detail_response = await client.get(f"/jobs/{response.json()['id']}")

    assert response.status_code == 202
    assert response.json()["status"] == "completed"
    assert response.json()["error"] == "partial_inventory"
    assert response.json()["result"]["coverage_level"] == "partial_inventory"
    assert response.json()["result"]["errors"] == [{"code": "dns_query_timeout", "record_type": "MX", "purpose": "root_standard_record"}]
    assert detail_response.json()["error"] == "partial_inventory"
    assert "example.com" not in response.text


@pytest.mark.anyio
async def test_active_dns_inventory_nxdomain_or_empty_result_is_controlled(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_ACTIVE_DNS_INVENTORY_ENABLED", "true")
    configure_test_state(monkeypatch, tmp_path)
    fake_resolver = make_active_dns_inventory_fake_resolver(empty_domain=True)
    app.state.active_dns_inventory_resolver = fake_resolver
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post("/active/network/dns-inventory", json=make_active_dns_inventory_payload(include_subdomain_discovery=False))

    assert response.status_code == 202
    result = response.json()["result"]
    assert result["coverage_level"] == "best_effort_inventory"
    assert result["records"]["A"]["count"] == 0
    assert result["security_records"]["spf"]["present"] is False
    assert result["security_records"]["dmarc"]["present"] is False
    assert result["security_records"]["caa"]["present"] is False
    assert result["errors"] == []


@pytest.mark.anyio
async def test_active_dns_inventory_enabled_requires_mode_and_profile(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_ACTIVE_DNS_INVENTORY_ENABLED", "true")
    configure_test_state(monkeypatch, tmp_path)
    fake_resolver = make_active_dns_inventory_fake_resolver()
    app.state.active_dns_inventory_resolver = fake_resolver
    payloads = [
        make_active_dns_inventory_payload(mode="dry_run"),
        make_active_dns_inventory_payload(profile="dns_any"),
        make_active_dns_inventory_payload(),
        make_active_dns_inventory_payload(),
    ]
    payloads[2].pop("mode")
    payloads[3].pop("profile")
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        responses = [await client.post("/active/network/dns-inventory", json=payload) for payload in payloads]
        jobs_response = await client.get("/jobs")

    assert [response.status_code for response in responses] == [400, 400, 400, 400]
    assert jobs_response.json() == []
    assert fake_resolver.calls == []


@pytest.mark.anyio
async def test_active_dns_inventory_requires_authorization_confirmations(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_ACTIVE_DNS_INVENTORY_ENABLED", "true")
    configure_test_state(monkeypatch, tmp_path)
    fake_resolver = make_active_dns_inventory_fake_resolver()
    app.state.active_dns_inventory_resolver = fake_resolver
    confirmation_fields = [
        "authorization_confirmed",
        "local_private_or_owned_scope_confirmed",
        "live_dns_queries_confirmed",
    ]
    payloads = []
    for field_name in confirmation_fields:
        payloads.append(make_active_dns_inventory_payload(**{field_name: False}))
        missing_payload = make_active_dns_inventory_payload()
        missing_payload.pop(field_name)
        payloads.append(missing_payload)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        responses = [await client.post("/active/network/dns-inventory", json=payload) for payload in payloads]
        jobs_response = await client.get("/jobs")

    assert [response.status_code for response in responses] == [400] * len(payloads)
    assert jobs_response.json() == []
    assert fake_resolver.calls == []


@pytest.mark.anyio
@pytest.mark.parametrize(
    "override",
    [
        {"domain": None},
        {"domain": ""},
        {"domain": ["example.com"]},
        {"domain": 42},
        {"domain": "a" * 64 + ".example.com"},
        {"domain": "a" * 250 + ".com"},
        {"domain": "example.com,example.net"},
        {"domain": "example.com example.net"},
        {"domain": "example.com\nexample.net"},
        {"domain": "http://example.com"},
        {"domain": "example.com/path"},
        {"domain": "example.com?debug=true"},
        {"domain": "example.com#fragment"},
        {"domain": "user:pass@example.com"},
        {"domain": "*.example.com"},
        {"domain": "192.0.2.10"},
        {"domain": "192.0.2.0/24"},
        {"domain": "192.0.2.1-192.0.2.10"},
        {"domain": "metadata.google.internal"},
        {"domain": "targets.txt"},
        {"domain": "singlelabel"},
        {"include_security_records": "true"},
        {"include_subdomain_discovery": "false"},
        {"attempt_zone_transfer": "false"},
        {"zone_transfer_authorized_confirmed": "true"},
    ],
)
async def test_active_dns_inventory_rejects_malformed_domain_and_flags(monkeypatch, tmp_path, override):
    monkeypatch.setenv("INSPECTRA_ACTIVE_DNS_INVENTORY_ENABLED", "true")
    configure_test_state(monkeypatch, tmp_path)
    fake_resolver = make_active_dns_inventory_fake_resolver()
    app.state.active_dns_inventory_resolver = fake_resolver
    payload = make_active_dns_inventory_payload(**override)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post("/active/network/dns-inventory", json=payload)
        jobs_response = await client.get("/jobs")

    assert response.status_code == 400
    assert "example.com" not in response.text
    assert "metadata.google.internal" not in response.text
    assert jobs_response.json() == []
    assert fake_resolver.calls == []


@pytest.mark.anyio
@pytest.mark.parametrize(
    "override",
    [
        {"record_types": None},
        {"record_types": []},
        {"record_types": ["A", "AXFR"]},
        {"record_types": ["A", "SRV"]},
        {"record_types": ["A", 1]},
    ],
)
async def test_active_dns_inventory_rejects_missing_or_unallowed_record_types(monkeypatch, tmp_path, override):
    monkeypatch.setenv("INSPECTRA_ACTIVE_DNS_INVENTORY_ENABLED", "true")
    configure_test_state(monkeypatch, tmp_path)
    fake_resolver = make_active_dns_inventory_fake_resolver()
    app.state.active_dns_inventory_resolver = fake_resolver
    payload = make_active_dns_inventory_payload(**override)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post("/active/network/dns-inventory", json=payload)
        jobs_response = await client.get("/jobs")

    assert response.status_code == 400
    assert jobs_response.json() == []
    assert fake_resolver.calls == []


@pytest.mark.anyio
async def test_active_dns_inventory_requires_specific_zone_transfer_authorization(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_ACTIVE_DNS_INVENTORY_ENABLED", "true")
    configure_test_state(monkeypatch, tmp_path)
    fake_resolver = make_active_dns_inventory_fake_resolver()
    fake_axfr = FakeActiveDnsInventoryAxfrTransport()
    app.state.active_dns_inventory_resolver = fake_resolver
    app.state.active_dns_inventory_axfr_transport = fake_axfr
    payload = make_active_dns_inventory_payload(
        domain="secret.example.com",
        attempt_zone_transfer=True,
    )
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post("/active/network/dns-inventory", json=payload)
        jobs_response = await client.get("/jobs")

    assert response.status_code == 400
    assert response.json()["detail"] == "zone_transfer_authorized_confirmed must be true."
    assert "secret.example.com" not in response.text
    assert jobs_response.json() == []
    assert fake_resolver.calls == []
    assert fake_axfr.calls == []


def test_active_dns_inventory_helper_blocks_axfr_without_internal_authorization():
    fake_resolver = make_active_dns_inventory_fake_resolver()
    fake_axfr = FakeActiveDnsInventoryAxfrTransport()
    result = run_active_dns_inventory(
        ActiveDnsInventoryContract(
            domain="example.com",
            record_types=("A",),
            include_security_records=False,
            include_subdomain_discovery=False,
            attempt_zone_transfer=True,
            zone_transfer_authorized_confirmed=False,
        ),
        resolver=fake_resolver,
        axfr_transport=fake_axfr,
    )

    assert result["zone_transfer"]["status"] == "authorization_required"
    assert result["zone_transfer"]["attempted"] is False
    assert fake_axfr.calls == []


@pytest.mark.anyio
async def test_active_dns_inventory_zone_transfer_no_authoritative_ns_is_controlled(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_ACTIVE_DNS_INVENTORY_ENABLED", "true")
    configure_test_state(monkeypatch, tmp_path)
    fake_resolver = FakeActiveDnsInventoryResolver(
        {
            ("example.com", "A"): [dns_record("example.com", "A", "192.0.2.10")],
            ("example.com", "NS"): ActiveDnsInventoryQueryResult(status="noerror_empty"),
        }
    )
    fake_axfr = FakeActiveDnsInventoryAxfrTransport()
    app.state.active_dns_inventory_resolver = fake_resolver
    app.state.active_dns_inventory_axfr_transport = fake_axfr
    payload = make_active_dns_inventory_payload(
        record_types=["A"],
        include_security_records=False,
        include_subdomain_discovery=False,
        attempt_zone_transfer=True,
        zone_transfer_authorized_confirmed=True,
    )
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post("/active/network/dns-inventory", json=payload)

    assert response.status_code == 202
    result = response.json()["result"]
    assert result["coverage_level"] == "best_effort_inventory"
    assert result["zone_transfer"]["attempted"] is False
    assert result["zone_transfer"]["status"] == "no_authoritative_nameservers"
    assert result["zone_transfer"]["nameservers_considered"] == 0
    assert fake_axfr.calls == []
    assert "example.com" not in response.text


@pytest.mark.anyio
async def test_active_dns_inventory_zone_transfer_refused_is_controlled(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_ACTIVE_DNS_INVENTORY_ENABLED", "true")
    configure_test_state(monkeypatch, tmp_path)
    fake_resolver = make_active_dns_inventory_fake_resolver()
    fake_axfr = FakeActiveDnsInventoryAxfrTransport(
        ActiveDnsInventoryZoneTransferResult(status="refused", reason_code="zone_transfer_refused")
    )
    app.state.active_dns_inventory_resolver = fake_resolver
    app.state.active_dns_inventory_axfr_transport = fake_axfr
    payload = make_active_dns_inventory_payload(
        include_subdomain_discovery=False,
        attempt_zone_transfer=True,
        zone_transfer_authorized_confirmed=True,
    )
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post("/active/network/dns-inventory", json=payload)

    assert response.status_code == 202
    result = response.json()["result"]
    assert result["coverage_level"] == "best_effort_inventory"
    assert result["zone_transfer"]["attempted"] is True
    assert result["zone_transfer"]["status"] == "refused"
    assert result["zone_transfer"]["reason_code"] == "zone_transfer_refused"
    assert result["zone_transfer"]["nameservers_considered"] == 1
    assert result["zone_transfer"]["nameservers_attempted"] == 1
    assert fake_axfr.calls == [("example.com", "ns1.example.net")]
    assert "ns1.example.net" not in response.text
    assert "example.com" not in response.text


@pytest.mark.anyio
async def test_active_dns_inventory_zone_transfer_timeout_is_partial_controlled(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_ACTIVE_DNS_INVENTORY_ENABLED", "true")
    configure_test_state(monkeypatch, tmp_path)
    fake_resolver = make_active_dns_inventory_fake_resolver()
    fake_axfr = FakeActiveDnsInventoryAxfrTransport(TimeoutError("secret.example.com timed out"))
    app.state.active_dns_inventory_resolver = fake_resolver
    app.state.active_dns_inventory_axfr_transport = fake_axfr
    payload = make_active_dns_inventory_payload(
        include_subdomain_discovery=False,
        attempt_zone_transfer=True,
        zone_transfer_authorized_confirmed=True,
    )
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post("/active/network/dns-inventory", json=payload)

    assert response.status_code == 202
    payload = response.json()
    assert payload["status"] == "completed"
    assert payload["error"] == "partial_inventory"
    result = payload["result"]
    assert result["coverage_level"] == "partial_inventory"
    assert result["zone_transfer"]["status"] == "timed_out"
    assert result["zone_transfer"]["reason_code"] == "zone_transfer_timed_out"
    assert {"code": "zone_transfer_timed_out", "record_type": "AXFR", "purpose": "authorized_zone_transfer"} in result["errors"]
    assert "secret.example.com" not in response.text


@pytest.mark.anyio
async def test_active_dns_inventory_zone_transfer_missing_terminal_soa_is_partial(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_ACTIVE_DNS_INVENTORY_ENABLED", "true")
    configure_test_state(monkeypatch, tmp_path)
    fake_resolver = make_active_dns_inventory_fake_resolver()
    axfr_records = [
        dns_record("example.com", "SOA", "mname=ns1.example.net;rname=hostmaster.example.com;serial=1"),
        dns_record("example.com", "A", "192.0.2.10"),
    ]
    fake_axfr = FakeActiveDnsInventoryAxfrTransport(
        ActiveDnsInventoryZoneTransferResult(
            status="zone_transfer_complete",
            records=tuple(axfr_records),
            records_received_count=len(axfr_records),
            records_retained_count=len(axfr_records),
            bytes_received=256,
        )
    )
    app.state.active_dns_inventory_resolver = fake_resolver
    app.state.active_dns_inventory_axfr_transport = fake_axfr
    payload = make_active_dns_inventory_payload(
        include_subdomain_discovery=False,
        attempt_zone_transfer=True,
        zone_transfer_authorized_confirmed=True,
    )
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post("/active/network/dns-inventory", json=payload)

    assert response.status_code == 202
    payload = response.json()
    assert payload["error"] == "partial_inventory"
    result = payload["result"]
    assert result["coverage_level"] == "partial_inventory"
    assert result["zone_transfer"]["status"] == "malformed_response"
    assert result["zone_transfer"]["reason_code"] == "zone_transfer_missing_terminal_soa"
    assert {"code": "zone_transfer_missing_terminal_soa", "record_type": "AXFR", "purpose": "authorized_zone_transfer"} in result["errors"]
    assert "hostmaster.example.com" not in response.text
    assert "192.0.2.10" not in response.text


@pytest.mark.anyio
async def test_active_dns_inventory_zone_transfer_success_is_complete_and_redacted(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_ACTIVE_DNS_INVENTORY_ENABLED", "true")
    configure_test_state(monkeypatch, tmp_path)
    fake_resolver = make_active_dns_inventory_fake_resolver()
    axfr_records = [
        dns_record("example.com", "SOA", "mname=ns1.example.net;rname=hostmaster.example.com;serial=1"),
        dns_record("example.com", "A", "192.0.2.10"),
        dns_record("www.example.com", "A", "192.0.2.20"),
        dns_record("example.com", "MX", "mail.example.com", priority=10),
        dns_record("example.com", "TXT", "token_should_never_render"),
        dns_record("example.com", "SOA", "mname=ns1.example.net;rname=hostmaster.example.com;serial=1"),
    ]
    fake_axfr = FakeActiveDnsInventoryAxfrTransport(
        ActiveDnsInventoryZoneTransferResult(
            status="zone_transfer_complete",
            records=tuple(axfr_records),
            records_received_count=len(axfr_records),
            records_retained_count=len(axfr_records),
            bytes_received=512,
        )
    )
    app.state.active_dns_inventory_resolver = fake_resolver
    app.state.active_dns_inventory_axfr_transport = fake_axfr
    payload = make_active_dns_inventory_payload(
        include_subdomain_discovery=False,
        attempt_zone_transfer=True,
        zone_transfer_authorized_confirmed=True,
    )
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post("/active/network/dns-inventory", json=payload)
        job_id = response.json()["id"]
        jobs_response = await client.get("/jobs")
        detail_response = await client.get(f"/jobs/{job_id}")
        export_responses = {
            report_format: await client.get(f"/jobs/{job_id}/export/{report_format}")
            for report_format in ("markdown", "html", "xml", "pdf")
        }

    assert response.status_code == 202
    assert detail_response.status_code == 200
    assert all(export_response.status_code == 200 for export_response in export_responses.values())
    payload = response.json()
    result = payload["result"]
    assert payload["status"] == "completed"
    assert payload["error"] is None
    assert result["status"] == "zone_transfer_complete"
    assert result["result_status"] == "zone_transfer_complete"
    assert result["coverage_level"] == "zone_transfer_complete"
    assert result["zone_transfer"]["attempted"] is True
    assert result["zone_transfer"]["status"] == "zone_transfer_complete"
    assert result["zone_transfer"]["records_received_count"] == len(axfr_records)
    assert result["zone_transfer"]["records_retained_count"] == len(axfr_records)
    assert result["zone_transfer"]["truncated"] is False
    assert result["limits"]["max_txt_value_length"] == 512
    assert result["records"]["A"]["count"] == 2
    assert result["records"]["MX"]["sample"][0]["priority"] == 10
    assert jobs_response.json()[0]["summary"]["coverage_level"] == "zone_transfer_complete"
    assert jobs_response.json()[0]["summary"]["zone_transfer_status"] == "zone_transfer_complete"
    assert detail_response.json()["result"]["zone_transfer"]["interpretation"] == "zone transfer accepted by authoritative server / high-risk configuration review indicator"
    combined = json.dumps({"create": payload, "detail": detail_response.json(), "list": jobs_response.json()}, sort_keys=True)
    combined += "\n" + "\n".join(
        export.text if report_format != "pdf" else export.content.decode("latin1", errors="ignore")
        for report_format, export in export_responses.items()
    )
    assert "zone transfer accepted by authoritative server / high-risk configuration review indicator" in combined
    assert "[REDACTED_DOMAIN]" in combined
    assert "[REDACTED_DNS_VALUE]" in combined
    for forbidden in (
        "example.com",
        "www.example.com",
        "ns1.example.net",
        "hostmaster.example.com",
        "mail.example.com",
        "192.0.2.10",
        "192.0.2.20",
        "token_should_never_render",
        "raw_zone",
        "raw_dns_packet",
    ):
        assert forbidden not in combined


@pytest.mark.anyio
async def test_active_dns_inventory_zone_transfer_record_limit_is_partial(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_ACTIVE_DNS_INVENTORY_ENABLED", "true")
    configure_test_state(monkeypatch, tmp_path)
    fake_resolver = make_active_dns_inventory_fake_resolver()
    axfr_records = [
        dns_record("example.com", "A", f"192.0.2.{index % 250}", ttl=300)
        for index in range(105)
    ]
    fake_axfr = FakeActiveDnsInventoryAxfrTransport(
        ActiveDnsInventoryZoneTransferResult(
            status="zone_transfer_complete",
            records=tuple(axfr_records),
            records_received_count=len(axfr_records),
            records_retained_count=len(axfr_records),
            bytes_received=2048,
        )
    )
    app.state.active_dns_inventory_resolver = fake_resolver
    app.state.active_dns_inventory_axfr_transport = fake_axfr
    payload = make_active_dns_inventory_payload(
        include_subdomain_discovery=False,
        attempt_zone_transfer=True,
        zone_transfer_authorized_confirmed=True,
    )
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post("/active/network/dns-inventory", json=payload)

    assert response.status_code == 202
    result = response.json()["result"]
    assert result["coverage_level"] == "partial_inventory"
    assert result["zone_transfer"]["status"] == "record_limit_exceeded"
    assert result["zone_transfer"]["truncated"] is True
    assert result["zone_transfer"]["records_received_count"] == 105
    assert result["zone_transfer"]["records_retained_count"] == 100
    assert {"code": "record_limit_exceeded", "record_type": "AXFR", "purpose": "authorized_zone_transfer"} in result["errors"]
    assert "192.0.2." not in response.text


@pytest.mark.anyio
@pytest.mark.parametrize(
    "field_name",
    [
        "resolver_override",
        "resolver",
        "nameserver",
        "provider_credentials",
        "provider_api_token",
        "api_token",
        "ct_source",
        "passive_dns_source",
        "wordlist",
        "axfr_server_override",
        "shell_command",
        "command",
        "headers",
        "cookies",
        "tokens",
        "credentials",
        "target_file",
    ],
)
async def test_active_dns_inventory_rejects_dangerous_extra_fields_without_job(monkeypatch, tmp_path, field_name):
    monkeypatch.setenv("INSPECTRA_ACTIVE_DNS_INVENTORY_ENABLED", "true")
    configure_test_state(monkeypatch, tmp_path)
    fake_resolver = make_active_dns_inventory_fake_resolver()
    app.state.active_dns_inventory_resolver = fake_resolver
    payload = make_active_dns_inventory_payload(**{field_name: "token_should_never_render"})
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post("/active/network/dns-inventory", json=payload)
        jobs_response = await client.get("/jobs")

    assert response.status_code == 400
    assert response.json()["detail"] == "Unsupported active_dns_inventory request field."
    assert "token_should_never_render" not in response.text
    assert jobs_response.json() == []
    assert fake_resolver.calls == []


@pytest.mark.anyio
async def test_active_dns_inventory_error_output_does_not_reflect_domain_or_payload(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_ACTIVE_DNS_INVENTORY_ENABLED", "true")
    configure_test_state(monkeypatch, tmp_path)
    fake_resolver = make_active_dns_inventory_fake_resolver()
    app.state.active_dns_inventory_resolver = fake_resolver
    payload = make_active_dns_inventory_payload(
        domain="secret.example.com/path?token=token_should_never_render",
    )
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post("/active/network/dns-inventory", json=payload)

    assert response.status_code == 400
    assert "secret.example.com" not in response.text
    assert "token_should_never_render" not in response.text
    assert fake_resolver.calls == []


@pytest.mark.anyio
async def test_active_dns_inventory_auth_required_anonymous_fails_before_validation(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_AUTH_MODE", "self_hosted_single_admin")
    monkeypatch.setenv("INSPECTRA_ACTIVE_DNS_INVENTORY_ENABLED", "true")
    configure_test_state(monkeypatch, tmp_path)
    fake_resolver = make_active_dns_inventory_fake_resolver()
    app.state.active_dns_inventory_resolver = fake_resolver
    payload = make_active_dns_inventory_payload(resolver_override="token_should_never_render")
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post("/active/network/dns-inventory", json=payload)

    assert response.status_code == 401
    assert response.json() == {"detail": AUTH_REQUIRED_DETAIL}
    assert "Unsupported active_dns_inventory request field" not in response.text
    assert "token_should_never_render" not in response.text
    assert app.state.jobs.list() == []
    assert fake_resolver.calls == []


@pytest.mark.anyio
async def test_active_dns_inventory_wrong_owner_cannot_read_detail_delete_or_exports(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    wrong_owner_job = app.state.jobs.create_active_dns_inventory_job(
        {
            "audit_type": "active_dns_inventory",
            "capability": "active_dns_inventory",
            "status": "best_effort_inventory",
            "result_status": "best_effort_inventory",
            "coverage_level": "best_effort_inventory",
            "domain": "[REDACTED_DOMAIN]",
            "records": {},
            "security_records": {},
            "subdomains": {"enabled": False, "count": 0},
            "manual_validation_required": True,
            "result_interpretation": "DNS configuration review indicator",
        },
        status="completed",
        owner_id="other-owner",
    )
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        detail_response = await client.get(f"/jobs/{wrong_owner_job.id}")
        delete_response = await client.delete(f"/jobs/{wrong_owner_job.id}")
        export_responses = [
            await client.get(f"/jobs/{wrong_owner_job.id}/export/{report_format}")
            for report_format in ("markdown", "html", "xml", "pdf")
        ]

    assert detail_response.status_code == 404
    assert delete_response.status_code == 404
    assert all(response.status_code == 404 for response in export_responses)
    assert all(response.json()["detail"] == "Job not found." for response in [detail_response, delete_response, *export_responses])


@pytest.mark.anyio
async def test_active_dns_inventory_legacy_raw_payload_is_redacted_in_detail_list_and_exports(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    job = app.state.jobs.create_active_dns_inventory_job(
        {
            "audit_type": "active_dns_inventory",
            "capability": "active_dns_inventory",
            "mode": "live_dns_inventory",
            "profile": "dns_inventory_authorized",
            "status": "best_effort_inventory",
            "result_status": "best_effort_inventory",
            "coverage_level": "best_effort_inventory",
            "domain": "secret.example.com",
            "raw_domain": "secret.example.com",
            "records": {
                "A": {
                    "count": 1,
                    "sample": [{"name": "secret.example.com", "type": "A", "value": "192.0.2.55", "ttl": 300}],
                },
                "TXT": {
                    "count": 1,
                    "sample": [{"name": "secret.example.com", "type": "TXT", "value": "token_should_never_render", "ttl": 300}],
                },
            },
            "security_records": {
                "spf": {"checked": True, "present": True, "record_value": "v=spf1 include:_spf.example.net -all"},
                "dmarc": {"checked": True, "present": True, "record_value": "v=DMARC1; p=reject"},
                "caa": {"checked": True, "present": True, "record_count": 1, "raw_value": "issue ca.example.net"},
            },
            "subdomains": {
                "enabled": True,
                "strategy": "fixed_candidate_allowlist",
                "candidates_checked": 12,
                "query_record_types": ["A", "AAAA", "CNAME"],
                "count": 1,
                "sample": [{"name": "admin.secret.example.com", "record_types": ["A"], "record_count": 1}],
            },
            "raw_dns_packet": "token_should_never_render",
            "raw_resolver_log": "secret.example.com 192.0.2.55 token_should_never_render",
            "provider_api_token": "token_should_never_render",
            "credentials": {"password": "token_should_never_render"},
            "execution": {"dns_queries_sent": 9, "subdomain_queries_sent": 0, "subprocess_invoked": False, "nmap_invoked": False},
            "limits": {"domain_value_persisted": False, "dns_packets_persisted": False, "resolver_logs_persisted": False},
            "manual_validation_required": True,
            "result_interpretation": "DNS configuration review indicator",
        },
        status="completed",
        error="legacy error for secret.example.com token_should_never_render",
        owner_id=DEFAULT_LOCAL_OPERATOR.id,
    )
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        list_response = await client.get("/jobs")
        detail_response = await client.get(f"/jobs/{job.id}")
        export_responses = {
            report_format: await client.get(f"/jobs/{job.id}/export/{report_format}")
            for report_format in ("markdown", "html", "xml", "pdf")
        }

    assert list_response.status_code == 200
    assert detail_response.status_code == 200
    assert all(response.status_code == 200 for response in export_responses.values())
    combined = json.dumps({"list": list_response.json(), "detail": detail_response.json()}, sort_keys=True)
    combined += "\n" + "\n".join(
        response.text if report_format != "pdf" else response.content.decode("latin1", errors="ignore")
        for report_format, response in export_responses.items()
    )
    assert "[REDACTED_DOMAIN]" in combined
    assert "[REDACTED_DNS_VALUE]" in combined
    assert "DNS configuration review indicator" in combined
    for forbidden in (
        "secret.example.com",
        "admin.secret.example.com",
        "192.0.2.55",
        "_spf.example.net",
        "ca.example.net",
        "token_should_never_render",
        "raw_dns_packet",
        "raw_resolver_log",
        "provider_api_token",
        "password",
    ):
        assert forbidden not in combined


def test_active_dns_inventory_backend_source_has_dns_runtime_only_in_dedicated_module():
    main_source = Path("backend/app/main.py").read_text()
    dns_module_source = Path("backend/app/active_dns_inventory.py").read_text()
    route_source = main_source[
        main_source.find('@app.post("/active/network/dns-inventory"') : main_source.find('@app.post("/audits/web/basic"')
    ]

    forbidden = [
        "import subprocess",
        "subprocess.",
        "os.system(",
        "Popen(",
        "shell=True",
        "dig ",
        "nslookup",
        "host ",
        "nmap ",
        "docker ",
        "httpx.",
        "requests.",
        "archive/run-all",
        "tools/runner/main.py",
        "background_tasks",
    ]
    for token in forbidden:
        assert token not in dns_module_source
        assert token not in route_source
    assert "socket" in dns_module_source
    assert "socket" not in route_source
    assert "ACTIVE_DNS_INVENTORY_MAX_NAMESERVERS = 1" in dns_module_source
    assert "create_active_dns_inventory_job" in route_source
    assert "dns_queries_sent" in dns_module_source


def test_active_tls_basic_backend_source_has_no_tls_socket_or_runner_integration():
    main_source = Path("backend/app/main.py").read_text()
    config_source = Path("backend/app/config.py").read_text()
    tls_module_source = Path("backend/app/active_tls_basic.py").read_text()
    route_source = main_source[
        main_source.find('@app.post("/active/network/tls-basic"') : main_source.find('@app.post("/audits/web/basic"')
    ]
    tls_config_lines = "\n".join(line for line in config_source.splitlines() if "ACTIVE_TLS_BASIC" in line or "active_tls_basic" in line)
    combined = route_source + tls_config_lines

    forbidden = [
        "openssl",
        "OpenSSL",
        "subprocess",
        "os.system",
        "shell=True",
        "docker",
        "archive/run-all",
        "tools/runner/main.py",
    ]
    for token in forbidden:
        assert token not in combined
        assert token not in tls_module_source
    assert "import socket" in tls_module_source
    assert "import ssl" in tls_module_source
    assert "subprocess" not in tls_module_source
    assert "requests." not in tls_module_source
    assert "httpx" not in tls_module_source
    assert "nmap" not in tls_module_source.lower()


@pytest.mark.anyio
async def test_active_network_dry_run_disabled_by_default_no_job(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)
    payload = make_active_dry_run_payload("https://example.test/?token=token_should_never_render")

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post("/active/network/dry-run", json=payload)
        jobs_response = await client.get("/jobs")

    assert response.status_code == 403
    assert response.json()["detail"] == "Active dry-run checks are disabled in this environment."
    assert "token_should_never_render" not in response.text
    assert jobs_response.json() == []


@pytest.mark.anyio
async def test_active_network_dry_run_enabled_creates_target_job_and_summary(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_ACTIVE_DRY_RUN_ENABLED", "true")
    configure_test_state(monkeypatch, tmp_path)
    original_runner = audit_services.run_active_network_dry_run
    calls = []

    def capturing_runner(active_request):
        calls.append(active_request)
        return original_runner(active_request)

    monkeypatch.setattr(audit_services, "run_active_network_dry_run", capturing_runner)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        create_response = await client.post("/active/network/dry-run", json=make_active_dry_run_payload())
        job_id = create_response.json()["id"]
        job_response = await client.get(f"/jobs/{job_id}")
        jobs_response = await client.get("/jobs")

    assert create_response.status_code == 202
    assert create_response.json()["audit_type"] == "active_network_dry_run"
    assert create_response.json()["file_id"] is None
    assert len(calls) == 1

    public_job = job_response.json()
    assert public_job["status"] == "completed"
    assert public_job["result"]["analyzer"] == "active_network_dry_run"
    assert public_job["result"]["summary"]["network_requests_sent"] == 0
    assert public_job["result"]["authorization"]["confirmed"] is True
    assert public_job["result"]["authorization"]["scope"] == "single-target"
    assert public_job["result"]["policy"]["allowed"] is True
    assert public_job["result"]["planned_checks"][0]["would_contact_target"] is False
    assert public_job["result"]["planned_checks"][0]["network_disabled"] is True

    summary = next(item for item in jobs_response.json() if item["id"] == job_id)["summary"]
    assert summary["analyzer"] == "active_network_dry_run"
    assert summary["target_display"] == "https://example.test/path?ok=value"
    assert summary["mode"] == "dry_run"
    assert summary["profile"] == "http_header_probe_preview"
    assert summary["allowed"] is True
    assert summary["planned_checks_count"] == 1
    assert summary["blocked_reasons_count"] == 0
    assert summary["network_requests_sent"] == 0
    assert summary["blocked_reason_codes"] == []
    assert summary["policy_version"] == "active-network-v0-dry-run"


@pytest.mark.anyio
async def test_active_network_dry_run_private_ip_completes_blocked(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_ACTIVE_DRY_RUN_ENABLED", "true")
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        create_response = await client.post("/active/network/dry-run", json=make_active_dry_run_payload("10.0.0.1"))
        job_id = create_response.json()["id"]
        job_response = await client.get(f"/jobs/{job_id}")

    result = job_response.json()["result"]
    assert job_response.json()["status"] == "completed"
    assert result["policy"]["allowed"] is False
    assert result["summary"]["network_requests_sent"] == 0
    assert result["planned_checks"] == []
    assert "private_range_blocked" in {reason["code"] for reason in result["blocked_reasons"]}


@pytest.mark.anyio
async def test_active_network_dry_run_policy_validation_blocks_without_network(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_ACTIVE_DRY_RUN_ENABLED", "true")
    configure_test_state(monkeypatch, tmp_path)
    cases = [
        (make_active_dry_run_payload(authorization={"confirmed": False}), "authorization_missing"),
        (make_active_dry_run_payload(mode="live"), "live_mode_not_available"),
        (make_active_dry_run_payload(profile="nmap_plan"), "nmap_not_allowed"),
        (
            make_active_dry_run_payload(
                limits={"max_requests": 1, "timeout_seconds": 0, "max_redirects": 0, "response_size_bytes": 0}
            ),
            "limits_exceed_dry_run",
        ),
    ]
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        for payload, reason_code in cases:
            create_response = await client.post("/active/network/dry-run", json=payload)
            job_response = await client.get(f"/jobs/{create_response.json()['id']}")
            result = job_response.json()["result"]

            assert create_response.status_code == 202
            assert job_response.json()["status"] == "completed"
            assert result["policy"]["allowed"] is False
            assert result["summary"]["network_requests_sent"] == 0
            assert reason_code in {reason["code"] for reason in result["blocked_reasons"]}


@pytest.mark.anyio
async def test_active_network_dry_run_rejects_unknown_fields_without_job(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_ACTIVE_DRY_RUN_ENABLED", "true")
    configure_test_state(monkeypatch, tmp_path)
    payload = make_active_dry_run_payload()
    payload["unexpected"] = "token_should_never_render"
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post("/active/network/dry-run", json=payload)
        jobs_response = await client.get("/jobs")

    assert response.status_code == 400
    assert "Unknown request field" in response.json()["detail"]
    assert "token_should_never_render" not in response.text
    assert jobs_response.json() == []


@pytest.mark.anyio
async def test_active_network_dry_run_url_credentials_redacted(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_ACTIVE_DRY_RUN_ENABLED", "true")
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        create_response = await client.post("/active/network/dry-run", json=make_active_dry_run_payload("http://user:pass@example.com"))
        job_id = create_response.json()["id"]
        job_response = await client.get(f"/jobs/{job_id}")
        jobs_response = await client.get("/jobs")
        exports = {
            report_format: await client.get(f"/jobs/{job_id}/export/{report_format}")
            for report_format in ("markdown", "html", "xml", "pdf")
        }

    combined = json.dumps({"create": create_response.json(), "job": job_response.json(), "jobs": jobs_response.json()}, sort_keys=True)
    combined += "\n" + "\n".join(
        response.text if report_format != "pdf" else response.content.decode("latin1", errors="ignore")
        for report_format, response in exports.items()
    )
    assert "http://user:pass@example.com" not in combined
    assert "user:pass" not in combined
    assert "[REDACTED]" in combined
    result = job_response.json()["result"]
    assert result["policy"]["allowed"] is False
    assert "url_credentials_rejected" in {reason["code"] for reason in result["blocked_reasons"]}
    summary = next(item for item in jobs_response.json() if item["id"] == job_id)["summary"]
    assert "user:pass" not in json.dumps(summary)


@pytest.mark.anyio
async def test_active_network_dry_run_exports_render_sections_and_redact(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_ACTIVE_DRY_RUN_ENABLED", "true")
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        create_response = await client.post(
            "/active/network/dry-run",
            json=make_active_dry_run_payload("https://example.test/?token=token_should_never_render"),
        )
        job_id = create_response.json()["id"]
        job_response = await client.get(f"/jobs/{job_id}")
        jobs_response = await client.get("/jobs")
        responses = {
            report_format: await client.get(f"/jobs/{job_id}/export/{report_format}")
            for report_format in ("markdown", "html", "xml", "pdf")
        }

    for response in responses.values():
        assert response.status_code == 200

    combined = "\n".join(
        response.text if report_format != "pdf" else response.content.decode("latin1", errors="ignore")
        for report_format, response in responses.items()
    )
    combined += "\n" + json.dumps({"job": job_response.json(), "jobs": jobs_response.json()}, sort_keys=True)
    assert "No network traffic was sent" in combined
    assert "This dry run records planned checks after authorization and target validation" in combined
    assert "Do not scan third-party systems without permission" in combined
    assert "Planned Checks" in combined
    assert "Blocked Reasons" in combined
    assert "token_should_never_render" not in combined
    assert "vulnerability confirmed" not in combined.lower()
    assert "target is safe" not in combined.lower()
    assert "credential valid" not in combined.lower()
    assert "bypass" not in combined.lower()
    assert "evade" not in combined.lower()
    assert ElementTree.fromstring(responses["xml"].text).findtext("./job/auditType") == "active_network_dry_run"
    assert responses["pdf"].content.startswith(b"%PDF")


@pytest.mark.anyio
async def test_active_network_dry_run_legacy_payload_redacted_in_api_and_exports(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    now = datetime.now(timezone.utc)
    job = JobRecord(
        id="a" * 31 + "1",
        audit_type="active_network_dry_run",
        file_id=None,
        target_url="http://user:pass@example.com/?token=token_should_never_render",
        status="completed",
        created_at=now,
        updated_at=now,
        result={
            "analyzer": "active_network_dry_run",
            "mode": "dry_run",
            "profile": "http_header_probe_preview",
            "target": {"raw": "http://user:pass@example.com/?token=token_should_never_render", "normalized": None},
            "authorization": {"confirmed": True, "statement": "Authorization: Bearer token_should_never_render"},
            "policy": {"allowed": False, "policy_version": "active-network-v0-dry-run"},
            "limits": {"max_requests": 0},
            "planned_checks": [{"url": "http://user:pass@example.com/?password=super-secret-password"}],
            "blocked_reasons": [{"code": "url_credentials_rejected", "message": "Authorization: Bearer token_should_never_render"}],
            "audit_log": [{"details": {"secret": "super-secret-password"}}],
            "errors": ["-----BEGIN PRIVATE KEY----- secret material -----END PRIVATE KEY-----"],
            "summary": {"allowed": False, "planned_checks_count": 1, "blocked_reasons_count": 1, "network_requests_sent": 0},
        },
        error="PRIVATE KEY token_should_never_render",
    )
    app.state.jobs.save(job)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        api_response = await client.get(f"/jobs/{job.id}")
        jobs_response = await client.get("/jobs")
        exports = {
            report_format: await client.get(f"/jobs/{job.id}/export/{report_format}")
            for report_format in ("markdown", "html", "xml", "pdf")
        }

    combined = json.dumps({"api": api_response.json(), "jobs": jobs_response.json()}, sort_keys=True)
    combined += "\n" + "\n".join(
        response.text if report_format != "pdf" else response.content.decode("latin1", errors="ignore")
        for report_format, response in exports.items()
    )
    for secret in (
        "http://user:pass@example.com",
        "user:pass",
        "token_should_never_render",
        "Authorization: Bearer token_should_never_render",
        "PRIVATE KEY",
        "super-secret-password",
    ):
        assert secret not in combined
    assert "[REDACTED]" in combined
    summary = next(item for item in jobs_response.json() if item["id"] == job.id)["summary"]
    assert summary["network_requests_sent"] == 0
    assert summary["blocked_reason_codes"] == ["url_credentials_rejected"]


@pytest.mark.anyio
async def test_active_network_dry_run_sparse_jobs_export_without_breaking(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    now = datetime.now(timezone.utc)
    jobs = [
        JobRecord(id="b" * 31 + "1", audit_type="active_network_dry_run", status="queued", created_at=now, updated_at=now),
        JobRecord(id="b" * 31 + "2", audit_type="active_network_dry_run", status="running", created_at=now, updated_at=now),
        JobRecord(id="b" * 31 + "3", audit_type="active_network_dry_run", status="failed", created_at=now, updated_at=now, error="token_should_never_render"),
        JobRecord(
            id="b" * 31 + "4",
            audit_type="active_network_dry_run",
            status="completed",
            created_at=now,
            updated_at=now,
            result={"analyzer": "active_network_dry_run", "summary": None, "target": "malformed", "policy": None},
        ),
    ]
    for job in jobs:
        app.state.jobs.save(job)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        for job in jobs:
            job_response = await client.get(f"/jobs/{job.id}")
            assert job_response.status_code == 200
            for report_format in ("markdown", "html", "xml", "pdf"):
                response = await client.get(f"/jobs/{job.id}/export/{report_format}")
                assert response.status_code == 200
                body = response.text if report_format != "pdf" else response.content.decode("latin1", errors="ignore")
                assert "token_should_never_render" not in body


@pytest.mark.anyio
async def test_active_http_header_probe_disabled_by_default_no_job(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)
    payload = make_active_http_header_probe_payload("https://example.test/?token=token_should_never_render")

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post("/active/network/http-header-probe", json=payload)
        jobs_response = await client.get("/jobs")

    assert response.status_code == 403
    assert response.json()["detail"] == "Active HTTP header probe is disabled in this environment."
    assert "token_should_never_render" not in response.text
    assert jobs_response.json() == []


@pytest.mark.anyio
async def test_active_http_header_probe_flag_is_independent_from_dry_run(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_ACTIVE_HTTP_HEADER_PROBE_ENABLED", "true")
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        dry_run_response = await client.post("/active/network/dry-run", json=make_active_dry_run_payload())
        header_response = await client.post(
            "/active/network/http-header-probe",
            json=make_active_http_header_probe_payload("http://10.0.0.1/"),
        )
        header_job = await client.get(f"/jobs/{header_response.json()['id']}")
        jobs_response = await client.get("/jobs")

    assert dry_run_response.status_code == 403
    assert dry_run_response.json()["detail"] == "Active dry-run checks are disabled in this environment."
    assert header_response.status_code == 202
    assert header_job.json()["result"]["summary"]["network_requests_sent"] == 0
    assert "private_range_blocked" in {reason["code"] for reason in header_job.json()["result"]["blocked_reasons"]}
    assert [job["audit_type"] for job in jobs_response.json()] == ["active_http_header_probe"]


@pytest.mark.anyio
async def test_active_http_header_probe_enabled_creates_job_and_summary(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_ACTIVE_HTTP_HEADER_PROBE_ENABLED", "true")
    configure_test_state(monkeypatch, tmp_path)
    calls = []

    def fake_runner(active_request):
        calls.append(active_request)
        return {
            "analyzer": "active_http_header_probe",
            "mode": "live_header_probe",
            "profile": "http_header_probe",
            "target": {
                "raw": active_request.target,
                "normalized": "https://example.test/path?ok=value",
                "scheme": "https",
                "host": "example.test",
                "port": 443,
                "classification": "public_hostname",
            },
            "authorization": {
                "confirmed": True,
                "live_traffic_confirmed": True,
                "statement_version": "active-authorization-v1",
                "live_statement_version": "active-live-head-v1",
                "scope": "single-target",
            },
            "policy": {
                "allowed": True,
                "policy_version": "active-network-v1-http-header-probe",
                "blocked_reasons": [],
                "warnings": [],
            },
            "limits": active_request.limits.to_result(),
            "dns": {"resolved": True, "answers_count": 1, "all_answers_allowed": True, "blocked_answers_count": 0},
            "request": {
                "method": "HEAD",
                "url": "https://example.test/path?ok=value",
                "headers_sent": {"User-Agent": "Inspectra active-header-probe", "Accept": "*/*"},
                "body_sent": False,
            },
            "response": {
                "status_code": 200,
                "headers": [
                    {"name": "Server", "value": "example"},
                    {"name": "Set-Cookie", "value": "[REDACTED]"},
                    {"name": "Authorization", "value": "[REDACTED]"},
                ],
                "headers_bytes": 64,
                "body_read": False,
                "body_bytes_read": 0,
                "redirect_presented": False,
                "redirect_followed": False,
            },
            "observations": [{"code": "server_header_present_info", "title": "Server header present", "level": "info"}],
            "findings": [],
            "blocked_reasons": [],
            "audit_log": [{"event": "http_head_request_completed"}],
            "errors": [],
            "summary": {
                "allowed": True,
                "network_requests_sent": 1,
                "redirects_followed": 0,
                "body_bytes_read": 0,
                "headers_received_count": 3,
                "redacted_headers_count": 2,
                "truncated_headers_count": 0,
            },
        }

    monkeypatch.setattr(audit_services, "run_authorized_http_header_probe", fake_runner)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        create_response = await client.post("/active/network/http-header-probe", json=make_active_http_header_probe_payload())
        job_id = create_response.json()["id"]
        job_response = await client.get(f"/jobs/{job_id}")
        jobs_response = await client.get("/jobs")

    assert create_response.status_code == 202
    assert create_response.json()["audit_type"] == "active_http_header_probe"
    assert create_response.json()["file_id"] is None
    assert len(calls) == 1
    assert calls[0].mode == "live_header_probe"
    assert calls[0].profile == "http_header_probe"
    public_job = job_response.json()
    assert public_job["status"] == "completed"
    assert public_job["result"]["analyzer"] == "active_http_header_probe"
    assert public_job["result"]["summary"]["network_requests_sent"] == 1
    assert public_job["result"]["response"]["body_read"] is False
    assert public_job["result"]["response"]["body_bytes_read"] == 0
    assert public_job["result"]["response"]["headers"][1]["value"] == "[REDACTED]"
    summary = next(item for item in jobs_response.json() if item["id"] == job_id)["summary"]
    assert summary["analyzer"] == "active_http_header_probe"
    assert summary["target_display"] == "https://example.test/path?ok=value"
    assert summary["mode"] == "live_header_probe"
    assert summary["profile"] == "http_header_probe"
    assert summary["allowed"] is True
    assert summary["network_requests_sent"] == 1
    assert summary["redirects_followed"] == 0
    assert summary["body_bytes_read"] == 0
    assert summary["headers_received_count"] == 3
    assert summary["redacted_headers_count"] == 2
    assert summary["policy_version"] == "active-network-v1-http-header-probe"


@pytest.mark.anyio
async def test_active_http_header_probe_policy_blocks_before_http(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_ACTIVE_HTTP_HEADER_PROBE_ENABLED", "true")
    configure_test_state(monkeypatch, tmp_path)
    cases = [
        (make_active_http_header_probe_payload("http://user:pass@example.com"), "url_credentials_rejected"),
        (make_active_http_header_probe_payload("http://10.0.0.1/"), "private_range_blocked"),
        (make_active_http_header_probe_payload("example.test"), "live_url_required"),
        (make_active_http_header_probe_payload(profile="nmap_plan"), "nmap_not_allowed"),
    ]
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        for payload, reason_code in cases:
            create_response = await client.post("/active/network/http-header-probe", json=payload)
            job_response = await client.get(f"/jobs/{create_response.json()['id']}")
            result = job_response.json()["result"]

            assert create_response.status_code == 202
            assert job_response.json()["status"] == "completed"
            assert result["policy"]["allowed"] is False
            assert result["summary"]["network_requests_sent"] == 0
            assert reason_code in {reason["code"] for reason in result["blocked_reasons"]}


@pytest.mark.anyio
async def test_active_http_header_probe_rejects_unknown_fields_without_job(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_ACTIVE_HTTP_HEADER_PROBE_ENABLED", "true")
    configure_test_state(monkeypatch, tmp_path)
    payload = make_active_http_header_probe_payload()
    payload["unexpected"] = "token_should_never_render"
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post("/active/network/http-header-probe", json=payload)
        jobs_response = await client.get("/jobs")

    assert response.status_code == 400
    assert "Unknown request field" in response.json()["detail"]
    assert "token_should_never_render" not in response.text
    assert jobs_response.json() == []


@pytest.mark.anyio
async def test_active_http_header_probe_exports_render_sections_and_redact(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_ACTIVE_HTTP_HEADER_PROBE_ENABLED", "true")
    configure_test_state(monkeypatch, tmp_path)

    def fake_runner(active_request):
        return {
            "analyzer": "active_http_header_probe",
            "mode": "live_header_probe",
            "profile": "http_header_probe",
            "target": {
                "raw": active_request.target,
                "normalized": "https://example.test/path?token=token_should_never_render",
                "scheme": "https",
                "host": "example.test",
                "port": 443,
                "classification": "public_hostname",
            },
            "authorization": {
                "confirmed": True,
                "live_traffic_confirmed": True,
                "statement_version": "active-authorization-v1",
                "live_statement_version": "active-live-head-v1",
                "scope": "single-target",
            },
            "policy": {"allowed": True, "policy_version": "active-network-v1-http-header-probe", "blocked_reasons": []},
            "limits": active_request.limits.to_result(),
            "dns": {"resolved": True, "answers_count": 1, "all_answers_allowed": True, "blocked_answers_count": 0},
            "request": {"method": "HEAD", "url": active_request.target, "headers_sent": {"User-Agent": "Inspectra active-header-probe", "Accept": "*/*"}, "body_sent": False},
            "response": {
                "status_code": 302,
                "headers": [
                    {"name": "Location", "value": "https://example.test/callback?token=token_should_never_render"},
                    {"name": "Set-Cookie", "value": "sessionid=secret-session-cookie"},
                    {"name": "Authorization", "value": "Authorization: Bearer token_should_never_render"},
                ],
                "headers_bytes": 128,
                "body_read": False,
                "body_bytes_read": 0,
                "redirect_presented": True,
                "redirect_followed": False,
            },
            "observations": [{"code": "redirect_present_not_followed_info", "evidence": "Location token=token_should_never_render"}],
            "findings": [{"code": "header_observation", "evidence": "Authorization: Bearer token_should_never_render"}],
            "blocked_reasons": [],
            "audit_log": [{"details": {"Authorization": "Bearer token_should_never_render"}}],
            "errors": ["-----BEGIN PRIVATE KEY----- secret material -----END PRIVATE KEY-----"],
            "summary": {
                "allowed": True,
                "network_requests_sent": 1,
                "redirects_followed": 0,
                "body_bytes_read": 0,
                "headers_received_count": 3,
                "redacted_headers_count": 2,
                "truncated_headers_count": 0,
            },
        }

    monkeypatch.setattr(audit_services, "run_authorized_http_header_probe", fake_runner)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        create_response = await client.post(
            "/active/network/http-header-probe",
            json=make_active_http_header_probe_payload("https://example.test/path?token=token_should_never_render"),
        )
        job_id = create_response.json()["id"]
        job_response = await client.get(f"/jobs/{job_id}")
        jobs_response = await client.get("/jobs")
        responses = {
            report_format: await client.get(f"/jobs/{job_id}/export/{report_format}")
            for report_format in ("markdown", "html", "xml", "pdf")
        }

    for response in responses.values():
        assert response.status_code == 200

    combined = json.dumps({"job": job_response.json(), "jobs": jobs_response.json()}, sort_keys=True)
    combined += "\n" + "\n".join(
        response.text if report_format != "pdf" else response.content.decode("latin1", errors="ignore")
        for report_format, response in responses.items()
    )
    assert "One authorized HTTP HEAD request was sent" in combined
    assert "Response body was not read" in combined
    assert "DNS Policy Summary" in combined
    assert "Response Headers" in combined
    for forbidden_copy in (
        "vulnerability confirmed",
        "target is safe",
        "credential valid",
        "bypass",
        "evade",
        "live exploitability",
        "nmap scan",
    ):
        assert forbidden_copy not in combined.lower()
    for secret in (
        "token_should_never_render",
        "Authorization: Bearer token_should_never_render",
        "secret-session-cookie",
        "PRIVATE KEY",
    ):
        assert secret not in combined
    assert "[REDACTED]" in combined
    assert ElementTree.fromstring(responses["xml"].text).findtext("./job/auditType") == "active_http_header_probe"
    assert responses["pdf"].content.startswith(b"%PDF")


@pytest.mark.anyio
async def test_active_http_header_probe_legacy_payload_redacted_in_api_and_exports(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    now = datetime.now(timezone.utc)
    job = JobRecord(
        id="c" * 31 + "1",
        audit_type="active_http_header_probe",
        file_id=None,
        target_url="http://user:pass@example.com/?token=token_should_never_render",
        status="completed",
        created_at=now,
        updated_at=now,
        result={
            "analyzer": "active_http_header_probe",
            "mode": "live_header_probe",
            "profile": "http_header_probe",
            "target": {"raw": "http://user:pass@example.com/?token=token_should_never_render"},
            "authorization": {"confirmed": True, "live_traffic_confirmed": True, "statement": "Authorization: Bearer token_should_never_render"},
            "policy": {"allowed": False, "policy_version": "active-network-v1-http-header-probe"},
            "dns": {"answers": ["10.0.0.1"]},
            "request": {"url": "http://user:pass@example.com/?password=super-secret-password", "headers_sent": {"Authorization": "Bearer token_should_never_render"}},
            "response": {
                "headers": [
                    {"name": "Set-Cookie", "value": "sessionid=secret-session-cookie"},
                    {"name": "Authorization", "value": "Authorization: Bearer token_should_never_render"},
                ],
                "body": "body_should_not_render",
                "body_read": False,
            },
            "observations": [{"evidence": "token_should_never_render"}],
            "findings": [{"evidence": "http://user:pass@example.com/?api_key=raw-api-key-123456"}],
            "blocked_reasons": [{"code": "url_credentials_rejected", "message": "http://user:pass@example.com"}],
            "audit_log": [{"details": {"secret": "super-secret-password"}}],
            "errors": ["-----BEGIN PRIVATE KEY----- secret material -----END PRIVATE KEY-----"],
            "summary": {"allowed": False, "network_requests_sent": 0, "redirects_followed": 0, "body_bytes_read": 0},
        },
        error="PRIVATE KEY token_should_never_render",
    )
    app.state.jobs.save(job)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        api_response = await client.get(f"/jobs/{job.id}")
        jobs_response = await client.get("/jobs")
        exports = {
            report_format: await client.get(f"/jobs/{job.id}/export/{report_format}")
            for report_format in ("markdown", "html", "xml", "pdf")
        }

    combined = json.dumps({"api": api_response.json(), "jobs": jobs_response.json()}, sort_keys=True)
    combined += "\n" + "\n".join(
        response.text if report_format != "pdf" else response.content.decode("latin1", errors="ignore")
        for report_format, response in exports.items()
    )
    for secret in (
        "http://user:pass@example.com",
        "user:pass",
        "token_should_never_render",
        "Authorization: Bearer token_should_never_render",
        "sessionid=secret-session-cookie",
        "raw-api-key-123456",
        "PRIVATE KEY",
        "super-secret-password",
        "body_should_not_render",
    ):
        assert secret not in combined
    assert "[REDACTED]" in combined
    summary = next(item for item in jobs_response.json() if item["id"] == job.id)["summary"]
    assert summary["network_requests_sent"] == 0
    assert summary["blocked_reason_codes"] == ["url_credentials_rejected"]


@pytest.mark.anyio
async def test_active_http_header_probe_sparse_jobs_export_without_breaking(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    now = datetime.now(timezone.utc)
    jobs = [
        JobRecord(id="d" * 31 + "1", audit_type="active_http_header_probe", status="queued", created_at=now, updated_at=now),
        JobRecord(id="d" * 31 + "2", audit_type="active_http_header_probe", status="running", created_at=now, updated_at=now),
        JobRecord(id="d" * 31 + "3", audit_type="active_http_header_probe", status="failed", created_at=now, updated_at=now, error="token_should_never_render"),
        JobRecord(
            id="d" * 31 + "4",
            audit_type="active_http_header_probe",
            status="completed",
            created_at=now,
            updated_at=now,
            result={"analyzer": "active_http_header_probe", "summary": None, "target": "malformed", "policy": None},
        ),
    ]
    for job in jobs:
        app.state.jobs.save(job)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        for job in jobs:
            job_response = await client.get(f"/jobs/{job.id}")
            assert job_response.status_code == 200
            for report_format in ("markdown", "html", "xml", "pdf"):
                response = await client.get(f"/jobs/{job.id}/export/{report_format}")
                assert response.status_code == 200
                body = response.text if report_format != "pdf" else response.content.decode("latin1", errors="ignore")
                assert "token_should_never_render" not in body


@pytest.mark.anyio
async def test_active_nmap_basic_synthetic_payload_exports_render_and_redact(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    now = datetime.now(timezone.utc)
    job = JobRecord(
        id="e" * 31 + "1",
        audit_type="active_nmap_basic",
        file_id=None,
        target_url="192.168.56.10",
        status="completed",
        created_at=now,
        updated_at=now,
        result={
            "audit_type": "active_nmap_basic",
            "capability": "active_nmap_basic",
            "mode": "live_nmap_basic",
            "profile": "tcp_connect_small",
            "status": "completed",
            "target": {"raw": "192.168.56.10", "hostname": "secret-lab.internal"},
            "command": "nmap -sT -Pn -n -oX - -p 22,443 -- 192.168.56.10",
            "stdout": "stdout with 192.168.56.10 and <nmaprun><host><address addr='192.168.56.10'/></host></nmaprun>",
            "stderr": "stderr for secret-lab.internal Authorization: Bearer token_should_never_render",
            "raw_xml": "<nmaprun args='nmap -sT 192.168.56.10'><host><ports /></host></nmaprun>",
            "port_observations": [
                {"port": 443, "protocol": "tcp", "state": "open", "reason": "syn-ack"},
                {"port": 22, "protocol": "tcp", "state": "closed", "reason": "reset"},
            ],
            "observation_count": 2,
            "limits": {"output_truncated": False, "stderr_truncated": True, "timed_out": False},
            "legacy": {
                "service_banner": "OpenSSH_9.9 secret-service-banner",
                "notes": "confirmed vulnerability exploitable target is safe all ports found full network scan",
                "headers": {"Cookie": "sessionid=secret-session-cookie"},
            },
            "summary": {"observation_count": 2},
            "errors": ["nmap -sT 192.168.56.10 failed with token_should_never_render"],
        },
        error="nmap -sT 192.168.56.10 PRIVATE KEY token_should_never_render",
    )
    app.state.jobs.save(job)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        api_response = await client.get(f"/jobs/{job.id}")
        jobs_response = await client.get("/jobs")
        responses = {
            report_format: await client.get(f"/jobs/{job.id}/export/{report_format}")
            for report_format in ("markdown", "html", "xml", "pdf")
        }

    for report_format, response in responses.items():
        assert response.status_code == 200
        if report_format == "xml":
            assert ElementTree.fromstring(response.text).findtext("./job/auditType") == "active_nmap_basic"
        elif report_format == "pdf":
            assert response.content.startswith(b"%PDF")

    combined = json.dumps({"api": api_response.json(), "jobs": jobs_response.json()}, sort_keys=True)
    combined += "\n" + "\n".join(
        response.text if report_format != "pdf" else response.content.decode("latin1", errors="ignore")
        for report_format, response in responses.items()
    )
    assert "Observed TCP exposure" in combined
    assert "Review indicator" in combined
    assert "Manual validation required" in combined
    assert "No vulnerability confirmation is asserted" in combined
    assert "Observation 1 Port" in combined
    assert "443" in combined
    assert "active_nmap_basic" in combined
    summary = next(item for item in jobs_response.json() if item["id"] == job.id)["summary"]
    assert summary["capability"] == "active_nmap_basic"
    assert summary["profile"] == "tcp_connect_small"
    assert summary["result_status"] == "completed"
    assert summary["observation_count"] == 2
    assert summary["open_tcp_observations_count"] == 1
    assert summary["stderr_truncated"] is True
    assert api_response.json()["result"]["target"] == "[REDACTED]"
    assert api_response.json()["result"]["command"] == "[REDACTED]"

    for forbidden in (
        "192.168.56.10",
        "secret-lab.internal",
        "nmap -sT",
        "stdout with",
        "stderr for",
        "<nmaprun",
        "OpenSSH_9.9",
        "secret-service-banner",
        "token_should_never_render",
        "Authorization: Bearer token_should_never_render",
        "sessionid=secret-session-cookie",
        "PRIVATE KEY",
        "confirmed vulnerability",
        "exploitable",
        "target is safe",
        "all ports found",
        "full network scan",
    ):
        assert forbidden not in combined


@pytest.mark.anyio
async def test_active_nmap_basic_real_shape_backend_surfaces_redact_without_live_runtime(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    now = datetime.now(timezone.utc)
    rich_payload = {
        "audit_type": "active_nmap_basic",
        "capability": "active_nmap_basic",
        "mode": "live_nmap_basic",
        "profile": "tcp_connect_small",
        "status": "completed",
        "target_kind": "authorized_fqdn",
        "target_display": "authorized target",
        "manual_validation_required": True,
        "result_interpretation": "observed_exposure_review_indicator",
        "port_observations": [
            {
                "port": 443,
                "protocol": "tcp",
                "state": "open",
                "reason": "syn-ack",
                "manual_validation_required": True,
                "result_interpretation": "observed_exposure_review_indicator",
            }
        ],
        "observation_count": 1,
        "limits": {"output_truncated": False, "stderr_truncated": False, "timed_out": False},
        "summary": {"observation_count": 1},
        "raw_xml": "<nmaprun args='nmap -sT -p 443 authorized.example.test'><host /></nmaprun>",
        "stdout": "stdout includes 203.0.113.10 redacted-ptr.example.internal <nmaprun />",
        "stderr": "stderr includes redacted-ptr.example.internal token_should_never_render",
        "args": "raw args nmap -sT -p 443 authorized.example.test --script default",
        "command": "nmap -sT -Pn -oX - -p 443 -- authorized.example.test",
        "resolved_ip": "203.0.113.10",
        "ptr_hostname": "redacted-ptr.example.internal",
        "hostnames": ["authorized.example.test", "unexpected-alias.example.internal"],
        "service": "https-private-service-label",
        "banner": "SyntheticPrivateServer synthetic-banner",
        "version": "9.9.9",
        "stylesheet": "file:///usr/share/nmap/nmap.xsl",
        "script_output": "synthetic NSE-like output",
        "nse": {"id": "ssl-cert", "output": "synthetic NSE-like output"},
        "credentials": {"username": "operator", "password": "super-secret-password"},
        "headers": {"Authorization": "Bearer token_should_never_render"},
        "cookies": {"session": "secret-session-cookie"},
        "tokens": ["token_should_never_render"],
        "nested": {
            "resolved_ip": "203.0.113.10",
            "ptr_hostname": "redacted-ptr.example.internal",
            "notes": "203.0.113.10 redacted-ptr.example.internal synthetic NSE-like output",
        },
    }
    job = JobRecord(
        id="e" * 31 + "2",
        audit_type="active_nmap_basic",
        file_id=None,
        target_url="authorized.example.test",
        status="completed",
        created_at=now,
        updated_at=now,
        result=rich_payload,
        error="nmap -sT authorized.example.test 203.0.113.10 redacted-ptr.example.internal",
    )
    wrong_owner_job = JobRecord(
        id="e" * 31 + "3",
        owner_id="other-owner",
        audit_type="active_nmap_basic",
        file_id=None,
        target_url="redacted-ptr.example.internal",
        status="completed",
        created_at=now,
        updated_at=now,
        result=rich_payload,
        error="203.0.113.10 redacted-ptr.example.internal",
    )
    app.state.jobs.save(job)
    app.state.jobs.save(wrong_owner_job)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        api_response = await client.get(f"/jobs/{job.id}")
        jobs_response = await client.get("/jobs")
        exports = {
            report_format: await client.get(f"/jobs/{job.id}/export/{report_format}")
            for report_format in ("markdown", "html", "xml", "pdf")
        }
        wrong_detail_response = await client.get(f"/jobs/{wrong_owner_job.id}")
        wrong_export_responses = [
            await client.get(f"/jobs/{wrong_owner_job.id}/export/{report_format}")
            for report_format in ("markdown", "html", "xml", "pdf")
        ]

    assert api_response.status_code == 200
    assert all(response.status_code == 200 for response in exports.values())
    assert ElementTree.fromstring(exports["xml"].text).findtext("./job/auditType") == "active_nmap_basic"
    assert exports["pdf"].content.startswith(b"%PDF")
    assert wrong_detail_response.status_code == 404
    assert all(response.status_code == 404 for response in wrong_export_responses)
    assert wrong_owner_job.id not in json.dumps(jobs_response.json(), sort_keys=True)

    api_result = api_response.json()["result"]
    assert api_result["manual_validation_required"] is True
    assert api_result["result_interpretation"] == "observed_exposure_review_indicator"
    assert api_result["port_observations"] == rich_payload["port_observations"]
    for redacted_key in (
        "raw_xml",
        "stdout",
        "stderr",
        "args",
        "command",
        "resolved_ip",
        "ptr_hostname",
        "hostnames",
        "service",
        "banner",
        "version",
        "stylesheet",
        "script_output",
        "nse",
        "credentials",
        "headers",
        "cookies",
        "tokens",
    ):
        assert api_result[redacted_key] == "[REDACTED]"
    assert api_result["nested"]["resolved_ip"] == "[REDACTED]"
    assert api_result["nested"]["ptr_hostname"] == "[REDACTED]"

    combined = json.dumps({"api": api_response.json(), "jobs": jobs_response.json()}, sort_keys=True)
    combined += "\n" + "\n".join(
        response.text if report_format != "pdf" else response.content.decode("latin1", errors="ignore")
        for report_format, response in exports.items()
    )
    assert "Observed TCP exposure" in combined
    assert "Review indicator" in combined
    assert "Manual validation required" in combined
    assert "observed_exposure_review_indicator" in combined
    assert "manual_validation_required" in combined
    assert "443" in combined
    assert "open" in combined
    assert "syn-ack" in combined
    for forbidden in (
        "203.0.113.10",
        "redacted-ptr.example.internal",
        "unexpected-alias.example.internal",
        "authorized.example.test",
        "raw args",
        "nmap -sT",
        "<nmaprun",
        "stdout includes",
        "stderr includes",
        "https-private-service-label",
        "SyntheticPrivateServer",
        "synthetic-banner",
        "9.9.9",
        "file:///usr/share/nmap/nmap.xsl",
        "synthetic NSE-like output",
        "super-secret-password",
        "token_should_never_render",
        "secret-session-cookie",
        "confirmed vulnerability",
        "exploitable",
        "target is safe",
        "full scan",
        "all ports found",
    ):
        assert forbidden not in combined


@pytest.mark.anyio
async def test_active_nmap_basic_fake_execution_parser_payload_exports_no_live(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    fake_execution = {
        "status": "completed",
        "capability": "active_nmap_basic",
        "profile": "tcp_connect_small",
        "execution_attempted": True,
        "stdout": """
        <nmaprun args="nmap -sT -p 443 192.168.56.10">
          <host>
            <address addr="192.168.56.10"/>
            <hostnames><hostname name="secret-lab.internal"/></hostnames>
            <ports>
              <port protocol="tcp" portid="443">
                <state state="open" reason="syn-ack"/>
                <service name="https" product="PrivateServer" version="9.9.9"/>
              </port>
            </ports>
          </host>
        </nmaprun>
        """,
        "stderr": "stderr for 192.168.56.10 token_should_never_render",
        "output_truncated": False,
        "stderr_truncated": True,
        "timed_out": False,
        "reason": "raw_bounded",
    }
    parse_result = parse_active_nmap_basic_xml(fake_execution["stdout"])
    payload = build_active_nmap_basic_result_payload(fake_execution, parse_result)
    payload_body = json.dumps(payload, sort_keys=True)

    assert payload["audit_type"] == "active_nmap_basic"
    assert payload["status"] == "completed"
    assert payload["parser_ran"] is True
    assert payload["stdout_returned"] is False
    assert payload["stderr_returned"] is False
    assert payload["command_returned"] is False
    assert payload["target_returned"] is False
    assert payload["raw_xml_returned"] is False
    assert payload["port_observations"] == [
        {
            "port": 443,
            "protocol": "tcp",
            "state": "open",
            "manual_validation_required": True,
            "result_interpretation": "observed_exposure_review_indicator",
            "reason": "syn-ack",
        }
    ]
    for forbidden in ("192.168.56.10", "secret-lab.internal", "PrivateServer", "9.9.9", "nmap -sT", "<nmaprun", "stderr for"):
        assert forbidden not in payload_body

    now = datetime.now(timezone.utc)
    job = JobRecord(
        id="f" * 31 + "1",
        audit_type="active_nmap_basic",
        file_id=None,
        target_url="192.168.56.10",
        status="completed",
        created_at=now,
        updated_at=now,
        result=payload,
        error="token_should_never_render",
    )
    app.state.jobs.save(job)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        api_response = await client.get(f"/jobs/{job.id}")
        jobs_response = await client.get("/jobs")
        exports = {
            report_format: await client.get(f"/jobs/{job.id}/export/{report_format}")
            for report_format in ("markdown", "html", "xml", "pdf")
        }

    combined = json.dumps({"api": api_response.json(), "jobs": jobs_response.json()}, sort_keys=True)
    combined += "\n" + "\n".join(
        response.text if report_format != "pdf" else response.content.decode("latin1", errors="ignore")
        for report_format, response in exports.items()
    )
    assert "Observed TCP exposure" in combined
    assert "Review indicator" in combined
    assert "No vulnerability confirmation is asserted" in combined
    for forbidden in (
        "192.168.56.10",
        "secret-lab.internal",
        "PrivateServer",
        "9.9.9",
        "nmap -sT",
        "<nmaprun",
        "stderr for",
        "token_should_never_render",
        "confirmed vulnerability",
        "exploitable",
        "target is safe",
    ):
        assert forbidden not in combined


@pytest.mark.anyio
async def test_active_nmap_basic_controlled_states_and_legacy_payloads_do_not_crash(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    now = datetime.now(timezone.utc)
    statuses = ["failed", "timed_out", "truncated", "malformed", "nmap_missing", "no_ports"]
    jobs = [
        JobRecord(
            id=f"{index:032x}",
            audit_type="active_nmap_basic",
            file_id=None,
            target_url="lab-router",
            status="completed",
            created_at=now,
            updated_at=now,
            result={
                "audit_type": "active_nmap_basic",
                "capability": "active_nmap_basic",
                "profile": "tcp_connect_small",
                "status": result_status,
                "target": "lab-router.internal",
                "port_observations": [] if result_status == "no_ports" else "malformed",
                "limits": {"output_truncated": result_status == "truncated", "stderr_truncated": False, "timed_out": result_status == "timed_out"},
                "errors": [{"message": "nmap -sT lab-router.internal Cookie: sessionid=secret-session-cookie"}],
                "nested": {"raw_command": "nmap -sT -- lab-router.internal", "stderr": "lab-router.internal token_should_never_render"},
            },
        )
        for index, result_status in enumerate(statuses, start=1)
    ]
    for job in jobs:
        app.state.jobs.save(job)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        for job, expected_status in zip(jobs, statuses, strict=True):
            job_response = await client.get(f"/jobs/{job.id}")
            assert job_response.status_code == 200
            for report_format in ("markdown", "html", "xml", "pdf"):
                response = await client.get(f"/jobs/{job.id}/export/{report_format}")
                assert response.status_code == 200
                body = response.text if report_format != "pdf" else response.content.decode("latin1", errors="ignore")
                assert expected_status in body
                assert "Controlled" in body or report_format == "xml"
                assert "lab-router" not in body
                assert "lab-router.internal" not in body
                assert "nmap -sT" not in body
                assert "token_should_never_render" not in body
                assert "sessionid=secret-session-cookie" not in body
                assert "confirmed vulnerability" not in body
                assert "exploitable" not in body
                assert "target is safe" not in body


def test_active_nmap_basic_backend_source_has_no_real_executor_subprocess_or_frontend_integration():
    main_source = Path("backend/app/main.py").read_text(encoding="utf-8")
    services_source = Path("backend/app/services.py").read_text(encoding="utf-8")
    reporting_source = Path("backend/app/reporting.py").read_text(encoding="utf-8")
    storage_source = Path("backend/app/storage.py").read_text(encoding="utf-8")
    combined = "\n".join([main_source, services_source, reporting_source, storage_source])

    for forbidden in (
        "import " + "subprocess",
        "subprocess.",
        "shell" + "=True",
        "os." + "system",
        "po" + "pen",
        "P" + "open(",
        "from active_runner import",
        "execute_active_nmap_basic",
        "nmap_basic.executor",
        "tools.runner",
        "frontend/src",
    ):
        assert forbidden not in combined


@pytest.mark.anyio
async def test_web_basic_audit_requires_authorization(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    app.state.web_audits = NoopAuditService()
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/audits/web/basic",
            json={"url": "https://example.com", "authorization_confirmed": False},
        )

    assert response.status_code == 400
    assert response.json()["detail"] == "Authorization confirmation is required."


@pytest.mark.anyio
async def test_web_basic_audit_rejects_invalid_url_and_scheme(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    app.state.web_audits = NoopAuditService()
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        invalid_response = await client.post(
            "/audits/web/basic",
            json={"url": "not-a-url", "authorization_confirmed": True},
        )
        scheme_response = await client.post(
            "/audits/web/basic",
            json={"url": "ftp://example.com", "authorization_confirmed": True},
        )
        userinfo_response = await client.post(
            "/audits/web/basic",
            json={"url": "https://user:pass@example.com", "authorization_confirmed": True},
        )

    assert invalid_response.status_code == 400
    assert scheme_response.status_code == 400
    assert scheme_response.json()["detail"] == "Only http and https URLs are accepted."
    assert userinfo_response.status_code == 400
    assert userinfo_response.json()["detail"] == "URL credentials are not accepted."


def test_web_query_redaction_helpers_preserve_safe_params_and_redact_sensitive_values():
    redacted = web_security.redact_url_query(
        "https://example.com/callback?code=abc123&state=xyz&page=1&Token=second&flag"
    )

    assert "code=REDACTED" in redacted
    assert "state=REDACTED" in redacted
    assert "Token=REDACTED" in redacted
    assert "page=1" in redacted
    assert "abc123" not in redacted
    assert "second" not in redacted
    assert web_security.query_redaction_summary(redacted)["redacted_query_params"] == ["code", "state", "Token"]


@pytest.mark.anyio
async def test_web_basic_audit_redacts_sensitive_query_params_in_stored_job(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    web_service = CapturingWebAuditService()
    app.state.web_audits = web_service
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/audits/web/basic",
            json={
                "url": "https://example.test/callback?token=supersecret&page=1&token=second",
                "authorization_confirmed": True,
            },
        )
        list_response = await client.get("/jobs")

    assert response.status_code == 202
    payload = response.json()
    assert "supersecret" not in json.dumps(payload)
    assert "second" not in json.dumps(payload)
    assert payload["target_url"] == "https://example.test/callback?token=REDACTED&page=1&token=REDACTED"
    assert list_response.json()[0]["target_url"] == payload["target_url"]
    assert web_service.calls
    assert web_service.calls[0][1] == "https://example.test/callback?token=supersecret&page=1&token=second"


@pytest.mark.anyio
async def test_web_basic_audit_leaves_url_without_query_unchanged(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    app.state.web_audits = NoopAuditService()
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/audits/web/basic",
            json={"url": "https://example.test/status", "authorization_confirmed": True},
        )

    assert response.status_code == 202
    assert response.json()["target_url"] == "https://example.test/status"


@pytest.mark.anyio
async def test_web_basic_audit_blocks_private_targets_by_default(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    app.state.web_audits = NoopAuditService()
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/audits/web/basic",
            json={"url": "http://127.0.0.1", "authorization_confirmed": True},
        )

    assert response.status_code == 400
    assert "blocked address range" in response.json()["detail"]


@pytest.mark.anyio
async def test_web_basic_audit_allows_private_targets_when_configured(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_WEB_ALLOW_PRIVATE_TARGETS", "true")
    monkeypatch.setenv("INSPECTRA_WEB_ALLOWED_PORTS", "80,443,8080")
    configure_test_state(monkeypatch, tmp_path)
    app.state.web_audits = NoopAuditService()
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/audits/web/basic",
            json={"url": "http://127.0.0.1:8080/status", "authorization_confirmed": True},
        )
        list_response = await client.get("/jobs")

    assert response.status_code == 202
    payload = response.json()
    assert payload["audit_type"] == "web_basic"
    assert payload["file_id"] is None
    assert payload["target_url"] == "http://127.0.0.1:8080/status"
    assert list_response.json()[0]["target_url"] == payload["target_url"]


@pytest.mark.anyio
async def test_web_basic_audit_enforces_allowed_ports(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    app.state.web_audits = NoopAuditService()
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        rejected = await client.post(
            "/audits/web/basic",
            json={"url": "https://example.com:8443", "authorization_confirmed": True},
        )

    monkeypatch.setenv("INSPECTRA_WEB_ALLOWED_PORTS", "80,443,8443")
    configure_test_state(monkeypatch, tmp_path)
    app.state.web_audits = NoopAuditService()
    monkeypatch.setattr(
        web_security,
        "resolve_host_addresses",
        lambda host, port: {web_security.ipaddress.ip_address("93.184.216.34")},
    )
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        accepted = await client.post(
            "/audits/web/basic",
            json={"url": "https://example.com:8443/status", "authorization_confirmed": True},
        )

    assert rejected.status_code == 400
    assert "port 8443 is not allowed" in rejected.json()["detail"]
    assert accepted.status_code == 202
    assert accepted.json()["target_url"] == "https://example.com:8443/status"


@pytest.mark.anyio
async def test_web_basic_audit_still_blocks_metadata_target_when_private_allowed(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_WEB_ALLOW_PRIVATE_TARGETS", "true")
    configure_test_state(monkeypatch, tmp_path)
    app.state.web_audits = NoopAuditService()
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/audits/web/basic",
            json={"url": "http://169.254.169.254/latest/meta-data/", "authorization_confirmed": True},
        )

    assert response.status_code == 400
    assert "cloud metadata" in response.json()["detail"]


@pytest.mark.anyio
async def test_web_basic_audit_blocks_hostname_resolving_to_private_ip(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    app.state.web_audits = NoopAuditService()
    monkeypatch.setattr(
        web_security,
        "resolve_host_addresses",
        lambda host, port: {web_security.ipaddress.ip_address("192.168.1.20")},
    )
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/audits/web/basic",
            json={"url": "https://example.test", "authorization_confirmed": True},
        )

    assert response.status_code == 400
    assert "private address" in response.json()["detail"]


@pytest.mark.anyio
async def test_domain_basic_audit_job_creation_and_list(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    app.state.domain_audits = NoopAuditService()
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/audits/domain/basic",
            json={"domain": "Example.COM", "authorization_confirmed": True},
        )
        list_response = await client.get("/jobs")

    assert response.status_code == 202
    payload = response.json()
    assert payload["audit_type"] == "domain_basic"
    assert payload["file_id"] is None
    assert payload["target_domain"] == "example.com"
    assert list_response.json()[0]["target_domain"] == "example.com"


@pytest.mark.anyio
async def test_domain_basic_audit_requires_authorization(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    app.state.domain_audits = NoopAuditService()
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/audits/domain/basic",
            json={"domain": "example.com", "authorization_confirmed": False},
        )

    assert response.status_code == 400
    assert response.json()["detail"] == "Authorization confirmation is required."


@pytest.mark.anyio
async def test_domain_basic_audit_rejects_invalid_domains(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    app.state.domain_audits = NoopAuditService()
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        url_response = await client.post(
            "/audits/domain/basic",
            json={"domain": "https://example.com", "authorization_confirmed": True},
        )
        path_response = await client.post(
            "/audits/domain/basic",
            json={"domain": "example.com/path", "authorization_confirmed": True},
        )
        ip_response = await client.post(
            "/audits/domain/basic",
            json={"domain": "127.0.0.1", "authorization_confirmed": True},
        )
        localhost_response = await client.post(
            "/audits/domain/basic",
            json={"domain": "localhost", "authorization_confirmed": True},
        )
        local_response = await client.post(
            "/audits/domain/basic",
            json={"domain": "test.local", "authorization_confirmed": True},
        )

    assert url_response.status_code == 400
    assert path_response.status_code == 400
    assert ip_response.status_code == 400
    assert localhost_response.status_code == 400
    assert local_response.status_code == 400


@pytest.mark.anyio
async def test_subdomain_inventory_audit_job_creation_and_list(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    service = CapturingSubdomainInventoryAuditService()
    app.state.subdomain_inventory_audits = service
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/audits/subdomains/basic",
            json={
                "root_domain": "Example.COM",
                "subdomains": ["www", "API.Example.COM"],
                "authorization_confirmed": True,
            },
        )
        list_response = await client.get("/jobs")

    assert response.status_code == 202
    payload = response.json()
    assert payload["audit_type"] == "subdomain_inventory_basic"
    assert payload["file_id"] is None
    assert payload["target_domain"] == "example.com"
    assert list_response.json()[0]["target_domain"] == "example.com"
    assert service.calls == [(payload["id"], ["www", "API.Example.COM"])]


@pytest.mark.anyio
async def test_subdomain_inventory_audit_requires_authorization(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    app.state.subdomain_inventory_audits = NoopAuditService()
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/audits/subdomains/basic",
            json={"root_domain": "example.com", "subdomains": ["www"], "authorization_confirmed": False},
        )

    assert response.status_code == 400
    assert response.json()["detail"] == "Authorization confirmation is required."


@pytest.mark.anyio
async def test_subdomain_inventory_audit_rejects_bad_root_and_candidate_lists(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_SUBDOMAIN_MAX_CANDIDATES", "2")
    configure_test_state(monkeypatch, tmp_path)
    app.state.subdomain_inventory_audits = NoopAuditService()
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        bad_root = await client.post(
            "/audits/subdomains/basic",
            json={"root_domain": "https://example.com", "subdomains": ["www"], "authorization_confirmed": True},
        )
        empty_list = await client.post(
            "/audits/subdomains/basic",
            json={"root_domain": "example.com", "subdomains": [], "authorization_confirmed": True},
        )
        too_many = await client.post(
            "/audits/subdomains/basic",
            json={"root_domain": "example.com", "subdomains": ["www", "api", "cdn"], "authorization_confirmed": True},
        )

    assert bad_root.status_code == 400
    assert empty_list.status_code == 422
    assert too_many.status_code == 400


@pytest.mark.anyio
async def test_subdomain_inventory_audit_rejects_invalid_candidates(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    service = CapturingSubdomainInventoryAuditService()
    app.state.subdomain_inventory_audits = service
    bad_candidates = [
        "example.com",
        "api.evil.com",
        "*.example.com",
        "https://api.example.com",
        "api.example.com/path",
        "api.example.com?x=1",
        "api.example.com#fragment",
        "api.example.com.",
        "api.",
        "127.0.0.1",
        "::1",
        "host.local",
        "bad candidate",
        f"{'a' * 64}.example.com",
    ]
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        responses = [
            await client.post(
                "/audits/subdomains/basic",
                json={"root_domain": "example.com", "subdomains": [candidate], "authorization_confirmed": True},
            )
            for candidate in bad_candidates
        ]
        mixed_response = await client.post(
            "/audits/subdomains/basic",
            json={"root_domain": "example.com", "subdomains": ["www", "api.evil.com"], "authorization_confirmed": True},
        )

    assert all(response.status_code == 400 for response in responses)
    assert mixed_response.status_code == 400
    assert service.calls == []


@pytest.mark.anyio
async def test_subdomain_inventory_audit_rejects_oversized_strings(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    service = CapturingSubdomainInventoryAuditService()
    app.state.subdomain_inventory_audits = service
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        long_root = await client.post(
            "/audits/subdomains/basic",
            json={"root_domain": f"{'a' * 250}.com", "subdomains": ["www"], "authorization_confirmed": True},
        )
        long_candidate = await client.post(
            "/audits/subdomains/basic",
            json={"root_domain": "example.com", "subdomains": [f"{'a' * 254}"], "authorization_confirmed": True},
        )

    assert long_root.status_code == 422
    assert long_candidate.status_code == 422
    assert service.calls == []


@pytest.mark.parametrize(
    ("root_domain", "candidate", "expected"),
    [
        ("example.com", "www", "www.example.com"),
        ("example.com", "API.Example.COM", "api.example.com"),
        ("example.com", "täst", "xn--tst-qla.example.com"),
    ],
)
def test_normalize_subdomain_candidate_accepts_labels_and_fqdns(root_domain, candidate, expected):
    assert normalize_subdomain_candidate(root_domain, candidate) == expected


@pytest.mark.parametrize(
    "candidate",
    [
        "example.com",
        "api.evil.com",
        "api.",
        "api.example.com.",
        "::1",
        "host.local",
        f"{'a' * 64}.example.com",
    ],
)
def test_normalize_subdomain_candidate_rejects_contract_edges(candidate):
    with pytest.raises(HTTPException):
        normalize_subdomain_candidate("example.com", candidate)


def test_domain_runner_timeout_budget_scales_with_dns_timeout():
    assert calculate_domain_runner_timeout_seconds(5.0) == 190.0
    assert calculate_domain_runner_timeout_seconds(5.0, include_www=False) == 145.0
    assert calculate_domain_runner_timeout_seconds(2.0) > calculate_domain_runner_timeout_seconds(1.0)
    assert calculate_domain_runner_timeout_seconds(0.25) > 10.0


def test_subdomain_inventory_runner_timeout_uses_global_deadline():
    assert calculate_subdomain_inventory_runner_timeout_seconds(30.0, dns_timeout_seconds=5.0) == 55.0
    assert calculate_subdomain_inventory_runner_timeout_seconds(30.0, dns_timeout_seconds=1.0) == 43.0
    assert calculate_subdomain_inventory_runner_timeout_seconds(120.0, dns_timeout_seconds=5.0) == 145.0


def test_subdomain_inventory_global_deadline_config(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("INSPECTRA_SUBDOMAIN_GLOBAL_DEADLINE_SECONDS", "12.5")

    settings = load_settings()

    assert settings.subdomain_global_deadline_seconds == 12.5


def test_default_auth_mode_is_trusted_local(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_DATA_DIR", str(tmp_path))

    settings = load_settings()

    assert settings.auth_mode == DEFAULT_AUTH_MODE
    assert get_auth_mode(settings) == "trusted_local_no_auth"


def test_active_nmap_basic_feature_flag_is_disabled_by_default_and_configurable(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_DATA_DIR", str(tmp_path))

    settings = load_settings()

    assert DEFAULT_ACTIVE_NMAP_BASIC_ENABLED is False
    assert settings.active_nmap_basic_enabled is False

    monkeypatch.setenv("INSPECTRA_ACTIVE_NMAP_BASIC_ENABLED", "true")

    enabled_settings = load_settings()

    assert enabled_settings.active_nmap_basic_enabled is True


def test_active_tls_basic_feature_flag_is_disabled_by_default_and_configurable(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_DATA_DIR", str(tmp_path))

    settings = load_settings()

    assert DEFAULT_ACTIVE_TLS_BASIC_ENABLED is False
    assert settings.active_tls_basic_enabled is False

    monkeypatch.setenv("INSPECTRA_ACTIVE_TLS_BASIC_ENABLED", "true")

    enabled_settings = load_settings()

    assert enabled_settings.active_tls_basic_enabled is True


def test_active_dns_inventory_feature_flag_is_disabled_by_default_and_configurable(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_DATA_DIR", str(tmp_path))

    settings = load_settings()

    assert DEFAULT_ACTIVE_DNS_INVENTORY_ENABLED is False
    assert settings.active_dns_inventory_enabled is False

    monkeypatch.setenv("INSPECTRA_ACTIVE_DNS_INVENTORY_ENABLED", "true")

    enabled_settings = load_settings()

    assert enabled_settings.active_dns_inventory_enabled is True


def test_default_local_operator_has_stable_id(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_DATA_DIR", str(tmp_path))

    operator = get_current_operator_for_trusted_local(load_settings())

    assert operator == DEFAULT_LOCAL_OPERATOR
    assert operator.id == "local-admin"
    assert operator.kind == "local_admin"


def test_backend_state_exposes_auth_mode_and_local_operator(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)

    assert app.state.auth_mode == "trusted_local_no_auth"
    assert app.state.default_local_operator.id == "local-admin"


def test_self_hosted_single_admin_auth_mode_can_be_configured(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("INSPECTRA_AUTH_MODE", "self_hosted_single_admin")

    settings = load_settings()

    assert settings.auth_mode == "self_hosted_single_admin"
    assert get_auth_mode(settings) == "self_hosted_single_admin"


def test_unknown_auth_mode_is_rejected(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("INSPECTRA_AUTH_MODE", "public-root-admin")

    with pytest.raises(ValueError, match="INSPECTRA_AUTH_MODE must be one of"):
        load_settings()


def test_django_config_limits_config(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("INSPECTRA_DJANGO_CONFIG_MAX_FILES", "12")
    monkeypatch.setenv("INSPECTRA_DJANGO_CONFIG_MAX_FILE_BYTES", "1024")
    monkeypatch.setenv("INSPECTRA_DJANGO_CONFIG_MAX_TOTAL_BYTES", "4096")

    settings = load_settings()

    assert settings.django_config_max_files == 12
    assert settings.django_config_max_file_bytes == 1024
    assert settings.django_config_max_total_bytes == 4096


def test_docker_config_limits_config(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("INSPECTRA_DOCKER_CONFIG_MAX_FILES", "12")
    monkeypatch.setenv("INSPECTRA_DOCKER_CONFIG_MAX_FILE_BYTES", "1024")
    monkeypatch.setenv("INSPECTRA_DOCKER_CONFIG_MAX_TOTAL_BYTES", "4096")

    settings = load_settings()

    assert settings.docker_config_max_files == 12
    assert settings.docker_config_max_file_bytes == 1024
    assert settings.docker_config_max_total_bytes == 4096


def test_node_package_config_limits_config(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("INSPECTRA_NODE_PACKAGE_CONFIG_MAX_FILES", "12")
    monkeypatch.setenv("INSPECTRA_NODE_PACKAGE_CONFIG_MAX_FILE_BYTES", "1024")
    monkeypatch.setenv("INSPECTRA_NODE_PACKAGE_CONFIG_MAX_TOTAL_BYTES", "4096")

    settings = load_settings()

    assert settings.node_package_config_max_files == 12
    assert settings.node_package_config_max_file_bytes == 1024
    assert settings.node_package_config_max_total_bytes == 4096


def test_ci_cd_config_limits_config(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("INSPECTRA_CI_CD_CONFIG_MAX_FILES", "12")
    monkeypatch.setenv("INSPECTRA_CI_CD_CONFIG_MAX_FILE_BYTES", "1024")
    monkeypatch.setenv("INSPECTRA_CI_CD_CONFIG_MAX_TOTAL_BYTES", "4096")

    settings = load_settings()

    assert settings.ci_cd_config_max_files == 12
    assert settings.ci_cd_config_max_file_bytes == 1024
    assert settings.ci_cd_config_max_total_bytes == 4096


def test_terraform_config_limits_config(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("INSPECTRA_TERRAFORM_CONFIG_MAX_FILES", "12")
    monkeypatch.setenv("INSPECTRA_TERRAFORM_CONFIG_MAX_FILE_BYTES", "1024")
    monkeypatch.setenv("INSPECTRA_TERRAFORM_CONFIG_MAX_TOTAL_BYTES", "4096")

    settings = load_settings()

    assert settings.terraform_config_max_files == 12
    assert settings.terraform_config_max_file_bytes == 1024
    assert settings.terraform_config_max_total_bytes == 4096


def test_compose_config_limits_config(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("INSPECTRA_COMPOSE_CONFIG_MAX_FILES", "12")
    monkeypatch.setenv("INSPECTRA_COMPOSE_CONFIG_MAX_FILE_BYTES", "1024")
    monkeypatch.setenv("INSPECTRA_COMPOSE_CONFIG_MAX_TOTAL_BYTES", "4096")

    settings = load_settings()

    assert settings.compose_config_max_files == 12
    assert settings.compose_config_max_file_bytes == 1024
    assert settings.compose_config_max_total_bytes == 4096


@pytest.mark.parametrize(
    ("raw_domain", "expected"),
    [
        ("example.com", "example.com"),
        ("www.example.com", "www.example.com"),
        ("Sub.Example.CO.UK", "sub.example.co.uk"),
        ("täst.example", "xn--tst-qla.example"),
        ("example.com.", "example.com"),
    ],
)
def test_normalize_domain_accepts_valid_domains(raw_domain, expected):
    assert normalize_domain(raw_domain) == expected


@pytest.mark.parametrize(
    "raw_domain",
    [
        "",
        "https://example.com",
        "http://example.com",
        "example.com/path",
        "example.com?x=1",
        "example.com#fragment",
        "user:pass@example.com",
        "exa mple.com",
        "127.0.0.1",
        "::1",
        "localhost",
        "test.local",
        "test.localhost",
        "test.internal",
        "test.test",
        "test.invalid",
        "example..com",
        f"{'a' * 64}.example",
        "-bad.example",
        "bad-.example",
        ".".join(["a" * 63] * 5),
        "\ud800.example",
    ],
)
def test_normalize_domain_rejects_invalid_domains(raw_domain):
    with pytest.raises(HTTPException):
        normalize_domain(raw_domain)


@pytest.mark.anyio
async def test_list_jobs_returns_recent_first_with_summary(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    older = datetime(2026, 1, 1, tzinfo=timezone.utc)
    newer = older + timedelta(days=1)
    app.state.jobs.save(
        JobRecord(
            id="a" * 32,
            audit_type="pdf_basic",
            file_id="1" * 32,
            status="completed",
            created_at=older,
            updated_at=older,
            result={"analyzer": "old", "hashes": {"sha256": "abc"}, "validation": {"qpdf_ok": True, "warnings": []}},
        )
    )
    app.state.jobs.save(
        JobRecord(
            id="b" * 32,
            audit_type="pdf_basic",
            file_id="2" * 32,
            status="failed",
            created_at=newer,
            updated_at=newer,
            error="runner unavailable",
        )
    )
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/jobs")

    assert response.status_code == 200
    payload = response.json()
    assert [item["id"] for item in payload] == ["b" * 32, "a" * 32]
    assert payload[0]["summary"] == {"error": "runner unavailable"}
    assert payload[1]["summary"]["sha256"] == "abc"


@pytest.mark.anyio
async def test_list_jobs_includes_docker_config_summary(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    now = datetime(2026, 5, 31, tzinfo=timezone.utc)
    app.state.jobs.save(
        JobRecord(
            id="c" * 32,
            audit_type="docker_config_basic",
            file_id="4" * 32,
            status="completed",
            created_at=now,
            updated_at=now,
            result={
                "analyzer": "docker_config_basic",
                "archive_type": "zip",
                "summary": {
                    "files_reviewed": 2,
                    "dockerfiles_detected": 1,
                    "compose_files_detected": 1,
                    "services_detected": 3,
                    "findings_count": 3,
                    "secrets_redacted_count": 1,
                    "truncated": False,
                },
                "compose_services": [{"name": "web"}],
                "errors": ["one controlled warning"],
            },
        )
    )
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/jobs")

    assert response.status_code == 200
    summary = response.json()[0]["summary"]
    assert summary["archive_type"] == "zip"
    assert summary["files_reviewed"] == 2
    assert summary["dockerfiles_detected"] == 1
    assert summary["compose_files_detected"] == 1
    assert summary["services_detected"] == 3
    assert summary["findings_count"] == 3
    assert summary["errors_count"] == 1


@pytest.mark.anyio
async def test_list_jobs_includes_node_package_config_summary(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    now = datetime(2026, 5, 31, tzinfo=timezone.utc)
    app.state.jobs.save(
        JobRecord(
            id="b" * 31 + "1",
            audit_type="node_package_config_basic",
            file_id="4" * 32,
            status="completed",
            created_at=now,
            updated_at=now,
            result={
                "analyzer": "node_package_config_basic",
                "archive_type": "zip",
                "summary": {
                    "files_considered": 4,
                    "files_reviewed": 3,
                    "package_manifests_detected": 1,
                    "lockfiles_detected": 2,
                    "package_manager_configs_detected": 1,
                    "packages_detected": 1,
                    "scripts_detected": 2,
                    "findings_count": 5,
                    "redacted_values_count": 1,
                    "truncated": False,
                },
                "errors": ["one controlled warning"],
            },
        )
    )
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/jobs")

    assert response.status_code == 200
    summary = response.json()[0]["summary"]
    assert summary["archive_type"] == "zip"
    assert summary["files_considered"] == 4
    assert summary["files_reviewed"] == 3
    assert summary["package_manifests_detected"] == 1
    assert summary["lockfiles_detected"] == 2
    assert summary["package_manager_configs_detected"] == 1
    assert summary["packages_detected"] == 1
    assert summary["scripts_detected"] == 2
    assert summary["findings_count"] == 5
    assert summary["redacted_values_count"] == 1
    assert summary["errors_count"] == 1


@pytest.mark.anyio
async def test_list_jobs_includes_ci_cd_config_summary(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    now = datetime(2026, 5, 31, tzinfo=timezone.utc)
    app.state.jobs.save(
        JobRecord(
            id="c" * 31 + "1",
            audit_type="ci_cd_config_basic",
            file_id="4" * 32,
            status="completed",
            created_at=now,
            updated_at=now,
            result={
                "analyzer": "ci_cd_config_basic",
                "archive_type": "zip",
                "summary": {
                    "files_considered": 3,
                    "files_reviewed": 2,
                    "workflow_files_detected": 1,
                    "jobs_detected": 2,
                    "steps_detected": 5,
                    "triggers_detected": 2,
                    "findings_count": 4,
                    "redacted_values_count": 1,
                    "truncated": False,
                },
                "errors": ["one controlled warning"],
            },
        )
    )
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/jobs")

    assert response.status_code == 200
    summary = response.json()[0]["summary"]
    assert summary["archive_type"] == "zip"
    assert summary["files_considered"] == 3
    assert summary["files_reviewed"] == 2
    assert summary["workflow_files_detected"] == 1
    assert summary["jobs_detected"] == 2
    assert summary["steps_detected"] == 5
    assert summary["triggers_detected"] == 2
    assert summary["findings_count"] == 4
    assert summary["redacted_values_count"] == 1
    assert summary["errors_count"] == 1


@pytest.mark.anyio
async def test_list_jobs_includes_k8s_config_summary_and_sparse_payload(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    now = datetime(2026, 5, 31, tzinfo=timezone.utc)
    app.state.jobs.save(
        JobRecord(
            id="e" * 31 + "1",
            audit_type="k8s_config_basic",
            file_id="4" * 32,
            status="completed",
            created_at=now,
            updated_at=now,
            result={
                "analyzer": "k8s_config_basic",
                "archive_type": "zip",
                "summary": {
                    "files_considered": 4,
                    "files_reviewed": 3,
                    "manifest_files_detected": 3,
                    "resources_detected": 6,
                    "workloads_detected": 2,
                    "services_detected": 1,
                    "secrets_detected": 1,
                    "rbac_resources_detected": 1,
                    "findings_count": 5,
                    "redacted_values_count": 2,
                    "truncated": False,
                },
                "errors": ["one controlled warning"],
            },
        )
    )
    app.state.jobs.save(
        JobRecord(
            id="e" * 31 + "2",
            audit_type="k8s_config_basic",
            file_id="4" * 32,
            status="completed",
            created_at=now,
            updated_at=now,
            result={"analyzer": "k8s_config_basic", "summary": "unexpected"},
        )
    )
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/jobs")

    assert response.status_code == 200
    summaries = {item["id"]: item["summary"] for item in response.json()}
    summary = summaries["e" * 31 + "1"]
    assert summary["archive_type"] == "zip"
    assert summary["files_considered"] == 4
    assert summary["files_reviewed"] == 3
    assert summary["manifest_files_detected"] == 3
    assert summary["resources_detected"] == 6
    assert summary["workloads_detected"] == 2
    assert summary["services_detected"] == 1
    assert summary["secrets_detected"] == 1
    assert summary["rbac_resources_detected"] == 1
    assert summary["findings_count"] == 5
    assert summary["redacted_values_count"] == 2
    assert summary["errors_count"] == 1
    sparse_summary = summaries["e" * 31 + "2"]
    assert sparse_summary["analyzer"] == "k8s_config_basic"
    assert sparse_summary["files_reviewed"] is None
    assert sparse_summary["errors_count"] == 0


@pytest.mark.anyio
async def test_list_jobs_includes_terraform_config_summary_and_sparse_payload(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    now = datetime(2026, 5, 31, tzinfo=timezone.utc)
    app.state.jobs.save(
        JobRecord(
            id="a" * 31 + "1",
            audit_type="terraform_config_basic",
            file_id="4" * 32,
            status="completed",
            created_at=now,
            updated_at=now,
            result={
                "analyzer": "terraform_config_basic",
                "archive_type": "zip",
                "summary": {
                    "files_considered": 5,
                    "files_reviewed": 3,
                    "terraform_files_detected": 2,
                    "tfvars_files_detected": 1,
                    "state_files_detected": 1,
                    "providers_detected": 1,
                    "backends_detected": 1,
                    "modules_detected": 1,
                    "resources_detected": 2,
                    "findings_count": 4,
                    "redacted_values_count": 3,
                    "truncated": False,
                },
                "errors": ["one controlled warning"],
            },
        )
    )
    app.state.jobs.save(
        JobRecord(
            id="a" * 31 + "2",
            audit_type="terraform_config_basic",
            file_id="4" * 32,
            status="completed",
            created_at=now,
            updated_at=now,
            result={"analyzer": "terraform_config_basic", "summary": "unexpected"},
        )
    )
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/jobs")

    assert response.status_code == 200
    summaries = {item["id"]: item["summary"] for item in response.json()}
    summary = summaries["a" * 31 + "1"]
    assert summary["archive_type"] == "zip"
    assert summary["files_considered"] == 5
    assert summary["files_reviewed"] == 3
    assert summary["terraform_files_detected"] == 2
    assert summary["tfvars_files_detected"] == 1
    assert summary["state_files_detected"] == 1
    assert summary["providers_detected"] == 1
    assert summary["backends_detected"] == 1
    assert summary["modules_detected"] == 1
    assert summary["resources_detected"] == 2
    assert summary["findings_count"] == 4
    assert summary["redacted_values_count"] == 3
    assert summary["errors_count"] == 1
    sparse_summary = summaries["a" * 31 + "2"]
    assert sparse_summary["analyzer"] == "terraform_config_basic"
    assert sparse_summary["files_reviewed"] is None
    assert sparse_summary["errors_count"] == 0


@pytest.mark.anyio
async def test_list_jobs_includes_nginx_config_summary_and_sparse_payload(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    now = datetime(2026, 6, 1, tzinfo=timezone.utc)
    app.state.jobs.save(
        JobRecord(
            id="9" * 31 + "1",
            audit_type="nginx_config_basic",
            file_id="4" * 32,
            status="completed",
            created_at=now,
            updated_at=now,
            result={
                "analyzer": "nginx_config_basic",
                "archive_type": "zip",
                "summary": {
                    "files_considered": 3,
                    "files_reviewed": 2,
                    "nginx_files_detected": 2,
                    "server_blocks_detected": 2,
                    "location_blocks_detected": 4,
                    "upstream_blocks_detected": 1,
                    "includes_detected": 2,
                    "tls_servers_detected": 1,
                    "findings_count": 5,
                    "redacted_values_count": 2,
                    "truncated": False,
                },
                "errors": ["one controlled warning"],
            },
        )
    )
    app.state.jobs.save(
        JobRecord(
            id="9" * 31 + "2",
            audit_type="nginx_config_basic",
            file_id="4" * 32,
            status="completed",
            created_at=now,
            updated_at=now,
            result={"analyzer": "nginx_config_basic", "summary": "unexpected"},
        )
    )
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/jobs")

    assert response.status_code == 200
    summaries = {item["id"]: item["summary"] for item in response.json()}
    summary = summaries["9" * 31 + "1"]
    assert summary["archive_type"] == "zip"
    assert summary["files_considered"] == 3
    assert summary["files_reviewed"] == 2
    assert summary["nginx_files_detected"] == 2
    assert summary["server_blocks_detected"] == 2
    assert summary["location_blocks_detected"] == 4
    assert summary["upstream_blocks_detected"] == 1
    assert summary["includes_detected"] == 2
    assert summary["tls_servers_detected"] == 1
    assert summary["findings_count"] == 5
    assert summary["redacted_values_count"] == 2
    assert summary["errors_count"] == 1
    sparse_summary = summaries["9" * 31 + "2"]
    assert sparse_summary["analyzer"] == "nginx_config_basic"
    assert sparse_summary["files_reviewed"] is None
    assert sparse_summary["errors_count"] == 0


@pytest.mark.anyio
async def test_list_jobs_includes_compose_config_summary_and_sparse_payload(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    now = datetime(2026, 6, 1, tzinfo=timezone.utc)
    app.state.jobs.save(
        JobRecord(
            id="7" * 31 + "1",
            audit_type="compose_config_basic",
            file_id="4" * 32,
            status="completed",
            created_at=now,
            updated_at=now,
            result={
                "analyzer": "compose_config_basic",
                "archive_type": "zip",
                "summary": {
                    "files_considered": 4,
                    "files_reviewed": 2,
                    "compose_files_detected": 2,
                    "services_detected": 3,
                    "networks_detected": 2,
                    "volumes_detected": 2,
                    "secrets_detected": 1,
                    "published_ports_detected": 4,
                    "env_files_detected": 1,
                    "findings_count": 6,
                    "redacted_values_count": 2,
                    "truncated": False,
                },
                "errors": ["one controlled warning"],
            },
        )
    )
    app.state.jobs.save(
        JobRecord(
            id="7" * 31 + "2",
            audit_type="compose_config_basic",
            file_id="4" * 32,
            status="completed",
            created_at=now,
            updated_at=now,
            result={"analyzer": "compose_config_basic", "summary": "unexpected"},
        )
    )
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/jobs")

    assert response.status_code == 200
    summaries = {item["id"]: item["summary"] for item in response.json()}
    summary = summaries["7" * 31 + "1"]
    assert summary["archive_type"] == "zip"
    assert summary["files_considered"] == 4
    assert summary["files_reviewed"] == 2
    assert summary["compose_files_detected"] == 2
    assert summary["services_detected"] == 3
    assert summary["networks_detected"] == 2
    assert summary["volumes_detected"] == 2
    assert summary["secrets_detected"] == 1
    assert summary["published_ports_detected"] == 4
    assert summary["env_files_detected"] == 1
    assert summary["findings_count"] == 6
    assert summary["redacted_values_count"] == 2
    assert summary["errors_count"] == 1
    sparse_summary = summaries["7" * 31 + "2"]
    assert sparse_summary["analyzer"] == "compose_config_basic"
    assert sparse_summary["files_reviewed"] is None
    assert sparse_summary["errors_count"] == 0


@pytest.mark.anyio
async def test_delete_file_removes_source_and_marks_jobs(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        upload_response = await client.post(
            "/files/pdf",
            files={"file": ("sample.pdf", b"%PDF-1.4\n%%EOF\n", "application/pdf")},
        )
        file_payload = upload_response.json()
        job = app.state.jobs.create_pdf_job(file_payload["id"])
        app.state.jobs.update(
            job.id,
            status="completed",
            result={"analyzer": "inspectra-pdf-basic", "hashes": {"sha256": file_payload["sha256"]}, "validation": {"qpdf_ok": True}},
        )

        delete_response = await client.delete(f"/files/{file_payload['id']}")
        deleted_file_response = await client.get(f"/files/{file_payload['id']}")
        job_response = await client.get(f"/jobs/{job.id}")

    assert delete_response.status_code == 200
    assert delete_response.json()["associated_jobs_marked"] == 1
    assert deleted_file_response.status_code == 404
    assert not (tmp_path / "uploads" / file_payload["stored_filename"]).exists()
    assert not (tmp_path / "uploads" / f"{file_payload['id']}.json").exists()
    assert job_response.status_code == 200
    assert job_response.json()["source_file_deleted_at"] is not None
    assert job_response.json()["result"]["hashes"]["sha256"] == file_payload["sha256"]


@pytest.mark.anyio
async def test_delete_file_is_owner_scoped_and_preserves_wrong_owner_data(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    created_at = datetime.now(timezone.utc).isoformat()
    file_id = "1" * 31 + "0"
    job_id = "1" * 31 + "1"
    stored_filename = f"{file_id}.pdf"
    upload_path = app.state.settings.upload_dir / stored_filename
    metadata_path = app.state.settings.upload_dir / f"{file_id}.json"
    job_path = app.state.settings.jobs_dir / f"{job_id}.json"
    upload_path.write_bytes(b"%PDF-1.4\n%%EOF\n")
    metadata_path.write_text(
        json.dumps(
            {
                "id": file_id,
                "owner_id": "other-owner",
                "kind": "pdf",
                "original_filename": "other.pdf",
                "stored_filename": stored_filename,
                "content_type": "application/pdf",
                "size_bytes": upload_path.stat().st_size,
                "sha256": "0" * 64,
                "created_at": created_at,
            }
        ),
        encoding="utf-8",
    )
    job_path.write_text(
        json.dumps(
            {
                "id": job_id,
                "owner_id": "other-owner",
                "audit_type": "pdf_basic",
                "file_id": file_id,
                "status": "completed",
                "created_at": created_at,
                "updated_at": created_at,
                "result": {"analyzer": "pdf_basic", "summary": {}},
            }
        ),
        encoding="utf-8",
    )
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        delete_response = await client.delete(f"/files/{file_id}")

    assert delete_response.status_code == 404
    assert delete_response.json()["detail"] == "File not found."
    assert upload_path.exists()
    assert metadata_path.exists()
    assert job_path.exists()
    assert app.state.jobs.get(job_id).source_file_deleted_at is None


@pytest.mark.anyio
async def test_self_hosted_single_admin_denies_anonymous_deletes(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_AUTH_MODE", "self_hosted_single_admin")
    configure_test_state(monkeypatch, tmp_path)
    now = datetime.now(timezone.utc)
    file_id = "1" * 31 + "2"
    job_id = "1" * 31 + "3"
    stored_filename = f"{file_id}.pdf"
    upload_path = app.state.settings.upload_dir / stored_filename
    metadata_path = app.state.settings.upload_dir / f"{file_id}.json"
    upload_path.write_bytes(b"%PDF-1.4\n%%EOF\n")
    metadata_path.write_text(
        json.dumps(
            {
                "id": file_id,
                "owner_id": DEFAULT_LOCAL_OPERATOR.id,
                "kind": "pdf",
                "original_filename": "sample.pdf",
                "stored_filename": stored_filename,
                "content_type": "application/pdf",
                "size_bytes": upload_path.stat().st_size,
                "sha256": "0" * 64,
                "created_at": now.isoformat(),
            }
        ),
        encoding="utf-8",
    )
    job = JobRecord(
        id=job_id,
        owner_id=DEFAULT_LOCAL_OPERATOR.id,
        audit_type="pdf_basic",
        file_id=file_id,
        status="completed",
        created_at=now,
        updated_at=now,
        result={"analyzer": "pdf_basic", "summary": {}},
    )
    app.state.jobs.save(job)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        file_delete_response = await client.delete(f"/files/{file_id}")
        job_delete_response = await client.delete(f"/jobs/{job_id}")

    assert file_delete_response.status_code == 401
    assert job_delete_response.status_code == 401
    assert file_delete_response.json()["detail"] == AUTH_REQUIRED_DETAIL
    assert job_delete_response.json()["detail"] == AUTH_REQUIRED_DETAIL
    assert upload_path.exists()
    assert metadata_path.exists()
    assert (app.state.settings.jobs_dir / f"{job_id}.json").exists()


@pytest.mark.anyio
async def test_delete_job_removes_result_and_report_surfaces(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    job = save_export_fixture_job()
    job_path = app.state.settings.jobs_dir / f"{job.id}.json"
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        before_job_response = await client.get(f"/jobs/{job.id}")
        before_export_response = await client.get(f"/jobs/{job.id}/export/markdown")
        before_sbom_response = await client.get(f"/jobs/{job.id}/sbom/cyclonedx-json")
        delete_response = await client.delete(f"/jobs/{job.id}")
        after_job_response = await client.get(f"/jobs/{job.id}")
        after_export_response = await client.get(f"/jobs/{job.id}/export/markdown")
        after_sbom_response = await client.get(f"/jobs/{job.id}/sbom/cyclonedx-json")

    assert before_job_response.status_code == 200
    assert before_export_response.status_code == 200
    assert before_sbom_response.status_code == 200
    assert delete_response.status_code == 200
    assert delete_response.json() == {"job_id": job.id, "deleted": True}
    assert not job_path.exists()
    for response in (after_job_response, after_export_response, after_sbom_response):
        assert response.status_code == 404
        assert response.json()["detail"] == "Job not found."


@pytest.mark.anyio
async def test_delete_job_is_owner_scoped_and_rejects_nonterminal_jobs(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    now = datetime.now(timezone.utc)
    wrong_owner_job = JobRecord(
        id="1" * 31 + "4",
        owner_id="other-owner",
        audit_type="pdf_basic",
        file_id="1" * 31 + "5",
        status="completed",
        created_at=now,
        updated_at=now,
        result={"analyzer": "pdf_basic", "summary": {}},
    )
    queued_job = app.state.jobs.create_pdf_job("1" * 31 + "6", owner_id=DEFAULT_LOCAL_OPERATOR.id)
    running_job = JobRecord(
        id="1" * 31 + "7",
        owner_id=DEFAULT_LOCAL_OPERATOR.id,
        audit_type="pdf_basic",
        file_id="1" * 31 + "8",
        status="running",
        created_at=now,
        updated_at=now,
    )
    app.state.jobs.save(wrong_owner_job)
    app.state.jobs.save(running_job)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        wrong_owner_response = await client.delete(f"/jobs/{wrong_owner_job.id}")
        queued_response = await client.delete(f"/jobs/{queued_job.id}")
        running_response = await client.delete(f"/jobs/{running_job.id}")

    assert wrong_owner_response.status_code == 404
    assert wrong_owner_response.json()["detail"] == "Job not found."
    for response in (queued_response, running_response):
        assert response.status_code == 409
        assert response.json()["detail"] == "Job deletion is only available for completed or failed jobs."
    for job_id in (wrong_owner_job.id, queued_job.id, running_job.id):
        assert (app.state.settings.jobs_dir / f"{job_id}.json").exists()


@pytest.mark.anyio
async def test_delete_failed_target_job_removes_app_side_history(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    now = datetime.now(timezone.utc)
    job = JobRecord(
        id="1" * 31 + "9",
        owner_id=DEFAULT_LOCAL_OPERATOR.id,
        audit_type="web_basic",
        file_id=None,
        target_url="https://example.com/status",
        status="failed",
        created_at=now,
        updated_at=now,
        error="controlled failure",
    )
    app.state.jobs.save(job)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        before_response = await client.get(f"/jobs/{job.id}")
        delete_response = await client.delete(f"/jobs/{job.id}")
        after_response = await client.get(f"/jobs/{job.id}")
        export_response = await client.get(f"/jobs/{job.id}/export/markdown")

    assert before_response.status_code == 200
    assert delete_response.status_code == 200
    assert delete_response.json() == {"job_id": job.id, "deleted": True}
    assert after_response.status_code == 404
    assert export_response.status_code == 404


def test_storage_lockfile_is_created_inside_data(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)

    app.state.jobs.create_pdf_job("1" * 32)

    lock_path = tmp_path / ".locks" / "storage.lock"
    assert lock_path.exists()
    assert lock_path.resolve().is_relative_to(tmp_path.resolve())


def test_job_save_preserves_existing_source_deleted_marker(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    job = app.state.jobs.create_pdf_job("2" * 32)
    stale_record = app.state.jobs.get(job.id)

    assert app.state.jobs.mark_file_deleted(job.file_id) == 1
    stale_completed = stale_record.model_copy(
        update={
            "status": "completed",
            "updated_at": datetime(2026, 5, 26, tzinfo=timezone.utc),
            "result": {"analyzer": "race-fixture"},
        }
    )
    app.state.jobs.save(stale_completed)

    final = app.state.jobs.get(job.id)
    assert final.status == "completed"
    assert final.result == {"analyzer": "race-fixture"}
    assert final.source_file_deleted_at is not None


def test_concurrent_job_completion_and_delete_marker_preserve_fields(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    job = app.state.jobs.create_pdf_job("3" * 32)
    barrier = threading.Barrier(2)

    def mark_deleted() -> None:
        barrier.wait(timeout=2)
        app.state.jobs.mark_file_deleted(job.file_id)

    def complete_job() -> None:
        barrier.wait(timeout=2)
        app.state.jobs.update(job.id, status="completed", result={"analyzer": "concurrent"})

    threads = [threading.Thread(target=mark_deleted), threading.Thread(target=complete_job)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=2)

    assert all(not thread.is_alive() for thread in threads)
    final = app.state.jobs.get(job.id)
    assert final.status == "completed"
    assert final.result == {"analyzer": "concurrent"}
    assert final.source_file_deleted_at is not None


def test_concurrent_updates_for_different_jobs_do_not_corrupt_json(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    jobs = [app.state.jobs.create_pdf_job(f"{index:032x}") for index in range(10, 16)]
    barrier = threading.Barrier(len(jobs))

    def complete_job(job: JobRecord, index: int) -> None:
        barrier.wait(timeout=2)
        app.state.jobs.update(job.id, status="completed", result={"index": index})

    threads = [threading.Thread(target=complete_job, args=(job, index)) for index, job in enumerate(jobs)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=2)

    assert all(not thread.is_alive() for thread in threads)
    for index, job in enumerate(jobs):
        payload = json.loads((tmp_path / "results" / "jobs" / f"{job.id}.json").read_text(encoding="utf-8"))
        final = app.state.jobs.get(job.id)
        assert payload["status"] == "completed"
        assert final.result == {"index": index}


@pytest.mark.anyio
async def test_export_markdown_for_existing_job(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    job = save_export_fixture_job()
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get(f"/jobs/{job.id}/export/markdown")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/markdown")
    assert response.headers["content-disposition"] == f'attachment; filename="inspectra-job-{job.id}.md"'
    assert "# Inspectra Audit Report" in response.text
    assert "manifest_basic" in response.text
    assert "`<script>alert('x')</script>`" in response.text


@pytest.mark.anyio
async def test_export_markdown_neutralizes_dynamic_markdown_content(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    job = save_malicious_markdown_fixture_job()
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get(f"/jobs/{job.id}/export/markdown")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/markdown")
    assert response.headers["content-disposition"] == f'attachment; filename="inspectra-job-{job.id}.md"'
    markdown = response.text
    assert "`[click me](https://evil.example)`" in markdown
    assert "`![x](https://evil.example/pixel.png)`" in markdown
    assert '`<img src="https://evil.example/pixel.png">`' in markdown
    assert "`# Fake Heading`" in markdown
    assert "`- fake item`" in markdown
    assert "`> fake quote`" in markdown
    assert "`value | injected | column`" in markdown
    assert "`demo @ git+https://evil.example/demo.git`" in markdown
    assert "`<script>alert(1)</script>`" in markdown
    assert "````text\nfirst line\n> fake quote\n```inside fenced content\nhttps://evil.example/log\n````" in markdown


def test_markdown_helpers_use_safe_code_delimiters():
    assert markdown_inline_value("[click](https://evil.example)") == "`[click](https://evil.example)`"
    assert markdown_inline_value("`inline`") == "`` `inline` ``"

    block = markdown_block_value("before\n```text\ninside\n```\nafter")

    assert block.startswith("````text\n")
    assert block.endswith("\n````")
    assert "```text\ninside\n```" in block


@pytest.mark.anyio
async def test_export_html_escapes_dynamic_content(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    job = save_export_fixture_job()
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get(f"/jobs/{job.id}/export/html")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert response.headers["content-disposition"] == f'attachment; filename="inspectra-job-{job.id}.html"'
    assert "<script>alert('x')</script>" not in response.text
    assert "&lt;script&gt;alert(&#x27;x&#x27;)&lt;/script&gt;" in response.text


@pytest.mark.anyio
async def test_export_xml_escapes_dynamic_content_and_is_valid(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    job = save_export_fixture_job()
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get(f"/jobs/{job.id}/export/xml")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/xml")
    assert response.headers["content-disposition"] == f'attachment; filename="inspectra-job-{job.id}.xml"'
    assert "<script>alert('x')</script>" not in response.text
    assert "&lt;script&gt;alert('x')&lt;/script&gt;" in response.text
    root = ElementTree.fromstring(response.text)
    assert root.tag == "inspectraAuditReport"
    assert root.findtext("./job/id") == job.id


@pytest.mark.anyio
async def test_export_pdf_for_existing_job(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    job = save_export_fixture_job()
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get(f"/jobs/{job.id}/export/pdf")

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert response.headers["content-disposition"] == f'attachment; filename="inspectra-job-{job.id}.pdf"'
    assert response.content.startswith(b"%PDF")
    assert len(response.content) > 200


@pytest.mark.anyio
async def test_export_archive_job_all_formats(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    job = save_archive_export_fixture_job()
    expected = {
        "markdown": ("text/markdown", "md"),
        "html": ("text/html", "html"),
        "xml": ("application/xml", "xml"),
        "pdf": ("application/pdf", "pdf"),
    }
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        responses = {
            report_format: await client.get(f"/jobs/{job.id}/export/{report_format}")
            for report_format in expected
        }

    for report_format, response in responses.items():
        content_type, extension = expected[report_format]
        assert response.status_code == 200
        assert response.headers["content-type"].startswith(content_type)
        assert response.headers["content-disposition"] == f'attachment; filename="inspectra-job-{job.id}.{extension}"'
    assert "archive_basic" in responses["markdown"].text
    assert "Archive Metrics" in responses["html"].text
    assert ElementTree.fromstring(responses["xml"].text).findtext("./job/auditType") == "archive_basic"
    assert responses["pdf"].content.startswith(b"%PDF")


@pytest.mark.anyio
async def test_export_project_archive_job_all_formats(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    job = save_project_archive_export_fixture_job()
    expected = {
        "markdown": ("text/markdown", "md"),
        "html": ("text/html", "html"),
        "xml": ("application/xml", "xml"),
        "pdf": ("application/pdf", "pdf"),
    }
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        responses = {
            report_format: await client.get(f"/jobs/{job.id}/export/{report_format}")
            for report_format in expected
        }

    for report_format, response in responses.items():
        content_type, extension = expected[report_format]
        assert response.status_code == 200
        assert response.headers["content-type"].startswith(content_type)
        assert response.headers["content-disposition"] == f'attachment; filename="inspectra-job-{job.id}.{extension}"'
    assert "project_archive_basic" in responses["markdown"].text
    assert "Project Archive Metrics" in responses["html"].text
    assert ElementTree.fromstring(responses["xml"].text).findtext("./job/auditType") == "project_archive_basic"
    assert responses["pdf"].content.startswith(b"%PDF")


@pytest.mark.anyio
async def test_export_web_job_all_formats(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    job = save_web_export_fixture_job()
    expected = {
        "markdown": ("text/markdown", "md"),
        "html": ("text/html", "html"),
        "xml": ("application/xml", "xml"),
        "pdf": ("application/pdf", "pdf"),
    }
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        responses = {
            report_format: await client.get(f"/jobs/{job.id}/export/{report_format}")
            for report_format in expected
        }

    for report_format, response in responses.items():
        content_type, extension = expected[report_format]
        assert response.status_code == 200
        assert response.headers["content-type"].startswith(content_type)
        assert response.headers["content-disposition"] == f'attachment; filename="inspectra-job-{job.id}.{extension}"'
    assert "web_basic" in responses["markdown"].text
    assert "Security Headers" in responses["html"].text
    assert ElementTree.fromstring(responses["xml"].text).findtext("./job/targetUrl") == "https://example.com/callback?token=REDACTED&page=1"
    assert responses["pdf"].content.startswith(b"%PDF")
    for response in responses.values():
        content = response.text if response.headers["content-type"].startswith(("text/", "application/xml")) else response.content.decode("latin1")
        assert "supersecret" not in content
        assert "[redacted]" in content
        if response.headers["content-type"].startswith(("text/", "application/xml")):
            assert "token=REDACTED" in content


@pytest.mark.anyio
async def test_export_domain_job_all_formats(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    job = save_domain_export_fixture_job()
    expected = {
        "markdown": ("text/markdown", "md"),
        "html": ("text/html", "html"),
        "xml": ("application/xml", "xml"),
        "pdf": ("application/pdf", "pdf"),
    }
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        responses = {
            report_format: await client.get(f"/jobs/{job.id}/export/{report_format}")
            for report_format in expected
        }

    for report_format, response in responses.items():
        content_type, extension = expected[report_format]
        assert response.status_code == 200
        assert response.headers["content-type"].startswith(content_type)
        assert response.headers["content-disposition"] == f'attachment; filename="inspectra-job-{job.id}.{extension}"'
    assert "domain_basic" in responses["markdown"].text
    assert "DNS Records" in responses["html"].text
    assert ElementTree.fromstring(responses["xml"].text).findtext("./job/targetDomain") == "example.com"
    assert responses["pdf"].content.startswith(b"%PDF")


@pytest.mark.anyio
async def test_export_subdomain_inventory_job_all_formats(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    job = save_subdomain_inventory_export_fixture_job()
    expected = {
        "markdown": ("text/markdown", "md"),
        "html": ("text/html", "html"),
        "xml": ("application/xml", "xml"),
        "pdf": ("application/pdf", "pdf"),
    }
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        responses = {
            report_format: await client.get(f"/jobs/{job.id}/export/{report_format}")
            for report_format in expected
        }

    for report_format, response in responses.items():
        content_type, extension = expected[report_format]
        assert response.status_code == 200
        assert response.headers["content-type"].startswith(content_type)
        assert response.headers["content-disposition"] == f'attachment; filename="inspectra-job-{job.id}.{extension}"'
    assert "subdomain_inventory_basic" in responses["markdown"].text
    assert "Subdomain Inventory Limits" in responses["markdown"].text
    assert "global_deadline_reached" in responses["markdown"].text
    assert "Subdomain Inventory Metrics" in responses["html"].text
    assert ElementTree.fromstring(responses["xml"].text).findtext("./job/targetDomain") == "example.com"
    assert responses["pdf"].content.startswith(b"%PDF")


@pytest.mark.anyio
async def test_export_django_config_job_all_formats(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    job = save_django_config_export_fixture_job()
    expected = {
        "markdown": ("text/markdown", "md"),
        "html": ("text/html", "html"),
        "xml": ("application/xml", "xml"),
        "pdf": ("application/pdf", "pdf"),
    }
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        responses = {
            report_format: await client.get(f"/jobs/{job.id}/export/{report_format}")
            for report_format in expected
        }

    for report_format, response in responses.items():
        content_type, extension = expected[report_format]
        assert response.status_code == 200
        assert response.headers["content-type"].startswith(content_type)
        assert response.headers["content-disposition"] == f'attachment; filename="inspectra-job-{job.id}.{extension}"'
    assert "django_config_basic" in responses["markdown"].text
    assert "Finding 1 Context" in responses["markdown"].text
    assert "production" in responses["markdown"].text
    assert "Finding 2 Context" in responses["markdown"].text
    assert "grouped" in responses["markdown"].text
    assert "Django Config Metrics" in responses["html"].text
    assert "Finding 1 Context" in responses["html"].text
    assert "production" in responses["html"].text
    assert "Finding 2 Context" in responses["html"].text
    assert "grouped" in responses["html"].text
    assert ElementTree.fromstring(responses["xml"].text).findtext("./job/auditType") == "django_config_basic"
    assert responses["pdf"].content.startswith(b"%PDF")
    assert "supersecret" not in responses["markdown"].text
    assert "[REDACTED]" in responses["markdown"].text


@pytest.mark.anyio
async def test_export_django_config_redacts_legacy_secret_values(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    now = datetime(2026, 5, 29, tzinfo=timezone.utc)
    job = JobRecord(
        id="e" * 32,
        audit_type="django_config_basic",
        file_id="4" * 32,
        status="completed",
        created_at=now,
        updated_at=now,
        error="TOKEN=super-secret-value-123",
        result={
            "analyzer": "django_config_basic",
            "archive_type": "zip",
            "summary": {"files_read": 1, "findings_count": 1, "secrets_redacted_count": 0},
            "detected_files": [
                {
                    "path": "project/settings.py",
                    "category": "django_config",
                    "read": False,
                    "skip_reason": "DATABASE_URL=postgres://user:rawpass@db/app",
                }
            ],
            "django_signals": {
                "secret_key": {"status": "SECRET_KEY = 'django-insecure-test-secret'", "files": ["project/settings.py"]},
            },
            "findings": [
                {
                    "id": "legacy_secret",
                    "title": "Legacy raw secret",
                    "level": "medium",
                    "description": "DATABASE_URL=postgres://user:rawpass@db/app",
                    "evidence": "SECRET_KEY = 'super-secret-value-123'",
                    "recommendation": "-----BEGIN PRIVATE KEY-----\nabc123\n-----END PRIVATE KEY-----",
                    "file_path": "project/settings.py",
                    "context": "production<script>TOKEN=super-secret-value-123</script>",
                }
            ],
            "errors": ["PASSWORD=super-secret-value-123"],
        },
    )
    app.state.jobs.save(job)
    expected = {
        "markdown": "text/markdown",
        "html": "text/html",
        "xml": "application/xml",
        "pdf": "application/pdf",
    }
    forbidden = (
        b"super-secret-value-123",
        b"django-insecure-test-secret",
        b"rawpass",
        b"abc123",
        b"BEGIN PRIVATE KEY",
    )
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        responses = {
            report_format: await client.get(f"/jobs/{job.id}/export/{report_format}")
            for report_format in expected
        }

    for report_format, response in responses.items():
        assert response.status_code == 200
        assert response.headers["content-type"].startswith(expected[report_format])
        assert b"REDACTED" in response.content
        for secret in forbidden:
            assert secret not in response.content
    assert "&lt;script&gt;" in responses["html"].text
    assert "<script>" not in responses["html"].text


@pytest.mark.anyio
async def test_export_django_config_jobs_with_sparse_and_incomplete_results(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    now = datetime(2026, 5, 29, tzinfo=timezone.utc)
    jobs = [
        JobRecord(id="1" * 32, audit_type="django_config_basic", file_id="4" * 32, status="queued", created_at=now, updated_at=now),
        JobRecord(id="2" * 32, audit_type="django_config_basic", file_id="4" * 32, status="running", created_at=now, updated_at=now),
        JobRecord(
            id="3" * 32,
            audit_type="django_config_basic",
            file_id="4" * 32,
            status="failed",
            created_at=now,
            updated_at=now,
            error="Django config runner failed safely.",
        ),
        JobRecord(
            id="4" * 32,
            audit_type="django_config_basic",
            file_id="4" * 32,
            status="completed",
            created_at=now,
            updated_at=now,
            result={"analyzer": "django_config_basic", "summary": {}, "findings": [], "errors": []},
        ),
    ]
    for job in jobs:
        app.state.jobs.save(job)
    expected = {
        "markdown": "text/markdown",
        "html": "text/html",
        "xml": "application/xml",
        "pdf": "application/pdf",
    }
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        for job in jobs:
            for report_format, content_type in expected.items():
                response = await client.get(f"/jobs/{job.id}/export/{report_format}")

                assert response.status_code == 200
                assert response.headers["content-type"].startswith(content_type)
                if report_format == "xml":
                    root = ElementTree.fromstring(response.text)
                    assert root.findtext("./job/status") == job.status
                    assert root.findtext("./job/auditType") == "django_config_basic"
                elif report_format == "pdf":
                    assert response.content.startswith(b"%PDF")
                else:
                    assert job.status in response.text
                    assert "django_config_basic" in response.text


@pytest.mark.anyio
async def test_export_docker_config_job_all_formats(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    job = save_docker_config_export_fixture_job()
    expected = {
        "markdown": ("text/markdown", "md"),
        "html": ("text/html", "html"),
        "xml": ("application/xml", "xml"),
        "pdf": ("application/pdf", "pdf"),
    }
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        responses = {
            report_format: await client.get(f"/jobs/{job.id}/export/{report_format}")
            for report_format in expected
        }

    for report_format, response in responses.items():
        content_type, extension = expected[report_format]
        assert response.status_code == 200
        assert response.headers["content-type"].startswith(content_type)
        assert response.headers["content-disposition"] == f'attachment; filename="inspectra-job-{job.id}.{extension}"'
    assert "docker_config_basic" in responses["markdown"].text
    assert "Docker Config Metrics" in responses["html"].text
    assert "Finding 1 Context" in responses["markdown"].text
    assert "production" in responses["markdown"].text
    assert "project/Dockerfile" in responses["markdown"].text
    assert "docker_runs_as_root" in responses["markdown"].text
    assert "USER = root" in responses["markdown"].text
    assert "production" in responses["html"].text
    assert ElementTree.fromstring(responses["xml"].text).findtext("./job/auditType") == "docker_config_basic"
    assert responses["pdf"].content.startswith(b"%PDF")


@pytest.mark.anyio
async def test_export_docker_config_redacts_legacy_secret_values(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    now = datetime(2026, 5, 31, tzinfo=timezone.utc)
    job = JobRecord(
        id="c" * 32,
        audit_type="docker_config_basic",
        file_id="4" * 32,
        status="completed",
        created_at=now,
        updated_at=now,
        error="TOKEN=super-secret-value-123",
        result={
            "analyzer": "docker_config_basic",
            "archive_type": "zip",
            "summary": {"files_reviewed": 1, "findings_count": 1, "secrets_redacted_count": 0},
            "files_detected": [
                {
                    "path": "docker-compose.yml",
                    "category": "compose",
                    "read": True,
                    "skip_reason": "DATABASE_URL=postgres://user:rawpass@db/app",
                }
            ],
            "findings": [
                {
                    "id": "legacy_secret",
                    "title": "Legacy raw secret",
                    "level": "medium",
                    "description": "API_KEY=super-secret-value-123",
                    "evidence": "SECRET_KEY = 'super-secret-value-123'",
                    "recommendation": "PRIVATE_KEY=-----BEGIN PRIVATE KEY-----abc123-----END PRIVATE KEY-----",
                    "file_path": "docker-compose.yml",
                    "context": "production<script>TOKEN=super-secret-value-123</script>",
                }
            ],
            "errors": ["PASSWORD=super-secret-value-123"],
        },
    )
    app.state.jobs.save(job)
    expected = {
        "markdown": "text/markdown",
        "html": "text/html",
        "xml": "application/xml",
        "pdf": "application/pdf",
    }
    forbidden = (
        b"super-secret-value-123",
        b"rawpass",
        b"abc123",
        b"BEGIN PRIVATE KEY",
    )
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        responses = {
            report_format: await client.get(f"/jobs/{job.id}/export/{report_format}")
            for report_format in expected
        }

    for report_format, response in responses.items():
        assert response.status_code == 200
        assert response.headers["content-type"].startswith(expected[report_format])
        assert b"REDACTED" in response.content
        for secret in forbidden:
            assert secret not in response.content
    assert "&lt;script&gt;" in responses["html"].text
    assert "<script>" not in responses["html"].text


@pytest.mark.anyio
async def test_export_docker_config_jobs_with_sparse_and_incomplete_results(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    now = datetime(2026, 5, 31, tzinfo=timezone.utc)
    jobs = [
        JobRecord(id="5" * 32, audit_type="docker_config_basic", file_id="4" * 32, status="queued", created_at=now, updated_at=now),
        JobRecord(id="6" * 32, audit_type="docker_config_basic", file_id="4" * 32, status="running", created_at=now, updated_at=now),
        JobRecord(
            id="7" * 32,
            audit_type="docker_config_basic",
            file_id="4" * 32,
            status="failed",
            created_at=now,
            updated_at=now,
            error="Docker config runner failed safely.",
        ),
        JobRecord(
            id="9" * 32,
            audit_type="docker_config_basic",
            file_id="4" * 32,
            status="completed",
            created_at=now,
            updated_at=now,
            result={"analyzer": "docker_config_basic", "summary": {}, "findings": [], "errors": []},
        ),
    ]
    for job in jobs:
        app.state.jobs.save(job)
    expected = {
        "markdown": "text/markdown",
        "html": "text/html",
        "xml": "application/xml",
        "pdf": "application/pdf",
    }
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        for job in jobs:
            for report_format, content_type in expected.items():
                response = await client.get(f"/jobs/{job.id}/export/{report_format}")

                assert response.status_code == 200
                assert response.headers["content-type"].startswith(content_type)
                if report_format == "xml":
                    root = ElementTree.fromstring(response.text)
                    assert root.findtext("./job/status") == job.status
                    assert root.findtext("./job/auditType") == "docker_config_basic"
                elif report_format == "pdf":
                    assert response.content.startswith(b"%PDF")
                else:
                    assert job.status in response.text
                    assert "docker_config_basic" in response.text


@pytest.mark.anyio
async def test_secrets_review_job_summary_and_export_all_formats(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    job = save_secrets_review_export_fixture_job()
    expected = {
        "markdown": ("text/markdown", "md"),
        "html": ("text/html", "html"),
        "xml": ("application/xml", "xml"),
        "pdf": ("application/pdf", "pdf"),
    }
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        list_response = await client.get("/jobs")
        responses = {
            report_format: await client.get(f"/jobs/{job.id}/export/{report_format}")
            for report_format in expected
        }

    summary = list_response.json()[0]["summary"]
    assert summary["analyzer"] == "secrets_review_basic"
    assert summary["files_considered"] == 3
    assert summary["files_reviewed"] == 2
    assert summary["sensitive_files_detected"] == 1
    assert summary["findings_count"] == 2
    assert summary["high_confidence_count"] == 1
    assert summary["redacted_values_count"] == 2
    assert summary["truncated"] is False
    assert summary["errors_count"] == 0
    for report_format, response in responses.items():
        content_type, extension = expected[report_format]
        assert response.status_code == 200
        assert response.headers["content-type"].startswith(content_type)
        assert response.headers["content-disposition"] == f'attachment; filename="inspectra-job-{job.id}.{extension}"'
    assert "secrets_review_basic" in responses["markdown"].text
    assert "Secrets Review Metrics" in responses["html"].text
    assert "Sensitive Files Detected But Not Read" in responses["markdown"].text
    assert "Finding 1 Confidence" in responses["markdown"].text
    assert "Finding 1 Category" in responses["markdown"].text
    assert "project/settings.py" in responses["markdown"].text
    assert "SECRET_KEY=[REDACTED]" in responses["markdown"].text
    assert "production" in responses["html"].text
    assert ElementTree.fromstring(responses["xml"].text).findtext("./job/auditType") == "secrets_review_basic"
    assert responses["pdf"].content.startswith(b"%PDF")


@pytest.mark.anyio
async def test_export_secrets_review_redacts_legacy_secret_values(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    now = datetime(2026, 5, 31, tzinfo=timezone.utc)
    private_key = "-----BEGIN PRIVATE KEY-----\nfixture-private-key-material\n-----END PRIVATE KEY-----"
    jwt_value = "eyJhbGciOiJIUzI1NiJ9.fixture.fixture"
    job = JobRecord(
        id="d" * 32,
        audit_type="secrets_review_basic",
        file_id="4" * 32,
        status="completed",
        created_at=now,
        updated_at=now,
        error="TOKEN=fixture-secret-token",
        result={
            "analyzer": "secrets_review_basic",
            "archive_type": "zip",
            "summary": {"files_reviewed": 1, "findings_count": 1, "redacted_values_count": 0},
            "raw_secret": "fixture-secret-key-value",
            "sensitive_files": [
                {
                    "path": ".env.production?token=fixture-query-token&key=fixture-query-key",
                    "category": "env_sensitive",
                    "read": False,
                    "skip_reason": "SECRET_KEY=fixture-secret-key",
                }
            ],
            "files_detected": [{"path": "settings.py", "skip_reason": "DATABASE_URL=postgres://user:fixture-pass@db/app"}],
            "findings": [
                {
                    "id": "legacy_secret",
                    "title": "Legacy raw secret",
                    "level": "medium",
                    "confidence": "high",
                    "category": "secret_assignment",
                    "description": f"SECRET_KEY=fixture-secret-key and JWT {jwt_value}",
                    "evidence": "DATABASE_URL=postgres://user:fixture-pass@db/app",
                    "recommendation": f"Rotate {private_key}",
                    "file_path": "settings.py",
                    "context": "production<script>API_KEY=fixture-secret-key</script>",
                    "line": "12",
                    "raw_secret": "fixture-secret-key-value",
                }
            ],
            "errors": ["REDIS_URL=redis://:fixture-pass@redis:6379/0"],
            "redaction_notes": ["Webhook https://example.test/hook?token=fixture-query-token&key=fixture-query-key"],
        },
    )
    app.state.jobs.save(job)
    expected = {
        "markdown": "text/markdown",
        "html": "text/html",
        "xml": "application/xml",
        "pdf": "application/pdf",
    }
    forbidden = (
        b"fixture-secret-token",
        b"fixture-secret-key",
        b"fixture-pass",
        b"fixture-secret-key-value",
        b"fixture-private-key-material",
        b"BEGIN PRIVATE KEY",
        b"eyJhbGciOiJIUzI1NiJ9.fixture.fixture",
        b"fixture-query-token",
        b"fixture-query-key",
    )
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        responses = {
            report_format: await client.get(f"/jobs/{job.id}/export/{report_format}")
            for report_format in expected
        }

    for report_format, response in responses.items():
        assert response.status_code == 200
        assert response.headers["content-type"].startswith(expected[report_format])
        assert b"REDACTED" in response.content
        for secret in forbidden:
            assert secret not in response.content
    assert "&lt;script&gt;" in responses["html"].text
    assert "<script>" not in responses["html"].text


@pytest.mark.anyio
async def test_export_secrets_review_jobs_with_sparse_and_incomplete_results(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    now = datetime(2026, 5, 31, tzinfo=timezone.utc)
    jobs = [
        JobRecord(id="e" * 32, audit_type="secrets_review_basic", file_id="4" * 32, status="queued", created_at=now, updated_at=now),
        JobRecord(id="f" * 32, audit_type="secrets_review_basic", file_id="4" * 32, status="running", created_at=now, updated_at=now),
        JobRecord(
            id="a" * 31 + "1",
            audit_type="secrets_review_basic",
            file_id="4" * 32,
            status="failed",
            created_at=now,
            updated_at=now,
            error="Secrets review runner failed safely.",
        ),
        JobRecord(
            id="a" * 31 + "2",
            audit_type="secrets_review_basic",
            file_id="4" * 32,
            status="completed",
            created_at=now,
            updated_at=now,
            result={"analyzer": "secrets_review_basic", "summary": {}, "findings": [], "errors": []},
        ),
    ]
    for job in jobs:
        app.state.jobs.save(job)
    expected = {
        "markdown": "text/markdown",
        "html": "text/html",
        "xml": "application/xml",
        "pdf": "application/pdf",
    }
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        for job in jobs:
            for report_format, content_type in expected.items():
                response = await client.get(f"/jobs/{job.id}/export/{report_format}")

                assert response.status_code == 200
                assert response.headers["content-type"].startswith(content_type)
                if report_format == "xml":
                    root = ElementTree.fromstring(response.text)
                    assert root.findtext("./job/status") == job.status
                    assert root.findtext("./job/auditType") == "secrets_review_basic"
                elif report_format == "pdf":
                    assert response.content.startswith(b"%PDF")
                else:
                    assert job.status in response.text
                    assert "secrets_review_basic" in response.text


@pytest.mark.anyio
async def test_node_package_config_job_summary_and_export_all_formats(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    job = save_node_package_config_export_fixture_job()
    expected = {
        "markdown": ("text/markdown", "md"),
        "html": ("text/html", "html"),
        "xml": ("application/xml", "xml"),
        "pdf": ("application/pdf", "pdf"),
    }
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        list_response = await client.get("/jobs")
        responses = {
            report_format: await client.get(f"/jobs/{job.id}/export/{report_format}")
            for report_format in expected
        }

    summary = list_response.json()[0]["summary"]
    assert summary["analyzer"] == "node_package_config_basic"
    assert summary["files_considered"] == 5
    assert summary["files_reviewed"] == 4
    assert summary["package_manifests_detected"] == 1
    assert summary["lockfiles_detected"] == 1
    assert summary["package_manager_configs_detected"] == 1
    assert summary["packages_detected"] == 1
    assert summary["scripts_detected"] == 2
    assert summary["findings_count"] == 2
    assert summary["redacted_values_count"] == 1
    assert summary["truncated"] is False
    assert summary["errors_count"] == 0
    for report_format, response in responses.items():
        content_type, extension = expected[report_format]
        assert response.status_code == 200
        assert response.headers["content-type"].startswith(content_type)
        assert response.headers["content-disposition"] == f'attachment; filename="inspectra-job-{job.id}.{extension}"'
    assert "node_package_config_basic" in responses["markdown"].text
    assert "Node Package Config Metrics" in responses["html"].text
    assert "Package Workspace Overview" in responses["markdown"].text
    assert "Dependency Groups" in responses["markdown"].text
    assert "Finding 1 Confidence" in responses["markdown"].text
    assert "Finding 1 Category" in responses["markdown"].text
    assert "project/package.json" in responses["markdown"].text
    assert "postinstall_script_present" in responses["markdown"].text
    assert "postinstall" in responses["markdown"].text
    assert "shared" in responses["html"].text
    assert ElementTree.fromstring(responses["xml"].text).findtext("./job/auditType") == "node_package_config_basic"
    assert responses["pdf"].content.startswith(b"%PDF")


@pytest.mark.anyio
async def test_export_node_package_config_redacts_legacy_secret_values(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    now = datetime(2026, 5, 31, tzinfo=timezone.utc)
    job = JobRecord(
        id="b" * 31 + "2",
        audit_type="node_package_config_basic",
        file_id="4" * 32,
        status="completed",
        created_at=now,
        updated_at=now,
        error="_authToken=fixture-token",
        result={
            "analyzer": "node_package_config_basic",
            "archive_type": "zip",
            "summary": {"files_reviewed": 1, "findings_count": 1, "redacted_values_count": 0},
            "package_manager_config_signals": [
                {
                    "path": ".npmrc",
                    "key": "_authToken",
                    "value": "fixture-token",
                    "registry": "https://user:fixture-password@registry.example.test/pkg",
                }
            ],
            "findings": [
                {
                    "id": "legacy_node_secret",
                    "title": "Legacy raw token",
                    "level": "medium",
                    "confidence": "high",
                    "category": "package_manager_config",
                    "description": "_auth=fixture-auth",
                    "evidence": "https://example.test/hook?token=fixture-token&key=fixture-key",
                    "recommendation": "API_KEY=fixture-key npm run build",
                    "file_path": ".npmrc",
                    "context": "shared<script>secret=fixture-secret</script>",
                    "line": "3",
                }
            ],
            "errors": ["password=fixture-password"],
            "redaction_notes": ["token=fixture-token"],
        },
    )
    app.state.jobs.save(job)
    expected = {
        "markdown": "text/markdown",
        "html": "text/html",
        "xml": "application/xml",
        "pdf": "application/pdf",
    }
    forbidden = (
        b"fixture-token",
        b"fixture-auth",
        b"fixture-password",
        b"fixture-key",
        b"fixture-secret",
    )
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        responses = {
            report_format: await client.get(f"/jobs/{job.id}/export/{report_format}")
            for report_format in expected
        }

    for report_format, response in responses.items():
        assert response.status_code == 200
        assert response.headers["content-type"].startswith(expected[report_format])
        assert b"REDACTED" in response.content
        for secret in forbidden:
            assert secret not in response.content
    assert "_authToken" in responses["markdown"].text
    assert "_authToken" in responses["html"].text
    assert "_authToken" in responses["xml"].text
    assert "&lt;script&gt;" in responses["html"].text
    assert "<script>" not in responses["html"].text


@pytest.mark.anyio
async def test_export_node_package_config_jobs_with_sparse_and_incomplete_results(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    now = datetime(2026, 5, 31, tzinfo=timezone.utc)
    jobs = [
        JobRecord(id="b" * 31 + "3", audit_type="node_package_config_basic", file_id="4" * 32, status="queued", created_at=now, updated_at=now),
        JobRecord(id="b" * 31 + "4", audit_type="node_package_config_basic", file_id="4" * 32, status="running", created_at=now, updated_at=now),
        JobRecord(
            id="b" * 31 + "5",
            audit_type="node_package_config_basic",
            file_id="4" * 32,
            status="failed",
            created_at=now,
            updated_at=now,
            error="Node package config runner failed safely.",
        ),
        JobRecord(
            id="b" * 31 + "6",
            audit_type="node_package_config_basic",
            file_id="4" * 32,
            status="completed",
            created_at=now,
            updated_at=now,
            result={"analyzer": "node_package_config_basic", "summary": {}, "findings": [], "errors": []},
        ),
    ]
    for job in jobs:
        app.state.jobs.save(job)
    expected = {
        "markdown": "text/markdown",
        "html": "text/html",
        "xml": "application/xml",
        "pdf": "application/pdf",
    }
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        for job in jobs:
            for report_format, content_type in expected.items():
                response = await client.get(f"/jobs/{job.id}/export/{report_format}")

                assert response.status_code == 200
                assert response.headers["content-type"].startswith(content_type)
                if report_format == "xml":
                    root = ElementTree.fromstring(response.text)
                    assert root.findtext("./job/status") == job.status
                    assert root.findtext("./job/auditType") == "node_package_config_basic"
                elif report_format == "pdf":
                    assert response.content.startswith(b"%PDF")
                else:
                    assert job.status in response.text
                    assert "node_package_config_basic" in response.text


@pytest.mark.anyio
async def test_ci_cd_config_job_summary_and_export_all_formats(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    job = save_ci_cd_config_export_fixture_job()
    expected = {
        "markdown": ("text/markdown", "md"),
        "html": ("text/html", "html"),
        "xml": ("application/xml", "xml"),
        "pdf": ("application/pdf", "pdf"),
    }
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        list_response = await client.get("/jobs")
        responses = {
            report_format: await client.get(f"/jobs/{job.id}/export/{report_format}")
            for report_format in expected
        }

    summary = list_response.json()[0]["summary"]
    assert summary["analyzer"] == "ci_cd_config_basic"
    assert summary["files_considered"] == 4
    assert summary["files_reviewed"] == 3
    assert summary["workflow_files_detected"] == 2
    assert summary["jobs_detected"] == 2
    assert summary["steps_detected"] == 4
    assert summary["triggers_detected"] == 2
    assert summary["findings_count"] == 2
    assert summary["redacted_values_count"] == 1
    assert summary["truncated"] is False
    assert summary["errors_count"] == 0
    for report_format, response in responses.items():
        content_type, extension = expected[report_format]
        assert response.status_code == 200
        assert response.headers["content-type"].startswith(content_type)
        assert response.headers["content-disposition"] == f'attachment; filename="inspectra-job-{job.id}.{extension}"'
    assert "ci_cd_config_basic" in responses["markdown"].text
    assert "CI/CD Config Metrics" in responses["html"].text
    assert "Workflow Overview" in responses["markdown"].text
    assert "Actions / Images" in responses["markdown"].text
    assert "Finding 1 Confidence" in responses["markdown"].text
    assert "Finding 1 Provider" in responses["markdown"].text
    assert "Finding 1 Job" in responses["markdown"].text
    assert "Finding 1 Step" in responses["markdown"].text
    assert ".github/workflows/release.yml" in responses["markdown"].text
    assert "pull_request_target_used" in responses["markdown"].text
    assert "production" in responses["html"].text
    assert ElementTree.fromstring(responses["xml"].text).findtext("./job/auditType") == "ci_cd_config_basic"
    assert responses["pdf"].content.startswith(b"%PDF")


@pytest.mark.anyio
async def test_export_ci_cd_config_redacts_legacy_secret_values(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    now = datetime(2026, 5, 31, tzinfo=timezone.utc)
    job = JobRecord(
        id="c" * 31 + "8",
        audit_type="ci_cd_config_basic",
        file_id="4" * 32,
        status="completed",
        created_at=now,
        updated_at=now,
        error="TOKEN=fixture-token",
        result={
            "analyzer": "ci_cd_config_basic",
            "archive_type": "zip",
            "summary": {"files_reviewed": 1, "findings_count": 1, "redacted_values_count": 0},
            "jobs": [
                {
                    "file_path": ".github/workflows/deploy.yml",
                    "provider": "github_actions",
                    "job": "deploy",
                    "script": 'API_KEY=fixture-key npm run deploy && echo "Authorization: Bearer token_should_never_render"',
                }
            ],
            "actions": [
                {
                    "file_path": ".github/workflows/deploy.yml",
                    "provider": "github_actions",
                    "action": "owner/deploy",
                    "ref": "main",
                    "token": "fixture-token",
                    "url": "https://user:fixture-password@ci.example.test/hook",
                }
            ],
            "publish_deploy_signals": [
                {
                    "file_path": ".github/workflows/deploy.yml",
                    "provider": "github_actions",
                    "signal": "https://example.test/deploy?token=fixture-token&key=fixture-key",
                }
            ],
            "findings": [
                {
                    "id": "legacy_ci_secret",
                    "title": "Legacy raw token",
                    "level": "medium",
                    "confidence": "high",
                    "category": "secrets_env",
                    "provider": "github_actions",
                    "description": "CLIENT_SECRET=fixture-secret",
                    "evidence": "PASSWORD=fixture-password",
                    "recommendation": "-----BEGIN PRIVATE KEY----- fixture-private-key-material -----END PRIVATE KEY-----",
                    "file_path": ".github/workflows/deploy.yml",
                    "context": "production<script>secret=fixture-secret</script>",
                    "job": "deploy",
                    "step": "publish",
                    "line": "7",
                }
            ],
            "errors": ["API_KEY=fixture-key", "Authorization: Bearer token_should_never_render"],
            "redaction_notes": ["TOKEN=fixture-token"],
        },
    )
    app.state.jobs.save(job)
    expected = {
        "markdown": "text/markdown",
        "html": "text/html",
        "xml": "application/xml",
        "pdf": "application/pdf",
    }
    forbidden = (
        b"fixture-token",
        b"fixture-password",
        b"fixture-key",
        b"fixture-secret",
        b"fixture-private-key-material",
        b"BEGIN PRIVATE KEY",
        b"token_should_never_render",
        b"Authorization: Bearer token_should_never_render",
    )
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        api_response = await client.get(f"/jobs/{job.id}")
        responses = {
            report_format: await client.get(f"/jobs/{job.id}/export/{report_format}")
            for report_format in expected
        }

    assert api_response.status_code == 200
    assert b"REDACTED" in api_response.content
    for secret in forbidden:
        assert secret not in api_response.content
    for report_format, response in responses.items():
        assert response.status_code == 200
        assert response.headers["content-type"].startswith(expected[report_format])
        assert b"REDACTED" in response.content
        for secret in forbidden:
            assert secret not in response.content
    assert "&lt;script&gt;" in responses["html"].text
    assert "<script>" not in responses["html"].text


@pytest.mark.anyio
async def test_export_ci_cd_config_jobs_with_sparse_and_incomplete_results(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    now = datetime(2026, 5, 31, tzinfo=timezone.utc)
    jobs = [
        JobRecord(id="c" * 31 + "9", audit_type="ci_cd_config_basic", file_id="4" * 32, status="queued", created_at=now, updated_at=now),
        JobRecord(id="d" * 31 + "1", audit_type="ci_cd_config_basic", file_id="4" * 32, status="running", created_at=now, updated_at=now),
        JobRecord(
            id="d" * 31 + "2",
            audit_type="ci_cd_config_basic",
            file_id="4" * 32,
            status="failed",
            created_at=now,
            updated_at=now,
            error="CI/CD config runner failed safely.",
        ),
        JobRecord(
            id="d" * 31 + "3",
            audit_type="ci_cd_config_basic",
            file_id="4" * 32,
            status="completed",
            created_at=now,
            updated_at=now,
            result={"analyzer": "ci_cd_config_basic", "summary": {}, "findings": [], "errors": []},
        ),
    ]
    for job in jobs:
        app.state.jobs.save(job)
    expected = {
        "markdown": "text/markdown",
        "html": "text/html",
        "xml": "application/xml",
        "pdf": "application/pdf",
    }
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        for job in jobs:
            for report_format, content_type in expected.items():
                response = await client.get(f"/jobs/{job.id}/export/{report_format}")

                assert response.status_code == 200
                assert response.headers["content-type"].startswith(content_type)
                if report_format == "xml":
                    root = ElementTree.fromstring(response.text)
                    assert root.findtext("./job/status") == job.status
                    assert root.findtext("./job/auditType") == "ci_cd_config_basic"
                elif report_format == "pdf":
                    assert response.content.startswith(b"%PDF")
                else:
                    assert job.status in response.text
                    assert "ci_cd_config_basic" in response.text


@pytest.mark.anyio
async def test_k8s_config_job_summary_and_export_all_formats(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    job = save_k8s_config_export_fixture_job()
    expected = {
        "markdown": ("text/markdown", "md"),
        "html": ("text/html", "html"),
        "xml": ("application/xml", "xml"),
        "pdf": ("application/pdf", "pdf"),
    }
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        list_response = await client.get("/jobs")
        responses = {
            report_format: await client.get(f"/jobs/{job.id}/export/{report_format}")
            for report_format in expected
        }

    summary = list_response.json()[0]["summary"]
    assert summary["analyzer"] == "k8s_config_basic"
    assert summary["files_considered"] == 4
    assert summary["files_reviewed"] == 3
    assert summary["manifest_files_detected"] == 3
    assert summary["resources_detected"] == 4
    assert summary["workloads_detected"] == 1
    assert summary["services_detected"] == 1
    assert summary["secrets_detected"] == 1
    assert summary["rbac_resources_detected"] == 1
    assert summary["findings_count"] == 2
    assert summary["redacted_values_count"] == 2
    assert summary["truncated"] is False
    assert summary["errors_count"] == 0
    for report_format, response in responses.items():
        content_type, extension = expected[report_format]
        assert response.status_code == 200
        assert response.headers["content-type"].startswith(content_type)
        assert response.headers["content-disposition"] == f'attachment; filename="inspectra-job-{job.id}.{extension}"'
    assert "k8s_config_basic" in responses["markdown"].text
    assert "Kubernetes Config Metrics" in responses["html"].text
    assert "Resource Overview" in responses["markdown"].text
    assert "Helm / Kustomize Signals" in responses["markdown"].text
    assert "Finding 1 Kind" in responses["markdown"].text
    assert "Finding 1 Resource name" in responses["markdown"].text
    assert "Finding 1 Field path" in responses["markdown"].text
    assert "deploy/production/app.yaml" in responses["markdown"].text
    assert "privileged_container" in responses["markdown"].text
    assert "production" in responses["html"].text
    assert ElementTree.fromstring(responses["xml"].text).findtext("./job/auditType") == "k8s_config_basic"
    assert responses["pdf"].content.startswith(b"%PDF")


@pytest.mark.anyio
async def test_export_k8s_config_redacts_legacy_secret_values(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    now = datetime(2026, 5, 31, tzinfo=timezone.utc)
    job = JobRecord(
        id="e" * 31 + "8",
        audit_type="k8s_config_basic",
        file_id="4" * 32,
        status="completed",
        created_at=now,
        updated_at=now,
        error="PASSWORD=super-secret-password",
        result={
            "analyzer": "k8s_config_basic",
            "archive_type": "zip",
            "summary": {"files_reviewed": 1, "findings_count": 1, "redacted_values_count": 0},
            "resources": [
                {
                    "kind": "Secret",
                    "name": "app-secret",
                    "namespace": "production",
                    "stringData": {"password": "super-secret-password", "privateKey": "-----BEGIN PRIVATE KEY----- db_password_plaintext -----END PRIVATE KEY-----"},
                    "data": {"token": "token_should_never_render"},
                }
            ],
            "containers": [
                {
                    "container": "app",
                    "env": [{"name": "API_KEY", "value": "raw-api-key-123456"}],
                    "image": "registry-user:registry-pass/k8s-app:latest",
                    "registry": "https://registry-user:registry-pass@registry.example.test/app",
                }
            ],
            "secrets": [
                {
                    "kind": "Secret",
                    "name": "app-secret",
                    "data": "password=db_password_plaintext",
                    "stringData": "TOKEN=token_should_never_render",
                }
            ],
            "findings": [
                {
                    "id": "legacy_k8s_secret",
                    "title": "Legacy raw secret",
                    "level": "medium",
                    "confidence": "high",
                    "category": "secrets",
                    "description": "CLIENT_SECRET=token_should_never_render",
                    "evidence": "PASSWORD=super-secret-password",
                    "recommendation": "-----BEGIN PRIVATE KEY----- db_password_plaintext -----END PRIVATE KEY-----",
                    "file_path": "deploy/app.yaml",
                    "context": "production<script>API_KEY=raw-api-key-123456</script>",
                    "kind": "Secret",
                    "resource_name": "app-secret",
                    "namespace": "production",
                    "field_path": "stringData.password",
                }
            ],
            "errors": ["API_KEY=raw-api-key-123456", "TOKEN=token_should_never_render"],
            "redaction_notes": ["PASSWORD=super-secret-password"],
        },
    )
    app.state.jobs.save(job)
    expected = {
        "markdown": "text/markdown",
        "html": "text/html",
        "xml": "application/xml",
        "pdf": "application/pdf",
    }
    forbidden = (
        b"super-secret-password",
        b"raw-api-key-123456",
        b"token_should_never_render",
        b"PRIVATE KEY",
        b"db_password_plaintext",
        b"registry-user:registry-pass",
    )
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        api_response = await client.get(f"/jobs/{job.id}")
        responses = {
            report_format: await client.get(f"/jobs/{job.id}/export/{report_format}")
            for report_format in expected
        }

    assert api_response.status_code == 200
    assert b"REDACTED" in api_response.content
    for secret in forbidden:
        assert secret not in api_response.content
    for report_format, response in responses.items():
        assert response.status_code == 200
        assert response.headers["content-type"].startswith(expected[report_format])
        assert b"REDACTED" in response.content
        for secret in forbidden:
            assert secret not in response.content
    assert "&lt;script&gt;" in responses["html"].text
    assert "<script>" not in responses["html"].text


@pytest.mark.anyio
async def test_export_k8s_config_jobs_with_sparse_and_incomplete_results(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    now = datetime(2026, 5, 31, tzinfo=timezone.utc)
    jobs = [
        JobRecord(id="e" * 31 + "9", audit_type="k8s_config_basic", file_id="4" * 32, status="queued", created_at=now, updated_at=now),
        JobRecord(id="f" * 31 + "1", audit_type="k8s_config_basic", file_id="4" * 32, status="running", created_at=now, updated_at=now),
        JobRecord(
            id="f" * 31 + "2",
            audit_type="k8s_config_basic",
            file_id="4" * 32,
            status="failed",
            created_at=now,
            updated_at=now,
            error="Kubernetes config runner failed safely.",
        ),
        JobRecord(
            id="f" * 31 + "3",
            audit_type="k8s_config_basic",
            file_id="4" * 32,
            status="completed",
            created_at=now,
            updated_at=now,
            result={"analyzer": "k8s_config_basic", "summary": {}, "findings": [{"id": "sparse"}], "errors": []},
        ),
    ]
    for job in jobs:
        app.state.jobs.save(job)
    expected = {
        "markdown": "text/markdown",
        "html": "text/html",
        "xml": "application/xml",
        "pdf": "application/pdf",
    }
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        for job in jobs:
            for report_format, content_type in expected.items():
                response = await client.get(f"/jobs/{job.id}/export/{report_format}")

                assert response.status_code == 200
                assert response.headers["content-type"].startswith(content_type)
                if report_format == "xml":
                    root = ElementTree.fromstring(response.text)
                    assert root.findtext("./job/status") == job.status
                    assert root.findtext("./job/auditType") == "k8s_config_basic"
                elif report_format == "pdf":
                    assert response.content.startswith(b"%PDF")
                else:
                    assert job.status in response.text
                    assert "k8s_config_basic" in response.text


@pytest.mark.anyio
async def test_terraform_config_job_summary_and_export_all_formats(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    job = save_terraform_config_export_fixture_job()
    expected = {
        "markdown": ("text/markdown", "md"),
        "html": ("text/html", "html"),
        "xml": ("application/xml", "xml"),
        "pdf": ("application/pdf", "pdf"),
    }
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        list_response = await client.get("/jobs")
        responses = {
            report_format: await client.get(f"/jobs/{job.id}/export/{report_format}")
            for report_format in expected
        }

    summary = list_response.json()[0]["summary"]
    assert summary["analyzer"] == "terraform_config_basic"
    assert summary["files_considered"] == 5
    assert summary["files_reviewed"] == 3
    assert summary["terraform_files_detected"] == 2
    assert summary["tfvars_files_detected"] == 1
    assert summary["state_files_detected"] == 1
    assert summary["providers_detected"] == 1
    assert summary["backends_detected"] == 1
    assert summary["modules_detected"] == 1
    assert summary["resources_detected"] == 2
    assert summary["findings_count"] == 2
    assert summary["redacted_values_count"] == 2
    assert summary["truncated"] is False
    assert summary["errors_count"] == 0
    for report_format, response in responses.items():
        content_type, extension = expected[report_format]
        assert response.status_code == 200
        assert response.headers["content-type"].startswith(content_type)
        assert response.headers["content-disposition"] == f'attachment; filename="inspectra-job-{job.id}.{extension}"'
    assert "terraform_config_basic" in responses["markdown"].text
    assert "Terraform Config Metrics" in responses["html"].text
    assert "Providers" in responses["markdown"].text
    assert "Backends" in responses["markdown"].text
    assert "Modules" in responses["markdown"].text
    assert "State Files Detected But Not Read" in responses["markdown"].text
    assert "Finding 1 Provider" in responses["markdown"].text
    assert "Finding 1 Resource type" in responses["markdown"].text
    assert "Finding 1 Field path" in responses["markdown"].text
    assert "infra/prod/main.tf" in responses["markdown"].text
    assert "aws_security_group_ssh_open_world" in responses["markdown"].text
    assert ElementTree.fromstring(responses["xml"].text).findtext("./job/auditType") == "terraform_config_basic"
    assert responses["pdf"].content.startswith(b"%PDF")


@pytest.mark.anyio
async def test_export_terraform_config_redacts_legacy_secret_values(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    now = datetime(2026, 5, 31, tzinfo=timezone.utc)
    job = JobRecord(
        id="f" * 31 + "8",
        audit_type="terraform_config_basic",
        file_id="4" * 32,
        status="completed",
        created_at=now,
        updated_at=now,
        error="PASSWORD=super-secret-password",
        result={
            "analyzer": "terraform_config_basic",
            "archive_type": "zip",
            "summary": {"files_reviewed": 1, "findings_count": 1, "redacted_values_count": 0},
            "providers": [{"name": "aws", "access_key": "AKIAIOSFODNN7EXAMPLE", "secret_key": "aws_secret_access_key_should_not_render"}],
            "backends": [{"type": "s3", "secret_key": "aws_secret_access_key_should_not_render"}],
            "modules": [{"name": "app", "source": "https://user:pass@example.com/db"}],
            "resources": [
                {
                    "resource_type": "aws_instance",
                    "resource_name": "app",
                    "user_data": "TOKEN=token_should_never_render\npostgres://user:pass@example.com/db\nregistry-user:registry-pass",
                }
            ],
            "variables": [{"name": "db_password", "default": "db_password_plaintext"}],
            "outputs": [{"name": "api_key", "value": "raw-api-key-123456", "sensitive": False}],
            "state_files": [
                {
                    "path": "terraform.tfstate",
                    "read": False,
                    "content": "super-secret-password raw-api-key-123456 token_should_never_render",
                }
            ],
            "findings": [
                {
                    "id": "legacy_terraform_secret",
                    "title": "Legacy raw secret",
                    "level": "medium",
                    "confidence": "high",
                    "category": "secrets",
                    "description": "CLIENT_SECRET=token_should_never_render",
                    "evidence": "PASSWORD=super-secret-password",
                    "recommendation": "-----BEGIN PRIVATE KEY----- PRIVATE KEY db_password_plaintext -----END PRIVATE KEY-----",
                    "file_path": "infra/prod/main.tf",
                    "context": "production<script>API_KEY=raw-api-key-123456</script>",
                    "provider": "aws",
                    "resource_type": "aws_instance",
                    "resource_name": "app",
                    "field_path": "user_data",
                }
            ],
            "errors": [
                "API_KEY=raw-api-key-123456",
                "AWS_SECRET_ACCESS_KEY=aws_secret_access_key_should_not_render",
                "postgres://user:pass@example.com/db",
                "registry-user:registry-pass",
            ],
            "redaction_notes": ["TOKEN=token_should_never_render"],
        },
    )
    app.state.jobs.save(job)
    expected = {
        "markdown": "text/markdown",
        "html": "text/html",
        "xml": "application/xml",
        "pdf": "application/pdf",
    }
    forbidden = (
        b"super-secret-password",
        b"raw-api-key-123456",
        b"token_should_never_render",
        b"PRIVATE KEY",
        b"db_password_plaintext",
        b"AKIAIOSFODNN7EXAMPLE",
        b"aws_secret_access_key_should_not_render",
        b"postgres://user:pass@example.com/db",
        b"registry-user:registry-pass",
    )
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        api_response = await client.get(f"/jobs/{job.id}")
        responses = {
            report_format: await client.get(f"/jobs/{job.id}/export/{report_format}")
            for report_format in expected
        }

    assert api_response.status_code == 200
    assert b"REDACTED" in api_response.content
    for secret in forbidden:
        assert secret not in api_response.content
    for report_format, response in responses.items():
        assert response.status_code == 200
        assert response.headers["content-type"].startswith(expected[report_format])
        assert b"REDACTED" in response.content
        for secret in forbidden:
            assert secret not in response.content
    assert "&lt;script&gt;" in responses["html"].text
    assert "<script>" not in responses["html"].text


@pytest.mark.anyio
async def test_export_terraform_config_jobs_with_sparse_and_incomplete_results(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    now = datetime(2026, 5, 31, tzinfo=timezone.utc)
    jobs = [
        JobRecord(id="f" * 31 + "9", audit_type="terraform_config_basic", file_id="4" * 32, status="queued", created_at=now, updated_at=now),
        JobRecord(id="a" * 31 + "3", audit_type="terraform_config_basic", file_id="4" * 32, status="running", created_at=now, updated_at=now),
        JobRecord(
            id="a" * 31 + "4",
            audit_type="terraform_config_basic",
            file_id="4" * 32,
            status="failed",
            created_at=now,
            updated_at=now,
            error="Terraform config runner failed safely.",
        ),
        JobRecord(
            id="a" * 31 + "5",
            audit_type="terraform_config_basic",
            file_id="4" * 32,
            status="completed",
            created_at=now,
            updated_at=now,
            result={"analyzer": "terraform_config_basic", "summary": {}, "findings": [{"id": "sparse"}], "errors": []},
        ),
    ]
    for job in jobs:
        app.state.jobs.save(job)
    expected = {
        "markdown": "text/markdown",
        "html": "text/html",
        "xml": "application/xml",
        "pdf": "application/pdf",
    }
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        for job in jobs:
            for report_format, content_type in expected.items():
                response = await client.get(f"/jobs/{job.id}/export/{report_format}")

                assert response.status_code == 200
                assert response.headers["content-type"].startswith(content_type)
                if report_format == "xml":
                    root = ElementTree.fromstring(response.text)
                    assert root.findtext("./job/status") == job.status
                    assert root.findtext("./job/auditType") == "terraform_config_basic"
                elif report_format == "pdf":
                    assert response.content.startswith(b"%PDF")
                else:
                    assert job.status in response.text
                    assert "terraform_config_basic" in response.text


@pytest.mark.anyio
async def test_nginx_config_job_summary_and_export_all_formats(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    job = save_nginx_config_export_fixture_job()
    expected = {
        "markdown": ("text/markdown", "md"),
        "html": ("text/html", "html"),
        "xml": ("application/xml", "xml"),
        "pdf": ("application/pdf", "pdf"),
    }
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        list_response = await client.get("/jobs")
        responses = {
            report_format: await client.get(f"/jobs/{job.id}/export/{report_format}")
            for report_format in expected
        }

    summary = list_response.json()[0]["summary"]
    assert summary["analyzer"] == "nginx_config_basic"
    assert summary["files_considered"] == 2
    assert summary["files_reviewed"] == 2
    assert summary["nginx_files_detected"] == 2
    assert summary["server_blocks_detected"] == 2
    assert summary["location_blocks_detected"] == 3
    assert summary["upstream_blocks_detected"] == 1
    assert summary["includes_detected"] == 2
    assert summary["tls_servers_detected"] == 1
    assert summary["findings_count"] == 2
    assert summary["redacted_values_count"] == 2
    assert summary["truncated"] is False
    assert summary["errors_count"] == 0
    for report_format, response in responses.items():
        content_type, extension = expected[report_format]
        assert response.status_code == 200
        assert response.headers["content-type"].startswith(content_type)
        assert response.headers["content-disposition"] == f'attachment; filename="inspectra-job-{job.id}.{extension}"'
    assert "nginx_config_basic" in responses["markdown"].text
    assert "Nginx Config Metrics" in responses["html"].text
    assert "Server Blocks" in responses["markdown"].text
    assert "Locations" in responses["markdown"].text
    assert "Upstreams" in responses["markdown"].text
    assert "Includes Detected But Not Resolved" in responses["markdown"].text
    assert "Directives" in responses["markdown"].text
    assert "Finding 1 Directive" in responses["markdown"].text
    assert "Finding 1 Block type" in responses["markdown"].text
    assert "deploy/nginx/default.conf" in responses["markdown"].text
    assert "nginx_proxy_pass_credentials_hint" in responses["markdown"].text
    assert "resolved: False" in responses["markdown"].text or "resolved`" in responses["markdown"].text
    assert ElementTree.fromstring(responses["xml"].text).findtext("./job/auditType") == "nginx_config_basic"
    assert responses["pdf"].content.startswith(b"%PDF")


@pytest.mark.anyio
async def test_export_nginx_config_redacts_legacy_secret_values(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    now = datetime(2026, 6, 1, tzinfo=timezone.utc)
    job = JobRecord(
        id="9" * 31 + "8",
        audit_type="nginx_config_basic",
        file_id="4" * 32,
        status="completed",
        created_at=now,
        updated_at=now,
        error="Authorization: Bearer token_should_never_render",
        result={
            "analyzer": "nginx_config_basic",
            "archive_type": "zip",
            "summary": {"files_reviewed": 1, "findings_count": 1, "redacted_values_count": 0},
            "servers": [{"server_name": "example.com", "password": "super-secret-password"}],
            "locations": [{"location": "/api", "proxy_pass": "http://user:pass@example.com"}],
            "upstreams": [{"name": "backend", "url": "http://registry-user:registry-pass@upstream.example.test"}],
            "includes": [{"target": "/etc/nginx/secrets.conf", "content": "raw-api-key-123456", "resolved": False}],
            "directives": [
                {"directive": "proxy_set_header", "arguments": "Authorization: Bearer token_should_never_render"},
                {"directive": "set", "arguments": "$api_key raw-api-key-123456"},
                {"directive": "set", "arguments": "$proxy_password proxy_password_should_not_render"},
            ],
            "findings": [
                {
                    "id": "legacy_nginx_secret",
                    "title": "Legacy raw secret",
                    "level": "medium",
                    "confidence": "high",
                    "category": "secrets",
                    "description": "PASSWORD=super-secret-password",
                    "evidence": "proxy_pass http://user:pass@example.com Authorization: Bearer token_should_never_render",
                    "recommendation": "-----BEGIN PRIVATE KEY----- PRIVATE KEY raw-api-key-123456 -----END PRIVATE KEY-----",
                    "file_path": "deploy/nginx/default.conf",
                    "context": "production<script>API_KEY=raw-api-key-123456</script>",
                    "block_type": "location",
                    "server_name": "example.com",
                    "location": "/api",
                    "directive": "proxy_pass",
                }
            ],
            "errors": [
                "API_KEY=raw-api-key-123456",
                "Authorization: Bearer token_should_never_render",
                "http://user:pass@example.com",
                "registry-user:registry-pass",
                "sessionid=secret-session-cookie",
            ],
            "redaction_notes": ["PASSWORD=super-secret-password"],
        },
    )
    app.state.jobs.save(job)
    expected = {
        "markdown": "text/markdown",
        "html": "text/html",
        "xml": "application/xml",
        "pdf": "application/pdf",
    }
    forbidden = (
        b"super-secret-password",
        b"raw-api-key-123456",
        b"token_should_never_render",
        b"Authorization: Bearer token_should_never_render",
        b"http://user:pass@example.com",
        b"registry-user:registry-pass",
        b"sessionid=secret-session-cookie",
        b"proxy_password_should_not_render",
        b"PRIVATE KEY",
    )
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        api_response = await client.get(f"/jobs/{job.id}")
        responses = {
            report_format: await client.get(f"/jobs/{job.id}/export/{report_format}")
            for report_format in expected
        }

    assert api_response.status_code == 200
    assert b"REDACTED" in api_response.content
    for secret in forbidden:
        assert secret not in api_response.content
    for report_format, response in responses.items():
        assert response.status_code == 200
        assert response.headers["content-type"].startswith(expected[report_format])
        assert b"REDACTED" in response.content
        for secret in forbidden:
            assert secret not in response.content
    assert "&lt;script&gt;" in responses["html"].text
    assert "<script>" not in responses["html"].text


@pytest.mark.anyio
async def test_export_nginx_config_jobs_with_sparse_and_incomplete_results(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    now = datetime(2026, 6, 1, tzinfo=timezone.utc)
    jobs = [
        JobRecord(id="9" * 31 + "9", audit_type="nginx_config_basic", file_id="4" * 32, status="queued", created_at=now, updated_at=now),
        JobRecord(id="8" * 31 + "1", audit_type="nginx_config_basic", file_id="4" * 32, status="running", created_at=now, updated_at=now),
        JobRecord(
            id="8" * 31 + "2",
            audit_type="nginx_config_basic",
            file_id="4" * 32,
            status="failed",
            created_at=now,
            updated_at=now,
            error="Nginx config runner failed safely.",
        ),
        JobRecord(
            id="8" * 31 + "3",
            audit_type="nginx_config_basic",
            file_id="4" * 32,
            status="completed",
            created_at=now,
            updated_at=now,
            result={"analyzer": "nginx_config_basic", "summary": {}, "findings": [{"id": "sparse"}], "errors": []},
        ),
    ]
    for job in jobs:
        app.state.jobs.save(job)
    expected = {
        "markdown": "text/markdown",
        "html": "text/html",
        "xml": "application/xml",
        "pdf": "application/pdf",
    }
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        for job in jobs:
            for report_format, content_type in expected.items():
                response = await client.get(f"/jobs/{job.id}/export/{report_format}")

                assert response.status_code == 200
                assert response.headers["content-type"].startswith(content_type)
                if report_format == "xml":
                    root = ElementTree.fromstring(response.text)
                    assert root.findtext("./job/status") == job.status
                    assert root.findtext("./job/auditType") == "nginx_config_basic"
                elif report_format == "pdf":
                    assert response.content.startswith(b"%PDF")
                else:
                    assert job.status in response.text
                    assert "nginx_config_basic" in response.text


@pytest.mark.anyio
async def test_compose_config_job_summary_and_export_all_formats(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    job = save_compose_config_export_fixture_job()
    expected = {
        "markdown": ("text/markdown", "md"),
        "html": ("text/html", "html"),
        "xml": ("application/xml", "xml"),
        "pdf": ("application/pdf", "pdf"),
    }
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        list_response = await client.get("/jobs")
        responses = {
            report_format: await client.get(f"/jobs/{job.id}/export/{report_format}")
            for report_format in expected
        }

    summary = list_response.json()[0]["summary"]
    assert summary["analyzer"] == "compose_config_basic"
    assert summary["files_considered"] == 3
    assert summary["files_reviewed"] == 2
    assert summary["compose_files_detected"] == 2
    assert summary["services_detected"] == 3
    assert summary["networks_detected"] == 2
    assert summary["volumes_detected"] == 2
    assert summary["secrets_detected"] == 1
    assert summary["published_ports_detected"] == 3
    assert summary["env_files_detected"] == 1
    assert summary["findings_count"] == 2
    assert summary["redacted_values_count"] == 2
    assert summary["truncated"] is False
    assert summary["errors_count"] == 0
    for report_format, response in responses.items():
        content_type, extension = expected[report_format]
        assert response.status_code == 200
        assert response.headers["content-type"].startswith(content_type)
        assert response.headers["content-disposition"] == f'attachment; filename="inspectra-job-{job.id}.{extension}"'
    assert "compose_config_basic" in responses["markdown"].text
    assert "Compose Config Metrics" in responses["html"].text
    assert "Services" in responses["markdown"].text
    assert "Ports / Exposure" in responses["markdown"].text
    assert "Volumes / Mounts" in responses["markdown"].text
    assert "Env Files Detected But Not Read" in responses["markdown"].text
    assert "Finding 1 Service" in responses["markdown"].text
    assert "Finding 1 Field path" in responses["markdown"].text
    assert "compose_environment_secret_like_value" in responses["markdown"].text
    assert "read: False" in responses["markdown"].text or "read`" in responses["markdown"].text
    assert ElementTree.fromstring(responses["xml"].text).findtext("./job/auditType") == "compose_config_basic"
    assert responses["pdf"].content.startswith(b"%PDF")


@pytest.mark.anyio
async def test_export_compose_config_redacts_legacy_secret_values(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    now = datetime(2026, 6, 2, tzinfo=timezone.utc)
    job = JobRecord(
        id="7" * 31 + "8",
        audit_type="compose_config_basic",
        file_id="4" * 32,
        status="completed",
        created_at=now,
        updated_at=now,
        error="POSTGRES_PASSWORD=super-secret-password",
        result={
            "analyzer": "compose_config_basic",
            "archive_type": "zip",
            "summary": {"files_reviewed": 1, "findings_count": 1, "redacted_values_count": 0},
            "services": [
                {
                    "name": "db",
                    "environment": {"POSTGRES_PASSWORD": "super-secret-password", "DATABASE_URL": "postgres://user:pass@example.com/db"},
                    "command": "TOKEN=token_should_never_render",
                    "labels": {"com.example.api_key": "raw-api-key-123456"},
                }
            ],
            "ports": [{"service": "db", "published": "0.0.0.0:5432:5432", "password": "super-secret-password"}],
            "volumes": [{"service": "web", "source": "/var/run/docker.sock", "content": "-----BEGIN PRIVATE KEY-----"}],
            "networks": [{"name": "public", "session": "sessionid=secret-session-cookie"}],
            "secrets": [{"name": "db_password", "file": "./secrets/db_password.txt", "content": "db_password_plaintext compose_secret_file_should_not_render"}],
            "env_files": [{"path": ".env", "read": False, "content": "POSTGRES_PASSWORD=super-secret-password compose_secret_file_should_not_render"}],
            "images": [{"service": "api", "image": "registry-user:registry-pass@example.test/app:latest"}],
            "build_contexts": [{"service": "api", "context": "../api", "args": "API_KEY=raw-api-key-123456"}],
            "findings": [
                {
                    "id": "legacy_compose_secret",
                    "title": "Legacy raw secret",
                    "level": "medium",
                    "confidence": "high",
                    "category": "secrets",
                    "description": "PASSWORD=super-secret-password",
                    "evidence": "DATABASE_URL=postgres://user:pass@example.com/db Authorization: Bearer token_should_never_render",
                    "recommendation": "-----BEGIN PRIVATE KEY----- PRIVATE KEY raw-api-key-123456 -----END PRIVATE KEY-----",
                    "file_path": "deploy/compose/docker-compose.yml",
                    "context": "production<script>API_KEY=raw-api-key-123456</script>",
                    "service": "db",
                    "field_path": "services.db.environment.POSTGRES_PASSWORD",
                }
            ],
            "errors": [
                "POSTGRES_PASSWORD=super-secret-password",
                "DATABASE_URL=postgres://user:pass@example.com/db",
                "redis://:super-secret-password@redis:6379/0",
                "registry-user:registry-pass",
                "token_should_never_render",
                "compose_secret_file_should_not_render",
            ],
            "redaction_notes": ["POSTGRES_PASSWORD=super-secret-password"],
        },
    )
    app.state.jobs.save(job)
    expected = {
        "markdown": "text/markdown",
        "html": "text/html",
        "xml": "application/xml",
        "pdf": "application/pdf",
    }
    forbidden = (
        b"super-secret-password",
        b"raw-api-key-123456",
        b"token_should_never_render",
        b"POSTGRES_PASSWORD=super-secret-password",
        b"postgres://user:pass@example.com/db",
        b"redis://:super-secret-password@redis:6379/0",
        b"registry-user:registry-pass",
        b"PRIVATE KEY",
        b"db_password_plaintext",
        b"compose_secret_file_should_not_render",
        b"sessionid=secret-session-cookie",
    )
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        api_response = await client.get(f"/jobs/{job.id}")
        responses = {
            report_format: await client.get(f"/jobs/{job.id}/export/{report_format}")
            for report_format in expected
        }

    assert api_response.status_code == 200
    assert b"REDACTED" in api_response.content
    for secret in forbidden:
        assert secret not in api_response.content
    for report_format, response in responses.items():
        assert response.status_code == 200
        assert response.headers["content-type"].startswith(expected[report_format])
        assert b"REDACTED" in response.content
        for secret in forbidden:
            assert secret not in response.content
    assert "&lt;script&gt;" in responses["html"].text
    assert "<script>" not in responses["html"].text


@pytest.mark.anyio
async def test_export_compose_config_jobs_with_sparse_and_incomplete_results(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    now = datetime(2026, 6, 2, tzinfo=timezone.utc)
    jobs = [
        JobRecord(id="7" * 31 + "9", audit_type="compose_config_basic", file_id="4" * 32, status="queued", created_at=now, updated_at=now),
        JobRecord(id="6" * 31 + "1", audit_type="compose_config_basic", file_id="4" * 32, status="running", created_at=now, updated_at=now),
        JobRecord(
            id="6" * 31 + "2",
            audit_type="compose_config_basic",
            file_id="4" * 32,
            status="failed",
            created_at=now,
            updated_at=now,
            error="Compose config runner failed safely.",
        ),
        JobRecord(
            id="6" * 31 + "3",
            audit_type="compose_config_basic",
            file_id="4" * 32,
            status="completed",
            created_at=now,
            updated_at=now,
            result={"analyzer": "compose_config_basic", "summary": {}, "findings": [{"id": "sparse"}], "errors": []},
        ),
    ]
    for job in jobs:
        app.state.jobs.save(job)
    expected = {
        "markdown": "text/markdown",
        "html": "text/html",
        "xml": "application/xml",
        "pdf": "application/pdf",
    }
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        for job in jobs:
            for report_format, content_type in expected.items():
                response = await client.get(f"/jobs/{job.id}/export/{report_format}")

                assert response.status_code == 200
                assert response.headers["content-type"].startswith(content_type)
                if report_format == "xml":
                    root = ElementTree.fromstring(response.text)
                    assert root.findtext("./job/status") == job.status
                    assert root.findtext("./job/auditType") == "compose_config_basic"
                elif report_format == "pdf":
                    assert response.content.startswith(b"%PDF")
                else:
                    assert job.status in response.text
                    assert "compose_config_basic" in response.text


@pytest.mark.anyio
async def test_database_config_job_summary_and_export_all_formats(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    job = save_database_config_export_fixture_job()
    expected = {
        "markdown": ("text/markdown", "md"),
        "html": ("text/html", "html"),
        "xml": ("application/xml", "xml"),
        "pdf": ("application/pdf", "pdf"),
    }
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        list_response = await client.get("/jobs")
        responses = {
            report_format: await client.get(f"/jobs/{job.id}/export/{report_format}")
            for report_format in expected
        }

    summary = list_response.json()[0]["summary"]
    assert summary["analyzer"] == "database_config_basic"
    assert summary["files_considered"] == 5
    assert summary["files_reviewed"] == 3
    assert summary["database_files_detected"] == 3
    assert summary["postgres_files_detected"] == 1
    assert summary["mysql_files_detected"] == 1
    assert summary["mariadb_files_detected"] == 1
    assert summary["pg_hba_files_detected"] == 1
    assert summary["dump_or_backup_files_detected"] == 2
    assert summary["engines_detected"] == 2
    assert summary["findings_count"] == 2
    assert summary["redacted_values_count"] == 2
    assert summary["truncated"] is False
    assert summary["errors_count"] == 0
    for report_format, response in responses.items():
        content_type, extension = expected[report_format]
        assert response.status_code == 200
        assert response.headers["content-type"].startswith(content_type)
        assert response.headers["content-disposition"] == f'attachment; filename="inspectra-job-{job.id}.{extension}"'
    assert "database_config_basic" in responses["markdown"].text
    assert "Database Config Metrics" in responses["html"].text
    assert "PostgreSQL Settings" in responses["markdown"].text
    assert "pg_hba.conf Rules" in responses["markdown"].text
    assert "MySQL / MariaDB Settings" in responses["markdown"].text
    assert "Includes Detected But Not Resolved" in responses["markdown"].text
    assert "Dumps / Backups Detected But Not Read" in responses["markdown"].text
    assert "Finding 1 Engine" in responses["markdown"].text
    assert "Finding 1 Auth method" in responses["markdown"].text
    assert "postgres_pg_hba_trust_auth" in responses["markdown"].text
    assert ElementTree.fromstring(responses["xml"].text).findtext("./job/auditType") == "database_config_basic"
    assert responses["pdf"].content.startswith(b"%PDF")


@pytest.mark.anyio
async def test_export_database_config_redacts_legacy_secret_values(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    now = datetime(2026, 6, 2, tzinfo=timezone.utc)
    job = JobRecord(
        id="5" * 31 + "8",
        audit_type="database_config_basic",
        file_id="4" * 32,
        status="completed",
        created_at=now,
        updated_at=now,
        error="PGPASSWORD=super-secret-password",
        result={
            "analyzer": "database_config_basic",
            "archive_type": "zip",
            "summary": {"files_reviewed": 1, "findings_count": 1, "redacted_values_count": 0},
            "engines": [{"engine": "postgresql", "password": "super-secret-password", "content": "pgpass_secret_should_not_render"}],
            "postgres_settings": [{"setting": "primary_conninfo", "value": "postgres://user:pass@example.com/db"}],
            "pg_hba_rules": [{"user": "all", "database": "all", "address": "0.0.0.0/0", "auth_method": "trust", "content": "db_password_plaintext"}],
            "mysql_settings": [{"setting": "password", "value": "raw-db-password-123456"}],
            "includes": [{"target": "/etc/postgresql/secret.conf", "content": "replication_password_should_not_render", "resolved": False}],
            "dump_or_backup_files": [{"path": "db/prod.sql", "read": False, "sql": "db_password_plaintext dump_row_secret_should_not_render"}],
            "findings": [
                {
                    "id": "legacy_database_secret",
                    "title": "Legacy raw secret",
                    "level": "medium",
                    "confidence": "high",
                    "category": "secrets",
                    "description": "MYSQL_PWD=super-secret-password",
                    "evidence": "DATABASE_URL=postgres://user:pass@example.com/db mysql://user:pass@example.com/db",
                    "recommendation": "-----BEGIN PRIVATE KEY----- PRIVATE KEY raw-db-password-123456 -----END PRIVATE KEY-----",
                    "file_path": "deploy/db/postgresql.conf",
                    "context": "production<script>PGPASSWORD=super-secret-password</script>",
                    "engine": "postgresql",
                    "setting": "primary_conninfo",
                }
            ],
            "errors": [
                "PGPASSWORD=super-secret-password",
                "MYSQL_PWD=super-secret-password",
                "postgres://user:pass@example.com/db",
                "mysql://user:pass@example.com/db",
                "replication_password_should_not_render",
                "pgpass_secret_should_not_render",
                "mycnf_secret_should_not_render",
                "dump_row_secret_should_not_render",
                "db_password_plaintext",
            ],
            "redaction_notes": ["raw-db-password-123456"],
        },
    )
    app.state.jobs.save(job)
    expected = {
        "markdown": "text/markdown",
        "html": "text/html",
        "xml": "application/xml",
        "pdf": "application/pdf",
    }
    forbidden = (
        b"super-secret-password",
        b"raw-db-password-123456",
        b"postgres://user:pass@example.com/db",
        b"mysql://user:pass@example.com/db",
        b"replication_password_should_not_render",
        b"PGPASSWORD=super-secret-password",
        b"MYSQL_PWD=super-secret-password",
        b"PRIVATE KEY",
        b"db_password_plaintext",
        b"dump_row_secret_should_not_render",
        b"pgpass_secret_should_not_render",
        b"mycnf_secret_should_not_render",
    )
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        api_response = await client.get(f"/jobs/{job.id}")
        responses = {
            report_format: await client.get(f"/jobs/{job.id}/export/{report_format}")
            for report_format in expected
        }

    assert api_response.status_code == 200
    assert b"REDACTED" in api_response.content
    for secret in forbidden:
        assert secret not in api_response.content
    for report_format, response in responses.items():
        assert response.status_code == 200
        assert response.headers["content-type"].startswith(expected[report_format])
        assert b"REDACTED" in response.content
        for secret in forbidden:
            assert secret not in response.content
    assert "&lt;script&gt;" in responses["html"].text
    assert "<script>" not in responses["html"].text


@pytest.mark.anyio
async def test_export_database_config_jobs_with_sparse_and_incomplete_results(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    now = datetime(2026, 6, 2, tzinfo=timezone.utc)
    jobs = [
        JobRecord(id="5" * 31 + "9", audit_type="database_config_basic", file_id="4" * 32, status="queued", created_at=now, updated_at=now),
        JobRecord(id="4" * 31 + "1", audit_type="database_config_basic", file_id="4" * 32, status="running", created_at=now, updated_at=now),
        JobRecord(
            id="4" * 31 + "2",
            audit_type="database_config_basic",
            file_id="4" * 32,
            status="failed",
            created_at=now,
            updated_at=now,
            error="Database config runner failed safely.",
        ),
        JobRecord(
            id="4" * 31 + "3",
            audit_type="database_config_basic",
            file_id="4" * 32,
            status="completed",
            created_at=now,
            updated_at=now,
            result={"analyzer": "database_config_basic", "summary": {}, "findings": [{"id": "sparse"}], "errors": []},
        ),
    ]
    for job in jobs:
        app.state.jobs.save(job)
    expected = {
        "markdown": "text/markdown",
        "html": "text/html",
        "xml": "application/xml",
        "pdf": "application/pdf",
    }
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        for job in jobs:
            for report_format, content_type in expected.items():
                response = await client.get(f"/jobs/{job.id}/export/{report_format}")

                assert response.status_code == 200
                assert response.headers["content-type"].startswith(content_type)
                if report_format == "xml":
                    root = ElementTree.fromstring(response.text)
                    assert root.findtext("./job/status") == job.status
                    assert root.findtext("./job/auditType") == "database_config_basic"
                elif report_format == "pdf":
                    assert response.content.startswith(b"%PDF")
                else:
                    assert job.status in response.text
                    assert "database_config_basic" in response.text


@pytest.mark.anyio
async def test_sql_database_config_job_summary_and_export_all_formats(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    job = save_sql_database_config_export_fixture_job()
    expected = {
        "markdown": ("text/markdown", "md"),
        "html": ("text/html", "html"),
        "xml": ("application/xml", "xml"),
        "pdf": ("application/pdf", "pdf"),
    }
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        list_response = await client.get("/jobs")
        responses = {
            report_format: await client.get(f"/jobs/{job.id}/export/{report_format}")
            for report_format in expected
        }

    summary = list_response.json()[0]["summary"]
    assert summary["analyzer"] == "sql_database_config_basic"
    assert summary["files_considered"] == 7
    assert summary["files_reviewed"] == 3
    assert summary["postgres_configs_detected"] == 1
    assert summary["postgres_hba_files_detected"] == 1
    assert summary["mysql_configs_detected"] == 1
    assert summary["mariadb_configs_detected"] == 1
    assert summary["dump_or_backup_files_detected"] == 1
    assert summary["data_files_detected"] == 1
    assert summary["findings_count"] == 2
    assert summary["redacted_values_count"] == 2
    assert summary["truncated"] is False
    assert summary["errors_count"] == 0
    for report_format, response in responses.items():
        content_type, extension = expected[report_format]
        assert response.status_code == 200
        assert response.headers["content-type"].startswith(content_type)
        assert response.headers["content-disposition"] == f'attachment; filename="inspectra-job-{job.id}.{extension}"'
    assert "sql_database_config_basic" in responses["markdown"].text
    assert "SQL Database Config Metrics" in responses["html"].text
    assert "PostgreSQL Configs" in responses["markdown"].text
    assert "pg_hba.conf Rules" in responses["markdown"].text
    assert "MySQL / MariaDB Configs" in responses["markdown"].text
    assert "Database Settings" in responses["markdown"].text
    assert "Includes Detected But Not Resolved" in responses["markdown"].text
    assert "Sensitive Files Detected But Not Read" in responses["markdown"].text
    assert "Dumps / Backups Detected But Not Read" in responses["markdown"].text
    assert "Data / WAL / Binlog Files Detected But Not Read" in responses["markdown"].text
    assert "Finding 1 Engine" in responses["markdown"].text
    assert "Finding 1 Auth method" in responses["markdown"].text
    assert "postgres_hba_trust_auth_hint" in responses["markdown"].text
    assert ElementTree.fromstring(responses["xml"].text).findtext("./job/auditType") == "sql_database_config_basic"
    assert responses["pdf"].content.startswith(b"%PDF")


@pytest.mark.anyio
async def test_sql_database_config_end_to_end_public_contract_and_no_read_exports(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    job = save_sql_database_config_export_fixture_job()
    expected_exports = {
        "markdown": "text/markdown",
        "html": "text/html",
        "xml": "application/xml",
        "pdf": "application/pdf",
    }
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        list_response = await client.get("/jobs")
        job_response = await client.get(f"/jobs/{job.id}")
        exports = {
            report_format: await client.get(f"/jobs/{job.id}/export/{report_format}")
            for report_format in expected_exports
        }

    public_payload = job_response.json()
    public_result = public_payload["result"]
    public_serialized = json.dumps(public_payload, sort_keys=True)
    assert public_payload["audit_type"] == "sql_database_config_basic"
    assert public_result["analyzer"] == "sql_database_config_basic"
    assert public_result["postgres_configs"]
    assert public_result["postgres_hba_rules"]
    assert public_result["mysql_configs"]
    assert public_result["database_settings"]
    assert public_result["includes"][0]["resolved"] is False
    assert public_result["sensitive_files"][0]["read"] is False
    assert public_result["dump_or_backup_files"][0]["read"] is False
    assert public_result["data_files"][0]["read"] is False
    assert "[REDACTED]" in public_serialized
    for secret in SQL_DATABASE_SECRET_FIXTURES:
        assert secret not in public_serialized

    summary = next(item for item in list_response.json() if item["id"] == job.id)["summary"]
    assert summary["analyzer"] == "sql_database_config_basic"
    assert summary["files_reviewed"] == 3
    assert summary["postgres_configs_detected"] == 1
    assert summary["postgres_hba_files_detected"] == 1
    assert summary["mysql_configs_detected"] == 1
    assert summary["mariadb_configs_detected"] == 1
    assert summary["dump_or_backup_files_detected"] == 1
    assert summary["data_files_detected"] == 1
    assert summary["errors_count"] == 0

    for report_format, response in exports.items():
        assert response.status_code == 200
        assert response.headers["content-type"].startswith(expected_exports[report_format])
        assert b"REDACTED" in response.content
        for secret in SQL_DATABASE_SECRET_FIXTURES:
            assert secret.encode() not in response.content
    markdown = exports["markdown"].text
    assert "PostgreSQL Configs" in markdown
    assert "pg_hba.conf Rules" in markdown
    assert "MySQL / MariaDB Configs" in markdown
    assert "Database Settings" in markdown
    assert "Includes Detected But Not Resolved" in markdown
    assert "Sensitive Files Detected But Not Read" in markdown
    assert "Dumps / Backups Detected But Not Read" in markdown
    assert "Data / WAL / Binlog Files Detected But Not Read" in markdown
    assert "sql_database_include_detected_not_resolved" in markdown
    assert ElementTree.fromstring(exports["xml"].text).findtext("./job/auditType") == "sql_database_config_basic"
    assert exports["pdf"].content.startswith(b"%PDF")


@pytest.mark.anyio
async def test_export_sql_database_config_redacts_legacy_secret_values(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    now = datetime(2026, 6, 2, tzinfo=timezone.utc)
    job = JobRecord(
        id="7" * 31 + "8",
        audit_type="sql_database_config_basic",
        file_id="4" * 32,
        status="completed",
        created_at=now,
        updated_at=now,
        error="PGPASSWORD=super-secret-password",
        result={
            "analyzer": "sql_database_config_basic",
            "archive_type": "zip",
            "summary": {"files_reviewed": 1, "findings_count": 1, "redacted_values_count": 0},
            "postgres_configs": [{"file_path": "postgresql.conf", "content": "postgres://user:pass@example.com/db"}],
            "postgres_hba_rules": [{"user": "all", "database": "all", "address": "0.0.0.0/0", "auth_method": "trust", "content": "db_password_plaintext"}],
            "mysql_configs": [{"file_path": "my.cnf", "content": "raw-db-password-123456"}],
            "database_settings": [{"setting": "primary_conninfo", "value": "postgres://user:pass@example.com/db"}],
            "includes": [{"target": "/etc/postgresql/secret.conf", "content": "replication_password_should_not_render", "resolved": False}],
            "sensitive_files": [{"path": ".pgpass", "read": False, "content": "pgpass_secret_should_not_render"}],
            "dump_or_backup_files": [{"path": "db/prod.sql", "read": False, "sql": "db_password_plaintext dump_row_secret_should_not_render"}],
            "data_files": [{"path": "db/postgres/pg_wal/0001", "read": False, "content": "dump_row_secret_should_not_render"}],
            "findings": [
                {
                    "id": "legacy_sql_database_secret",
                    "title": "password encryption is weak but safe wording",
                    "level": "medium",
                    "confidence": "high",
                    "category": "secrets",
                    "description": "MYSQL_PWD=super-secret-password",
                    "evidence": "DATABASE_URL=postgres://user:pass@example.com/db mysql://user:pass@example.com/db",
                    "recommendation": "-----BEGIN PRIVATE KEY----- PRIVATE KEY raw-db-password-123456 -----END PRIVATE KEY-----",
                    "file_path": "deploy/db/postgresql.conf",
                    "context": "production<script>PGPASSWORD=super-secret-password</script>",
                    "engine": "postgresql",
                    "setting": "primary_conninfo",
                }
            ],
            "errors": [
                "PGPASSWORD=super-secret-password",
                "MYSQL_PWD=super-secret-password",
                "postgres://user:pass@example.com/db",
                "mysql://user:pass@example.com/db",
                "replication_password_should_not_render",
                "pgpass_secret_should_not_render",
                "mycnf_secret_should_not_render",
                "dump_row_secret_should_not_render",
                "db_password_plaintext",
            ],
            "redaction_notes": ["raw-db-password-123456"],
        },
    )
    app.state.jobs.save(job)
    expected = {
        "markdown": "text/markdown",
        "html": "text/html",
        "xml": "application/xml",
        "pdf": "application/pdf",
    }
    forbidden = tuple(secret.encode() for secret in SQL_DATABASE_SECRET_FIXTURES)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        api_response = await client.get(f"/jobs/{job.id}")
        responses = {
            report_format: await client.get(f"/jobs/{job.id}/export/{report_format}")
            for report_format in expected
        }

    assert api_response.status_code == 200
    assert b"REDACTED" in api_response.content
    assert b"password encryption is weak but safe wording" in api_response.content
    for secret in forbidden:
        assert secret not in api_response.content
    for report_format, response in responses.items():
        assert response.status_code == 200
        assert response.headers["content-type"].startswith(expected[report_format])
        assert b"REDACTED" in response.content
        for secret in forbidden:
            assert secret not in response.content
    assert "password encryption is weak but safe wording" in responses["markdown"].text
    assert "&lt;script&gt;" in responses["html"].text
    assert "<script>" not in responses["html"].text


@pytest.mark.anyio
async def test_export_sql_database_config_jobs_with_sparse_and_incomplete_results(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    now = datetime(2026, 6, 2, tzinfo=timezone.utc)
    jobs = [
        JobRecord(id="7" * 31 + "9", audit_type="sql_database_config_basic", file_id="4" * 32, status="queued", created_at=now, updated_at=now),
        JobRecord(id="6" * 31 + "1", audit_type="sql_database_config_basic", file_id="4" * 32, status="running", created_at=now, updated_at=now),
        JobRecord(
            id="6" * 31 + "2",
            audit_type="sql_database_config_basic",
            file_id="4" * 32,
            status="failed",
            created_at=now,
            updated_at=now,
            error="SQL database config runner failed safely. MYSQL_PWD=super-secret-password",
        ),
        JobRecord(
            id="6" * 31 + "3",
            audit_type="sql_database_config_basic",
            file_id="4" * 32,
            status="completed",
            created_at=now,
            updated_at=now,
            result={"analyzer": "sql_database_config_basic", "summary": None, "findings": [{"id": "sparse"}], "errors": "PGPASSWORD=super-secret-password"},
        ),
    ]
    for job in jobs:
        app.state.jobs.save(job)
    expected = {
        "markdown": "text/markdown",
        "html": "text/html",
        "xml": "application/xml",
        "pdf": "application/pdf",
    }
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        jobs_response = await client.get("/jobs")
        for job in jobs:
            job_response = await client.get(f"/jobs/{job.id}")
            for report_format, content_type in expected.items():
                response = await client.get(f"/jobs/{job.id}/export/{report_format}")

                assert response.status_code == 200
                assert response.headers["content-type"].startswith(content_type)
                assert b"super-secret-password" not in response.content
                if report_format == "xml":
                    root = ElementTree.fromstring(response.text)
                    assert root.findtext("./job/status") == job.status
                    assert root.findtext("./job/auditType") == "sql_database_config_basic"
                elif report_format == "pdf":
                    assert response.content.startswith(b"%PDF")
                else:
                    assert job.status in response.text
                    assert "sql_database_config_basic" in response.text
            assert "super-secret-password" not in job_response.text
    sparse_summary = next(item for item in jobs_response.json() if item["id"] == "6" * 31 + "3")["summary"]
    assert sparse_summary["errors_count"] == 1


@pytest.mark.anyio
async def test_redis_config_job_summary_and_export_all_formats(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    job = save_redis_config_export_fixture_job()
    expected = {
        "markdown": ("text/markdown", "md"),
        "html": ("text/html", "html"),
        "xml": ("application/xml", "xml"),
        "pdf": ("application/pdf", "pdf"),
    }
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        list_response = await client.get("/jobs")
        responses = {
            report_format: await client.get(f"/jobs/{job.id}/export/{report_format}")
            for report_format in expected
        }

    summary = list_response.json()[0]["summary"]
    assert summary["analyzer"] == "redis_config_basic"
    assert summary["files_considered"] == 6
    assert summary["files_reviewed"] == 2
    assert summary["redis_files_detected"] == 1
    assert summary["sentinel_files_detected"] == 1
    assert summary["acl_files_detected"] == 1
    assert summary["dump_or_aof_files_detected"] == 2
    assert summary["configs_detected"] == 2
    assert summary["findings_count"] == 2
    assert summary["redacted_values_count"] == 2
    assert summary["truncated"] is False
    assert summary["errors_count"] == 0
    for report_format, response in responses.items():
        content_type, extension = expected[report_format]
        assert response.status_code == 200
        assert response.headers["content-type"].startswith(content_type)
        assert response.headers["content-disposition"] == f'attachment; filename="inspectra-job-{job.id}.{extension}"'
    assert "redis_config_basic" in responses["markdown"].text
    assert "Redis Config Metrics" in responses["html"].text
    assert "Redis Settings" in responses["markdown"].text
    assert "Sentinel Settings" in responses["markdown"].text
    assert "Includes Detected But Not Resolved" in responses["markdown"].text
    assert "ACL Files Detected But Not Read" in responses["markdown"].text
    assert "Dumps / AOF / Backups Detected But Not Read" in responses["markdown"].text
    assert "Finding 1 Config type" in responses["markdown"].text
    assert "redis_requirepass_present_redacted" in responses["markdown"].text
    assert ElementTree.fromstring(responses["xml"].text).findtext("./job/auditType") == "redis_config_basic"
    assert responses["pdf"].content.startswith(b"%PDF")


@pytest.mark.anyio
async def test_export_redis_config_redacts_legacy_secret_values(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    now = datetime(2026, 6, 2, tzinfo=timezone.utc)
    job = JobRecord(
        id="3" * 31 + "8",
        audit_type="redis_config_basic",
        file_id="4" * 32,
        status="completed",
        created_at=now,
        updated_at=now,
        error="requirepass super-secret-password",
        result={
            "analyzer": "redis_config_basic",
            "archive_type": "zip",
            "summary": {"files_reviewed": 1, "findings_count": 1, "redacted_values_count": 0},
            "configs": [{"path": "deploy/redis/redis.conf", "content": "requirepass super-secret-password"}],
            "redis_settings": [{"setting": "requirepass", "value": "super-secret-password"}],
            "sentinel_settings": [{"setting": "sentinel auth-pass", "value": "sentinel_auth_should_not_render"}],
            "includes": [{"target": "/etc/redis/secrets.conf", "content": "masterauth_secret_should_not_render", "resolved": False}],
            "acl_files": [{"path": "users.acl", "read": False, "content": "acl_password_hash_should_not_render ACLHASHSECRET_should_not_render"}],
            "dump_or_aof_files": [{"path": "dump.rdb", "read": False, "content": "dump_value_should_not_render"}],
            "findings": [
                {
                    "id": "legacy_redis_secret",
                    "title": "Legacy raw secret",
                    "level": "medium",
                    "confidence": "high",
                    "category": "secrets",
                    "description": "masterauth masterauth_secret_should_not_render",
                    "evidence": "requirepass super-secret-password redis://:super-secret-password@redis:6379/0",
                    "recommendation": "-----BEGIN PRIVATE KEY----- PRIVATE KEY raw-redis-password-123456 -----END PRIVATE KEY-----",
                    "file_path": "deploy/redis/redis.conf",
                    "context": "production<script>requirepass super-secret-password</script>",
                    "config_type": "redis",
                    "setting": "requirepass",
                }
            ],
            "errors": [
                "requirepass super-secret-password",
                "masterauth masterauth_secret_should_not_render",
                "sentinel auth-pass mymaster sentinel_auth_should_not_render",
                "redis://:super-secret-password@redis:6379/0",
                "raw-redis-password-123456",
                "ACLHASHSECRET_should_not_render",
                "dump_value_should_not_render",
                "acl_password_hash_should_not_render",
            ],
            "redaction_notes": ["raw-redis-password-123456"],
        },
    )
    app.state.jobs.save(job)
    expected = {
        "markdown": "text/markdown",
        "html": "text/html",
        "xml": "application/xml",
        "pdf": "application/pdf",
    }
    forbidden = (
        b"super-secret-password",
        b"raw-redis-password-123456",
        b"redis://:super-secret-password@redis:6379/0",
        b"masterauth_secret_should_not_render",
        b"sentinel_auth_should_not_render",
        b"ACLHASHSECRET_should_not_render",
        b"PRIVATE KEY",
        b"dump_value_should_not_render",
        b"acl_password_hash_should_not_render",
    )
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        api_response = await client.get(f"/jobs/{job.id}")
        responses = {
            report_format: await client.get(f"/jobs/{job.id}/export/{report_format}")
            for report_format in expected
        }

    assert api_response.status_code == 200
    assert b"REDACTED" in api_response.content
    for secret in forbidden:
        assert secret not in api_response.content
    for report_format, response in responses.items():
        assert response.status_code == 200
        assert response.headers["content-type"].startswith(expected[report_format])
        assert b"REDACTED" in response.content
        for secret in forbidden:
            assert secret not in response.content
    assert "&lt;script&gt;" in responses["html"].text
    assert "<script>" not in responses["html"].text


@pytest.mark.anyio
async def test_export_redis_config_jobs_with_sparse_and_incomplete_results(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    now = datetime(2026, 6, 2, tzinfo=timezone.utc)
    jobs = [
        JobRecord(id="3" * 31 + "9", audit_type="redis_config_basic", file_id="4" * 32, status="queued", created_at=now, updated_at=now),
        JobRecord(id="2" * 31 + "1", audit_type="redis_config_basic", file_id="4" * 32, status="running", created_at=now, updated_at=now),
        JobRecord(
            id="2" * 31 + "2",
            audit_type="redis_config_basic",
            file_id="4" * 32,
            status="failed",
            created_at=now,
            updated_at=now,
            error="Redis config runner failed safely.",
        ),
        JobRecord(
            id="2" * 31 + "3",
            audit_type="redis_config_basic",
            file_id="4" * 32,
            status="completed",
            created_at=now,
            updated_at=now,
            result={"analyzer": "redis_config_basic", "summary": {}, "findings": [{"id": "sparse"}], "errors": []},
        ),
    ]
    for job in jobs:
        app.state.jobs.save(job)
    expected = {
        "markdown": "text/markdown",
        "html": "text/html",
        "xml": "application/xml",
        "pdf": "application/pdf",
    }
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        for job in jobs:
            for report_format, content_type in expected.items():
                response = await client.get(f"/jobs/{job.id}/export/{report_format}")

                assert response.status_code == 200
                assert response.headers["content-type"].startswith(content_type)
                if report_format == "xml":
                    root = ElementTree.fromstring(response.text)
                    assert root.findtext("./job/status") == job.status
                    assert root.findtext("./job/auditType") == "redis_config_basic"
                elif report_format == "pdf":
                    assert response.content.startswith(b"%PDF")
                else:
                    assert job.status in response.text
                    assert "redis_config_basic" in response.text


@pytest.mark.anyio
async def test_export_domain_jobs_with_sparse_and_incomplete_results(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    now = datetime(2026, 5, 27, tzinfo=timezone.utc)
    jobs = [
        JobRecord(
            id="a" * 32,
            audit_type="domain_basic",
            file_id=None,
            target_domain="queued.example",
            status="queued",
            created_at=now,
            updated_at=now,
        ),
        JobRecord(
            id="b" * 32,
            audit_type="domain_basic",
            file_id=None,
            target_domain="running.example",
            status="running",
            created_at=now,
            updated_at=now,
        ),
        JobRecord(
            id="c" * 32,
            audit_type="domain_basic",
            file_id=None,
            target_domain="failed.example",
            status="failed",
            created_at=now,
            updated_at=now,
            error="DNS runner failed safely.",
        ),
        JobRecord(
            id="d" * 32,
            audit_type="domain_basic",
            file_id=None,
            target_domain="sparse.example",
            status="completed",
            created_at=now,
            updated_at=now,
            result={"analyzer": "domain_basic", "target": {"normalized_domain": "sparse.example"}, "summary": {}},
        ),
    ]
    for job in jobs:
        app.state.jobs.save(job)
    expected = {
        "markdown": "text/markdown",
        "html": "text/html",
        "xml": "application/xml",
        "pdf": "application/pdf",
    }
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        for job in jobs:
            for report_format, content_type in expected.items():
                response = await client.get(f"/jobs/{job.id}/export/{report_format}")

                assert response.status_code == 200
                assert response.headers["content-type"].startswith(content_type)
                if report_format == "xml":
                    root = ElementTree.fromstring(response.text)
                    assert root.findtext("./job/status") == job.status
                    assert root.findtext("./job/targetDomain") == job.target_domain
                elif report_format == "pdf":
                    assert response.content.startswith(b"%PDF")
                else:
                    assert job.status in response.text
                    assert job.target_domain in response.text


@pytest.mark.anyio
async def test_export_subdomain_inventory_jobs_with_sparse_and_incomplete_results(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    now = datetime(2026, 5, 27, tzinfo=timezone.utc)
    jobs = [
        JobRecord(
            id="9" * 32,
            audit_type="subdomain_inventory_basic",
            file_id=None,
            target_domain="queued.example",
            status="queued",
            created_at=now,
            updated_at=now,
        ),
        JobRecord(
            id="a1" * 16,
            audit_type="subdomain_inventory_basic",
            file_id=None,
            target_domain="running.example",
            status="running",
            created_at=now,
            updated_at=now,
        ),
        JobRecord(
            id="b2" * 16,
            audit_type="subdomain_inventory_basic",
            file_id=None,
            target_domain="failed.example",
            status="failed",
            created_at=now,
            updated_at=now,
            error="Subdomain inventory runner failed safely.",
        ),
        JobRecord(
            id="c3" * 16,
            audit_type="subdomain_inventory_basic",
            file_id=None,
            target_domain="sparse.example",
            status="completed",
            created_at=now,
            updated_at=now,
            result={
                "analyzer": "subdomain_inventory_basic",
                "target": {"normalized_root_domain": "sparse.example"},
                "summary": {"truncated": False, "deadline_reached": False},
            },
        ),
    ]
    for job in jobs:
        app.state.jobs.save(job)
    expected = {
        "markdown": "text/markdown",
        "html": "text/html",
        "xml": "application/xml",
        "pdf": "application/pdf",
    }
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        for job in jobs:
            for report_format, content_type in expected.items():
                response = await client.get(f"/jobs/{job.id}/export/{report_format}")

                assert response.status_code == 200
                assert response.headers["content-type"].startswith(content_type)
                if report_format == "xml":
                    root = ElementTree.fromstring(response.text)
                    assert root.findtext("./job/status") == job.status
                    assert root.findtext("./job/auditType") == "subdomain_inventory_basic"
                    assert root.findtext("./job/targetDomain") == job.target_domain
                elif report_format == "pdf":
                    assert response.content.startswith(b"%PDF")
                else:
                    assert job.status in response.text
                    assert job.target_domain in response.text


@pytest.mark.anyio
async def test_export_returns_404_for_missing_job(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get(f"/jobs/{'f' * 32}/export/html")

    assert response.status_code == 404


@pytest.mark.anyio
async def test_export_rejects_invalid_job_id(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/jobs/../../etc/passwd/export/html")
        invalid_response = await client.get("/jobs/not-a-job/export/html")

    assert response.status_code in {400, 404}
    assert invalid_response.status_code == 400


@pytest.mark.anyio
async def test_export_cyclonedx_sbom_for_manifest_job(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    job = save_export_fixture_job()
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get(f"/jobs/{job.id}/sbom/cyclonedx-json")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/vnd.cyclonedx+json")
    assert response.headers["content-disposition"] == f'attachment; filename="inspectra-job-{job.id}-cyclonedx.json"'
    payload = response.json()
    assert payload["bomFormat"] == "CycloneDX"
    assert payload["metadata"]["component"]["name"] == "<script>alert('x')</script>"
    assert payload["components"][0]["name"] == "react"
    assert payload["components"][0]["purl"] == "pkg:npm/react"
    assert "vulnerabilities" not in json.dumps(payload).lower()


@pytest.mark.anyio
async def test_export_spdx_sbom_for_manifest_job(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    job = save_export_fixture_job()
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get(f"/jobs/{job.id}/sbom/spdx-json")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/spdx+json")
    assert response.headers["content-disposition"] == f'attachment; filename="inspectra-job-{job.id}-spdx.json"'
    payload = response.json()
    assert payload["spdxVersion"] == "SPDX-2.3"
    assert payload["packages"][0]["name"] == "react"
    assert payload["packages"][0]["downloadLocation"] == "NOASSERTION"
    assert payload["packages"][0]["externalRefs"][0]["referenceLocator"] == "pkg:npm/react"
    assert "vulnerabilities" not in json.dumps(payload).lower()


@pytest.mark.anyio
async def test_export_sbom_for_project_archive_job(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    job = save_project_archive_export_fixture_job()
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        cyclonedx_response = await client.get(f"/jobs/{job.id}/sbom/cyclonedx-json")
        spdx_response = await client.get(f"/jobs/{job.id}/sbom/spdx-json")

    assert cyclonedx_response.status_code == 200
    cyclonedx = cyclonedx_response.json()
    assert cyclonedx["components"][0]["name"] == "react"
    assert find_cyclonedx_property(cyclonedx["components"][0], "inspectra:source_manifest") == "package.json"

    assert spdx_response.status_code == 200
    spdx = spdx_response.json()
    assert spdx["packages"][0]["name"] == "react"
    assert "source manifest: package.json" in spdx["packages"][0]["comment"]


@pytest.mark.anyio
async def test_sbom_export_rejects_incompatible_jobs(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    now = datetime(2026, 5, 26, tzinfo=timezone.utc)
    audit_types = (
        "pdf_basic",
        "image_basic",
        "archive_basic",
        "web_basic",
        "domain_basic",
        "subdomain_inventory_basic",
        "django_config_basic",
        "docker_config_basic",
        "secrets_review_basic",
        "node_package_config_basic",
        "ci_cd_config_basic",
        "k8s_config_basic",
        "terraform_config_basic",
        "nginx_config_basic",
        "compose_config_basic",
        "database_config_basic",
    )
    job_ids: list[str] = []
    for index, audit_type in enumerate(audit_types, start=1):
        job_id = f"{index:032x}"
        job_ids.append(job_id)
        app.state.jobs.save(
            JobRecord(
                id=job_id,
                audit_type=audit_type,
                file_id=None if audit_type in {"web_basic", "domain_basic", "subdomain_inventory_basic"} else f"{index + 3:032x}",
                target_url="https://example.com/" if audit_type == "web_basic" else None,
                target_domain="example.com" if audit_type in {"domain_basic", "subdomain_inventory_basic"} else None,
                status="completed",
                created_at=now,
                updated_at=now,
                result={"analyzer": audit_type, "hashes": {"sha256": "abc123"}},
            )
        )
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        responses = [await client.get(f"/jobs/{job_id}/sbom/cyclonedx-json") for job_id in job_ids]

    for response in responses:
        assert response.status_code == 400
        assert response.json()["detail"] == "SBOM export is only available for dependency manifest jobs"


@pytest.mark.anyio
async def test_sbom_export_requires_completed_manifest_job(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    now = datetime(2026, 5, 26, tzinfo=timezone.utc)
    job = JobRecord(
        id="9" * 32,
        audit_type="manifest_basic",
        file_id="8" * 32,
        status="running",
        created_at=now,
        updated_at=now,
        result={"analyzer": "manifest_basic"},
    )
    app.state.jobs.save(job)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get(f"/jobs/{job.id}/sbom/spdx-json")

    assert response.status_code == 409
    assert response.json()["detail"] == "SBOM export requires a completed manifest analysis job"


@pytest.mark.anyio
async def test_sbom_export_rejects_missing_and_invalid_job_ids(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        missing_response = await client.get(f"/jobs/{'f' * 32}/sbom/cyclonedx-json")
        traversal_response = await client.get("/jobs/../../etc/passwd/sbom/cyclonedx-json")
        invalid_response = await client.get("/jobs/not-a-job/sbom/cyclonedx-json")

    assert missing_response.status_code == 404
    assert traversal_response.status_code in {400, 404}
    assert invalid_response.status_code == 400


def test_sbom_helpers_normalize_npm_dependencies():
    job = save_standalone_job(
        manifest_type="package_json",
        dependencies={
            "dependencies": [
                {"name": "react", "specifier": "^18.3.1"},
                {"name": "@scope/pkg", "specifier": "1.2.3"},
            ]
        },
        original_filename="package.json",
    )

    components = extract_components_from_job(job)
    cyclonedx = json.loads(generate_cyclonedx_json(job))

    assert components[0].ecosystem == "npm"
    assert components[0].declared_requirement == "react: ^18.3.1"
    assert components[0].dependency_source_type == "registry"
    assert components[0].package_url == "pkg:npm/react"
    assert components[1].package_url == "pkg:npm/%40scope/pkg@1.2.3"
    react_component = cyclonedx_component_by_name(cyclonedx, "react")
    assert react_component["name"] == "react"
    assert "version" not in react_component
    assert find_cyclonedx_property(react_component, "inspectra:dependency_source_type") == "registry"


def test_sbom_helpers_omit_purl_for_ambiguous_npm_sources():
    job = save_standalone_job(
        manifest_type="package_json",
        dependencies={
            "dependencies": [
                {"name": "local-lib", "specifier": "file:../local-lib"},
                {"name": "workspace-lib", "specifier": "workspace:*"},
                {"name": "git-lib", "specifier": "git+https://example.invalid/git-lib.git"},
                {"name": "tarball-lib", "specifier": "https://example.invalid/tarball-lib.tgz"},
                {"name": "repo-lib", "specifier": "github:user/repo"},
                {"name": "alias-lib", "specifier": "npm:real-package@1.2.3"},
            ]
        },
        original_filename="package.json",
    )

    components = {component.name: component for component in extract_components_from_job(job)}
    cyclonedx = json.loads(generate_cyclonedx_json(job))

    expected_sources = {
        "local-lib": "local",
        "workspace-lib": "workspace",
        "git-lib": "vcs",
        "tarball-lib": "url",
        "repo-lib": "vcs",
        "alias-lib": "alias",
    }
    for name, source_type in expected_sources.items():
        component = components[name]
        cyclonedx_component = cyclonedx_component_by_name(cyclonedx, name)
        assert component.package_url is None
        assert component.dependency_source_type == source_type
        assert "purl" not in cyclonedx_component
        assert find_cyclonedx_property(cyclonedx_component, "inspectra:dependency_source_type") == source_type
        assert find_cyclonedx_property(cyclonedx_component, "inspectra:purl_omitted_reason")


def test_sbom_helpers_normalize_python_requirements():
    job = save_standalone_job(
        manifest_type="requirements_txt",
        dependencies={
            "dependencies": [
                {"name": "fastapi", "specifier": "==0.115.0", "source": "line 1"},
                {"name": "httpx", "specifier": ">=0.27", "source": "line 2"},
            ]
        },
        original_filename="requirements.txt",
    )

    components = extract_components_from_job(job)

    assert components[0].ecosystem == "pypi"
    assert components[0].declared_requirement == "fastapi==0.115.0"
    assert components[0].package_url == "pkg:pypi/fastapi@0.115.0"
    assert components[1].declared_requirement == "httpx>=0.27"
    assert components[1].package_url == "pkg:pypi/httpx"


def test_sbom_helpers_omit_purl_for_ambiguous_python_requirements():
    job = save_standalone_job(
        manifest_type="requirements_txt",
        dependencies={
            "dependencies": [
                {"name": "editable-reference", "specifier": "-e .", "declared_requirement": "-e .", "source_type": "editable"},
                {
                    "name": "demo",
                    "specifier": "@ git+https://example.invalid/demo.git",
                    "declared_requirement": "demo @ git+https://example.invalid/demo.git",
                },
                {
                    "name": "localpkg",
                    "specifier": "@ file:///tmp/localpkg.whl",
                    "declared_requirement": "localpkg @ file:///tmp/localpkg.whl",
                },
                {
                    "name": "wheelpkg",
                    "specifier": "@ https://example.invalid/wheelpkg.whl",
                    "declared_requirement": "wheelpkg @ https://example.invalid/wheelpkg.whl",
                },
                {"name": "./local-package", "specifier": "./local-package", "declared_requirement": "./local-package"},
            ]
        },
        original_filename="requirements.txt",
    )

    components = {component.name: component for component in extract_components_from_job(job)}
    spdx = json.loads(generate_spdx_json(job))

    expected_sources = {
        "editable-reference": "editable",
        "demo": "vcs",
        "localpkg": "local",
        "wheelpkg": "url",
        "./local-package": "local",
    }
    for name, source_type in expected_sources.items():
        component = components[name]
        spdx_package_payload = spdx_package_by_name(spdx, name)
        assert component.package_url is None
        assert component.dependency_source_type == source_type
        assert "externalRefs" not in spdx_package_payload
        assert f"dependency source type: {source_type}" in spdx_package_payload["comment"]
        assert "Package URL omitted:" in spdx_package_payload["comment"]


def test_sbom_helpers_omit_purl_for_ambiguous_pyproject_sources():
    job = save_standalone_job(
        manifest_type="pyproject_toml",
        dependencies={
            "dependencies": [
                {"name": "fastapi", "specifier": ">=0.115", "declared_requirement": "fastapi>=0.115"},
                {
                    "name": "demo",
                    "specifier": "@ https://example.invalid/demo.whl",
                    "declared_requirement": "demo @ https://example.invalid/demo.whl",
                },
                {
                    "name": "localpkg",
                    "specifier": "path = ../localpkg",
                    "declared_requirement": "localpkg: path = ../localpkg",
                },
            ]
        },
        original_filename="pyproject.toml",
    )

    components = {component.name: component for component in extract_components_from_job(job)}
    cyclonedx = json.loads(generate_cyclonedx_json(job))

    assert components["fastapi"].package_url == "pkg:pypi/fastapi"
    for name, source_type in {"demo": "url", "localpkg": "local"}.items():
        component = components[name]
        cyclonedx_component = cyclonedx_component_by_name(cyclonedx, name)
        assert component.package_url is None
        assert component.dependency_source_type == source_type
        assert "purl" not in cyclonedx_component
        assert find_cyclonedx_property(cyclonedx_component, "inspectra:purl_omitted_reason")


def test_sbom_helpers_normalize_pyproject_from_project_archive():
    now = datetime(2026, 5, 26, tzinfo=timezone.utc)
    job = JobRecord(
        id="b" * 32,
        audit_type="project_archive_basic",
        file_id="7" * 32,
        status="completed",
        created_at=now,
        updated_at=now,
        result={
            "analyzer": "project_archive_basic",
            "parsed_manifests": [
                {
                    "path": "services/api/pyproject.toml",
                    "manifest_type": "pyproject_toml",
                    "parsed": {
                        "project": {"name": "api"},
                        "dependencies": {"dependencies": [{"name": "requests", "specifier": ">=2.31"}]},
                    },
                }
            ],
        },
    )

    components = extract_components_from_job(job)

    assert components[0].ecosystem == "pypi"
    assert components[0].source_manifest_path == "services/api/pyproject.toml"
    assert components[0].declared_requirement == "requests>=2.31"


def test_sbom_helpers_apply_conservative_purl_policy_to_project_archives():
    now = datetime(2026, 5, 26, tzinfo=timezone.utc)
    job = JobRecord(
        id="b" * 32,
        audit_type="project_archive_basic",
        file_id="7" * 32,
        status="completed",
        created_at=now,
        updated_at=now,
        result={
            "analyzer": "project_archive_basic",
            "parsed_manifests": [
                {
                    "path": "web/package.json",
                    "manifest_type": "package_json",
                    "parsed": {
                        "project": {"name": "web"},
                        "dependencies": {
                            "dependencies": [
                                {"name": "react", "specifier": "^18.3.1"},
                                {"name": "local-lib", "specifier": "file:../local-lib"},
                            ]
                        },
                    },
                },
                {
                    "path": "api/requirements.txt",
                    "manifest_type": "requirements_txt",
                    "parsed": {
                        "project": {},
                        "dependencies": {
                            "dependencies": [
                                {
                                    "name": "demo",
                                    "specifier": "@ git+https://example.invalid/demo.git",
                                    "declared_requirement": "demo @ git+https://example.invalid/demo.git",
                                }
                            ]
                        },
                    },
                },
            ],
        },
    )

    components = {component.name: component for component in extract_components_from_job(job)}

    assert components["react"].package_url == "pkg:npm/react"
    assert components["react"].source_manifest_path == "web/package.json"
    assert components["local-lib"].package_url is None
    assert components["local-lib"].source_manifest_path == "web/package.json"
    assert components["demo"].package_url is None
    assert components["demo"].dependency_source_type == "vcs"
    assert components["demo"].source_manifest_path == "api/requirements.txt"


def find_cyclonedx_property(component: dict, name: str) -> str | None:
    for prop in component.get("properties", []):
        if prop.get("name") == name:
            return prop.get("value")
    return None


def cyclonedx_component_by_name(payload: dict, name: str) -> dict:
    for component in payload["components"]:
        if component.get("name") == name:
            return component
    raise AssertionError(f"CycloneDX component not found: {name}")


def spdx_package_by_name(payload: dict, name: str) -> dict:
    for package in payload["packages"]:
        if package.get("name") == name:
            return package
    raise AssertionError(f"SPDX package not found: {name}")


def save_standalone_job(manifest_type: str, dependencies: dict, original_filename: str) -> JobRecord:
    now = datetime(2026, 5, 26, tzinfo=timezone.utc)
    return JobRecord(
        id="a" * 32,
        audit_type="manifest_basic",
        file_id="6" * 32,
        status="completed",
        created_at=now,
        updated_at=now,
        result={
            "analyzer": "manifest_basic",
            "manifest_type": manifest_type,
            "file_identification": {"original_filename": original_filename},
            "parsed": {"project": {"name": "demo"}, "dependencies": dependencies, "scripts": {}, "engines": {}},
            "summary": {"total_dependencies": sum(len(items) for items in dependencies.values())},
            "findings": [],
            "errors": [],
        },
    )


def save_export_fixture_job() -> JobRecord:
    now = datetime(2026, 5, 26, tzinfo=timezone.utc)
    job = JobRecord(
        id="e" * 32,
        audit_type="manifest_basic",
        file_id="1" * 32,
        status="completed",
        created_at=now,
        updated_at=now,
        result={
            "analyzer": "manifest_basic",
            "completed_at": now.isoformat(),
            "manifest_type": "package_json",
            "hashes": {"sha256": "abc123"},
            "file_identification": {"size_bytes": 128, "original_filename": "package.json"},
            "parsed": {
                "project": {"name": "<script>alert('x')</script>", "version": "1.0.0"},
                "dependencies": {"dependencies": [{"name": "react", "specifier": "^18.3.1"}]},
                "scripts": {"postinstall": "node setup.js"},
            },
            "summary": {"total_dependencies": 1, "dependency_groups": ["dependencies"], "informational_findings_count": 1},
            "findings": [
                {
                    "id": "package_sensitive_lifecycle_script",
                    "title": "Lifecycle script should be reviewed",
                    "level": "medium",
                    "description": "Review before running package manager commands.",
                    "evidence": "postinstall: node setup.js",
                    "recommendation": "Confirm the script is expected.",
                }
            ],
            "errors": [],
        },
    )
    app.state.jobs.save(job)
    return job


def save_malicious_markdown_fixture_job() -> JobRecord:
    now = datetime(2026, 5, 26, tzinfo=timezone.utc)
    job = JobRecord(
        id="5" * 32,
        audit_type="manifest_basic",
        file_id="4" * 32,
        status="completed",
        created_at=now,
        updated_at=now,
        error="![x](https://evil.example/pixel.png)",
        result={
            "analyzer": "manifest_basic",
            "completed_at": now.isoformat(),
            "manifest_type": "requirements_txt",
            "hashes": {"sha256": "abc123"},
            "file_identification": {
                "size_bytes": 256,
                "original_filename": "[click me](https://evil.example)",
                "path_hint": "value | injected | column",
            },
            "parsed": {
                "project": {"name": '<img src="https://evil.example/pixel.png">'},
                "dependencies": {
                    "dependencies": [
                        {
                            "name": "# Fake Heading",
                            "specifier": "- fake item",
                            "declared_requirement": "demo @ git+https://evil.example/demo.git",
                        },
                        {"name": "> fake quote", "specifier": "value | injected | column"},
                    ]
                },
                "scripts": {"postinstall": "`inline`"},
            },
            "summary": {"total_dependencies": 2, "dependency_groups": ["dependencies"], "informational_findings_count": 1},
            "findings": [
                {
                    "id": "markdown_fixture",
                    "title": "[click me](https://evil.example)",
                    "level": "medium",
                    "description": "- fake item",
                    "evidence": "> fake quote",
                    "recommendation": "# Fake Heading",
                }
            ],
            "tool_outputs": {
                "fake_tool": {
                    "exit_code": 1,
                    "timed_out": False,
                    "stderr": "first line\n> fake quote\n```inside fenced content\nhttps://evil.example/log",
                }
            },
            "errors": ["<script>alert(1)</script>"],
        },
    )
    app.state.jobs.save(job)
    return job


def save_archive_export_fixture_job() -> JobRecord:
    now = datetime(2026, 5, 26, tzinfo=timezone.utc)
    job = JobRecord(
        id="d" * 32,
        audit_type="archive_basic",
        file_id="2" * 32,
        status="completed",
        created_at=now,
        updated_at=now,
        result={
            "analyzer": "archive_basic",
            "archive_type": "zip",
            "completed_at": now.isoformat(),
            "hashes": {"sha256": "abc123"},
            "file_identification": {"size_bytes": 512, "original_filename": "project.zip"},
            "summary": {
                "total_entries": 3,
                "total_uncompressed_bytes": 128,
                "total_compressed_bytes": 96,
                "directories": 1,
                "files": 2,
                "symlinks": 0,
                "hardlinks": 0,
                "executables": 0,
                "nested_archives": 1,
                "sensitive_name_matches": 1,
                "path_traversal_entries": 0,
                "absolute_path_entries": 0,
                "manifest_files_detected": 1,
                "findings_count": 2,
                "truncated": False,
            },
            "detected_manifests": [{"path": "package.json", "manifest_type": "package.json"}],
            "entries_sample": [
                {
                    "path": "package.json",
                    "type": "file",
                    "size": 64,
                    "compressed_size": 48,
                    "mode": "0o644",
                    "depth": 1,
                    "flags": {"manifest_file": True},
                }
            ],
            "findings": [
                {
                    "id": "archive_sensitive_name_entry",
                    "title": "Potentially sensitive filename detected",
                    "level": "medium",
                    "description": "Review this indicator manually.",
                    "evidence": ".env",
                    "recommendation": "Confirm the file should be present.",
                }
            ],
            "errors": [],
        },
    )
    app.state.jobs.save(job)
    return job


def save_project_archive_export_fixture_job() -> JobRecord:
    now = datetime(2026, 5, 26, tzinfo=timezone.utc)
    job = JobRecord(
        id="c" * 32,
        audit_type="project_archive_basic",
        file_id="3" * 32,
        status="completed",
        created_at=now,
        updated_at=now,
        result={
            "analyzer": "project_archive_basic",
            "archive_type": "zip",
            "completed_at": now.isoformat(),
            "hashes": {"sha256": "abc123"},
            "file_identification": {"size_bytes": 1024, "original_filename": "project.zip"},
            "summary": {
                "total_entries_seen": 4,
                "supported_manifests_found": 1,
                "supported_manifests_parsed": 1,
                "unsupported_manifests_detected": 1,
                "total_dependencies": 1,
                "dependency_groups": ["dependencies"],
                "findings_count": 1,
                "truncated": False,
            },
            "supported_manifests": [{"path": "package.json", "manifest_type": "package_json", "status": "parsed"}],
            "unsupported_manifests": [{"path": "package-lock.json", "manifest_type": "package-lock.json"}],
            "parsed_manifests": [
                {
                    "path": "package.json",
                    "manifest_type": "package_json",
                    "size_bytes": 128,
                    "parsed": {
                        "project": {"name": "demo"},
                        "dependencies": {"dependencies": [{"name": "react", "specifier": "^18.3.1"}]},
                        "scripts": {"postinstall": "node setup.js"},
                    },
                    "summary": {"total_dependencies": 1, "dependency_groups": ["dependencies"], "informational_findings_count": 1},
                    "findings": [],
                    "errors": [],
                }
            ],
            "findings": [
                {
                    "id": "package_sensitive_lifecycle_script",
                    "title": "Lifecycle script should be reviewed",
                    "level": "medium",
                    "description": "Review before running package manager commands.",
                    "evidence": "package.json: postinstall: node setup.js",
                    "recommendation": "Confirm the script is expected.",
                }
            ],
            "errors": [],
        },
    )
    app.state.jobs.save(job)
    return job


def save_web_export_fixture_job() -> JobRecord:
    now = datetime(2026, 5, 26, tzinfo=timezone.utc)
    job = JobRecord(
        id="8" * 32,
        audit_type="web_basic",
        file_id=None,
        target_url="https://example.com/callback?token=supersecret&page=1",
        status="completed",
        created_at=now,
        updated_at=now,
        result={
            "analyzer": "web_basic",
            "completed_at": now.isoformat(),
            "target": {
                "original_url": "https://example.com/callback?token=supersecret&page=1",
                "normalized_url": "https://example.com/callback?token=supersecret&page=1",
                "final_url": "https://example.com/callback?token=supersecret&page=1",
                "scheme": "https",
                "host": "example.com",
            },
            "http": {
                "status_code": 200,
                "redirects": [
                    {
                        "from_url": "https://example.com/start?token=supersecret",
                        "to_url": "https://example.com/callback?token=supersecret&page=1",
                        "status_code": 302,
                    }
                ],
                "response_headers": {
                    "Content-Type": "text/html",
                    "Server": "unit-test",
                    "Set-Cookie": "sid=supersecret; HttpOnly",
                    "Location": "https://example.com/callback?token=supersecret&page=1",
                },
                "content_type": "text/html",
                "bytes_read": 128,
            },
            "security_headers": {
                "Content-Security-Policy": {"present": False, "value": None},
                "X-Content-Type-Options": {"present": True, "value": "nosniff"},
            },
            "cookies": [{"name": "sid", "value_redacted": True, "value_length": 11, "secure": True, "httponly": True, "samesite": "Lax"}],
            "tls": {"present": True, "certificate": {"days_until_expiration": 90}, "errors": []},
            "robots_txt": {"checked": True, "present": True, "status_code": 200, "has_disallow": False},
            "security_txt": {"checked": True, "present": False, "status_code": 404, "fields": {}},
            "findings": [
                {
                    "id": "web_csp_missing",
                    "title": "Content-Security-Policy header is absent",
                    "level": "info",
                    "description": "Review hardening options.",
                    "evidence": "https://example.com/callback?token=supersecret&page=1",
                    "recommendation": "Consider adding CSP where appropriate.",
                }
            ],
            "summary": {
                "findings_count": 1,
                "missing_security_headers_count": 1,
                "cookies_count": 1,
                "redirects_count": 0,
                "tls_present": True,
                "security_txt_present": False,
                "robots_txt_present": True,
            },
            "errors": [],
        },
    )
    app.state.jobs.save(job)
    return job


def save_domain_export_fixture_job() -> JobRecord:
    now = datetime(2026, 5, 26, tzinfo=timezone.utc)
    job = JobRecord(
        id="9" * 32,
        audit_type="domain_basic",
        file_id=None,
        target_domain="example.com",
        status="completed",
        created_at=now,
        updated_at=now,
        result={
            "analyzer": "domain_basic",
            "target": {
                "domain": "example.com",
                "normalized_domain": "example.com",
                "checked_at": now.isoformat(),
            },
            "dns": {
                "A": ["93.184.216.34"],
                "AAAA": [],
                "CNAME": [],
                "MX": [{"preference": 10, "exchange": "mail.example.com"}],
                "NS": ["ns1.example.com", "ns2.example.com"],
                "TXT": ["v=spf1 -all"],
                "CAA": [{"flags": 0, "tag": "issue", "value": "letsencrypt.org"}],
                "SOA": [{"mname": "ns1.example.com", "rname": "hostmaster.example.com", "serial": 1}],
                "www": {"checked": True, "domain": "www.example.com", "CNAME": ["example.com"], "errors": []},
            },
            "email_security": {
                "spf": {"present": True, "record_count": 1, "all_mechanism": "-all", "records": ["v=spf1 -all"]},
                "dmarc": {"present": True, "record_count": 1, "policy": "reject", "records": ["v=DMARC1; p=reject"]},
                "dkim": {"checked": False, "status": "not_checked"},
            },
            "findings": [{"id": "domain_caa_absent", "title": "CAA records were not observed", "level": "info"}],
            "summary": {
                "records_found_count": 7,
                "findings_count": 1,
                "spf_present": True,
                "dmarc_present": True,
                "dmarc_policy": "reject",
                "caa_present": True,
                "mx_present": True,
                "www_resolves": True,
            },
            "errors": [],
        },
    )
    app.state.jobs.save(job)
    return job


def save_subdomain_inventory_export_fixture_job() -> JobRecord:
    now = datetime(2026, 5, 26, tzinfo=timezone.utc)
    job = JobRecord(
        id="8" * 32,
        audit_type="subdomain_inventory_basic",
        file_id=None,
        target_domain="example.com",
        status="completed",
        created_at=now,
        updated_at=now,
        result={
            "analyzer": "subdomain_inventory_basic",
            "target": {
                "root_domain": "example.com",
                "normalized_root_domain": "example.com",
                "checked_at": now.isoformat(),
            },
            "summary": {
                "candidates_submitted": 4,
                "candidates_accepted": 3,
                "candidates_rejected": 1,
                "candidates_processed": 2,
                "candidates_pending": 1,
                "resolved_count": 1,
                "unresolved_count": 1,
                "cname_count": 1,
                "private_ip_count": 1,
                "findings_count": 3,
                "wildcard_dns_possible": False,
                "truncated": True,
                "deadline_reached": True,
            },
            "limits": {
                "global_deadline_seconds": 30,
                "dns_timeout_seconds": 5,
                "max_candidates": 100,
                "wildcard_checks": 2,
            },
            "candidates": [
                {"input": "www", "fqdn": "www.example.com", "status": "accepted"},
                {"input": "api.example.com", "fqdn": "api.example.com", "status": "accepted"},
                {"input": "cdn", "fqdn": "cdn.example.com", "status": "accepted"},
                {"input": "api.evil.com", "fqdn": None, "status": "rejected", "rejection_reason": "outside root"},
            ],
            "results": [
                {
                    "fqdn": "www.example.com",
                    "resolves": True,
                    "status": "processed",
                    "A": ["192.168.1.10"],
                    "AAAA": [],
                    "CNAME": ["example.net"],
                    "private_or_reserved_ip_detected": True,
                    "errors": [],
                },
                {
                    "fqdn": "api.example.com",
                    "resolves": False,
                    "status": "processed",
                    "A": [],
                    "AAAA": [],
                    "CNAME": [],
                    "private_or_reserved_ip_detected": False,
                    "errors": ["A query failed safely."],
                },
                {
                    "fqdn": "cdn.example.com",
                    "resolves": False,
                    "status": "skipped",
                    "skip_reason": "global_deadline_reached",
                    "deadline_reached": True,
                    "A": [],
                    "AAAA": [],
                    "CNAME": [],
                    "private_or_reserved_ip_detected": False,
                    "errors": ["Skipped because the global subdomain inventory deadline was reached."],
                },
            ],
            "wildcard_dns": {"checked": True, "possible": False, "probes_count": 2, "notes": "heuristic", "errors": []},
            "findings": [
                {"id": "subdomain_private_or_reserved_ip", "title": "Private IP", "level": "low"},
                {"id": "subdomain_external_cname", "title": "External CNAME", "level": "info"},
                {"id": "subdomain_global_deadline_reached", "title": "Deadline reached", "level": "low"},
            ],
            "truncation_reason": "global_deadline_reached",
            "errors": [],
        },
    )
    app.state.jobs.save(job)
    return job


def save_django_config_export_fixture_job() -> JobRecord:
    now = datetime(2026, 5, 26, tzinfo=timezone.utc)
    job = JobRecord(
        id="d" * 32,
        audit_type="django_config_basic",
        file_id="4" * 32,
        status="completed",
        created_at=now,
        updated_at=now,
        result={
            "analyzer": "django_config_basic",
            "archive_type": "zip",
            "completed_at": now.isoformat(),
            "hashes": {"sha256": "abc123"},
            "file_identification": {"size_bytes": 2048, "original_filename": "django.zip"},
            "limits": {"max_files": 100, "max_file_bytes": 524288, "max_total_bytes": 2097152},
            "summary": {
                "files_considered": 2,
                "files_read": 1,
                "settings_files_detected": 1,
                "deployment_files_detected": 0,
                "env_files_detected": 1,
                "findings_count": 2,
                "secrets_redacted_count": 1,
                "truncated": False,
            },
            "detected_files": [
                {"path": "project/settings.py", "category": "django_config", "read": True, "size_bytes": 128, "context": "production"},
                {"path": ".env", "category": "env_sensitive", "read": False, "skip_reason": "sensitive_env_not_read"},
            ],
            "django_signals": {
                "debug": {"status": "enabled_or_default_true", "files": ["project/settings.py"]},
                "secret_key": {"status": "hardcoded", "files": ["project/settings.py"]},
            },
            "findings": [
                {
                    "id": "django_debug_enabled",
                    "title": "Django DEBUG appears enabled or defaults to true",
                    "level": "medium",
                    "description": "Review production settings.",
                    "evidence": "DEBUG = True",
                    "recommendation": "Set DEBUG=False in production.",
                    "file_path": "project/settings.py",
                    "context": "production",
                },
                {
                    "id": "django_secret_key_hardcoded",
                    "title": "Django SECRET_KEY appears hardcoded",
                    "level": "medium",
                    "description": "Review production secrets.",
                    "evidence": "SECRET_KEY = [REDACTED]",
                    "recommendation": "Load SECRET_KEY from a protected environment secret.",
                    "context": "grouped",
                },
            ],
            "errors": [],
        },
    )
    app.state.jobs.save(job)
    return job


def save_docker_config_export_fixture_job() -> JobRecord:
    now = datetime(2026, 5, 31, tzinfo=timezone.utc)
    job = JobRecord(
        id="c" * 32,
        audit_type="docker_config_basic",
        file_id="4" * 32,
        status="completed",
        created_at=now,
        updated_at=now,
        result={
            "analyzer": "docker_config_basic",
            "archive_type": "zip",
            "completed_at": now.isoformat(),
            "hashes": {"sha256": "abc123"},
            "file_identification": {"size_bytes": 2048, "original_filename": "docker.zip"},
            "limits": {"max_files": 100, "max_file_bytes": 524288, "max_total_bytes": 2097152},
            "summary": {
                "files_considered": 2,
                "files_reviewed": 2,
                "dockerfiles_detected": 1,
                "compose_files_detected": 1,
                "dockerignore_files_detected": 0,
                "services_detected": 1,
                "findings_count": 2,
                "secrets_redacted_count": 1,
                "truncated": False,
            },
            "files_detected": [
                {"path": "project/Dockerfile", "category": "dockerfile", "read": True, "size_bytes": 128, "context": "production"},
                {"path": "docker-compose.yml", "category": "compose", "read": True, "size_bytes": 256, "context": "shared"},
            ],
            "files_reviewed": [
                {"path": "project/Dockerfile", "category": "dockerfile", "context": "production", "bytes_read": 128},
                {"path": "docker-compose.yml", "category": "compose", "context": "shared", "bytes_read": 256},
            ],
            "dockerfile_stages": [
                {
                    "file_path": "project/Dockerfile",
                    "context": "production",
                    "base_image": "python:latest",
                    "stage": None,
                    "user_observed": True,
                    "healthcheck_observed": False,
                }
            ],
            "compose_services": [{"file_path": "docker-compose.yml", "name": "web", "context": "shared"}],
            "findings": [
                {
                    "id": "docker_runs_as_root",
                    "title": "Dockerfile declares root as runtime user",
                    "level": "medium",
                    "description": "Review the runtime user.",
                    "evidence": "USER = root",
                    "recommendation": "Use a dedicated non-root runtime user where practical.",
                    "file_path": "project/Dockerfile",
                    "context": "production",
                },
                {
                    "id": "docker_sensitive_env_name",
                    "title": "Compose file contains a sensitive-looking environment name",
                    "level": "low",
                    "description": "Review secret injection.",
                    "evidence": "SECRET_KEY= [REDACTED]",
                    "recommendation": "Avoid committing real secret values.",
                    "file_path": "docker-compose.yml",
                    "context": "shared",
                },
            ],
            "redaction_notes": ["Secret-like values in Docker/Compose evidence are redacted on a best-effort basis."],
            "errors": [],
        },
    )
    app.state.jobs.save(job)
    return job


def save_secrets_review_export_fixture_job() -> JobRecord:
    now = datetime(2026, 5, 31, tzinfo=timezone.utc)
    job = JobRecord(
        id="d" * 32,
        audit_type="secrets_review_basic",
        file_id="4" * 32,
        status="completed",
        created_at=now,
        updated_at=now,
        result={
            "analyzer": "secrets_review_basic",
            "archive_type": "zip",
            "completed_at": now.isoformat(),
            "hashes": {"sha256": "abc123"},
            "file_identification": {"size_bytes": 2048, "original_filename": "secrets.zip"},
            "limits": {"max_files": 100, "max_file_bytes": 524288, "max_total_bytes": 2097152},
            "summary": {
                "files_considered": 3,
                "files_reviewed": 2,
                "sensitive_files_detected": 1,
                "findings_count": 2,
                "high_confidence_count": 1,
                "redacted_values_count": 2,
                "truncated": False,
            },
            "sensitive_files": [
                {
                    "path": ".env.production",
                    "category": "env_sensitive",
                    "context": "production",
                    "read": False,
                    "skip_reason": "real_env_file_not_read",
                    "size_bytes": 120,
                }
            ],
            "files_detected": [
                {
                    "path": ".env.production",
                    "category": "env_sensitive",
                    "read": False,
                    "skip_reason": "real_env_file_not_read",
                    "context": "production",
                },
                {"path": ".env.example", "category": "env_template", "read": True, "size_bytes": 128, "context": "example"},
                {"path": "project/settings.py", "category": "app_config", "read": True, "size_bytes": 256, "context": "production"},
            ],
            "files_reviewed": [
                {"path": ".env.example", "category": "env_template", "context": "example", "bytes_read": 128},
                {"path": "project/settings.py", "category": "app_config", "context": "production", "bytes_read": 256},
            ],
            "findings": [
                {
                    "id": "secret_like_assignment",
                    "title": "Secret-like assignment observed",
                    "level": "medium",
                    "confidence": "medium",
                    "category": "secret_assignment",
                    "description": "A secret-like key appears to have an inline value.",
                    "evidence": "SECRET_KEY=[REDACTED]",
                    "recommendation": "Move real secret values to an approved runtime secret mechanism.",
                    "file_path": "project/settings.py",
                    "context": "production",
                    "line": "12",
                },
                {
                    "id": "real_env_file_present_not_read",
                    "title": "Real environment file detected but not read",
                    "level": "low",
                    "confidence": "high",
                    "category": "sensitive_file",
                    "description": "A real .env-style file was present in the archive.",
                    "evidence": ".env.production",
                    "recommendation": "Remove real environment files from shared archives.",
                    "file_path": ".env.production",
                    "context": "production",
                },
            ],
            "redaction_notes": ["Secret-like values are redacted before storage and export on a best-effort basis."],
            "errors": [],
        },
    )
    app.state.jobs.save(job)
    return job


def save_node_package_config_export_fixture_job() -> JobRecord:
    now = datetime(2026, 5, 31, tzinfo=timezone.utc)
    job = JobRecord(
        id="b" * 31 + "7",
        audit_type="node_package_config_basic",
        file_id="4" * 32,
        status="completed",
        created_at=now,
        updated_at=now,
        result={
            "analyzer": "node_package_config_basic",
            "archive_type": "zip",
            "completed_at": now.isoformat(),
            "hashes": {"sha256": "abc123"},
            "file_identification": {"size_bytes": 4096, "original_filename": "node.zip"},
            "limits": {"max_files": 100, "max_file_bytes": 524288, "max_total_bytes": 2097152},
            "summary": {
                "files_considered": 5,
                "files_reviewed": 4,
                "package_manifests_detected": 1,
                "lockfiles_detected": 1,
                "package_manager_configs_detected": 1,
                "packages_detected": 1,
                "scripts_detected": 2,
                "findings_count": 2,
                "redacted_values_count": 1,
                "truncated": False,
            },
            "files_detected": [
                {"path": "project/package.json", "category": "package_manifest", "read": True, "size_bytes": 512, "context": "shared"},
                {"path": "project/pnpm-lock.yaml", "category": "lockfile", "read": True, "size_bytes": 1024, "context": "shared"},
                {"path": "project/.npmrc", "category": "package_manager_config", "read": True, "size_bytes": 128, "context": "shared"},
                {"path": "project/vite.config.ts", "category": "js_ts_config", "read": True, "size_bytes": 256, "context": "development"},
                {"path": "project/.env.production", "category": "env_sensitive", "read": False, "skip_reason": "real_env_file_not_read", "context": "production"},
            ],
            "files_reviewed": [
                {"path": "project/package.json", "category": "package_manifest", "context": "shared", "bytes_read": 512},
                {"path": "project/pnpm-lock.yaml", "category": "lockfile", "context": "shared", "bytes_read": 1024},
                {"path": "project/.npmrc", "category": "package_manager_config", "context": "shared", "bytes_read": 128},
                {"path": "project/vite.config.ts", "category": "js_ts_config", "context": "development", "bytes_read": 256},
            ],
            "packages": [
                {
                    "file_path": "project/package.json",
                    "name": "inspectra-demo",
                    "version": "1.0.0",
                    "private": False,
                    "package_manager": "pnpm@9.0.0",
                    "context": "shared",
                }
            ],
            "scripts": [
                {"file_path": "project/package.json", "name": "postinstall", "command": "node scripts/setup.js", "context": "shared"},
                {"file_path": "project/package.json", "name": "build", "command": "vite build", "context": "shared"},
            ],
            "dependency_groups": [
                {
                    "file_path": "project/package.json",
                    "group": "dependencies",
                    "dependencies": [{"name": "react", "specifier": "^18.3.1", "source_type": "registry"}],
                    "context": "shared",
                }
            ],
            "package_manager_config_signals": [
                {"file_path": "project/.npmrc", "key": "_authToken", "value": "[REDACTED]", "line": "1", "context": "shared"}
            ],
            "lockfile_signals": [
                {"file_path": "project/pnpm-lock.yaml", "lockfile": "pnpm-lock.yaml", "manager": "pnpm", "context": "shared"}
            ],
            "findings": [
                {
                    "id": "postinstall_script_present",
                    "title": "Lifecycle script requires review",
                    "level": "low",
                    "confidence": "medium",
                    "category": "scripts",
                    "description": "A postinstall script is present in package.json.",
                    "evidence": "postinstall: node scripts/setup.js",
                    "recommendation": "Review lifecycle scripts before installing dependencies.",
                    "file_path": "project/package.json",
                    "context": "shared",
                    "line": "8",
                },
                {
                    "id": "npmrc_token_reference_detected",
                    "title": "npm config references an auth token",
                    "level": "medium",
                    "confidence": "high",
                    "category": "package_manager_config",
                    "description": "An npm auth token-like setting was observed.",
                    "evidence": "_authToken=[REDACTED]",
                    "recommendation": "Keep registry credentials out of shared archives.",
                    "file_path": "project/.npmrc",
                    "context": "shared",
                    "line": "1",
                },
            ],
            "redaction_notes": ["npm registry credentials and script secret-like assignments are redacted on a best-effort basis."],
            "errors": [],
        },
    )
    app.state.jobs.save(job)
    return job


def save_ci_cd_config_export_fixture_job() -> JobRecord:
    now = datetime(2026, 5, 31, tzinfo=timezone.utc)
    job = JobRecord(
        id="c" * 31 + "7",
        audit_type="ci_cd_config_basic",
        file_id="4" * 32,
        status="completed",
        created_at=now,
        updated_at=now,
        result={
            "analyzer": "ci_cd_config_basic",
            "archive_type": "zip",
            "completed_at": now.isoformat(),
            "hashes": {"sha256": "abc123"},
            "file_identification": {"size_bytes": 4096, "original_filename": "ci.zip"},
            "limits": {"max_files": 100, "max_file_bytes": 524288, "max_total_bytes": 2097152},
            "summary": {
                "files_considered": 4,
                "files_reviewed": 3,
                "workflow_files_detected": 2,
                "jobs_detected": 2,
                "steps_detected": 4,
                "triggers_detected": 2,
                "findings_count": 2,
                "redacted_values_count": 1,
                "truncated": False,
            },
            "files_detected": [
                {"path": ".github/workflows/release.yml", "category": "github_actions", "read": True, "size_bytes": 1024, "context": "production"},
                {"path": ".gitlab-ci.yml", "category": "gitlab_ci", "read": True, "size_bytes": 512, "context": "shared"},
                {"path": ".env.production", "category": "env_sensitive", "read": False, "skip_reason": "real_env_file_not_read", "context": "production"},
            ],
            "files_reviewed": [
                {"path": ".github/workflows/release.yml", "category": "github_actions", "context": "production", "bytes_read": 1024},
                {"path": ".gitlab-ci.yml", "category": "gitlab_ci", "context": "shared", "bytes_read": 512},
            ],
            "workflows": [
                {
                    "file_path": ".github/workflows/release.yml",
                    "provider": "github_actions",
                    "name": "release",
                    "context": "production",
                }
            ],
            "jobs": [
                {
                    "file_path": ".github/workflows/release.yml",
                    "provider": "github_actions",
                    "job": "publish",
                    "steps_detected": 2,
                    "context": "production",
                }
            ],
            "triggers": [
                {
                    "file_path": ".github/workflows/release.yml",
                    "provider": "github_actions",
                    "trigger": "pull_request_target",
                    "context": "production",
                }
            ],
            "permissions": [
                {
                    "file_path": ".github/workflows/release.yml",
                    "provider": "github_actions",
                    "permission": "contents",
                    "value": "write",
                    "context": "production",
                }
            ],
            "actions": [
                {
                    "file_path": ".github/workflows/release.yml",
                    "provider": "github_actions",
                    "action": "actions/checkout",
                    "ref": "main",
                    "job": "publish",
                    "context": "production",
                }
            ],
            "service_containers": [
                {"file_path": ".gitlab-ci.yml", "provider": "gitlab_ci", "image": "postgres:latest", "context": "shared"}
            ],
            "publish_deploy_signals": [
                {"file_path": ".github/workflows/release.yml", "provider": "github_actions", "job": "publish", "signal": "npm publish"}
            ],
            "findings": [
                {
                    "id": "pull_request_target_used",
                    "title": "pull_request_target trigger requires review",
                    "level": "medium",
                    "confidence": "medium",
                    "category": "triggers",
                    "provider": "github_actions",
                    "description": "A workflow uses pull_request_target.",
                    "evidence": "on: pull_request_target",
                    "recommendation": "Review checkout and script behavior before using privileged pull request triggers.",
                    "file_path": ".github/workflows/release.yml",
                    "job": "publish",
                    "step": "checkout",
                    "context": "production",
                    "line": "4",
                },
                {
                    "id": "inline_secret_like_env",
                    "title": "Inline secret-like CI environment value observed",
                    "level": "medium",
                    "confidence": "high",
                    "category": "secrets_env",
                    "provider": "github_actions",
                    "description": "A secret-like CI env value was observed.",
                    "evidence": "TOKEN=[REDACTED]",
                    "recommendation": "Use provider secret stores and avoid inline values.",
                    "file_path": ".github/workflows/release.yml",
                    "job": "publish",
                    "step": "publish",
                    "context": "production",
                    "line": "12",
                },
            ],
            "redaction_notes": ["CI/CD secret-like evidence is redacted on a best-effort basis."],
            "errors": [],
        },
    )
    app.state.jobs.save(job)
    return job


def save_k8s_config_export_fixture_job() -> JobRecord:
    now = datetime(2026, 5, 31, tzinfo=timezone.utc)
    job = JobRecord(
        id="e" * 31 + "7",
        audit_type="k8s_config_basic",
        file_id="4" * 32,
        status="completed",
        created_at=now,
        updated_at=now,
        result={
            "analyzer": "k8s_config_basic",
            "archive_type": "zip",
            "completed_at": now.isoformat(),
            "hashes": {"sha256": "abc123"},
            "file_identification": {"size_bytes": 4096, "original_filename": "k8s.zip"},
            "limits": {"max_files": 100, "max_file_bytes": 524288, "max_total_bytes": 2097152},
            "summary": {
                "files_considered": 4,
                "files_reviewed": 3,
                "manifest_files_detected": 3,
                "resources_detected": 4,
                "workloads_detected": 1,
                "services_detected": 1,
                "secrets_detected": 1,
                "rbac_resources_detected": 1,
                "findings_count": 2,
                "redacted_values_count": 2,
                "truncated": False,
            },
            "files_detected": [
                {"path": "deploy/production/app.yaml", "category": "k8s_manifest", "read": True, "size_bytes": 2048, "context": "production"},
                {"path": "charts/app/templates/deployment.yaml", "category": "helm_template", "read": True, "size_bytes": 512, "context": "example"},
                {"path": "kustomization.yaml", "category": "kustomize_config", "read": True, "size_bytes": 128, "context": "shared"},
                {"path": ".env.production", "category": "env_sensitive", "read": False, "skip_reason": "real_env_file_not_read", "context": "production"},
            ],
            "files_reviewed": [
                {"path": "deploy/production/app.yaml", "category": "k8s_manifest", "context": "production", "bytes_read": 2048},
                {"path": "charts/app/templates/deployment.yaml", "category": "helm_template", "context": "example", "bytes_read": 512},
                {"path": "kustomization.yaml", "category": "kustomize_config", "context": "shared", "bytes_read": 128},
            ],
            "resources": [
                {"path": "deploy/production/app.yaml", "kind": "Deployment", "name": "web", "namespace": "production", "context": "production"},
                {"path": "deploy/production/app.yaml", "kind": "Secret", "name": "app-secret", "namespace": "production", "context": "production"},
            ],
            "workloads": [{"path": "deploy/production/app.yaml", "kind": "Deployment", "name": "web", "namespace": "production", "context": "production"}],
            "containers": [
                {
                    "path": "deploy/production/app.yaml",
                    "kind": "Deployment",
                    "resource_name": "web",
                    "namespace": "production",
                    "container": "app",
                    "image": "nginx:latest",
                    "context": "production",
                }
            ],
            "services": [{"path": "deploy/production/app.yaml", "kind": "Service", "name": "web", "type": "LoadBalancer", "context": "production"}],
            "ingress": [{"path": "deploy/production/app.yaml", "kind": "Ingress", "name": "web", "context": "production"}],
            "rbac": [{"path": "deploy/production/app.yaml", "kind": "ClusterRole", "name": "broad", "context": "production"}],
            "secrets": [{"path": "deploy/production/app.yaml", "kind": "Secret", "name": "app-secret", "namespace": "production", "context": "production"}],
            "helm_kustomize_signals": [
                {"path": "charts/app/templates/deployment.yaml", "category": "helm_template", "rendered": False, "context": "example"},
                {"path": "kustomization.yaml", "category": "kustomize_config", "built": False, "context": "shared"},
            ],
            "findings": [
                {
                    "id": "privileged_container",
                    "title": "Container is configured as privileged",
                    "level": "medium",
                    "confidence": "high",
                    "category": "pod_security",
                    "context": "production",
                    "kind": "Deployment",
                    "resource_name": "web",
                    "namespace": "production",
                    "container": "app",
                    "field_path": "securityContext.privileged",
                    "file_path": "deploy/production/app.yaml",
                    "line": "22",
                    "description": "A Kubernetes manifest review indicator was observed.",
                    "evidence": "kind=Deployment; metadata.name=web; container=app; field=securityContext.privileged",
                    "recommendation": "Review the manifest in the intended deployment context.",
                },
                {
                    "id": "k8s_secret_stringdata_present",
                    "title": "Kubernetes Secret stringData contains plaintext values",
                    "level": "medium",
                    "confidence": "high",
                    "category": "secrets",
                    "context": "production",
                    "kind": "Secret",
                    "resource_name": "app-secret",
                    "namespace": "production",
                    "field_path": "stringData.password",
                    "file_path": "deploy/production/app.yaml",
                    "line": "8",
                    "description": "A Kubernetes Secret contains secret material.",
                    "evidence": "kind=Secret; metadata.name=app-secret; key password=[REDACTED]",
                    "recommendation": "Avoid sharing plaintext secret material in archives.",
                },
            ],
            "redaction_notes": ["Secret-like Kubernetes manifest values are redacted on a best-effort basis."],
            "errors": [],
        },
    )
    app.state.jobs.save(job)
    return job


def save_terraform_config_export_fixture_job() -> JobRecord:
    now = datetime(2026, 5, 31, tzinfo=timezone.utc)
    job = JobRecord(
        id="f" * 31 + "7",
        audit_type="terraform_config_basic",
        file_id="4" * 32,
        status="completed",
        created_at=now,
        updated_at=now,
        result={
            "analyzer": "terraform_config_basic",
            "archive_type": "zip",
            "completed_at": now.isoformat(),
            "hashes": {"sha256": "abc123"},
            "file_identification": {"size_bytes": 4096, "original_filename": "terraform.zip"},
            "limits": {"max_files": 100, "max_file_bytes": 524288, "max_total_bytes": 2097152},
            "summary": {
                "files_considered": 5,
                "files_reviewed": 3,
                "terraform_files_detected": 2,
                "tfvars_files_detected": 1,
                "state_files_detected": 1,
                "providers_detected": 1,
                "backends_detected": 1,
                "modules_detected": 1,
                "resources_detected": 2,
                "findings_count": 2,
                "redacted_values_count": 2,
                "truncated": False,
            },
            "files_detected": [
                {"path": "infra/prod/main.tf", "category": "terraform", "read": True, "size_bytes": 2048, "context": "production"},
                {"path": "infra/prod/variables.tf", "category": "terraform", "read": True, "size_bytes": 512, "context": "production"},
                {"path": "infra/prod/prod.tfvars", "category": "tfvars", "read": True, "size_bytes": 256, "context": "production"},
                {"path": "infra/prod/terraform.tfstate", "category": "state_file", "read": False, "skip_reason": "terraform_state_file_not_read", "context": "production"},
            ],
            "files_reviewed": [
                {"path": "infra/prod/main.tf", "category": "terraform", "context": "production", "bytes_read": 2048},
                {"path": "infra/prod/variables.tf", "category": "terraform", "context": "production", "bytes_read": 512},
                {"path": "infra/prod/prod.tfvars", "category": "tfvars", "context": "production", "bytes_read": 256},
            ],
            "providers": [{"file_path": "infra/prod/main.tf", "name": "aws", "version": "~> 5.0", "context": "production"}],
            "backends": [{"file_path": "infra/prod/main.tf", "type": "s3", "context": "production"}],
            "modules": [{"file_path": "infra/prod/main.tf", "name": "network", "source": "git::https://example.com/net.git?ref=v1", "context": "production"}],
            "resources": [
                {
                    "file_path": "infra/prod/main.tf",
                    "provider": "aws",
                    "resource_type": "aws_security_group",
                    "resource_name": "web",
                    "context": "production",
                },
                {
                    "file_path": "infra/prod/main.tf",
                    "provider": "aws",
                    "resource_type": "aws_s3_bucket",
                    "resource_name": "assets",
                    "context": "production",
                },
            ],
            "variables": [
                {"file_path": "infra/prod/variables.tf", "name": "db_password", "default": "[REDACTED]", "context": "production"}
            ],
            "outputs": [{"file_path": "infra/prod/main.tf", "name": "api_key", "sensitive": False, "context": "production"}],
            "state_files": [
                {
                    "path": "infra/prod/terraform.tfstate",
                    "category": "terraform_state",
                    "read": False,
                    "skip_reason": "terraform_state_file_not_read",
                    "context": "production",
                }
            ],
            "findings": [
                {
                    "id": "aws_security_group_ssh_open_world",
                    "title": "Security group allows SSH from any IPv4 address",
                    "level": "medium",
                    "confidence": "medium",
                    "category": "aws_network",
                    "context": "production",
                    "provider": "aws",
                    "resource_type": "aws_security_group",
                    "resource_name": "web",
                    "block_type": "resource",
                    "field_path": "ingress.cidr_blocks",
                    "file_path": "infra/prod/main.tf",
                    "line": "22",
                    "description": "A Terraform review indicator was observed.",
                    "evidence": "aws_security_group.web ingress cidr_blocks includes 0.0.0.0/0 on port 22",
                    "recommendation": "Review the rule in the intended cloud context.",
                },
                {
                    "id": "terraform_state_file_present",
                    "title": "Terraform state file present in archive",
                    "level": "medium",
                    "confidence": "high",
                    "category": "state",
                    "context": "production",
                    "file_path": "infra/prod/terraform.tfstate",
                    "description": "Terraform state files can contain secrets and generated values.",
                    "evidence": "path=infra/prod/terraform.tfstate; read=false",
                    "recommendation": "Avoid sharing Terraform state files in archives.",
                },
            ],
            "redaction_notes": ["Terraform secret-like values and state contents are redacted on a best-effort basis."],
            "errors": [],
        },
    )
    app.state.jobs.save(job)
    return job


def save_nginx_config_export_fixture_job() -> JobRecord:
    now = datetime(2026, 6, 1, tzinfo=timezone.utc)
    job = JobRecord(
        id="9" * 31 + "7",
        audit_type="nginx_config_basic",
        file_id="4" * 32,
        status="completed",
        created_at=now,
        updated_at=now,
        result={
            "analyzer": "nginx_config_basic",
            "archive_type": "zip",
            "completed_at": now.isoformat(),
            "hashes": {"sha256": "abc123"},
            "file_identification": {"size_bytes": 4096, "original_filename": "nginx.zip"},
            "limits": {"max_files": 100, "max_file_bytes": 524288, "max_total_bytes": 2097152},
            "summary": {
                "files_considered": 2,
                "files_reviewed": 2,
                "nginx_files_detected": 2,
                "server_blocks_detected": 2,
                "location_blocks_detected": 3,
                "upstream_blocks_detected": 1,
                "includes_detected": 2,
                "tls_servers_detected": 1,
                "findings_count": 2,
                "redacted_values_count": 2,
                "truncated": False,
            },
            "files_detected": [
                {"path": "deploy/nginx/default.conf", "category": "nginx_config", "read": True, "size_bytes": 2048, "context": "production"},
                {"path": "deploy/nginx/conf.d/app.conf", "category": "nginx_config", "read": True, "size_bytes": 512, "context": "production"},
            ],
            "files_reviewed": [
                {"path": "deploy/nginx/default.conf", "category": "nginx_config", "context": "production", "bytes_read": 2048},
                {"path": "deploy/nginx/conf.d/app.conf", "category": "nginx_config", "context": "production", "bytes_read": 512},
            ],
            "servers": [
                {
                    "path": "deploy/nginx/default.conf",
                    "context": "production",
                    "line": 1,
                    "server_name": "example.com",
                    "listen": ["80 default_server", "443 ssl"],
                    "tls": True,
                }
            ],
            "locations": [
                {"path": "deploy/nginx/default.conf", "context": "production", "line": 20, "location": "/api", "server_name": "example.com"},
                {"path": "deploy/nginx/default.conf", "context": "production", "line": 28, "location": "/.git", "server_name": "example.com"},
                {"path": "deploy/nginx/conf.d/app.conf", "context": "production", "line": 4, "location": "/status", "server_name": "example.com"},
            ],
            "upstreams": [{"path": "deploy/nginx/default.conf", "context": "production", "line": 40, "name": "backend"}],
            "includes": [
                {"path": "deploy/nginx/default.conf", "context": "production", "line": 8, "target": "/etc/nginx/snippets/tls.conf", "absolute": True, "glob": False, "resolved": False},
                {"path": "deploy/nginx/default.conf", "context": "production", "line": 9, "target": "conf.d/*.conf", "absolute": False, "glob": True, "resolved": False},
            ],
            "directives": [
                {
                    "path": "deploy/nginx/default.conf",
                    "context": "production",
                    "line": 22,
                    "directive": "proxy_pass",
                    "arguments": "http://[REDACTED]@example.com",
                    "block_type": "location",
                    "server_name": "example.com",
                    "location": "/api",
                },
                {
                    "path": "deploy/nginx/default.conf",
                    "context": "production",
                    "line": 23,
                    "directive": "proxy_set_header",
                    "arguments": "Host $host",
                    "block_type": "location",
                    "server_name": "example.com",
                    "location": "/api",
                },
            ],
            "findings": [
                {
                    "id": "nginx_proxy_pass_credentials_hint",
                    "title": "Nginx proxy_pass URL contains credentials",
                    "level": "medium",
                    "confidence": "high",
                    "category": "secrets",
                    "context": "production",
                    "block_type": "location",
                    "server_name": "example.com",
                    "location": "/api",
                    "directive": "proxy_pass",
                    "file_path": "deploy/nginx/default.conf",
                    "line": "22",
                    "description": "A Nginx static review indicator was observed.",
                    "evidence": "proxy_pass=[REDACTED]",
                    "recommendation": "Move upstream credentials out of committed proxy URLs.",
                },
                {
                    "id": "nginx_include_not_resolved",
                    "title": "Nginx include was detected but not resolved",
                    "level": "low",
                    "confidence": "high",
                    "category": "include",
                    "context": "production",
                    "block_type": "server",
                    "directive": "include",
                    "file_path": "deploy/nginx/default.conf",
                    "line": "8",
                    "description": "Includes are detected but intentionally not resolved.",
                    "evidence": "include=/etc/nginx/snippets/tls.conf",
                    "recommendation": "Review referenced include files separately.",
                },
            ],
            "redaction_notes": [
                "Secret-like Nginx/reverse-proxy values are redacted before storage on a best-effort basis.",
                "Nginx include directives are detected but not resolved by this analyzer.",
            ],
            "errors": [],
        },
    )
    app.state.jobs.save(job)
    return job


def save_compose_config_export_fixture_job() -> JobRecord:
    now = datetime(2026, 6, 2, tzinfo=timezone.utc)
    job = JobRecord(
        id="7" * 31 + "7",
        audit_type="compose_config_basic",
        file_id="4" * 32,
        status="completed",
        created_at=now,
        updated_at=now,
        result={
            "analyzer": "compose_config_basic",
            "archive_type": "zip",
            "completed_at": now.isoformat(),
            "hashes": {"sha256": "abc123"},
            "file_identification": {"size_bytes": 4096, "original_filename": "compose.zip"},
            "limits": {"max_files": 100, "max_file_bytes": 524288, "max_total_bytes": 2097152},
            "summary": {
                "files_considered": 3,
                "files_reviewed": 2,
                "compose_files_detected": 2,
                "services_detected": 3,
                "networks_detected": 2,
                "volumes_detected": 2,
                "secrets_detected": 1,
                "published_ports_detected": 3,
                "env_files_detected": 1,
                "findings_count": 2,
                "redacted_values_count": 2,
                "truncated": False,
            },
            "files_detected": [
                {"path": "deploy/compose/docker-compose.yml", "category": "compose_config", "read": True, "size_bytes": 2048, "context": "production"},
                {"path": "deploy/compose/docker-compose.override.yml", "category": "compose_config", "read": True, "size_bytes": 512, "context": "production"},
                {"path": "deploy/compose/.env", "category": "env_file_sensitive", "read": False, "skip_reason": "sensitive_env_file_not_read", "context": "production"},
            ],
            "files_reviewed": [
                {"path": "deploy/compose/docker-compose.yml", "category": "compose_config", "context": "production", "bytes_read": 2048},
                {"path": "deploy/compose/docker-compose.override.yml", "category": "compose_config", "context": "production", "bytes_read": 512},
            ],
            "services": [
                {"file_path": "deploy/compose/docker-compose.yml", "name": "web", "image": "nginx:latest", "context": "production"},
                {"file_path": "deploy/compose/docker-compose.yml", "name": "db", "image": "postgres:15", "context": "production"},
                {"file_path": "deploy/compose/docker-compose.yml", "name": "worker", "build": "./worker", "context": "production"},
            ],
            "images": [
                {"service": "web", "image": "nginx:latest", "tag": "latest", "context": "production"},
                {"service": "db", "image": "postgres:15", "tag": "15", "context": "production"},
            ],
            "build_contexts": [{"service": "worker", "context": "./worker", "file_path": "deploy/compose/docker-compose.yml"}],
            "ports": [
                {"service": "web", "host_ip": "0.0.0.0", "published": "8080", "target": "80", "protocol": "tcp"},
                {"service": "db", "host_ip": "0.0.0.0", "published": "5432", "target": "5432", "protocol": "tcp"},
                {"service": "admin", "published": "9000-9010", "target": "9000-9010", "protocol": "tcp"},
            ],
            "volumes": [
                {"service": "web", "host_path": "/var/run/docker.sock", "container_path": "/var/run/docker.sock", "read_only": False},
                {"service": "db", "name": "postgres-data", "container_path": "/var/lib/postgresql/data"},
            ],
            "networks": [
                {"name": "edge", "external": True, "internal": False},
                {"name": "backend", "external": False, "internal": True},
            ],
            "secrets": [{"name": "db_password", "file": "./secrets/db_password.txt", "read": False}],
            "env_files": [{"service": "db", "path": ".env", "read": False, "skip_reason": "env_file_not_read"}],
            "findings": [
                {
                    "id": "compose_environment_secret_like_value",
                    "title": "Compose environment has secret-like value",
                    "level": "medium",
                    "confidence": "high",
                    "category": "secrets",
                    "context": "production",
                    "service": "db",
                    "field_path": "services.db.environment.POSTGRES_PASSWORD",
                    "file_path": "deploy/compose/docker-compose.yml",
                    "description": "A Compose review indicator was observed.",
                    "evidence": "POSTGRES_PASSWORD=[REDACTED]",
                    "recommendation": "Move secret-like values into a secret manager or runtime-only environment.",
                },
                {
                    "id": "compose_docker_socket_mounted",
                    "title": "Docker socket mounted into Compose service",
                    "level": "medium",
                    "confidence": "high",
                    "category": "volumes",
                    "context": "production",
                    "service": "web",
                    "host_path": "/var/run/docker.sock",
                    "container_path": "/var/run/docker.sock",
                    "file_path": "deploy/compose/docker-compose.yml",
                    "description": "A Compose review indicator was observed.",
                    "evidence": "host_path=/var/run/docker.sock; container_path=/var/run/docker.sock",
                    "recommendation": "Review whether the service needs Docker socket access.",
                },
            ],
            "redaction_notes": [
                "Secret-like Docker Compose values are redacted before storage on a best-effort basis.",
                "Compose env_file and secrets.file references are detected but not read by this analyzer.",
            ],
            "errors": [],
        },
    )
    app.state.jobs.save(job)
    return job


def save_database_config_export_fixture_job() -> JobRecord:
    now = datetime(2026, 6, 2, tzinfo=timezone.utc)
    job = JobRecord(
        id="5" * 31 + "7",
        audit_type="database_config_basic",
        file_id="4" * 32,
        status="completed",
        created_at=now,
        updated_at=now,
        result={
            "analyzer": "database_config_basic",
            "archive_type": "zip",
            "completed_at": now.isoformat(),
            "hashes": {"sha256": "abc123"},
            "file_identification": {"size_bytes": 4096, "original_filename": "database.zip"},
            "limits": {"max_files": 100, "max_file_bytes": 524288, "max_total_bytes": 2097152},
            "summary": {
                "files_considered": 5,
                "files_reviewed": 3,
                "database_files_detected": 3,
                "postgres_files_detected": 1,
                "mysql_files_detected": 1,
                "mariadb_files_detected": 1,
                "pg_hba_files_detected": 1,
                "dump_or_backup_files_detected": 2,
                "engines_detected": 2,
                "findings_count": 2,
                "redacted_values_count": 2,
                "truncated": False,
            },
            "files_detected": [
                {"path": "deploy/db/postgresql.conf", "category": "postgres", "read": True, "size_bytes": 1024, "context": "production"},
                {"path": "deploy/db/pg_hba.conf", "category": "pg_hba", "read": True, "size_bytes": 512, "context": "production"},
                {"path": "deploy/db/my.cnf", "category": "mysql", "read": True, "size_bytes": 512, "context": "production"},
                {"path": "db/prod.sql", "category": "dump_or_backup", "read": False, "skip_reason": "dump_or_backup_not_read", "context": "production"},
                {"path": ".pgpass", "category": "database_credential_file", "read": False, "skip_reason": "sensitive_file_not_read", "context": "production"},
            ],
            "files_reviewed": [
                {"path": "deploy/db/postgresql.conf", "category": "postgres", "context": "production", "bytes_read": 1024},
                {"path": "deploy/db/pg_hba.conf", "category": "pg_hba", "context": "production", "bytes_read": 512},
                {"path": "deploy/db/my.cnf", "category": "mysql", "context": "production", "bytes_read": 512},
            ],
            "engines": [
                {"engine": "postgresql", "file_path": "deploy/db/postgresql.conf", "context": "production"},
                {"engine": "mysql", "file_path": "deploy/db/my.cnf", "context": "production"},
            ],
            "postgres_settings": [
                {"file_path": "deploy/db/postgresql.conf", "engine": "postgresql", "line": 2, "setting": "listen_addresses", "value": "*"},
                {"file_path": "deploy/db/postgresql.conf", "engine": "postgresql", "line": 3, "setting": "primary_conninfo", "value": "[REDACTED]"},
            ],
            "pg_hba_rules": [
                {
                    "file_path": "deploy/db/pg_hba.conf",
                    "engine": "postgresql",
                    "line": 1,
                    "type": "host",
                    "database": "all",
                    "user": "all",
                    "address": "0.0.0.0/0",
                    "auth_method": "trust",
                }
            ],
            "mysql_settings": [
                {"file_path": "deploy/db/my.cnf", "engine": "mysql", "section": "mysqld", "line": 3, "setting": "bind-address", "value": "0.0.0.0"},
                {"file_path": "deploy/db/my.cnf", "engine": "mysql", "section": "mysqld", "line": 4, "setting": "password", "value": "[REDACTED]"},
            ],
            "includes": [
                {
                    "file_path": "deploy/db/postgresql.conf",
                    "engine": "postgresql",
                    "line": 5,
                    "directive": "include",
                    "target": "/etc/postgresql/secret.conf",
                    "resolved": False,
                }
            ],
            "dump_or_backup_files": [
                {"path": "db/prod.sql", "category": "dump_or_backup", "read": False, "skip_reason": "dump_or_backup_not_read"},
                {"path": "db/snapshot.backup", "category": "dump_or_backup", "read": False, "skip_reason": "dump_or_backup_not_read"},
            ],
            "findings": [
                {
                    "id": "postgres_pg_hba_trust_auth",
                    "title": "PostgreSQL pg_hba uses trust auth",
                    "level": "medium",
                    "confidence": "high",
                    "category": "auth",
                    "context": "production",
                    "engine": "postgresql",
                    "auth_method": "trust",
                    "address": "0.0.0.0/0",
                    "file_path": "deploy/db/pg_hba.conf",
                    "line": 1,
                    "description": "A database static configuration review indicator was observed.",
                    "evidence": "database=all; user=all; address=0.0.0.0/0; auth_method=trust",
                    "recommendation": "Review pg_hba.conf rules manually.",
                },
                {
                    "id": "database_include_not_resolved",
                    "title": "Database config include was detected but not resolved",
                    "level": "low",
                    "confidence": "high",
                    "category": "include",
                    "context": "production",
                    "engine": "postgresql",
                    "setting": "include",
                    "file_path": "deploy/db/postgresql.conf",
                    "line": 5,
                    "description": "Includes are detected but intentionally not resolved.",
                    "evidence": "include /etc/postgresql/secret.conf",
                    "recommendation": "Review included files manually in the intended deployment context.",
                },
            ],
            "redaction_notes": [
                "Secret-like database config values are redacted before storage on a best-effort basis.",
                ".env, .pgpass, hidden client credential files, dumps, and backups are detected but not read by this analyzer.",
            ],
            "errors": [],
        },
    )
    app.state.jobs.save(job)
    return job


def save_sql_database_config_export_fixture_job() -> JobRecord:
    now = datetime(2026, 6, 2, tzinfo=timezone.utc)
    job = JobRecord(
        id="7" * 31 + "7",
        audit_type="sql_database_config_basic",
        file_id="4" * 32,
        status="completed",
        created_at=now,
        updated_at=now,
        result={
            "analyzer": "sql_database_config_basic",
            "archive_type": "zip",
            "completed_at": now.isoformat(),
            "hashes": {"sha256": "sqlabc123"},
            "file_identification": {"size_bytes": 4096, "original_filename": "sql-db.zip"},
            "limits": {"max_files": 100, "max_file_bytes": 524288, "max_total_bytes": 2097152},
            "summary": {
                "files_considered": 7,
                "files_reviewed": 3,
                "postgres_configs_detected": 1,
                "postgres_hba_files_detected": 1,
                "mysql_configs_detected": 1,
                "mariadb_configs_detected": 1,
                "dump_or_backup_files_detected": 1,
                "data_files_detected": 1,
                "findings_count": 2,
                "redacted_values_count": 2,
                "truncated": False,
            },
            "files_detected": [
                {"path": "deploy/db/postgresql.conf", "category": "postgres", "read": True, "size_bytes": 1024, "context": "production"},
                {"path": "deploy/db/pg_hba.conf", "category": "pg_hba", "read": True, "size_bytes": 512, "context": "production"},
                {"path": "deploy/db/my.cnf", "category": "mysql", "read": True, "size_bytes": 512, "context": "production"},
                {"path": ".pgpass", "category": "sensitive", "read": False, "skip_reason": "sensitive_file_not_read", "context": "production"},
                {"path": "db/prod.sql", "category": "dump_or_backup", "read": False, "skip_reason": "dump_or_backup_not_read", "context": "production"},
                {"path": "db/postgres/pg_wal/0001", "category": "data_file", "read": False, "skip_reason": "data_file_not_read", "context": "production"},
            ],
            "files_reviewed": [
                {"path": "deploy/db/postgresql.conf", "category": "postgres", "context": "production", "bytes_read": 1024},
                {"path": "deploy/db/pg_hba.conf", "category": "pg_hba", "context": "production", "bytes_read": 512},
                {"path": "deploy/db/my.cnf", "category": "mysql", "context": "production", "bytes_read": 512},
            ],
            "postgres_configs": [
                {"file_path": "deploy/db/postgresql.conf", "category": "postgres", "engine": "postgresql", "context": "production", "settings_count": 2},
            ],
            "postgres_hba_rules": [
                {
                    "file_path": "deploy/db/pg_hba.conf",
                    "engine": "postgresql",
                    "line": 1,
                    "type": "host",
                    "database": "all",
                    "user": "all",
                    "address": "0.0.0.0/0",
                    "auth_method": "trust",
                }
            ],
            "mysql_configs": [
                {"file_path": "deploy/db/my.cnf", "category": "mysql", "engine": "mysql", "context": "production", "settings_count": 2},
                {"file_path": "deploy/db/mariadb.cnf", "category": "mariadb", "engine": "mariadb", "context": "production", "settings_count": 1},
            ],
            "database_settings": [
                {"file_path": "deploy/db/postgresql.conf", "engine": "postgresql", "line": 2, "setting": "listen_addresses", "value": "*"},
                {"file_path": "deploy/db/postgresql.conf", "engine": "postgresql", "line": 3, "setting": "primary_conninfo", "value": "[REDACTED]"},
                {"file_path": "deploy/db/my.cnf", "engine": "mysql", "section": "mysqld", "line": 3, "setting": "bind-address", "value": "0.0.0.0"},
                {"file_path": "deploy/db/my.cnf", "engine": "mysql", "section": "mysqld", "line": 4, "setting": "password", "value": "[REDACTED]"},
            ],
            "includes": [
                {
                    "file_path": "deploy/db/postgresql.conf",
                    "engine": "postgresql",
                    "line": 5,
                    "directive": "include",
                    "target": "/etc/postgresql/secret.conf",
                    "resolved": False,
                }
            ],
            "sensitive_files": [
                {"path": ".pgpass", "category": "sensitive", "read": False, "skip_reason": "sensitive_file_not_read"},
            ],
            "dump_or_backup_files": [
                {"path": "db/prod.sql", "category": "dump_or_backup", "read": False, "skip_reason": "dump_or_backup_not_read"},
            ],
            "data_files": [
                {"path": "db/postgres/pg_wal/0001", "category": "data_file", "read": False, "skip_reason": "data_file_not_read"},
            ],
            "findings": [
                {
                    "id": "postgres_hba_trust_auth_hint",
                    "code": "postgres_hba_trust_auth_hint",
                    "title": "PostgreSQL pg_hba uses trust auth",
                    "level": "medium",
                    "confidence": "high",
                    "category": "auth",
                    "context": "production",
                    "engine": "postgresql",
                    "auth_method": "trust",
                    "address": "0.0.0.0/0",
                    "file_path": "deploy/db/pg_hba.conf",
                    "line": 1,
                    "description": "A SQL database static configuration review indicator was observed.",
                    "evidence": "database=all; user=all; address=0.0.0.0/0; auth_method=trust",
                    "recommendation": "Review pg_hba.conf rules manually.",
                },
                {
                    "id": "sql_database_include_detected_not_resolved",
                    "code": "sql_database_include_detected_not_resolved",
                    "title": "SQL database config include was detected but not resolved",
                    "level": "low",
                    "confidence": "high",
                    "category": "include",
                    "context": "production",
                    "engine": "postgresql",
                    "setting": "include",
                    "file_path": "deploy/db/postgresql.conf",
                    "line": 5,
                    "description": "Includes are detected but intentionally not resolved.",
                    "evidence": "include /etc/postgresql/secret.conf",
                    "recommendation": "Review included files manually in the intended deployment context.",
                },
            ],
            "redaction_notes": [
                "Secret-like SQL database config values are redacted before storage on a best-effort basis.",
                ".env, client credential, dump, backup, data, WAL/binlog, and key-like files are detected but not read by this analyzer.",
            ],
            "errors": [],
        },
    )
    app.state.jobs.save(job)
    return job


def save_redis_config_export_fixture_job() -> JobRecord:
    now = datetime(2026, 6, 2, tzinfo=timezone.utc)
    job = JobRecord(
        id="6" * 31 + "8",
        audit_type="redis_config_basic",
        file_id="4" * 32,
        status="completed",
        created_at=now,
        updated_at=now,
        result={
            "analyzer": "redis_config_basic",
            "archive_type": "zip",
            "completed_at": now.isoformat(),
            "hashes": {"sha256": "redis256"},
            "file_identification": {"size_bytes": 4096, "original_filename": "redis.zip"},
            "limits": {"max_files": 100, "max_file_bytes": 524288, "max_total_bytes": 2097152},
            "summary": {
                "files_considered": 6,
                "files_reviewed": 2,
                "redis_files_detected": 1,
                "sentinel_files_detected": 1,
                "acl_files_detected": 1,
                "dump_or_aof_files_detected": 2,
                "configs_detected": 2,
                "findings_count": 2,
                "redacted_values_count": 2,
                "truncated": False,
            },
            "files_detected": [
                {"path": "deploy/redis/redis.conf", "category": "redis", "read": True, "size_bytes": 1024, "context": "production"},
                {"path": "deploy/redis/sentinel.conf", "category": "sentinel", "read": True, "size_bytes": 512, "context": "production"},
                {"path": ".env.production", "category": "sensitive", "read": False, "skip_reason": "sensitive_file_not_read", "context": "production"},
                {"path": "deploy/redis/users.acl", "category": "acl", "read": False, "skip_reason": "acl_file_not_read", "context": "production"},
                {"path": "deploy/redis/dump.rdb", "category": "dump_or_aof", "read": False, "skip_reason": "dump_or_aof_not_read", "context": "production"},
                {"path": "deploy/redis/appendonly.aof", "category": "dump_or_aof", "read": False, "skip_reason": "dump_or_aof_not_read", "context": "production"},
            ],
            "files_reviewed": [
                {"path": "deploy/redis/redis.conf", "category": "redis", "config_type": "redis", "context": "production", "bytes_read": 1024},
                {"path": "deploy/redis/sentinel.conf", "category": "sentinel", "config_type": "sentinel", "context": "production", "bytes_read": 512},
            ],
            "configs": [
                {"path": "deploy/redis/redis.conf", "config_type": "redis", "context": "production"},
                {"path": "deploy/redis/sentinel.conf", "config_type": "sentinel", "context": "production"},
            ],
            "redis_settings": [
                {"file_path": "deploy/redis/redis.conf", "config_type": "redis", "line": 2, "setting": "bind", "value": "0.0.0.0"},
                {"file_path": "deploy/redis/redis.conf", "config_type": "redis", "line": 3, "setting": "requirepass", "value": "[REDACTED]"},
            ],
            "sentinel_settings": [
                {
                    "file_path": "deploy/redis/sentinel.conf",
                    "config_type": "sentinel",
                    "line": 2,
                    "setting": "sentinel monitor",
                    "value": "mymaster 10.0.0.2 6379 2",
                },
                {
                    "file_path": "deploy/redis/sentinel.conf",
                    "config_type": "sentinel",
                    "line": 3,
                    "setting": "sentinel auth-pass",
                    "value": "[REDACTED]",
                },
            ],
            "includes": [
                {
                    "file_path": "deploy/redis/redis.conf",
                    "config_type": "redis",
                    "line": 5,
                    "directive": "include",
                    "target": "/etc/redis/secrets.conf",
                    "resolved": False,
                }
            ],
            "acl_files": [
                {"path": "deploy/redis/users.acl", "category": "acl", "read": False, "skip_reason": "acl_file_not_read"}
            ],
            "dump_or_aof_files": [
                {"path": "deploy/redis/dump.rdb", "category": "dump_or_aof", "read": False, "skip_reason": "dump_or_aof_not_read"},
                {"path": "deploy/redis/appendonly.aof", "category": "dump_or_aof", "read": False, "skip_reason": "dump_or_aof_not_read"},
            ],
            "findings": [
                {
                    "id": "redis_requirepass_present_redacted",
                    "title": "Redis requirepass is present",
                    "level": "medium",
                    "confidence": "high",
                    "category": "secrets",
                    "context": "production",
                    "config_type": "redis",
                    "setting": "requirepass",
                    "directive": "requirepass",
                    "file_path": "deploy/redis/redis.conf",
                    "line": 3,
                    "description": "A Redis static configuration review indicator was observed.",
                    "evidence": "requirepass [REDACTED]",
                    "recommendation": "Review this setting in the intended deployment context.",
                },
                {
                    "id": "redis_include_not_resolved",
                    "title": "Redis config include was detected but not resolved",
                    "level": "low",
                    "confidence": "high",
                    "category": "include",
                    "context": "production",
                    "config_type": "redis",
                    "setting": "include",
                    "path": "/etc/redis/secrets.conf",
                    "file_path": "deploy/redis/redis.conf",
                    "line": 5,
                    "description": "Includes are detected but intentionally not resolved.",
                    "evidence": "include /etc/redis/secrets.conf",
                    "recommendation": "Review included files manually in the intended deployment context.",
                },
            ],
            "redaction_notes": [
                "Secret-like Redis config values are redacted before storage on a best-effort basis.",
                ".env, ACL, RDB, AOF, appendonly, dump, and backup files are detected but not read by this analyzer.",
            ],
            "errors": [],
        },
    )
    app.state.jobs.save(job)
    return job


def make_zip_bytes(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return buffer.getvalue()


def make_tar_bytes(entries: dict[str, bytes], *, gzipped: bool = False) -> bytes:
    buffer = io.BytesIO()
    mode = "w:gz" if gzipped else "w"
    with tarfile.open(fileobj=buffer, mode=mode) as archive:
        for name, content in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
    return buffer.getvalue()
