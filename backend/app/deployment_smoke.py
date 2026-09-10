"""Local TLS smoke for a private Inspectra deployment candidate.

The client destination is fixed to loopback and redirects/proxy environment are
disabled.  It accepts only an explicitly attested synthetic ZIP, exercises the
product flow, removes the created data and emits bounded evidence without IDs,
paths, cookies, tokens or response bodies.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import ssl
import sys
import time
from typing import Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field

from app.retention import RETENTION_POLICY_CLASS_COUNT, RETENTION_POLICY_CONTRACT_VERSION


DEPLOYMENT_SMOKE_CONTRACT_VERSION = "2026-09-06.1"
MAX_SYNTHETIC_FIXTURE_BYTES = 5 * 1024 * 1024
_SOURCE_REFERENCE = re.compile(r"^snapshot-[a-f0-9]{16}$")
_SECURITY_HEADERS = {
    "strict-transport-security": "max-age=31536000",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "camera=(), geolocation=(), microphone=(), payment=(), usb=()",
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-origin",
}


class DeploymentSmokeError(RuntimeError):
    """Stable, content-free candidate smoke failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class DeploymentSmokeSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal["2026-09-06.1"] = DEPLOYMENT_SMOKE_CONTRACT_VERSION
    status: Literal["succeeded"] = "succeeded"
    destination: Literal["loopback_tls"] = "loopback_tls"
    data_scope: Literal["operator_attested_synthetic_zip"] = "operator_attested_synthetic_zip"
    health_verified: Literal[True] = True
    readiness_verified: Literal[True] = True
    security_headers_verified: Literal[True] = True
    authentication_boundary_verified: Literal[True] = True
    secure_cookie_verified: Literal[True] = True
    csrf_verified: Literal[True] = True
    project_analysis_status: Literal["completed"] = "completed"
    project_privacy_verified: Literal[True] = True
    egress_disabled_verified: Literal[True] = True
    retention_classes_verified: Literal[25] = RETENTION_POLICY_CLASS_COUNT
    report_verified: Literal[True] = True
    cleanup_verified: Literal[True] = True
    external_provider_contacted: Literal[False] = False
    elapsed_ms: float = Field(ge=0)


def run_private_candidate_smoke(
    *,
    https_port: int,
    ca_certificate: Path,
    synthetic_archive: Path,
    password: str,
    synthetic_data_confirmed: bool,
    timeout_seconds: float = 10.0,
    analysis_wait_seconds: float = 60.0,
) -> DeploymentSmokeSummary:
    """Connect only to localhost and execute the bounded acceptance smoke."""

    if not synthetic_data_confirmed:
        raise DeploymentSmokeError("synthetic_data_confirmation_required")
    if not 1 <= https_port <= 65_535:
        raise DeploymentSmokeError("invalid_https_port")
    if not password:
        raise DeploymentSmokeError("acceptance_password_required")
    archive_bytes = _read_synthetic_archive(synthetic_archive)
    try:
        context = ssl.create_default_context(cafile=str(_regular_file(ca_certificate, "invalid_ca_certificate")))
        with httpx.Client(
            base_url=f"https://localhost:{https_port}",
            verify=context,
            timeout=timeout_seconds,
            follow_redirects=False,
            trust_env=False,
        ) as client:
            return execute_private_candidate_smoke(
                client,
                archive_bytes=archive_bytes,
                password=password,
                analysis_wait_seconds=analysis_wait_seconds,
            )
    except DeploymentSmokeError:
        raise
    except (httpx.HTTPError, OSError, ssl.SSLError, ValueError) as exc:
        raise DeploymentSmokeError("candidate_unreachable") from exc
    except Exception as exc:
        raise DeploymentSmokeError("candidate_smoke_failed") from exc


def execute_private_candidate_smoke(
    client: httpx.Client,
    *,
    archive_bytes: bytes,
    password: str,
    analysis_wait_seconds: float,
    clock=time.perf_counter,
    sleeper=time.sleep,
) -> DeploymentSmokeSummary:
    """Exercise the smoke against an injected client for deterministic tests."""

    started = clock()
    home = client.get("/")
    _expect_status(home, 200, "frontend_unavailable")
    _verify_security_headers(home)

    health = _json_request(client, "GET", "/api/health", expected_status=200, code="health_failed")
    if health != {"status": "ok", "service": "inspectra-backend"}:
        raise DeploymentSmokeError("health_contract_mismatch")
    ready = _json_request(client, "GET", "/api/ready", expected_status=200, code="readiness_failed")
    expected_checks = {
        "storage": "ready",
        "analysis_runners": "ready",
        "admission": "ready",
        "recovery_cleanup": "ready",
    }
    if ready.get("status") != "ready" or ready.get("checks") != expected_checks:
        raise DeploymentSmokeError("readiness_contract_mismatch")

    unauthorized = client.get("/api/files")
    _expect_status(unauthorized, 401, "authentication_boundary_failed")
    wrong_login = client.post("/api/auth/login", json={"password": "synthetic-wrong-password"})
    _expect_status(wrong_login, 401, "authentication_failure_contract_mismatch")
    if wrong_login.json() != {"detail": "Invalid credentials."}:
        raise DeploymentSmokeError("authentication_failure_contract_mismatch")

    login = client.post("/api/auth/login", json={"password": password})
    _expect_status(login, 200, "authentication_failed")
    login_payload = _json_object(login, "authentication_contract_mismatch")
    if login_payload.get("authenticated") is not True:
        raise DeploymentSmokeError("authentication_contract_mismatch")
    cookie = login.headers.get("set-cookie", "").lower()
    if "secure" not in cookie or "httponly" not in cookie or "samesite=strict" not in cookie:
        raise DeploymentSmokeError("secure_cookie_contract_mismatch")
    auth_status = _json_request(
        client,
        "GET",
        "/api/auth/status",
        expected_status=200,
        code="authentication_contract_mismatch",
    )
    csrf_token = auth_status.get("csrf_token")
    if auth_status.get("authenticated") is not True or not isinstance(csrf_token, str) or len(csrf_token) < 32:
        raise DeploymentSmokeError("csrf_contract_mismatch")
    csrf_headers = {"X-CSRF-Token": csrf_token}

    csrf_denied = client.post(
        "/api/projects",
        json={"source_file_id": "0" * 32, "authorization_confirmed": True},
    )
    _expect_status(csrf_denied, 403, "csrf_boundary_failed")

    upload = client.post(
        "/api/files/archive",
        headers=csrf_headers,
        files={"file": ("inspectra-acceptance-synthetic.zip", archive_bytes, "application/zip")},
    )
    _expect_status(upload, 201, "synthetic_upload_failed")
    upload_payload = _json_object(upload, "synthetic_upload_contract_mismatch")
    file_id = _opaque_identifier(upload_payload.get("id"), "synthetic_upload_contract_mismatch")
    source_digest = _sha256_digest(upload_payload.get("sha256"), "synthetic_upload_contract_mismatch")

    created = _json_request(
        client,
        "POST",
        "/api/projects",
        expected_status=201,
        code="project_creation_failed",
        headers=csrf_headers,
        json={
            "source_file_id": file_id,
            "authorization_confirmed": True,
            "name": "Synthetic deployment candidate",
        },
    )
    project = created.get("project")
    job = created.get("job")
    if not isinstance(project, dict) or not isinstance(job, dict):
        raise DeploymentSmokeError("project_contract_mismatch")
    project_id = _opaque_identifier(project.get("id"), "project_contract_mismatch")
    job_id = _opaque_identifier(job.get("id"), "project_contract_mismatch")
    if not _SOURCE_REFERENCE.fullmatch(str(project.get("source_reference", ""))):
        raise DeploymentSmokeError("project_privacy_contract_mismatch")

    deadline = clock() + analysis_wait_seconds
    terminal_job: dict[str, object] | None = None
    while clock() < deadline:
        current = _json_request(
            client,
            "GET",
            f"/api/jobs/{job_id}",
            expected_status=200,
            code="analysis_status_failed",
        )
        if current.get("status") in {"completed", "failed", "cancelled"}:
            terminal_job = current
            break
        sleeper(0.2)
    if terminal_job is None:
        raise DeploymentSmokeError("analysis_timeout")
    if terminal_job.get("status") != "completed":
        raise DeploymentSmokeError("analysis_not_completed")
    _verify_project_job_privacy(terminal_job)

    projects = _json_request(client, "GET", "/api/projects", expected_status=200, code="project_list_failed")
    if not isinstance(projects, list) or len(projects) != 1:
        raise DeploymentSmokeError("project_list_contract_mismatch")
    serialized_projects = json.dumps(projects, sort_keys=True)
    if any(
        forbidden in serialized_projects
        for forbidden in ('"source_filename"', '"source_sha256"', '"source_file_id"', '"file_id"')
    ):
        raise DeploymentSmokeError("project_privacy_contract_mismatch")

    intelligence = _json_request(
        client,
        "GET",
        f"/api/projects/{project_id}/analyses/{job_id}/vulnerability-intelligence",
        expected_status=200,
        code="intelligence_status_failed",
    )
    if intelligence.get("egress_enabled") is not False:
        raise DeploymentSmokeError("egress_not_disabled")

    retention = _json_request(
        client,
        "GET",
        "/api/privacy/retention",
        expected_status=200,
        code="retention_status_failed",
    )
    if (
        retention.get("contract_version") != RETENTION_POLICY_CONTRACT_VERSION
        or len(retention.get("classes", [])) != RETENTION_POLICY_CLASS_COUNT
    ):
        raise DeploymentSmokeError("retention_contract_mismatch")

    report_path = f"/api/projects/{project_id}/analyses/{job_id}/report/markdown"
    report = client.get(report_path)
    _expect_status(report, 200, "minimal_report_failed")
    report_text = report.text
    if (
        "Minimal redacted profile" not in report_text
        or "snapshot-" in report_text
        or project_id in report_text
        or job_id in report_text
        or "inspectra-acceptance-synthetic.zip" in report_text
        or source_digest in report_text
    ):
        raise DeploymentSmokeError("minimal_report_privacy_contract_mismatch")

    technical_report = client.post(
        report_path,
        headers=csrf_headers,
        json={"profile": "technical", "technical_detail_confirmed": True},
    )
    _expect_status(technical_report, 200, "technical_report_failed")
    technical_text = technical_report.text
    if (
        "Technical redacted profile" not in technical_text
        or "snapshot-" not in technical_text
        or "inspectra-acceptance-synthetic.zip" in technical_text
        or source_digest in technical_text
    ):
        raise DeploymentSmokeError("technical_report_privacy_contract_mismatch")

    _json_request(
        client,
        "DELETE",
        f"/api/projects/{project_id}",
        expected_status=200,
        code="project_cleanup_failed",
        headers=csrf_headers,
        json={"deletion_confirmed": True},
    )
    _json_request(
        client,
        "DELETE",
        f"/api/files/{file_id}",
        expected_status=200,
        code="source_cleanup_failed",
        headers=csrf_headers,
    )
    remaining_projects = _json_request(client, "GET", "/api/projects", expected_status=200, code="cleanup_check_failed")
    remaining_files = _json_request(client, "GET", "/api/files", expected_status=200, code="cleanup_check_failed")
    if remaining_projects or remaining_files:
        raise DeploymentSmokeError("cleanup_incomplete")
    logout = client.post("/api/auth/logout", headers=csrf_headers)
    _expect_status(logout, 200, "logout_failed")

    return DeploymentSmokeSummary(elapsed_ms=round(max(0.0, (clock() - started) * 1000), 3))


def _read_synthetic_archive(path: Path) -> bytes:
    source = _regular_file(path, "invalid_synthetic_archive")
    if source.suffix.lower() != ".zip":
        raise DeploymentSmokeError("invalid_synthetic_archive")
    try:
        size = source.stat().st_size
        if not 1 <= size <= MAX_SYNTHETIC_FIXTURE_BYTES:
            raise DeploymentSmokeError("invalid_synthetic_archive")
        return source.read_bytes()
    except OSError as exc:
        raise DeploymentSmokeError("invalid_synthetic_archive") from exc


def _regular_file(path: Path, code: str) -> Path:
    try:
        if path.is_symlink() or not path.is_file():
            raise DeploymentSmokeError(code)
        return path.resolve(strict=True)
    except OSError as exc:
        raise DeploymentSmokeError(code) from exc


def _expect_status(response: httpx.Response, expected: int, code: str) -> None:
    if response.status_code != expected or response.is_redirect:
        raise DeploymentSmokeError(code)


def _json_object(response: httpx.Response, code: str) -> dict[str, object]:
    try:
        payload = response.json()
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise DeploymentSmokeError(code) from exc
    if not isinstance(payload, dict):
        raise DeploymentSmokeError(code)
    return payload


def _json_request(
    client: httpx.Client,
    method: str,
    path: str,
    *,
    expected_status: int,
    code: str,
    **kwargs,
):
    response = client.request(method, path, **kwargs)
    _expect_status(response, expected_status, code)
    try:
        return response.json()
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise DeploymentSmokeError(code) from exc


def _opaque_identifier(value: object, code: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[a-f0-9]{32}", value) is None:
        raise DeploymentSmokeError(code)
    return value


def _sha256_digest(value: object, code: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[a-f0-9]{64}", value) is None:
        raise DeploymentSmokeError(code)
    return value


def _verify_security_headers(response: httpx.Response) -> None:
    for key, expected in _SECURITY_HEADERS.items():
        if response.headers.get(key) != expected:
            raise DeploymentSmokeError("security_header_mismatch")
    content_security_policy = response.headers.get("content-security-policy", "")
    if "default-src 'self'" not in content_security_policy or "frame-ancestors 'none'" not in content_security_policy:
        raise DeploymentSmokeError("security_header_mismatch")
    if "server" in response.headers:
        raise DeploymentSmokeError("server_header_exposed")


def _verify_project_job_privacy(job: dict[str, object]) -> None:
    serialized = json.dumps(job, sort_keys=True)
    for forbidden in ('"file_id"', '"source_sha256"', '"hashes"', '"original_filename"'):
        if forbidden in serialized:
            raise DeploymentSmokeError("project_privacy_contract_mismatch")
    if not _SOURCE_REFERENCE.fullmatch(str(job.get("source_reference", ""))):
        raise DeploymentSmokeError("project_privacy_contract_mismatch")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Inspectra local private deployment-candidate smoke")
    parser.add_argument("--https-port", type=int, required=True)
    parser.add_argument("--ca-certificate", type=Path, required=True)
    parser.add_argument("--synthetic-archive", type=Path, required=True)
    parser.add_argument("--synthetic-data-confirmed", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        summary = run_private_candidate_smoke(
            https_port=args.https_port,
            ca_certificate=args.ca_certificate,
            synthetic_archive=args.synthetic_archive,
            password=os.environ.get("INSPECTRA_ACCEPTANCE_PASSWORD", ""),
            synthetic_data_confirmed=args.synthetic_data_confirmed,
        )
    except DeploymentSmokeError as exc:
        print(json.dumps({"status": "failed", "code": exc.code}, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(summary.model_dump(mode="json"), sort_keys=True))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
