from __future__ import annotations

import json

import httpx

from app.deployment_smoke import DeploymentSmokeError, execute_private_candidate_smoke, main


SECURITY_HEADERS = {
    "strict-transport-security": "max-age=31536000",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "camera=(), geolocation=(), microphone=(), payment=(), usb=()",
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-origin",
    "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
}
FILE_ID = "1" * 32
PROJECT_ID = "2" * 32
JOB_ID = "3" * 32
SOURCE_REFERENCE = "snapshot-0123456789abcdef"
SOURCE_SHA256 = "4" * 64


def test_candidate_smoke_exercises_tls_auth_project_privacy_egress_and_cleanup_without_provider_calls():
    state = {"authenticated": False, "project_deleted": False, "file_deleted": False}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        headers = SECURITY_HEADERS if path == "/" else {}
        if path == "/":
            return httpx.Response(200, text="Inspectra", headers=headers)
        if path == "/api/health":
            return httpx.Response(200, json={"status": "ok", "service": "inspectra-backend"})
        if path == "/api/ready":
            return httpx.Response(200, json={
                "status": "ready",
                "service": "inspectra-backend",
                "checks": {
                    "storage": "ready",
                    "analysis_runners": "ready",
                    "admission": "ready",
                    "recovery_cleanup": "ready",
                },
            })
        if path == "/api/auth/login":
            payload = json.loads(request.content)
            if payload["password"] != "synthetic-candidate-password":
                return httpx.Response(401, json={"detail": "Invalid credentials."})
            state["authenticated"] = True
            return httpx.Response(
                200,
                json={"authenticated": True, "auth_mode": "self_hosted_single_admin"},
                headers={"set-cookie": "inspectra_session=opaque; Secure; HttpOnly; SameSite=Strict"},
            )
        if path == "/api/auth/status":
            return httpx.Response(200, json={"authenticated": True, "csrf_token": "c" * 64})
        if path == "/api/auth/logout":
            return httpx.Response(200, json={"authenticated": False})
        if path == "/api/files" and not state["authenticated"]:
            return httpx.Response(401, json={"detail": "Authentication required."})
        if path == "/api/projects" and request.method == "POST" and "x-csrf-token" not in request.headers:
            return httpx.Response(403, json={"detail": "CSRF token required."})
        assert state["authenticated"] is True
        if path == "/api/files/archive":
            assert request.headers["x-csrf-token"] == "c" * 64
            return httpx.Response(201, json={"id": FILE_ID, "sha256": SOURCE_SHA256})
        if path == "/api/projects" and request.method == "POST":
            return httpx.Response(201, json={
                "project": {"id": PROJECT_ID, "source_reference": SOURCE_REFERENCE},
                "job": {"id": JOB_ID, "status": "queued"},
            })
        if path == f"/api/jobs/{JOB_ID}":
            return httpx.Response(200, json={
                "id": JOB_ID,
                "project_id": PROJECT_ID,
                "source_reference": SOURCE_REFERENCE,
                "status": "completed",
                "result": {"analyzer": "project_archive_basic", "summary": {}, "findings": []},
            })
        if path == "/api/projects" and request.method == "GET":
            if state["project_deleted"]:
                return httpx.Response(200, json=[])
            return httpx.Response(200, json=[{
                "project": {"id": PROJECT_ID, "source_reference": SOURCE_REFERENCE},
                "latest_job": {"id": JOB_ID, "source_reference": SOURCE_REFERENCE},
            }])
        if path.endswith("/vulnerability-intelligence"):
            return httpx.Response(200, json={"state": "not_requested", "egress_enabled": False})
        if path == "/api/privacy/retention":
            return httpx.Response(200, json={"contract_version": "2026-09-10.7", "classes": [{}] * 25})
        if path.endswith("/report/markdown"):
            if request.method == "GET":
                return httpx.Response(200, text="Minimal redacted profile: aggregate risk only")
            assert request.headers["x-csrf-token"] == "c" * 64
            assert json.loads(request.content) == {
                "profile": "technical",
                "technical_detail_confirmed": True,
            }
            return httpx.Response(
                200,
                text=f"Technical redacted profile: Source snapshot reference: {SOURCE_REFERENCE}",
            )
        if path == f"/api/projects/{PROJECT_ID}" and request.method == "DELETE":
            state["project_deleted"] = True
            return httpx.Response(200, json={"state": "completed"})
        if path == f"/api/files/{FILE_ID}" and request.method == "DELETE":
            state["file_deleted"] = True
            return httpx.Response(200, json={"deleted": True})
        if path == "/api/files" and request.method == "GET":
            return httpx.Response(200, json=[] if state["file_deleted"] else [{"id": FILE_ID}])
        raise AssertionError(f"Unexpected smoke request: {request.method} {path}")

    with httpx.Client(
        base_url="https://localhost:18443",
        transport=httpx.MockTransport(handler),
        follow_redirects=False,
        trust_env=False,
    ) as client:
        summary = execute_private_candidate_smoke(
            client,
            archive_bytes=b"PK\x03\x04synthetic-zip",
            password="synthetic-candidate-password",
            analysis_wait_seconds=1,
        )

    assert summary.status == "succeeded"
    assert summary.destination == "loopback_tls"
    assert summary.project_analysis_status == "completed"
    assert summary.egress_disabled_verified is True
    assert summary.external_provider_contacted is False
    assert summary.project_privacy_verified is True
    assert summary.retention_classes_verified == 25
    assert summary.cleanup_verified is True
    assert state == {"authenticated": True, "project_deleted": True, "file_deleted": True}


def test_candidate_smoke_rejects_project_job_source_metadata():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, text="Inspectra", headers=SECURITY_HEADERS)
        if request.url.path == "/api/health":
            return httpx.Response(200, json={"status": "ok", "service": "inspectra-backend"})
        if request.url.path == "/api/ready":
            return httpx.Response(200, json={"status": "ready", "checks": {"storage": "ready"}})
        raise AssertionError("The smoke should stop at the malformed readiness contract.")

    with httpx.Client(base_url="https://localhost:18443", transport=httpx.MockTransport(handler)) as client:
        try:
            execute_private_candidate_smoke(
                client,
                archive_bytes=b"PK\x03\x04synthetic-zip",
                password="synthetic-candidate-password",
                analysis_wait_seconds=1,
            )
        except DeploymentSmokeError as exc:
            assert exc.code == "readiness_contract_mismatch"
        else:
            raise AssertionError("An incomplete readiness contract must fail closed.")


def test_candidate_smoke_cli_failure_does_not_echo_paths_or_password(tmp_path, monkeypatch, capsys):
    marker = "private-candidate-path-marker"
    monkeypatch.setenv("INSPECTRA_ACCEPTANCE_PASSWORD", "private-candidate-password-marker")

    exit_code = main([
        "--https-port",
        "18443",
        "--ca-certificate",
        str(tmp_path / marker),
        "--synthetic-archive",
        str(tmp_path / "synthetic.zip"),
        "--synthetic-data-confirmed",
    ])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.out == ""
    assert marker not in captured.err
    assert "private-candidate-password-marker" not in captured.err
    assert json.loads(captured.err) == {"code": "invalid_synthetic_archive", "status": "failed"}
