import asyncio
import json
from pathlib import Path
import subprocess

import pytest

from active_runner.app import app, create_active_tools_app
from active_runner.contracts import ACTIVE_NMAP_BASIC_MODE, ACTIVE_NMAP_BASIC_PROFILE
from active_runner.service import (
    ACTIVE_TOOLS_FAKE_EXECUTOR_NAME,
    ACTIVE_TOOLS_NO_SCAN_REASON,
    response_contains_sensitive_terms,
)

_MISSING = object()


def make_boundary_request(**overrides):
    payload = {
        "mode": ACTIVE_NMAP_BASIC_MODE,
        "profile": ACTIVE_NMAP_BASIC_PROFILE,
        "request_id": "request-123",
        "job_id": "job-123",
        "correlation_id": "corr-123",
        "confirmations_verified_by_backend": True,
        "target_unit": {
            "target": "192.168.56.10",
            "target_kind": "private_ip",
            "accepted_ports": [443, 22, 443],
        },
        "limits": {
            "process_timeout_seconds": 35,
            "stdout_max_bytes": 131072,
            "stderr_max_bytes": 16384,
            "response_max_bytes": 32768,
        },
    }
    payload.update(overrides)
    return payload


def completed_fake_response():
    return {
        "status": "completed",
        "profile": ACTIVE_NMAP_BASIC_PROFILE,
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
            "executor": ACTIVE_TOOLS_FAKE_EXECUTOR_NAME,
            "duration_ms": 7,
            "nmap_executed": False,
        },
        "warnings": ["synthetic_fake_completed"],
        "errors": [],
    }


def serialized(payload) -> str:
    return json.dumps(payload, sort_keys=True)


def asgi_json(asgi_app, method: str, path: str, *, json_payload=_MISSING):
    return asyncio.run(_asgi_json(asgi_app, method, path, json_payload=json_payload))


async def _asgi_json(asgi_app, method: str, path: str, *, json_payload):
    if "?" in path:
        request_path, query_string = path.split("?", 1)
    else:
        request_path, query_string = path, ""

    body = b""
    headers = [(b"host", b"testserver")]
    if json_payload is not _MISSING:
        body = json.dumps(json_payload).encode("utf-8")
        headers.extend(
            [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
            ]
        )

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": request_path,
        "raw_path": request_path.encode("ascii"),
        "query_string": query_string.encode("ascii"),
        "headers": headers,
        "client": ("testclient", 50000),
        "server": ("testserver", 80),
        "root_path": "",
    }
    response = {"status": None, "body": b""}
    receive_called = False

    async def receive():
        nonlocal receive_called
        if receive_called:
            return {"type": "http.disconnect"}
        receive_called = True
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message):
        if message["type"] == "http.response.start":
            response["status"] = message["status"]
        if message["type"] == "http.response.body":
            response["body"] += message.get("body", b"")

    await asgi_app(scope, receive, send)
    return response["status"], json.loads(response["body"].decode("utf-8"))


def assert_no_sensitive_output(response):
    body = serialized(response)
    for forbidden in (
        "192.168.56.10",
        "127.0.0.1",
        "secret-lab.internal",
        "token_should_never_render",
        "raw_xml",
        "stdout",
        "stderr",
        "command",
        "ptr_hostname",
        "resolved_ip",
        "script_output",
        "credentials",
        "cookies",
        "tokens",
        "headers",
        "hostname",
        "local_path",
        "nmap " + "-sT",
        "<nmaprun",
        "confirmed vulnerability",
        "exploitable",
        "target is safe",
        "all ports found",
    ):
        assert forbidden not in body
    assert response_contains_sensitive_terms(response) is False


def test_asgi_health_returns_stable_readiness_without_live_behavior():
    status, payload = asgi_json(app, "GET", "/health")

    assert status == 200
    assert payload["service"] == "active-tools"
    assert payload["status"] == "scaffold_ready"
    assert payload["network_requests_sent"] == 0
    assert payload["nmap_executed"] is False
    assert payload["capabilities"]["active_nmap_basic"] == {
        "status": "disabled_no_scan",
        "execution_enabled": False,
        "target_input_allowed": False,
    }
    assert_no_sensitive_output(payload)


def test_asgi_health_reports_ready_bounded_execution_when_explicitly_enabled_without_targets():
    asgi_app = create_active_tools_app(nmap_basic_execution_enabled=True, nmap_basic_runner=lambda *args, **kwargs: None)

    status, payload = asgi_json(asgi_app, "GET", "/health")

    assert status == 200
    assert payload["service"] == "active-tools"
    assert payload["status"] == "scaffold_ready"
    assert payload["network_requests_sent"] == 0
    assert payload["nmap_executed"] is False
    assert payload["capabilities"]["active_nmap_basic"] == {
        "status": "ready_bounded_execution",
        "execution_enabled": True,
        "target_input_allowed": False,
    }
    assert_no_sensitive_output(payload)


def test_asgi_health_rejects_target_payload_without_leaking_value():
    status, payload = asgi_json(app, "GET", "/health", json_payload={"target": "192.168.56.10"})

    assert status == 200
    assert payload["status"] == "blocked_no_live_service"
    assert payload["errors"] == ["health_payload_not_accepted"]
    assert payload["network_requests_sent"] == 0
    assert payload["nmap_executed"] is False
    assert_no_sensitive_output(payload)


def test_asgi_health_rejects_target_query_without_leaking_value():
    status, payload = asgi_json(app, "GET", "/health?target=192.168.56.10")

    assert status == 200
    assert payload["status"] == "blocked_no_live_service"
    assert payload["errors"] == ["health_payload_not_accepted"]
    assert_no_sensitive_output(payload)


def test_asgi_nmap_basic_valid_boundary_request_returns_not_executed():
    status, payload = asgi_json(app, "POST", "/active/nmap-basic", json_payload=make_boundary_request())

    assert status == 200
    assert payload["service"] == "active-tools"
    assert payload["status"] == "not_executed"
    assert payload["capability"] == "active_nmap_basic"
    assert payload["mode"] == ACTIVE_NMAP_BASIC_MODE
    assert payload["profile"] == ACTIVE_NMAP_BASIC_PROFILE
    assert payload["execution_enabled"] is False
    assert payload["manual_validation_required"] is True
    assert payload["reason"] == ACTIVE_TOOLS_NO_SCAN_REASON
    assert payload["observations"] == []
    assert payload["job_created"] is False
    assert payload["target_expansion_performed"] is False
    assert payload["network_requests_sent"] == 0
    assert payload["summary"] == {
        "evidence_available": False,
        "nmap_executed": False,
        "port_count": 2,
        "target_count": 1,
    }
    assert_no_sensitive_output(payload)


@pytest.mark.parametrize("field_name", ["raw_flags", "scripts", "credentials", "headers", "cookies", "tokens"])
def test_asgi_nmap_basic_rejects_dangerous_fields_without_leaking_values(field_name):
    status, payload = asgi_json(
        app,
        "POST",
        "/active/nmap-basic",
        json_payload=make_boundary_request(**{field_name: "token_should_never_render"}),
    )

    assert status == 200
    assert payload["status"] == "blocked_no_live_service"
    assert payload["errors"] == ["unsupported_request_field"]
    assert payload["job_created"] is False
    assert payload["network_requests_sent"] == 0
    assert_no_sensitive_output(payload)


@pytest.mark.parametrize(
    ("override", "reason"),
    [
        ({"targets": ["192.168.56.10", "192.168.56.11"]}, "multiple_targets_not_supported"),
        (
            {"target_unit": {"target": "192.168.56.0/24", "target_kind": "private_ip", "accepted_ports": [443]}},
            "target_range_rejected",
        ),
        (
            {"target_unit": {"target": "192.168.56.10", "target_kind": "private_ip", "accepted_ports": []}},
            "accepted_ports_invalid",
        ),
    ],
)
def test_asgi_nmap_basic_rejects_expanded_or_invalid_target_shapes(override, reason):
    status, payload = asgi_json(app, "POST", "/active/nmap-basic", json_payload=make_boundary_request(**override))

    assert status == 200
    assert payload["status"] == "blocked_no_live_service"
    assert payload["errors"] == [reason]
    assert_no_sensitive_output(payload)


def test_asgi_fake_executor_is_explicitly_injected_and_allowlisted():
    calls = []

    def fake_executor(request):
        calls.append(request)
        return completed_fake_response()

    asgi_app = create_active_tools_app(nmap_basic_executor=fake_executor)

    status, payload = asgi_json(asgi_app, "POST", "/active/nmap-basic", json_payload=make_boundary_request())

    assert status == 200
    assert calls == [
        {
            "mode": ACTIVE_NMAP_BASIC_MODE,
            "profile": ACTIVE_NMAP_BASIC_PROFILE,
            "request_id": "request-123",
            "job_id": "job-123",
            "correlation_id": "corr-123",
            "confirmations_verified_by_backend": True,
            "target_unit": {
                "target": "192.168.56.10",
                "target_kind": "private_ip",
                "accepted_ports": [22, 443],
            },
            "limits": {
                "process_timeout_seconds": 35,
                "stdout_max_bytes": 131072,
                "stderr_max_bytes": 16384,
                "response_max_bytes": 32768,
            },
        }
    ]
    assert payload["status"] == "completed"
    assert payload["manual_validation_required"] is True
    assert payload["result_interpretation"] == "observed_exposure_review_indicator"
    assert payload["observations"] == [
        {
            "port": 443,
            "protocol": "tcp",
            "state": "open",
            "manual_validation_required": True,
            "result_interpretation": "observed_exposure_review_indicator",
            "reason": "syn-ack",
        }
    ]
    assert payload["summary"]["fake_executor"] is True
    assert payload["summary"]["nmap_executed"] is False
    assert payload["network_requests_sent"] == 0
    assert_no_sensitive_output(payload)


def test_asgi_real_nmap_basic_requires_explicit_execution_flag_and_uses_bounded_runner():
    calls = []

    def fake_runner(argv, **kwargs):
        calls.append({"argv": argv, "kwargs": kwargs})
        return subprocess.CompletedProcess(
            argv,
            0,
            stdout=(
                b"<nmaprun><host><ports>"
                b"<port protocol='tcp' portid='65000'>"
                b"<state state='closed' reason='conn-refused'/>"
                b"</port></ports></host></nmaprun>"
            ),
            stderr=b"",
        )

    asgi_app = create_active_tools_app(nmap_basic_execution_enabled=True, nmap_basic_runner=fake_runner)

    status, payload = asgi_json(
        asgi_app,
        "POST",
        "/active/nmap-basic",
        json_payload=make_boundary_request(
            target_unit={"target": "127.0.0.1", "target_kind": "container_loopback", "accepted_ports": [65000]},
            limits={
                "process_timeout_seconds": 5,
                "stdout_max_bytes": 8192,
                "stderr_max_bytes": 2048,
                "response_max_bytes": 32768,
            },
        ),
    )

    assert status == 200
    assert len(calls) == 1
    assert calls[0]["argv"] == [
        "nmap",
        "-sT",
        "-Pn",
        "-n",
        "--max-retries",
        "1",
        "--host-timeout",
        "30s",
        "-oX",
        "-",
        "-p",
        "65000",
        "--",
        "127.0.0.1",
    ]
    assert calls[0]["kwargs"]["shell"] is False
    assert calls[0]["kwargs"]["timeout"] == 5
    assert payload["service"] == "active-tools"
    assert payload["status"] == "completed"
    assert payload["capability"] == "active_nmap_basic"
    assert payload["execution_enabled"] is True
    assert payload["target_input_allowed"] is False
    assert payload["job_created"] is False
    assert payload["target_expansion_performed"] is False
    assert payload["network_requests_sent"] == 1
    assert payload["summary"]["nmap_executed"] is True
    assert payload["summary"]["evidence_available"] is True
    assert payload["observations"] == [
        {
            "port": 65000,
            "protocol": "tcp",
            "state": "closed",
            "manual_validation_required": True,
            "result_interpretation": "observed_exposure_review_indicator",
            "reason": "conn-refused",
        }
    ]
    assert payload["execution_metadata"] == {
        "executor": "active_nmap_basic",
        "nmap_invoked": True,
        "subprocess_invoked_inside_active_tools": True,
    }
    assert_no_sensitive_output(payload)


def test_asgi_real_nmap_basic_maps_missing_nmap_to_controlled_error_without_target_leak():
    def missing_runner(argv, **kwargs):
        raise FileNotFoundError("nmap missing for 127.0.0.1")

    asgi_app = create_active_tools_app(nmap_basic_execution_enabled=True, nmap_basic_runner=missing_runner)

    status, payload = asgi_json(
        asgi_app,
        "POST",
        "/active/nmap-basic",
        json_payload=make_boundary_request(
            target_unit={"target": "127.0.0.1", "target_kind": "container_loopback", "accepted_ports": [65000]},
        ),
    )

    assert status == 200
    assert payload["status"] == "nmap_missing"
    assert payload["execution_enabled"] is True
    assert payload["network_requests_sent"] == 0
    assert payload["summary"]["nmap_executed"] is False
    assert payload["summary"]["evidence_available"] is False
    assert payload["errors"] == ["nmap_missing"]
    assert_no_sensitive_output(payload)


def test_asgi_known_wrong_method_and_unknown_path_return_controlled_errors():
    wrong_method_status, wrong_method = asgi_json(
        app,
        "GET",
        "/active/nmap-basic",
        json_payload=make_boundary_request(),
    )
    unknown_path_status, unknown_path = asgi_json(
        app,
        "POST",
        "/public/scan",
        json_payload={"token": "token_should_never_render"},
    )

    assert wrong_method_status == 200
    assert wrong_method["status"] == "blocked_no_live_service"
    assert wrong_method["errors"] == ["method_not_allowed"]
    assert wrong_method["network_requests_sent"] == 0
    assert unknown_path_status == 200
    assert unknown_path["status"] == "blocked_no_live_service"
    assert unknown_path["errors"] == ["not_found"]
    assert unknown_path["network_requests_sent"] == 0
    assert_no_sensitive_output(wrong_method)
    assert_no_sensitive_output(unknown_path)


def test_asgi_app_source_has_no_live_runtime_or_forbidden_imports():
    app_source = Path("tools/active_runner/app.py").read_text(encoding="utf-8")
    service_source = Path("tools/active_runner/service.py").read_text(encoding="utf-8")
    runner_source = Path("tools/runner/main.py").read_text(encoding="utf-8")
    backend_services_source = Path("backend/app/services.py").read_text(encoding="utf-8")
    backend_main_source = Path("backend/app/main.py").read_text(encoding="utf-8")

    for source in (app_source, service_source):
        for forbidden in (
            "import " + "sub" + "process",
            "sub" + "process.",
            "Docker" + "Client",
            "from " + "doc" + "ker",
            "doc" + "ker.sock",
            "nmap --" + "version",
            "nmap " + "-sT",
            "uvicorn",
            "gunicorn",
            "backend.app",
            "tools/runner/" + "main.py",
        ):
            assert forbidden not in source
    assert "active_runner.nmap_basic.executor" in service_source
    assert "execute_active_nmap_basic" in service_source
    assert "active_nmap_basic" not in runner_source
    assert "nmap_basic" not in runner_source
    assert "active_runner.app" not in backend_services_source
    assert "active_runner.app" not in backend_main_source
