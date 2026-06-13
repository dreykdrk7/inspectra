import json
from pathlib import Path

import pytest

from active_runner.service import (
    ACTIVE_TOOLS_HEALTH_PATH,
    ACTIVE_TOOLS_NMAP_BASIC_PATH,
    active_tools_capability_metadata,
    handle_active_tools_health,
    handle_active_tools_request,
    response_contains_sensitive_terms,
)


def serialized(payload) -> str:
    return json.dumps(payload, sort_keys=True)


def assert_health_no_scan(response):
    assert response["network_requests_sent"] == 0
    assert response["nmap_executed"] is False
    assert response["capabilities"]["active_nmap_basic"]["status"] == "disabled_no_scan"
    assert response["capabilities"]["active_nmap_basic"]["execution_enabled"] is False
    assert response["capabilities"]["active_nmap_basic"]["target_input_allowed"] is False


def assert_no_health_leak(response):
    body = serialized(response)
    for forbidden in (
        "192.168.56.10",
        "secret-lab.internal",
        "443",
        "token_should_never_render",
        "secret-session-cookie",
        "super-secret-password",
        "private-api-key",
        "nmap " + "-sT",
        "<nmaprun",
        "raw_xml",
        "stdout",
        "stderr",
        "ptr_hostname",
        "resolved_ip",
        "script_output",
        "/tmp/inspectra-secret",
        "/var/run/" + "doc" + "ker.sock",
        "container-hostname",
        "confirmed vulnerability",
        "exploitable",
        "target is safe",
        "all ports found",
    ):
        assert forbidden not in body
    assert response_contains_sensitive_terms(response) is False


def test_health_without_payload_returns_small_stable_readiness():
    response = handle_active_tools_health()

    assert response == {
        "service": "active-tools",
        "status": "scaffold_ready",
        "capabilities": active_tools_capability_metadata(),
        "network_requests_sent": 0,
        "nmap_executed": False,
    }
    assert_health_no_scan(response)
    assert_no_health_leak(response)


@pytest.mark.parametrize(
    "payload",
    [
        {"target": "192.168.56.10"},
        {"targets": ["192.168.56.10", "secret-lab.internal"]},
        {"target_unit": {"target": "secret-lab.internal", "accepted_ports": [443]}},
    ],
)
def test_health_rejects_target_bearing_payloads_without_leaking_target(payload):
    response = handle_active_tools_health(payload)

    assert response["status"] == "blocked_no_live_service"
    assert response["errors"] == ["health_payload_not_accepted"]
    assert_health_no_scan(response)
    assert_no_health_leak(response)


@pytest.mark.parametrize(
    "payload",
    [
        {"ports": [443, 8443]},
        {"accepted_ports": [22]},
        {"port": 80},
    ],
)
def test_health_rejects_port_payloads_without_scan(payload):
    response = handle_active_tools_health(payload)

    assert response["status"] == "blocked_no_live_service"
    assert response["errors"] == ["health_payload_not_accepted"]
    assert_health_no_scan(response)
    assert_no_health_leak(response)


@pytest.mark.parametrize(
    "payload",
    [
        {"credentials": {"password": "super-secret-password"}},
        {"headers": {"Authorization": "Bearer token_should_never_render"}},
        {"cookies": {"session": "secret-session-cookie"}},
        {"tokens": ["token_should_never_render"]},
    ],
)
def test_health_rejects_secret_payloads_without_leaking_values(payload):
    response = handle_active_tools_health(payload)

    assert response["status"] == "blocked_no_live_service"
    assert response["errors"] == ["health_payload_not_accepted"]
    assert_health_no_scan(response)
    assert_no_health_leak(response)


@pytest.mark.parametrize(
    "payload",
    [
        {"command": "nmap " + "-sT --script default"},
        {"args": ["nmap", "-sT"]},
        {"raw_flags": "--script vuln"},
        {"scripts": ["default"]},
        {"nse": "synthetic output"},
    ],
)
def test_health_rejects_command_script_and_nse_payloads(payload):
    response = handle_active_tools_health(payload)

    assert response["status"] == "blocked_no_live_service"
    assert response["errors"] == ["health_payload_not_accepted"]
    assert_health_no_scan(response)
    assert_no_health_leak(response)


def test_health_rejects_non_mapping_payload_without_scan():
    response = handle_active_tools_health(["target", "192.168.56.10"])

    assert response["status"] == "blocked_no_live_service"
    assert response["errors"] == ["health_payload_not_mapping"]
    assert_health_no_scan(response)
    assert_no_health_leak(response)


def test_health_response_has_no_environment_host_path_or_output_fields():
    response = handle_active_tools_health(
        {
            "env": {"HOME": "/tmp/inspectra-secret"},
            "local_path": "/tmp/inspectra-secret",
            "hostname": "container-hostname",
            "raw_xml": "<nmaprun />",
            "stdout": "stdout token_should_never_render",
            "stderr": "stderr token_should_never_render",
        }
    )

    assert response["status"] == "blocked_no_live_service"
    assert_health_no_scan(response)
    assert_no_health_leak(response)


def test_health_dispatch_preserves_controlled_method_and_path_errors():
    wrong_method = handle_active_tools_request("POST", ACTIVE_TOOLS_HEALTH_PATH, {"target": "192.168.56.10"})
    unknown_path = handle_active_tools_request("GET", "/health/live", {"token": "token_should_never_render"})
    nmap_wrong_method = handle_active_tools_request("GET", ACTIVE_TOOLS_NMAP_BASIC_PATH, {"command": "nmap " + "-sT"})

    assert wrong_method["errors"] == ["method_not_allowed"]
    assert unknown_path["errors"] == ["not_found"]
    assert nmap_wrong_method["errors"] == ["method_not_allowed"]
    assert wrong_method["network_requests_sent"] == 0
    assert unknown_path["network_requests_sent"] == 0
    assert nmap_wrong_method["network_requests_sent"] == 0
    assert_no_health_leak(wrong_method)
    assert_no_health_leak(unknown_path)
    assert_no_health_leak(nmap_wrong_method)


def test_health_source_has_no_host_introspection_execution_or_runner_imports():
    service_source = Path("tools/active_runner/service.py").read_text(encoding="utf-8")
    runner_source = Path("tools/runner/" + "main.py").read_text(encoding="utf-8")
    backend_services_source = Path("backend/app/services.py").read_text(encoding="utf-8")

    for forbidden in (
        "import " + "sub" + "process",
        "sub" + "process.",
        "Docker" + "Client",
        "from " + "doc" + "ker",
        "doc" + "ker.sock",
        "nmap --" + "version",
        "nmap " + "-sT",
        "os." + "environ",
        "socket." + "gethostname",
        "tools/runner/" + "main.py",
    ):
        assert forbidden not in service_source
    assert "execute_active_nmap_basic" in service_source
    assert "active_runner.nmap_basic.executor" in service_source
    assert "active_nmap_basic" not in runner_source
    assert "nmap_basic" not in runner_source
    assert "active_runner.service" not in backend_services_source
