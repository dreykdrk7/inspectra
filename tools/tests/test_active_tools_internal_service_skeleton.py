import inspect
import json
from pathlib import Path

import pytest

from active_runner.contracts import ACTIVE_NMAP_BASIC_MODE, ACTIVE_NMAP_BASIC_PROFILE
from active_runner.service import (
    ACTIVE_TOOLS_HEALTH_PATH,
    ACTIVE_TOOLS_NMAP_BASIC_PATH,
    ACTIVE_TOOLS_NO_SCAN_REASON,
    active_tools_capability_metadata,
    handle_active_nmap_basic_no_scan,
    handle_active_tools_health,
    handle_active_tools_request,
    response_contains_sensitive_terms,
)


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


def serialized(payload) -> str:
    return json.dumps(payload, sort_keys=True)


def assert_no_sensitive_output(response):
    body = serialized(response)
    for forbidden in (
        "192.168.56.10",
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
        "confirmed vulnerability",
        "exploitable",
        "target is safe",
        "all ports found",
    ):
        assert forbidden not in body
    assert response_contains_sensitive_terms(response) is False


def test_health_readiness_has_no_target_and_no_execution():
    response = handle_active_tools_health()
    dispatched = handle_active_tools_request("GET", ACTIVE_TOOLS_HEALTH_PATH)

    assert response == dispatched
    assert response["service"] == "active-tools"
    assert response["status"] == "scaffold_ready"
    assert response["network_requests_sent"] == 0
    assert response["nmap_executed"] is False
    assert response["capabilities"] == active_tools_capability_metadata()
    assert response["capabilities"]["active_nmap_basic"]["status"] == "disabled_no_scan"
    assert response["capabilities"]["active_nmap_basic"]["execution_enabled"] is False
    assert response["capabilities"]["active_nmap_basic"]["target_input_allowed"] is False
    assert "192.168.56.10" not in serialized(response)


def test_health_rejects_target_payload_without_leaking_target():
    response = handle_active_tools_health({"target": "192.168.56.10"})

    assert response["status"] == "blocked_no_live_service"
    assert response["errors"] == ["health_payload_not_accepted"]
    assert response["network_requests_sent"] == 0
    assert response["nmap_executed"] is False
    assert_no_sensitive_output(response)


def test_nmap_basic_valid_boundary_request_returns_not_executed_no_scan():
    response = handle_active_tools_request("POST", ACTIVE_TOOLS_NMAP_BASIC_PATH, make_boundary_request())

    assert response["service"] == "active-tools"
    assert response["status"] == "not_executed"
    assert response["capability"] == "active_nmap_basic"
    assert response["mode"] == ACTIVE_NMAP_BASIC_MODE
    assert response["profile"] == ACTIVE_NMAP_BASIC_PROFILE
    assert response["execution_enabled"] is False
    assert response["manual_validation_required"] is True
    assert response["reason"] == ACTIVE_TOOLS_NO_SCAN_REASON
    assert response["observations"] == []
    assert "result_interpretation" not in response
    assert response["job_created"] is False
    assert response["target_expansion_performed"] is False
    assert response["network_requests_sent"] == 0
    assert response["summary"] == {
        "evidence_available": False,
        "nmap_executed": False,
        "port_count": 2,
        "target_count": 1,
    }
    assert response["warnings"] == ["no_scan_service_skeleton"]
    assert response["errors"] == []
    assert_no_sensitive_output(response)


@pytest.mark.parametrize(
    "field_name",
    [
        "raw_flags",
        "scripts",
        "nse",
        "extra_args",
        "shell_command",
        "credentials",
        "cookies",
        "tokens",
        "headers",
        "target_files",
        "command",
    ],
)
def test_nmap_basic_rejects_dangerous_fields_without_leaking_values(field_name):
    response = handle_active_nmap_basic_no_scan(make_boundary_request(**{field_name: "token_should_never_render"}))

    assert response["status"] == "blocked_no_live_service"
    assert response["errors"] == ["unsupported_request_field"]
    assert response["manual_validation_required"] is True
    assert response["job_created"] is False
    assert response["network_requests_sent"] == 0
    assert "token_should_never_render" not in serialized(response)
    assert_no_sensitive_output(response)


def test_nmap_basic_rejects_nested_dangerous_fields():
    payload = make_boundary_request(target_unit=make_boundary_request()["target_unit"] | {"script_output": "secret NSE"})

    response = handle_active_nmap_basic_no_scan(payload)

    assert response["status"] == "blocked_no_live_service"
    assert response["errors"] == ["unsupported_request_field"]
    assert "secret NSE" not in serialized(response)
    assert_no_sensitive_output(response)


@pytest.mark.parametrize(
    ("override", "reason"),
    [
        ({"targets": ["192.168.56.10", "192.168.56.11"]}, "multiple_targets_not_supported"),
        ({"target_unit": {"target": "192.168.56.0/24", "target_kind": "private_ip", "accepted_ports": [443]}}, "target_range_rejected"),
        ({"confirmations_verified_by_backend": False}, "backend_confirmations_missing"),
        ({"mode": "dry_run"}, "unsupported_mode"),
        ({"profile": "custom"}, "unsupported_profile"),
        ({"target_unit": {"target": "192.168.56.10", "target_kind": "private_ip", "accepted_ports": []}}, "accepted_ports_invalid"),
    ],
)
def test_nmap_basic_rejects_invalid_or_expanded_contract_shapes(override, reason):
    response = handle_active_nmap_basic_no_scan(make_boundary_request(**override))

    assert response["status"] == "blocked_no_live_service"
    assert response["errors"] == [reason]
    assert response["summary"]["target_count"] == 0
    assert_no_sensitive_output(response)


def test_dispatch_rejects_wrong_method_or_unknown_path_without_live_behavior():
    wrong_method = handle_active_tools_request("GET", ACTIVE_TOOLS_NMAP_BASIC_PATH, make_boundary_request())
    unknown_path = handle_active_tools_request("POST", "/public/scan", make_boundary_request())

    assert wrong_method["errors"] == ["method_not_allowed"]
    assert unknown_path["errors"] == ["not_found"]
    assert wrong_method["network_requests_sent"] == 0
    assert unknown_path["network_requests_sent"] == 0
    assert_no_sensitive_output(wrong_method)
    assert_no_sensitive_output(unknown_path)


def test_internal_service_skeleton_signature_has_no_server_or_raw_parameters():
    parameters = inspect.signature(handle_active_nmap_basic_no_scan).parameters

    assert set(parameters) == {"payload", "executor"}
    assert parameters["executor"].kind is inspect.Parameter.KEYWORD_ONLY
    for forbidden in ("raw_flags", "extra_args", "scripts", "credentials", "headers", "target_file"):
        assert forbidden not in parameters


def test_internal_service_skeleton_source_has_no_executor_or_runner_integration():
    service_source = Path("tools/active_runner/service.py").read_text(encoding="utf-8")
    runner_source = Path("tools/runner/main.py").read_text(encoding="utf-8")
    backend_services_source = Path("backend/app/services.py").read_text(encoding="utf-8")
    backend_main_source = Path("backend/app/main.py").read_text(encoding="utf-8")

    for forbidden in (
        "import " + "subprocess",
        "subprocess.",
        "shell" + "=True",
        "os." + "system",
        "po" + "pen",
        "P" + "open(",
        "DockerClient",
        "from " + "docker",
        "docker.sock",
        "nmap --version",
        "nmap -sT",
        "execute_active_nmap_basic",
        "active_runner.nmap_basic.executor",
        "tools/runner/main.py",
    ):
        assert forbidden not in service_source
    assert "active_nmap_basic" not in runner_source
    assert "nmap_basic" not in runner_source
    assert "active_runner.service" not in backend_services_source
    assert "active_runner.service" not in backend_main_source
