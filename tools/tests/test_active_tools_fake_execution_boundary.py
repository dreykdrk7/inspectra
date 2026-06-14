import json
from pathlib import Path

import pytest

from active_runner.contracts import ACTIVE_NMAP_BASIC_MODE, ACTIVE_NMAP_BASIC_PROFILE
from active_runner.service import (
    ACTIVE_TOOLS_FAKE_EXECUTOR_NAME,
    ACTIVE_TOOLS_NO_SCAN_REASON,
    handle_active_nmap_basic_no_scan,
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


def completed_fake_response(**overrides):
    response = {
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
    response.update(overrides)
    return response


def serialized(payload) -> str:
    return json.dumps(payload, sort_keys=True)


def assert_no_sensitive_output(response):
    body = serialized(response)
    for forbidden in (
        "192.168.56.10",
        "secret-lab.internal",
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


def test_valid_request_without_fake_executor_still_returns_not_executed():
    response = handle_active_nmap_basic_no_scan(make_boundary_request())

    assert response["status"] == "not_executed"
    assert response["reason"] == ACTIVE_TOOLS_NO_SCAN_REASON
    assert response["network_requests_sent"] == 0
    assert response["summary"]["nmap_executed"] is False
    assert response["observations"] == []
    assert response["errors"] == []
    assert_no_sensitive_output(response)


def test_fake_executor_completed_response_returns_minimal_observation():
    calls = []

    def fake_executor(request):
        calls.append(request)
        return completed_fake_response()

    response = handle_active_nmap_basic_no_scan(make_boundary_request(), executor=fake_executor)

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
    assert response["status"] == "completed"
    assert response["profile"] == ACTIVE_NMAP_BASIC_PROFILE
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
    assert response["summary"] == {
        "target_count": 1,
        "port_count": 2,
        "nmap_executed": False,
        "fake_executor": True,
        "evidence_available": True,
    }
    assert response["execution_metadata"]["executor"] == ACTIVE_TOOLS_FAKE_EXECUTOR_NAME
    assert response["execution_metadata"]["duration_ms"] == 7
    assert response["execution_metadata"]["nmap_executed"] is False
    assert response["network_requests_sent"] == 0
    assert response["warnings"] == ["synthetic_fake_completed"]
    assert response["errors"] == []
    assert_no_sensitive_output(response)


@pytest.mark.parametrize("field_name", ["raw_flags", "scripts", "credentials", "headers", "cookies", "tokens"])
def test_request_validation_rejects_dangerous_fields_before_fake_executor(field_name):
    def fake_executor(request):
        raise AssertionError("fake executor must not be called")

    response = handle_active_nmap_basic_no_scan(
        make_boundary_request(**{field_name: "token_should_never_render"}),
        executor=fake_executor,
    )

    assert response["status"] == "blocked_no_live_service"
    assert response["errors"] == ["unsupported_request_field"]
    assert_no_sensitive_output(response)


@pytest.mark.parametrize(
    "field_name",
    [
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
    ],
)
def test_fake_response_with_sensitive_or_unexpected_fields_is_blocked(field_name):
    def fake_executor(request):
        return completed_fake_response(**{field_name: "token_should_never_render"})

    response = handle_active_nmap_basic_no_scan(make_boundary_request(), executor=fake_executor)

    assert response["status"] == "blocked"
    assert response["errors"] == ["unexpected_fields"]
    assert response["observations"] == []
    assert_no_sensitive_output(response)


def test_fake_response_with_nested_sensitive_metadata_is_blocked():
    def fake_executor(request):
        return completed_fake_response(execution_metadata={"raw_xml": "<nmaprun />"})

    response = handle_active_nmap_basic_no_scan(make_boundary_request(), executor=fake_executor)

    assert response["status"] == "blocked"
    assert response["errors"] == ["unexpected_fields"]
    assert_no_sensitive_output(response)


def test_fake_response_with_unexpected_metadata_field_is_blocked():
    def fake_executor(request):
        return completed_fake_response(
            execution_metadata={"executor": ACTIVE_TOOLS_FAKE_EXECUTOR_NAME, "extra": "value"}
        )

    response = handle_active_nmap_basic_no_scan(make_boundary_request(), executor=fake_executor)

    assert response["status"] == "blocked"
    assert response["errors"] == ["unexpected_fields"]
    assert_no_sensitive_output(response)


@pytest.mark.parametrize(
    "override",
    [
        {"manual_validation_required": False},
        {"result_interpretation": "confirmed vulnerability"},
    ],
)
def test_fake_response_with_unsafe_top_level_semantics_is_controlled(override):
    def fake_executor(request):
        return completed_fake_response(**override)

    response = handle_active_nmap_basic_no_scan(make_boundary_request(), executor=fake_executor)

    assert response["status"] == "unsupported_shape"
    assert response["errors"] == ["unsupported_shape"]
    assert_no_sensitive_output(response)


@pytest.mark.parametrize(
    "observation_override",
    [
        {"manual_validation_required": False},
        {"result_interpretation": "exploitable"},
    ],
)
def test_fake_response_with_unsafe_observation_semantics_is_controlled(observation_override):
    observation = {
        "port": 443,
        "protocol": "tcp",
        "state": "open",
        "reason": "syn-ack",
        "manual_validation_required": True,
        "result_interpretation": "observed_exposure_review_indicator",
    }
    observation.update(observation_override)

    def fake_executor(request):
        return completed_fake_response(observations=[observation])

    response = handle_active_nmap_basic_no_scan(make_boundary_request(), executor=fake_executor)

    assert response["status"] == "unsupported_shape"
    assert response["errors"] == ["unsupported_shape"]
    assert_no_sensitive_output(response)


@pytest.mark.parametrize(
    "observation_override",
    [
        {"state": "confirmed vulnerability"},
        {"reason": "service banner token_should_never_render"},
    ],
)
def test_fake_response_with_unallowlisted_observation_values_is_malformed(observation_override):
    observation = {
        "port": 443,
        "protocol": "tcp",
        "state": "open",
        "reason": "syn-ack",
        "manual_validation_required": True,
        "result_interpretation": "observed_exposure_review_indicator",
    }
    observation.update(observation_override)

    def fake_executor(request):
        return completed_fake_response(observations=[observation])

    response = handle_active_nmap_basic_no_scan(make_boundary_request(), executor=fake_executor)

    assert response["status"] == "malformed"
    assert response["errors"] == ["malformed"]
    assert "confirmed vulnerability" not in json.dumps(response, sort_keys=True)
    assert "token_should_never_render" not in json.dumps(response, sort_keys=True)
    assert_no_sensitive_output(response)


def test_fake_response_with_unexpected_port_is_policy_drift():
    def fake_executor(request):
        return completed_fake_response(
            observations=[
                {
                    "port": 8443,
                    "protocol": "tcp",
                    "state": "open",
                    "reason": "syn-ack",
                    "manual_validation_required": True,
                    "result_interpretation": "observed_exposure_review_indicator",
                }
            ]
        )

    response = handle_active_nmap_basic_no_scan(make_boundary_request(), executor=fake_executor)

    assert response["status"] == "blocked"
    assert response["errors"] == ["policy_drift"]
    assert response["observations"] == []
    assert_no_sensitive_output(response)


def test_fake_response_with_unsupported_protocol_is_controlled():
    def fake_executor(request):
        return completed_fake_response(observations=[{"port": 443, "protocol": "udp", "state": "open"}])

    response = handle_active_nmap_basic_no_scan(make_boundary_request(), executor=fake_executor)

    assert response["status"] == "unsupported_shape"
    assert response["errors"] == ["unsupported_shape"]
    assert_no_sensitive_output(response)


def test_fake_executor_exception_returns_controlled_failed_response():
    def fake_executor(request):
        raise RuntimeError("secret-lab.internal token_should_never_render")

    response = handle_active_nmap_basic_no_scan(make_boundary_request(), executor=fake_executor)

    assert response["status"] == "failed"
    assert response["errors"] == ["fake_executor_exception"]
    assert response["network_requests_sent"] == 0
    assert response["summary"]["nmap_executed"] is False
    assert_no_sensitive_output(response)


@pytest.mark.parametrize(
    ("status", "expected_status"),
    [
        ("timed_out", "timed_out"),
        ("nmap_missing", "nmap_missing"),
        ("malformed", "malformed"),
        ("unsupported_shape", "unsupported_shape"),
        ("blocked", "blocked"),
    ],
)
def test_fake_executor_controlled_statuses_are_preserved(status, expected_status):
    def fake_executor(request):
        return {
            "status": status,
            "profile": ACTIVE_NMAP_BASIC_PROFILE,
            "target_kind": "private_ip",
            "manual_validation_required": True,
            "result_interpretation": "observed_exposure_review_indicator",
            "observations": [],
            "output_truncated": False,
            "execution_metadata": {"executor": ACTIVE_TOOLS_FAKE_EXECUTOR_NAME, "nmap_executed": False},
            "warnings": [],
            "errors": [status],
        }

    response = handle_active_nmap_basic_no_scan(make_boundary_request(), executor=fake_executor)

    assert response["status"] == expected_status
    assert response["manual_validation_required"] is True
    assert response["result_interpretation"] == "observed_exposure_review_indicator"
    assert response["observations"] == []
    assert response["network_requests_sent"] == 0
    assert response["summary"]["fake_executor"] is True
    assert response["summary"]["nmap_executed"] is False
    assert_no_sensitive_output(response)


def test_fake_executor_source_has_no_live_runtime_or_backend_imports():
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
        "backend.app",
        "tools/runner/" + "main.py",
    ):
        assert forbidden not in service_source
    assert "execute_active_nmap_basic" in service_source
    assert "active_runner.nmap_basic.executor" in service_source
    assert "active_nmap_basic" not in runner_source
    assert "nmap_basic" not in runner_source
    assert "active_runner.service" not in backend_services_source
