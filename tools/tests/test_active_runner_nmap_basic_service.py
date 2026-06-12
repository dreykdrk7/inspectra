import inspect
import json
from pathlib import Path

import pytest

from active_runner.nmap_basic.service import (
    ActiveNmapBasicServiceError,
    ActiveNmapBasicServiceRequest,
    handle_active_nmap_basic_skeleton,
)
from active_runner.contracts import (
    ACTIVE_NMAP_BASIC_CAPABILITY,
    ACTIVE_NMAP_BASIC_MODE,
    ACTIVE_NMAP_BASIC_NOT_EXECUTED_REASON,
    ACTIVE_NMAP_BASIC_PROFILE,
)
from active_runner.nmap_basic import service


def make_request(**overrides):
    payload = {
        "mode": ACTIVE_NMAP_BASIC_MODE,
        "profile": ACTIVE_NMAP_BASIC_PROFILE,
        "target": "secret-lab.internal",
        "ports": [443, 22, 443, 80],
        "authorization_confirmed": True,
        "local_private_scope_confirmed": True,
        "live_traffic_confirmed": True,
    }
    payload.update(overrides)
    return payload


def serialized(payload) -> str:
    return json.dumps(payload, sort_keys=True)


def test_service_accepts_valid_input_and_returns_not_executed():
    result = handle_active_nmap_basic_skeleton(make_request())

    assert result["status"] == "not_executed"
    assert result["capability"] == ACTIVE_NMAP_BASIC_CAPABILITY
    assert result["mode"] == ACTIVE_NMAP_BASIC_MODE
    assert result["profile"] == ACTIVE_NMAP_BASIC_PROFILE
    assert result["execution_enabled"] is False
    assert result["job_created"] is False
    assert result["reason"] == ACTIVE_NMAP_BASIC_NOT_EXECUTED_REASON
    assert result["argv_preview_available"] is False
    assert result["command_builder_checked"] is True
    assert result["target_count"] == 1
    assert result["port_count"] == 3
    assert result["network_requests_sent"] is None
    assert result["summary"] == {
        "evidence_available": False,
        "nmap_executed": False,
        "parser_ran": False,
    }


def test_service_accepts_structured_request_instance():
    request = ActiveNmapBasicServiceRequest(
        target="192.168.56.10",
        ports=[22],
        authorization_confirmed=True,
        local_private_scope_confirmed=True,
        live_traffic_confirmed=True,
    )

    result = handle_active_nmap_basic_skeleton(request)

    assert result["status"] == "not_executed"
    assert result["port_count"] == 1


@pytest.mark.parametrize(
    ("override", "reason_code"),
    [
        ({"profile": "default"}, "unsupported_profile"),
        ({"mode": "dry_run"}, "unsupported_mode"),
        ({"target": ""}, "target_empty"),
        ({"ports": []}, "ports_empty"),
        ({"ports": ["22"]}, "port_not_integer"),
        ({"ports": [True]}, "port_not_integer"),
        ({"ports": [0]}, "port_out_of_range"),
        ({"ports": [65536]}, "port_out_of_range"),
    ],
)
def test_service_rejects_invalid_contract_or_builder_inputs(override, reason_code):
    with pytest.raises(ActiveNmapBasicServiceError, match=reason_code):
        handle_active_nmap_basic_skeleton(make_request(**override))


@pytest.mark.parametrize(
    "confirmation_field",
    [
        "authorization_confirmed",
        "local_private_scope_confirmed",
        "live_traffic_confirmed",
    ],
)
def test_service_rejects_missing_or_false_confirmations(confirmation_field):
    missing_payload = make_request()
    missing_payload.pop(confirmation_field)

    with pytest.raises(ActiveNmapBasicServiceError, match=f"{confirmation_field}_missing"):
        handle_active_nmap_basic_skeleton(missing_payload)
    with pytest.raises(ActiveNmapBasicServiceError, match=f"{confirmation_field}_missing"):
        handle_active_nmap_basic_skeleton(make_request(**{confirmation_field: False}))


@pytest.mark.parametrize(
    "field_name",
    [
        "raw_flags",
        "extra_args",
        "scripts",
        "script",
        "script_args",
        "credentials",
        "cookies",
        "tokens",
        "headers",
        "target_files",
        "shell",
        "shell_command",
        "command",
        "args",
        "custom_profile",
    ],
)
def test_service_rejects_raw_extra_script_and_shell_fields(field_name):
    with pytest.raises(ActiveNmapBasicServiceError, match="unsupported_request_field"):
        handle_active_nmap_basic_skeleton(make_request(**{field_name: "token_should_never_render"}))


def test_service_uses_builder_but_does_not_return_raw_argv_or_target(monkeypatch):
    calls = []

    def fake_builder(*, target, ports, profile):
        calls.append({"target": target, "ports": ports, "profile": profile})
        return ["nmap", "-p", "22,80", "--", target]

    monkeypatch.setattr(service, "build_active_nmap_basic_argv", fake_builder)

    result = service.handle_active_nmap_basic_skeleton(make_request(target="token-target.internal", ports=[80, 22]))
    body = serialized(result)

    assert calls == [{"target": "token-target.internal", "ports": [80, 22], "profile": ACTIVE_NMAP_BASIC_PROFILE}]
    assert result["command_builder_checked"] is True
    assert result["argv_preview_available"] is False
    assert "argv" not in result
    assert "command" not in result
    assert "token-target.internal" not in body
    assert "nmap -p" not in body


def test_service_response_has_no_nmap_output_or_vulnerability_claims():
    body = serialized(handle_active_nmap_basic_skeleton(make_request(target="token-target.internal")))

    assert "token-target.internal" not in body
    assert "stdout" not in body
    assert "stderr" not in body
    assert "confirmed vulnerability" not in body
    assert "exploitable" not in body
    assert "target is safe" not in body


def test_service_signature_has_no_raw_or_extra_argument_parameters():
    parameters = inspect.signature(handle_active_nmap_basic_skeleton).parameters

    assert set(parameters) == {"request"}
    assert "extra_args" not in parameters
    assert "raw_flags" not in parameters
    assert "script" not in parameters


def test_service_source_has_no_execution_network_or_passive_runner_integration():
    source_paths = [
        Path("tools/active_runner/contracts.py"),
        Path("tools/active_runner/nmap_basic/__init__.py"),
        Path("tools/active_runner/nmap_basic/command_builder.py"),
        Path("tools/active_runner/nmap_basic/service.py"),
    ]
    combined = "\n".join(path.read_text(encoding="utf-8") for path in source_paths)

    forbidden_source_terms = [
        "sub" + "process",
        "shell" + "=True",
        "os." + "system",
        "po" + "pen",
        "P" + "open(",
        "requests.",
        "httpx",
        "socket.",
        "dns.",
        "tools.runner",
        "runner/main.py",
    ]
    for term in forbidden_source_terms:
        assert term not in combined
