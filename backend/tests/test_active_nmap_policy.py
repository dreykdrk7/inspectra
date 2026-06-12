import socket

import pytest

from active_runner import (
    ActiveNmapBasicTargetPolicyError,
    validate_active_nmap_basic_execution_target,
)
from app.active_nmap_handoff import ActiveNmapBasicHandoffError, build_active_nmap_basic_handoff_plan
from app.active_nmap_policy import ActiveNmapTargetPolicyError, validate_active_nmap_basic_targets


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("192.168.56.10", "192.168.56.10"),
        ("10.1.2.3", "10.1.2.3"),
        ("172.16.5.20", "172.16.5.20"),
        ("127.0.0.1", "127.0.0.1"),
        ("fc00::10", "fc00::10"),
        ("::1", "::1"),
        ("inspectra-lab", "inspectra-lab"),
        ("NAS-01.local", "nas-01.local"),
        ("app.internal", "app.internal"),
        ("service.test", "service.test"),
    ],
)
def test_active_nmap_policy_accepts_exact_private_or_local_targets(target, expected):
    result = validate_active_nmap_basic_targets([target])

    assert result.normalized_targets == (expected,)
    assert result.target_count == 1


@pytest.mark.parametrize(
    ("target", "reason_code"),
    [
        ("192.168.56.0/24", "target_unsupported_syntax"),
        ("192.168.1.1-254", "target_range_not_allowed"),
        ("*.internal", "target_unsupported_syntax"),
        ("http://192.168.56.10", "target_unsupported_syntax"),
        ("lab.internal/path", "target_unsupported_syntax"),
        ("lab.internal?debug=true", "target_unsupported_syntax"),
        ("lab.internal#fragment", "target_unsupported_syntax"),
        ("user:pass@lab.internal", "target_unsupported_syntax"),
        ("192.168.56.10,192.168.56.11", "target_unsupported_syntax"),
        ("192.168.56.10 192.168.56.11", "target_list_in_string"),
        ("169.254.169.254", "target_special_purpose_blocked"),
        ("169.254.170.2", "target_special_purpose_blocked"),
        ("metadata.google.internal", "target_control_plane_blocked"),
        ("kubernetes.default.svc", "target_control_plane_blocked"),
        ("203.0.113.10", "target_special_purpose_blocked"),
        ("198.51.100.10", "target_special_purpose_blocked"),
        ("198.18.0.1", "target_special_purpose_blocked"),
        ("224.0.0.1", "target_special_purpose_blocked"),
        ("255.255.255.255", "target_special_purpose_blocked"),
        ("8.8.8.8", "target_not_local_private"),
        ("example.com", "target_not_local_private"),
        ("lab.internal.", "target_ambiguous"),
        (" lab.internal", "target_ambiguous"),
        ("lab.internal:443", "target_port_not_allowed"),
        ("@targets.txt", "target_unsupported_syntax"),
    ],
)
def test_active_nmap_policy_rejects_unsafe_or_ambiguous_targets(target, reason_code):
    with pytest.raises(ActiveNmapTargetPolicyError) as exc_info:
        validate_active_nmap_basic_targets([target])

    assert exc_info.value.reason_code == reason_code


def test_active_nmap_policy_enforces_target_count_and_length():
    with pytest.raises(ActiveNmapTargetPolicyError, match="too_many_targets"):
        validate_active_nmap_basic_targets(["192.168.56.10", "192.168.56.11", "192.168.56.12", "192.168.56.13"])

    with pytest.raises(ActiveNmapTargetPolicyError, match="target_too_long"):
        validate_active_nmap_basic_targets([f"{'a' * 245}.internal"])


def test_active_nmap_policy_rejects_duplicate_normalized_targets():
    with pytest.raises(ActiveNmapTargetPolicyError, match="duplicate_targets"):
        validate_active_nmap_basic_targets(["NAS-01.local", "nas-01.local"])


def test_active_nmap_policy_does_not_resolve_dns(monkeypatch):
    def fail_getaddrinfo(*args, **kwargs):
        raise AssertionError("DNS resolution must not be attempted")

    monkeypatch.setattr(socket, "getaddrinfo", fail_getaddrinfo)

    result = validate_active_nmap_basic_targets(["router.local", "192.168.56.10"])

    assert result.normalized_targets == ("router.local", "192.168.56.10")


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("192.168.56.10", "192.168.56.10"),
        ("10.1.2.3", "10.1.2.3"),
        ("172.16.5.20", "172.16.5.20"),
        ("127.0.0.1", "127.0.0.1"),
        ("fc00::10", "fc00::10"),
        ("::1", "::1"),
        ("inspectra-lab", "inspectra-lab"),
        ("NAS-01.local", "nas-01.local"),
        ("app.internal", "app.internal"),
        ("service.test", "service.test"),
    ],
)
def test_active_nmap_basic_backend_and_runner_policy_acceptance_parity(target, expected):
    backend_result = validate_active_nmap_basic_targets([target])
    runner_result = validate_active_nmap_basic_execution_target(target)

    assert backend_result.normalized_targets == (expected,)
    assert runner_result.normalized_target == expected


@pytest.mark.parametrize(
    ("target", "reason_code"),
    [
        ("192.168.56.0/24", "target_unsupported_syntax"),
        ("192.168.1.1-254", "target_range_not_allowed"),
        ("*.internal", "target_unsupported_syntax"),
        ("http://192.168.56.10", "target_unsupported_syntax"),
        ("lab.internal/path", "target_unsupported_syntax"),
        ("lab.internal?debug=true", "target_unsupported_syntax"),
        ("lab.internal#fragment", "target_unsupported_syntax"),
        ("user:pass@lab.internal", "target_unsupported_syntax"),
        ("192.168.56.10,192.168.56.11", "target_unsupported_syntax"),
        ("192.168.56.10 192.168.56.11", "target_list_in_string"),
        ("169.254.169.254", "target_special_purpose_blocked"),
        ("169.254.170.2", "target_special_purpose_blocked"),
        ("metadata.google.internal", "target_control_plane_blocked"),
        ("kubernetes.default.svc", "target_control_plane_blocked"),
        ("203.0.113.10", "target_special_purpose_blocked"),
        ("198.51.100.10", "target_special_purpose_blocked"),
        ("198.18.0.1", "target_special_purpose_blocked"),
        ("224.0.0.1", "target_special_purpose_blocked"),
        ("255.255.255.255", "target_special_purpose_blocked"),
        ("8.8.8.8", "target_not_local_private"),
        ("example.com", "target_not_local_private"),
        ("lab.internal.", "target_ambiguous"),
        (" lab.internal", "target_ambiguous"),
        ("lab.internal:443", "target_port_not_allowed"),
        ("@targets.txt", "target_unsupported_syntax"),
    ],
)
def test_active_nmap_basic_backend_and_runner_policy_rejection_parity(target, reason_code):
    with pytest.raises(ActiveNmapTargetPolicyError) as backend_exc:
        validate_active_nmap_basic_targets([target])
    with pytest.raises(ActiveNmapBasicTargetPolicyError) as runner_exc:
        validate_active_nmap_basic_execution_target(target)

    assert backend_exc.value.reason_code == reason_code
    assert runner_exc.value.reason_code == reason_code


def make_active_nmap_basic_handoff_payload(**overrides):
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


def test_active_nmap_basic_handoff_serializes_targets_to_single_target_units_no_live():
    plan = build_active_nmap_basic_handoff_plan(
        make_active_nmap_basic_handoff_payload(
            targets=["192.168.56.10", "NAS-01.local", "fc00::10"],
            ports=[443, 22],
        )
    )

    assert plan.target_count == 3
    assert plan.port_count == 2
    assert plan.target_port_checks == 6
    assert plan.implicit_concurrency == 1
    assert [unit.target for unit in plan.units] == ["192.168.56.10", "nas-01.local", "fc00::10"]
    assert [unit.sequence_index for unit in plan.units] == [0, 1, 2]
    assert all(unit.ports == (443, 22) for unit in plan.units)
    assert all(unit.mode == "live_nmap_basic" and unit.profile == "tcp_connect_small" for unit in plan.units)
    assert all(unit.authorization_confirmed is True for unit in plan.units)
    assert all(unit.local_private_scope_confirmed is True for unit in plan.units)
    assert all(unit.live_traffic_confirmed is True for unit in plan.units)


@pytest.mark.parametrize(
    ("override", "reason_code"),
    [
        ({"targets": ["192.168.56.10", "192.168.56.11", "192.168.56.12", "192.168.56.13"]}, "too_many_targets"),
        ({"targets": ["NAS-01.local", "nas-01.local"]}, "duplicate_targets"),
        ({"targets": ["192.168.56.0/24"]}, "target_unsupported_syntax"),
        ({"targets": ["192.168.56.10 192.168.56.11"]}, "target_list_in_string"),
        ({"ports": list(range(1, 34))}, "too_many_ports"),
        ({"ports": ["22"]}, "port_not_integer"),
        ({"authorization_confirmed": False}, "authorization_confirmed_missing"),
        ({"local_private_scope_confirmed": False}, "local_private_scope_confirmed_missing"),
        ({"live_traffic_confirmed": False}, "live_traffic_confirmed_missing"),
        ({"raw_flags": "-A"}, "unsupported_request_field"),
    ],
)
def test_active_nmap_basic_handoff_rejects_wide_batches_and_unsupported_fields_no_live(override, reason_code):
    with pytest.raises(ActiveNmapBasicHandoffError) as exc_info:
        build_active_nmap_basic_handoff_plan(make_active_nmap_basic_handoff_payload(**override))

    assert exc_info.value.reason_code == reason_code
