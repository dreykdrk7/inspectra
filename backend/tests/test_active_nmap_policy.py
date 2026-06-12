import socket

import pytest

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
