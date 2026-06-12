import json
from pathlib import Path

from active_runner.nmap_basic.parser import parse_active_nmap_basic_xml
from active_runner.nmap_basic.result import build_active_nmap_basic_result_payload


FIXTURE_DIR = Path(__file__).parent / "fixtures" / "active_nmap_basic"
FORBIDDEN_VISIBLE_TOKENS = (
    "203.0.113.10",
    "203.0.113.11",
    "redacted-ptr.example.internal",
    "unexpected-alias.example.internal",
    "other.example.internal",
    "nmap -sT",
    "<nmaprun",
    "file:///usr/share/nmap/nmap.xsl",
    "SyntheticPrivateServer",
    "9.9.9",
    "synthetic-banner",
    "synthetic NSE-like output",
)


def fixture(name: str) -> bytes:
    return (FIXTURE_DIR / name).read_bytes()


def serialized(payload) -> str:
    return json.dumps(payload, sort_keys=True)


def payload_from_xml(name: str, **parser_kwargs):
    parse_result = parse_active_nmap_basic_xml(fixture(name), **parser_kwargs)
    execution_result = {
        "status": "completed",
        "execution_attempted": True,
        "reason": "raw_bounded",
        "output_truncated": False,
        "stderr_truncated": False,
        "timed_out": False,
        "stdout": fixture(name).decode("utf-8", errors="replace"),
        "stderr": "raw stderr should not appear",
    }
    return parse_result, build_active_nmap_basic_result_payload(execution_result, parse_result)


def assert_forbidden_tokens_absent(payload):
    body = serialized(payload)
    for token in FORBIDDEN_VISIBLE_TOKENS:
        assert token not in body


def test_fqdn_xml_with_ptr_redacts_ptr_ip_raw_args_and_keeps_minimal_observation():
    parse_result, payload = payload_from_xml(
        "fqdn_with_ptr.xml",
        accepted_ports=[443],
        target_kind="authorized_fqdn",
    )

    assert parse_result["status"] == "completed"
    assert payload["status"] == "completed"
    assert payload["target_kind"] == "authorized_fqdn"
    assert payload["raw_xml_returned"] is False
    assert payload["command_returned"] is False
    assert payload["target_returned"] is False
    assert payload["stdout_returned"] is False
    assert payload["stderr_returned"] is False
    assert payload["manual_validation_required"] is True
    assert payload["result_interpretation"] == "observed_exposure_review_indicator"
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
    assert_forbidden_tokens_absent(payload)
    assert "resolved_target_observed" not in payload


def test_fqdn_xml_with_multiple_hostnames_does_not_expose_any_hostname_or_ip():
    parse_result, payload = payload_from_xml(
        "multiple_hostnames.xml",
        accepted_ports=[443],
        target_kind="authorized_fqdn",
    )

    assert parse_result["status"] == "completed"
    assert payload["port_observations"][0]["port"] == 443
    assert_forbidden_tokens_absent(payload)


def test_container_loopback_preserves_closed_observation_without_extra_hostname_or_ip():
    parse_result, payload = payload_from_xml(
        "container_loopback_closed.xml",
        accepted_ports=[65000],
        target_kind="container_loopback",
    )

    assert parse_result["status"] == "completed"
    assert payload["target_kind"] == "container_loopback"
    assert payload["port_observations"] == [
        {
            "port": 65000,
            "protocol": "tcp",
            "state": "closed",
            "manual_validation_required": True,
            "result_interpretation": "observed_exposure_review_indicator",
            "reason": "conn-refused",
        }
    ]
    body = serialized(payload)
    assert "hostname" not in body
    assert "hostnames" not in body
    assert "127.0.0.1" not in body


def test_multiple_hosts_are_unsupported_without_leaking_raw_hostnames_or_ips():
    parse_result, payload = payload_from_xml(
        "multiple_hosts.xml",
        accepted_ports=[443],
        target_kind="authorized_fqdn",
    )

    assert parse_result["status"] == "unsupported_shape"
    assert parse_result["parse_error"] == "multiple_hosts_unsupported"
    assert parse_result["parser_warnings"] == ["multiple_hosts_rejected"]
    assert payload["status"] == "unsupported_shape"
    assert payload["port_observations"] == []
    assert_forbidden_tokens_absent(payload)


def test_unexpected_port_is_unsupported_and_does_not_emit_observation():
    parse_result, payload = payload_from_xml(
        "unexpected_port.xml",
        accepted_ports=[443],
        target_kind="authorized_fqdn",
    )

    assert parse_result["status"] == "unsupported_shape"
    assert parse_result["parse_error"] == "unexpected_port"
    assert parse_result["parser_warnings"] == ["unexpected_port_rejected"]
    assert payload["status"] == "unsupported_shape"
    assert payload["port_observations"] == []
    assert "8443" not in serialized(payload)
    assert_forbidden_tokens_absent(payload)


def test_malformed_truncated_xml_returns_controlled_state_without_raw_xml():
    parse_result, payload = payload_from_xml(
        "malformed_truncated.xml",
        accepted_ports=[443],
        target_kind="authorized_fqdn",
    )

    assert parse_result["status"] == "malformed"
    assert parse_result["parse_error"] == "malformed_xml"
    assert payload["status"] == "malformed"
    assert payload["port_observations"] == []
    assert_forbidden_tokens_absent(payload)


def test_service_version_and_nse_like_sections_are_unsupported_or_dropped():
    parse_result, payload = payload_from_xml(
        "service_version_nse.xml",
        accepted_ports=[443],
        target_kind="authorized_fqdn",
    )

    assert parse_result["status"] == "unsupported_shape"
    assert parse_result["parse_error"] == "unsupported_live_output_section"
    assert parse_result["parser_warnings"] == ["script_or_os_output_rejected"]
    assert payload["port_observations"] == []
    assert_forbidden_tokens_absent(payload)
