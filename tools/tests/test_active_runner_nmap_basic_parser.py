import json
from pathlib import Path

from active_runner import parse_active_nmap_basic_xml


def serialized(payload) -> str:
    return json.dumps(payload, sort_keys=True)


def test_parser_accepts_minimal_xml_with_open_tcp_port():
    result = parse_active_nmap_basic_xml(
        b"""
        <nmaprun>
          <host>
            <ports>
              <port protocol="tcp" portid="443">
                <state state="open" reason="syn-ack"/>
              </port>
            </ports>
          </host>
        </nmaprun>
        """
    )

    assert result["status"] == "completed"
    assert result["port_observations"] == [{"port": 443, "protocol": "tcp", "state": "open", "reason": "syn-ack"}]
    assert result["observation_count"] == 1
    assert result["output_truncated"] is False
    assert result["parse_error"] is None
    assert result["raw_xml_returned"] is False
    assert result["command_returned"] is False
    assert result["target_returned"] is False
    assert result["findings_created"] is False


def test_parser_preserves_closed_filtered_as_conservative_observation():
    result = parse_active_nmap_basic_xml(
        """
        <nmaprun>
          <host>
            <ports>
              <port protocol="tcp" portid="25">
                <state state="closed|filtered" reason="no-response"/>
              </port>
            </ports>
          </host>
        </nmaprun>
        """
    )

    assert result["status"] == "completed"
    assert result["port_observations"] == [
        {"port": 25, "protocol": "tcp", "state": "closed|filtered", "reason": "no-response"}
    ]


def test_parser_ignores_host_addresses_and_hostnames():
    result = parse_active_nmap_basic_xml(
        b"""
        <nmaprun>
          <host>
            <address addr="192.168.56.10" addrtype="ipv4"/>
            <hostnames>
              <hostname name="secret-lab.internal" type="PTR"/>
            </hostnames>
            <ports>
              <port protocol="tcp" portid="22">
                <state state="open" reason="syn-ack"/>
              </port>
            </ports>
          </host>
        </nmaprun>
        """
    )
    body = serialized(result)

    assert result["status"] == "completed"
    assert result["target_returned"] is False
    assert "192.168.56.10" not in body
    assert "secret-lab.internal" not in body


def test_parser_ignores_service_and_version_fields():
    result = parse_active_nmap_basic_xml(
        b"""
        <nmaprun>
          <host>
            <ports>
              <port protocol="tcp" portid="443">
                <state state="open" reason="syn-ack"/>
                <service name="https" product="PrivateServer" version="9.9.9" extrainfo="secret-banner"/>
              </port>
            </ports>
          </host>
        </nmaprun>
        """
    )
    body = serialized(result)

    assert result["status"] == "completed"
    assert result["port_observations"] == [{"port": 443, "protocol": "tcp", "state": "open", "reason": "syn-ack"}]
    assert "PrivateServer" not in body
    assert "9.9.9" not in body
    assert "secret-banner" not in body
    assert "service" not in body


def test_parser_handles_malformed_xml_as_controlled_error():
    result = parse_active_nmap_basic_xml(b"<nmaprun><host>")

    assert result["status"] == "malformed"
    assert result["parse_error"] == "malformed_xml"
    assert result["port_observations"] == []
    assert result["observation_count"] == 0
    assert result["output_truncated"] is False


def test_parser_handles_empty_output_as_controlled_state():
    result = parse_active_nmap_basic_xml(b"   \n\t")

    assert result["status"] == "empty"
    assert result["parse_error"] is None
    assert result["port_observations"] == []
    assert result["observation_count"] == 0


def test_parser_rejects_oversized_output_before_parse():
    result = parse_active_nmap_basic_xml(b"<nmaprun>" + (b" " * 32) + b"</nmaprun>", max_input_bytes=16)

    assert result["status"] == "truncated"
    assert result["parse_error"] == "output_exceeds_parser_limit"
    assert result["output_truncated"] is True
    assert result["port_observations"] == []
    assert result["parser_warnings"] == ["input_truncated_before_parse"]


def test_parser_limits_too_many_port_observations():
    ports = "\n".join(
        f'<port protocol="tcp" portid="{port}"><state state="open" reason="syn-ack"/></port>'
        for port in range(20, 25)
    )
    result = parse_active_nmap_basic_xml(
        f"<nmaprun><host><ports>{ports}</ports></host></nmaprun>",
        max_port_observations=2,
    )

    assert result["status"] == "completed"
    assert result["output_truncated"] is True
    assert result["observation_count"] == 2
    assert [observation["port"] for observation in result["port_observations"]] == [20, 21]
    assert result["parser_warnings"] == ["port_observation_limit_reached"]


def test_parser_normalizes_unknown_state_without_claiming_more():
    result = parse_active_nmap_basic_xml(
        b"""
        <nmaprun>
          <host>
            <ports>
              <port protocol="tcp" portid="8080">
                <state state="weird" reason="reset"/>
              </port>
            </ports>
          </host>
        </nmaprun>
        """
    )

    assert result["status"] == "completed"
    assert result["port_observations"] == [
        {"port": 8080, "protocol": "tcp", "state": "unknown", "reason": "reset"}
    ]
    assert result["parser_warnings"] == ["unknown_state_normalized"]


def test_parser_drops_unallowlisted_reason_values():
    result = parse_active_nmap_basic_xml(
        b"""
        <nmaprun>
          <host>
            <ports>
              <port protocol="tcp" portid="8080">
                <state state="open" reason="192.168.56.10"/>
              </port>
            </ports>
          </host>
        </nmaprun>
        """
    )
    body = serialized(result)

    assert result["status"] == "completed"
    assert result["port_observations"] == [{"port": 8080, "protocol": "tcp", "state": "open"}]
    assert "192.168.56.10" not in body


def test_parser_returns_no_raw_xml_target_command_or_claim_wording():
    result = parse_active_nmap_basic_xml(
        b"""
        <nmaprun args="nmap -sT -p 443 192.168.56.10">
          <host>
            <address addr="192.168.56.10"/>
            <ports>
              <port protocol="tcp" portid="443">
                <state state="open" reason="syn-ack"/>
                <service name="https" product="confirmed vulnerability exploitable target is safe"/>
              </port>
            </ports>
          </host>
        </nmaprun>
        """
    )
    body = serialized(result)

    assert "raw_xml" not in result
    assert "stdout" not in result
    assert "stderr" not in result
    assert "command" not in result
    assert result["raw_xml_returned"] is False
    assert result["command_returned"] is False
    assert result["target_returned"] is False
    assert result["findings_created"] is False
    assert "192.168.56.10" not in body
    assert "nmap -sT" not in body
    assert "confirmed vulnerability" not in body
    assert "exploitable" not in body
    assert "target is safe" not in body


def test_parser_rejects_doctype_and_entity_shapes():
    result = parse_active_nmap_basic_xml(
        b"""
        <!DOCTYPE nmaprun [
          <!ENTITY secret SYSTEM "file:///tmp/secret">
        ]>
        <nmaprun><host><ports/></host></nmaprun>
        """
    )

    assert result["status"] == "unsupported_shape"
    assert result["parse_error"] == "unsupported_xml_shape"
    assert result["parser_warnings"] == ["doctype_or_entity_rejected"]
    assert result["port_observations"] == []


def test_parser_ignores_non_tcp_and_invalid_ports():
    result = parse_active_nmap_basic_xml(
        b"""
        <nmaprun>
          <host>
            <ports>
              <port protocol="udp" portid="53"><state state="open"/></port>
              <port protocol="tcp" portid="0"><state state="open"/></port>
              <port protocol="tcp" portid="22"><state state="closed"/></port>
            </ports>
          </host>
        </nmaprun>
        """
    )

    assert result["status"] == "completed"
    assert result["port_observations"] == [{"port": 22, "protocol": "tcp", "state": "closed"}]
    assert result["parser_warnings"] == ["unsupported_protocol_ignored", "invalid_port_ignored"]


def test_parser_source_has_no_subprocess_dns_network_or_runner_integration():
    source = Path("tools/active_runner/nmap_basic/parser.py").read_text(encoding="utf-8")

    forbidden_source_terms = [
        "sub" + "process",
        "shell" + "=True",
        "os." + "system",
        "po" + "pen",
        "P" + "open(",
        "socket.",
        "dns.",
        "requests.",
        "httpx",
        "tools.runner",
        "runner/main.py",
    ]
    for term in forbidden_source_terms:
        assert term not in source
