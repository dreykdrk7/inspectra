import ast
import json
from pathlib import Path

from active_runner import ActiveAuthorization, ActiveDryRunLimits, ActiveDryRunRequest, run_active_network_dry_run
from active_runner.models import APPROVED_AUTHORIZATION_STATEMENT


FIXTURE_SECRETS = (
    "super-secret-password",
    "token_should_never_render",
    "http://user:pass@example.com",
    "Authorization: Bearer token_should_never_render",
    "PRIVATE KEY",
)


def make_request(
    target: str = "https://example.test",
    *,
    confirmed: bool = True,
    statement: str = APPROVED_AUTHORIZATION_STATEMENT,
    mode: str = "dry_run",
    profile: str = "http_header_probe_preview",
    limits: ActiveDryRunLimits | None = None,
) -> ActiveDryRunRequest:
    return ActiveDryRunRequest(
        target=target,
        authorization=ActiveAuthorization(confirmed=confirmed, statement=statement, scope="single-target"),
        mode=mode,
        profile=profile,
        limits=limits or ActiveDryRunLimits(),
    )


def reason_codes(result: dict) -> set[str]:
    return {reason["code"] for reason in result["blocked_reasons"]}


def serialized(result: dict) -> str:
    return json.dumps(result, sort_keys=True)


def test_valid_url_dry_run_allowed():
    result = run_active_network_dry_run(make_request("https://example.test/path?ok=value"))

    assert result["analyzer"] == "active_network_dry_run"
    assert result["mode"] == "dry_run"
    assert result["policy"]["allowed"] is True
    assert result["summary"]["network_requests_sent"] == 0
    assert result["summary"]["planned_checks_count"] == 1
    assert result["target"]["normalized"] == "https://example.test/path?ok=value"
    planned = result["planned_checks"][0]
    assert planned["would_contact_target"] is False
    assert planned["network_disabled"] is True
    assert planned["reason"] == "dry_run"


def test_valid_hostname_dry_run_allowed():
    result = run_active_network_dry_run(make_request("example.test"))

    assert result["policy"]["allowed"] is True
    assert result["target"]["type"] == "hostname"
    assert result["target"]["normalized"] == "example.test"
    assert result["planned_checks"][0]["url"] == "https://example.test/"
    assert result["summary"]["network_requests_sent"] == 0


def test_authorization_missing_blocked():
    result = run_active_network_dry_run(make_request(confirmed=False))

    assert result["policy"]["allowed"] is False
    assert "authorization_missing" in reason_codes(result)
    assert result["planned_checks"] == []
    assert result["summary"]["network_requests_sent"] == 0


def test_live_mode_rejected():
    result = run_active_network_dry_run(make_request(mode="live"))

    assert result["policy"]["allowed"] is False
    assert "live_mode_not_available" in reason_codes(result)
    assert result["summary"]["network_requests_sent"] == 0


def test_unknown_profile_rejected():
    result = run_active_network_dry_run(make_request(profile="ftp_probe"))

    assert result["policy"]["allowed"] is False
    assert "unknown_profile" in reason_codes(result)


def test_nmap_profile_rejected():
    result = run_active_network_dry_run(make_request(profile="nmap_plan"))

    assert result["policy"]["allowed"] is False
    assert "nmap_not_allowed" in reason_codes(result)
    assert result["summary"]["network_requests_sent"] == 0


def test_limits_above_zero_rejected():
    result = run_active_network_dry_run(make_request(limits=ActiveDryRunLimits(max_requests=1)))

    assert result["policy"]["allowed"] is False
    assert "limits_exceed_dry_run" in reason_codes(result)


def test_url_credentials_rejected_and_not_leaked():
    result = run_active_network_dry_run(make_request("http://user:pass@example.com"))
    body = serialized(result)

    assert result["policy"]["allowed"] is False
    assert "url_credentials_rejected" in reason_codes(result)
    assert "http://user:pass@example.com" not in body
    assert "user:pass" not in body
    assert "[REDACTED]" in body


def test_sensitive_query_values_are_redacted():
    result = run_active_network_dry_run(make_request("https://example.test/deploy?token=token_should_never_render&ok=value"))
    body = serialized(result)

    assert result["policy"]["allowed"] is True
    assert result["target"]["query_redacted"] == "token=REDACTED&ok=value"
    assert "token_should_never_render" not in body
    assert "token=REDACTED" in body


def test_private_ip_blocked():
    result = run_active_network_dry_run(make_request("10.0.0.1"))

    assert result["policy"]["allowed"] is False
    assert "private_range_blocked" in reason_codes(result)


def test_loopback_blocked_without_local_lab():
    result = run_active_network_dry_run(make_request("127.0.0.1"))

    assert result["policy"]["allowed"] is False
    assert "loopback_requires_local_lab" in reason_codes(result)


def test_metadata_ip_blocked():
    result = run_active_network_dry_run(make_request("169.254.169.254"))

    assert result["policy"]["allowed"] is False
    assert "metadata_target_blocked" in reason_codes(result)


def test_cidr_blocked():
    result = run_active_network_dry_run(make_request("10.0.0.0/8"))

    assert result["policy"]["allowed"] is False
    assert "target_cidr_rejected" in reason_codes(result)


def test_wildcard_blocked():
    result = run_active_network_dry_run(make_request("*.example.test"))

    assert result["policy"]["allowed"] is False
    assert "wildcard_rejected" in reason_codes(result)


def test_shell_like_input_blocked():
    result = run_active_network_dry_run(make_request("example.test; rm -rf /"))

    assert result["policy"]["allowed"] is False
    assert "suspicious_target_input" in reason_codes(result)


def test_audit_log_contains_expected_events_and_no_query_secret():
    result = run_active_network_dry_run(make_request("https://example.test/?api_key=token_should_never_render"))
    events = [event["event"] for event in result["audit_log"]]
    body = serialized(result)

    assert events == [
        "active_request_received",
        "authorization_checked",
        "target_normalized",
        "policy_evaluated",
        "dry_run_planned",
    ]
    assert "token_should_never_render" not in body


def test_blocked_audit_log_records_target_rejected():
    result = run_active_network_dry_run(make_request("*.example.test"))
    events = [event["event"] for event in result["audit_log"]]

    assert "target_rejected" in events
    assert "dry_run_blocked" in events


def test_no_bypass_wording_in_blocked_messages():
    blocked_results = [
        run_active_network_dry_run(make_request(confirmed=False)),
        run_active_network_dry_run(make_request("10.0.0.1")),
        run_active_network_dry_run(make_request(profile="nmap_plan")),
    ]
    messages = " ".join(reason["message"] for result in blocked_results for reason in result["blocked_reasons"]).lower()

    for forbidden in ("bypass", "proxy", "scan anyway", "try another encoding", "evade"):
        assert forbidden not in messages


def test_serialized_results_do_not_contain_fixture_secrets():
    targets = [
        "https://example.test/?password=super-secret-password",
        "https://example.test/?token=token_should_never_render",
        "http://user:pass@example.com",
        "Authorization: Bearer token_should_never_render",
        "-----BEGIN PRIVATE KEY----- secret material -----END PRIVATE KEY-----",
    ]
    body = "\n".join(serialized(run_active_network_dry_run(make_request(target))) for target in targets)

    for secret in FIXTURE_SECRETS:
        assert secret not in body
    assert "[REDACTED]" in body


def test_active_runner_does_not_import_network_or_probe_runtime_modules():
    forbidden_modules = {
        "requests",
        "httpx",
        "aiohttp",
        "socket",
        "subprocess",
        "nmap",
        "dns",
        "tools.runner.main",
    }
    active_runner_dir = Path(__file__).resolve().parents[1] / "active_runner"

    for path in active_runner_dir.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported = {alias.name for alias in node.names}
            elif isinstance(node, ast.ImportFrom):
                imported = {node.module or ""}
            else:
                continue
            blocked = {
                module
                for module in imported
                for forbidden in forbidden_modules
                if module == forbidden or module.startswith(f"{forbidden}.")
            }
            assert not blocked, f"{path} imports forbidden active runtime module(s): {blocked}"


def test_from_mapping_rejects_unknown_fields():
    payload = {
        "target": "https://example.test",
        "authorization": {"confirmed": True, "statement": APPROVED_AUTHORIZATION_STATEMENT, "scope": "single-target"},
        "mode": "dry_run",
        "profile": "http_header_probe_preview",
        "limits": {"max_requests": 0, "timeout_seconds": 0, "max_redirects": 0, "response_size_bytes": 0},
        "unexpected": True,
    }

    try:
        ActiveDryRunRequest.from_mapping(payload)
    except ValueError as exc:
        assert "Unknown request field" in str(exc)
    else:
        raise AssertionError("unknown fields should be rejected")
