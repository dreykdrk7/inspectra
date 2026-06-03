import ast
import json
from pathlib import Path

from active_runner import (
    ActiveAuthorization,
    ActiveDryRunLimits,
    ActiveDryRunRequest,
    ActiveHttpHeaderProbeAuthorization,
    ActiveHttpHeaderProbeLimits,
    ActiveHttpHeaderProbeRequest,
    HeadResponse,
    run_active_network_dry_run,
    run_authorized_http_header_probe,
)
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


def make_header_probe_request(
    target: str = "https://public.example/path?ok=value",
    *,
    confirmed: bool = True,
    live_traffic_confirmed: bool = True,
    statement: str = APPROVED_AUTHORIZATION_STATEMENT,
    mode: str = "live_header_probe",
    profile: str = "http_header_probe",
    limits: ActiveHttpHeaderProbeLimits | None = None,
) -> ActiveHttpHeaderProbeRequest:
    return ActiveHttpHeaderProbeRequest(
        target=target,
        authorization=ActiveHttpHeaderProbeAuthorization(
            confirmed=confirmed,
            live_traffic_confirmed=live_traffic_confirmed,
            statement=statement,
            scope="single-target",
        ),
        mode=mode,
        profile=profile,
        limits=limits or ActiveHttpHeaderProbeLimits(),
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
            if path.name != "http_header_probe.py":
                blocked.update(module for module in imported if module == "socket")
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


def test_http_header_probe_valid_request_sends_one_head_and_redacts_headers():
    calls: list[tuple[str, int, dict[str, str]]] = []

    def resolver(host: str, port: int, timeout: int, max_answers: int) -> list[str]:
        assert host == "public.example"
        assert port == 443
        assert timeout == 3
        assert max_answers == 8
        return ["93.184.216.34"]

    def head_request(url: str, timeout: int, headers: dict[str, str]) -> HeadResponse:
        calls.append((url, timeout, headers))
        return HeadResponse(
            status_code=200,
            headers=[
                ("Server", "nginx"),
                ("Set-Cookie", "sessionid=super-secret-password"),
                ("Authorization", "Bearer token_should_never_render"),
            ],
        )

    result = run_authorized_http_header_probe(make_header_probe_request(), resolver=resolver, head_request=head_request)
    body = serialized(result)

    assert result["analyzer"] == "active_http_header_probe"
    assert result["mode"] == "live_header_probe"
    assert result["profile"] == "http_header_probe"
    assert result["policy"]["allowed"] is True
    assert result["summary"]["network_requests_sent"] == 1
    assert result["summary"]["headers_received_count"] == 3
    assert result["summary"]["redacted_headers_count"] == 2
    assert result["response"]["body_read"] is False
    assert result["response"]["body_bytes_read"] == 0
    assert result["response"]["redirect_followed"] is False
    assert calls == [
        (
            "https://public.example/path?ok=value",
            3,
            {"User-Agent": "Inspectra active-header-probe", "Accept": "*/*"},
        )
    ]
    assert "server_header_present_info" in {item["code"] for item in result["observations"]}
    for secret in FIXTURE_SECRETS + ("sessionid=super-secret-password",):
        assert secret not in body
    assert "[REDACTED]" in body


def test_http_header_probe_blocks_before_request_for_url_credentials_and_private_resolution():
    def forbidden_resolver(host: str, port: int, timeout: int, max_answers: int) -> list[str]:
        raise AssertionError("resolver should not be called")

    def forbidden_head(url: str, timeout: int, headers: dict[str, str]) -> HeadResponse:
        raise AssertionError("HEAD should not be sent")

    credential_result = run_authorized_http_header_probe(
        make_header_probe_request("http://user:pass@example.com"),
        resolver=forbidden_resolver,
        head_request=forbidden_head,
    )
    assert credential_result["summary"]["network_requests_sent"] == 0
    assert "url_credentials_rejected" in reason_codes(credential_result)
    assert "user:pass" not in serialized(credential_result)

    def private_resolver(host: str, port: int, timeout: int, max_answers: int) -> list[str]:
        return ["10.0.0.1"]

    private_result = run_authorized_http_header_probe(
        make_header_probe_request("https://public.example/"),
        resolver=private_resolver,
        head_request=forbidden_head,
    )
    assert private_result["summary"]["network_requests_sent"] == 0
    assert "resolved_ip_blocked" in reason_codes(private_result)
    assert private_result["dns"]["blocked_answers_count"] == 1


def test_http_header_probe_policy_validation_blocks_without_dns_or_http():
    def forbidden_resolver(host: str, port: int, timeout: int, max_answers: int) -> list[str]:
        raise AssertionError("resolver should not be called")

    def forbidden_head(url: str, timeout: int, headers: dict[str, str]) -> HeadResponse:
        raise AssertionError("HEAD should not be sent")

    cases = [
        (make_header_probe_request(confirmed=False), "authorization_missing"),
        (make_header_probe_request(live_traffic_confirmed=False), "live_traffic_confirmation_missing"),
        (make_header_probe_request(mode="dry_run"), "live_header_probe_mode_required"),
        (make_header_probe_request(profile="nmap_plan"), "nmap_not_allowed"),
        (make_header_probe_request(limits=ActiveHttpHeaderProbeLimits(max_requests=2)), "limits_exceed_http_header_probe"),
        (make_header_probe_request("public.example"), "live_url_required"),
    ]
    for request, reason_code in cases:
        result = run_authorized_http_header_probe(request, resolver=forbidden_resolver, head_request=forbidden_head)
        assert result["policy"]["allowed"] is False
        assert result["summary"]["network_requests_sent"] == 0
        assert reason_code in reason_codes(result)


def test_http_header_probe_no_get_fallback_and_redirect_not_followed():
    calls = []

    def resolver(host: str, port: int, timeout: int, max_answers: int) -> list[str]:
        return ["93.184.216.34"]

    def head_405(url: str, timeout: int, headers: dict[str, str]) -> HeadResponse:
        calls.append(url)
        return HeadResponse(status_code=405, headers=[("Allow", "GET")])

    method_result = run_authorized_http_header_probe(make_header_probe_request(), resolver=resolver, head_request=head_405)
    assert calls == ["https://public.example/path?ok=value"]
    assert method_result["summary"]["network_requests_sent"] == 1
    assert "head_not_allowed" in {error["code"] for error in method_result["errors"]}

    def head_redirect(url: str, timeout: int, headers: dict[str, str]) -> HeadResponse:
        return HeadResponse(
            status_code=302,
            headers=[("Location", "https://redirect.example/?token=token_should_never_render")],
        )

    redirect_result = run_authorized_http_header_probe(make_header_probe_request(), resolver=resolver, head_request=head_redirect)
    body = serialized(redirect_result)
    assert redirect_result["summary"]["network_requests_sent"] == 1
    assert redirect_result["summary"]["redirects_followed"] == 0
    assert redirect_result["response"]["redirect_presented"] is True
    assert redirect_result["response"]["redirect_followed"] is False
    assert "redirect_not_followed" in {error["code"] for error in redirect_result["errors"]}
    assert "token_should_never_render" not in body
    assert "token=REDACTED" in body


def test_http_header_probe_from_mapping_rejects_unknown_fields():
    payload = {
        "target": "https://public.example/",
        "authorization": {
            "confirmed": True,
            "live_traffic_confirmed": True,
            "statement": APPROVED_AUTHORIZATION_STATEMENT,
            "scope": "single-target",
        },
        "mode": "live_header_probe",
        "profile": "http_header_probe",
        "limits": {"max_targets": 1, "max_requests": 1, "unexpected": 0},
    }

    try:
        ActiveHttpHeaderProbeRequest.from_mapping(payload)
    except ValueError as exc:
        assert "Unknown limits field" in str(exc)
    else:
        raise AssertionError("unknown fields should be rejected")
