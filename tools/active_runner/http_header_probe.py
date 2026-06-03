from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from dataclasses import dataclass
import http.client
import ipaddress
import socket
from typing import Any, Callable
from urllib.parse import urlsplit, urlunsplit

from .audit_log import audit_event
from .models import (
    ALLOWED_HTTP_HEADER_PROBE_PROFILES,
    APPROVED_AUTHORIZATION_STATEMENT,
    HTTP_HEADER_PROBE,
    HTTP_HEADER_PROBE_POLICY_VERSION,
    LIVE_HEADER_PROBE_MODE,
    ActiveHttpHeaderProbeRequest,
    ActiveHttpHeaderProbeResult,
)
from .safety import (
    REDACTED,
    blocked_ip_reason,
    blocked_reason,
    normalize_target,
    redact_sensitive_text,
    redact_url_for_display,
)


Resolver = Callable[[str, int, int, int], list[str]]
HeadRequester = Callable[[str, int, dict[str, str]], "HeadResponse"]

USER_AGENT = "Inspectra active-header-probe"
SENSITIVE_HEADER_NAMES = {
    "set-cookie",
    "cookie",
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "api-key",
    "x-auth-token",
    "x-csrf-token",
    "csrf-token",
}


@dataclass(frozen=True)
class HeadResponse:
    status_code: int
    headers: list[tuple[str, str]]


def run_authorized_http_header_probe(
    request: ActiveHttpHeaderProbeRequest,
    *,
    resolver: Resolver | None = None,
    head_request: HeadRequester | None = None,
) -> ActiveHttpHeaderProbeResult:
    resolver = resolver or default_resolver
    head_request = head_request or default_head_request
    audit_log: list[dict[str, Any]] = [audit_event("active_http_header_probe_received", {"mode": request.mode, "profile": request.profile})]
    blocked_reasons: list[dict[str, str]] = []
    errors: list[dict[str, str]] = []

    if not request.authorization.confirmed or request.authorization.statement != APPROVED_AUTHORIZATION_STATEMENT:
        blocked_reasons.append(blocked_reason("authorization_missing"))
    if not request.authorization.live_traffic_confirmed:
        blocked_reasons.append(blocked_reason("live_traffic_confirmation_missing"))
    audit_log.append(
        audit_event(
            "authorization_checked",
            {
                "confirmed": request.authorization.confirmed,
                "live_traffic_confirmed": request.authorization.live_traffic_confirmed,
            },
        )
    )

    target, target_reasons = normalize_live_url_target(request.target)
    blocked_reasons.extend(target_reasons)
    if target_reasons:
        audit_log.append(audit_event("target_rejected", {"blocked_reasons": [reason["code"] for reason in target_reasons]}))
    else:
        audit_log.append(audit_event("target_normalized", {"type": target["type"], "classification": target["classification"]}))

    blocked_reasons.extend(validate_mode_profile_and_limits(request))
    if blocked_reasons:
        audit_log.append(audit_event("policy_evaluated", {"allowed": False, "blocked_reasons": [reason["code"] for reason in blocked_reasons]}))
        return build_result(request, target, blocked_reasons, audit_log, errors, dns_summary(), None, network_requests_sent=0)

    dns = dns_summary()
    host = str(target.get("host") or "")
    port = int(target.get("port") or (443 if target.get("scheme") == "https" else 80))
    try:
        audit_log.append(audit_event("dns_resolution_started", {"host": host, "max_answers": request.limits.max_dns_answers}))
        addresses = resolver(host, port, request.limits.timeout_seconds, request.limits.max_dns_answers)
    except TimeoutError:
        errors.append({"code": "dns_resolution_failed", "message": "DNS resolution did not complete within the active probe limit."})
        blocked_reasons.append(blocked_reason("dns_resolution_failed"))
        audit_log.append(audit_event("dns_resolution_failed", {"reason": "timeout"}))
        return build_result(request, target, blocked_reasons, audit_log, errors, dns, None, network_requests_sent=0)
    except OSError:
        errors.append({"code": "dns_resolution_failed", "message": "DNS resolution failed before any HTTP request was sent."})
        blocked_reasons.append(blocked_reason("dns_resolution_failed"))
        audit_log.append(audit_event("dns_resolution_failed", {"reason": "resolver_error"}))
        return build_result(request, target, blocked_reasons, audit_log, errors, dns, None, network_requests_sent=0)

    unique_addresses = sorted(set(addresses))
    if len(unique_addresses) > request.limits.max_dns_answers:
        errors.append({"code": "dns_answers_limit_exceeded", "message": "DNS answers exceeded the active probe limit."})
        blocked_reasons.append(blocked_reason("dns_answers_limit_exceeded"))
        audit_log.append(audit_event("dns_answers_limit_exceeded", {"answers_count": len(unique_addresses)}))
        return build_result(request, target, blocked_reasons, audit_log, errors, dns, None, network_requests_sent=0)

    blocked_count = count_blocked_addresses(unique_addresses)
    dns = dns_summary(resolved=bool(unique_addresses), answers_count=len(unique_addresses), blocked_answers_count=blocked_count)
    audit_log.append(
        audit_event(
            "dns_resolution_completed",
            {
                "answers_count": dns["answers_count"],
                "all_answers_allowed": dns["all_answers_allowed"],
                "blocked_answers_count": dns["blocked_answers_count"],
            },
        )
    )
    if not unique_addresses:
        errors.append({"code": "dns_resolution_failed", "message": "DNS resolution returned no usable answers."})
        blocked_reasons.append(blocked_reason("dns_resolution_failed"))
        return build_result(request, target, blocked_reasons, audit_log, errors, dns, None, network_requests_sent=0)
    if blocked_count:
        blocked_reasons.append(blocked_reason("resolved_ip_blocked"))
        audit_log.append(audit_event("resolved_addresses_blocked", {"blocked_answers_count": blocked_count}))
        return build_result(request, target, blocked_reasons, audit_log, errors, dns, None, network_requests_sent=0)

    request_url = str(target.get("request_url") or target.get("normalized") or "")
    request_headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    audit_log.append(audit_event("http_head_request_started", {"method": "HEAD"}))
    try:
        response = head_request(request_url, request.limits.timeout_seconds, request_headers)
    except TimeoutError:
        errors.append({"code": "timeout", "message": "The HTTP HEAD request timed out."})
        audit_log.append(audit_event("http_head_request_error", {"code": "timeout"}))
        return build_result(request, target, blocked_reasons, audit_log, errors, dns, None, network_requests_sent=1)
    except OSError:
        errors.append({"code": "controlled_network_error", "message": "The HTTP HEAD request failed with a controlled network error."})
        audit_log.append(audit_event("http_head_request_error", {"code": "controlled_network_error"}))
        return build_result(request, target, blocked_reasons, audit_log, errors, dns, None, network_requests_sent=1)

    public_headers, redacted_count, truncated_count, headers_bytes = redact_and_bound_headers(
        response.headers,
        request.limits.max_response_header_bytes,
    )
    response_result = {
        "status_code": response.status_code,
        "headers": public_headers,
        "headers_bytes": headers_bytes,
        "body_read": False,
        "body_bytes_read": 0,
        "redirect_presented": 300 <= response.status_code < 400,
        "redirect_followed": False,
    }
    observations = build_observations(target, response_result)
    if response.status_code in {405, 501}:
        errors.append({"code": "head_not_allowed", "message": "The target did not allow HTTP HEAD. No GET fallback was attempted."})
    if response_result["redirect_presented"]:
        errors.append({"code": "redirect_not_followed", "message": "A redirect was returned and was not followed."})
    audit_log.append(
        audit_event(
            "response_headers_received",
            {
                "status_code": response.status_code,
                "headers_received_count": len(public_headers),
                "redacted_headers_count": redacted_count,
                "truncated_headers_count": truncated_count,
            },
        )
    )
    audit_log.append(audit_event("http_head_request_completed", {"network_requests_sent": 1}))

    result = build_result(request, target, blocked_reasons, audit_log, errors, dns, response_result, network_requests_sent=1)
    result["observations"] = observations
    result["summary"]["headers_received_count"] = len(public_headers)
    result["summary"]["redacted_headers_count"] = redacted_count
    result["summary"]["truncated_headers_count"] = truncated_count
    return result


def normalize_live_url_target(raw_target: str) -> tuple[dict[str, Any], list[dict[str, str]]]:
    raw = raw_target.strip()
    if not raw:
        return unknown_live_target(""), [blocked_reason("target_required")]
    if "://" not in raw:
        target, reasons = normalize_target(raw)
        if reasons:
            return target, reasons
        return unknown_live_target(redact_sensitive_text(raw)), [blocked_reason("live_url_required")]
    target, reasons = normalize_target(raw)
    if reasons:
        return target, reasons
    if target.get("type") != "url":
        return unknown_live_target(redact_sensitive_text(raw)), [blocked_reason("live_url_required")]
    normalized = str(target.get("normalized") or "")
    target = dict(target)
    target["request_url"] = request_url_from_raw(raw)
    target["normalized"] = normalized
    return target, []


def request_url_from_raw(raw: str) -> str:
    parsed = urlsplit(raw.strip())
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower().rstrip(".")
    port = parsed.port
    netloc = f"{host}:{port}" if port is not None else host
    path = parsed.path or "/"
    return urlunsplit((scheme, netloc, path, parsed.query, ""))


def unknown_live_target(raw: str) -> dict[str, Any]:
    return {
        "raw": raw,
        "normalized": None,
        "type": "unknown",
        "scheme": None,
        "host": None,
        "port": None,
        "path": None,
        "query_redacted": "",
        "classification": "rejected",
        "local_lab": False,
    }


def validate_mode_profile_and_limits(request: ActiveHttpHeaderProbeRequest) -> list[dict[str, str]]:
    reasons: list[dict[str, str]] = []
    if request.mode != LIVE_HEADER_PROBE_MODE:
        reasons.append(blocked_reason("live_header_probe_mode_required"))
    if request.profile.lower().startswith("nmap"):
        reasons.append(blocked_reason("nmap_not_allowed"))
    elif request.profile not in ALLOWED_HTTP_HEADER_PROBE_PROFILES:
        reasons.append(blocked_reason("unknown_profile"))
    if not request.limits.is_within_v0():
        reasons.append(blocked_reason("limits_exceed_http_header_probe"))
    return reasons


def default_resolver(host: str, port: int, timeout_seconds: int, max_answers: int) -> list[str]:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        return [str(address)]

    def resolve() -> list[str]:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        addresses: list[str] = []
        for info in infos:
            sockaddr = info[4]
            if sockaddr and sockaddr[0] not in addresses:
                addresses.append(sockaddr[0])
            if len(addresses) > max_answers:
                break
        return addresses

    executor = ThreadPoolExecutor(max_workers=1)
    future = executor.submit(resolve)
    try:
        return future.result(timeout=timeout_seconds)
    except FutureTimeoutError as exc:
        future.cancel()
        raise TimeoutError from exc
    finally:
        executor.shutdown(wait=False, cancel_futures=True)


def default_head_request(url: str, timeout_seconds: int, headers: dict[str, str]) -> HeadResponse:
    parsed = urlsplit(url)
    connection_cls = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
    port = parsed.port
    host = parsed.hostname or ""
    connection = connection_cls(host, port=port, timeout=timeout_seconds)
    path = urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
    try:
        connection.request("HEAD", path, headers=headers)
        response = connection.getresponse()
        return HeadResponse(status_code=response.status, headers=[(name, value) for name, value in response.getheaders()])
    finally:
        connection.close()


def count_blocked_addresses(addresses: list[str]) -> int:
    blocked = 0
    for value in addresses:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            blocked += 1
            continue
        if blocked_ip_reason(address):
            blocked += 1
    return blocked


def dns_summary(*, resolved: bool = False, answers_count: int = 0, blocked_answers_count: int = 0) -> dict[str, Any]:
    return {
        "resolved": resolved,
        "answers_count": answers_count,
        "all_answers_allowed": resolved and blocked_answers_count == 0,
        "blocked_answers_count": blocked_answers_count,
    }


def redact_and_bound_headers(headers: list[tuple[str, str]], max_bytes: int) -> tuple[list[dict[str, str]], int, int, int]:
    public_headers: list[dict[str, str]] = []
    redacted_count = 0
    truncated_count = 0
    headers_bytes = 0
    for name, value in headers:
        header_name = str(name)
        header_value = str(value)
        redacted_value, redacted = redact_header_value(header_name, header_value)
        if redacted:
            redacted_count += 1
        entry_bytes = len(header_name.encode("utf-8")) + len(redacted_value.encode("utf-8")) + 4
        if headers_bytes + entry_bytes > max_bytes:
            truncated_count += 1
            if headers_bytes >= max_bytes:
                continue
            redacted_value = "[TRUNCATED]"
            entry_bytes = len(header_name.encode("utf-8")) + len(redacted_value.encode("utf-8")) + 4
        headers_bytes += entry_bytes
        public_headers.append({"name": header_name, "value": redacted_value})
    return public_headers, redacted_count, truncated_count, headers_bytes


def redact_header_value(name: str, value: str) -> tuple[str, bool]:
    normalized = name.strip().lower()
    if normalized in SENSITIVE_HEADER_NAMES or "token" in normalized or "secret" in normalized or "password" in normalized:
        return REDACTED, True
    redacted = redact_sensitive_text(value)
    if normalized == "location":
        redacted = redact_url_for_display(value) if "://" in value else redact_sensitive_text(value)
    redacted = redact_bearer_basic(redacted)
    return redacted, redacted != value


def redact_bearer_basic(value: str) -> str:
    redacted = value
    for marker in ("Bearer ", "Basic "):
        index = redacted.lower().find(marker.lower())
        if index != -1:
            return REDACTED
    return redacted


def build_observations(target: dict[str, Any], response: dict[str, Any]) -> list[dict[str, Any]]:
    observations: list[dict[str, Any]] = []
    if target.get("scheme") == "http":
        observations.append(
            {
                "code": "http_scheme_used_hint",
                "level": "low",
                "title": "HTTP scheme used",
                "description": "The request used HTTP. Review whether HTTPS is expected for this target.",
            }
        )
    header_names = {str(header.get("name", "")).lower() for header in response.get("headers", []) if isinstance(header, dict)}
    if "server" in header_names:
        observations.append(
            {
                "code": "server_header_present_info",
                "level": "info",
                "title": "Server header present",
                "description": "A Server response header was present. Treat this as an observation for manual review.",
            }
        )
    if "set-cookie" in header_names:
        observations.append(
            {
                "code": "set_cookie_present_redacted_info",
                "level": "info",
                "title": "Set-Cookie header present",
                "description": "A Set-Cookie header was present and its value was redacted.",
            }
        )
    if response.get("redirect_presented"):
        observations.append(
            {
                "code": "redirect_present_not_followed_info",
                "level": "info",
                "title": "Redirect presented but not followed",
                "description": "The target returned a redirect. v0 records it but does not follow it.",
            }
        )
    return observations


def build_result(
    request: ActiveHttpHeaderProbeRequest,
    target: dict[str, Any],
    blocked_reasons: list[dict[str, str]],
    audit_log: list[dict[str, Any]],
    errors: list[dict[str, str]],
    dns: dict[str, Any],
    response: dict[str, Any] | None,
    *,
    network_requests_sent: int,
) -> ActiveHttpHeaderProbeResult:
    allowed = not blocked_reasons
    policy = {
        "allowed": allowed,
        "policy_version": HTTP_HEADER_PROBE_POLICY_VERSION,
        "blocked_reasons": blocked_reasons,
        "warnings": [],
    }
    request_url = target.get("normalized") if allowed else None
    return {
        "analyzer": "active_http_header_probe",
        "mode": LIVE_HEADER_PROBE_MODE,
        "profile": HTTP_HEADER_PROBE,
        "target": public_target(target),
        "authorization": request.authorization.to_result(),
        "policy": policy,
        "limits": request.limits.to_result(),
        "dns": dns,
        "request": {
            "method": "HEAD",
            "url": request_url,
            "headers_sent": {"User-Agent": USER_AGENT, "Accept": "*/*"} if allowed else {},
            "body_sent": False,
        },
        "response": response
        or {
            "status_code": None,
            "headers": [],
            "headers_bytes": 0,
            "body_read": False,
            "body_bytes_read": 0,
            "redirect_presented": False,
            "redirect_followed": False,
        },
        "observations": [],
        "findings": [],
        "audit_log": audit_log,
        "errors": errors,
        "blocked_reasons": blocked_reasons,
        "summary": {
            "network_requests_sent": network_requests_sent,
            "redirects_followed": 0,
            "body_bytes_read": 0,
            "headers_received_count": len(response.get("headers", [])) if response else 0,
            "redacted_headers_count": 0,
            "truncated_headers_count": 0,
            "blocked_reasons_count": len(blocked_reasons),
            "errors_count": len(errors),
        },
    }


def public_target(target: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in target.items()
        if key != "request_url"
    }
