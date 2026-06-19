from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from dataclasses import dataclass
import http.client
import ipaddress
import re
import socket
from typing import Any
from urllib.parse import urlsplit, urlunsplit


ACTIVE_HTTP_BASIC_HEADER_REVIEW_AUDIT_TYPE = "active_http_basic_header_review"
ACTIVE_HTTP_BASIC_HEADER_REVIEW_MODE = "live_http_basic_header_review"
ACTIVE_HTTP_BASIC_HEADER_REVIEW_PROFILE = "http_headers_single_request"
ACTIVE_HTTP_BASIC_HEADER_REVIEW_METHOD = "HEAD"
ACTIVE_HTTP_BASIC_HEADER_REVIEW_REDACTED_TARGET = "[REDACTED_TARGET]"
ACTIVE_HTTP_BASIC_HEADER_REVIEW_MAX_URL_LENGTH = 2048
ACTIVE_HTTP_BASIC_HEADER_REVIEW_TIMEOUT_SECONDS = 5.0
ACTIVE_HTTP_BASIC_HEADER_REVIEW_MAX_RESPONSE_HEADER_BYTES = 32_768
ACTIVE_HTTP_BASIC_HEADER_REVIEW_MAX_DNS_ANSWERS = 8
ACTIVE_HTTP_BASIC_HEADER_REVIEW_CAVEATS = [
    "No live HTTP request was performed",
    "No redirect was followed",
    "No response body was read",
    "Manual validation required",
    "HTTP header review indicator wording only",
]
ACTIVE_HTTP_BASIC_HEADER_REVIEW_LIVE_CAVEATS = [
    "One authorized HTTP HEAD request was attempted",
    "No redirect was followed",
    "No response body was read",
    "Manual validation required",
    "HTTP header review indicator wording only",
]

_ALLOWED_FIELDS = frozenset(
    {
        "mode",
        "profile",
        "target",
        "method",
        "authorization_confirmed",
        "target_control_confirmed",
        "delegated_permission_confirmed",
        "live_http_request_confirmed",
    }
)
_REQUIRED_CONTRACT_FIELDS = frozenset({"mode", "profile", "target", "method"})
_PUBLIC_REVIEW_LABEL = "HTTP header review indicator"
_NO_LIVE_JOB_STATUS_MEANING = "Completed job status means the no-live record was stored; no HTTP request was performed."
_LIVE_JOB_STATUS_MEANING = "Job status means a bounded live HEAD attempt reached a controlled terminal state; manual validation required."
_PERSISTABLE_RESULT_STATUSES = frozenset({"not_executed", "observed", "timed_out", "request_failed"})
_LIVE_RESULT_STATUSES = _PERSISTABLE_RESULT_STATUSES - {"not_executed"}
_IPV4ISH_RE = re.compile(r"^[0-9.]+$")
_IP_RANGE_RE = re.compile(r"^[0-9.]+-[0-9.]+$")
_CONTROL_PLANE_HOSTS = {"metadata.google.internal"}
_METADATA_IPS = {ipaddress.ip_address("169.254.169.254")}
_SECURITY_HEADER_NAMES = {
    "strict-transport-security": "hsts_present",
    "content-security-policy": "csp_present",
    "x-content-type-options": "x_content_type_options_present",
    "x-frame-options": "x_frame_options_present",
    "referrer-policy": "referrer_policy_present",
    "permissions-policy": "permissions_policy_present",
}
_FIXED_REQUEST_HEADERS = {"User-Agent": "Inspectra active-http-basic-header-review", "Accept": "*/*"}


@dataclass(frozen=True)
class ActiveHttpBasicHeaderReviewHeadResponse:
    status_code: int
    headers: list[tuple[str, str]]


ActiveHttpBasicHeaderReviewResolver = Callable[[str, int, float, int], list[str]]
ActiveHttpBasicHeaderReviewHeadTransport = Callable[
    [str, str, dict[str, str], float],
    ActiveHttpBasicHeaderReviewHeadResponse,
]


class ActiveHttpBasicHeaderReviewContractError(ValueError):
    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code
        self.message = message


def build_active_http_basic_header_review_response(
    payload: Any,
    *,
    enabled: bool,
    live_head_enabled: bool = False,
    resolver: ActiveHttpBasicHeaderReviewResolver | None = None,
    head_transport: ActiveHttpBasicHeaderReviewHeadTransport | None = None,
) -> dict[str, Any]:
    if not enabled:
        return _response("blocked_unconfigured", ["feature_disabled"])

    if not isinstance(payload, dict):
        raise ActiveHttpBasicHeaderReviewContractError(
            "invalid_json_body",
            "active_http_basic_header_review requires a JSON object body.",
        )

    _validate_contract_shape(payload)
    missing_approval = _missing_approval_reason(payload)
    if missing_approval is not None:
        return _response("blocked_missing_approval", [missing_approval])

    policy_reason = _target_policy_reason(payload["target"])
    if policy_reason is not None:
        return _response("blocked_by_policy", [policy_reason])

    if not live_head_enabled:
        return _response("not_executed", [])

    return _run_live_head_review(
        payload["target"],
        resolver=resolver or default_active_http_basic_header_review_resolver,
        head_transport=head_transport or default_active_http_basic_header_review_head_transport,
    )


def default_active_http_basic_header_review_resolver(
    host: str,
    port: int,
    timeout_seconds: float,
    max_answers: int,
) -> list[str]:
    try:
        return [str(ipaddress.ip_address(host))]
    except ValueError:
        pass

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


def default_active_http_basic_header_review_head_transport(
    method: str,
    url: str,
    headers: dict[str, str],
    timeout_seconds: float,
) -> ActiveHttpBasicHeaderReviewHeadResponse:
    parsed = urlsplit(url)
    connection_cls = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
    connection = connection_cls(parsed.hostname or "", port=parsed.port, timeout=timeout_seconds)
    path = urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
    try:
        connection.request(method, path, body=None, headers=headers)
        response = connection.getresponse()
        return ActiveHttpBasicHeaderReviewHeadResponse(
            status_code=response.status,
            headers=[(name, value) for name, value in response.getheaders()],
        )
    finally:
        connection.close()


def _run_live_head_review(
    target: str,
    *,
    resolver: ActiveHttpBasicHeaderReviewResolver,
    head_transport: ActiveHttpBasicHeaderReviewHeadTransport,
) -> dict[str, Any]:
    request_url = _request_url_from_target(target)
    guard = _resolve_target_guard(request_url, resolver)
    if guard["blocked"]:
        return _response("blocked_by_policy", [str(guard["reason_code"])])

    try:
        response = head_transport(
            ACTIVE_HTTP_BASIC_HEADER_REVIEW_METHOD,
            request_url,
            dict(_FIXED_REQUEST_HEADERS),
            ACTIVE_HTTP_BASIC_HEADER_REVIEW_TIMEOUT_SECONDS,
        )
    except TimeoutError:
        return _live_response(
            "timed_out",
            guard,
            response=None,
            reason_codes=["request_timed_out"],
            error_codes=["request_timed_out"],
        )
    except Exception:
        return _live_response(
            "request_failed",
            guard,
            response=None,
            reason_codes=["controlled_network_error"],
            error_codes=["controlled_network_error"],
        )

    return _live_response("observed", guard, response=response, reason_codes=[], error_codes=[])


def _request_url_from_target(target: str) -> str:
    parsed = urlsplit(target)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower().rstrip(".")
    path = parsed.path or "/"
    return urlunsplit((scheme, host, path, parsed.query, ""))


def _resolve_target_guard(
    request_url: str,
    resolver: ActiveHttpBasicHeaderReviewResolver,
) -> dict[str, Any]:
    parsed = urlsplit(request_url)
    host = (parsed.hostname or "").lower().rstrip(".")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    guard = {
        "checked": True,
        "resolved": False,
        "answers_count": 0,
        "blocked_answers_count": 0,
        "dns_queries_sent": 0,
        "blocked": False,
        "reason_code": None,
    }
    if host in _CONTROL_PLANE_HOSTS:
        guard.update({"blocked": True, "reason_code": "control_plane_host_blocked"})
        return guard

    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        try:
            addresses = resolver(
                host,
                port,
                ACTIVE_HTTP_BASIC_HEADER_REVIEW_TIMEOUT_SECONDS,
                ACTIVE_HTTP_BASIC_HEADER_REVIEW_MAX_DNS_ANSWERS,
            )
        except TimeoutError:
            guard.update({"blocked": True, "reason_code": "resolver_guard_failed", "dns_queries_sent": 1})
            return guard
        except Exception:
            guard.update({"blocked": True, "reason_code": "resolver_guard_failed", "dns_queries_sent": 1})
            return guard
        guard["dns_queries_sent"] = 1
    else:
        addresses = [str(address)]

    unique_addresses = sorted({str(address) for address in addresses})
    guard["answers_count"] = min(len(unique_addresses), ACTIVE_HTTP_BASIC_HEADER_REVIEW_MAX_DNS_ANSWERS)
    if not unique_addresses:
        guard.update({"blocked": True, "reason_code": "resolver_guard_failed"})
        return guard
    if len(unique_addresses) > ACTIVE_HTTP_BASIC_HEADER_REVIEW_MAX_DNS_ANSWERS:
        guard.update({"blocked": True, "reason_code": "resolver_answer_limit_exceeded"})
        return guard

    blocked_count = 0
    for value in unique_addresses:
        try:
            resolved_address = ipaddress.ip_address(value)
        except ValueError:
            blocked_count += 1
            continue
        if _blocked_ip_reason(resolved_address) is not None:
            blocked_count += 1
    guard["blocked_answers_count"] = blocked_count
    guard["resolved"] = True
    if blocked_count:
        guard.update({"blocked": True, "reason_code": "resolved_ip_blocked"})
    return guard


def _blocked_ip_reason(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
    if address in _METADATA_IPS:
        return "metadata_target_blocked"
    if address.is_unspecified:
        return "unspecified_address_blocked"
    if address.is_loopback:
        return "loopback_blocked"
    if address.is_link_local:
        return "link_local_blocked"
    if address.is_multicast:
        return "multicast_blocked"
    if address.version == 4 and str(address) == "255.255.255.255":
        return "broadcast_blocked"
    if address.is_private:
        return "private_range_blocked"
    return None


def active_http_basic_header_review_is_persistable(result: dict[str, Any]) -> bool:
    result_status = str(result.get("result_status") or result.get("status") or "")
    return result_status in _PERSISTABLE_RESULT_STATUSES


def active_http_basic_header_review_job_status(result: dict[str, Any]) -> str:
    if not active_http_basic_header_review_is_persistable(result):
        raise ValueError("active_http_basic_header_review can only persist accepted results.")
    result_status = str(result.get("result_status") or result.get("status") or "")
    if result_status in {"timed_out", "request_failed"}:
        return "failed"
    return "completed"


def build_active_http_basic_header_review_persisted_result(result: dict[str, Any]) -> dict[str, Any]:
    if not active_http_basic_header_review_is_persistable(result):
        raise ValueError("active_http_basic_header_review can only persist accepted results.")

    result_status = str(result.get("result_status") or result.get("status") or "")
    if result_status in _LIVE_RESULT_STATUSES:
        return _build_live_persisted_result(result, result_status)

    persisted = _response("not_executed", _safe_reason_codes(result.get("reason_codes")))
    persisted["lifecycle_state"] = "not_executed"
    persisted["surface_caveats"] = list(ACTIVE_HTTP_BASIC_HEADER_REVIEW_CAVEATS)
    _mark_persisted(persisted)
    return persisted


def _live_response(
    status: str,
    resolver_guard: dict[str, Any],
    *,
    response: ActiveHttpBasicHeaderReviewHeadResponse | None,
    reason_codes: list[str],
    error_codes: list[str],
) -> dict[str, Any]:
    bounded_headers, header_counts = _bound_response_headers(response.headers if response is not None else [])
    header_indicators = _build_header_indicators(bounded_headers)
    status_code = _safe_status_code(response.status_code if response is not None else None)
    response_summary = _response_summary(status_code, header_indicators)
    execution = {
        "live_request_performed": True,
        "network_requests_sent": 1,
        "requests_sent": 1,
        "http_requests_sent": 1,
        "dns_queries_sent": _safe_int(resolver_guard.get("dns_queries_sent"), default=0),
        "tls_handshake_attempted": False,
        "nmap_executed": False,
        "subprocess_invoked": False,
        "docker_invoked": False,
        "browser_side_request_performed": False,
        "redirect_followed": False,
        "body_read": False,
        "job_created": False,
        "storage_persisted": False,
    }
    return {
        "audit_type": ACTIVE_HTTP_BASIC_HEADER_REVIEW_AUDIT_TYPE,
        "capability": ACTIVE_HTTP_BASIC_HEADER_REVIEW_AUDIT_TYPE,
        "job_type": ACTIVE_HTTP_BASIC_HEADER_REVIEW_AUDIT_TYPE,
        "mode": ACTIVE_HTTP_BASIC_HEADER_REVIEW_MODE,
        "profile": ACTIVE_HTTP_BASIC_HEADER_REVIEW_PROFILE,
        "status": status,
        "result_status": status,
        "target": ACTIVE_HTTP_BASIC_HEADER_REVIEW_REDACTED_TARGET,
        "target_display": ACTIVE_HTTP_BASIC_HEADER_REVIEW_REDACTED_TARGET,
        "method": ACTIVE_HTTP_BASIC_HEADER_REVIEW_METHOD,
        "headers": [],
        "cookies": [],
        "redirect_chain": [],
        "findings": [],
        "reason_codes": reason_codes,
        "errors": [{"code": code} for code in error_codes],
        "warnings": [],
        "manual_validation_required": True,
        "review_wording": _PUBLIC_REVIEW_LABEL,
        "result_interpretation": _PUBLIC_REVIEW_LABEL,
        "lifecycle_state": status,
        "execution": execution,
        "resolver_guard": _public_resolver_guard(resolver_guard),
        "response": response_summary,
        "header_indicators": header_indicators,
        "limits": _limits(),
        "summary": {
            "status": status,
            "reason_codes": reason_codes,
            "manual_validation_required": True,
            "review_wording": _PUBLIC_REVIEW_LABEL,
            "result_interpretation": _PUBLIC_REVIEW_LABEL,
            "live_request_performed": True,
            "redirect_followed": False,
            "body_read": False,
            "job_created": False,
            "storage_persisted": False,
            "network_requests_sent": 1,
            "requests_sent": 1,
            "http_requests_sent": 1,
            "dns_queries_sent": execution["dns_queries_sent"],
            "status_code": status_code,
            "status_class": response_summary["status_class"],
            "redirect_present": response_summary["redirect_present"],
            "location_header_present": response_summary["location_header_present"],
            "headers_received_count": header_counts["headers_received_count"],
            "headers_processed_count": header_counts["headers_processed_count"],
            "redacted_headers_count": header_counts["redacted_headers_count"],
            "truncated_headers_count": header_counts["truncated_headers_count"],
            "header_bytes_processed": header_counts["header_bytes_processed"],
        },
        "surface_caveats": list(ACTIVE_HTTP_BASIC_HEADER_REVIEW_LIVE_CAVEATS),
    }


def _build_live_persisted_result(result: dict[str, Any], result_status: str) -> dict[str, Any]:
    execution = _safe_execution(result.get("execution"), live=True)
    summary = _safe_summary(result.get("summary"), result_status=result_status, execution=execution)
    response_summary = _public_response_summary(result.get("response"))
    header_indicators = _public_header_indicators(result.get("header_indicators"))
    persisted = {
        "audit_type": ACTIVE_HTTP_BASIC_HEADER_REVIEW_AUDIT_TYPE,
        "capability": ACTIVE_HTTP_BASIC_HEADER_REVIEW_AUDIT_TYPE,
        "job_type": ACTIVE_HTTP_BASIC_HEADER_REVIEW_AUDIT_TYPE,
        "mode": ACTIVE_HTTP_BASIC_HEADER_REVIEW_MODE,
        "profile": ACTIVE_HTTP_BASIC_HEADER_REVIEW_PROFILE,
        "status": result_status,
        "result_status": result_status,
        "lifecycle_state": result_status,
        "target": ACTIVE_HTTP_BASIC_HEADER_REVIEW_REDACTED_TARGET,
        "target_display": ACTIVE_HTTP_BASIC_HEADER_REVIEW_REDACTED_TARGET,
        "method": ACTIVE_HTTP_BASIC_HEADER_REVIEW_METHOD,
        "headers": [],
        "cookies": [],
        "redirect_chain": [],
        "findings": [],
        "reason_codes": _safe_reason_codes(result.get("reason_codes")),
        "errors": _safe_errors(result.get("errors")),
        "warnings": [],
        "manual_validation_required": True,
        "review_wording": _PUBLIC_REVIEW_LABEL,
        "result_interpretation": _PUBLIC_REVIEW_LABEL,
        "execution": execution,
        "resolver_guard": _public_resolver_guard(result.get("resolver_guard")),
        "response": response_summary,
        "header_indicators": header_indicators,
        "limits": _limits(),
        "summary": summary,
        "surface_caveats": list(ACTIVE_HTTP_BASIC_HEADER_REVIEW_LIVE_CAVEATS),
    }
    _mark_persisted(persisted)
    return persisted


def _bound_response_headers(headers: list[tuple[str, str]]) -> tuple[list[tuple[str, str]], dict[str, int]]:
    bounded: list[tuple[str, str]] = []
    processed_bytes = 0
    truncated_count = 0
    redacted_count = 0
    for name, value in headers:
        header_name = str(name)
        header_value = str(value)
        header_bytes = len(header_name.encode("utf-8")) + len(header_value.encode("utf-8")) + 4
        if processed_bytes + header_bytes > ACTIVE_HTTP_BASIC_HEADER_REVIEW_MAX_RESPONSE_HEADER_BYTES:
            truncated_count += 1
            continue
        processed_bytes += header_bytes
        if _is_sensitive_header_name(header_name):
            redacted_count += 1
        bounded.append((header_name, header_value))
    return bounded, {
        "headers_received_count": len(headers),
        "headers_processed_count": len(bounded),
        "redacted_headers_count": redacted_count,
        "truncated_headers_count": truncated_count,
        "header_bytes_processed": processed_bytes,
    }


def _build_header_indicators(headers: list[tuple[str, str]]) -> dict[str, Any]:
    indicators: dict[str, Any] = {value: False for value in _SECURITY_HEADER_NAMES.values()}
    normalized_headers = [(name.strip().lower(), value) for name, value in headers]
    for name, _value in normalized_headers:
        indicator_name = _SECURITY_HEADER_NAMES.get(name)
        if indicator_name:
            indicators[indicator_name] = True
    set_cookie_values = [value for name, value in normalized_headers if name == "set-cookie"]
    cookie_count = min(len(set_cookie_values), 8)
    cookie_values = set_cookie_values[:8]
    indicators.update(
        {
            "server_header_present": any(name == "server" for name, _value in normalized_headers),
            "server_header_value_redacted": any(name == "server" for name, _value in normalized_headers),
            "set_cookie_present": bool(set_cookie_values),
            "set_cookie_count": cookie_count,
            "set_cookie_count_truncated": len(set_cookie_values) > cookie_count,
            "set_cookie_secure_attribute_present": any(_cookie_has_attribute(value, "secure") for value in cookie_values),
            "set_cookie_httponly_attribute_present": any(_cookie_has_attribute(value, "httponly") for value in cookie_values),
            "set_cookie_samesite_attribute_present": any("samesite=" in value.lower() for value in cookie_values),
            "location_header_present": any(name == "location" for name, _value in normalized_headers),
        }
    )
    return indicators


def _cookie_has_attribute(value: str, attribute: str) -> bool:
    return any(part.strip().lower() == attribute for part in value.split(";"))


def _is_sensitive_header_name(name: str) -> bool:
    normalized = name.strip().lower()
    return (
        normalized in {"set-cookie", "cookie", "authorization", "proxy-authorization", "x-api-key", "api-key"}
        or "token" in normalized
        or "secret" in normalized
        or "password" in normalized
    )


def _response_summary(status_code: int | None, header_indicators: dict[str, Any]) -> dict[str, Any]:
    redirect_present = status_code is not None and 300 <= status_code < 400
    return {
        "status_code": status_code,
        "status_class": _status_class(status_code),
        "redirect_present": redirect_present,
        "location_header_present": bool(header_indicators.get("location_header_present")),
        "redirect_followed": False,
        "body_read": False,
        "body_bytes_read": 0,
    }


def _public_response_summary(value: Any) -> dict[str, Any]:
    response = value if isinstance(value, dict) else {}
    status_code = _safe_status_code(response.get("status_code"))
    return {
        "status_code": status_code,
        "status_class": _status_class(status_code),
        "redirect_present": bool(response.get("redirect_present")),
        "location_header_present": bool(response.get("location_header_present")),
        "redirect_followed": False,
        "body_read": False,
        "body_bytes_read": 0,
    }


def _public_header_indicators(value: Any) -> dict[str, Any]:
    indicators = value if isinstance(value, dict) else {}
    public = {indicator: bool(indicators.get(indicator)) for indicator in _SECURITY_HEADER_NAMES.values()}
    public.update(
        {
            "server_header_present": bool(indicators.get("server_header_present")),
            "server_header_value_redacted": bool(indicators.get("server_header_present")),
            "set_cookie_present": bool(indicators.get("set_cookie_present")),
            "set_cookie_count": min(_safe_int(indicators.get("set_cookie_count"), default=0), 8),
            "set_cookie_count_truncated": bool(indicators.get("set_cookie_count_truncated")),
            "set_cookie_secure_attribute_present": bool(indicators.get("set_cookie_secure_attribute_present")),
            "set_cookie_httponly_attribute_present": bool(indicators.get("set_cookie_httponly_attribute_present")),
            "set_cookie_samesite_attribute_present": bool(indicators.get("set_cookie_samesite_attribute_present")),
            "location_header_present": bool(indicators.get("location_header_present")),
        }
    )
    return public


def _public_resolver_guard(value: Any) -> dict[str, Any]:
    guard = value if isinstance(value, dict) else {}
    return {
        "checked": bool(guard.get("checked")),
        "resolved": bool(guard.get("resolved")),
        "answers_count": min(_safe_int(guard.get("answers_count"), default=0), ACTIVE_HTTP_BASIC_HEADER_REVIEW_MAX_DNS_ANSWERS),
        "blocked_answers_count": min(
            _safe_int(guard.get("blocked_answers_count"), default=0),
            ACTIVE_HTTP_BASIC_HEADER_REVIEW_MAX_DNS_ANSWERS,
        ),
        "dns_queries_sent": min(_safe_int(guard.get("dns_queries_sent"), default=0), 1),
        "blocked": bool(guard.get("blocked")),
        "reason_code": _safe_reason_code(guard.get("reason_code")),
    }


def _safe_execution(value: Any, *, live: bool) -> dict[str, Any]:
    execution = value if isinstance(value, dict) else {}
    requests_sent = 1 if live and _safe_int(execution.get("requests_sent"), default=1) > 0 else 0
    return {
        "live_request_performed": bool(live and execution.get("live_request_performed", True)),
        "network_requests_sent": requests_sent,
        "requests_sent": requests_sent,
        "http_requests_sent": requests_sent,
        "dns_queries_sent": min(_safe_int(execution.get("dns_queries_sent"), default=0), 1),
        "tls_handshake_attempted": False,
        "nmap_executed": False,
        "subprocess_invoked": False,
        "docker_invoked": False,
        "browser_side_request_performed": False,
        "redirect_followed": False,
        "body_read": False,
        "job_created": bool(execution.get("job_created", False)),
        "storage_persisted": bool(execution.get("storage_persisted", False)),
    }


def _safe_summary(value: Any, *, result_status: str, execution: dict[str, Any]) -> dict[str, Any]:
    summary = value if isinstance(value, dict) else {}
    return {
        "status": result_status,
        "reason_codes": _safe_reason_codes(summary.get("reason_codes")),
        "manual_validation_required": True,
        "review_wording": _PUBLIC_REVIEW_LABEL,
        "result_interpretation": _PUBLIC_REVIEW_LABEL,
        "live_request_performed": bool(execution.get("live_request_performed")),
        "redirect_followed": False,
        "body_read": False,
        "job_created": bool(execution.get("job_created")),
        "storage_persisted": bool(execution.get("storage_persisted")),
        "network_requests_sent": _safe_int(execution.get("network_requests_sent"), default=0),
        "requests_sent": _safe_int(execution.get("requests_sent"), default=0),
        "http_requests_sent": _safe_int(execution.get("http_requests_sent"), default=0),
        "dns_queries_sent": _safe_int(execution.get("dns_queries_sent"), default=0),
        "status_code": _safe_status_code(summary.get("status_code")),
        "status_class": _status_class(_safe_status_code(summary.get("status_code"))),
        "redirect_present": bool(summary.get("redirect_present")),
        "location_header_present": bool(summary.get("location_header_present")),
        "headers_received_count": _safe_int(summary.get("headers_received_count"), default=0),
        "headers_processed_count": _safe_int(summary.get("headers_processed_count"), default=0),
        "redacted_headers_count": _safe_int(summary.get("redacted_headers_count"), default=0),
        "truncated_headers_count": _safe_int(summary.get("truncated_headers_count"), default=0),
        "header_bytes_processed": min(
            _safe_int(summary.get("header_bytes_processed"), default=0),
            ACTIVE_HTTP_BASIC_HEADER_REVIEW_MAX_RESPONSE_HEADER_BYTES,
        ),
    }


def _limits() -> dict[str, Any]:
    return {
        "max_targets": 1,
        "max_url_length": ACTIVE_HTTP_BASIC_HEADER_REVIEW_MAX_URL_LENGTH,
        "method": ACTIVE_HTTP_BASIC_HEADER_REVIEW_METHOD,
        "max_redirects": 0,
        "timeout_seconds": ACTIVE_HTTP_BASIC_HEADER_REVIEW_TIMEOUT_SECONDS,
        "max_response_header_bytes": ACTIVE_HTTP_BASIC_HEADER_REVIEW_MAX_RESPONSE_HEADER_BYTES,
        "max_dns_answers": ACTIVE_HTTP_BASIC_HEADER_REVIEW_MAX_DNS_ANSWERS,
        "response_body_bytes": 0,
        "raw_target_persisted": False,
        "headers_persisted": False,
        "cookies_persisted": False,
        "response_body_persisted": False,
    }


def _safe_errors(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list):
        return []
    errors = []
    for item in value[:8]:
        if not isinstance(item, dict):
            continue
        code = _safe_reason_code(item.get("code"))
        if code:
            errors.append({"code": code})
    return errors


def _safe_reason_code(value: Any) -> str | None:
    if isinstance(value, str) and re.fullmatch(r"[a-z0-9_]{1,64}", value):
        return value
    return None


def _safe_int(value: Any, *, default: int) -> int:
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return max(value, 0)
    return default


def _safe_status_code(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    if 100 <= value <= 599:
        return value
    return None


def _status_class(status_code: int | None) -> str | None:
    if status_code is None:
        return None
    return f"{status_code // 100}xx"


def _validate_contract_shape(payload: dict[str, Any]) -> None:
    extra_fields = sorted(set(payload) - _ALLOWED_FIELDS)
    if extra_fields:
        raise ActiveHttpBasicHeaderReviewContractError(
            "unsupported_field",
            "active_http_basic_header_review does not accept extra request fields.",
        )

    missing_fields = sorted(_REQUIRED_CONTRACT_FIELDS - set(payload))
    if missing_fields:
        raise ActiveHttpBasicHeaderReviewContractError(
            "missing_required_field",
            "active_http_basic_header_review is missing a required request field.",
        )

    if payload.get("mode") != ACTIVE_HTTP_BASIC_HEADER_REVIEW_MODE:
        raise ActiveHttpBasicHeaderReviewContractError(
            "unsupported_mode",
            "active_http_basic_header_review mode is not supported.",
        )
    if payload.get("profile") != ACTIVE_HTTP_BASIC_HEADER_REVIEW_PROFILE:
        raise ActiveHttpBasicHeaderReviewContractError(
            "unsupported_profile",
            "active_http_basic_header_review profile is not supported.",
        )
    if payload.get("method") != ACTIVE_HTTP_BASIC_HEADER_REVIEW_METHOD:
        raise ActiveHttpBasicHeaderReviewContractError(
            "unsupported_method",
            "active_http_basic_header_review method is not supported.",
        )
    if not isinstance(payload.get("target"), str):
        raise ActiveHttpBasicHeaderReviewContractError(
            "invalid_target",
            "active_http_basic_header_review target must be a URL string.",
        )


def _missing_approval_reason(payload: dict[str, Any]) -> str | None:
    if payload.get("authorization_confirmed") is not True:
        return "authorization_missing"
    has_target_permission = (
        payload.get("target_control_confirmed") is True
        or payload.get("delegated_permission_confirmed") is True
    )
    if not has_target_permission:
        return "target_permission_missing"
    if payload.get("live_http_request_confirmed") is not True:
        return "live_http_request_missing"
    return None


def _target_policy_reason(target: str) -> str | None:
    if not target:
        return "url_required"
    if len(target) > ACTIVE_HTTP_BASIC_HEADER_REVIEW_MAX_URL_LENGTH:
        return "url_too_long"
    if target.strip() != target or any(ch in target for ch in "\r\n\t ,"):
        return "pasted_list_rejected"
    if "*" in target:
        return "wildcard_rejected"

    lowered = target.lower()
    if "://" not in target:
        return "url_required"
    if not (lowered.startswith("http://") or lowered.startswith("https://")):
        return "unsupported_scheme"

    _, remainder = target.split("://", 1)
    authority, suffix = _split_authority(remainder)
    if not authority:
        return "host_required"
    if "@" in authority:
        return "url_credentials_rejected"
    if "[" in authority or "]" in authority:
        return "unsupported_host"
    if ":" in authority:
        return "custom_port_rejected"

    host = authority.rstrip(".").lower()
    if not host:
        return "host_required"
    if _IP_RANGE_RE.fullmatch(host):
        return "ip_range_rejected"
    if "#" in suffix:
        return "fragment_rejected"

    path = _path_from_suffix(suffix)
    if path not in ("", "/"):
        if _IPV4ISH_RE.fullmatch(host) and re.fullmatch(r"/\d{1,2}", path):
            return "cidr_rejected"
        return "path_not_allowed"

    return None


def _split_authority(remainder: str) -> tuple[str, str]:
    cut_points = [
        idx
        for idx in (remainder.find("/"), remainder.find("?"), remainder.find("#"))
        if idx >= 0
    ]
    if not cut_points:
        return remainder, ""
    cut = min(cut_points)
    return remainder[:cut], remainder[cut:]


def _path_from_suffix(suffix: str) -> str:
    if not suffix or suffix.startswith("?"):
        return ""
    if not suffix.startswith("/"):
        return suffix
    query_index = suffix.find("?")
    if query_index < 0:
        return suffix
    return suffix[:query_index]


def _safe_reason_codes(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    safe_codes = []
    for item in value:
        if not isinstance(item, str):
            continue
        if re.fullmatch(r"[a-z0-9_]{1,64}", item):
            safe_codes.append(item)
    return safe_codes[:8]


def _response(status: str, reason_codes: list[str]) -> dict[str, Any]:
    execution = {
        "live_request_performed": False,
        "network_requests_sent": 0,
        "requests_sent": 0,
        "http_requests_sent": 0,
        "dns_queries_sent": 0,
        "tls_handshake_attempted": False,
        "nmap_executed": False,
        "subprocess_invoked": False,
        "docker_invoked": False,
        "browser_side_request_performed": False,
        "redirect_followed": False,
        "body_read": False,
        "job_created": False,
        "storage_persisted": False,
    }
    return {
        "audit_type": ACTIVE_HTTP_BASIC_HEADER_REVIEW_AUDIT_TYPE,
        "capability": ACTIVE_HTTP_BASIC_HEADER_REVIEW_AUDIT_TYPE,
        "job_type": ACTIVE_HTTP_BASIC_HEADER_REVIEW_AUDIT_TYPE,
        "mode": ACTIVE_HTTP_BASIC_HEADER_REVIEW_MODE,
        "profile": ACTIVE_HTTP_BASIC_HEADER_REVIEW_PROFILE,
        "status": status,
        "result_status": status,
        "target": ACTIVE_HTTP_BASIC_HEADER_REVIEW_REDACTED_TARGET,
        "target_display": ACTIVE_HTTP_BASIC_HEADER_REVIEW_REDACTED_TARGET,
        "method": ACTIVE_HTTP_BASIC_HEADER_REVIEW_METHOD,
        "headers": [],
        "cookies": [],
        "redirect_chain": [],
        "findings": [],
        "reason_codes": reason_codes,
        "errors": [{"code": code} for code in reason_codes],
        "warnings": [],
        "manual_validation_required": True,
        "review_wording": _PUBLIC_REVIEW_LABEL,
        "result_interpretation": _PUBLIC_REVIEW_LABEL,
        "lifecycle_state": status,
        "execution": execution,
        "limits": _limits(),
        "summary": {
            "status": status,
            "reason_codes": reason_codes,
            "manual_validation_required": True,
            "review_wording": _PUBLIC_REVIEW_LABEL,
            "result_interpretation": _PUBLIC_REVIEW_LABEL,
            "live_request_performed": False,
            "redirect_followed": False,
            "body_read": False,
            "job_created": False,
            "storage_persisted": False,
            "network_requests_sent": 0,
            "requests_sent": 0,
            "http_requests_sent": 0,
        },
        "surface_caveats": list(ACTIVE_HTTP_BASIC_HEADER_REVIEW_CAVEATS),
    }


def _mark_persisted(result: dict[str, Any]) -> None:
    execution = result.get("execution")
    if not isinstance(execution, dict):
        execution = {}
        result["execution"] = execution
    summary = result.get("summary")
    if not isinstance(summary, dict):
        summary = {}
        result["summary"] = summary

    result_status = str(result.get("result_status") or result.get("status") or "not_executed")
    live = result_status in _LIVE_RESULT_STATUSES
    requests_sent = 1 if live and _safe_int(execution.get("requests_sent"), default=1) > 0 else 0
    job_status_meaning = _LIVE_JOB_STATUS_MEANING if live else _NO_LIVE_JOB_STATUS_MEANING

    execution["job_created"] = True
    execution["storage_persisted"] = True
    execution["live_request_performed"] = live
    execution["redirect_followed"] = False
    execution["body_read"] = False
    execution["network_requests_sent"] = requests_sent
    execution["requests_sent"] = requests_sent
    execution["http_requests_sent"] = requests_sent
    summary["job_created"] = True
    summary["storage_persisted"] = True
    result["job_status_meaning"] = job_status_meaning
    summary["job_status_meaning"] = job_status_meaning
    summary["live_request_performed"] = live
    summary["redirect_followed"] = False
    summary["body_read"] = False
    summary["network_requests_sent"] = requests_sent
    summary["requests_sent"] = requests_sent
    summary["http_requests_sent"] = requests_sent
