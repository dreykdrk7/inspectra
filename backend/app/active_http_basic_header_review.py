from __future__ import annotations

import re
from typing import Any


ACTIVE_HTTP_BASIC_HEADER_REVIEW_AUDIT_TYPE = "active_http_basic_header_review"
ACTIVE_HTTP_BASIC_HEADER_REVIEW_MODE = "live_http_basic_header_review"
ACTIVE_HTTP_BASIC_HEADER_REVIEW_PROFILE = "http_headers_single_request"
ACTIVE_HTTP_BASIC_HEADER_REVIEW_METHOD = "HEAD"
ACTIVE_HTTP_BASIC_HEADER_REVIEW_REDACTED_TARGET = "[REDACTED_TARGET]"
ACTIVE_HTTP_BASIC_HEADER_REVIEW_MAX_URL_LENGTH = 2048
ACTIVE_HTTP_BASIC_HEADER_REVIEW_CAVEATS = [
    "No live HTTP request was performed",
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
_JOB_STATUS_MEANING = "Completed job status means the no-live record was stored; no HTTP request was performed."
_IPV4ISH_RE = re.compile(r"^[0-9.]+$")
_IP_RANGE_RE = re.compile(r"^[0-9.]+-[0-9.]+$")


class ActiveHttpBasicHeaderReviewContractError(ValueError):
    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code
        self.message = message


def build_active_http_basic_header_review_response(
    payload: Any,
    *,
    enabled: bool,
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

    return _response("not_executed", [])


def active_http_basic_header_review_is_persistable(result: dict[str, Any]) -> bool:
    return result.get("status") == "not_executed" and result.get("result_status") == "not_executed"


def active_http_basic_header_review_job_status(result: dict[str, Any]) -> str:
    if not active_http_basic_header_review_is_persistable(result):
        raise ValueError("active_http_basic_header_review can only persist accepted no-live results.")
    return "completed"


def build_active_http_basic_header_review_persisted_result(result: dict[str, Any]) -> dict[str, Any]:
    if not active_http_basic_header_review_is_persistable(result):
        raise ValueError("active_http_basic_header_review can only persist accepted no-live results.")

    persisted = _response("not_executed", _safe_reason_codes(result.get("reason_codes")))
    persisted["lifecycle_state"] = "not_executed"
    persisted["surface_caveats"] = list(ACTIVE_HTTP_BASIC_HEADER_REVIEW_CAVEATS)
    _mark_persisted(persisted)
    return persisted


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
        "limits": {
            "max_targets": 1,
            "max_url_length": ACTIVE_HTTP_BASIC_HEADER_REVIEW_MAX_URL_LENGTH,
            "method": ACTIVE_HTTP_BASIC_HEADER_REVIEW_METHOD,
            "max_redirects": 0,
            "response_body_bytes": 0,
            "raw_target_persisted": False,
            "headers_persisted": False,
            "cookies_persisted": False,
            "response_body_persisted": False,
        },
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

    execution["job_created"] = True
    execution["storage_persisted"] = True
    execution["live_request_performed"] = False
    execution["redirect_followed"] = False
    execution["body_read"] = False
    execution["network_requests_sent"] = 0
    execution["requests_sent"] = 0
    execution["http_requests_sent"] = 0
    summary["job_created"] = True
    summary["storage_persisted"] = True
    result["job_status_meaning"] = _JOB_STATUS_MEANING
    summary["job_status_meaning"] = _JOB_STATUS_MEANING
    summary["live_request_performed"] = False
    summary["redirect_followed"] = False
    summary["body_read"] = False
    summary["network_requests_sent"] = 0
    summary["requests_sent"] = 0
    summary["http_requests_sent"] = 0
