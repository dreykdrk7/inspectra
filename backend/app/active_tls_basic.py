from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress
import math
import socket
import ssl
from typing import Any, Callable


ACTIVE_TLS_BASIC_AUDIT_TYPE = "active_tls_basic"
ACTIVE_TLS_BASIC_CAPABILITY = "active_tls_basic"
ACTIVE_TLS_BASIC_MODE = "live_tls_basic"
ACTIVE_TLS_BASIC_PROFILE = "tls_handshake_summary"
ACTIVE_TLS_BASIC_REDACTED_TARGET = "[REDACTED_TARGET]"
ACTIVE_TLS_BASIC_RESULT_INTERPRETATION = "tls_configuration_review_indicator"
ACTIVE_TLS_BASIC_MAX_TEXT_LENGTH = 160
ACTIVE_TLS_BASIC_MAX_SAN_SAMPLE = 3
ACTIVE_TLS_BASIC_DEFAULT_TIMEOUT_SECONDS = 3.0


@dataclass(frozen=True)
class ActiveTlsBasicRequest:
    target: str
    port: int
    timeout_seconds: float = ACTIVE_TLS_BASIC_DEFAULT_TIMEOUT_SECONDS


@dataclass(frozen=True)
class ActiveTlsBasicConnectionSnapshot:
    protocol: str | None = None
    cipher: str | tuple[Any, ...] | None = None
    certificate: dict[str, Any] | None = None


ActiveTlsBasicConnector = Callable[[ActiveTlsBasicRequest], ActiveTlsBasicConnectionSnapshot | dict[str, Any]]


def run_active_tls_basic(
    request: ActiveTlsBasicRequest,
    *,
    connector: ActiveTlsBasicConnector | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    current_time = now or datetime.now(timezone.utc)
    try:
        snapshot = _coerce_snapshot((connector or _perform_tls_handshake)(request))
    except (socket.timeout, TimeoutError):
        return _controlled_error_result(request, "timed_out", "timeout")
    except ssl.SSLCertVerificationError:
        return _controlled_error_result(request, "tls_error_controlled", "certificate_verification_failed")
    except ssl.SSLError:
        return _controlled_error_result(request, "tls_error_controlled", "tls_handshake_error")
    except (ConnectionRefusedError, OSError):
        return _controlled_error_result(request, "handshake_failed", "connection_failed")
    except Exception:
        return _controlled_error_result(request, "tls_error_controlled", "unexpected_tls_error")

    certificate = _public_certificate(snapshot.certificate, request.target, now=current_time)
    result_status = "handshake_succeeded" if certificate.get("available") else "certificate_unavailable"
    reason_codes = [] if result_status == "handshake_succeeded" else ["certificate_unavailable"]
    return _base_result(
        request,
        result_status=result_status,
        handshake={
            "status": "succeeded",
            "protocol": _bounded_text(snapshot.protocol, request.target),
            "cipher": _bounded_text(_cipher_name(snapshot.cipher), request.target),
        },
        certificate=certificate,
        reason_codes=reason_codes,
    )


def active_tls_basic_job_status(result: dict[str, Any]) -> str:
    return "completed" if result.get("result_status") == "handshake_succeeded" else "failed"


def active_tls_basic_job_error(result: dict[str, Any]) -> str | None:
    if active_tls_basic_job_status(result) == "completed":
        return None
    reason_codes = result.get("reason_codes")
    if isinstance(reason_codes, list) and reason_codes:
        return str(reason_codes[0])
    return str(result.get("result_status") or "tls_error_controlled")


def _perform_tls_handshake(request: ActiveTlsBasicRequest) -> ActiveTlsBasicConnectionSnapshot:
    timeout = _bounded_timeout(request.timeout_seconds)
    server_hostname = None if _is_ip_address(request.target) else request.target
    context = ssl.create_default_context()
    with socket.create_connection((request.target, request.port), timeout=timeout) as tcp_socket:
        tcp_socket.settimeout(timeout)
        with context.wrap_socket(tcp_socket, server_hostname=server_hostname) as tls_socket:
            tls_socket.settimeout(timeout)
            return ActiveTlsBasicConnectionSnapshot(
                protocol=tls_socket.version(),
                cipher=tls_socket.cipher(),
                certificate=tls_socket.getpeercert() or None,
            )


def _coerce_snapshot(snapshot: ActiveTlsBasicConnectionSnapshot | dict[str, Any]) -> ActiveTlsBasicConnectionSnapshot:
    if isinstance(snapshot, ActiveTlsBasicConnectionSnapshot):
        return snapshot
    if isinstance(snapshot, dict):
        return ActiveTlsBasicConnectionSnapshot(
            protocol=snapshot.get("protocol"),
            cipher=snapshot.get("cipher"),
            certificate=snapshot.get("certificate") if isinstance(snapshot.get("certificate"), dict) else None,
        )
    return ActiveTlsBasicConnectionSnapshot()


def _controlled_error_result(request: ActiveTlsBasicRequest, result_status: str, reason_code: str) -> dict[str, Any]:
    return _base_result(
        request,
        result_status=result_status,
        handshake={"status": result_status, "protocol": None, "cipher": None},
        certificate={"available": False, "subject": None, "issuer": None, "san_count": 0, "san_sample": [], "not_before": None, "not_after": None, "days_until_expiry": None},
        reason_codes=[reason_code],
    )


def _base_result(
    request: ActiveTlsBasicRequest,
    *,
    result_status: str,
    handshake: dict[str, Any],
    certificate: dict[str, Any],
    reason_codes: list[str],
) -> dict[str, Any]:
    return {
        "audit_type": ACTIVE_TLS_BASIC_AUDIT_TYPE,
        "capability": ACTIVE_TLS_BASIC_CAPABILITY,
        "mode": ACTIVE_TLS_BASIC_MODE,
        "profile": ACTIVE_TLS_BASIC_PROFILE,
        "status": result_status,
        "result_status": result_status,
        "target": ACTIVE_TLS_BASIC_REDACTED_TARGET,
        "port": request.port,
        "handshake": handshake,
        "certificate": certificate,
        "summary": {
            "manual_validation_required": True,
            "result_interpretation": ACTIVE_TLS_BASIC_RESULT_INTERPRETATION,
            "certificate_available": bool(certificate.get("available")),
            "san_count": certificate.get("san_count", 0),
            "reason_codes": list(reason_codes),
        },
        "execution": {
            "tls_handshake_attempted": True,
            "network_requests_sent": 1,
            "http_requests_sent": 0,
            "target_expansion_performed": False,
            "dns_expansion_performed": False,
            "crawling_performed": False,
            "credential_validation_performed": False,
        },
        "manual_validation_required": True,
        "result_interpretation": ACTIVE_TLS_BASIC_RESULT_INTERPRETATION,
        "reason_codes": list(reason_codes),
        "errors": [{"code": code} for code in reason_codes],
        "warnings": [],
        "limits": {
            "connect_timeout_seconds": _bounded_timeout(request.timeout_seconds),
            "handshake_timeout_seconds": _bounded_timeout(request.timeout_seconds),
            "max_san_sample": ACTIVE_TLS_BASIC_MAX_SAN_SAMPLE,
            "max_text_length": ACTIVE_TLS_BASIC_MAX_TEXT_LENGTH,
            "raw_certificate_persisted": False,
            "raw_target_persisted": False,
        },
    }


def _public_certificate(certificate: dict[str, Any] | None, target: str, *, now: datetime) -> dict[str, Any]:
    if not certificate:
        return {
            "available": False,
            "subject": None,
            "issuer": None,
            "san_count": 0,
            "san_sample": [],
            "not_before": None,
            "not_after": None,
            "days_until_expiry": None,
        }

    not_before = _parse_cert_time(certificate.get("notBefore"))
    not_after = _parse_cert_time(certificate.get("notAfter"))
    san_values = _subject_alt_names(certificate.get("subjectAltName"))
    return {
        "available": True,
        "subject": _bounded_text(_name_tuple_to_text(certificate.get("subject")), target),
        "issuer": _bounded_text(_name_tuple_to_text(certificate.get("issuer")), target),
        "san_count": len(san_values),
        "san_sample": [
            {"type": _bounded_text(item_type, target, max_length=24), "value": "[REDACTED_SAN]"}
            for item_type, _item_value in san_values[:ACTIVE_TLS_BASIC_MAX_SAN_SAMPLE]
        ],
        "not_before": _format_dt(not_before),
        "not_after": _format_dt(not_after),
        "days_until_expiry": _days_until_expiry(not_after, now),
    }


def _subject_alt_names(value: Any) -> list[tuple[str, str]]:
    if not isinstance(value, (list, tuple)):
        return []
    names: list[tuple[str, str]] = []
    for item in value:
        if isinstance(item, (list, tuple)) and len(item) >= 2:
            names.append((str(item[0]), str(item[1])))
    return names


def _name_tuple_to_text(value: Any) -> str | None:
    if not isinstance(value, (list, tuple)):
        return None
    parts: list[str] = []
    for group in value:
        if not isinstance(group, (list, tuple)):
            continue
        for pair in group:
            if isinstance(pair, (list, tuple)) and len(pair) >= 2:
                parts.append(f"{pair[0]}={pair[1]}")
    return ", ".join(parts) if parts else None


def _parse_cert_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return datetime.fromtimestamp(ssl.cert_time_to_seconds(value), tz=timezone.utc)
    except (OSError, ValueError):
        return None


def _format_dt(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _days_until_expiry(not_after: datetime | None, now: datetime) -> int | None:
    if not_after is None:
        return None
    remaining_seconds = (not_after.astimezone(timezone.utc) - now.astimezone(timezone.utc)).total_seconds()
    return math.floor(remaining_seconds / 86400)


def _cipher_name(value: str | tuple[Any, ...] | None) -> str | None:
    if isinstance(value, tuple) and value:
        return str(value[0])
    if isinstance(value, str):
        return value
    return None


def _bounded_text(value: Any, target: str, *, max_length: int = ACTIVE_TLS_BASIC_MAX_TEXT_LENGTH) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    for token in {target, target.strip().lower()}:
        if token:
            text = text.replace(token, ACTIVE_TLS_BASIC_REDACTED_TARGET)
    if len(text) > max_length:
        return text[: max_length - 3] + "..."
    return text


def _bounded_timeout(value: float) -> float:
    try:
        timeout = float(value)
    except (TypeError, ValueError):
        timeout = ACTIVE_TLS_BASIC_DEFAULT_TIMEOUT_SECONDS
    return min(max(timeout, 0.25), ACTIVE_TLS_BASIC_DEFAULT_TIMEOUT_SECONDS)


def _is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True
