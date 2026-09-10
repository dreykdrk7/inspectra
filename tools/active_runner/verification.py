from __future__ import annotations

from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
import http.client
import ipaddress
import re
import socket
import ssl
from typing import Any, Literal
from urllib.parse import urlsplit

from fastapi import HTTPException, status
from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.active_dns_inventory import ActiveDnsInventoryQueryResult, UdpDnsInventoryResolver


ACTIVE_VERIFICATION_CONTRACT_VERSION = "2026-09-08.1"
ACTIVE_VERIFICATION_PATH = "/active/asset-verification"
ACTIVE_VERIFICATION_CAPABILITY = "active_asset_verification"
ACTIVE_VERIFICATION_TIMEOUT_SECONDS = 3.0
ACTIVE_VERIFICATION_MAX_BODY_BYTES = 512
ACTIVE_VERIFICATION_MAX_DNS_ANSWERS = 8
ACTIVE_VERIFICATION_WELL_KNOWN_PATH = "/.well-known/inspectra-verification"
ACTIVE_VERIFICATION_REASON_CODES = {
    "matched",
    "token_not_observed",
    "dns_unavailable",
    "dns_answer_limit",
    "http_target_not_public",
    "http_timeout",
    "http_unavailable",
    "http_body_limit",
    "http_status_not_ok",
    "http_body_invalid",
}
_DNS_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


class ActiveVerificationBoundaryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    contract_version: Literal[ACTIVE_VERIFICATION_CONTRACT_VERSION]
    capability: Literal[ACTIVE_VERIFICATION_CAPABILITY]
    method: Literal["dns_txt", "http_well_known"]
    target: str = Field(min_length=1, max_length=2048)
    challenge_token: str = Field(min_length=36, max_length=36, pattern=r"^iv1_[A-Za-z0-9_-]{32}$")
    confirmations_verified_by_backend: Literal[True]

    @model_validator(mode="after")
    def validate_derived_target(self) -> "ActiveVerificationBoundaryRequest":
        if self.method == "dns_txt":
            if not self.target.startswith("_inspectra-verification.") or not _valid_dns_name(self.target):
                raise ValueError("DNS verification target is not the fixed derived record.")
        else:
            parsed = urlsplit(self.target)
            if (
                parsed.scheme not in {"http", "https"}
                or not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
                or parsed.path not in {"", "/"}
                or parsed.query
                or parsed.fragment
                or parsed.port not in {None, 80, 443}
            ):
                raise ValueError("HTTP verification target is not an exact origin.")
        return self


VerificationExecutor = Callable[[ActiveVerificationBoundaryRequest], Mapping[str, Any]]


def execute_active_verification(
    payload: Mapping[str, Any] | Any,
    *,
    enabled: bool,
    executor: VerificationExecutor | None = None,
) -> dict[str, Any]:
    if not enabled:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Active verification is disabled in the isolated runner.")
    try:
        request = ActiveVerificationBoundaryRequest.model_validate(payload)
        outcome = dict(executor(request) if executor is not None else _execute_builtin(request))
        if set(outcome) != {"matched", "reason_code"}:
            raise ValueError("unexpected outcome fields")
        matched = outcome.get("matched")
        reason_code = outcome.get("reason_code")
        if not isinstance(matched, bool) or reason_code not in ACTIVE_VERIFICATION_REASON_CODES:
            raise ValueError("invalid outcome")
        if (reason_code == "matched") != matched:
            raise ValueError("inconsistent outcome")
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="Active verification failed safely inside its boundary.") from exc
    return {
        "contract_version": ACTIVE_VERIFICATION_CONTRACT_VERSION,
        "capability": ACTIVE_VERIFICATION_CAPABILITY,
        "matched": matched,
        "reason_code": reason_code,
    }


def _execute_builtin(request: ActiveVerificationBoundaryRequest) -> dict[str, Any]:
    if request.method == "dns_txt":
        try:
            result = UdpDnsInventoryResolver(timeout_seconds=ACTIVE_VERIFICATION_TIMEOUT_SECONDS).query(request.target, "TXT")
        except Exception:
            return {"matched": False, "reason_code": "dns_unavailable"}
        if not isinstance(result, ActiveDnsInventoryQueryResult) or result.status != "ok":
            return {"matched": False, "reason_code": "dns_unavailable"}
        if len(result.records) > ACTIVE_VERIFICATION_MAX_DNS_ANSWERS:
            return {"matched": False, "reason_code": "dns_answer_limit"}
        values = {_normalize_txt(record.value) for record in result.records}
        matched = request.challenge_token in values
        return {"matched": matched, "reason_code": "matched" if matched else "token_not_observed"}

    parsed = urlsplit(request.target)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        addresses = _bounded_resolve(host, port)
        if not addresses or any(not ipaddress.ip_address(value).is_global for value in addresses):
            return {"matched": False, "reason_code": "http_target_not_public"}
        status_code, body = _bounded_http_get(request.target, addresses[0])
    except TimeoutError:
        return {"matched": False, "reason_code": "http_timeout"}
    except Exception:
        return {"matched": False, "reason_code": "http_unavailable"}
    if len(body) > ACTIVE_VERIFICATION_MAX_BODY_BYTES:
        return {"matched": False, "reason_code": "http_body_limit"}
    if status_code != 200:
        return {"matched": False, "reason_code": "http_status_not_ok"}
    try:
        value = body.decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError:
        return {"matched": False, "reason_code": "http_body_invalid"}
    matched = value == request.challenge_token
    return {"matched": matched, "reason_code": "matched" if matched else "token_not_observed"}


def _valid_dns_name(value: str) -> bool:
    if len(value) > 253 or value.endswith("."):
        return False
    labels = value.split(".")
    return (
        len(labels) >= 3
        and labels[0] == "_inspectra-verification"
        and all(_DNS_LABEL.fullmatch(label) for label in labels[1:])
    )


def _normalize_txt(value: str) -> str:
    normalized = value.strip()
    return normalized[1:-1] if len(normalized) >= 2 and normalized[0] == normalized[-1] == '"' else normalized


def _bounded_resolve(host: str, port: int) -> list[str]:
    def resolve() -> list[str]:
        values: list[str] = []
        for _family, _kind, _protocol, _canonical, sockaddr in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM):
            value = str(sockaddr[0])
            if value not in values:
                values.append(value)
            if len(values) > 8:
                raise ValueError("too many addresses")
        return values

    executor = ThreadPoolExecutor(max_workers=1)
    future = executor.submit(resolve)
    try:
        return future.result(timeout=ACTIVE_VERIFICATION_TIMEOUT_SECONDS)
    except FutureTimeoutError as exc:
        future.cancel()
        raise TimeoutError from exc
    finally:
        executor.shutdown(wait=False, cancel_futures=True)


def _bounded_http_get(origin: str, address: str) -> tuple[int, bytes]:
    parsed = urlsplit(origin)
    if not parsed.hostname:
        raise ValueError("invalid origin")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    raw_socket = socket.create_connection((address, port), timeout=ACTIVE_VERIFICATION_TIMEOUT_SECONDS)
    connection_socket: socket.socket = raw_socket
    try:
        if parsed.scheme == "https":
            connection_socket = ssl.create_default_context().wrap_socket(raw_socket, server_hostname=parsed.hostname)
        host_header = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
        if port != (443 if parsed.scheme == "https" else 80):
            host_header = f"{host_header}:{port}"
        request = (
            f"GET {ACTIVE_VERIFICATION_WELL_KNOWN_PATH} HTTP/1.1\r\n"
            f"Host: {host_header}\r\nAccept: text/plain\r\n"
            "User-Agent: Inspectra-active-verification\r\nConnection: close\r\n\r\n"
        ).encode("ascii")
        connection_socket.sendall(request)
        response = http.client.HTTPResponse(connection_socket)
        response.begin()
        body = response.read(ACTIVE_VERIFICATION_MAX_BODY_BYTES + 1)
        return response.status, body
    finally:
        connection_socket.close()
