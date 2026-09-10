from __future__ import annotations

from collections.abc import Mapping
import json
from typing import Any, Protocol

import httpx

from app.active_tools_client import _normalize_active_tools_base_url


ACTIVE_CAPABILITY_RUNNER_CONTRACT_VERSION = "2026-09-09.1"
ACTIVE_CAPABILITY_RUNNER_MAX_RESPONSE_BYTES = 262_144
ACTIVE_CAPABILITY_RUNNER_TIMEOUT_SECONDS = 8.0
ACTIVE_CAPABILITY_PATHS = {
    "active_dns_inventory": "/active/dns-inventory",
    "active_dns_osint": "/active/dns-osint",
    "active_http_basic_header_review": "/active/http-headers",
    "active_tls_basic": "/active/tls-basic",
}
ACTIVE_CAPABILITY_PROFILES = {
    "active_dns_inventory": "dns_inventory_authorized",
    "active_dns_osint": "ct_subdomain_discovery_bounded",
    "active_http_basic_header_review": "http_headers_single_request",
    "active_tls_basic": "tls_handshake_summary",
}
_BLOCKED_RESULT_KEYS = {
    "argv", "command", "credentials", "environment", "raw_body", "raw_certificate",
    "raw_dns", "raw_headers", "raw_output", "request_headers", "response_body",
    "secret", "stderr", "stdout", "token",
}


class ActiveCapabilityRunnerError(RuntimeError):
    pass


class ActiveCapabilityRunner(Protocol):
    async def execute(self, *, capability: str, target: str, port: int | None = None) -> dict[str, Any]:
        ...


class ActiveToolsCapabilityRunner:
    def __init__(
        self,
        base_url: str | None,
        *,
        timeout_seconds: float = ACTIVE_CAPABILITY_RUNNER_TIMEOUT_SECONDS,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.base_url = _normalize_active_tools_base_url(base_url)
        self.timeout_seconds = min(max(float(timeout_seconds), 0.5), ACTIVE_CAPABILITY_RUNNER_TIMEOUT_SECONDS)
        self.transport = transport

    async def execute(self, *, capability: str, target: str, port: int | None = None) -> dict[str, Any]:
        path = ACTIVE_CAPABILITY_PATHS.get(capability)
        profile = ACTIVE_CAPABILITY_PROFILES.get(capability)
        if not path or not profile or not self.base_url:
            raise ActiveCapabilityRunnerError("active_runner_unconfigured")
        payload = {
            "contract_version": ACTIVE_CAPABILITY_RUNNER_CONTRACT_VERSION,
            "capability": capability,
            "profile": profile,
            "target": target,
            "port": port,
            "confirmations_verified_by_backend": True,
        }
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout_seconds,
                transport=self.transport,
                follow_redirects=False,
            ) as client:
                async with client.stream("POST", f"{self.base_url}{path}", json=payload) as response:
                    if response.status_code != 200:
                        raise ActiveCapabilityRunnerError("active_runner_unavailable")
                    declared = response.headers.get("content-length")
                    if declared and int(declared) > ACTIVE_CAPABILITY_RUNNER_MAX_RESPONSE_BYTES:
                        raise ActiveCapabilityRunnerError("active_runner_response_too_large")
                    body = bytearray()
                    async for chunk in response.aiter_bytes():
                        body.extend(chunk)
                        if len(body) > ACTIVE_CAPABILITY_RUNNER_MAX_RESPONSE_BYTES:
                            raise ActiveCapabilityRunnerError("active_runner_response_too_large")
        except ActiveCapabilityRunnerError:
            raise
        except (httpx.TimeoutException, httpx.RequestError, ValueError) as exc:
            raise ActiveCapabilityRunnerError("active_runner_unavailable") from exc
        try:
            result = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ActiveCapabilityRunnerError("active_runner_invalid_response") from exc
        if not isinstance(result, dict) or result.get("capability") != capability:
            raise ActiveCapabilityRunnerError("active_runner_invalid_response")
        if target in json.dumps(result, sort_keys=True) or _contains_blocked_key(result):
            raise ActiveCapabilityRunnerError("active_runner_invalid_response")
        return result


def _contains_blocked_key(value: Any) -> bool:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            normalized = str(key).strip().casefold()
            if normalized in _BLOCKED_RESULT_KEYS or _contains_blocked_key(nested):
                return True
    elif isinstance(value, list):
        return any(_contains_blocked_key(item) for item in value)
    return False
