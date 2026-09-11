from __future__ import annotations

from collections.abc import Callable, Mapping
import os
from typing import Any, Literal

from fastapi import HTTPException, status
from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.active_dns_inventory import (
    ActiveDnsInventoryContract,
    normalize_active_dns_inventory_domain,
    run_active_dns_inventory,
)
from app.active_dns_osint import (
    ACTIVE_DNS_OSINT_CRTSH_ALLOWED_HOST,
    ActiveDnsOsintContract,
    build_active_dns_osint_ct_source,
    normalize_active_dns_osint_domain,
    run_active_dns_osint,
)
from app.active_http_basic_header_review import build_active_http_basic_header_review_response
from app.active_tls_basic import ActiveTlsBasicRequest, run_active_tls_basic


ACTIVE_CAPABILITY_RUNNER_CONTRACT_VERSION = "2026-09-09.1"
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
ACTIVE_CAPABILITY_ENV_FLAGS = {
    "active_dns_inventory": "INSPECTRA_ACTIVE_TOOLS_DNS_INVENTORY_EXECUTION_ENABLED",
    "active_dns_osint": "INSPECTRA_ACTIVE_TOOLS_DNS_OSINT_EXECUTION_ENABLED",
    "active_http_basic_header_review": "INSPECTRA_ACTIVE_TOOLS_HTTP_HEADERS_EXECUTION_ENABLED",
    "active_tls_basic": "INSPECTRA_ACTIVE_TOOLS_TLS_BASIC_EXECUTION_ENABLED",
}

CapabilityName = Literal[
    "active_dns_inventory",
    "active_dns_osint",
    "active_http_basic_header_review",
    "active_tls_basic",
]
CapabilityExecutor = Callable[["ActiveCapabilityBoundaryRequest"], Mapping[str, Any]]


class ActiveCapabilityBoundaryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    contract_version: Literal[ACTIVE_CAPABILITY_RUNNER_CONTRACT_VERSION]
    capability: CapabilityName
    profile: str = Field(min_length=1, max_length=64)
    target: str = Field(min_length=1, max_length=2048)
    port: int | None = Field(default=None, ge=1, le=65535)
    confirmations_verified_by_backend: Literal[True]

    @model_validator(mode="after")
    def validate_fixed_profile_and_port(self) -> "ActiveCapabilityBoundaryRequest":
        if self.profile != ACTIVE_CAPABILITY_PROFILES[self.capability]:
            raise ValueError("Active capability profile is not the fixed profile.")
        if self.capability == "active_tls_basic" and self.port is None:
            raise ValueError("TLS basic requires one explicit authorized port.")
        if self.capability != "active_tls_basic" and self.port is not None:
            raise ValueError("A port selector is accepted only for TLS basic.")
        return self


def capability_execution_enabled(capability: CapabilityName) -> bool:
    value = os.getenv(ACTIVE_CAPABILITY_ENV_FLAGS[capability], "")
    return value.strip().lower() in {"1", "true", "yes", "on"}


def execute_active_capability(
    payload: Mapping[str, Any] | Any,
    *,
    enabled: bool,
    executor: CapabilityExecutor | None = None,
) -> dict[str, Any]:
    if not enabled:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Active capability is disabled in the isolated runner.")
    try:
        request = ActiveCapabilityBoundaryRequest.model_validate(payload)
        result = dict(executor(request) if executor is not None else _execute_builtin(request))
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="Active capability failed safely inside its boundary.") from exc
    if result.get("capability") != request.capability:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Active capability returned an invalid bounded result.")
    serialized = str(result)
    if request.target in serialized or len(serialized.encode("utf-8")) > 262_144:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Active capability returned an invalid bounded result.")
    return result


def _execute_builtin(request: ActiveCapabilityBoundaryRequest) -> dict[str, Any]:
    if request.capability == "active_dns_inventory":
        domain = normalize_active_dns_inventory_domain(request.target)
        return run_active_dns_inventory(
            ActiveDnsInventoryContract(
                domain=domain,
                record_types=("A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT", "CAA"),
                include_security_records=True,
                include_subdomain_discovery=False,
                attempt_zone_transfer=False,
            ),
            axfr_transport=None,
        )
    if request.capability == "active_dns_osint":
        domain = normalize_active_dns_osint_domain(request.target)
        source = build_active_dns_osint_ct_source(
            enabled=True,
            source_url=f"https://{ACTIVE_DNS_OSINT_CRTSH_ALLOWED_HOST}/",
            timeout_seconds=5.0,
            max_response_bytes=1_048_576,
            max_names_parsed=100,
        )
        return run_active_dns_osint(
            ActiveDnsOsintContract(domain=domain, include_certificate_transparency=True, include_passive_dns=False, max_names=100),
            ct_source=source,
        )
    if request.capability == "active_http_basic_header_review":
        return build_active_http_basic_header_review_response(
            {
                "mode": "live_http_basic_header_review",
                "profile": ACTIVE_CAPABILITY_PROFILES[request.capability],
                "target": request.target,
                "method": "HEAD",
                "authorization_confirmed": True,
                "target_control_confirmed": True,
                "delegated_permission_confirmed": True,
                "live_http_request_confirmed": True,
            },
            enabled=True,
            live_head_enabled=True,
        )
    assert request.port is not None
    return run_active_tls_basic(ActiveTlsBasicRequest(target=request.target, port=request.port, timeout_seconds=3.0))
