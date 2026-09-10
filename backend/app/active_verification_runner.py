from __future__ import annotations

import json
from typing import Any, Literal, Mapping, Protocol

import httpx

from app.active_asset_verification import ActiveAssetVerificationObservation
from app.active_tools_client import _normalize_active_tools_base_url


ACTIVE_VERIFICATION_RUNNER_CONTRACT_VERSION = "2026-09-08.1"
ACTIVE_VERIFICATION_RUNNER_PATH = "/active/asset-verification"
ACTIVE_VERIFICATION_RUNNER_MAX_RESPONSE_BYTES = 1_024
ACTIVE_VERIFICATION_RUNNER_TIMEOUT_SECONDS = 4.0
_ALLOWED_RESPONSE_KEYS = {"contract_version", "capability", "matched", "reason_code"}
_ALLOWED_REASON_CODES = {
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


class ActiveVerificationRunnerError(RuntimeError):
    pass


class ActiveVerificationRunner(Protocol):
    async def verify(
        self,
        *,
        method: Literal["dns_txt", "http_well_known"],
        target: str,
        challenge_token: str,
    ) -> ActiveAssetVerificationObservation: ...


class ActiveToolsVerificationRunner:
    """Bounded internal client; target and token are never returned or logged."""

    def __init__(
        self,
        base_url: str | None,
        *,
        timeout_seconds: float = ACTIVE_VERIFICATION_RUNNER_TIMEOUT_SECONDS,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.base_url = _normalize_active_tools_base_url(base_url)
        self.timeout_seconds = min(max(float(timeout_seconds), 0.5), ACTIVE_VERIFICATION_RUNNER_TIMEOUT_SECONDS)
        self.transport = transport

    async def verify(
        self,
        *,
        method: Literal["dns_txt", "http_well_known"],
        target: str,
        challenge_token: str,
    ) -> ActiveAssetVerificationObservation:
        if not self.base_url:
            raise ActiveVerificationRunnerError("active_verification_runner_unconfigured")
        payload = {
            "contract_version": ACTIVE_VERIFICATION_RUNNER_CONTRACT_VERSION,
            "capability": "active_asset_verification",
            "method": method,
            "target": target,
            "challenge_token": challenge_token,
            "confirmations_verified_by_backend": True,
        }
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout_seconds,
                transport=self.transport,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                async with client.stream("POST", f"{self.base_url}{ACTIVE_VERIFICATION_RUNNER_PATH}", json=payload) as response:
                    if response.status_code != 200:
                        raise ActiveVerificationRunnerError("active_verification_runner_unavailable")
                    declared = response.headers.get("content-length")
                    if declared is not None and int(declared) > ACTIVE_VERIFICATION_RUNNER_MAX_RESPONSE_BYTES:
                        raise ActiveVerificationRunnerError("active_verification_runner_invalid_response")
                    body = bytearray()
                    async for chunk in response.aiter_bytes():
                        body.extend(chunk)
                        if len(body) > ACTIVE_VERIFICATION_RUNNER_MAX_RESPONSE_BYTES:
                            raise ActiveVerificationRunnerError("active_verification_runner_invalid_response")
        except ActiveVerificationRunnerError:
            raise
        except (httpx.TimeoutException, httpx.RequestError, ValueError) as exc:
            raise ActiveVerificationRunnerError("active_verification_runner_unavailable") from exc
        try:
            result = json.loads(body)
        except (ValueError, UnicodeDecodeError) as exc:
            raise ActiveVerificationRunnerError("active_verification_runner_invalid_response") from exc
        if (
            not isinstance(result, Mapping)
            or set(result) != _ALLOWED_RESPONSE_KEYS
            or result.get("contract_version") != ACTIVE_VERIFICATION_RUNNER_CONTRACT_VERSION
            or result.get("capability") != "active_asset_verification"
            or not isinstance(result.get("matched"), bool)
            or result.get("reason_code") not in _ALLOWED_REASON_CODES
            or (result.get("reason_code") == "matched") != result.get("matched")
            or target in json.dumps(result, sort_keys=True)
            or challenge_token in json.dumps(result, sort_keys=True)
        ):
            raise ActiveVerificationRunnerError("active_verification_runner_invalid_response")
        return ActiveAssetVerificationObservation(bool(result["matched"]), str(result["reason_code"]))


def verification_runner_target(asset: Any, method: str) -> str:
    if method == "dns_txt":
        return f"_inspectra-verification.{asset.canonical_value}"
    if method == "http_well_known":
        if asset.asset_type == "http_origin":
            return asset.canonical_value
        scheme = "https" if "https" in asset.allowed_protocols else "http"
        return f"{scheme}://{asset.canonical_value}"
    raise ValueError("Only remote verification methods cross the runner boundary.")
