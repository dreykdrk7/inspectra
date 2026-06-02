from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, TypeAlias


APPROVED_AUTHORIZATION_STATEMENT = "I confirm I own or am authorized to test this target."
DEFAULT_AUTHORIZATION_SCOPE = "single-target"
DRY_RUN_MODE = "dry_run"
HTTP_HEADER_PROBE_PREVIEW = "http_header_probe_preview"
ALLOWED_PROFILES = {HTTP_HEADER_PROBE_PREVIEW}
POLICY_VERSION = "active-network-v0-dry-run"

ActiveDryRunResult: TypeAlias = dict[str, Any]


@dataclass(frozen=True)
class ActiveAuthorization:
    confirmed: bool = False
    statement: str = APPROVED_AUTHORIZATION_STATEMENT
    scope: str = DEFAULT_AUTHORIZATION_SCOPE

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any] | None) -> "ActiveAuthorization":
        if data is None:
            return cls()
        _reject_unknown_keys(data, {"confirmed", "statement", "scope"}, "authorization")
        return cls(
            confirmed=bool(data.get("confirmed", False)),
            statement=str(data.get("statement", APPROVED_AUTHORIZATION_STATEMENT)),
            scope=str(data.get("scope", DEFAULT_AUTHORIZATION_SCOPE)),
        )

    def to_result(self) -> dict[str, Any]:
        return {
            "confirmed": self.confirmed,
            "statement_version": "active-authorization-v1",
            "scope": self.scope,
        }


@dataclass(frozen=True)
class ActiveDryRunLimits:
    max_requests: int = 0
    timeout_seconds: int = 0
    max_redirects: int = 0
    response_size_bytes: int = 0

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any] | None) -> "ActiveDryRunLimits":
        if data is None:
            return cls()
        _reject_unknown_keys(
            data,
            {"max_requests", "timeout_seconds", "max_redirects", "response_size_bytes"},
            "limits",
        )
        return cls(
            max_requests=_to_int(data.get("max_requests", 0)),
            timeout_seconds=_to_int(data.get("timeout_seconds", 0)),
            max_redirects=_to_int(data.get("max_redirects", 0)),
            response_size_bytes=_to_int(data.get("response_size_bytes", 0)),
        )

    def to_result(self) -> dict[str, int]:
        return {
            "max_requests": self.max_requests,
            "timeout_seconds": self.timeout_seconds,
            "max_redirects": self.max_redirects,
            "response_size_bytes": self.response_size_bytes,
        }

    def is_zero(self) -> bool:
        return (
            self.max_requests == 0
            and self.timeout_seconds == 0
            and self.max_redirects == 0
            and self.response_size_bytes == 0
        )


@dataclass(frozen=True)
class ActiveDryRunRequest:
    target: str
    authorization: ActiveAuthorization = field(default_factory=ActiveAuthorization)
    mode: str = DRY_RUN_MODE
    profile: str = HTTP_HEADER_PROBE_PREVIEW
    limits: ActiveDryRunLimits = field(default_factory=ActiveDryRunLimits)

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "ActiveDryRunRequest":
        _reject_unknown_keys(data, {"target", "authorization", "mode", "profile", "limits"}, "request")
        return cls(
            target=str(data.get("target", "")),
            authorization=ActiveAuthorization.from_mapping(_mapping_or_none(data.get("authorization"))),
            mode=str(data.get("mode", DRY_RUN_MODE)),
            profile=str(data.get("profile", HTTP_HEADER_PROBE_PREVIEW)),
            limits=ActiveDryRunLimits.from_mapping(_mapping_or_none(data.get("limits"))),
        )


def _mapping_or_none(value: Any) -> Mapping[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise ValueError("Expected object.")
    return value


def _reject_unknown_keys(data: Mapping[str, Any], allowed: set[str], label: str) -> None:
    unknown = sorted(set(data) - allowed)
    if unknown:
        joined = ", ".join(unknown)
        raise ValueError(f"Unknown {label} field: {joined}.")


def _to_int(value: Any) -> int:
    if isinstance(value, bool):
        return int(value)
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("Expected integer limit value.") from exc
