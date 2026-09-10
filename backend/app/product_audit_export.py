"""Bounded, snapshot-bound export of the redacted product audit projection."""

from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
from io import StringIO
import json
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.models import ProductAuditEvent
from app.product_audit import ProductAuditStore


PRODUCT_AUDIT_EXPORT_CONTRACT_VERSION = "2026-09-10.1"
PRODUCT_AUDIT_EXPORT_MAX_EVENTS = 1_000
PRODUCT_AUDIT_EXPORT_MAX_BYTES = 1024 * 1024
PRODUCT_AUDIT_EXPORT_PREFLIGHT_TTL_SECONDS = 300
ProductAuditExportPeriod = Literal["7d", "30d", "90d", "365d"]
ProductAuditExportFormat = Literal["json", "csv"]
_PERIOD_DAYS: dict[ProductAuditExportPeriod, int] = {
    "7d": 7,
    "30d": 30,
    "90d": 90,
    "365d": 365,
}


class ProductAuditExportError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class ProductAuditExportPrivacy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    organization_identifier_included: Literal[False] = False
    original_actor_identifier_included: Literal[False] = False
    original_resource_identifier_included: Literal[False] = False
    correlation_identifier_included: Literal[False] = False
    metadata_included: Literal[False] = False
    names_paths_targets_included: Literal[False] = False
    source_or_evidence_included: Literal[False] = False


class ProductAuditExportPreflight(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal[PRODUCT_AUDIT_EXPORT_CONTRACT_VERSION] = PRODUCT_AUDIT_EXPORT_CONTRACT_VERSION
    state: Literal["ready", "no_matches"]
    period: ProductAuditExportPeriod
    starts_at: datetime
    state_at: datetime
    expires_at: datetime
    action_filter: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9_.-]{2,95}$")
    total_events: int = Field(ge=0)
    included_events: int = Field(ge=0, le=PRODUCT_AUDIT_EXPORT_MAX_EVENTS)
    truncated: bool
    snapshot_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    max_events: Literal[PRODUCT_AUDIT_EXPORT_MAX_EVENTS] = PRODUCT_AUDIT_EXPORT_MAX_EVENTS
    max_bytes: Literal[PRODUCT_AUDIT_EXPORT_MAX_BYTES] = PRODUCT_AUDIT_EXPORT_MAX_BYTES
    retention_days: int = Field(gt=0)
    available_formats: tuple[Literal["json", "csv"], Literal["json", "csv"]] = ("json", "csv")
    privacy: ProductAuditExportPrivacy = Field(default_factory=ProductAuditExportPrivacy)


class ProductAuditExportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    period: ProductAuditExportPeriod
    export_format: ProductAuditExportFormat
    action_filter: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9_.-]{2,95}$")
    state_at: datetime
    snapshot_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    redacted_export_confirmed: Literal[True]

    @model_validator(mode="after")
    def normalize_state_at(self):
        if self.state_at.tzinfo is None or self.state_at.utcoffset() is None:
            raise ValueError("state_at requires timezone information")
        self.state_at = self.state_at.astimezone(timezone.utc)
        return self


class ProductAuditExportEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    event_reference: str = Field(pattern=r"^event-[a-f0-9]{20}$")
    occurred_at: datetime
    actor_reference: str = Field(pattern=r"^actor-[a-f0-9]{20}$")
    actor_role: Literal["administrator", "maintainer", "reader"]
    action: str = Field(pattern=r"^[a-z][a-z0-9_.-]{2,95}$")
    result: Literal["succeeded", "denied", "failed"]
    resource_type: str = Field(pattern=r"^[a-z][a-z0-9_-]{1,47}$")
    resource_reference: str = Field(pattern=r"^resource-[a-f0-9]{20}$")


@dataclass(frozen=True)
class ProductAuditExportSelection:
    preflight: ProductAuditExportPreflight
    events: tuple[ProductAuditExportEvent, ...]


def select_product_audit_export(
    store: ProductAuditStore,
    *,
    organization_id: str,
    period: ProductAuditExportPeriod,
    action_filter: str | None = None,
    state_at: datetime | None = None,
) -> ProductAuditExportSelection:
    days = _PERIOD_DAYS.get(period)
    if days is None:
        raise ProductAuditExportError("invalid_period")
    resolved_state_at = (state_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    starts_at = resolved_state_at - timedelta(days=days)
    events, total = store.events_for_export(
        organization_id,
        starts_at=starts_at,
        ends_at=resolved_state_at,
        action=action_filter,
        limit=PRODUCT_AUDIT_EXPORT_MAX_EVENTS,
    )
    projected = tuple(_project_event(event, organization_id=organization_id) for event in events)
    manifest = {
        "contract_version": PRODUCT_AUDIT_EXPORT_CONTRACT_VERSION,
        "period": period,
        "starts_at": starts_at.isoformat(),
        "state_at": resolved_state_at.isoformat(),
        "action_filter": action_filter,
        "total_events": total,
        "included_events": len(projected),
        "truncated": total > len(projected),
        "retention_days": store.retention_days,
        "events": [event.model_dump(mode="json") for event in projected],
    }
    snapshot_digest = hashlib.sha256(_canonical_json(manifest)).hexdigest()
    return ProductAuditExportSelection(
        preflight=ProductAuditExportPreflight(
            state="ready" if projected else "no_matches",
            period=period,
            starts_at=starts_at,
            state_at=resolved_state_at,
            expires_at=resolved_state_at + timedelta(seconds=PRODUCT_AUDIT_EXPORT_PREFLIGHT_TTL_SECONDS),
            action_filter=action_filter,
            total_events=total,
            included_events=len(projected),
            truncated=total > len(projected),
            snapshot_digest=snapshot_digest,
            retention_days=store.retention_days,
        ),
        events=projected,
    )


def validate_product_audit_export_request(
    selection: ProductAuditExportSelection,
    request: ProductAuditExportRequest,
    *,
    now: datetime | None = None,
) -> None:
    checked_at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if checked_at > selection.preflight.expires_at or request.state_at > checked_at + timedelta(seconds=5):
        raise ProductAuditExportError("preflight_expired")
    if selection.preflight.state != "ready":
        raise ProductAuditExportError("no_matches")
    if request.snapshot_digest != selection.preflight.snapshot_digest:
        raise ProductAuditExportError("snapshot_changed")


def render_product_audit_export(
    selection: ProductAuditExportSelection,
    export_format: ProductAuditExportFormat,
) -> bytes:
    if export_format == "json":
        payload = _canonical_json(
            {
                "contract_version": PRODUCT_AUDIT_EXPORT_CONTRACT_VERSION,
                "preflight": selection.preflight.model_dump(mode="json"),
                "events": [event.model_dump(mode="json") for event in selection.events],
            }
        ) + b"\n"
    elif export_format == "csv":
        payload = _render_csv(selection).encode("utf-8")
    else:
        raise ProductAuditExportError("invalid_format")
    if len(payload) > PRODUCT_AUDIT_EXPORT_MAX_BYTES:
        raise ProductAuditExportError("export_too_large")
    return payload


def _project_event(event: ProductAuditEvent, *, organization_id: str) -> ProductAuditExportEvent:
    return ProductAuditExportEvent(
        event_reference=f"event-{_opaque(organization_id, 'event', event.id)}",
        occurred_at=event.occurred_at,
        actor_reference=f"actor-{_opaque(organization_id, 'actor', event.actor_id)}",
        actor_role=event.actor_role,
        action=event.action,
        result=event.result,
        resource_type=event.resource_type,
        resource_reference=f"resource-{_opaque(organization_id, 'resource', event.resource_id)}",
    )


def _opaque(organization_id: str, kind: str, value: str) -> str:
    return hashlib.sha256(
        b"inspectra-product-audit-export-v1\0"
        + organization_id.encode("ascii")
        + b"\0"
        + kind.encode("ascii")
        + b"\0"
        + value.encode("ascii")
    ).hexdigest()[:20]


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _render_csv(selection: ProductAuditExportSelection) -> str:
    stream = StringIO(newline="")
    fields = [
        "record_type", "contract_version", "period", "starts_at", "state_at", "action_filter",
        "total_events", "included_events", "truncated", "snapshot_digest", "event_reference",
        "occurred_at", "actor_reference", "actor_role", "action", "result", "resource_type",
        "resource_reference",
    ]
    writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n", extrasaction="raise")
    writer.writeheader()
    preflight = selection.preflight
    writer.writerow(
        {
            "record_type": "manifest",
            "contract_version": PRODUCT_AUDIT_EXPORT_CONTRACT_VERSION,
            "period": preflight.period,
            "starts_at": preflight.starts_at.isoformat(),
            "state_at": preflight.state_at.isoformat(),
            "action_filter": preflight.action_filter or "",
            "total_events": preflight.total_events,
            "included_events": preflight.included_events,
            "truncated": str(preflight.truncated).lower(),
            "snapshot_digest": preflight.snapshot_digest,
        }
    )
    for event in selection.events:
        writer.writerow(
            {
                "record_type": "event",
                "contract_version": PRODUCT_AUDIT_EXPORT_CONTRACT_VERSION,
                "event_reference": event.event_reference,
                "occurred_at": event.occurred_at.isoformat(),
                "actor_reference": event.actor_reference,
                "actor_role": event.actor_role,
                "action": event.action,
                "result": event.result,
                "resource_type": event.resource_type,
                "resource_reference": event.resource_reference,
            }
        )
    return stream.getvalue()
