from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
from io import StringIO
import json
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from app.models import ProductAuditEvent
from app.product_audit import ProductAuditStore


ACTIVE_AUDIT_EXPORT_CONTRACT_VERSION = "2026-09-08.1"
ACTIVE_AUDIT_EXPORT_MAX_EVENTS = 1_000
ACTIVE_AUDIT_EXPORT_MAX_BYTES = 1024 * 1024
ActiveAuditPeriod = Literal["7d", "30d", "90d", "365d"]
ActiveAuditFormat = Literal["json", "csv"]
_PERIOD_DAYS: dict[ActiveAuditPeriod, int] = {"7d": 7, "30d": 30, "90d": 90, "365d": 365}
_OPAQUE_ID = re.compile(r"^[a-f0-9]{32}$")
_RESOURCE_TYPES = {"active_asset", "active_execution", "deleted_active_asset", "organization"}


class ActiveAuditExportError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class ActiveAuditExportPrivacy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    target_included: Literal[False] = False
    authorization_reference_included: Literal[False] = False
    notes_included: Literal[False] = False
    client_ip_included: Literal[False] = False
    correlation_id_included: Literal[False] = False
    raw_metadata_included: Literal[False] = False
    raw_evidence_included: Literal[False] = False


class ActiveAuditExportPreflight(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal[ACTIVE_AUDIT_EXPORT_CONTRACT_VERSION] = ACTIVE_AUDIT_EXPORT_CONTRACT_VERSION
    state: Literal["ready", "no_matches"]
    period: ActiveAuditPeriod
    starts_at: datetime
    ends_at: datetime
    asset_filter_applied: bool
    total_events: int = Field(ge=0)
    included_events: int = Field(ge=0, le=ACTIVE_AUDIT_EXPORT_MAX_EVENTS)
    truncated: bool
    max_events: Literal[ACTIVE_AUDIT_EXPORT_MAX_EVENTS] = ACTIVE_AUDIT_EXPORT_MAX_EVENTS
    retention_days: int = Field(gt=0)
    available_formats: tuple[Literal["json", "csv"], Literal["json", "csv"]] = ("json", "csv")
    privacy: ActiveAuditExportPrivacy = Field(default_factory=ActiveAuditExportPrivacy)


class ActiveAuditExportEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    event_reference: str = Field(pattern=r"^event-[a-f0-9]{20}$")
    occurred_at: datetime
    actor_reference: str = Field(pattern=r"^actor-[a-f0-9]{20}$")
    actor_role: Literal["administrator", "maintainer", "reader"]
    action: str = Field(pattern=r"^active_asset\.[a-z0-9_.-]+$")
    result: Literal["succeeded", "denied", "failed"]
    resource_type: Literal["active_asset", "active_execution", "deleted_active_asset", "organization", "active_resource"]
    resource_reference: str = Field(pattern=r"^resource-[a-f0-9]{20}$")
    authorization_revision_id: str | None = Field(default=None, pattern=r"^[a-f0-9]{32}$")
    authorization_revision_sequence: int | None = Field(default=None, ge=1, le=64)


@dataclass(frozen=True)
class ActiveAuditExportSelection:
    preflight: ActiveAuditExportPreflight
    events: tuple[ActiveAuditExportEvent, ...]


def select_active_audit_export(
    store: ProductAuditStore,
    *,
    organization_id: str,
    period: ActiveAuditPeriod,
    asset_id: str | None = None,
    job_ids: set[str] | None = None,
    now: datetime | None = None,
) -> ActiveAuditExportSelection:
    days = _PERIOD_DAYS.get(period)
    if days is None:
        raise ActiveAuditExportError("invalid_period")
    ends_at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    starts_at = ends_at - timedelta(days=days)
    events, total = store.active_events_for_export(
        organization_id,
        starts_at=starts_at,
        ends_at=ends_at,
        asset_id=asset_id,
        job_ids=job_ids,
        limit=ACTIVE_AUDIT_EXPORT_MAX_EVENTS,
    )
    projected = tuple(_project_event(event, organization_id=organization_id) for event in events)
    preflight = ActiveAuditExportPreflight(
        state="ready" if projected else "no_matches",
        period=period,
        starts_at=starts_at,
        ends_at=ends_at,
        asset_filter_applied=asset_id is not None,
        total_events=total,
        included_events=len(projected),
        truncated=total > len(projected),
        retention_days=store.retention_days,
    )
    return ActiveAuditExportSelection(preflight=preflight, events=projected)


def render_active_audit_export(selection: ActiveAuditExportSelection, export_format: ActiveAuditFormat) -> bytes:
    if export_format == "json":
        document = {
            "contract_version": ACTIVE_AUDIT_EXPORT_CONTRACT_VERSION,
            "preflight": selection.preflight.model_dump(mode="json"),
            "events": [event.model_dump(mode="json") for event in selection.events],
        }
        payload = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    elif export_format == "csv":
        payload = _render_csv(selection).encode("utf-8")
    else:
        raise ActiveAuditExportError("invalid_format")
    if len(payload) > ACTIVE_AUDIT_EXPORT_MAX_BYTES:
        raise ActiveAuditExportError("export_too_large")
    return payload


def _project_event(event: ProductAuditEvent, *, organization_id: str) -> ActiveAuditExportEvent:
    revision_id = event.metadata.get("authorization_revision_id")
    if not isinstance(revision_id, str) or _OPAQUE_ID.fullmatch(revision_id) is None:
        revision_id = None
    revision_sequence = event.metadata.get("authorization_revision_sequence")
    if isinstance(revision_sequence, bool) or not isinstance(revision_sequence, int) or not 1 <= revision_sequence <= 64:
        revision_sequence = None
    return ActiveAuditExportEvent(
        event_reference=f"event-{_opaque(organization_id, 'event', event.id)}",
        occurred_at=event.occurred_at,
        actor_reference=f"actor-{_opaque(organization_id, 'actor', event.actor_id)}",
        actor_role=event.actor_role,
        action=event.action,
        result=event.result,
        resource_type=event.resource_type if event.resource_type in _RESOURCE_TYPES else "active_resource",
        resource_reference=f"resource-{_opaque(organization_id, 'resource', event.resource_id)}",
        authorization_revision_id=revision_id,
        authorization_revision_sequence=revision_sequence,
    )


def _opaque(organization_id: str, kind: str, value: str) -> str:
    return hashlib.sha256(
        b"inspectra-active-audit-export-v1\0"
        + organization_id.encode("ascii")
        + b"\0"
        + kind.encode("ascii")
        + b"\0"
        + value.encode("ascii")
    ).hexdigest()[:20]


def _render_csv(selection: ActiveAuditExportSelection) -> str:
    stream = StringIO(newline="")
    fields = [
        "record_type", "contract_version", "period", "starts_at", "ends_at", "asset_filter_applied",
        "total_events", "included_events", "truncated", "event_reference", "occurred_at",
        "actor_reference", "actor_role", "action", "result", "resource_type", "resource_reference",
        "authorization_revision_id", "authorization_revision_sequence",
    ]
    writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n", extrasaction="raise")
    writer.writeheader()
    preflight = selection.preflight
    writer.writerow(
        {
            "record_type": "manifest",
            "contract_version": ACTIVE_AUDIT_EXPORT_CONTRACT_VERSION,
            "period": preflight.period,
            "starts_at": preflight.starts_at.isoformat(),
            "ends_at": preflight.ends_at.isoformat(),
            "asset_filter_applied": str(preflight.asset_filter_applied).lower(),
            "total_events": preflight.total_events,
            "included_events": preflight.included_events,
            "truncated": str(preflight.truncated).lower(),
        }
    )
    for event in selection.events:
        writer.writerow(
            {
                "record_type": "event",
                "contract_version": ACTIVE_AUDIT_EXPORT_CONTRACT_VERSION,
                "event_reference": event.event_reference,
                "occurred_at": event.occurred_at.isoformat(),
                "actor_reference": event.actor_reference,
                "actor_role": event.actor_role,
                "action": event.action,
                "result": event.result,
                "resource_type": event.resource_type,
                "resource_reference": event.resource_reference,
                "authorization_revision_id": event.authorization_revision_id or "",
                "authorization_revision_sequence": event.authorization_revision_sequence or "",
            }
        )
    return stream.getvalue()
