"""Bounded, reproducible portfolio reports for authorized Active operations."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.active_assets import ActiveAssetRecord
from app.active_recurrence import ActiveRecurrenceRecord
from app.models import JobRecord
from app.reporting import markdown_inline_value


ACTIVE_WEEKLY_REPORT_CONTRACT_VERSION = "2026-09-09.1"
ACTIVE_WEEKLY_REPORT_MAX_BYTES = 1024 * 1024
ACTIVE_WEEKLY_REPORT_MAX_ACTIONS = 100
ACTIVE_WEEKLY_REPORT_MAX_RECURRENCES = 100
ActiveWeeklyReportPeriod = Literal["7d", "30d"]
ActiveWeeklyReportFormat = Literal["markdown", "json"]
_PERIOD_DAYS: dict[ActiveWeeklyReportPeriod, int] = {"7d": 7, "30d": 30}


class ActiveWeeklyReportError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class ActiveWeeklyReportPrivacy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    exact_targets_included: Literal[True] = True
    notes_included: Literal[False] = False
    authorization_references_included: Literal[False] = False
    authorization_digests_included: Literal[False] = False
    responsible_accounts_included: Literal[False] = False
    actor_identifiers_included: Literal[False] = False
    challenge_material_included: Literal[False] = False
    raw_results_included: Literal[False] = False
    runner_responses_included: Literal[False] = False


class ActiveWeeklyReportPreflight(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal[ACTIVE_WEEKLY_REPORT_CONTRACT_VERSION] = ACTIVE_WEEKLY_REPORT_CONTRACT_VERSION
    state: Literal["ready", "partial", "no_assets"]
    period: ActiveWeeklyReportPeriod
    starts_at: datetime
    state_at: datetime
    snapshot_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    assets_total: int = Field(ge=0)
    assets_included: int = Field(ge=0, le=500)
    jobs_total: int = Field(ge=0)
    jobs_included: int = Field(ge=0, le=2_000)
    actions_total: int = Field(ge=0)
    actions_included: int = Field(ge=0, le=ACTIVE_WEEKLY_REPORT_MAX_ACTIONS)
    recurrence_attention_total: int = Field(ge=0)
    recurrence_attention_included: int = Field(ge=0, le=ACTIVE_WEEKLY_REPORT_MAX_RECURRENCES)
    incomplete: bool
    available_formats: tuple[Literal["markdown", "json"], Literal["markdown", "json"]] = (
        "markdown", "json"
    )
    max_bytes: Literal[ACTIVE_WEEKLY_REPORT_MAX_BYTES] = ACTIVE_WEEKLY_REPORT_MAX_BYTES
    privacy: ActiveWeeklyReportPrivacy = Field(default_factory=ActiveWeeklyReportPrivacy)


class ActiveWeeklyReportExportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    period: ActiveWeeklyReportPeriod
    report_format: ActiveWeeklyReportFormat
    state_at: datetime
    snapshot_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    sensitive_targets_confirmed: Literal[True]

    @model_validator(mode="after")
    def normalize_state_at(self):
        if self.state_at.tzinfo is None or self.state_at.utcoffset() is None:
            raise ValueError("state_at requires timezone information")
        self.state_at = self.state_at.astimezone(timezone.utc)
        return self


@dataclass(frozen=True)
class ActiveWeeklyReportSnapshot:
    document: dict[str, Any]
    digest: str
    preflight: ActiveWeeklyReportPreflight


def build_active_weekly_report_snapshot(
    summary: dict[str, Any],
    assets: list[ActiveAssetRecord],
    jobs: list[JobRecord],
    recurrences: list[ActiveRecurrenceRecord],
    *,
    organization_id: str,
    period: ActiveWeeklyReportPeriod,
    state_at: datetime,
) -> ActiveWeeklyReportSnapshot:
    days = _PERIOD_DAYS.get(period)
    if days is None or state_at.tzinfo is None or state_at.utcoffset() is None:
        raise ActiveWeeklyReportError("invalid_request")
    state_at = state_at.astimezone(timezone.utc)
    starts_at = state_at - timedelta(days=days)
    asset_by_id = {asset.id: asset for asset in assets}
    if any(
        asset.organization_id != organization_id or asset.updated_at > state_at
        for asset in assets
    ):
        raise ActiveWeeklyReportError("snapshot_changed")
    if any(
        job.owner_id != organization_id
        or job.active_asset_id not in asset_by_id
        or job.updated_at > state_at
        for job in jobs
    ):
        raise ActiveWeeklyReportError("snapshot_changed")
    if any(
        recurrence.organization_id != organization_id
        or recurrence.asset_id not in asset_by_id
        or recurrence.updated_at > state_at
        for recurrence in recurrences
    ):
        raise ActiveWeeklyReportError("snapshot_changed")

    recent_jobs = [job for job in jobs if starts_at <= job.updated_at <= state_at]
    recent_job_counts = {
        status: sum(job.status == status for job in recent_jobs)
        for status in ("queued", "running", "cancelling", "cancelled", "completed", "failed")
    }
    recent_job_counts["degraded"] = sum(_job_is_degraded(job) for job in recent_jobs)

    asset_inventory = [
        {
            "asset_reference": f"active-{asset.id[:12]}",
            "exact_target": asset.canonical_value,
            "asset_type": asset.asset_type,
            "authorization_status": asset.status,
            "authorization_expires_at": asset.expires_at.isoformat(),
            "capabilities": sorted(asset.capabilities),
        }
        for asset in sorted(assets, key=lambda item: item.id)
    ]

    actions: list[dict[str, Any]] = []
    for action in summary["action_queue"]["items"][:ACTIVE_WEEKLY_REPORT_MAX_ACTIONS]:
        asset = asset_by_id.get(action["asset_id"])
        if asset is None:
            raise ActiveWeeklyReportError("snapshot_changed")
        actions.append(
            {
                "action_reference": f"action-{action['id'][:20]}",
                "asset_reference": f"active-{asset.id[:12]}",
                "exact_target": asset.canonical_value,
                "asset_type": asset.asset_type,
                "authorization_status": asset.status,
                "kind": action["kind"],
                "urgency": action["urgency"],
                "recommended_action": action["action_code"],
                "reference_at": action["reference_at"],
                "due_at": action["due_at"],
                "occurrence_count": action["occurrence_count"],
                "execution_reference": (
                    f"execution-{action['job_id'][:12]}" if action["job_id"] else None
                ),
            }
        )

    recurrence_counts = {
        status: sum(item.status == status for item in recurrences)
        for status in ("active", "paused", "suspended")
    }
    recurrence_counts["retry_scheduled"] = sum(
        item.status == "active" and item.next_retry_at is not None for item in recurrences
    )
    recurrence_attention_records = [
        item
        for item in recurrences
        if item.status != "active" or item.next_retry_at is not None
    ]
    recurrence_attention_records.sort(
        key=lambda item: (item.next_retry_at or item.next_run_at, item.id)
    )
    recurrence_attention = [
        {
            "schedule_reference": f"schedule-{item.id[:12]}",
            "asset_reference": f"active-{item.asset_id[:12]}",
            "exact_target": asset_by_id[item.asset_id].canonical_value,
            "status": item.status,
            "reason_code": item.reason_code,
            "next_run_at": item.next_run_at.isoformat(),
            "next_retry_at": item.next_retry_at.isoformat() if item.next_retry_at else None,
            "last_outcome": item.last_outcome,
        }
        for item in recurrence_attention_records[:ACTIVE_WEEKLY_REPORT_MAX_RECURRENCES]
    ]

    incomplete = bool(
        summary["limits"]["incomplete"]
        or summary["action_queue"]["items_truncated"]
        or len(recurrence_attention) < len(recurrence_attention_records)
    )
    state = "no_assets" if summary["assets"]["total"] == 0 else "partial" if incomplete else "ready"
    document = {
        "contract_version": ACTIVE_WEEKLY_REPORT_CONTRACT_VERSION,
        "state": state,
        "period": {
            "kind": period,
            "starts_at": starts_at.isoformat(),
            "state_at": state_at.isoformat(),
        },
        "portfolio": summary["assets"],
        "asset_inventory": asset_inventory,
        "execution_window": {
            "counts": recent_job_counts,
            "records_included": len(recent_jobs),
            "source_records_included": len(jobs),
            "source_records_total": summary["limits"]["jobs_total"],
            "source_incomplete": summary["limits"]["jobs_considered"] < summary["limits"]["jobs_total"],
        },
        "changes": summary["changes"],
        "attention": {
            "counts": summary["actions"],
            "items": actions,
            "included": len(actions),
            "total": summary["action_queue"]["total"],
            "truncated": summary["action_queue"]["items_truncated"],
        },
        "recurrence": {
            "counts": recurrence_counts,
            "attention_items": recurrence_attention,
            "attention_included": len(recurrence_attention),
            "attention_total": len(recurrence_attention_records),
            "attention_truncated": len(recurrence_attention) < len(recurrence_attention_records),
        },
        "coverage": {
            "assets_included": len(assets),
            "assets_total": summary["limits"]["assets_total"],
            "jobs_included": len(jobs),
            "jobs_total": summary["limits"]["jobs_total"],
            "actions_included": len(actions),
            "actions_total": summary["action_queue"]["total"],
            "selection_strategy": summary["limits"]["selection_strategy"],
            "incomplete": incomplete,
            "limits": {"assets": 500, "jobs": 2_000, "actions": 100, "recurrence_attention": 100},
        },
        "privacy": ActiveWeeklyReportPrivacy().model_dump(mode="json"),
        "interpretation": "bounded_authorized_observations_not_confirmed_vulnerabilities_or_sla",
    }
    digest = _sha256(_json_bytes(document))
    preflight = ActiveWeeklyReportPreflight(
        state=state,
        period=period,
        starts_at=starts_at,
        state_at=state_at,
        snapshot_digest=digest,
        assets_total=summary["limits"]["assets_total"],
        assets_included=len(assets),
        jobs_total=summary["limits"]["jobs_total"],
        jobs_included=len(jobs),
        actions_total=summary["action_queue"]["total"],
        actions_included=len(actions),
        recurrence_attention_total=len(recurrence_attention_records),
        recurrence_attention_included=len(recurrence_attention),
        incomplete=incomplete,
    )
    return ActiveWeeklyReportSnapshot(document=document, digest=digest, preflight=preflight)


def render_active_weekly_report(
    snapshot: ActiveWeeklyReportSnapshot, report_format: ActiveWeeklyReportFormat
) -> bytes:
    if report_format == "json":
        payload = _json_bytes(snapshot.document | {"snapshot_digest": snapshot.digest})
    elif report_format == "markdown":
        payload = _markdown(snapshot).encode("utf-8")
    else:
        raise ActiveWeeklyReportError("invalid_request")
    if not payload or len(payload) > ACTIVE_WEEKLY_REPORT_MAX_BYTES:
        raise ActiveWeeklyReportError("report_too_large")
    return payload


def _markdown(snapshot: ActiveWeeklyReportSnapshot) -> str:
    document = snapshot.document
    period = document["period"]
    coverage = document["coverage"]
    lines = [
        "# Inspectra Active weekly portfolio report",
        "",
        f"- Contract: {markdown_inline_value(document['contract_version'])}",
        f"- Snapshot SHA-256: {markdown_inline_value(snapshot.digest)}",
        f"- Review period: {markdown_inline_value(period['kind'])}",
        f"- Window: {markdown_inline_value(period['starts_at'])} to {markdown_inline_value(period['state_at'])}",
        f"- State: {markdown_inline_value(document['state'])}",
        "- Sensitive scope: exact authorized targets are included when present; store and share this report accordingly.",
        "- Interpretation: bounded observations, not confirmed vulnerabilities or an organizational SLA.",
        "",
        "## Portfolio and coverage",
        "",
        f"- Assets: {coverage['assets_included']} included / {coverage['assets_total']} total.",
        f"- Executions: {coverage['jobs_included']} source records included / {coverage['jobs_total']} total.",
        f"- Actions: {coverage['actions_included']} included / {coverage['actions_total']} total.",
        f"- Coverage incomplete: {markdown_inline_value(str(coverage['incomplete']).lower())}",
        "",
        "## Recent execution window",
        "",
        f"- Records in period: {document['execution_window']['records_included']}.",
        f"- Queued: {document['execution_window']['counts']['queued']}.",
        f"- Running: {document['execution_window']['counts']['running']}.",
        f"- Cancelling: {document['execution_window']['counts']['cancelling']}.",
        f"- Cancelled: {document['execution_window']['counts']['cancelled']}.",
        f"- Completed: {document['execution_window']['counts']['completed']}.",
        f"- Failed: {document['execution_window']['counts']['failed']}.",
        f"- Completed with degraded coverage: {document['execution_window']['counts']['degraded']}.",
        f"- Source incomplete: {markdown_inline_value(str(document['execution_window']['source_incomplete']).lower())}",
        "",
        "## Comparable changes",
        "",
        f"- Assets compared: {document['changes']['assets_compared']}.",
        f"- Assets with changes: {document['changes']['assets_with_changes']}.",
        f"- Changed observations: {document['changes']['observations_changed']}.",
        f"- Inconclusive comparisons: {document['changes']['inconclusive']}.",
        "",
        "## Authorized asset inventory",
        "",
        *(
            [
                f"- {markdown_inline_value(item['exact_target'])} · {markdown_inline_value(item['asset_type'])} · "
                f"{markdown_inline_value(item['authorization_status'])}; authorization expires "
                f"{markdown_inline_value(item['authorization_expires_at'])}."
                for item in document["asset_inventory"]
            ]
            or ["No authorized Active asset appears in this snapshot."]
        ),
        "",
        "## Current attention",
        "",
    ]
    if not document["attention"]["items"]:
        lines.append("No current action appears in the bounded snapshot.")
    for item in document["attention"]["items"]:
        lines.append(
            f"- {markdown_inline_value(item['urgency'])} · {markdown_inline_value(item['exact_target'])} · "
            f"{markdown_inline_value(item['kind'])} → {markdown_inline_value(item['recommended_action'])} "
            f"(recorded {markdown_inline_value(item['reference_at'])})."
        )
    lines.extend(["", "## Recurrence attention", ""])
    if not document["recurrence"]["attention_items"]:
        lines.append("No paused, suspended or retrying schedule appears in the bounded snapshot.")
    for item in document["recurrence"]["attention_items"]:
        lines.append(
            f"- {markdown_inline_value(item['exact_target'])} · {markdown_inline_value(item['status'])} · "
            f"{markdown_inline_value(item['reason_code'])}; next {markdown_inline_value(item['next_retry_at'] or item['next_run_at'])}."
        )
    lines.extend(
        [
            "",
            "## Privacy exclusions",
            "",
            "Notes, authorization references and digests, responsible or actor identities, challenge material, raw results and runner responses are excluded.",
        ]
    )
    return "\n".join(lines) + "\n"


def _job_is_degraded(job: JobRecord) -> bool:
    if job.status != "completed" or not isinstance(job.result, dict):
        return False
    return job.result.get("status") in {
        "partial", "timed_out", "request_failed", "source_unavailable"
    } or job.result.get("coverage_level") in {"partial", "partial_inventory", "incomplete"}


def _json_bytes(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()
