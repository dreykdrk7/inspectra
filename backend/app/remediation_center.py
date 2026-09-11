"""Owner-scoped, read-only remediation planning across current project evidence.

This projection groups already-normalized evidence.  It never opens source
files, contacts providers, executes package managers, or marks a fix verified.
"""

from __future__ import annotations

import base64
import binascii
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import re
import secrets
from typing import Any

from fastapi import HTTPException, status

from app.finding_lifecycle import FindingLifecycleError, effective_status
from app.models import (
    FindingDecisionRecord,
    JobRecord,
    NormalizedFinding,
    ProjectRecord,
    ProjectView,
    ProjectVulnerabilityFinding,
    RemediationActionGroup,
    RemediationOccurrence,
    RemediationPage,
    RemediationSearchRequest,
    RemediationSummary,
)
from app.project_coverage import build_project_analysis_coverage, compare_project_analysis_coverage
from app.project_portfolio import (
    PROJECT_AGGREGATE_MAX_PROJECTS,
    _as_utc,
    _local_findings,
    _owned_project_job,
    _public_findings,
)


REMEDIATION_MAX_GROUPS = 20_000
REMEDIATION_MAX_OCCURRENCES_PER_GROUP = 100
REMEDIATION_REVIEW_HORIZON_DAYS = 30
_CURSOR_KEY = secrets.token_bytes(32)
_MUTABLE_FINDING_ID = re.compile(r"^(?:[a-f0-9]{64}|pvf_[a-f0-9]{64})$")
_PRIORITY_ORDER = {"urgent": 0, "high": 1, "review": 2}
_SEVERITY_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "none": 1, "unknown": 0}
_REASON_ORDER = (
    "known_exploited",
    "critical",
    "high",
    "source_conflict",
    "new_finding",
    "direct_dependency",
    "coverage_incomplete",
    "exception_review_due",
    "awaiting_reanalysis",
)


class RemediationCenterService:
    def __init__(self, projects, jobs, vulnerability_store, decision_store) -> None:
        self.projects = projects
        self.jobs = jobs
        self.vulnerability_store = vulnerability_store
        self.decision_store = decision_store

    def search(
        self,
        *,
        organization_id: str,
        payload: RemediationSearchRequest,
        now: datetime | None = None,
    ) -> RemediationPage:
        observed_at = _as_utc(now or datetime.now(timezone.utc))
        cursor = _decode_cursor(payload.cursor) if payload.cursor else None
        filter_digest = _filter_digest(organization_id, payload)
        offset = 0
        expected_digest = ""
        if cursor is not None:
            if cursor.get("filter") != filter_digest:
                raise HTTPException(status_code=400, detail="Remediation cursor is invalid. Restart from the first page.")
            try:
                observed_at = _as_utc(datetime.fromisoformat(str(cursor["snapshot_at"])))
                offset = int(cursor["offset"])
                expected_digest = str(cursor["digest"])
            except (KeyError, TypeError, ValueError) as exc:
                raise HTTPException(status_code=400, detail="Remediation cursor is invalid. Restart from the first page.") from exc

        accumulators = self._build_accumulators(organization_id=organization_id, now=observed_at)
        groups = [_finalize_group(value) for value in accumulators.values()]
        project_ids_by_group = {
            str(value["id"]): frozenset(str(project_id) for project_id in value["projects"])
            for value in accumulators.values()
        }
        groups.sort(key=lambda item: _sort_key(item, payload.sort))
        filtered = [item for item in groups if _matches(item, payload)]
        digest = _snapshot_digest(filtered)
        if expected_digest and not hmac.compare_digest(expected_digest, digest):
            raise HTTPException(status_code=409, detail="Remediation state changed while paging. Restart from the first page.")
        if offset < 0 or offset > len(filtered):
            raise HTTPException(status_code=400, detail="Remediation cursor is invalid. Restart from the first page.")
        page_items = filtered[offset : offset + payload.page_size]
        next_offset = offset + len(page_items)
        next_cursor = _encode_cursor({
            "snapshot_at": observed_at.isoformat(),
            "offset": next_offset,
            "digest": digest,
            "filter": filter_digest,
        }) if next_offset < len(filtered) else None
        return RemediationPage(
            snapshot_at=observed_at,
            items=page_items,
            returned_count=len(page_items),
            total_count=len(filtered),
            has_more=next_cursor is not None,
            next_cursor=next_cursor,
            summary=_summary(groups, filtered, project_ids_by_group=project_ids_by_group),
            limitations=[
                "Only current normalized evidence is actionable here; a correction is verified only after a new comparable analysis no longer reports it.",
                "Project exposure is not inferred from passive source evidence and remains explicitly not assessed.",
            ],
        )

    def validate_bulk_selection(
        self,
        *,
        organization_id: str,
        group_id: str,
        expected_revision: str,
        selections: list[object],
        now: datetime | None = None,
    ) -> list[RemediationOccurrence]:
        """Resolve a bounded selection against current owner-scoped evidence."""

        observed_at = _as_utc(now or datetime.now(timezone.utc))
        accumulators = self._build_accumulators(organization_id=organization_id, now=observed_at)
        accumulator = accumulators.get(group_id)
        if accumulator is None:
            raise HTTPException(status_code=409, detail="This remediation group is no longer current. Refresh before applying changes.")
        group = _finalize_group(accumulator)
        if not hmac.compare_digest(group.revision, expected_revision):
            raise HTTPException(status_code=409, detail="This remediation group changed. Refresh before applying changes.")
        requested = [
            (str(item.project_id), str(item.analysis_id), str(item.finding_id))
            for item in selections
        ]
        if len(set(requested)) != len(requested):
            raise HTTPException(status_code=422, detail="A remediation selection cannot contain duplicates.")
        available = {
            (item.project.id, item.analysis.id, item.finding_id): item
            for item in group.occurrences
            if item.workflow_mutable
        }
        resolved: list[RemediationOccurrence] = []
        for identity in requested:
            occurrence = available.get(identity)
            if occurrence is None:
                raise HTTPException(status_code=409, detail="A selected finding is no longer actionable. Refresh before applying changes.")
            resolved.append(occurrence)
        return resolved

    def _build_accumulators(self, *, organization_id: str, now: datetime) -> dict[str, dict[str, Any]]:
        projects = self.projects.bounded_owner_snapshot(
            owner_id=organization_id, limit=PROJECT_AGGREGATE_MAX_PROJECTS
        )
        if len(projects) > PROJECT_AGGREGATE_MAX_PROJECTS:
            raise HTTPException(status_code=409, detail="Remediation portfolio exceeds the current safe aggregation limit.")
        try:
            decisions = self.decision_store.list_for_projects(
                organization_id, {project.id for project in projects}
            )
        except FindingLifecycleError as exc:
            raise HTTPException(status_code=503, detail="Remediation workflow state is temporarily unavailable.") from exc
        accumulators: dict[str, dict[str, Any]] = {}
        for project in projects:
            self._collect_project(
                project,
                decisions=decisions.get(project.id, []),
                now=now,
                accumulators=accumulators,
            )
            if len(accumulators) > REMEDIATION_MAX_GROUPS:
                raise HTTPException(status_code=409, detail="Remediation groups exceed the current safe aggregation limit.")
        return accumulators

    def collect_report_projects(
        self,
        *,
        organization_id: str,
        projects: list[ProjectRecord],
        observed_at: datetime,
        accumulators: dict[str, dict[str, Any]],
        decisions_by_project: dict[str, list[FindingDecisionRecord]],
    ) -> None:
        """Add one indexed page to a report snapshot without scanning projects."""

        for project in projects:
            if _as_utc(project.updated_at) > observed_at:
                raise RuntimeError("remediation_snapshot_changed")
            project_decisions = decisions_by_project.get(project.id, [])
            self._collect_project(
                project,
                decisions=project_decisions,
                now=observed_at,
                accumulators=accumulators,
                cutoff=observed_at,
            )
            if len(accumulators) > REMEDIATION_MAX_GROUPS:
                raise RuntimeError("remediation_group_limit")

    def report_decision_snapshot(
        self, *, organization_id: str, observed_at: datetime
    ) -> dict[str, list[FindingDecisionRecord]]:
        try:
            return self.decision_store.report_snapshot(
                organization_id, cutoff=observed_at
            )
        except FindingLifecycleError as exc:
            if exc.code == "snapshot_changed":
                raise RuntimeError("remediation_snapshot_changed") from exc
            raise RuntimeError("remediation_source_unavailable") from exc

    @staticmethod
    def finalize_report_groups(
        *,
        organization_id: str,
        payload: RemediationSearchRequest,
        observed_at: datetime,
        accumulators: dict[str, dict[str, Any]],
    ) -> tuple[list[RemediationActionGroup], RemediationSummary]:
        groups = [_finalize_group(value) for value in accumulators.values()]
        groups.sort(key=lambda item: _sort_key(item, payload.sort))
        filtered = [item for item in groups if _matches(item, payload)]
        project_ids_by_group = {
            str(value["id"]): frozenset(str(project_id) for project_id in value["projects"])
            for value in accumulators.values()
        }
        return filtered, _summary(groups, filtered, project_ids_by_group=project_ids_by_group)

    def _collect_project(
        self,
        project: ProjectRecord,
        *,
        decisions: list[FindingDecisionRecord],
        now: datetime,
        accumulators: dict[str, dict[str, Any]],
        cutoff: datetime | None = None,
    ) -> None:
        current = self.jobs.latest_completed_project_job(project.id, owner_id=project.owner_id)
        if current is None:
            return
        if cutoff is not None and _as_utc(current.updated_at) > cutoff:
            raise RuntimeError("remediation_snapshot_changed")
        baseline = _owned_project_job(self.jobs, project, project.baseline_analysis_id)
        local, local_invalid = _local_findings(current)
        snapshot = self.vulnerability_store.get(current.id)
        if cutoff is not None and snapshot is not None:
            recorded_at = snapshot.get("snapshot_recorded_at") or snapshot.get("queried_at")
            try:
                if recorded_at and _as_utc(datetime.fromisoformat(str(recorded_at))) > cutoff:
                    raise RuntimeError("remediation_snapshot_changed")
            except ValueError as exc:
                raise RuntimeError("remediation_source_unavailable") from exc
        public, public_invalid = _public_findings(snapshot)
        lifecycle = _latest_decisions(decisions)
        coverage_state = _coverage_state(current, baseline)
        new_local, new_public = _new_finding_ids(
            current=current,
            baseline=baseline,
            local=local,
            current_snapshot=snapshot,
            vulnerability_store=self.vulnerability_store,
        )
        analysis = self.jobs.get_list_item(current.id)
        project_view = ProjectView.model_validate(project)

        for finding in local:
            key = _group_key("local", finding.rule_id, finding.recommendation or finding.title)
            occurrence = _occurrence(
                project_view,
                analysis,
                finding_id=finding.id,
                rule_id=finding.rule_id,
                evidence_kind="local_finding",
                decision=lifecycle.get(finding.id),
                current=current,
                observed_version=None,
                dependency_scope="unknown",
                relationship_status="not_applicable",
                is_new=finding.id in new_local if new_local is not None else None,
                coverage_state=coverage_state,
                now=now,
            )
            accumulator = accumulators.setdefault(key, _local_group(key, finding))
            _add_occurrence(
                accumulator,
                occurrence,
                severity="none" if finding.severity == "info" else finding.severity,
                known_exploited=False,
                source_conflict=False,
                is_new=occurrence.is_new,
                coverage_incomplete=coverage_state != "complete" or local_invalid,
                now=now,
            )

        for finding in public:
            advisory = _canonical_advisory_id(finding)
            target = _safe_common_fixed_version(finding)
            key = _group_key("public", finding.ecosystem, finding.component_name, advisory, target or "no-fixed-version")
            rule_id = public_vulnerability_rule_id(finding)
            occurrence = _occurrence(
                project_view,
                analysis,
                finding_id=finding.id,
                rule_id=rule_id,
                evidence_kind="public_vulnerability",
                decision=lifecycle.get(finding.id),
                current=current,
                observed_version=finding.component_version,
                dependency_scope=finding.dependency_scope if finding.relationship_status == "reported" else "unknown",
                relationship_status=finding.relationship_status,
                is_new=finding.id in new_public if new_public is not None else None,
                coverage_state=coverage_state,
                now=now,
            )
            accumulator = accumulators.setdefault(key, _public_group(key, finding, advisory))
            source_conflict = bool(finding.source_conflicts) or finding.source_consensus in {"conflicting", "secondary_withdrawn"}
            _merge_public(accumulator, finding)
            _add_occurrence(
                accumulator,
                occurrence,
                severity=finding.cvss_band,
                known_exploited=any(signal.status == "known_exploited" for signal in finding.kev_signals),
                source_conflict=source_conflict,
                is_new=occurrence.is_new,
                coverage_incomplete=coverage_state != "complete" or public_invalid or not _snapshot_ready(snapshot),
                now=now,
            )


def _local_group(key: str, finding: NormalizedFinding) -> dict[str, Any]:
    return {
        "id": key,
        "evidence_kind": "local_finding",
        "title": finding.title[:240],
        "ecosystem": None,
        "component_name": None,
        "advisory_ids": [reference.id for reference in finding.references][:32],
        "observed_versions": set(),
        "affected_ranges": [],
        "fixed_versions": set(),
        "recommendation": (finding.recommendation or "Review the finding evidence and validate a correction in a new comparable snapshot.")[:2000],
        "severity": "none",
        "known_exploited": False,
        "source_conflict": False,
        "scopes": {"unknown"},
        "occurrences": [],
        "occurrence_count": 0,
        "projects": set(),
        "workflow": {},
        "reasons": set(),
        "limitations": [],
        "revision_items": set(),
    }


def _public_group(key: str, finding: ProjectVulnerabilityFinding, advisory: str) -> dict[str, Any]:
    return {
        "id": key,
        "evidence_kind": "public_vulnerability",
        "title": f"Update {finding.component_name} for {advisory}"[:240],
        "ecosystem": finding.ecosystem,
        "component_name": finding.component_name,
        "advisory_ids": [],
        "observed_versions": set(),
        "affected_ranges": [],
        "fixed_versions": set(),
        "recommendation": finding.recommendation[:2000],
        "severity": "unknown",
        "known_exploited": False,
        "source_conflict": False,
        "scopes": set(),
        "occurrences": [],
        "occurrence_count": 0,
        "projects": set(),
        "workflow": {},
        "reasons": set(),
        "limitations": [],
        "revision_items": set(),
    }


def _merge_public(accumulator: dict[str, Any], finding: ProjectVulnerabilityFinding) -> None:
    accumulator["advisory_ids"] = sorted(set(accumulator["advisory_ids"]) | set(finding.aliases) | {finding.advisory_id})[:32]
    accumulator["observed_versions"].add(finding.component_version)
    accumulator["fixed_versions"].update(finding.fixed_versions)
    known_ranges = {json.dumps(item.model_dump(mode="json"), sort_keys=True) for item in accumulator["affected_ranges"]}
    for item in finding.affected_ranges:
        encoded = json.dumps(item.model_dump(mode="json"), sort_keys=True)
        if encoded not in known_ranges and len(accumulator["affected_ranges"]) < 64:
            accumulator["affected_ranges"].append(item)
            known_ranges.add(encoded)


def _add_occurrence(
    accumulator: dict[str, Any],
    occurrence: RemediationOccurrence,
    *,
    severity: str,
    known_exploited: bool,
    source_conflict: bool,
    is_new: bool | None,
    coverage_incomplete: bool,
    now: datetime,
) -> None:
    accumulator["occurrence_count"] += 1
    accumulator["projects"].add(occurrence.project.id)
    accumulator["scopes"].add(occurrence.dependency_scope)
    accumulator["workflow"][occurrence.workflow_state] = accumulator["workflow"].get(occurrence.workflow_state, 0) + 1
    accumulator["revision_items"].add((
        occurrence.project.id,
        occurrence.analysis.id,
        occurrence.finding_id,
        occurrence.rule_id,
        occurrence.workflow_state,
    ))
    if len(accumulator["occurrences"]) < REMEDIATION_MAX_OCCURRENCES_PER_GROUP:
        accumulator["occurrences"].append(occurrence)
    if _SEVERITY_ORDER.get(severity, 0) > _SEVERITY_ORDER.get(accumulator["severity"], 0):
        accumulator["severity"] = severity
    accumulator["known_exploited"] |= known_exploited
    accumulator["source_conflict"] |= source_conflict
    if known_exploited:
        accumulator["reasons"].add("known_exploited")
    if severity == "critical":
        accumulator["reasons"].add("critical")
    elif severity == "high":
        accumulator["reasons"].add("high")
    if source_conflict:
        accumulator["reasons"].add("source_conflict")
    if is_new is True:
        accumulator["reasons"].add("new_finding")
    if occurrence.dependency_scope == "direct":
        accumulator["reasons"].add("direct_dependency")
    if coverage_incomplete:
        accumulator["reasons"].add("coverage_incomplete")
    if occurrence.review_at is not None and occurrence.review_at <= now + timedelta(days=REMEDIATION_REVIEW_HORIZON_DAYS):
        accumulator["reasons"].add("exception_review_due")
    if occurrence.workflow_state in {"awaiting_reanalysis", "still_detected"}:
        accumulator["reasons"].add("awaiting_reanalysis")
    if not occurrence.workflow_mutable and "Some legacy finding identifiers cannot receive workflow actions." not in accumulator["limitations"]:
        accumulator["limitations"].append("Some legacy finding identifiers cannot receive workflow actions.")


def _finalize_group(value: dict[str, Any]) -> RemediationActionGroup:
    reasons = [reason for reason in _REASON_ORDER if reason in value["reasons"]]
    if any(reason in reasons for reason in ("known_exploited", "critical")):
        priority = "urgent"
    elif any(reason in reasons for reason in ("high", "source_conflict", "new_finding", "direct_dependency", "coverage_incomplete", "exception_review_due", "awaiting_reanalysis")):
        priority = "high"
    else:
        priority = "review"
    fixed_versions = sorted(value["fixed_versions"])
    recommended = fixed_versions[0] if len(fixed_versions) == 1 and not value["source_conflict"] else None
    limitations = list(value["limitations"])
    if value["source_conflict"]:
        limitations.append("Sources disagree or a corroborating advisory changed; review each source before selecting a target version.")
    if recommended is None and value["evidence_kind"] == "public_vulnerability":
        limitations.append("No single conflict-free fixed version can be recommended automatically.")
    return RemediationActionGroup(
        id=value["id"],
        revision=hashlib.sha256(
            json.dumps(sorted(value["revision_items"]), separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
        evidence_kind=value["evidence_kind"],
        title=value["title"],
        ecosystem=value["ecosystem"],
        component_name=value["component_name"],
        advisory_ids=value["advisory_ids"],
        observed_versions=sorted(value["observed_versions"])[:32],
        affected_ranges=value["affected_ranges"],
        fixed_versions=fixed_versions[:32],
        recommended_fixed_version=recommended,
        recommendation=value["recommendation"],
        priority=priority,
        priority_reasons=reasons,
        highest_severity=value["severity"],
        known_exploited=value["known_exploited"],
        source_conflict=value["source_conflict"],
        dependency_scopes=sorted(value["scopes"]),
        affected_project_count=len(value["projects"]),
        occurrence_count=value["occurrence_count"],
        occurrences=value["occurrences"],
        occurrences_truncated=value["occurrence_count"] > len(value["occurrences"]),
        workflow_counts=value["workflow"],
        limitations=limitations,
    )


def _occurrence(
    project: ProjectView,
    analysis,
    *,
    finding_id: str,
    rule_id: str,
    evidence_kind: str,
    decision: FindingDecisionRecord | None,
    current: JobRecord,
    observed_version: str | None,
    dependency_scope: str,
    relationship_status: str,
    is_new: bool | None,
    coverage_state: str,
    now: datetime,
) -> RemediationOccurrence:
    state = effective_status(decision, now=now) if decision is not None else "open"
    if state == "resolved":
        state = "still_detected" if decision is not None and _as_utc(current.created_at) > _as_utc(decision.created_at) else "awaiting_reanalysis"
    return RemediationOccurrence(
        project=project,
        analysis=analysis,
        finding_id=finding_id,
        rule_id=rule_id,
        evidence_kind=evidence_kind,
        observed_version=observed_version,
        dependency_scope=dependency_scope,
        relationship_status=relationship_status,
        workflow_state=state,
        workflow_mutable=bool(_MUTABLE_FINDING_ID.fullmatch(finding_id)),
        assignee_username=decision.assignee_username if decision is not None else None,
        review_at=decision.review_at if decision is not None else None,
        is_new=is_new,
        coverage_state=coverage_state,
    )


def _coverage_state(current: JobRecord, baseline: JobRecord | None) -> str:
    current_coverage = build_project_analysis_coverage(current)
    if baseline is not None:
        comparison = compare_project_analysis_coverage(baseline, current)
        if comparison.status == "unknown" or (
            comparison.status == "changed"
            and (
                comparison.target.supported_manifests_parsed < comparison.base.supported_manifests_parsed
                or comparison.target.lockfiles_parsed < comparison.base.lockfiles_parsed
                or comparison.target.total_dependencies < comparison.base.total_dependencies
            )
        ):
            return "lost"
    return current_coverage.coverage_status


def _new_finding_ids(*, current, baseline, local, current_snapshot, vulnerability_store):
    if baseline is None or baseline.id == current.id or baseline.status != "completed":
        return None, None
    comparison = compare_project_analysis_coverage(baseline, current)
    if (
        baseline.audit_type != current.audit_type
        or baseline.analysis_profile != current.analysis_profile
        or baseline.execution_profile != current.execution_profile
        or comparison.status != "equivalent"
    ):
        return None, None
    baseline_local, invalid = _local_findings(baseline)
    if invalid:
        return None, None
    baseline_snapshot = vulnerability_store.get(baseline.id)
    baseline_public, baseline_invalid = _public_findings(baseline_snapshot)
    current_public, current_invalid = _public_findings(current_snapshot)
    new_local = {item.id for item in local} - {item.id for item in baseline_local}
    if baseline_invalid or current_invalid or not _snapshot_ready(baseline_snapshot) or not _snapshot_ready(current_snapshot):
        return new_local, None
    return new_local, {item.id for item in current_public} - {item.id for item in baseline_public}


def _snapshot_ready(value: object) -> bool:
    return isinstance(value, dict) and value.get("state") == "ready"


def _latest_decisions(records: list[FindingDecisionRecord]) -> dict[str, FindingDecisionRecord]:
    result: dict[str, FindingDecisionRecord] = {}
    for record in records:
        result[record.finding_id] = record
    return result


def _canonical_advisory_id(finding: ProjectVulnerabilityFinding) -> str:
    candidates = [finding.advisory_id, *finding.aliases]
    cves = sorted(value.upper() for value in candidates if re.fullmatch(r"CVE-\d{4}-\d{4,}", value, re.IGNORECASE))
    ghsas = sorted(value.upper() for value in candidates if re.fullmatch(r"GHSA-[A-Z0-9]{4}(?:-[A-Z0-9]{4}){2}", value, re.IGNORECASE))
    return (cves or ghsas or [finding.advisory_id])[0]


def public_vulnerability_rule_id(finding: ProjectVulnerabilityFinding) -> str:
    """Stable lifecycle rule identity for validated public evidence."""

    return f"public_vulnerability:{_canonical_advisory_id(finding)}"[:160]


def _safe_common_fixed_version(finding: ProjectVulnerabilityFinding) -> str | None:
    if finding.source_conflicts or finding.source_consensus in {"conflicting", "secondary_withdrawn"}:
        return None
    values = sorted(set(finding.fixed_versions))
    return values[0] if len(values) == 1 else None


def _group_key(*parts: str) -> str:
    return hashlib.sha256("\0".join(parts).encode("utf-8")).hexdigest()


def _matches(item: RemediationActionGroup, payload: RemediationSearchRequest) -> bool:
    if payload.search:
        candidate = " ".join(filter(None, [item.component_name, item.title, *item.advisory_ids])).casefold()
        needle = payload.search.casefold()
        if payload.search_mode == "exact" and candidate != needle:
            return False
        if payload.search_mode == "prefix" and not any(part.startswith(needle) for part in candidate.split()):
            return False
    if payload.priority is not None and item.priority != payload.priority:
        return False
    if payload.evidence_kind is not None and item.evidence_kind != payload.evidence_kind:
        return False
    if payload.ecosystem is not None and item.ecosystem != payload.ecosystem:
        return False
    if payload.dependency_scope is not None and payload.dependency_scope not in item.dependency_scopes:
        return False
    if payload.workflow_state is not None and getattr(item.workflow_counts, payload.workflow_state) == 0:
        return False
    return True


def _sort_key(item: RemediationActionGroup, sort: str) -> tuple[Any, ...]:
    if sort == "component":
        return ((item.component_name or item.title).casefold(), item.id)
    if sort == "projects":
        return (-item.affected_project_count, _PRIORITY_ORDER[item.priority], item.id)
    return (
        _PRIORITY_ORDER[item.priority],
        -int(item.known_exploited),
        -_SEVERITY_ORDER[item.highest_severity],
        -item.affected_project_count,
        (item.component_name or item.title).casefold(),
        item.id,
    )


def _summary(
    all_items: list[RemediationActionGroup],
    filtered: list[RemediationActionGroup],
    *,
    project_ids_by_group: dict[str, frozenset[str]],
) -> RemediationSummary:
    return RemediationSummary(
        total_groups=len(all_items),
        filtered_groups=len(filtered),
        urgent_groups=sum(item.priority == "urgent" for item in filtered),
        high_groups=sum(item.priority == "high" for item in filtered),
        projects_affected=len({
            project_id
            for item in filtered
            for project_id in project_ids_by_group.get(item.id, frozenset())
        }),
        known_exploited_groups=sum(item.known_exploited for item in filtered),
        conflicting_groups=sum(item.source_conflict for item in filtered),
        awaiting_reanalysis=sum(
            item.workflow_counts.awaiting_reanalysis + item.workflow_counts.still_detected
            for item in filtered
        ),
    )


def _snapshot_digest(items: list[RemediationActionGroup]) -> str:
    value = [{
        "id": item.id,
        "priority": item.priority,
        "revision": item.revision,
        "reasons": item.priority_reasons,
        "count": item.occurrence_count,
        "projects": [
            {
                "id": occurrence.project.id,
                "name": occurrence.project.name,
                "analysis_id": occurrence.analysis.id,
                "workflow": occurrence.workflow_state,
            }
            for occurrence in item.occurrences
        ],
        "workflow": item.workflow_counts.model_dump(mode="json"),
    } for item in items]
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _filter_digest(organization_id: str, payload: RemediationSearchRequest) -> str:
    value = payload.model_dump(exclude={"cursor", "page_size"}, mode="json")
    return hashlib.sha256(json.dumps({"organization_id": organization_id, "filters": value}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _encode_cursor(payload: dict[str, object]) -> str:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    signature = hmac.new(_CURSOR_KEY, body, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(body + signature).decode().rstrip("=")


def _decode_cursor(value: str) -> dict[str, object]:
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        if base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != value:
            raise ValueError
        body, signature = decoded[:-32], decoded[-32:]
        if not body or not hmac.compare_digest(signature, hmac.new(_CURSOR_KEY, body, hashlib.sha256).digest()):
            raise ValueError
        payload = json.loads(body)
        if not isinstance(payload, dict):
            raise ValueError
        return payload
    except (ValueError, TypeError, json.JSONDecodeError, binascii.Error) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Remediation cursor is invalid. Restart from the first page.") from exc
