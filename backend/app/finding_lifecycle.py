from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
from typing import Iterable, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.config import Settings
from app.models import (
    FindingDecisionRecord,
    FindingDecisionStatus,
    FindingLifecycleState,
    NormalizedFinding,
)
from app.reporting import redact_active_secret_text
from app.risk_trend_source_clock import RiskTrendSourceClock
from app.storage import _atomic_write_json, storage_lock


FINDING_DECISION_CONTRACT_VERSION = "2026-09-06.1"
MAX_DECISIONS_PER_FINDING = 100
MAX_DECISIONS_PER_PROJECT = 10_000
MAX_PORTFOLIO_QUERY_PROJECTS = 20_000

ALLOWED_TRANSITIONS: dict[FindingDecisionStatus, frozenset[FindingDecisionStatus]] = {
    "open": frozenset({"in_review", "accepted", "false_positive", "resolved"}),
    "in_review": frozenset({"open", "accepted", "false_positive", "resolved"}),
    "accepted": frozenset({"open", "in_review", "resolved"}),
    "false_positive": frozenset({"open", "in_review"}),
    "resolved": frozenset({"open", "in_review"}),
}
EXCEPTION_STATUSES = frozenset({"accepted", "false_positive"})
MAX_EXCEPTION_REVIEW_DAYS = 366
REMEDIATION_BATCH_CONTRACT_VERSION = "2026-09-09.1"
_BATCH_ID = re.compile(r"^[a-f0-9]{64}$")
_ORGANIZATION_ID = re.compile(r"^(?:local-admin|[a-f0-9]{32})$")


class RemediationBatchJournal(BaseModel):
    """Content-free recovery marker; decision text stays in staged records."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal["2026-09-09.1"] = REMEDIATION_BATCH_CONTRACT_VERSION
    operation_id: str = Field(pattern=r"^[a-f0-9]{64}$")
    organization_id: str = Field(pattern=r"^(?:local-admin|[a-f0-9]{32})$")
    request_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    group_id: str = Field(pattern=r"^[a-f0-9]{64}$")
    decision_ids: list[str] = Field(min_length=1, max_length=25)
    decision_digests: dict[str, str]
    prepared_at: datetime

    def model_post_init(self, _context) -> None:
        if len(set(self.decision_ids)) != len(self.decision_ids):
            raise ValueError("Batch decision identifiers must be unique.")
        if set(self.decision_digests) != set(self.decision_ids):
            raise ValueError("Batch decision digests are incomplete.")
        if any(not re.fullmatch(r"[a-f0-9]{32}", value) for value in self.decision_ids):
            raise ValueError("Batch decision identifier is invalid.")
        if any(not _BATCH_ID.fullmatch(value) for value in self.decision_digests.values()):
            raise ValueError("Batch decision digest is invalid.")
        if self.prepared_at.tzinfo is None or self.prepared_at.utcoffset() is None:
            raise ValueError("Batch timestamp must include a timezone.")


class RemediationBatchReceipt(RemediationBatchJournal):
    """Private committed receipt used for atomic visibility and replay."""

    completed_at: datetime
    replayable: bool = True

    def model_post_init(self, context) -> None:
        super().model_post_init(context)
        if self.completed_at.tzinfo is None or self.completed_at.utcoffset() is None:
            raise ValueError("Batch completion timestamp must include a timezone.")


class FindingLifecycleError(RuntimeError):
    """Controlled finding-decision failure with a non-sensitive reason code."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class FindingDecisionStore:
    """Append-only triage decisions scoped to an organization and project.

    Analyzer output is never updated. Every transition is a separate atomic
    record and the current lifecycle state is derived at read time, including
    review-date expiry.
    """

    def __init__(self, settings: Settings, *, now_func=None, id_factory=None, after_batch_step=None) -> None:
        self.settings = settings
        self.directory = settings.finding_decisions_dir
        self.batch_directory = settings.remediation_batches_dir
        self.batch_journal_directory = settings.remediation_batch_journals_dir
        self._now_func = now_func or _utc_now
        self._id_factory = id_factory or (lambda: uuid4().hex)
        self._after_batch_step = after_batch_step
        self.risk_trend_source_clock = RiskTrendSourceClock(settings)
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.batch_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.batch_journal_directory.mkdir(parents=True, exist_ok=True, mode=0o700)

    def record(
        self,
        *,
        organization_id: str,
        project_id: str,
        finding_id: str,
        rule_id: str,
        status: FindingDecisionStatus,
        reason: str,
        comment: str | None,
        actor_id: str,
        actor_username: str,
        actor_role: str,
        review_at: datetime | None,
        assignee_user_id: str | None,
        assignee_username: str | None,
    ) -> FindingDecisionRecord:
        now = self._now()
        safe_reason = safe_decision_text(reason, required=True, max_length=240)
        safe_comment = safe_decision_text(comment, required=False, max_length=1_000)
        normalized_review_at = normalize_review_at(review_at, status=status, now=now)
        if len(rule_id) > 160 or any(ord(character) < 32 for character in rule_id):
            raise FindingLifecycleError("finding_not_supported")
        if bool(assignee_user_id) != bool(assignee_username):
            raise FindingLifecycleError("invalid_assignee")

        with storage_lock(self.settings):
            existing = self._list_for_project_unlocked(organization_id, project_id)
            if len(existing) >= MAX_DECISIONS_PER_PROJECT:
                raise FindingLifecycleError("project_decision_limit")
            history = [item for item in existing if item.finding_id == finding_id]
            if len(history) >= MAX_DECISIONS_PER_FINDING:
                raise FindingLifecycleError("finding_decision_limit")
            previous = history[-1] if history else None
            if previous is not None and previous.rule_id != rule_id:
                raise FindingLifecycleError("finding_identity_conflict")
            current_status = effective_status(previous, now=now) if previous is not None else "open"
            if previous is not None and status not in ALLOWED_TRANSITIONS[current_status]:
                raise FindingLifecycleError("invalid_transition")

            decision_id = self._new_id()
            record = FindingDecisionRecord(
                contract_version=FINDING_DECISION_CONTRACT_VERSION,
                id=decision_id,
                organization_id=organization_id,
                project_id=project_id,
                finding_id=finding_id,
                rule_id=rule_id,
                status=status,
                reason=safe_reason,
                comment=safe_comment,
                assignee_user_id=assignee_user_id,
                assignee_username=assignee_username,
                actor_id=actor_id,
                actor_username=actor_username,
                actor_role=actor_role,
                review_at=normalized_review_at,
                created_at=now,
                previous_decision_id=previous.id if previous is not None else None,
            )
            source_revision = self.risk_trend_source_clock.raw_source_revision()
            _atomic_write_json(self._path(decision_id), record.model_dump(mode="json"))
            self.risk_trend_source_clock.record_mutation(
                organization_id,
                previous_source_revision=source_revision,
            )
            return record

    def list_for_project(self, organization_id: str, project_id: str) -> list[FindingDecisionRecord]:
        with storage_lock(self.settings):
            return self._list_for_project_unlocked(organization_id, project_id)

    def batch_binding(
        self,
        *,
        organization_id: str,
        actor_id: str,
        idempotency_key: str,
        request_payload: dict,
    ) -> tuple[str, str]:
        """Derive opaque operation/request bindings without retaining the key or payload."""

        if (
            not _ORGANIZATION_ID.fullmatch(organization_id)
            or not isinstance(actor_id, str)
            or not 1 <= len(actor_id) <= 64
            or not isinstance(idempotency_key, str)
            or not 16 <= len(idempotency_key) <= 128
            or not re.fullmatch(r"[A-Za-z0-9._:-]+", idempotency_key)
        ):
            raise FindingLifecycleError("invalid_batch")
        try:
            canonical = json.dumps(request_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        except (TypeError, ValueError) as exc:
            raise FindingLifecycleError("invalid_batch") from exc
        operation_id = hashlib.sha256(
            f"inspectra-remediation-operation-v1\0{organization_id}\0{idempotency_key}".encode("utf-8")
        ).hexdigest()
        request_digest = hashlib.sha256(
            b"inspectra-remediation-request-v1\0"
            + organization_id.encode("utf-8")
            + b"\0"
            + actor_id.encode("utf-8")
            + b"\0"
            + idempotency_key.encode("utf-8")
            + b"\0"
            + canonical.encode("utf-8")
        ).hexdigest()
        return operation_id, request_digest

    def replay_batch(
        self,
        operation_id: str,
        *,
        organization_id: str,
        request_digest: str,
    ) -> list[FindingDecisionRecord] | None:
        with storage_lock(self.settings):
            return self._replay_batch_unlocked(
                operation_id,
                organization_id=organization_id,
                request_digest=request_digest,
            )

    def recover_pending_batches(self) -> int:
        """Finish prepared batches and remove only provably orphaned staged records."""

        recovered = 0
        with storage_lock(self.settings):
            paths = sorted(self.batch_journal_directory.iterdir())
            for path in paths:
                if path.name.startswith(".") and path.name.endswith(".staging"):
                    continue
                if path.is_symlink() or not path.is_file() or path.suffix != ".json" or not _BATCH_ID.fullmatch(path.stem):
                    continue
                self._recover_batch_unlocked(path.stem)
                recovered += 1
            self._cleanup_orphan_batches_unlocked()
        return recovered

    def has_pending_batches(self) -> bool:
        try:
            return any(path.name != ".gitkeep" for path in self.batch_journal_directory.iterdir())
        except OSError:
            return True

    def record_many(
        self,
        *,
        organization_id: str,
        operation_id: str,
        request_digest: str,
        group_id: str,
        items: list[tuple[str, str, str]],
        status: FindingDecisionStatus,
        reason: str,
        comment: str | None,
        actor_id: str,
        actor_username: str,
        actor_role: str,
        review_at: datetime | None,
        assignee_user_id: str | None,
        assignee_username: str | None,
    ) -> tuple[list[FindingDecisionRecord], bool]:
        """Commit one recoverable batch; its decisions become visible together."""

        if not 1 <= len(items) <= 25 or len({(p, f) for p, f, _r in items}) != len(items):
            raise FindingLifecycleError("invalid_batch")
        if not _BATCH_ID.fullmatch(operation_id) or not _BATCH_ID.fullmatch(request_digest) or not _BATCH_ID.fullmatch(group_id):
            raise FindingLifecycleError("invalid_batch")
        now = self._now()
        safe_reason = safe_decision_text(reason, required=True, max_length=240)
        safe_comment = safe_decision_text(comment, required=False, max_length=1_000)
        normalized_review_at = normalize_review_at(review_at, status=status, now=now)
        if bool(assignee_user_id) != bool(assignee_username):
            raise FindingLifecycleError("invalid_assignee")

        with storage_lock(self.settings):
            replay = self._replay_batch_unlocked(
                operation_id,
                organization_id=organization_id,
                request_digest=request_digest,
            )
            if replay is not None:
                return replay, True
            journal_path = self._batch_journal_path(operation_id)
            if journal_path.exists() or journal_path.is_symlink():
                self._recover_batch_unlocked(operation_id)
                replay = self._replay_batch_unlocked(
                    operation_id,
                    organization_id=organization_id,
                    request_digest=request_digest,
                )
                if replay is None:
                    raise FindingLifecycleError("batch_recovery_failed")
                return replay, True

            by_project: dict[str, list[FindingDecisionRecord]] = {}
            for project_id, finding_id, rule_id in items:
                if len(rule_id) > 160 or any(ord(character) < 32 for character in rule_id):
                    raise FindingLifecycleError("finding_not_supported")
                if project_id not in by_project:
                    by_project[project_id] = self._list_for_project_unlocked(organization_id, project_id)
                existing = by_project[project_id]
                if len(existing) + sum(value[0] == project_id for value in items) > MAX_DECISIONS_PER_PROJECT:
                    raise FindingLifecycleError("project_decision_limit")
                history = [record for record in existing if record.finding_id == finding_id]
                if len(history) >= MAX_DECISIONS_PER_FINDING:
                    raise FindingLifecycleError("finding_decision_limit")
                previous = history[-1] if history else None
                if previous is not None and previous.rule_id != rule_id:
                    raise FindingLifecycleError("finding_identity_conflict")
                current_status = effective_status(previous, now=now) if previous is not None else "open"
                if previous is not None and status not in ALLOWED_TRANSITIONS[current_status]:
                    raise FindingLifecycleError("invalid_transition")

            records: list[FindingDecisionRecord] = []
            identifiers: set[str] = set()
            for project_id, finding_id, rule_id in items:
                previous = next(
                    (record for record in reversed(by_project[project_id]) if record.finding_id == finding_id),
                    None,
                )
                decision_id = self._new_batch_id(identifiers)
                identifiers.add(decision_id)
                records.append(FindingDecisionRecord(
                    contract_version=FINDING_DECISION_CONTRACT_VERSION,
                    id=decision_id,
                    organization_id=organization_id,
                    project_id=project_id,
                    finding_id=finding_id,
                    rule_id=rule_id,
                    status=status,
                    reason=safe_reason,
                    comment=safe_comment,
                    assignee_user_id=assignee_user_id,
                    assignee_username=assignee_username,
                    actor_id=actor_id,
                    actor_username=actor_username,
                    actor_role=actor_role,
                    review_at=normalized_review_at,
                    created_at=now,
                    previous_decision_id=previous.id if previous is not None else None,
                    batch_operation_id=operation_id,
                ))
            try:
                journal = self._prepare_batch_unlocked(
                    operation_id=operation_id,
                    organization_id=organization_id,
                    request_digest=request_digest,
                    group_id=group_id,
                    records=records,
                    prepared_at=now,
                )
                self._recover_batch_operation_unlocked(journal)
            except (OSError, ValidationError, ValueError) as exc:
                raise FindingLifecycleError("store_unavailable") from exc
            return records, False

    def list_for_projects(
        self, organization_id: str, project_ids: set[str]
    ) -> dict[str, list[FindingDecisionRecord]]:
        """Read portfolio decision state once instead of rescanning per project."""

        if (
            not 0 <= len(project_ids) <= MAX_PORTFOLIO_QUERY_PROJECTS
            or any(len(value) != 32 or any(character not in "0123456789abcdef" for character in value) for value in project_ids)
        ):
            raise FindingLifecycleError("invalid_project_scope")
        grouped = {project_id: [] for project_id in project_ids}
        if not project_ids:
            return grouped
        with storage_lock(self.settings):
            for record in self._visible_records_unlocked():
                if record.organization_id == organization_id and record.project_id in project_ids:
                    grouped[record.project_id].append(record)
        return {
            project_id: validated_decision_chains(records)
            for project_id, records in grouped.items()
        }

    def report_snapshot(
        self, organization_id: str, *, cutoff: datetime
    ) -> dict[str, list[FindingDecisionRecord]]:
        """Load one bounded owner decision snapshot for a long-running report."""

        if cutoff.tzinfo is None or cutoff.utcoffset() is None:
            raise FindingLifecycleError("invalid_project_scope")
        grouped: dict[str, list[FindingDecisionRecord]] = {}
        with storage_lock(self.settings):
            records = self._visible_records_unlocked()
        for record in records:
            if record.organization_id != organization_id:
                continue
            if record.created_at > cutoff.astimezone(timezone.utc):
                raise FindingLifecycleError("snapshot_changed")
            grouped.setdefault(record.project_id, []).append(record)
        return {
            project_id: validated_decision_chains(project_records)
            for project_id, project_records in grouped.items()
        }

    def delete_project(self, organization_id: str, project_id: str) -> int:
        """Delete only the validated decision chain bound to one organization/project."""

        with storage_lock(self.settings):
            records = self._list_for_project_unlocked(organization_id, project_id)
            source_revision = self.risk_trend_source_clock.raw_source_revision()
            for record in records:
                self._path(record.id).unlink(missing_ok=True)
            if records:
                _fsync_directory(self.directory)
            removed_ids = {record.id for record in records}
            for receipt_path, receipt in self._load_batch_receipts_unlocked().values():
                retained_ids = [value for value in receipt.decision_ids if value not in removed_ids]
                if len(retained_ids) == len(receipt.decision_ids):
                    continue
                if not retained_ids:
                    receipt_path.unlink(missing_ok=True)
                    _fsync_directory(self.batch_directory)
                    continue
                updated = receipt.model_copy(update={
                    "decision_ids": retained_ids,
                    "decision_digests": {
                        value: receipt.decision_digests[value] for value in retained_ids
                    },
                    "replayable": False,
                })
                _durable_write_json(receipt_path, updated.model_dump(mode="json"))
            if records:
                self.risk_trend_source_clock.record_mutation(
                    organization_id,
                    previous_source_revision=source_revision,
                )
            return len(records)

    def lifecycle_for_findings(
        self,
        organization_id: str,
        project_id: str,
        findings: Iterable[NormalizedFinding],
    ) -> dict[str, FindingLifecycleState]:
        now = self._now()
        records = self.list_for_project(organization_id, project_id)
        by_finding: dict[str, list[FindingDecisionRecord]] = {}
        for record in records:
            by_finding.setdefault(record.finding_id, []).append(record)

        states: dict[str, FindingLifecycleState] = {}
        for finding in findings:
            history = by_finding.get(finding.id, [])
            current = history[-1] if history else None
            review_overdue = current is not None and is_expired(current, now=now)
            status = effective_status(current, now=now) if current is not None else "open"
            states[finding.id] = FindingLifecycleState(
                finding_id=finding.id,
                rule_id=finding.rule_id,
                current_status=status,
                has_decision=current is not None,
                needs_review=current is not None and status == "in_review",
                review_overdue=review_overdue,
                current_decision=current,
                history=list(reversed(history)),
            )
        return states

    def _list_for_project_unlocked(self, organization_id: str, project_id: str) -> list[FindingDecisionRecord]:
        records = [
            record
            for record in self._visible_records_unlocked()
            if record.organization_id == organization_id and record.project_id == project_id
        ]
        return validated_decision_chains(records)

    def _prepare_batch_unlocked(
        self,
        *,
        operation_id: str,
        organization_id: str,
        request_digest: str,
        group_id: str,
        records: list[FindingDecisionRecord],
        prepared_at: datetime,
    ) -> RemediationBatchJournal:
        staging = self._batch_staging_path(operation_id)
        if staging.exists() or staging.is_symlink():
            raise FindingLifecycleError("batch_state_invalid")
        staging.mkdir(mode=0o700)
        _fsync_directory(self.batch_journal_directory)
        digests = {record.id: _decision_digest(record) for record in records}
        try:
            for record in records:
                _durable_write_json(staging / f"{record.id}.json", record.model_dump(mode="json"))
            self._batch_step("staged")
            journal = RemediationBatchJournal(
                operation_id=operation_id,
                organization_id=organization_id,
                request_digest=request_digest,
                group_id=group_id,
                decision_ids=[record.id for record in records],
                decision_digests=digests,
                prepared_at=prepared_at,
            )
            _durable_write_json(self._batch_journal_path(operation_id), journal.model_dump(mode="json"))
            self._batch_step("prepared")
            return journal
        except Exception:
            if not self._batch_journal_path(operation_id).exists():
                self._remove_staging_unlocked(staging)
            raise

    def _recover_batch_unlocked(self, operation_id: str) -> None:
        path = self._batch_journal_path(operation_id)
        if path.is_symlink() or not path.is_file():
            raise FindingLifecycleError("batch_state_invalid")
        try:
            journal = RemediationBatchJournal.model_validate_json(path.read_text(encoding="utf-8"))
        except (OSError, ValidationError, ValueError) as exc:
            raise FindingLifecycleError("batch_state_invalid") from exc
        if journal.operation_id != operation_id:
            raise FindingLifecycleError("batch_state_invalid")
        self._recover_batch_operation_unlocked(journal)

    def _recover_batch_operation_unlocked(self, journal: RemediationBatchJournal) -> None:
        receipt_path = self._batch_receipt_path(journal.operation_id)
        if receipt_path.exists() or receipt_path.is_symlink():
            receipt = self._load_batch_receipt_unlocked(journal.operation_id)
            if (
                receipt.organization_id != journal.organization_id
                or receipt.request_digest != journal.request_digest
                or receipt.decision_digests != journal.decision_digests
            ):
                raise FindingLifecycleError("batch_state_invalid")
            self._cleanup_completed_batch_unlocked(journal.operation_id)
            return
        source_revision = self.risk_trend_source_clock.raw_source_revision()
        staging = self._batch_staging_path(journal.operation_id)
        if staging.is_symlink() or not staging.is_dir():
            raise FindingLifecycleError("batch_state_invalid")
        for decision_id in journal.decision_ids:
            final = self._path(decision_id)
            staged = staging / f"{decision_id}.json"
            if final.exists() or final.is_symlink():
                record = self._load_decision_path(final)
            else:
                if staged.is_symlink() or not staged.is_file():
                    raise FindingLifecycleError("batch_state_invalid")
                record = self._load_decision_path(staged)
                os.replace(staged, final)
                _fsync_directory(staging)
                _fsync_directory(self.directory)
            if (
                record.batch_operation_id != journal.operation_id
                or record.organization_id != journal.organization_id
                or _decision_digest(record) != journal.decision_digests[decision_id]
            ):
                raise FindingLifecycleError("batch_state_invalid")
            self._batch_step("decision_written")
        receipt = RemediationBatchReceipt(
            **journal.model_dump(mode="python"),
            completed_at=self._now(),
        )
        _durable_write_json(receipt_path, receipt.model_dump(mode="json"))
        self._batch_step("committed")
        self._cleanup_completed_batch_unlocked(journal.operation_id)
        self._batch_step("cleaned")
        self.risk_trend_source_clock.record_mutation(
            journal.organization_id,
            previous_source_revision=source_revision,
        )

    def _replay_batch_unlocked(
        self,
        operation_id: str,
        *,
        organization_id: str,
        request_digest: str,
    ) -> list[FindingDecisionRecord] | None:
        if not _BATCH_ID.fullmatch(operation_id) or not _BATCH_ID.fullmatch(request_digest):
            raise FindingLifecycleError("invalid_batch")
        path = self._batch_receipt_path(operation_id)
        if not path.exists() and not path.is_symlink():
            return None
        receipt = self._load_batch_receipt_unlocked(operation_id)
        if receipt.organization_id != organization_id:
            raise FindingLifecycleError("idempotency_conflict")
        if not hmac.compare_digest(request_digest, receipt.request_digest):
            raise FindingLifecycleError("idempotency_conflict")
        if not receipt.replayable:
            raise FindingLifecycleError("batch_replay_unavailable")
        records = [self._load_decision_path(self._path(value)) for value in receipt.decision_ids]
        for record in records:
            if (
                record.organization_id != organization_id
                or record.batch_operation_id != operation_id
                or _decision_digest(record) != receipt.decision_digests.get(record.id)
            ):
                raise FindingLifecycleError("batch_state_invalid")
        return records

    def _visible_records_unlocked(self) -> list[FindingDecisionRecord]:
        try:
            paths = sorted(self.directory.glob("*.json"))
        except OSError as exc:
            raise FindingLifecycleError("store_unavailable") from exc
        if len(paths) > MAX_DECISIONS_PER_PROJECT * 10:
            raise FindingLifecycleError("store_limit")
        receipts = self._load_batch_receipts_unlocked()
        records: list[FindingDecisionRecord] = []
        seen_by_batch: dict[str, set[str]] = {}
        for path in paths:
            record = self._load_decision_path(path)
            operation_id = record.batch_operation_id
            if operation_id is None:
                records.append(record)
                continue
            receipt_entry = receipts.get(operation_id)
            if receipt_entry is None:
                continue
            receipt = receipt_entry[1]
            if (
                record.id not in receipt.decision_digests
                or _decision_digest(record) != receipt.decision_digests[record.id]
                or record.organization_id != receipt.organization_id
            ):
                raise FindingLifecycleError("stored_decision_invalid")
            seen_by_batch.setdefault(operation_id, set()).add(record.id)
            records.append(record)
        for operation_id, (_path, receipt) in receipts.items():
            if seen_by_batch.get(operation_id, set()) != set(receipt.decision_ids):
                raise FindingLifecycleError("stored_decision_invalid")
        return records

    def _load_decision_path(self, path: Path) -> FindingDecisionRecord:
        if path.is_symlink() or not path.is_file() or not re.fullmatch(r"[a-f0-9]{32}", path.stem):
            raise FindingLifecycleError("stored_decision_invalid")
        try:
            record = FindingDecisionRecord.model_validate_json(path.read_text(encoding="utf-8"))
        except (OSError, ValidationError, ValueError) as exc:
            raise FindingLifecycleError("stored_decision_invalid") from exc
        if record.id != path.stem:
            raise FindingLifecycleError("stored_decision_invalid")
        return record

    def _load_batch_receipts_unlocked(self) -> dict[str, tuple[Path, RemediationBatchReceipt]]:
        result: dict[str, tuple[Path, RemediationBatchReceipt]] = {}
        try:
            paths = sorted(self.batch_directory.iterdir())
        except OSError as exc:
            raise FindingLifecycleError("store_unavailable") from exc
        for path in paths:
            if path.name == ".gitkeep":
                continue
            if path.is_symlink() or not path.is_file() or path.suffix != ".json" or not _BATCH_ID.fullmatch(path.stem):
                raise FindingLifecycleError("batch_state_invalid")
            receipt = self._load_batch_receipt_unlocked(path.stem)
            result[path.stem] = (path, receipt)
        return result

    def _load_batch_receipt_unlocked(self, operation_id: str) -> RemediationBatchReceipt:
        path = self._batch_receipt_path(operation_id)
        if path.is_symlink() or not path.is_file():
            raise FindingLifecycleError("batch_state_invalid")
        try:
            receipt = RemediationBatchReceipt.model_validate_json(path.read_text(encoding="utf-8"))
        except (OSError, ValidationError, ValueError) as exc:
            raise FindingLifecycleError("batch_state_invalid") from exc
        if receipt.operation_id != operation_id:
            raise FindingLifecycleError("batch_state_invalid")
        return receipt

    def _cleanup_completed_batch_unlocked(self, operation_id: str) -> None:
        journal = self._batch_journal_path(operation_id)
        if journal.is_symlink():
            raise FindingLifecycleError("batch_state_invalid")
        journal.unlink(missing_ok=True)
        _fsync_directory(self.batch_journal_directory)
        self._remove_staging_unlocked(self._batch_staging_path(operation_id))

    def _cleanup_orphan_batches_unlocked(self) -> None:
        receipt_ids = set(self._load_batch_receipts_unlocked())
        journal_ids = {
            path.stem for path in self.batch_journal_directory.glob("*.json")
            if _BATCH_ID.fullmatch(path.stem)
        }
        removed_record = False
        for path in self.directory.glob("*.json"):
            record = self._load_decision_path(path)
            if record.batch_operation_id and record.batch_operation_id not in receipt_ids | journal_ids:
                path.unlink()
                removed_record = True
        if removed_record:
            _fsync_directory(self.directory)
        for path in self.batch_journal_directory.glob(".*.staging"):
            operation_id = path.name[1:-8]
            if _BATCH_ID.fullmatch(operation_id) and operation_id not in journal_ids:
                self._remove_staging_unlocked(path)

    @staticmethod
    def _remove_staging_unlocked(path: Path) -> None:
        if not path.exists() and not path.is_symlink():
            return
        if path.is_symlink() or not path.is_dir():
            raise FindingLifecycleError("batch_state_invalid")
        for child in path.iterdir():
            if child.is_symlink() or not child.is_file():
                raise FindingLifecycleError("batch_state_invalid")
            child.unlink()
        _fsync_directory(path)
        path.rmdir()
        _fsync_directory(path.parent)

    def _batch_step(self, name: str) -> None:
        if self._after_batch_step is not None:
            self._after_batch_step(name)

    def _batch_journal_path(self, operation_id: str) -> Path:
        if not _BATCH_ID.fullmatch(operation_id):
            raise FindingLifecycleError("invalid_batch")
        return self.batch_journal_directory / f"{operation_id}.json"

    def _batch_staging_path(self, operation_id: str) -> Path:
        if not _BATCH_ID.fullmatch(operation_id):
            raise FindingLifecycleError("invalid_batch")
        return self.batch_journal_directory / f".{operation_id}.staging"

    def _batch_receipt_path(self, operation_id: str) -> Path:
        if not _BATCH_ID.fullmatch(operation_id):
            raise FindingLifecycleError("invalid_batch")
        return self.batch_directory / f"{operation_id}.json"

    def _new_id(self) -> str:
        for _ in range(3):
            candidate = self._id_factory()
            if isinstance(candidate, str) and len(candidate) == 32 and all(character in "0123456789abcdef" for character in candidate):
                if not self._path(candidate).exists():
                    return candidate
        raise FindingLifecycleError("identifier_unavailable")

    def _new_batch_id(self, reserved: set[str]) -> str:
        for _ in range(6):
            candidate = self._id_factory()
            if (
                isinstance(candidate, str)
                and len(candidate) == 32
                and all(character in "0123456789abcdef" for character in candidate)
                and candidate not in reserved
                and not self._path(candidate).exists()
            ):
                return candidate
        raise FindingLifecycleError("identifier_unavailable")

    def _path(self, decision_id: str) -> Path:
        if len(decision_id) != 32 or any(character not in "0123456789abcdef" for character in decision_id):
            raise FindingLifecycleError("invalid_identifier")
        return self.directory / f"{decision_id}.json"

    def _now(self) -> datetime:
        current = self._now_func()
        if current.tzinfo is None:
            return current.replace(tzinfo=timezone.utc)
        return current.astimezone(timezone.utc)


def _decision_digest(record: FindingDecisionRecord) -> str:
    return hashlib.sha256(
        json.dumps(record.model_dump(mode="json"), sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _durable_write_json(path: Path, payload: dict) -> None:
    """Publish one private JSON record and durably persist its directory entry."""

    encoded = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
    temporary = path.parent / f".{path.name}.{uuid4().hex}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = None
    try:
        descriptor = os.open(temporary, flags, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            descriptor = None
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def safe_decision_text(value: str | None, *, required: bool, max_length: int) -> str | None:
    if value is None:
        if required:
            raise FindingLifecycleError("reason_required")
        return None
    if not isinstance(value, str) or len(value) > max_length:
        raise FindingLifecycleError("invalid_text")
    normalized = " ".join(value.strip().split())
    if any(ord(character) < 32 for character in normalized):
        raise FindingLifecycleError("invalid_text")
    if required and len(normalized) < 3:
        raise FindingLifecycleError("reason_required")
    if not normalized:
        return None
    redacted = " ".join(redact_active_secret_text(normalized).split())
    return redacted[:max_length]


def normalize_review_at(
    value: datetime | None,
    *,
    status: FindingDecisionStatus,
    now: datetime,
) -> datetime | None:
    if value is None:
        if status in EXCEPTION_STATUSES:
            raise FindingLifecycleError("review_date_required")
        return None
    if status not in EXCEPTION_STATUSES:
        raise FindingLifecycleError("review_date_not_allowed")
    if value.tzinfo is None or value.utcoffset() is None:
        raise FindingLifecycleError("review_date_timezone_required")
    normalized = value.astimezone(timezone.utc)
    if normalized <= now:
        raise FindingLifecycleError("review_date_not_future")
    if normalized > now + timedelta(days=MAX_EXCEPTION_REVIEW_DAYS):
        raise FindingLifecycleError("review_date_too_far")
    return normalized


def is_expired(record: FindingDecisionRecord, *, now: datetime) -> bool:
    # Contracts before PROD-103 allowed an exception without a review date.
    # Preserve its immutable record but fail it into review instead of treating
    # it as an indefinite acceptance.
    return bool(record.status in EXCEPTION_STATUSES and (record.review_at is None or record.review_at <= now))


def effective_status(record: FindingDecisionRecord, *, now: datetime) -> FindingDecisionStatus:
    return "in_review" if is_expired(record, now=now) else record.status


def validated_decision_chains(records: list[FindingDecisionRecord]) -> list[FindingDecisionRecord]:
    """Return deterministic per-finding chains or reject broken persisted history."""

    by_finding: dict[str, list[FindingDecisionRecord]] = {}
    for record in records:
        by_finding.setdefault(record.finding_id, []).append(record)

    ordered: list[FindingDecisionRecord] = []
    for finding_id in sorted(by_finding):
        items = by_finding[finding_id]
        by_id = {item.id: item for item in items}
        if len(by_id) != len(items):
            raise FindingLifecycleError("stored_decision_invalid")
        roots = [item for item in items if item.previous_decision_id is None]
        if len(roots) != 1:
            raise FindingLifecycleError("stored_decision_invalid")
        child_by_parent: dict[str, FindingDecisionRecord] = {}
        for item in items:
            parent_id = item.previous_decision_id
            if parent_id is None:
                continue
            if parent_id not in by_id or parent_id in child_by_parent:
                raise FindingLifecycleError("stored_decision_invalid")
            child_by_parent[parent_id] = item

        current = roots[0]
        chain: list[FindingDecisionRecord] = []
        while current.id not in {item.id for item in chain}:
            chain.append(current)
            successor = child_by_parent.get(current.id)
            if successor is None:
                break
            current = successor
        if len(chain) != len(items):
            raise FindingLifecycleError("stored_decision_invalid")
        if any(item.rule_id != chain[0].rule_id for item in chain):
            raise FindingLifecycleError("stored_decision_invalid")
        ordered.extend(chain)
    return ordered


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)
