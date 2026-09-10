from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from types import SimpleNamespace

import pytest

import app.project_action_inbox as project_action_inbox_module
from app.config import load_settings
from app.project_action_inbox import (
    PROJECT_ACTION_INBOX_MAX_EVENTS,
    ProjectActionInboxError,
    ProjectActionInboxService,
    ProjectActionInboxStore,
)


NOW = datetime(2026, 9, 10, 12, tzinfo=timezone.utc)
ORG_A = "a" * 32
ORG_B = "b" * 32
ACTOR_A = "c" * 32
ACTOR_B = "d" * 32


def item(
    project_id: str,
    analysis_id: str,
    reasons: list[str],
    *,
    priority: str = "urgent",
    name: str = "Private display name",
):
    project = SimpleNamespace(id=project_id, name=name, updated_at=NOW, created_at=NOW)
    job = SimpleNamespace(id=analysis_id, updated_at=NOW + timedelta(minutes=1))
    return SimpleNamespace(
        project=project,
        latest_job=job,
        latest_completed_analysis=job,
        priority=priority,
        priority_reasons=reasons,
    )


class FakePortfolio:
    def __init__(self, by_organization):
        self.by_organization = by_organization

    def search(self, *, organization_id, payload):
        values = self.by_organization.get(organization_id, [])
        offset = int(payload.cursor or 0)
        page = values[offset : offset + payload.page_size]
        next_cursor = str(offset + len(page)) if offset + len(page) < len(values) else None
        return SimpleNamespace(items=page, next_cursor=next_cursor)


def service(monkeypatch, tmp_path, by_organization):
    monkeypatch.setenv("INSPECTRA_DATA_DIR", str(tmp_path))
    settings = load_settings()
    settings.ensure_directories()
    return ProjectActionInboxService(
        FakePortfolio(by_organization), ProjectActionInboxStore(settings)
    ), settings


def test_reconciles_closed_actions_without_persisting_display_or_evidence(monkeypatch, tmp_path):
    project_id = "1" * 32
    analysis_id = "2" * 32
    inbox, settings = service(
        monkeypatch,
        tmp_path,
        {
            ORG_A: [
                item(
                    project_id,
                    analysis_id,
                    ["critical_findings", "public_intelligence_stale"],
                    name="Customer secret display name",
                )
            ]
        },
    )

    page = inbox.list(ORG_A, ACTOR_A)
    stored = settings.project_action_inbox_dir / f"{ORG_A}.json"
    serialized = stored.read_text(encoding="utf-8")

    assert [value.reason for value in page.items] == [
        "critical_findings",
        "public_intelligence_stale",
    ]
    assert page.items[0].project_name == "Customer secret display name"
    assert page.unread == 2
    assert page.source_complete is True
    assert stored.stat().st_mode & 0o777 == 0o600
    for withheld in ("Customer secret display name", "evidence", "component", "path"):
        assert withheld not in serialized
    assert set(json.loads(serialized)["events"][0]) == {
        "analysis_id",
        "destination",
        "id",
        "occurred_at",
        "organization_id",
        "priority",
        "project_id",
        "read_by",
        "reason",
    }


def test_read_state_is_durable_per_user_and_new_analysis_is_unread(monkeypatch, tmp_path):
    project_id = "1" * 32
    first_analysis = "2" * 32
    portfolio = FakePortfolio({ORG_A: [item(project_id, first_analysis, ["high_findings"], priority="high")]})
    monkeypatch.setenv("INSPECTRA_DATA_DIR", str(tmp_path))
    settings = load_settings()
    settings.ensure_directories()
    inbox = ProjectActionInboxService(portfolio, ProjectActionInboxStore(settings))

    first = inbox.list(ORG_A, ACTOR_A)
    read = inbox.mark_read(ORG_A, ACTOR_A, first.items[0].id)
    restarted = ProjectActionInboxService(portfolio, ProjectActionInboxStore(settings))

    assert read.unread == 0
    assert restarted.list(ORG_A, ACTOR_A).items[0].read is True
    assert restarted.list(ORG_A, ACTOR_B).items[0].read is False

    portfolio.by_organization[ORG_A] = [item(project_id, "3" * 32, ["high_findings"], priority="high")]
    changed = restarted.list(ORG_A, ACTOR_A)
    assert changed.unread == 1
    assert changed.items[0].id != first.items[0].id


def test_two_organizations_are_isolated(monkeypatch, tmp_path):
    inbox, _settings = service(
        monkeypatch,
        tmp_path,
        {
            ORG_A: [item("1" * 32, "2" * 32, ["latest_analysis_failed"])],
            ORG_B: [item("3" * 32, "4" * 32, ["known_exploited"], name="Other tenant")],
        },
    )

    first = inbox.list(ORG_A, ACTOR_A)
    second = inbox.list(ORG_B, ACTOR_A)

    assert {value.project_id for value in first.items} == {"1" * 32}
    assert {value.project_id for value in second.items} == {"3" * 32}
    with pytest.raises(ProjectActionInboxError, match="action_not_found"):
        inbox.mark_read(ORG_A, ACTOR_A, second.items[0].id)

    assert inbox.store.remove_project(ORG_A, "1" * 32) == 1
    assert inbox.store.remove_project(ORG_A, "1" * 32) == 0
    assert inbox.store._load(ORG_A).events == ()
    assert inbox.list(ORG_A, ACTOR_A).total == 1  # authoritative source restores current actions
    assert inbox.list(ORG_B, ACTOR_A).total == 1


def test_corrupt_state_fails_closed_and_explicit_rebuild_recovers(monkeypatch, tmp_path):
    inbox, settings = service(
        monkeypatch,
        tmp_path,
        {ORG_A: [item("1" * 32, "2" * 32, ["no_baseline"], priority="review")]},
    )
    inbox.list(ORG_A, ACTOR_A)
    path = settings.project_action_inbox_dir / f"{ORG_A}.json"
    path.write_text('{"schema_version":1,"organization_id":"wrong"}', encoding="utf-8")

    with pytest.raises(ProjectActionInboxError, match="invalid_store"):
        inbox.list(ORG_A, ACTOR_A)

    rebuilt = inbox.list(ORG_A, ACTOR_A, rebuild=True)
    assert rebuilt.total == 1
    assert rebuilt.items[0].reason == "no_baseline"


def test_event_limit_is_explicit_and_keeps_priority_order(monkeypatch, tmp_path):
    projects = [
        item(f"{index:032x}", f"{index + 10_000:032x}", ["critical_findings", "high_findings"])
        for index in range(1, 1_011)
    ]
    inbox, _settings = service(monkeypatch, tmp_path, {ORG_A: projects})

    page = inbox.list(ORG_A, ACTOR_A, limit=200)

    assert page.total == PROJECT_ACTION_INBOX_MAX_EVENTS
    assert page.unread == PROJECT_ACTION_INBOX_MAX_EVENTS
    assert page.source_complete is False
    assert len(page.items) == 200
    assert page.items[0].priority == "urgent"


def test_interrupted_reconcile_preserves_previous_durable_state(monkeypatch, tmp_path):
    project_id = "1" * 32
    portfolio = FakePortfolio(
        {ORG_A: [item(project_id, "2" * 32, ["high_findings"], priority="high")]}
    )
    monkeypatch.setenv("INSPECTRA_DATA_DIR", str(tmp_path))
    settings = load_settings()
    settings.ensure_directories()
    inbox = ProjectActionInboxService(portfolio, ProjectActionInboxStore(settings))
    first = inbox.list(ORG_A, ACTOR_A)
    path = settings.project_action_inbox_dir / f"{ORG_A}.json"
    previous = path.read_bytes()

    portfolio.by_organization[ORG_A] = [
        item(project_id, "3" * 32, ["critical_findings"])
    ]

    def interrupted_write(_path, _payload):
        raise OSError("simulated interruption")

    monkeypatch.setattr(project_action_inbox_module, "_atomic_write_json", interrupted_write)
    with pytest.raises(ProjectActionInboxError, match="store_unavailable"):
        inbox.list(ORG_A, ACTOR_A)

    assert path.read_bytes() == previous
    restored = project_action_inbox_module.ProjectActionCollection.model_validate_json(
        previous
    )
    assert restored.events[0].id == first.items[0].id
