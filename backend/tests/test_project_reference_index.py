from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
import time
import tracemalloc

import pytest
from fastapi import HTTPException

from app.config import Settings
from app.models import (
    ProjectRecord,
    ProjectSourceSnapshot,
    current_project_responsibility,
)
from app.storage import ProjectStore


NOW = datetime(2026, 9, 9, 12, tzinfo=timezone.utc)
OWNER_A = "a" * 32
OWNER_B = "b" * 32
BASELINE = "7" * 32
SOURCE = "8" * 32


def _settings(tmp_path: Path) -> Settings:
    settings = Settings(data_dir=tmp_path, tool_runner_url="http://audit-tools:8081")
    settings.ensure_directories()
    return settings


def _project(index: int, *, owner_id: str, related: bool) -> ProjectRecord:
    project_id = f"{index + 1:032x}"
    source_id = SOURCE if related else f"{100_000 + index:032x}"
    snapshot = ProjectSourceSnapshot(
        id=f"{200_000 + index:032x}",
        source_file_id=source_id,
        source_filename="private-name.zip",
        source_sha256=f"{300_000 + index:064x}",
        created_at=NOW + timedelta(microseconds=index),
    )
    return ProjectRecord(
        id=project_id,
        owner_id=owner_id,
        name="Private project",
        source_file_id=source_id,
        source_filename="private-name.zip",
        source_sha256=snapshot.source_sha256,
        baseline_analysis_id=BASELINE if related else None,
        baseline_version=1 if related else 0,
        baseline_updated_at=NOW if related else None,
        source_snapshots=[snapshot],
        created_at=NOW,
        updated_at=NOW + timedelta(microseconds=index),
    )


def _write(settings: Settings, record: ProjectRecord) -> None:
    (settings.projects_dir / f"{record.id}.json").write_text(
        json.dumps(record.model_dump(mode="json"), sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )


def test_project_reference_cleanup_is_private_indexed_batched_and_resumable(
    tmp_path, monkeypatch
):
    settings = _settings(tmp_path)
    related_owner_a = {
        f"{index + 1:032x}" for index in range(137)
    }
    foreign_related_id = f"{4_501:032x}"
    for index in range(5_000):
        owner_id = OWNER_A if index < 4_500 else OWNER_B
        _write(
            settings,
            _project(
                index,
                owner_id=owner_id,
                related=index < 137 or index == 4_500,
            ),
        )

    bootstrap = ProjectStore(settings)
    assert len(
        bootstrap.reference_index.records_for_baselines(
            analysis_ids={BASELINE}, owner_id=OWNER_A
        )
    ) == 100
    store = ProjectStore(settings)
    assert len(
        store.reference_index.records_for_sources(
            file_ids={SOURCE}, owner_id=OWNER_A
        )
    ) == 100
    raw_index = store.reference_index.path.read_bytes()
    assert BASELINE.encode("ascii") not in raw_index
    assert SOURCE.encode("ascii") not in raw_index
    assert b"private-name.zip" not in raw_index

    reads = 0
    original_loader = store._load_project_file

    def counted_loader(path):
        nonlocal reads
        reads += 1
        return original_loader(path)

    store.reference_index.loader = counted_loader
    monkeypatch.setattr(store, "_load_project_file", counted_loader)
    original_glob = Path.glob

    def guarded_glob(path, pattern):
        if path == settings.projects_dir:
            raise AssertionError("steady-state relation cleanup must not glob projects")
        return original_glob(path, pattern)

    monkeypatch.setattr(Path, "glob", guarded_glob)
    samples = []
    tracemalloc.start()
    for _index in range(20):
        started = time.perf_counter()
        records = store.reference_index.records_for_baselines(
            analysis_ids={BASELINE}, owner_id=OWNER_A
        )
        samples.append(time.perf_counter() - started)
        assert len(records) == 100
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert reads == 2_000
    assert sorted(samples)[18] < 0.5
    assert peak < 32 * 1024 * 1024

    baseline_batches: list[int] = []
    original_baselines = store.reference_index.records_for_baselines

    def counted_baselines(**kwargs):
        records = original_baselines(**kwargs)
        baseline_batches.append(len(records))
        return records

    monkeypatch.setattr(store.reference_index, "records_for_baselines", counted_baselines)
    reads = 0
    assert store.clear_baselines_for_analysis_ids({BASELINE}, owner_id=OWNER_A) == 137
    assert baseline_batches == [100, 37, 0]
    assert reads == 137
    assert store.get(foreign_related_id).baseline_analysis_id == BASELINE
    assert all(store.get(project_id).baseline_analysis_id is None for project_id in related_owner_a)

    source_batches: list[int] = []
    original_sources = store.reference_index.records_for_sources

    def counted_sources(**kwargs):
        records = original_sources(**kwargs)
        source_batches.append(len(records))
        return records

    monkeypatch.setattr(store.reference_index, "records_for_sources", counted_sources)
    reads = 0
    assert store.mark_source_file_deleted(SOURCE, owner_id=OWNER_A) == 137
    assert source_batches == [100, 37, 0]
    assert reads == 137
    assert store.get(foreign_related_id).source_file_deleted_at is None
    assert all(
        store.get(project_id).source_file_deleted_at is not None
        for project_id in related_owner_a
    )
    assert BASELINE.encode("ascii") not in store.reference_index.path.read_bytes()
    assert SOURCE.encode("ascii") not in store.reference_index.path.read_bytes()

    retry_baseline = "9" * 32
    retry_projects = [
        _project(6_000 + index, owner_id=OWNER_A, related=False).model_copy(
            update={"baseline_analysis_id": retry_baseline, "baseline_version": 1}
        )
        for index in range(3)
    ]
    for record in retry_projects:
        store._save_unlocked(record)
    original_save = store._save_unlocked
    save_calls = 0

    def fail_second_save(record):
        nonlocal save_calls
        save_calls += 1
        if save_calls == 2:
            raise OSError("simulated interrupted project cleanup")
        return original_save(record)

    monkeypatch.setattr(store, "_save_unlocked", fail_second_save)
    with pytest.raises(OSError, match="simulated interrupted project cleanup"):
        store.clear_baselines_for_analysis_ids({retry_baseline}, owner_id=OWNER_A)
    monkeypatch.setattr(store, "_save_unlocked", original_save)
    assert store.clear_baselines_for_analysis_ids({retry_baseline}, owner_id=OWNER_A) == 2
    assert all(store.get(record.id).baseline_analysis_id is None for record in retry_projects)


def test_project_listing_is_private_paged_restart_safe_and_fails_closed_on_change(
    tmp_path, monkeypatch
):
    settings = _settings(tmp_path)
    for index in range(20_000):
        _write(
            settings,
            _project(
                index,
                owner_id=OWNER_A if index < 18_000 else OWNER_B,
                related=False,
            ),
        )

    bootstrap = ProjectStore(settings)
    first, total, cursor = bootstrap.page(owner_id=OWNER_A, page_size=100)
    assert total == 18_000
    assert len(first) == 100
    assert cursor is not None
    assert first[0].id == f"{18_000:032x}"
    assert first[-1].id == f"{17_901:032x}"
    encoded_payload, encoded_signature = cursor.split(".", 1)
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    signature_alias = (
        encoded_signature[:-1]
        + alphabet[alphabet.index(encoded_signature[-1]) + 1]
    )
    with pytest.raises(HTTPException) as noncanonical:
        bootstrap.page(
            owner_id=OWNER_A,
            page_size=100,
            cursor=f"{encoded_payload}.{signature_alias}",
        )
    assert noncanonical.value.status_code == 400
    raw_index = bootstrap.reference_index.path.read_bytes()
    assert b"Private project" not in raw_index
    assert b"private-name.zip" not in raw_index

    original_glob = Path.glob

    def guarded_glob(path, pattern):
        if path == settings.projects_dir:
            raise AssertionError("warm project pagination must not glob project metadata")
        return original_glob(path, pattern)

    monkeypatch.setattr(Path, "glob", guarded_glob)
    restarted = ProjectStore(settings)
    samples: list[float] = []
    reads = 0
    original_loader = restarted.reference_index.loader

    def counted_loader(path):
        nonlocal reads
        reads += 1
        return original_loader(path)

    restarted.reference_index.loader = counted_loader
    page_cursor = None
    tracemalloc.start()
    for expected_page in range(20):
        started = time.perf_counter()
        page, page_total, page_cursor = restarted.page(
            owner_id=OWNER_A, page_size=100, cursor=page_cursor
        )
        samples.append(time.perf_counter() - started)
        assert len(page) == 100
        assert page_total == 18_000
        assert page[0].id == f"{18_000 - expected_page * 100:032x}"
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert reads == 2_000
    assert sorted(samples)[18] < 0.5
    assert peak < 32 * 1024 * 1024

    bounded = restarted.bounded_owner_snapshot(owner_id=OWNER_A, limit=5_000)
    assert len(bounded) == 5_001
    assert all(record.owner_id == OWNER_A for record in bounded)

    foreign, foreign_total, _foreign_cursor = restarted.page(
        owner_id=OWNER_B, page_size=10
    )
    assert foreign_total == 2_000
    assert all(record.owner_id == OWNER_B for record in foreign)

    stale_cursor = cursor
    restarted._save_unlocked(
        _project(25_000, owner_id=OWNER_A, related=False)
    )
    with pytest.raises(HTTPException) as stale:
        restarted.page(owner_id=OWNER_A, page_size=100, cursor=stale_cursor)
    assert stale.value.status_code == 400

    with sqlite3.connect(restarted.reference_index.path) as connection:
        connection.execute(
            "UPDATE project_reference_index SET record_digest = ? WHERE project_id = ?",
            ("0" * 64, f"{25_001:032x}"),
        )
        connection.commit()
    corrupted = ProjectStore(settings)
    with pytest.raises(HTTPException) as unavailable:
        corrupted.page(owner_id=OWNER_A, page_size=10)
    assert unavailable.value.status_code == 503


def test_project_responsibility_is_versioned_private_indexed_and_reconciled_on_departure(
    tmp_path,
):
    settings = _settings(tmp_path)
    assigned = _project(0, owner_id=OWNER_A, related=False)
    foreign = _project(1, owner_id=OWNER_B, related=False)
    _write(settings, assigned)
    _write(settings, foreign)
    store = ProjectStore(settings)
    member_id = "member-private-123"

    updated, changed = store.set_responsibility(
        assigned.id,
        responsible_user_id=member_id,
        actor_id="team-admin",
        expected_updated_at=assigned.updated_at,
    )
    assert changed is True
    assert current_project_responsibility(updated).model_dump() == {
        "state": "assigned",
        "responsible_user_id": member_id,
        "revision": 1,
        "updated_at": updated.updated_at,
    }
    assert store.responsibility_impact(member_id, owner_id=OWNER_A) == 1
    assert store.responsibility_impact(member_id, owner_id=OWNER_B) == 0
    assert member_id.encode("ascii") not in store.reference_index.path.read_bytes()

    replayed, changed = store.set_responsibility(
        assigned.id,
        responsible_user_id=member_id,
        actor_id="team-admin",
        expected_updated_at=updated.updated_at,
    )
    assert changed is False
    assert replayed.responsibility_revisions == updated.responsibility_revisions
    with pytest.raises(HTTPException) as stale:
        store.set_responsibility(
            assigned.id,
            responsible_user_id=None,
            actor_id="team-admin",
            expected_updated_at=assigned.updated_at,
        )
    assert stale.value.status_code == 409

    restarted = ProjectStore(settings)
    assert restarted.responsibility_impact(member_id, owner_id=OWNER_A) == 1
    assert restarted.unassign_member(
        member_id,
        owner_id=OWNER_A,
        actor_id="team-admin",
    ) == 1
    after = restarted.get(assigned.id)
    assert current_project_responsibility(after).model_dump() == {
        "state": "unassigned_attention",
        "responsible_user_id": None,
        "revision": 2,
        "updated_at": after.updated_at,
    }
    assert after.responsibility_revisions[-1].state == "membership_revoked"
    assert restarted.unassign_member(
        member_id,
        owner_id=OWNER_A,
        actor_id="team-admin",
    ) == 0
    assert restarted.get(foreign.id).responsibility_revisions == []
