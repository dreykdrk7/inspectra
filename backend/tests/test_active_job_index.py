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
from app.models import JobRecord
from app.storage import JobStore


NOW = datetime(2026, 9, 9, 12, tzinfo=timezone.utc)
OWNER_A = "a" * 32
OWNER_B = "b" * 32


def _settings(tmp_path) -> Settings:
    settings = Settings(data_dir=tmp_path, tool_runner_url="http://audit-tools:8081")
    settings.ensure_directories()
    return settings


def _record(
    index: int,
    *,
    owner_id: str,
    asset_id: str,
    status: str = "completed",
    result: dict | None = None,
    idempotency_key_sha256: str | None = None,
    project_id: str | None = None,
    file_id: str | None = None,
) -> JobRecord:
    at = NOW + timedelta(microseconds=index)
    return JobRecord(
        id=f"{index + 1:032x}", owner_id=owner_id, active_asset_id=asset_id,
        audit_type="active_dns_inventory", status=status, created_at=at, updated_at=at,
        result=result,
        active_execution_idempotency_key_sha256=idempotency_key_sha256,
        project_id=project_id,
        file_id=file_id,
    )


def _write_record(settings: Settings, record: JobRecord) -> None:
    (settings.jobs_dir / f"{record.id}.json").write_text(
        json.dumps(record.model_dump(mode="json"), sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )


def test_active_job_projection_is_owner_scoped_bounded_and_meets_warm_budget(tmp_path):
    settings = _settings(tmp_path)
    selected_assets = {f"{100_000 + index:032x}" for index in range(500)}
    selected = sorted(selected_assets)
    for index in range(20_000):
        owner_id = OWNER_A if index < 19_000 else OWNER_B
        asset_id = selected[index % len(selected)]
        _write_record(settings, _record(index, owner_id=owner_id, asset_id=asset_id))

    store = JobStore(settings)
    records, total = store.active_operations_snapshot(
        owner_id=OWNER_A, asset_ids=selected_assets
    )
    assert total == 19_000
    assert len(records) == 2_000
    assert all(record.owner_id == OWNER_A for record in records)

    reads = 0
    original_loader = store._load_job_file

    def counted_loader(path):
        nonlocal reads
        reads += 1
        return original_loader(path)

    store.active_index.loader = counted_loader
    samples = []
    tracemalloc.start()
    for _index in range(20):
        started = time.perf_counter()
        warm_records, warm_total = store.active_operations_snapshot(
            owner_id=OWNER_A, asset_ids=selected_assets
        )
        samples.append(time.perf_counter() - started)
        assert len(warm_records) == 2_000
        assert warm_total == 19_000
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    assert reads == 40_000
    assert store.active_admission_available(owner_id=OWNER_A) is True
    assert reads == 40_000
    assert sorted(samples)[18] < 1.0
    assert peak < 128 * 1024 * 1024

    reads = 0
    page_samples = []
    for _index in range(20):
        started = time.perf_counter()
        page, page_total, page_cursor = store.page(owner_id=OWNER_A, page_size=100)
        page_samples.append(time.perf_counter() - started)
        assert len(page) == 100
        assert page_total == 19_000
        assert page_cursor is not None
    assert reads == 2_000
    assert sorted(page_samples)[18] < 0.5


def test_active_job_projection_tracks_update_delete_and_cross_process_write(tmp_path):
    settings = _settings(tmp_path)
    asset_id = "c" * 32
    record = _record(0, owner_id=OWNER_A, asset_id=asset_id, status="failed")
    store = JobStore(settings)
    store.save(record)
    assert store.active_operations_snapshot(owner_id=OWNER_A, asset_ids={asset_id})[1] == 1

    updated = record.model_copy(update={"status": "completed", "updated_at": NOW + timedelta(seconds=1)})
    store.save(updated)
    records, total = store.active_operations_snapshot(owner_id=OWNER_A, asset_ids={asset_id})
    assert total == 1
    assert records[0].status == "completed"

    external = _record(1, owner_id=OWNER_A, asset_id=asset_id)
    _write_record(settings, external)
    records, total = store.active_operations_snapshot(owner_id=OWNER_A, asset_ids={asset_id})
    assert total == 2
    assert {item.id for item in records} == {record.id, external.id}

    store.delete(record.id, owner_id=OWNER_A)
    records, total = store.active_operations_snapshot(owner_id=OWNER_A, asset_ids={asset_id})
    assert total == 1
    assert [item.id for item in records] == [external.id]


def test_terminal_retention_is_indexed_batched_retryable_and_race_safe(
    tmp_path, monkeypatch
):
    settings = _settings(tmp_path)
    asset_id = "c" * 32
    cutoff = NOW + timedelta(microseconds=136)
    expired_owner_a_ids: set[str] = set()
    foreign_expired_id = f"{19_001:032x}"
    old_live_id = f"{501:032x}"
    for index in range(20_000):
        owner_id = OWNER_A if index < 19_000 else OWNER_B
        record = _record(index, owner_id=owner_id, asset_id=asset_id)
        if index <= 136:
            expired_owner_a_ids.add(record.id)
        elif index == 500:
            old_at = NOW - timedelta(days=2)
            record = record.model_copy(
                update={"status": "running", "created_at": old_at, "updated_at": old_at}
            )
        elif index == 19_000:
            old_at = NOW - timedelta(days=2)
            record = record.model_copy(
                update={"created_at": old_at, "updated_at": old_at}
            )
        _write_record(settings, record)

    assert JobStore(settings).active_index.global_inflight_count() == 1
    store = JobStore(settings)
    assert store.active_index.ready() is True
    reads = 0
    original_loader = store._load_job_file

    def counted_loader(path):
        nonlocal reads
        reads += 1
        return original_loader(path)

    store.active_index.loader = counted_loader
    monkeypatch.setattr(store, "_load_job_file", counted_loader)
    original_glob = Path.glob

    def guarded_glob(path, pattern):
        if path == settings.jobs_dir:
            raise AssertionError("steady-state retention must not glob retained jobs")
        return original_glob(path, pattern)

    monkeypatch.setattr(Path, "glob", guarded_glob)
    samples = []
    tracemalloc.start()
    for _index in range(20):
        started = time.perf_counter()
        candidates = store.active_index.expired_terminal_records(
            cutoff=cutoff, owner_id=OWNER_A, limit=100
        )
        samples.append(time.perf_counter() - started)
        assert len(candidates) == 100
        assert all(item.id in expired_owner_a_ids for item in candidates)
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert reads == 2_000
    assert sorted(samples)[18] < 0.5
    assert peak < 32 * 1024 * 1024

    selected_batch_sizes: list[int] = []
    original_select = store.active_index.expired_terminal_records

    def counted_select(**kwargs):
        selected = original_select(**kwargs)
        selected_batch_sizes.append(len(selected))
        return selected

    monkeypatch.setattr(store.active_index, "expired_terminal_records", counted_select)
    reads = 0

    def fail_callback(_record):
        raise RuntimeError("fixture callback failed")

    with pytest.raises(RuntimeError, match="fixture callback failed"):
        store.purge_expired_terminal(
            cutoff, owner_id=OWNER_A, before_delete=fail_callback, batch_size=100
        )
    assert selected_batch_sizes == [100]
    assert reads == 100
    assert all(store.get(job_id).owner_id == OWNER_A for job_id in expired_owner_a_ids)

    selected_batch_sizes.clear()
    reads = 0
    changed_id: str | None = None
    concurrent_recent = _record(30_000, owner_id=OWNER_A, asset_id=asset_id)

    def change_first_candidate(record):
        nonlocal changed_id
        if changed_id is not None:
            return
        changed_id = record.id
        changed_at = NOW + timedelta(days=1)
        store.save(
            record.model_copy(
                update={
                    "status": "running",
                    "updated_at": changed_at,
                    "finished_at": None,
                }
            )
        )
        store.save(concurrent_recent)

    deleted = store.purge_expired_terminal(
        cutoff, owner_id=OWNER_A, before_delete=change_first_candidate, batch_size=100
    )

    assert selected_batch_sizes == [100, 37, 0]
    # One additional authoritative read belongs to the simulated concurrent
    # terminal-to-running update; retention itself reads each candidate twice.
    assert reads == 137 * 2 + 1
    assert changed_id is not None
    assert {item.id for item in deleted} == expired_owner_a_ids - {changed_id}
    assert store.get(changed_id).status == "running"
    assert store.get(old_live_id).status == "running"
    assert store.get(concurrent_recent.id).status == "completed"
    assert store.get(foreign_expired_id).owner_id == OWNER_B
    with sqlite3.connect(store.active_index.path) as connection:
        indexed_ids = {
            str(row[0])
            for row in connection.execute("SELECT job_id FROM active_job_index")
        }
    assert not ({item.id for item in deleted} & indexed_ids)
    assert {changed_id, old_live_id, concurrent_recent.id, foreign_expired_id} <= indexed_ids


def test_active_job_projection_selects_only_latest_failed_or_degraded_capability(tmp_path):
    settings = _settings(tmp_path)
    failed_asset = "c" * 32
    recovered_asset = "d" * 32
    degraded_asset = "e" * 32
    records = [
        _record(0, owner_id=OWNER_A, asset_id=failed_asset, status="failed"),
        _record(1, owner_id=OWNER_A, asset_id=recovered_asset, status="failed"),
        _record(2, owner_id=OWNER_A, asset_id=recovered_asset),
        _record(
            3,
            owner_id=OWNER_A,
            asset_id=degraded_asset,
            result={"status": "partial"},
        ),
        _record(4, owner_id=OWNER_B, asset_id="f" * 32, status="failed"),
    ]
    for record in records:
        _write_record(settings, record)

    failed, degraded = JobStore(settings).active_attention_asset_ids(owner_id=OWNER_A)

    assert failed == {failed_asset}
    assert degraded == {degraded_asset}


def test_active_job_projection_repairs_database_corruption_but_fails_closed_on_source(tmp_path):
    settings = _settings(tmp_path)
    asset_id = "c" * 32
    record = _record(0, owner_id=OWNER_A, asset_id=asset_id)
    _write_record(settings, record)
    store = JobStore(settings)
    store.active_operations_snapshot(owner_id=OWNER_A, asset_ids={asset_id})

    with sqlite3.connect(store.active_index.path) as connection:
        connection.execute("DELETE FROM active_job_index")
    records, total = store.active_operations_snapshot(owner_id=OWNER_A, asset_ids={asset_id})
    assert total == 1
    assert [item.id for item in records] == [record.id]

    (settings.jobs_dir / f"{record.id}.json").write_text("{", encoding="utf-8")
    with pytest.raises(HTTPException) as error:
        store.active_operations_snapshot(owner_id=OWNER_A, asset_ids={asset_id})
    assert error.value.status_code == 503
    assert error.value.detail == "Active operations index is temporarily unavailable."


def test_active_job_projection_indexes_admission_recovery_and_replay_without_history_scan(
    tmp_path, monkeypatch
):
    settings = _settings(tmp_path)
    selected_asset = "c" * 32
    project_id = "e" * 32
    replay_key = "d" * 64
    for index in range(20_000):
        owner_id = OWNER_A if index < 19_000 else OWNER_B
        record = _record(
            index,
            owner_id=owner_id,
            asset_id=selected_asset if index <= 1_002 else "9" * 32,
            status="queued" if index in {0, 19_000} else "completed",
            idempotency_key_sha256=replay_key if index == 1 else None,
            project_id=project_id if index < 1_000 else None,
        )
        if index < 137:
            record = record.model_copy(update={"file_id": "1" * 32})
        if index == 2:
            record = record.model_copy(
                update={
                    "active_asset_id": None,
                    "audit_type": "manifest_basic",
                    "status": "queued",
                    "file_id": "2" * 32,
                }
            )
        if index == 3:
            record = record.model_copy(
                update={
                    "active_asset_id": None,
                    "audit_type": "project_archive_basic",
                    "status": "running",
                    "file_id": "3" * 32,
                }
            )
        if index == 0:
            record = record.model_copy(update={"file_id": "1" * 32})
        if index == 19_000:
            record = record.model_copy(update={"file_id": "4" * 32})
        _write_record(settings, record)

    store = JobStore(settings)
    assert store.active_index.admission_counts(owner_id=OWNER_A) == (4, 3)
    assert store.active_index.active_capacity_counts(
        owner_id=OWNER_A,
        active_asset_id=selected_asset,
        audit_type="active_dns_inventory",
    ) == (2, 1, 1, 2)
    assert store.has_global_admission_capacity() is True
    assert store.has_active_project_job(project_id, owner_id=OWNER_A) is True
    assert store.has_active_project_job(project_id, owner_id=OWNER_B) is False
    assert store.active_project_job_ids() == {f"{4:032x}"}
    assert store.active_index.inflight_source_reference_exists(file_id="1" * 32) is True
    assert store.active_index.inflight_source_reference_exists(file_id="2" * 32) is True
    assert store.active_index.inflight_source_reference_exists(file_id="3" * 32) is True
    assert store.active_index.inflight_source_reference_exists(file_id="4" * 32) is True
    assert store.active_index.inflight_source_reference_exists(file_id="5" * 32) is False
    with sqlite3.connect(store.active_index.path) as connection:
        columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(active_job_index)")
        }
    assert columns == {
        "job_id", "owner_id", "active_asset_id", "project_id", "audit_type", "status",
        "degraded", "active_idempotency_key_sha256", "created_at_micros",
        "updated_at_micros", "source_reference_digest", "source_deleted",
        "record_digest",
    }

    reads = 0
    original_loader = store._load_job_file

    def counted_loader(path):
        nonlocal reads
        reads += 1
        return original_loader(path)

    store.active_index.loader = counted_loader
    original_glob = Path.glob

    def guarded_glob(path, pattern):
        if path == settings.jobs_dir:
            raise AssertionError("steady-state recovery must not glob the retained job history")
        return original_glob(path, pattern)

    monkeypatch.setattr(Path, "glob", guarded_glob)
    control_samples = []
    for _index in range(20):
        started = time.perf_counter()
        assert store.has_global_admission_capacity() is True
        assert store.has_active_project_job(project_id, owner_id=OWNER_A) is True
        assert store.has_active_project_job(project_id, owner_id=OWNER_B) is False
        assert store.active_project_job_ids() == {f"{4:032x}"}
        latest = store.latest_completed_project_job(project_id, owner_id=OWNER_A)
        control_samples.append(time.perf_counter() - started)
        assert latest is not None and latest.id == f"{1_000:032x}"
    assert reads == 20
    assert sorted(control_samples)[18] < 0.25
    restarted_store = JobStore(settings)
    restarted_store.active_index.loader = counted_loader
    reads = 0
    recovery_samples = []
    for _index in range(20):
        started = time.perf_counter()
        assert restarted_store.list_queued_project_jobs() == []
        assert {item.id for item in restarted_store.list_queued_active_jobs()} == {
            f"{1:032x}",
            f"{19_001:032x}",
        }
        assert restarted_store.active_file_ids() == {
            "1" * 32,
            "2" * 32,
            "3" * 32,
            "4" * 32,
        }
        recovery_samples.append(time.perf_counter() - started)
    assert reads == 20 * 4 * 3
    assert sorted(recovery_samples)[18] < 0.5
    reads = 0
    first_active_page, active_total, active_cursor = restarted_store.page(
        owner_id=OWNER_A,
        active_asset_id=selected_asset,
        page_size=100,
    )
    assert len(first_active_page) == 100
    assert active_total == 1_001
    assert active_cursor is not None
    active_ids = {item.id for item in first_active_page}
    concurrent = _record(
        30_000,
        owner_id=OWNER_A,
        asset_id=selected_asset,
    )
    restarted_store.save(concurrent)
    while active_cursor is not None:
        active_page, page_total, active_cursor = restarted_store.page(
            owner_id=OWNER_A,
            active_asset_id=selected_asset,
            page_size=100,
            cursor=active_cursor,
        )
        assert page_total == active_total
        assert not active_ids.intersection(item.id for item in active_page)
        active_ids.update(item.id for item in active_page)
    assert len(active_ids) == active_total == 1_001
    assert concurrent.id not in active_ids
    assert reads == 1_001
    _items, _total, rebound_source_cursor = restarted_store.page(
        owner_id=OWNER_A,
        active_asset_id=selected_asset,
        page_size=100,
    )
    assert rebound_source_cursor is not None
    with pytest.raises(HTTPException) as rebound_cursor:
        restarted_store.page(
            owner_id=OWNER_A,
            active_asset_id="9" * 32,
            page_size=100,
            cursor=rebound_source_cursor,
        )
    assert rebound_cursor.value.status_code == 400
    reads = 0
    inflight_asset = restarted_store.active_asset_inflight_history(
        owner_id=OWNER_A, asset_id=selected_asset
    )
    assert [record.id for record in inflight_asset] == [f"{1:032x}"]
    assert reads == 1
    reads = 0
    deletion_samples = []
    for _index in range(20):
        started = time.perf_counter()
        deletion_records = restarted_store.active_index.records_for_active_asset(
            owner_id=OWNER_A, active_asset_id=selected_asset
        )
        deletion_samples.append(time.perf_counter() - started)
        assert len(deletion_records) == 1_002
        assert all(
            item.owner_id == OWNER_A and item.active_asset_id == selected_asset
            for item in deletion_records
        )
    assert reads == 20_040
    assert sorted(deletion_samples)[18] < 0.5
    reads = 0
    asset_history = restarted_store.active_asset_history(
        owner_id=OWNER_A, asset_id=selected_asset, limit=500
    )
    assert len(asset_history) == 500
    assert all(item.owner_id == OWNER_A and item.active_asset_id == selected_asset for item in asset_history)
    assert reads == 500
    reads = 0
    samples = []
    for _index in range(20):
        started = time.perf_counter()
        assert restarted_store.active_index.admission_counts(owner_id=OWNER_A) == (4, 3)
        assert restarted_store.active_index.active_capacity_counts(
            owner_id=OWNER_A,
            active_asset_id=selected_asset,
            audit_type="active_dns_inventory",
        ) == (2, 1, 1, 2)
        replay = restarted_store.active_index.idempotent_record(
            owner_id=OWNER_A,
            idempotency_key_sha256=replay_key,
        )
        samples.append(time.perf_counter() - started)
        assert replay is not None and replay.id == f"{2:032x}"

    assert reads == 20
    assert sorted(samples)[18] < 0.25
    assert restarted_store.active_index.idempotent_record(
        owner_id=OWNER_B,
        idempotency_key_sha256=replay_key,
    ) is None

    source_ids = {value * 32 for value in ("1", "2", "3", "4")}
    index_bytes = restarted_store.active_index.path.read_bytes()
    assert all(source_id.encode("ascii") not in index_bytes for source_id in source_ids)
    source_batch_sizes: list[int] = []
    original_source_select = restarted_store.active_index.records_for_source_references

    def counted_source_select(**kwargs):
        selected = original_source_select(**kwargs)
        source_batch_sizes.append(len(selected))
        return selected

    monkeypatch.setattr(
        restarted_store.active_index,
        "records_for_source_references",
        counted_source_select,
    )
    monkeypatch.setattr(restarted_store, "_load_job_file", counted_loader)
    reads = 0
    assert restarted_store.mark_files_deleted(source_ids, owner_id=OWNER_A) == 137
    assert source_batch_sizes == [100, 37, 0]
    assert reads == 137 * 2
    assert restarted_store.mark_files_deleted(source_ids, owner_id=OWNER_A) == 0
    assert restarted_store.get(f"{19_001:032x}").source_file_deleted_at is None
    assert all(
        restarted_store.get(job_id).source_file_deleted_at is not None
        for job_id in (f"{1:032x}", f"{3:032x}", f"{4:032x}")
    )
    index_bytes = restarted_store.active_index.path.read_bytes()
    assert all(source_id.encode("ascii") not in index_bytes for source_id in source_ids)

    retry_source_id = "5" * 32
    retry_records = [
        _record(40_000 + index, owner_id=OWNER_A, asset_id=selected_asset).model_copy(
            update={"file_id": retry_source_id}
        )
        for index in range(3)
    ]
    for record in retry_records:
        restarted_store.save(record)
    original_save = restarted_store._save_unlocked
    save_calls = 0

    def fail_second_save(record):
        nonlocal save_calls
        save_calls += 1
        if save_calls == 2:
            raise OSError("simulated interrupted source marking")
        return original_save(record)

    monkeypatch.setattr(restarted_store, "_save_unlocked", fail_second_save)
    with pytest.raises(OSError, match="simulated interrupted source marking"):
        restarted_store.mark_file_deleted(retry_source_id, owner_id=OWNER_A)
    monkeypatch.setattr(restarted_store, "_save_unlocked", original_save)
    assert restarted_store.mark_file_deleted(retry_source_id, owner_id=OWNER_A) == 2
    assert all(
        restarted_store.get(record.id).source_file_deleted_at is not None
        for record in retry_records
    )


def test_job_history_page_is_bounded_owner_scoped_and_cursor_bound(tmp_path):
    settings = _settings(tmp_path)
    project_id = "c" * 32
    for index in range(205):
        _write_record(
            settings,
            _record(
                index,
                owner_id=OWNER_A if index < 200 else OWNER_B,
                asset_id=f"{100_000 + index:032x}",
                status="failed" if index % 2 else "completed",
                project_id=project_id if index < 150 else None,
            ),
        )
    store = JobStore(settings)
    first, total, cursor = store.page(owner_id=OWNER_A, page_size=100)
    assert len(first) == 100
    assert total == 200
    assert cursor is not None

    reads = 0
    original_loader = store._load_job_file

    def counted_loader(path):
        nonlocal reads
        reads += 1
        return original_loader(path)

    store.active_index.loader = counted_loader

    inserted = _record(
        10_000,
        owner_id=OWNER_A,
        asset_id="e" * 32,
        project_id=project_id,
    )
    store.save(inserted)
    second, second_total, next_cursor = store.page(
        owner_id=OWNER_A, page_size=100, cursor=cursor
    )
    assert len(second) == 100
    assert second_total == 200
    assert next_cursor is None
    assert reads == 100
    assert not ({item.id for item in first} & {item.id for item in second})
    assert inserted.id not in {item.id for item in second}

    reads = 0
    project_items, project_total, _project_cursor = store.page(
        owner_id=OWNER_A,
        page_size=100,
        project_id=project_id,
        status_filter="failed",
    )
    assert project_total == 75
    assert len(project_items) == 75
    assert reads == 75
    assert all(item.project_id == project_id and item.status == "failed" for item in project_items)

    with pytest.raises(HTTPException) as changed_filter:
        store.page(owner_id=OWNER_A, page_size=100, cursor=cursor, status_filter="failed")
    assert changed_filter.value.status_code == 400
    with pytest.raises(HTTPException) as foreign_owner:
        store.page(owner_id=OWNER_B, page_size=100, cursor=cursor)
    assert foreign_owner.value.status_code == 400
