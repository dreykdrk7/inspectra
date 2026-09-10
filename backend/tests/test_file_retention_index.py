from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import time
import tracemalloc

import pytest

from app.config import Settings
from app.models import StoredFile
from app.storage import FileStore


NOW = datetime(2026, 9, 9, 12, tzinfo=timezone.utc)
OWNER_A = "a" * 32
OWNER_B = "b" * 32


def _settings(tmp_path: Path) -> Settings:
    settings = Settings(data_dir=tmp_path, tool_runner_url="http://audit-tools:8081")
    settings.ensure_directories()
    return settings


def _record(index: int, *, owner_id: str, expired: bool) -> StoredFile:
    file_id = f"{index + 1:032x}"
    payload = f"fixture-{index}".encode("ascii")
    return StoredFile(
        id=file_id,
        owner_id=owner_id,
        kind="archive",
        original_filename=f"customer-secret-{index}.zip",
        stored_filename=f"{file_id}.zip",
        content_type="application/zip",
        size_bytes=len(payload),
        sha256=hashlib.sha256(payload).hexdigest(),
        created_at=NOW - timedelta(days=2) if expired else NOW + timedelta(days=2),
    )


def _write(settings: Settings, record: StoredFile, index: int) -> None:
    (settings.upload_dir / record.stored_filename).write_bytes(
        f"fixture-{index}".encode("ascii")
    )
    (settings.upload_dir / f"{record.id}.json").write_text(
        json.dumps(record.model_dump(mode="json"), sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )


def test_file_retention_is_indexed_batched_private_and_race_safe(tmp_path, monkeypatch):
    settings = _settings(tmp_path)
    expired_owner_a = {f"{index + 1:032x}" for index in range(137)}
    static_protected = f"{1:032x}"
    dynamically_protected = f"{2:032x}"
    foreign_expired = f"{9_001:032x}"
    records: dict[str, StoredFile] = {}
    for index in range(10_000):
        owner_id = OWNER_A if index < 9_000 else OWNER_B
        record = _record(
            index,
            owner_id=owner_id,
            expired=index < 137 or index == 9_000,
        )
        records[record.id] = record
        _write(settings, record, index)

    bootstrap = FileStore(settings)
    assert len(
        bootstrap.retention_index.expired_records(
            cutoff=NOW,
            protected_file_ids={static_protected},
            owner_id=OWNER_A,
        )
    ) == 100
    store = FileStore(settings)
    assert len(
        store.retention_index.expired_records(
            cutoff=NOW,
            protected_file_ids={static_protected},
            owner_id=OWNER_A,
        )
    ) == 100
    index_bytes = store.retention_index.path.read_bytes()
    assert b"customer-secret" not in index_bytes
    assert records[static_protected].sha256.encode("ascii") not in index_bytes

    reads = 0
    original_loader = store._load_metadata_file

    def counted_loader(path):
        nonlocal reads
        reads += 1
        return original_loader(path)

    store.retention_index.loader = counted_loader
    monkeypatch.setattr(store, "_load_metadata_file", counted_loader)
    original_glob = Path.glob

    def guarded_glob(path, pattern):
        if path == settings.upload_dir:
            raise AssertionError("steady-state file retention must not glob uploads")
        return original_glob(path, pattern)

    monkeypatch.setattr(Path, "glob", guarded_glob)
    samples = []
    tracemalloc.start()
    for _index in range(20):
        started = time.perf_counter()
        selected = store.retention_index.expired_records(
            cutoff=NOW,
            protected_file_ids={static_protected},
            owner_id=OWNER_A,
        )
        samples.append(time.perf_counter() - started)
        assert len(selected) == 100
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert reads == 2_000
    assert sorted(samples)[18] < 0.5
    assert peak < 32 * 1024 * 1024

    batch_sizes: list[int] = []
    original_select = store.retention_index.expired_records

    def counted_select(**kwargs):
        selected = original_select(**kwargs)
        batch_sizes.append(len(selected))
        return selected

    monkeypatch.setattr(store.retention_index, "expired_records", counted_select)
    dynamic = {dynamically_protected}

    def is_protected(file_id: str) -> bool:
        return file_id in dynamic

    def failing_callback(_record: StoredFile) -> None:
        raise RuntimeError("simulated derived cleanup failure")

    with pytest.raises(RuntimeError, match="simulated derived cleanup failure"):
        store.purge_expired(
            NOW,
            protected_file_ids={static_protected},
            owner_id=OWNER_A,
            before_delete=failing_callback,
            is_protected=is_protected,
        )
    assert batch_sizes == [100]
    assert store.get(static_protected).owner_id == OWNER_A
    assert store.get(dynamically_protected).owner_id == OWNER_A
    failed_candidate = f"{3:032x}"
    assert store.get(failed_candidate).owner_id == OWNER_A

    batch_sizes.clear()
    callback_ids: list[str] = []
    deleted = store.purge_expired(
        NOW,
        protected_file_ids={static_protected},
        owner_id=OWNER_A,
        before_delete=lambda record: callback_ids.append(record.id),
        is_protected=is_protected,
    )
    expected_deleted = expired_owner_a - {static_protected, dynamically_protected}
    assert {record.id for record in deleted} == expected_deleted
    assert set(callback_ids) == expected_deleted
    assert batch_sizes == [100, 36, 0]
    assert store.get(foreign_expired).owner_id == OWNER_B
    for protected in (static_protected, dynamically_protected):
        record = store.get(protected)
        assert store.source_path(record).exists()
    for file_id in expected_deleted:
        assert not (settings.upload_dir / f"{file_id}.json").exists()
        assert not (settings.upload_dir / records[file_id].stored_filename).exists()
