from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
import time
import tracemalloc

from app.active_recurrence import (
    ACTIVE_RECURRENCE_CONTRACT_VERSION,
    ACTIVE_RECURRENCE_IDEMPOTENCY_DOMAIN_VERSION,
    ActiveRecurrenceRecord,
    ActiveRecurrenceStore,
)
from app.config import Settings


NOW = datetime(2026, 9, 8, 10, 0, tzinfo=timezone.utc)
OWNER_A = "a" * 32
OWNER_B = "b" * 32
TARGET_ASSET = "c" * 32


def _record(position: int, *, organization_id: str, asset_id: str) -> ActiveRecurrenceRecord:
    due = position < 16
    return ActiveRecurrenceRecord(
        contract_version=ACTIVE_RECURRENCE_CONTRACT_VERSION,
        idempotency_domain_version=ACTIVE_RECURRENCE_IDEMPOTENCY_DOMAIN_VERSION,
        id=f"{position + 1:032x}",
        organization_id=organization_id,
        asset_id=asset_id,
        capability="active_dns_inventory",
        interval_days=7,
        timezone_name="UTC",
        window_weekdays=[
            "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"
        ],
        window_start_hour=0,
        window_duration_hours=24,
        authorization_revision_id="d" * 32,
        authorization_revision_digest_sha256="e" * 64,
        authorization_revision_sequence=1,
        authorization_expires_at=NOW + timedelta(days=60),
        verification_id="f" * 32,
        status="active",
        reason_code="scheduled",
        next_run_at=NOW - timedelta(minutes=position + 1) if due else NOW + timedelta(days=position + 1),
        created_at=NOW - timedelta(days=1),
        updated_at=NOW - timedelta(days=1),
        actor_id=organization_id,
        actor_role="administrator",
    )


def test_recurrence_index_bounds_global_due_and_asset_aggregate_after_restart(monkeypatch, tmp_path):
    settings = Settings(data_dir=tmp_path, tool_runner_url="http://audit-tools:8081")
    settings.ensure_directories()
    source = settings.data_dir / "results" / "active_recurrences"
    records: list[ActiveRecurrenceRecord] = []
    for position in range(10_000):
        organization_number = position // 500
        organization_id = (
            OWNER_A if organization_number == 0
            else OWNER_B if organization_number == 1
            else f"{organization_number + 1:032x}"
        )
        asset_id = TARGET_ASSET if position < 101 else f"{position + 20_000:032x}"
        record = _record(position, organization_id=organization_id, asset_id=asset_id)
        directory = source / organization_id
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        (directory / f"{record.id}.json").write_text(
            json.dumps(record.model_dump(mode="json"), sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
        records.append(record)

    built = ActiveRecurrenceStore(settings, now_func=lambda: NOW)
    assert len(built.list_due(now=NOW)) == 16
    index_path = built.index.path
    assert index_path.exists()
    index_bytes = index_path.read_bytes()
    assert ("e" * 64).encode() not in index_bytes
    assert ("f" * 32).encode() not in index_bytes

    restarted = ActiveRecurrenceStore(settings, now_func=lambda: NOW)
    original_iterdir = Path.iterdir

    def forbid_organization_scan(path):
        if path.parent == source:
            raise AssertionError("steady-state recurrence organization scan")
        return original_iterdir(path)

    monkeypatch.setattr(Path, "iterdir", forbid_organization_scan)
    tracemalloc.start()
    timings = []
    for _sample in range(20):
        started = time.perf_counter()
        due = restarted.list_due(now=NOW)
        timings.append(time.perf_counter() - started)
        assert len(due) == 16
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert sorted(timings)[18] < 0.5
    assert peak < 32 * 1024 * 1024
    assert restarted.count_for_asset_unlocked(TARGET_ASSET, organization_id=OWNER_A) == 101
    assert len(restarted.list_for_asset(TARGET_ASSET, organization_id=OWNER_A)) == 101
    assert restarted.count_for_asset_unlocked(TARGET_ASSET, organization_id=OWNER_B) == 0
    assert restarted.delete_for_asset(TARGET_ASSET, organization_id=OWNER_A) == 101
    assert restarted.count_for_asset_unlocked(TARGET_ASSET, organization_id=OWNER_A) == 0
    with sqlite3.connect(index_path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM active_recurrence_index"
        ).fetchone()[0] == 9_899
