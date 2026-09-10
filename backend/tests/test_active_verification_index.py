from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
import time
import tracemalloc

import pytest

from app.active_asset_verification import (
    ActiveAssetVerificationError,
    ActiveAssetVerificationRecord,
    ActiveAssetVerificationStore,
)
from app.config import Settings


NOW = datetime(2026, 9, 9, 12, tzinfo=timezone.utc)
OWNER_A = "a" * 32
OWNER_B = "b" * 32


def _settings(tmp_path) -> Settings:
    settings = Settings(data_dir=tmp_path, tool_runner_url="http://audit-tools:8081")
    settings.ensure_directories()
    return settings


def _record(index: int, *, owner_id: str, asset_id: str) -> ActiveAssetVerificationRecord:
    at = NOW + timedelta(microseconds=index)
    return ActiveAssetVerificationRecord(
        id=f"{index + 1:032x}", asset_id=asset_id, organization_id=owner_id,
        actor_id=owner_id, method="manual_attestation", status="verified",
        challenge_sha256="d" * 64, created_at=at,
        challenge_expires_at=at + timedelta(minutes=15), requested_valid_days=30,
        attempts=1, last_attempt_at=at, verified_at=at,
        verification_expires_at=at + timedelta(days=30), reason_code="matched",
    )


def _write_record(settings: Settings, record: ActiveAssetVerificationRecord) -> None:
    directory = settings.data_dir / "results" / "active_asset_verifications" / record.organization_id
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"{record.id}.json").write_text(
        json.dumps(record.model_dump(mode="json"), sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )


def test_verification_projection_returns_latest_owner_scoped_records_with_bounded_reads(
    tmp_path, monkeypatch
):
    settings = _settings(tmp_path)
    selected_assets = {f"{100_000 + index:032x}" for index in range(500)}
    selected = sorted(selected_assets)
    for index in range(10_000):
        owner_id = OWNER_A if index < 9_000 else OWNER_B
        asset_id = selected[0] if owner_id == OWNER_A and index < 101 else selected[1 + index % 499]
        _write_record(settings, _record(index, owner_id=owner_id, asset_id=asset_id))

    store = ActiveAssetVerificationStore(settings, now_func=lambda: NOW)
    latest = store.latest_many(selected_assets, organization_id=OWNER_A)
    assert len(latest) == 500
    assert all(record.organization_id == OWNER_A for record in latest.values())

    reads = 0
    original_loader = store._read

    def counted_loader(path):
        nonlocal reads
        reads += 1
        return original_loader(path)

    store.index.loader = counted_loader
    samples = []
    tracemalloc.start()
    for _index in range(20):
        started = time.perf_counter()
        assert len(store.latest_many(selected_assets, organization_id=OWNER_A)) == 500
        samples.append(time.perf_counter() - started)
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    assert reads == 10_000
    assert sorted(samples)[18] < 1.0
    assert peak < 128 * 1024 * 1024

    original_glob = Path.glob

    def guarded_glob(path, pattern):
        if path.parent == store.root:
            raise AssertionError("asset lookup must not scan an organization directory")
        return original_glob(path, pattern)

    monkeypatch.setattr(Path, "glob", guarded_glob)
    restarted = ActiveAssetVerificationStore(settings, now_func=lambda: NOW)
    reads = 0

    def restarted_loader(path):
        nonlocal reads
        reads += 1
        return restarted._read(path)

    restarted.index.loader = restarted_loader
    history_samples = []
    for _index in range(20):
        started = time.perf_counter()
        history = restarted._load_asset_unlocked(selected[0], OWNER_A)
        history_samples.append(time.perf_counter() - started)
        assert len(history) == 101
        assert all(
            record.organization_id == OWNER_A and record.asset_id == selected[0]
            for record in history
        )
    assert reads == 2_020
    assert sorted(history_samples)[18] < 0.5


def test_verification_projection_tracks_writes_deletes_and_repairs_index(tmp_path):
    settings = _settings(tmp_path)
    asset_id = "c" * 32
    record = _record(0, owner_id=OWNER_A, asset_id=asset_id)
    _write_record(settings, record)
    store = ActiveAssetVerificationStore(settings, now_func=lambda: NOW)
    assert store.latest(asset_id, organization_id=OWNER_A).id == record.id

    newer = _record(1, owner_id=OWNER_A, asset_id=asset_id)
    store._write(newer)
    assert store.latest(asset_id, organization_id=OWNER_A).id == newer.id

    with sqlite3.connect(store.index.path) as connection:
        connection.execute("DELETE FROM active_verification_index")
    assert store.latest(asset_id, organization_id=OWNER_A).id == newer.id

    assert store.delete_for_asset(asset_id, organization_id=OWNER_A) == 2
    assert store.latest(asset_id, organization_id=OWNER_A) is None


def test_verification_projection_selects_failed_and_dynamically_expired_latest_state(tmp_path):
    settings = _settings(tmp_path)
    failed_asset = "c" * 32
    expired_asset = "d" * 32
    healthy_asset = "e" * 32
    failed = _record(0, owner_id=OWNER_A, asset_id=failed_asset).model_copy(
        update={"status": "failed", "verification_expires_at": None, "reason_code": "token_not_observed"}
    )
    expired = _record(1, owner_id=OWNER_A, asset_id=expired_asset).model_copy(
        update={"verification_expires_at": NOW - timedelta(seconds=1)}
    )
    healthy = _record(2, owner_id=OWNER_A, asset_id=healthy_asset)
    foreign = _record(3, owner_id=OWNER_B, asset_id="f" * 32).model_copy(
        update={"status": "failed", "verification_expires_at": None, "reason_code": "token_not_observed"}
    )
    for record in (failed, expired, healthy, foreign):
        _write_record(settings, record)

    attention = ActiveAssetVerificationStore(
        settings, now_func=lambda: NOW
    ).attention_asset_ids(organization_id=OWNER_A)

    assert attention == {failed_asset, expired_asset}


def test_verification_projection_fails_closed_for_invalid_source(tmp_path):
    settings = _settings(tmp_path)
    verification_root = settings.data_dir / "results" / "active_asset_verifications"
    verification_root.mkdir(parents=True, exist_ok=True)
    (verification_root / ".gitkeep").touch()
    asset_id = "c" * 32
    record = _record(0, owner_id=OWNER_A, asset_id=asset_id)
    _write_record(settings, record)
    store = ActiveAssetVerificationStore(settings, now_func=lambda: NOW)
    assert store.latest(asset_id, organization_id=OWNER_A) is not None
    source = settings.data_dir / "results" / "active_asset_verifications" / OWNER_A / f"{record.id}.json"
    source.write_text("{", encoding="utf-8")

    with pytest.raises(ActiveAssetVerificationError, match="verification_store_invalid"):
        store.latest(asset_id, organization_id=OWNER_A)
