from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import sqlite3

import pytest

from app.adoption_metrics import AdoptionMetricsError, AdoptionMetricsStore
from app.adoption_metrics_cli import main as export_main
from app.backup import BackupError, validate_data_store
from app.config import Settings, load_settings


NOW = datetime(2026, 9, 10, 12, tzinfo=timezone.utc)


def _settings(tmp_path, *, enabled=False):
    settings = Settings(
        data_dir=tmp_path,
        tool_runner_url="http://audit-tools:8081",
        adoption_metrics_enabled=enabled,
    )
    settings.ensure_directories()
    return settings


def test_metrics_are_off_by_default_and_create_no_store(tmp_path):
    store = AdoptionMetricsStore(_settings(tmp_path))

    assert store.record_http(
        method="POST", route_template="/projects", status_code=201,
        duration_ms=12, observed_at=NOW,
    ) is False
    assert store.path.exists() is False
    payload = json.loads(store.export(observed_at=NOW))
    assert payload["enabled"] is False
    assert payload["metrics"] == []


def test_metrics_env_is_explicit_opt_in(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("INSPECTRA_ADOPTION_METRICS_ENABLED", raising=False)
    assert load_settings().adoption_metrics_enabled is False
    monkeypatch.setenv("INSPECTRA_ADOPTION_METRICS_ENABLED", "true")
    assert load_settings().adoption_metrics_enabled is True


def test_metrics_aggregate_only_closed_daily_dimensions_and_purge_old_rows(tmp_path):
    store = AdoptionMetricsStore(_settings(tmp_path, enabled=True))
    private_canary = "/projects/private-project-id/source-secret"
    assert store.record_http(
        method="POST", route_template="/projects", status_code=403,
        duration_ms=900, observed_at=NOW - timedelta(days=100),
    ) is True
    for duration in (12, 20):
        assert store.record_http(
            method="POST", route_template="/projects", status_code=201,
            duration_ms=duration, observed_at=NOW,
        ) is True
    assert store.record_http(
        method="POST", route_template=private_canary, status_code=500,
        duration_ms=1, observed_at=NOW,
    ) is False
    store.record_http(
        method="POST", route_template="/projects/import/sbom/preflight",
        status_code=422, duration_ms=550, observed_at=NOW,
    )

    exported = store.export(observed_at=NOW)
    payload = json.loads(exported)
    assert payload["privacy"] == {
        "exact_duration": False, "exact_timestamp": False,
        "external_transport": False, "organization_identifier": False,
        "project_identifier": False, "request_identifier": False,
        "source_or_component_data": False, "user_identifier": False,
    }
    assert payload["metrics"] == [
        {
            "day": "2026-09-10", "duration_bucket": "lt_100ms",
            "event_count": 2, "flow": "archive_onboarding",
            "outcome": "succeeded", "phase": "create",
        },
        {
            "day": "2026-09-10", "duration_bucket": "lt_2s",
            "event_count": 1, "flow": "sbom_onboarding",
            "outcome": "invalid", "phase": "preflight",
        },
    ]
    assert private_canary.encode() not in store.path.read_bytes()
    assert private_canary.encode() not in exported
    assert store.path.stat().st_mode & 0o777 == 0o600


def test_metrics_reject_tampered_text_and_cli_exports_locally(tmp_path, capsysbinary):
    store = AdoptionMetricsStore(_settings(tmp_path, enabled=True))
    store.record_http(
        method="POST", route_template="/projects", status_code=201,
        duration_ms=12, observed_at=NOW,
    )
    assert export_main([
        "--data-dir", str(tmp_path), "--local-export-confirmed",
    ]) == 0
    exported = json.loads(capsysbinary.readouterr().out)
    assert exported["metrics"][0]["flow"] == "archive_onboarding"
    validate_data_store(tmp_path)

    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "UPDATE adoption_metric SET flow = ?", ("PRIVATE-PROJECT-CANARY",),
        )
        connection.commit()
    with pytest.raises(AdoptionMetricsError, match="adoption_metrics_invalid"):
        store.export(observed_at=NOW)
    with pytest.raises(BackupError, match="invalid_storage_reference"):
        validate_data_store(tmp_path)
