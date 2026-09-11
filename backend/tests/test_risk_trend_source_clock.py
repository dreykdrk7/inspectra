from __future__ import annotations

from time import perf_counter

from app.config import Settings
from app.risk_trend_source_clock import RiskTrendSourceClock, RiskTrendSourceClockError


OWNER = "local-admin"
FOREIGN = "b" * 32


def _settings(tmp_path):
    settings = Settings(data_dir=tmp_path, tool_runner_url="http://audit-tools:8081")
    settings.ensure_directories()
    return settings


def test_owner_clock_isolates_mutations_and_recovers_an_unjournaled_change(tmp_path):
    settings = _settings(tmp_path)
    clock = RiskTrendSourceClock(settings)

    assert clock.recover() is True
    owner_initial = clock.revision(OWNER)
    foreign_initial = clock.revision(FOREIGN)
    assert owner_initial != foreign_initial

    before = clock.raw_source_revision()
    marker = settings.jobs_dir / "clock-only-marker"
    marker.write_text("private-marker-canary", encoding="utf-8")
    assert clock.record_mutation(OWNER, previous_source_revision=before) == "owner_invalidated"
    owner_changed = clock.revision(OWNER)
    assert owner_changed != owner_initial
    assert clock.revision(FOREIGN) == foreign_initial

    # An out-of-band mutation cannot be assigned safely. Both owners receive
    # the same global fallback revision until startup recovery rotates an epoch.
    marker.unlink()
    fallback_owner = clock.revision(OWNER)
    fallback_foreign = clock.revision(FOREIGN)
    assert fallback_owner == fallback_foreign
    assert fallback_owner not in {owner_changed, foreign_initial}

    assert clock.recover() is True
    recovered_owner = clock.revision(OWNER)
    recovered_foreign = clock.revision(FOREIGN)
    assert recovered_owner != fallback_owner
    assert recovered_foreign != fallback_foreign
    assert recovered_owner != recovered_foreign
    assert clock.ready() is True


def test_owner_clock_rotates_all_owners_when_the_previous_revision_is_not_covered(tmp_path):
    settings = _settings(tmp_path)
    clock = RiskTrendSourceClock(settings)
    clock.recover()
    owner_initial = clock.revision(OWNER)
    foreign_initial = clock.revision(FOREIGN)

    stale_before = clock.raw_source_revision()
    (settings.projects_dir / "untracked-first-change").write_text("first", encoding="utf-8")
    actual_before_second = clock.raw_source_revision()
    (settings.jobs_dir / "tracked-second-change").write_text("second", encoding="utf-8")

    assert stale_before != actual_before_second
    assert clock.record_mutation(
        FOREIGN,
        previous_source_revision=actual_before_second,
    ) == "all_invalidated"
    assert clock.revision(OWNER) != owner_initial
    assert clock.revision(FOREIGN) != foreign_initial
    assert clock.revision(OWNER) != clock.revision(FOREIGN)
    assert clock.ready() is True


def test_corrupt_clock_reads_fall_back_without_repairing_outside_the_writer_lock(tmp_path):
    settings = _settings(tmp_path)
    clock = RiskTrendSourceClock(settings)
    clock.recover()
    clock.path.write_bytes(b"not-sqlite")

    assert clock.revision(OWNER) == clock.revision(FOREIGN)
    assert clock.path.read_bytes() == b"not-sqlite"
    assert clock.ready() is False

    assert clock.recover() is True
    assert clock.ready() is True
    assert clock.revision(OWNER) != clock.revision(FOREIGN)


def test_owner_clock_has_bounded_write_overhead_and_retains_no_source_labels(tmp_path):
    settings = _settings(tmp_path)
    clock = RiskTrendSourceClock(settings)
    clock.recover()
    samples = []

    for index in range(50):
        before = clock.raw_source_revision()
        marker = settings.jobs_dir / f"private-canary-{index}"
        started = perf_counter()
        marker.write_text("private-content-canary", encoding="utf-8")
        clock.record_mutation(OWNER, previous_source_revision=before)
        samples.append(perf_counter() - started)

        before = clock.raw_source_revision()
        started = perf_counter()
        marker.unlink()
        clock.record_mutation(OWNER, previous_source_revision=before)
        samples.append(perf_counter() - started)

    p95 = sorted(samples)[int(len(samples) * 0.95) - 1]
    assert p95 < 0.05
    retained = clock.path.read_bytes()
    assert b"private-canary" not in retained
    assert b"private-content-canary" not in retained
    assert OWNER.encode() not in retained
    assert clock.path.stat().st_mode & 0o777 == 0o600
    connection = clock._connect()
    try:
        assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "delete"
        assert connection.execute("PRAGMA synchronous").fetchone()[0] == 1
    finally:
        connection.close()


def test_owner_clock_accepts_legacy_labels_but_persists_only_an_opaque_digest(tmp_path):
    settings = _settings(tmp_path)
    clock = RiskTrendSourceClock(settings)
    clock.recover()
    before = clock.raw_source_revision()
    (settings.projects_dir / "legacy-owner-project").write_text("fixture", encoding="utf-8")

    assert clock.record_mutation(
        "legacy-owner-name",
        previous_source_revision=before,
    ) == "owner_invalidated"
    assert b"legacy-owner-name" not in clock.path.read_bytes()
    assert clock.revision("legacy-owner-name") != clock.revision(OWNER)


def test_clock_repair_failure_never_rolls_back_an_authoritative_mutation(tmp_path, monkeypatch):
    settings = _settings(tmp_path)
    clock = RiskTrendSourceClock(settings)
    clock.recover()
    before = clock.raw_source_revision()
    clock.path.write_bytes(b"not-sqlite")
    (settings.jobs_dir / "authoritative-job").write_text("fixture", encoding="utf-8")
    monkeypatch.setattr(
        clock,
        "_reset_database",
        lambda _revision: (_ for _ in ()).throw(
            RiskTrendSourceClockError("risk_trend_source_clock_invalid")
        ),
    )

    assert clock.record_mutation(
        OWNER,
        previous_source_revision=before,
    ) == "fallback_required"
    assert (settings.jobs_dir / "authoritative-job").read_text(encoding="utf-8") == "fixture"
    assert clock.ready() is False
