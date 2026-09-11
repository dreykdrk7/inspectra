from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor
import sqlite3

import pytest

from app.automation_tokens import AutomationTokenError, AutomationTokenStore


def test_automation_token_expires_and_never_persists_plaintext(tmp_path):
    now = [datetime(2026, 9, 7, 12, 0, tzinfo=timezone.utc)]
    store = AutomationTokenStore(
        tmp_path / "auth.sqlite3",
        now_func=lambda: now[0],
        token_bytes_func=lambda: "a" * 43,
    )
    record, plaintext = store.create(
        name="CI pipeline",
        organization_id="local-admin",
        project_id="1" * 32,
        scopes=("project:scan", "project:read", "project:scan"),
        created_by="local-admin",
        lifetime_seconds=300,
    )

    assert record.scopes == ("project:read", "project:scan")
    assert store.authenticate(plaintext).project_id == "1" * 32
    assert plaintext.encode() not in (tmp_path / "auth.sqlite3").read_bytes()
    now[0] += timedelta(seconds=301)
    assert store.authenticate(plaintext) is None


def test_automation_token_rejects_invalid_scope_and_rate_limits_durably(tmp_path):
    store = AutomationTokenStore(tmp_path / "auth.sqlite3", token_bytes_func=lambda: "b" * 43)
    with pytest.raises(AutomationTokenError, match="invalid_scopes"):
        store.create(
            name="Unsafe token",
            organization_id="local-admin",
            project_id="2" * 32,
            scopes=("administrator",),
            created_by="local-admin",
            lifetime_seconds=300,
        )

    _record, plaintext = store.create(
        name="Bounded token",
        organization_id="local-admin",
        project_id="2" * 32,
        scopes=("project:read",),
        created_by="local-admin",
        lifetime_seconds=300,
    )
    with sqlite3.connect(tmp_path / "auth.sqlite3") as connection:
        connection.execute("UPDATE automation_tokens SET rate_window_requests = 600")
    with pytest.raises(AutomationTokenError, match="rate_limited"):
        store.authenticate(plaintext)


def test_rotation_allows_two_active_concurrently_and_preserves_coarse_usage(tmp_path):
    now = [datetime(2026, 9, 7, 12, 34, 56, tzinfo=timezone.utc)]
    secret_counter = iter(("c" * 43, "d" * 43, "e" * 43))
    store = AutomationTokenStore(
        tmp_path / "auth.sqlite3",
        now_func=lambda: now[0],
        token_bytes_func=lambda: next(secret_counter),
    )
    common = {
        "organization_id": "a" * 32,
        "project_id": "1" * 32,
        "scopes": ("project:read", "project:scan", "report:read"),
        "created_by": "2" * 32,
        "lifetime_seconds": 86_400,
    }
    first, first_secret = store.create(name="Pipeline current", **common)
    second, _second_secret = store.create(name="Pipeline replacement", **common)
    with pytest.raises(AutomationTokenError, match="active_limit"):
        store.create(name="Unexpected third token", **common)

    restarted = AutomationTokenStore(
        tmp_path / "auth.sqlite3",
        now_func=lambda: now[0],
        token_bytes_func=lambda: next(secret_counter),
    )
    with pytest.raises(AutomationTokenError, match="active_limit"):
        restarted.create(name="Still bounded after restart", **common)
    assert restarted.authenticate(first_secret) is not None
    first_after_use = restarted.get(common["organization_id"], first.token_id)
    assert first_after_use.last_used_at == datetime(2026, 9, 7, 12, 0, tzinfo=timezone.utc)
    now[0] += timedelta(minutes=10)
    assert restarted.authenticate(first_secret) is not None
    assert restarted.get(common["organization_id"], first.token_id).last_used_at == first_after_use.last_used_at

    restarted.revoke(common["organization_id"], first.token_id)
    third, _third_secret = restarted.create(name="Pipeline next rotation", **common)
    assert {item.token_id for item in restarted.list(common["organization_id"]) if item.revoked_at is None} == {
        second.token_id,
        third.token_id,
    }


def test_active_limit_is_atomic_and_inactive_purge_is_organization_scoped(tmp_path):
    now = [datetime(2026, 9, 7, 12, tzinfo=timezone.utc)]
    database = tmp_path / "auth.sqlite3"
    seed = AutomationTokenStore(database, now_func=lambda: now[0])
    common = {
        "project_id": "3" * 32,
        "scopes": ("project:scan",),
        "created_by": "4" * 32,
        "lifetime_seconds": 300,
    }

    def create(index: int):
        local = AutomationTokenStore(database, now_func=lambda: now[0])
        try:
            return local.create(name=f"Concurrent {index}", organization_id="a" * 32, **common)[0]
        except AutomationTokenError as exc:
            return exc.code

    with ThreadPoolExecutor(max_workers=3) as pool:
        outcomes = list(pool.map(create, range(3)))
    assert sum(not isinstance(item, str) for item in outcomes) == 2
    assert outcomes.count("active_limit") == 1

    other, _secret = seed.create(name="Other organization", organization_id="b" * 32, **common)
    now[0] += timedelta(days=31)
    assert seed.purge_inactive("a" * 32, cutoff=now[0] - timedelta(days=30)) == 2
    assert seed.list("a" * 32) == []
    assert seed.get("b" * 32, other.token_id).token_id == other.token_id
