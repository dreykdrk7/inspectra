from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from app.repository_import_grants import RepositoryImportGrantStore


def test_grant_is_hashed_short_lived_and_single_use(tmp_path):
    now = [datetime(2026, 9, 11, 12, 0, tzinfo=timezone.utc)]
    store = RepositoryImportGrantStore(
        tmp_path / "auth.sqlite3",
        now_func=lambda: now[0],
        token_bytes_func=lambda: "a" * 43,
    )
    record, plaintext = store.create(
        organization_id="organization-a",
        created_by="administrator-a",
        lifetime_seconds=300,
    )

    principal = store.authenticate(plaintext)
    assert principal is not None
    assert principal.organization_id == "organization-a"
    assert plaintext.encode() not in (tmp_path / "auth.sqlite3").read_bytes()
    consumed = store.consume(principal)
    assert consumed.grant_id == record.grant_id
    assert consumed.consumed_at == now[0]
    assert store.authenticate(plaintext) is None

    _record, expiring = store.create(
        organization_id="organization-a",
        created_by="administrator-a",
        lifetime_seconds=300,
    )
    now[0] += timedelta(seconds=301)
    assert store.authenticate(expiring) is None


def test_grant_consumption_is_atomic(tmp_path):
    store = RepositoryImportGrantStore(
        tmp_path / "auth.sqlite3",
        token_bytes_func=lambda: "b" * 43,
    )
    _record, plaintext = store.create(
        organization_id="organization-a",
        created_by="administrator-a",
        lifetime_seconds=300,
    )

    def spend():
        local = RepositoryImportGrantStore(tmp_path / "auth.sqlite3")
        principal = local.authenticate(plaintext)
        if principal is None:
            return "already_consumed"
        try:
            local.consume(principal)
            return "consumed"
        except Exception as exc:  # the domain code is asserted below
            return getattr(exc, "code", "unexpected")

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda _index: spend(), range(2)))
    assert outcomes.count("consumed") == 1
    assert next(item for item in outcomes if item != "consumed") in {"already_consumed", "invalid_or_consumed"}
