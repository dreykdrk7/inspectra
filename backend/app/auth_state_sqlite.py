from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import math
from pathlib import Path
import secrets
import sqlite3
from typing import Any

from app.auth import ADMIN_CSRF_TOKEN_BYTES, ADMIN_SESSION_ID_BYTES, AdminSession, LoginAttemptRecord


AUTH_STATE_SCHEMA_VERSION = 1
_HASH_PREFIX = "inspectra-auth-state-v1"


class SQLiteAuthStateError(RuntimeError):
    """Controlled error for isolated auth-state store failures."""


@dataclass(frozen=True)
class SQLiteAuthSession:
    operator_id: str
    auth_mode: str
    created_at: datetime
    last_seen_at: datetime
    expires_at: datetime
    revoked_at: datetime | None = None
    revocation_reason: str | None = None


@dataclass(frozen=True)
class SQLiteLoginAttempt:
    failure_count: int
    first_failed_at: datetime
    last_failed_at: datetime
    locked_until: datetime | None = None
    updated_at: datetime | None = None


class SQLiteAuthStateStore:
    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self._initialize_schema()

    def create_session(
        self,
        session_id: str,
        csrf_token: str,
        operator_id: str,
        auth_mode: str = "self_hosted_single_admin",
        *,
        expires_at: datetime | float | int,
        now: datetime | float | int | None = None,
        client_key: str | None = None,
        user_agent: str | None = None,
    ) -> SQLiteAuthSession:
        self._require_non_blank("session_id", session_id)
        self._require_non_blank("csrf_token", csrf_token)
        self._require_non_blank("operator_id", operator_id)
        self._require_non_blank("auth_mode", auth_mode)

        now_ts = _timestamp(now)
        expires_ts = _timestamp(expires_at)
        session_hash = hash_session_id(session_id)
        csrf_hash = hash_csrf_token(csrf_token)
        client_key_hash = hash_client_key(client_key) if client_key is not None else None
        user_agent_hash = _hash_value("user_agent", user_agent) if user_agent is not None else None

        self._execute(
            """
            INSERT OR REPLACE INTO auth_sessions (
                session_id_hash,
                csrf_token_hash,
                operator_id,
                auth_mode,
                created_at,
                last_seen_at,
                expires_at,
                revoked_at,
                revocation_reason,
                client_key_hash,
                user_agent_hash
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?)
            """,
            (
                session_hash,
                csrf_hash,
                operator_id,
                auth_mode,
                now_ts,
                now_ts,
                expires_ts,
                client_key_hash,
                user_agent_hash,
            ),
        )
        return SQLiteAuthSession(
            operator_id=operator_id,
            auth_mode=auth_mode,
            created_at=_datetime_from_timestamp(now_ts),
            last_seen_at=_datetime_from_timestamp(now_ts),
            expires_at=_datetime_from_timestamp(expires_ts),
        )

    def get_session(self, session_id: str | None, *, now: datetime | float | int | None = None) -> SQLiteAuthSession | None:
        if not isinstance(session_id, str) or not session_id:
            return None

        session_hash = hash_session_id(session_id)
        row = self._fetchone("SELECT * FROM auth_sessions WHERE session_id_hash = ?", (session_hash,))
        if row is None or not hmac.compare_digest(str(row["session_id_hash"]), session_hash):
            return None

        now_ts = _timestamp(now)
        if row["revoked_at"] is not None or float(row["expires_at"]) <= now_ts:
            return None

        return _session_from_row(row)

    def verify_session_csrf_token(
        self,
        session_id: str | None,
        csrf_token: str | None,
        *,
        now: datetime | float | int | None = None,
    ) -> bool:
        if not isinstance(session_id, str) or not session_id or not isinstance(csrf_token, str) or not csrf_token:
            return False

        session_hash = hash_session_id(session_id)
        row = self._fetchone(
            "SELECT session_id_hash, csrf_token_hash, expires_at, revoked_at FROM auth_sessions WHERE session_id_hash = ?",
            (session_hash,),
        )
        if row is None or not hmac.compare_digest(str(row["session_id_hash"]), session_hash):
            return False
        if row["revoked_at"] is not None or float(row["expires_at"]) <= _timestamp(now):
            return False
        return hmac.compare_digest(str(row["csrf_token_hash"]), hash_csrf_token(csrf_token))

    def update_session_csrf_token(
        self,
        session_id: str | None,
        csrf_token: str,
        *,
        now: datetime | float | int | None = None,
    ) -> bool:
        if not isinstance(session_id, str) or not session_id:
            return False
        self._require_non_blank("csrf_token", csrf_token)
        now_ts = _timestamp(now)
        cursor = self._execute(
            """
            UPDATE auth_sessions
            SET csrf_token_hash = ?, last_seen_at = ?
            WHERE session_id_hash = ?
              AND revoked_at IS NULL
              AND expires_at > ?
            """,
            (hash_csrf_token(csrf_token), now_ts, hash_session_id(session_id), now_ts),
        )
        return cursor.rowcount > 0

    def revoke_session(
        self,
        session_id: str | None,
        reason: str | None = None,
        *,
        now: datetime | float | int | None = None,
    ) -> bool:
        if not isinstance(session_id, str) or not session_id:
            return False

        cursor = self._execute(
            """
            UPDATE auth_sessions
            SET revoked_at = ?, revocation_reason = ?
            WHERE session_id_hash = ? AND revoked_at IS NULL
            """,
            (_timestamp(now), _safe_reason(reason), hash_session_id(session_id)),
        )
        return cursor.rowcount > 0

    def touch_session(self, session_id: str | None, *, now: datetime | float | int | None = None) -> bool:
        if not isinstance(session_id, str) or not session_id:
            return False

        now_ts = _timestamp(now)
        cursor = self._execute(
            """
            UPDATE auth_sessions
            SET last_seen_at = ?
            WHERE session_id_hash = ?
              AND revoked_at IS NULL
              AND expires_at > ?
            """,
            (now_ts, hash_session_id(session_id), now_ts),
        )
        return cursor.rowcount > 0

    def cleanup_sessions(
        self,
        *,
        now: datetime | float | int | None = None,
        revoked_retention_seconds: int = 0,
    ) -> int:
        now_ts = _timestamp(now)
        retention_seconds = max(0, int(revoked_retention_seconds))
        cursor = self._execute(
            """
            DELETE FROM auth_sessions
            WHERE expires_at <= ?
               OR (revoked_at IS NOT NULL AND revoked_at <= ?)
            """,
            (now_ts, now_ts - retention_seconds),
        )
        return max(0, cursor.rowcount)

    def record_login_failure(
        self,
        client_key: str,
        *,
        now: datetime | float | int | None = None,
        window_seconds: int,
        max_failures: int,
        lockout_seconds: int,
    ) -> SQLiteLoginAttempt:
        key_hash = hash_client_key(client_key)
        now_ts = _timestamp(now)
        window = max(1, int(window_seconds))
        threshold = max(1, int(max_failures))
        lockout = max(1, int(lockout_seconds))
        existing = self._fetchone("SELECT * FROM auth_login_attempts WHERE client_key_hash = ?", (key_hash,))

        if existing is None or _login_attempt_expired(existing, now_ts, window):
            failure_count = 1
            first_failed_at = now_ts
        elif existing["locked_until"] is not None and float(existing["locked_until"]) > now_ts:
            return _login_attempt_from_row(existing)
        else:
            failure_count = int(existing["failure_count"]) + 1
            first_failed_at = float(existing["first_failed_at"])

        locked_until = now_ts + lockout if failure_count >= threshold else None
        self._execute(
            """
            INSERT OR REPLACE INTO auth_login_attempts (
                client_key_hash,
                failure_count,
                first_failed_at,
                last_failed_at,
                locked_until,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (key_hash, failure_count, first_failed_at, now_ts, locked_until, now_ts),
        )
        return SQLiteLoginAttempt(
            failure_count=failure_count,
            first_failed_at=_datetime_from_timestamp(first_failed_at),
            last_failed_at=_datetime_from_timestamp(now_ts),
            locked_until=_datetime_from_timestamp(locked_until) if locked_until is not None else None,
            updated_at=_datetime_from_timestamp(now_ts),
        )

    def get_login_attempt(self, client_key: str) -> SQLiteLoginAttempt | None:
        row = self._fetchone("SELECT * FROM auth_login_attempts WHERE client_key_hash = ?", (hash_client_key(client_key),))
        if row is None:
            return None
        return _login_attempt_from_row(row)

    def reset_login_attempt(self, client_key: str) -> bool:
        cursor = self._execute(
            "DELETE FROM auth_login_attempts WHERE client_key_hash = ?",
            (hash_client_key(client_key),),
        )
        return cursor.rowcount > 0

    def count_login_attempts(self) -> int:
        row = self._fetchone("SELECT COUNT(*) AS row_count FROM auth_login_attempts")
        if row is None:
            return 0
        return max(0, int(row["row_count"]))

    def cleanup_login_attempts(
        self,
        *,
        now: datetime | float | int | None = None,
        window_seconds: int,
    ) -> int:
        now_ts = _timestamp(now)
        window = max(1, int(window_seconds))
        cursor = self._execute(
            """
            DELETE FROM auth_login_attempts
            WHERE (locked_until IS NOT NULL AND locked_until <= ?)
               OR (locked_until IS NULL AND last_failed_at + ? <= ?)
            """,
            (now_ts, window, now_ts),
        )
        return max(0, cursor.rowcount)

    def prune_login_attempts(
        self,
        *,
        max_rows: int,
        now: datetime | float | int | None = None,
    ) -> int:
        limit = max(1, int(max_rows))
        total = self.count_login_attempts()
        if total <= limit:
            return 0

        excess = total - limit
        now_ts = _timestamp(now)
        try:
            connection = self._connect()
            try:
                rows = connection.execute(
                    """
                    SELECT client_key_hash
                    FROM auth_login_attempts
                    WHERE locked_until IS NULL OR locked_until <= ?
                    ORDER BY updated_at ASC
                    LIMIT ?
                    """,
                    (now_ts, excess),
                ).fetchall()
                if not rows:
                    return 0
                deleted = 0
                for row in rows:
                    cursor = connection.execute(
                        "DELETE FROM auth_login_attempts WHERE client_key_hash = ?",
                        (row["client_key_hash"],),
                    )
                    deleted += max(0, cursor.rowcount)
                connection.commit()
                return deleted
            finally:
                connection.close()
        except sqlite3.Error as exc:
            raise SQLiteAuthStateError("SQLite auth state operation failed.") from exc

    def get_schema_version(self) -> int | None:
        row = self._fetchone("SELECT value FROM auth_state_metadata WHERE key = 'schema_version'")
        if row is None:
            return None
        try:
            return int(row["value"])
        except (TypeError, ValueError):
            return None

    def _initialize_schema(self) -> None:
        try:
            if self.db_path.parent:
                self.db_path.parent.mkdir(parents=True, exist_ok=True)
            connection = self._connect()
            try:
                connection.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS auth_sessions (
                        session_id_hash TEXT PRIMARY KEY,
                        csrf_token_hash TEXT NOT NULL,
                        operator_id TEXT NOT NULL,
                        auth_mode TEXT NOT NULL,
                        created_at REAL NOT NULL,
                        last_seen_at REAL NOT NULL,
                        expires_at REAL NOT NULL,
                        revoked_at REAL NULL,
                        revocation_reason TEXT NULL,
                        client_key_hash TEXT NULL,
                        user_agent_hash TEXT NULL
                    );
                    CREATE INDEX IF NOT EXISTS idx_auth_sessions_expires_at
                        ON auth_sessions (expires_at);
                    CREATE INDEX IF NOT EXISTS idx_auth_sessions_revoked_at
                        ON auth_sessions (revoked_at);
                    CREATE INDEX IF NOT EXISTS idx_auth_sessions_operator_id
                        ON auth_sessions (operator_id);
                    CREATE TABLE IF NOT EXISTS auth_login_attempts (
                        client_key_hash TEXT PRIMARY KEY,
                        failure_count INTEGER NOT NULL,
                        first_failed_at REAL NOT NULL,
                        last_failed_at REAL NOT NULL,
                        locked_until REAL NULL,
                        updated_at REAL NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS idx_auth_login_attempts_locked_until
                        ON auth_login_attempts (locked_until);
                    CREATE INDEX IF NOT EXISTS idx_auth_login_attempts_updated_at
                        ON auth_login_attempts (updated_at);
                    CREATE TABLE IF NOT EXISTS auth_state_metadata (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL,
                        updated_at REAL NOT NULL
                    );
                    """
                )
                connection.execute(
                    """
                    INSERT INTO auth_state_metadata (key, value, updated_at)
                    VALUES ('schema_version', ?, ?)
                    ON CONFLICT(key) DO UPDATE SET
                        value = excluded.value,
                        updated_at = excluded.updated_at
                    """,
                    (str(AUTH_STATE_SCHEMA_VERSION), _timestamp(None)),
                )
                connection.commit()
            finally:
                connection.close()
        except (OSError, sqlite3.Error) as exc:
            raise SQLiteAuthStateError("Unable to initialize SQLite auth state store.") from exc

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path, timeout=30)
        connection.row_factory = sqlite3.Row
        return connection

    def _execute(self, query: str, params: tuple[Any, ...] = ()) -> sqlite3.Cursor:
        try:
            connection = self._connect()
            try:
                cursor = connection.execute(query, params)
                connection.commit()
                return cursor
            finally:
                connection.close()
        except sqlite3.Error as exc:
            raise SQLiteAuthStateError("SQLite auth state operation failed.") from exc

    def _fetchone(self, query: str, params: tuple[Any, ...] = ()) -> sqlite3.Row | None:
        try:
            connection = self._connect()
            try:
                cursor = connection.execute(query, params)
                return cursor.fetchone()
            finally:
                connection.close()
        except sqlite3.Error as exc:
            raise SQLiteAuthStateError("SQLite auth state operation failed.") from exc

    @staticmethod
    def _require_non_blank(field_name: str, value: str) -> None:
        if not isinstance(value, str) or not value:
            raise ValueError(f"{field_name} is required")


class SQLiteAdminSessionStore:
    def __init__(self, db_path: str | Path, ttl_seconds: int, now_func=None, token_factory=None, csrf_token_factory=None) -> None:
        self.ttl_seconds = max(1, int(ttl_seconds))
        self._now_func = now_func or _utc_now
        self._token_factory = token_factory or _new_session_id
        self._csrf_token_factory = csrf_token_factory or _new_csrf_token
        self._auth_state = SQLiteAuthStateStore(db_path)
        self._csrf_token_cache: dict[str, str] = {}

    def create_admin_session(self, operator_id: str, auth_mode: str = "self_hosted_single_admin") -> AdminSession:
        now = self._now()
        session_id = self._unique_session_id()
        csrf_token = self._csrf_token_factory()
        persisted = self._auth_state.create_session(
            session_id,
            csrf_token,
            operator_id,
            auth_mode=auth_mode,
            expires_at=now + timedelta(seconds=self.ttl_seconds),
            now=now,
        )
        self._csrf_token_cache[session_id] = csrf_token
        return AdminSession(
            session_id=session_id,
            csrf_token=csrf_token,
            operator_id=persisted.operator_id,
            created_at=persisted.created_at,
            expires_at=persisted.expires_at,
            auth_mode=persisted.auth_mode,
        )

    def get_session(self, session_id: str | None) -> AdminSession | None:
        if not isinstance(session_id, str) or not session_id:
            return None
        persisted = self._auth_state.get_session(session_id, now=self._now())
        if persisted is None:
            self._csrf_token_cache.pop(session_id, None)
            return None
        return AdminSession(
            session_id=session_id,
            csrf_token=self._csrf_token_cache.get(session_id, ""),
            operator_id=persisted.operator_id,
            created_at=persisted.created_at,
            expires_at=persisted.expires_at,
            auth_mode=persisted.auth_mode,
        )

    def is_session_valid(self, session: AdminSession | None) -> bool:
        if session is None:
            return False
        persisted = self._auth_state.get_session(session.session_id, now=self._now())
        return (
            persisted is not None
            and persisted.operator_id == session.operator_id
            and persisted.auth_mode == session.auth_mode
            and persisted.expires_at == session.expires_at
        )

    def invalidate_session(self, session_id: str | None) -> bool:
        if not isinstance(session_id, str) or not session_id:
            return False
        self._csrf_token_cache.pop(session_id, None)
        return self._auth_state.revoke_session(session_id, "logout", now=self._now())

    def purge_expired_sessions(self) -> int:
        return self._auth_state.cleanup_sessions(now=self._now())

    def csrf_token_for_session(self, session: AdminSession | None) -> str | None:
        if session is None:
            return None
        cached_token = self._csrf_token_cache.get(session.session_id)
        if cached_token:
            return cached_token
        csrf_token = self._csrf_token_factory()
        if not self._auth_state.update_session_csrf_token(session.session_id, csrf_token, now=self._now()):
            return None
        self._csrf_token_cache[session.session_id] = csrf_token
        return csrf_token

    def verify_csrf_token(self, session_id: str | None, csrf_token: str | None) -> bool:
        if not isinstance(session_id, str) or not session_id or not isinstance(csrf_token, str) or not csrf_token:
            return False
        cached_token = self._csrf_token_cache.get(session_id)
        if cached_token and hmac.compare_digest(cached_token, csrf_token):
            return True
        if not self._auth_state.verify_session_csrf_token(session_id, csrf_token, now=self._now()):
            return False
        self._csrf_token_cache[session_id] = csrf_token
        return True

    def _unique_session_id(self) -> str:
        for _ in range(5):
            session_id = self._token_factory()
            if self._auth_state.get_session(session_id, now=self._now()) is None:
                return session_id
        return _new_session_id()

    def _now(self) -> datetime:
        current = self._now_func()
        if current.tzinfo is None:
            return current.replace(tzinfo=timezone.utc)
        return current.astimezone(timezone.utc)


class SQLiteLoginAttemptStore:
    def __init__(
        self,
        db_path: str | Path,
        window_seconds: int,
        max_failures: int,
        lockout_seconds: int,
        max_keys: int,
        now_func=None,
    ) -> None:
        self.window_seconds = max(1, int(window_seconds))
        self.max_failures = max(1, int(max_failures))
        self.lockout_seconds = max(1, int(lockout_seconds))
        self.max_keys = max(1, int(max_keys))
        self._now_func = now_func or _utc_now
        self._auth_state = SQLiteAuthStateStore(db_path)

    def record_failure(self, client_key: str) -> LoginAttemptRecord:
        key = self._client_key(client_key)
        now = self._now()
        record = self._auth_state.record_login_failure(
            key,
            now=now,
            window_seconds=self.window_seconds,
            max_failures=self.max_failures,
            lockout_seconds=self.lockout_seconds,
        )
        self._auth_state.prune_login_attempts(max_rows=self.max_keys, now=now)
        return _login_attempt_record_from_sqlite(key, record)

    def is_locked(self, client_key: str) -> bool:
        key = self._client_key(client_key)
        record = self._auth_state.get_login_attempt(key)
        if record is None:
            return False

        now = self._now()
        if self._is_expired(record, now):
            self.purge_expired()
            return False

        return record.locked_until is not None and record.locked_until > now

    def seconds_until_unlock(self, client_key: str) -> int:
        key = self._client_key(client_key)
        record = self._auth_state.get_login_attempt(key)
        if record is None or record.locked_until is None:
            return 0

        now = self._now()
        if record.locked_until <= now:
            self.purge_expired()
            return 0

        return max(0, math.ceil((record.locked_until - now).total_seconds()))

    def reset_success(self, client_key: str) -> bool:
        return self._auth_state.reset_login_attempt(self._client_key(client_key))

    def purge_expired(self) -> int:
        return self._auth_state.cleanup_login_attempts(now=self._now(), window_seconds=self.window_seconds)

    def failure_count(self, client_key: str) -> int:
        key = self._client_key(client_key)
        record = self._auth_state.get_login_attempt(key)
        if record is None:
            return 0
        if self._is_expired(record, self._now()):
            self.purge_expired()
            return 0
        return record.failure_count

    def record_count(self) -> int:
        return self._auth_state.count_login_attempts()

    def _is_expired(self, record: SQLiteLoginAttempt, now: datetime) -> bool:
        if record.locked_until is not None:
            return record.locked_until <= now
        return record.last_failed_at + timedelta(seconds=self.window_seconds) <= now

    def _now(self) -> datetime:
        current = self._now_func()
        if current.tzinfo is None:
            return current.replace(tzinfo=timezone.utc)
        return current.astimezone(timezone.utc)

    @staticmethod
    def _client_key(client_key: str) -> str:
        if not isinstance(client_key, str):
            return "unknown"
        normalized = client_key.strip()
        return normalized or "unknown"


def hash_session_id(session_id: str) -> str:
    return _hash_value("session", session_id)


def hash_csrf_token(csrf_token: str) -> str:
    return _hash_value("csrf", csrf_token)


def hash_client_key(client_key: str | None) -> str:
    if not isinstance(client_key, str):
        normalized = "unknown"
    else:
        normalized = client_key.strip() or "unknown"
    return _hash_value("client_key", normalized)


def _hash_value(purpose: str, value: str | None) -> str:
    if not isinstance(value, str):
        value = ""
    payload = f"{_HASH_PREFIX}:{purpose}\0{value}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _timestamp(value: datetime | float | int | None) -> float:
    if value is None:
        return datetime.now(timezone.utc).timestamp()
    if isinstance(value, datetime):
        current = value
        if current.tzinfo is None:
            current = current.replace(tzinfo=timezone.utc)
        return current.astimezone(timezone.utc).timestamp()
    return float(value)


def _datetime_from_timestamp(value: float | int) -> datetime:
    return datetime.fromtimestamp(float(value), tz=timezone.utc)


def _session_from_row(row: sqlite3.Row) -> SQLiteAuthSession:
    return SQLiteAuthSession(
        operator_id=str(row["operator_id"]),
        auth_mode=str(row["auth_mode"]),
        created_at=_datetime_from_timestamp(row["created_at"]),
        last_seen_at=_datetime_from_timestamp(row["last_seen_at"]),
        expires_at=_datetime_from_timestamp(row["expires_at"]),
        revoked_at=_datetime_from_timestamp(row["revoked_at"]) if row["revoked_at"] is not None else None,
        revocation_reason=str(row["revocation_reason"]) if row["revocation_reason"] is not None else None,
    )


def _login_attempt_from_row(row: sqlite3.Row) -> SQLiteLoginAttempt:
    return SQLiteLoginAttempt(
        failure_count=int(row["failure_count"]),
        first_failed_at=_datetime_from_timestamp(row["first_failed_at"]),
        last_failed_at=_datetime_from_timestamp(row["last_failed_at"]),
        locked_until=_datetime_from_timestamp(row["locked_until"]) if row["locked_until"] is not None else None,
        updated_at=_datetime_from_timestamp(row["updated_at"]),
    )


def _login_attempt_record_from_sqlite(client_key: str, record: SQLiteLoginAttempt) -> LoginAttemptRecord:
    return LoginAttemptRecord(
        client_key=client_key,
        failure_count=record.failure_count,
        first_failed_at=record.first_failed_at,
        last_failed_at=record.last_failed_at,
        locked_until=record.locked_until,
    )


def _login_attempt_expired(row: sqlite3.Row, now_ts: float, window_seconds: int) -> bool:
    locked_until = row["locked_until"]
    if locked_until is not None:
        return float(locked_until) <= now_ts
    return float(row["last_failed_at"]) + window_seconds <= now_ts


def _safe_reason(reason: str | None) -> str | None:
    if not isinstance(reason, str):
        return None
    normalized = reason.strip()
    if not normalized:
        return None
    return normalized[:120]


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _new_session_id() -> str:
    return secrets.token_urlsafe(ADMIN_SESSION_ID_BYTES)


def _new_csrf_token() -> str:
    return secrets.token_urlsafe(ADMIN_CSRF_TOKEN_BYTES)
