from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import math
import re
import secrets


ADMIN_PASSWORD_HASH_SCHEME = "pbkdf2_sha256"
MIN_ADMIN_PASSWORD_HASH_ITERATIONS = 600_000
ADMIN_SESSION_COOKIE_NAME = "inspectra_session"
ADMIN_SESSION_COOKIE_SAMESITE = "lax"
ADMIN_SESSION_ID_BYTES = 32
ADMIN_CSRF_HEADER_NAME = "X-CSRF-Token"
ADMIN_CSRF_TOKEN_BYTES = 32
_ADMIN_PASSWORD_HASH_PATTERN = re.compile(
    r"^pbkdf2_sha256\$(?P<iterations>[1-9][0-9]*)\$(?P<salt>[A-Za-z0-9_.-]{16,128})\$(?P<digest>[A-Fa-f0-9]{64})$"
)


@dataclass(frozen=True)
class AdminSession:
    session_id: str
    csrf_token: str
    operator_id: str
    created_at: datetime
    expires_at: datetime
    auth_mode: str = "self_hosted_single_admin"


@dataclass(frozen=True)
class LoginAttemptRecord:
    client_key: str
    failure_count: int
    first_failed_at: datetime
    last_failed_at: datetime
    locked_until: datetime | None = None


@dataclass(frozen=True)
class SessionCookieSettings:
    name: str
    httponly: bool
    samesite: str
    secure: bool
    max_age_seconds: int
    path: str = "/"


class AdminSessionStore:
    def __init__(self, ttl_seconds: int, now_func=None, token_factory=None, csrf_token_factory=None) -> None:
        self.ttl_seconds = max(1, int(ttl_seconds))
        self._now_func = now_func or _utc_now
        self._token_factory = token_factory or _new_session_id
        self._csrf_token_factory = csrf_token_factory or _new_csrf_token
        self._sessions: dict[str, AdminSession] = {}

    def create_admin_session(self, operator_id: str, auth_mode: str = "self_hosted_single_admin") -> AdminSession:
        now = self._now()
        session = AdminSession(
            session_id=self._unique_session_id(),
            csrf_token=self._new_session_csrf_token(),
            operator_id=operator_id,
            created_at=now,
            expires_at=now + timedelta(seconds=self.ttl_seconds),
            auth_mode=auth_mode,
        )
        self._sessions[session.session_id] = session
        return session

    def get_session(self, session_id: str | None) -> AdminSession | None:
        if not isinstance(session_id, str) or not session_id:
            return None

        session = self._sessions.get(session_id)
        if session is None:
            return None

        if not self.is_session_valid(session):
            self._sessions.pop(session_id, None)
            return None

        return session

    def is_session_valid(self, session: AdminSession | None) -> bool:
        if session is None:
            return False
        stored_session = self._sessions.get(session.session_id)
        return stored_session == session and session.expires_at > self._now()

    def invalidate_session(self, session_id: str | None) -> bool:
        if not isinstance(session_id, str) or not session_id:
            return False
        return self._sessions.pop(session_id, None) is not None

    def purge_expired_sessions(self) -> int:
        expired_session_ids = [
            session_id
            for session_id, session in self._sessions.items()
            if not self.is_session_valid(session)
        ]
        for session_id in expired_session_ids:
            self._sessions.pop(session_id, None)
        return len(expired_session_ids)

    def _now(self) -> datetime:
        current = self._now_func()
        if current.tzinfo is None:
            return current.replace(tzinfo=timezone.utc)
        return current.astimezone(timezone.utc)

    def _unique_session_id(self) -> str:
        for _ in range(5):
            session_id = self._token_factory()
            if session_id not in self._sessions:
                return session_id
        return _new_session_id()

    def _new_session_csrf_token(self) -> str:
        return self._csrf_token_factory()


class LoginAttemptStore:
    def __init__(
        self,
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
        self._records: dict[str, LoginAttemptRecord] = {}

    def record_failure(self, client_key: str) -> LoginAttemptRecord:
        key = self._client_key(client_key)
        now = self._now()
        existing = self._records.get(key)

        if existing is None or self._is_expired(existing, now):
            locked_until = None
            if self.max_failures <= 1:
                locked_until = now + timedelta(seconds=self.lockout_seconds)
            record = LoginAttemptRecord(
                client_key=key,
                failure_count=1,
                first_failed_at=now,
                last_failed_at=now,
                locked_until=locked_until,
            )
        elif existing.locked_until is not None and existing.locked_until > now:
            record = existing
        else:
            failure_count = existing.failure_count + 1
            locked_until = None
            if failure_count >= self.max_failures:
                locked_until = now + timedelta(seconds=self.lockout_seconds)
            record = LoginAttemptRecord(
                client_key=key,
                failure_count=failure_count,
                first_failed_at=existing.first_failed_at,
                last_failed_at=now,
                locked_until=locked_until,
            )

        self._records[key] = record
        self._evict_oldest_keys()
        return record

    def is_locked(self, client_key: str) -> bool:
        key = self._client_key(client_key)
        record = self._records.get(key)
        if record is None:
            return False

        now = self._now()
        if record.locked_until is None:
            if self._is_expired(record, now):
                self._records.pop(key, None)
            return False

        if record.locked_until <= now:
            self._records.pop(key, None)
            return False

        return True

    def seconds_until_unlock(self, client_key: str) -> int:
        key = self._client_key(client_key)
        record = self._records.get(key)
        if record is None or record.locked_until is None:
            return 0

        now = self._now()
        if record.locked_until <= now:
            self._records.pop(key, None)
            return 0

        return max(0, math.ceil((record.locked_until - now).total_seconds()))

    def reset_success(self, client_key: str) -> bool:
        key = self._client_key(client_key)
        return self._records.pop(key, None) is not None

    def purge_expired(self) -> int:
        now = self._now()
        expired_keys = [
            key
            for key, record in self._records.items()
            if self._is_expired(record, now)
        ]
        for key in expired_keys:
            self._records.pop(key, None)
        return len(expired_keys)

    def failure_count(self, client_key: str) -> int:
        key = self._client_key(client_key)
        record = self._records.get(key)
        if record is None:
            return 0
        if self._is_expired(record, self._now()):
            self._records.pop(key, None)
            return 0
        return record.failure_count

    def record_count(self) -> int:
        return len(self._records)

    def _is_expired(self, record: LoginAttemptRecord, now: datetime) -> bool:
        if record.locked_until is not None:
            return record.locked_until <= now
        return record.last_failed_at + timedelta(seconds=self.window_seconds) <= now

    def _evict_oldest_keys(self) -> None:
        while len(self._records) > self.max_keys:
            oldest_key = min(self._records, key=lambda key: self._records[key].last_failed_at)
            self._records.pop(oldest_key, None)

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


def build_session_cookie_settings(ttl_seconds: int, secure: bool = False) -> SessionCookieSettings:
    return SessionCookieSettings(
        name=ADMIN_SESSION_COOKIE_NAME,
        httponly=True,
        samesite=ADMIN_SESSION_COOKIE_SAMESITE,
        secure=secure,
        max_age_seconds=max(1, int(ttl_seconds)),
    )


def is_supported_admin_password_hash(password_hash: str | None) -> bool:
    parsed = _parse_admin_password_hash(password_hash)
    return parsed is not None


def verify_admin_password(password: str | None, password_hash: str | None) -> bool:
    if not isinstance(password, str) or not password:
        return False

    parsed = _parse_admin_password_hash(password_hash)
    if parsed is None:
        return False

    try:
        iterations, salt, expected_digest = parsed
        actual_digest = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            iterations,
        ).hex()
    except Exception:
        return False

    return hmac.compare_digest(actual_digest, expected_digest)


def verify_admin_csrf_token(token: str | None, session: AdminSession | None) -> bool:
    if session is None or not isinstance(token, str) or not token:
        return False
    return hmac.compare_digest(token, session.csrf_token)


def _parse_admin_password_hash(password_hash: str | None) -> tuple[int, str, str] | None:
    if not isinstance(password_hash, str):
        return None

    value = password_hash.strip()
    if not value:
        return None

    match = _ADMIN_PASSWORD_HASH_PATTERN.fullmatch(value)
    if match is None:
        return None

    try:
        iterations = int(match.group("iterations"))
    except ValueError:
        return None

    if iterations < MIN_ADMIN_PASSWORD_HASH_ITERATIONS:
        return None

    return iterations, match.group("salt"), match.group("digest").lower()


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _new_session_id() -> str:
    return secrets.token_urlsafe(ADMIN_SESSION_ID_BYTES)


def _new_csrf_token() -> str:
    return secrets.token_urlsafe(ADMIN_CSRF_TOKEN_BYTES)
