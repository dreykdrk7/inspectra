from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import re
import secrets


ADMIN_PASSWORD_HASH_SCHEME = "pbkdf2_sha256"
MIN_ADMIN_PASSWORD_HASH_ITERATIONS = 600_000
ADMIN_SESSION_COOKIE_NAME = "inspectra_session"
ADMIN_SESSION_COOKIE_SAMESITE = "lax"
ADMIN_SESSION_ID_BYTES = 32
_ADMIN_PASSWORD_HASH_PATTERN = re.compile(
    r"^pbkdf2_sha256\$(?P<iterations>[1-9][0-9]*)\$(?P<salt>[A-Za-z0-9_.-]{16,128})\$(?P<digest>[A-Fa-f0-9]{64})$"
)


@dataclass(frozen=True)
class AdminSession:
    session_id: str
    operator_id: str
    created_at: datetime
    expires_at: datetime
    auth_mode: str = "self_hosted_single_admin"


@dataclass(frozen=True)
class SessionCookieSettings:
    name: str
    httponly: bool
    samesite: str
    secure: bool
    max_age_seconds: int
    path: str = "/"


class AdminSessionStore:
    def __init__(self, ttl_seconds: int, now_func=None, token_factory=None) -> None:
        self.ttl_seconds = max(1, int(ttl_seconds))
        self._now_func = now_func or _utc_now
        self._token_factory = token_factory or _new_session_id
        self._sessions: dict[str, AdminSession] = {}

    def create_admin_session(self, operator_id: str, auth_mode: str = "self_hosted_single_admin") -> AdminSession:
        now = self._now()
        session = AdminSession(
            session_id=self._unique_session_id(),
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
