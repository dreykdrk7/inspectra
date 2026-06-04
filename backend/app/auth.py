import hashlib
import hmac
import re


ADMIN_PASSWORD_HASH_SCHEME = "pbkdf2_sha256"
MIN_ADMIN_PASSWORD_HASH_ITERATIONS = 600_000
_ADMIN_PASSWORD_HASH_PATTERN = re.compile(
    r"^pbkdf2_sha256\$(?P<iterations>[1-9][0-9]*)\$(?P<salt>[A-Za-z0-9_.-]{16,128})\$(?P<digest>[A-Fa-f0-9]{64})$"
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
