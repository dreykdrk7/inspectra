from __future__ import annotations

import asyncio
import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import secrets
from typing import Awaitable, Callable, Mapping
from urllib.parse import urlencode, urlsplit

import httpx
import jwt


OIDC_TRANSACTION_TTL_SECONDS = 300
OIDC_MAX_TRANSACTIONS = 256
OIDC_MAX_RESPONSE_BYTES = 262_144
OIDC_TIMEOUT_SECONDS = 5.0
OIDC_JWKS_TTL_SECONDS = 3_600
OIDC_MAX_CONCURRENCY = 4
OIDC_ALLOWED_ALGORITHMS = ("RS256", "ES256")
OIDC_STATE_COOKIE_NAME = "inspectra_oidc_binding"
OIDC_STATE_COOKIE_SAMESITE = "lax"


class OidcFederationError(RuntimeError):
    """Fail-closed federation error whose code is safe to audit internally."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class OidcFederationConfig:
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    client_id: str
    client_secret: str
    redirect_uri: str
    post_login_redirect_uri: str
    organization_id: str
    reader_group: str
    maintainer_group: str
    subject_hmac_key: bytes
    tenant_claim: str | None = None
    expected_tenant: str | None = None

    def __post_init__(self) -> None:
        issuer = _fixed_https_url(self.issuer, allow_path=True)
        issuer_origin = _origin(issuer)
        for value in (self.authorization_endpoint, self.token_endpoint, self.jwks_uri):
            endpoint = _fixed_https_url(value, allow_path=True)
            if _origin(endpoint) != issuer_origin:
                raise ValueError("OIDC provider endpoints must share the configured issuer origin")
        _fixed_callback_url(self.redirect_uri)
        _fixed_callback_url(self.post_login_redirect_uri, callback=False)
        if not self.client_id or len(self.client_id) > 256:
            raise ValueError("OIDC client id is required and bounded")
        if not self.client_secret or len(self.client_secret) > 1024:
            raise ValueError("OIDC client secret is required and bounded")
        if not self.organization_id or len(self.organization_id) > 128:
            raise ValueError("OIDC organization id is required and bounded")
        if not self.reader_group or not self.maintainer_group or self.reader_group == self.maintainer_group:
            raise ValueError("OIDC reader and maintainer groups must be distinct")
        if max(len(self.reader_group), len(self.maintainer_group)) > 256:
            raise ValueError("OIDC group names are bounded")
        if len(self.subject_hmac_key) < 32:
            raise ValueError("OIDC subject HMAC key must contain at least 32 bytes")
        if bool(self.tenant_claim) != bool(self.expected_tenant):
            raise ValueError("OIDC tenant claim and expected value must be configured together")
        if self.tenant_claim is not None and (
            not self.tenant_claim.replace("_", "").isalnum() or len(self.tenant_claim) > 64
        ):
            raise ValueError("OIDC tenant claim is invalid")
        if self.expected_tenant is not None and len(self.expected_tenant) > 256:
            raise ValueError("OIDC expected tenant is bounded")

    def authorization_url(self, transaction: "OidcTransaction") -> str:
        query = urlencode(
            {
                "response_type": "code",
                "scope": "openid",
                "client_id": self.client_id,
                "redirect_uri": self.redirect_uri,
                "state": transaction.state,
                "nonce": transaction.nonce,
                "code_challenge": _b64url(hashlib.sha256(transaction.code_verifier.encode("ascii")).digest()),
                "code_challenge_method": "S256",
            }
        )
        return f"{self.authorization_endpoint}?{query}"

    def subject_digest(self, subject: str) -> str:
        if not isinstance(subject, str) or not subject or len(subject) > 255 or not subject.isascii():
            raise OidcFederationError("invalid_subject")
        material = f"{self.issuer}\0{subject}".encode("utf-8")
        return hmac.new(self.subject_hmac_key, material, hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class OidcTransaction:
    state: str
    nonce: str
    code_verifier: str
    binding: str
    expires_at: datetime


@dataclass(frozen=True)
class OidcIdentity:
    subject_digest: str
    asserted_role: str


class OidcTransactionStore:
    def __init__(self, *, now_func=None, token_factory=None) -> None:
        self._now_func = now_func or _utc_now
        self._token_factory = token_factory or (lambda: secrets.token_urlsafe(32))
        self._transactions: dict[str, OidcTransaction] = {}

    def create(self) -> OidcTransaction:
        self.purge_expired()
        if len(self._transactions) >= OIDC_MAX_TRANSACTIONS:
            oldest = min(self._transactions, key=lambda key: self._transactions[key].expires_at)
            self._transactions.pop(oldest, None)
        transaction = OidcTransaction(
            state=self._token(),
            nonce=self._token(),
            code_verifier=self._token() + self._token(),
            binding=self._token(),
            expires_at=self._now() + timedelta(seconds=OIDC_TRANSACTION_TTL_SECONDS),
        )
        self._transactions[_digest(transaction.state)] = transaction
        return transaction

    def consume(self, state: str, binding: str | None) -> OidcTransaction:
        if not isinstance(state, str) or not state or len(state) > 256:
            raise OidcFederationError("invalid_state")
        transaction = self._transactions.pop(_digest(state), None)
        if transaction is None or transaction.expires_at <= self._now():
            raise OidcFederationError("invalid_state")
        if not isinstance(binding, str) or not hmac.compare_digest(transaction.binding, binding):
            raise OidcFederationError("invalid_browser_binding")
        return transaction

    def purge_expired(self) -> int:
        now = self._now()
        expired = [key for key, value in self._transactions.items() if value.expires_at <= now]
        for key in expired:
            self._transactions.pop(key, None)
        return len(expired)

    def _token(self) -> str:
        value = self._token_factory()
        if not isinstance(value, str) or len(value) < 32 or len(value) > 128:
            raise OidcFederationError("transaction_unavailable")
        return value

    def _now(self) -> datetime:
        value = self._now_func()
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)


class OidcProviderClient:
    """Bounded client for operator-fixed OIDC endpoints; it never follows redirects."""

    def __init__(self, config: OidcFederationConfig, *, now_func=None, transport=None) -> None:
        self.config = config
        self._now_func = now_func or _utc_now
        self._jwks: Mapping[str, object] | None = None
        self._jwks_expires_at: datetime | None = None
        self._lock = asyncio.Lock()
        self._semaphore = asyncio.Semaphore(OIDC_MAX_CONCURRENCY)
        self._transport = transport

    async def exchange_code(self, code: str, verifier: str) -> str:
        if not isinstance(code, str) or not code or len(code) > 2048:
            raise OidcFederationError("invalid_code")
        basic = base64.b64encode(
            f"{self.config.client_id}:{self.config.client_secret}".encode("utf-8")
        ).decode("ascii")
        payload = await self._request_json(
            "POST",
            self.config.token_endpoint,
            headers={
                "Authorization": f"Basic {basic}",
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self.config.redirect_uri,
                "code_verifier": verifier,
            },
        )
        token = payload.get("id_token")
        if not isinstance(token, str) or not token or len(token) > 16_384:
            raise OidcFederationError("invalid_token_response")
        return token

    async def jwks(self) -> Mapping[str, object]:
        now = self._now()
        if self._jwks is not None and self._jwks_expires_at is not None and self._jwks_expires_at > now:
            return self._jwks
        async with self._lock:
            now = self._now()
            if self._jwks is not None and self._jwks_expires_at is not None and self._jwks_expires_at > now:
                return self._jwks
            payload = await self._request_json("GET", self.config.jwks_uri, headers={"Accept": "application/json"})
            keys = payload.get("keys")
            if not isinstance(keys, list) or not keys or len(keys) > 100:
                raise OidcFederationError("invalid_jwks")
            self._jwks = payload
            self._jwks_expires_at = now + timedelta(seconds=OIDC_JWKS_TTL_SECONDS)
            return payload

    async def _request_json(self, method: str, url: str, **kwargs) -> dict[str, object]:
        try:
            timeout = httpx.Timeout(OIDC_TIMEOUT_SECONDS)
            async with self._semaphore:
                async with httpx.AsyncClient(
                    timeout=timeout,
                    follow_redirects=False,
                    trust_env=False,
                    transport=self._transport,
                ) as client:
                    async with client.stream(method, url, **kwargs) as response:
                        if response.is_redirect or response.status_code != 200:
                            raise OidcFederationError("provider_unavailable")
                        chunks: list[bytes] = []
                        size = 0
                        async for chunk in response.aiter_bytes():
                            size += len(chunk)
                            if size > OIDC_MAX_RESPONSE_BYTES:
                                raise OidcFederationError("provider_response_too_large")
                            chunks.append(chunk)
            payload = json.loads(b"".join(chunks))
        except OidcFederationError:
            raise
        except (httpx.HTTPError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise OidcFederationError("provider_unavailable") from exc
        if not isinstance(payload, dict):
            raise OidcFederationError("invalid_provider_response")
        return payload

    def _now(self) -> datetime:
        value = self._now_func()
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)


async def authenticate_oidc_callback(
    *,
    config: OidcFederationConfig,
    transaction: OidcTransaction,
    code: str,
    exchange_code: Callable[[str, str], Awaitable[str]],
    load_jwks: Callable[[], Awaitable[Mapping[str, object]]],
) -> OidcIdentity:
    token = await exchange_code(code, transaction.code_verifier)
    jwks = await load_jwks()
    claims = _decode_id_token(token, jwks, config)
    if not hmac.compare_digest(str(claims.get("nonce", "")), transaction.nonce):
        raise OidcFederationError("invalid_nonce")
    if config.tenant_claim is not None and claims.get(config.tenant_claim) != config.expected_tenant:
        raise OidcFederationError("unexpected_tenant")
    asserted_role = _asserted_role(claims.get("groups"), config)
    return OidcIdentity(
        subject_digest=config.subject_digest(str(claims.get("sub", ""))),
        asserted_role=asserted_role,
    )


def _decode_id_token(
    token: str,
    jwks: Mapping[str, object],
    config: OidcFederationConfig,
) -> dict[str, object]:
    try:
        header = jwt.get_unverified_header(token)
        algorithm = header.get("alg")
        key_id = header.get("kid")
        if algorithm not in OIDC_ALLOWED_ALGORITHMS or not isinstance(key_id, str) or not key_id:
            raise OidcFederationError("invalid_token_header")
        keys = jwks.get("keys")
        matches = [
            item for item in keys if isinstance(item, dict) and item.get("kid") == key_id
        ] if isinstance(keys, list) else []
        if len(matches) != 1:
            raise OidcFederationError("signing_key_unavailable")
        jwk = matches[0]
        if jwk.get("alg") not in {None, algorithm} or jwk.get("use") not in {None, "sig"}:
            raise OidcFederationError("invalid_signing_key")
        key = jwt.PyJWK.from_dict(jwk, algorithm=algorithm)
        claims = jwt.decode(
            token,
            key=key,
            algorithms=list(OIDC_ALLOWED_ALGORITHMS),
            audience=config.client_id,
            issuer=config.issuer,
            options={"require": ["exp", "iat", "iss", "aud", "sub", "nonce"]},
        )
    except OidcFederationError:
        raise
    except (jwt.PyJWTError, TypeError, ValueError) as exc:
        raise OidcFederationError("invalid_id_token") from exc
    audiences = claims.get("aud")
    if isinstance(audiences, list) and len(audiences) > 1 and claims.get("azp") != config.client_id:
        raise OidcFederationError("invalid_authorized_party")
    return claims


def _asserted_role(groups: object, config: OidcFederationConfig) -> str:
    if not isinstance(groups, list) or len(groups) > 100:
        raise OidcFederationError("unexpected_group")
    if any(not isinstance(value, str) or len(value) > 256 for value in groups):
        raise OidcFederationError("unexpected_group")
    roles = {
        role
        for role, configured_group in (
            ("reader", config.reader_group),
            ("maintainer", config.maintainer_group),
        )
        if configured_group in groups
    }
    if len(roles) != 1:
        raise OidcFederationError("unexpected_group")
    return roles.pop()


def _fixed_https_url(value: str, *, allow_path: bool) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or (not allow_path and parsed.path not in {"", "/"})
    ):
        raise ValueError("OIDC URLs must be fixed HTTPS URLs without credentials, query or fragment")
    try:
        parsed.port
    except ValueError as exc:
        raise ValueError("OIDC URL port is invalid") from exc
    return value.rstrip("/")


def _fixed_callback_url(value: str, *, callback: bool = True) -> None:
    parsed = urlsplit(value)
    local_http = parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    if (
        (parsed.scheme != "https" and not local_http)
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or (callback and parsed.path != "/auth/oidc/callback")
    ):
        raise ValueError("OIDC redirect URI is invalid")


def _origin(value: str) -> tuple[str, str, int | None]:
    parsed = urlsplit(value)
    return parsed.scheme, parsed.hostname or "", parsed.port


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)
