"""Small, fixed-destination transport for public vulnerability intelligence.

This module is deliberately *not* a general HTTP client.  Callers cannot supply
URLs, hosts, paths, query parameters, headers, or proxy settings.  The first
OSV integration may send only a normalized registry component identity.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import base64
import hashlib
import json
from pathlib import Path
import re
import threading
import time
from typing import Any, Callable, Iterable, Literal
from urllib.parse import urlsplit

from app.version_matching import canonicalize_nuget_version
from uuid import uuid4

import httpx

from app.observability import log_audit_event


PublicAdvisoryProvider = Literal["osv", "github_advisories", "nvd", "cisa_kev"]
PublicAdvisoryStatus = Literal[
    "disabled",
    "success",
    "rate_limited",
    "timed_out",
    "unavailable",
    "response_too_large",
    "redirect_blocked",
    "invalid_content_type",
    "invalid_source_response",
    "provider_rejected",
    "source_error",
    "concurrency_limited",
    "invalid_request",
    "pagination_incomplete",
    "stale_cached",
    "circuit_open",
]
PublicAdvisoryCacheStatus = Literal["not_used", "miss", "fresh", "stale"]

OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULNERABILITY_URL_PREFIX = "https://api.osv.dev/v1/vulns/"
GITHUB_GLOBAL_ADVISORIES_URL = "https://api.github.com/advisories"
CISA_KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PUBLIC_ADVISORY_ENDPOINTS: dict[PublicAdvisoryProvider, tuple[str, str]] = {
    "osv": ("POST", OSV_QUERYBATCH_URL),
    "github_advisories": ("GET", GITHUB_GLOBAL_ADVISORIES_URL),
    "nvd": ("GET", NVD_CVE_API_URL),
    "cisa_kev": ("GET", CISA_KEV_FEED_URL),
}
# Keep the expected method, host and path independently from the URL mapping
# above.  The redundancy is intentional: if a future change accidentally
# makes the transport mapping configurable or changes an endpoint to a
# redirector, this boundary fails closed before opening a socket.
_PUBLIC_ADVISORY_ENDPOINT_INVARIANTS: dict[PublicAdvisoryProvider, tuple[str, str, str]] = {
    "osv": ("POST", "api.osv.dev", "/v1/querybatch"),
    "github_advisories": ("GET", "api.github.com", "/advisories"),
    "nvd": ("GET", "services.nvd.nist.gov", "/rest/json/cves/2.0"),
    "cisa_kev": ("GET", "www.cisa.gov", "/sites/default/files/feeds/known_exploited_vulnerabilities.json"),
}

_NPM_PACKAGE_NAME = re.compile(r"^(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*$")
_PYPI_PACKAGE_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
_PYPI_NORMALIZATION = re.compile(r"[-_.]+")
_CARGO_PACKAGE_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
_COMPOSER_PACKAGE_NAME = re.compile(r"^[a-z0-9][a-z0-9_.-]*/[a-z0-9][a-z0-9_.-]*$")
_MAVEN_PACKAGE_NAME = re.compile(r"^[a-z0-9][a-z0-9_.-]*:[a-z0-9][a-z0-9_.-]*$")
_VERSION_SPECIFIER_MARKERS = frozenset({"^", "~", "<", ">", "=", "*", "|", ","})
_GHSA_IDENTIFIER = re.compile(r"^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$", re.IGNORECASE)
_CVE_IDENTIFIER = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
PUBLIC_ADVISORY_CACHE_SCHEMA = "2026-09-05.2"
DEFAULT_CACHE_RETENTION_SECONDS = 604_800
# These shallow structural limits are enforced at the egress boundary before a
# successful response can be cached.  The provider-specific normalizers still
# validate every retained field; this prevents malformed or unexpectedly large
# JSON documents from becoming a durable cache entry in the first place.
# OSV may page a Querybatch result after approximately 1,000 vulnerabilities
# for one identity.  A bounded local continuation prevents a paged response
# from becoming a false clean result while keeping request and memory budgets
# finite.  Tokens remain in memory only for the current request sequence.
MAX_OSV_VULNERABILITIES_PER_PAGE = 1_000
MAX_OSV_QUERYBATCH_PAGES = 4
MAX_OSV_VULNERABILITIES_PER_QUERY = MAX_OSV_VULNERABILITIES_PER_PAGE * MAX_OSV_QUERYBATCH_PAGES
MAX_OSV_ADVISORIES_PER_BATCH = 250
MAX_OSV_PAGE_TOKEN_LENGTH = 512
_OSV_PAGE_TOKEN = re.compile(r"^[A-Za-z0-9._~=-]{1,512}$")
_OSV_ADVISORY_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
MAX_GITHUB_ADVISORIES_PER_LOOKUP = 1
MAX_NVD_CVES_PER_LOOKUP = 1
PROVIDER_CIRCUIT_FAILURE_THRESHOLD = 3
PROVIDER_CIRCUIT_COOLDOWN_SECONDS = 30
MAX_OPERATIONAL_CACHE_ENTRIES = 10_000


@dataclass(frozen=True)
class PublicComponentIdentity:
    """The only component fields that can cross the advisory boundary."""

    ecosystem: Literal["npm", "pypi", "go", "cargo", "composer", "maven", "nuget"]
    name: str
    version: str
    # Local authorization evidence only. It is deliberately excluded from the
    # normalized OSV request and cache key. The PVI service may set it solely
    # for a normalized SBOM component whose importer recorded the operator's
    # explicit public-registry attestation.
    operator_attested_public_sbom: bool = False


@dataclass(frozen=True)
class PublicAdvisoryNamespacePolicy:
    """Local-only exclusions for names that may identify private components.

    This is deliberately a deny policy, not an allow-list escape hatch: npm
    scopes remain excluded in every deployment.  Rules are parsed by settings
    at startup and are never placed in requests, cache keys, result snapshots,
    or audit logs.
    """

    private_package_rules: tuple[str, ...] = ()
    # A PyPI name can be private even when its manifest source looks like a
    # registry. These names are a deployment-level attestation, never a
    # project-controlled input and never persisted or logged outside policy.
    public_pypi_packages: tuple[str, ...] = ()
    public_go_modules: tuple[str, ...] = ()
    public_composer_packages: tuple[str, ...] = ()
    public_maven_packages: tuple[str, ...] = ()
    public_nuget_packages: tuple[str, ...] = ()
    # Team deployments may require a second, organization-scoped approval for
    # every otherwise eligible identity. Entries are canonical
    # ``ecosystem:name`` values assembled by trusted server-side state, never
    # request-controlled endpoints or query fragments.
    organization_public_packages: tuple[str, ...] = ()
    organization_attestation_required: bool = False

    @classmethod
    def from_entries(
        cls,
        entries: Iterable[str],
        *,
        public_pypi_packages: Iterable[str] = (),
        public_go_modules: Iterable[str] = (),
        public_composer_packages: Iterable[str] = (),
        public_maven_packages: Iterable[str] = (),
        public_nuget_packages: Iterable[str] = (),
    ) -> "PublicAdvisoryNamespacePolicy":
        # Settings has already validated the deployment value.  Re-check the
        # compact grammar so direct programmatic callers cannot weaken it.
        raw_entries = tuple(entry.strip().lower() for entry in entries if isinstance(entry, str) and entry.strip())
        allowed = re.compile(r"^(?:npm|pypi|go|cargo|composer|maven|nuget):(?:exact|prefix):[a-z0-9@/:._~+\-]+$|^npm:scope:@[a-z0-9][a-z0-9._-]*/$")
        if len(raw_entries) > 100 or any(len(entry) > 200 or "*" in entry or not allowed.fullmatch(entry) for entry in raw_entries):
            raise ValueError("Public advisory private package rules are invalid.")
        normalized: set[str] = set()
        for entry in raw_entries:
            ecosystem, kind, value = entry.split(":", 2)
            if kind == "scope":
                if ecosystem != "npm" or not re.fullmatch(r"@[a-z0-9][a-z0-9._-]*/", value):
                    raise ValueError("Public advisory private package rules are invalid.")
                normalized.add(entry)
                continue
            normalized_name = _normalize_component_name(ecosystem, value)
            if normalized_name is None:
                raise ValueError("Public advisory private package rules are invalid.")
            normalized.add(f"{ecosystem}:{kind}:{normalized_name}")
        normalized_entries = tuple(sorted(normalized))
        normalized_public_pypi: set[str] = set()
        raw_public_pypi = tuple(value.strip().lower() for value in public_pypi_packages if isinstance(value, str) and value.strip())
        if len(raw_public_pypi) > 100:
            raise ValueError("Public advisory PyPI attestations are invalid.")
        for value in raw_public_pypi:
            normalized_name = _normalize_component_name("pypi", value)
            if normalized_name is None or len(value) > 200:
                raise ValueError("Public advisory PyPI attestations are invalid.")
            normalized_public_pypi.add(normalized_name)
        normalized_public_go: set[str] = set()
        raw_public_go = tuple(value.strip() for value in public_go_modules if isinstance(value, str) and value.strip())
        if len(raw_public_go) > 500:
            raise ValueError("Public advisory Go attestations are invalid.")
        for value in raw_public_go:
            normalized_name = _normalize_component_name("go", value)
            if normalized_name is None or len(value) > 300:
                raise ValueError("Public advisory Go attestations are invalid.")
            normalized_public_go.add(normalized_name)
        normalized_public_composer: set[str] = set()
        raw_public_composer = tuple(value.strip() for value in public_composer_packages if isinstance(value, str) and value.strip())
        if len(raw_public_composer) > 500:
            raise ValueError("Public advisory Composer attestations are invalid.")
        for value in raw_public_composer:
            normalized_name = _normalize_component_name("composer", value)
            if normalized_name is None or len(value) > 200:
                raise ValueError("Public advisory Composer attestations are invalid.")
            normalized_public_composer.add(normalized_name)
        normalized_public_maven: set[str] = set()
        raw_public_maven = tuple(value.strip() for value in public_maven_packages if isinstance(value, str) and value.strip())
        if len(raw_public_maven) > 500:
            raise ValueError("Public advisory Maven attestations are invalid.")
        for value in raw_public_maven:
            normalized_name = _normalize_component_name("maven", value)
            if normalized_name is None or len(value) > 321:
                raise ValueError("Public advisory Maven attestations are invalid.")
            normalized_public_maven.add(normalized_name)
        normalized_public_nuget: set[str] = set()
        raw_public_nuget = tuple(value.strip() for value in public_nuget_packages if isinstance(value, str) and value.strip())
        if len(raw_public_nuget) > 500:
            raise ValueError("Public advisory NuGet attestations are invalid.")
        for value in raw_public_nuget:
            normalized_name = _normalize_component_name("nuget", value)
            if normalized_name is None or len(value) > 200:
                raise ValueError("Public advisory NuGet attestations are invalid.")
            normalized_public_nuget.add(normalized_name)
        return cls(
            private_package_rules=normalized_entries,
            public_pypi_packages=tuple(sorted(normalized_public_pypi)),
            public_go_modules=tuple(sorted(normalized_public_go)),
            public_composer_packages=tuple(sorted(normalized_public_composer)),
            public_maven_packages=tuple(sorted(normalized_public_maven)),
            public_nuget_packages=tuple(sorted(normalized_public_nuget)),
        )

    def excludes(self, component: PublicComponentIdentity) -> bool:
        normalized_name = _normalize_component_name(component.ecosystem, component.name)
        if normalized_name is None:
            return False
        # A scoped npm name is never demonstrably public in the initial
        # product boundary, even if it happens to exist in the public registry.
        if component.ecosystem == "npm" and normalized_name.startswith("@"):
            return True
        for rule in self.private_package_rules:
            ecosystem, kind, value = rule.split(":", 2)
            if ecosystem != component.ecosystem:
                continue
            if kind == "exact" and normalized_name == value:
                return True
            if kind == "prefix" and normalized_name.startswith(value):
                return True
            if kind == "scope" and normalized_name.startswith(value):
                return True
        return False

    def allows_attested_public_pypi(self, component: PublicComponentIdentity) -> bool:
        """Return true only for one deployment-attested, non-excluded PyPI name."""

        if component.ecosystem != "pypi" or self.excludes(component):
            return False
        normalized_name = _normalize_component_name("pypi", component.name)
        return normalized_name is not None and normalized_name in self.public_pypi_packages

    def allows_attested_public_go(self, component: PublicComponentIdentity) -> bool:
        if component.ecosystem != "go" or self.excludes(component):
            return False
        normalized_name = _normalize_component_name("go", component.name)
        return normalized_name is not None and normalized_name in self.public_go_modules

    def allows_attested_public_composer(self, component: PublicComponentIdentity) -> bool:
        if component.ecosystem != "composer" or self.excludes(component):
            return False
        normalized_name = _normalize_component_name("composer", component.name)
        return normalized_name is not None and normalized_name in self.public_composer_packages

    def allows_attested_public_maven(self, component: PublicComponentIdentity) -> bool:
        if component.ecosystem != "maven" or self.excludes(component):
            return False
        normalized_name = _normalize_component_name("maven", component.name)
        return normalized_name is not None and normalized_name in self.public_maven_packages

    def allows_attested_public_nuget(self, component: PublicComponentIdentity) -> bool:
        if component.ecosystem != "nuget" or self.excludes(component):
            return False
        normalized_name = _normalize_component_name("nuget", component.name)
        return normalized_name is not None and normalized_name in self.public_nuget_packages

    def with_organization_attestations(self, entries: Iterable[str]) -> "PublicAdvisoryNamespacePolicy":
        raw_entries = tuple(entries)
        if len(raw_entries) > 200:
            raise ValueError("Organization public identity attestations are invalid.")
        normalized: set[str] = set()
        for entry in raw_entries:
            if not isinstance(entry, str) or ":" not in entry or len(entry) > 340:
                raise ValueError("Organization public identity attestations are invalid.")
            ecosystem, name = entry.split(":", 1)
            normalized_name = normalize_public_component_name(ecosystem, name)
            if normalized_name is None:
                raise ValueError("Organization public identity attestations are invalid.")
            normalized.add(f"{ecosystem}:{normalized_name}")
        return PublicAdvisoryNamespacePolicy(
            private_package_rules=self.private_package_rules,
            public_pypi_packages=self.public_pypi_packages,
            public_go_modules=self.public_go_modules,
            public_composer_packages=self.public_composer_packages,
            public_maven_packages=self.public_maven_packages,
            public_nuget_packages=self.public_nuget_packages,
            organization_public_packages=tuple(sorted(normalized)),
            organization_attestation_required=True,
        )

    def allows_organization_identity(self, component: PublicComponentIdentity) -> bool:
        if not self.organization_attestation_required:
            return True
        normalized_name = normalize_public_component_name(component.ecosystem, component.name)
        return normalized_name is not None and f"{component.ecosystem}:{normalized_name}" in self.organization_public_packages

    def is_safe_overlay_of(self, operator_policy: "PublicAdvisoryNamespacePolicy") -> bool:
        """An organization overlay may restrict, but never broaden, operator policy."""

        return (
            self.private_package_rules == operator_policy.private_package_rules
            and self.public_pypi_packages == operator_policy.public_pypi_packages
            and self.public_go_modules == operator_policy.public_go_modules
            and self.public_composer_packages == operator_policy.public_composer_packages
            and self.public_maven_packages == operator_policy.public_maven_packages
            and self.public_nuget_packages == operator_policy.public_nuget_packages
            and self.organization_attestation_required
        )

    def without_organization_attestation(self) -> "PublicAdvisoryNamespacePolicy":
        return PublicAdvisoryNamespacePolicy(
            private_package_rules=self.private_package_rules,
            public_pypi_packages=self.public_pypi_packages,
            public_go_modules=self.public_go_modules,
            public_composer_packages=self.public_composer_packages,
            public_maven_packages=self.public_maven_packages,
            public_nuget_packages=self.public_nuget_packages,
        )


@dataclass(frozen=True)
class PublicAdvisoryEgressResult:
    provider: PublicAdvisoryProvider
    status: PublicAdvisoryStatus
    body: bytes | None = None
    attempts: int = 0
    pages: int = 0
    cache_status: PublicAdvisoryCacheStatus = "not_used"
    fetched_at: datetime | None = None
    expires_at: datetime | None = None
    offline_snapshot_id: str | None = None

    @property
    def succeeded(self) -> bool:
        return self.status == "success" and self.body is not None


@dataclass(frozen=True)
class PublicAdvisoryCacheEntry:
    """A provider response keyed only by a digest of minimal component identity."""

    provider: PublicAdvisoryProvider
    body: bytes
    fetched_at: datetime
    expires_at: datetime
    pages: int = 1
    offline_snapshot_id: str | None = None

    def is_fresh_at(self, now: datetime) -> bool:
        """Evaluate freshness against a trusted clock, never request input."""

        if now.tzinfo is None:
            return False
        return self.expires_at >= now.astimezone(timezone.utc)

    @property
    def fresh(self) -> bool:
        """Compatibility convenience for callers that do not inject a clock."""

        return self.is_fresh_at(datetime.now(timezone.utc))


@dataclass(frozen=True)
class PublicAdvisoryCacheSummary:
    provider: PublicAdvisoryProvider
    entries: int
    fresh_entries: int
    stale_entries: int
    invalid_entries: int
    total_bytes: int
    last_updated_at: datetime | None
    truncated: bool


class PublicAdvisoryResponseCache:
    """Small local cache that retains no request payload or project metadata."""

    def __init__(
        self,
        directory: Path,
        *,
        ttl_seconds: int,
        max_response_bytes: int,
        retention_seconds: int = DEFAULT_CACHE_RETENTION_SECONDS,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        if retention_seconds < ttl_seconds:
            raise ValueError("Public advisory cache retention must be at least its TTL.")
        self.directory = directory
        self.ttl_seconds = ttl_seconds
        self.max_response_bytes = max_response_bytes
        self.retention_seconds = retention_seconds
        self.clock = clock
        self._lock = threading.RLock()

    def get(self, provider: PublicAdvisoryProvider, key: str, *, now: datetime | None = None) -> PublicAdvisoryCacheEntry | None:
        path = self._path(provider, key)
        with self._lock:
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError, TypeError):
                return None
        if not isinstance(raw, dict) or raw.get("schema") != PUBLIC_ADVISORY_CACHE_SCHEMA:
            return None
        if raw.get("provider") != provider or raw.get("key") != key:
            return None
        try:
            body = base64.b64decode(raw["body"], validate=True)
            fetched_at = _parse_utc_timestamp(raw["fetched_at"])
            expires_at = _parse_utc_timestamp(raw["expires_at"])
            pages = raw.get("pages", 1)
        except (KeyError, TypeError, ValueError):
            return None
        if (
            len(body) > self.max_response_bytes
            or fetched_at > expires_at
            or not isinstance(pages, int)
            or not 1 <= pages <= MAX_OSV_QUERYBATCH_PAGES
        ):
            return None
        current = now or self.clock()
        if current.tzinfo is None:
            return None
        current = current.astimezone(timezone.utc)
        # A cache response cannot survive its bounded retention period even if
        # the remote provider remains unavailable. The key/path is validated
        # above and the cache is disposable, so removing this one expired file
        # cannot affect project results or other provider entries.
        if current > fetched_at + timedelta(seconds=self.retention_seconds):
            with self._lock:
                try:
                    path.unlink(missing_ok=True)
                except OSError:
                    pass
            return None
        return PublicAdvisoryCacheEntry(provider=provider, body=body, fetched_at=fetched_at, expires_at=expires_at, pages=pages)

    def put(
        self,
        provider: PublicAdvisoryProvider,
        key: str,
        body: bytes,
        *,
        pages: int = 1,
        now: datetime | None = None,
    ) -> PublicAdvisoryCacheEntry | None:
        if len(body) > self.max_response_bytes or not isinstance(pages, int) or not 1 <= pages <= MAX_OSV_QUERYBATCH_PAGES:
            return None
        fetched_at = now or self.clock()
        if fetched_at.tzinfo is None:
            return None
        # Persisted timestamps are second-granular. Keep the in-process result
        # identical to a post-restart cache read so freshness is reproducible.
        fetched_at = fetched_at.astimezone(timezone.utc).replace(microsecond=0)
        expires_at = fetched_at + timedelta(seconds=self.ttl_seconds)
        entry = PublicAdvisoryCacheEntry(provider=provider, body=body, fetched_at=fetched_at, expires_at=expires_at, pages=pages)
        document = {
            "schema": PUBLIC_ADVISORY_CACHE_SCHEMA,
            "provider": provider,
            "key": key,
            "fetched_at": _render_utc_timestamp(fetched_at),
            "expires_at": _render_utc_timestamp(expires_at),
            "pages": pages,
            # The response is public provider data. The minimal request identity
            # is deliberately represented only by ``key``'s one-way digest.
            "body": base64.b64encode(body).decode("ascii"),
        }
        path = self._path(provider, key)
        temporary = path.with_suffix(f".tmp-{uuid4().hex}")
        with self._lock:
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                temporary.write_text(json.dumps(document, sort_keys=True, separators=(",", ":")), encoding="utf-8")
                temporary.replace(path)
            except OSError:
                temporary.unlink(missing_ok=True)
                return None
        return entry

    def purge_expired(self, *, now: datetime | None = None) -> int:
        """Remove expired or invalid provider responses without reading identities.

        Only fixed provider directories and 64-character digest files are
        eligible. Project vulnerability snapshots use 32-character analysis
        identifiers and therefore cannot be selected by this cleanup.
        """

        current = now or self.clock()
        if current.tzinfo is None or current.utcoffset() is None:
            raise ValueError("Public advisory cache cleanup requires an aware clock.")
        current = current.astimezone(timezone.utc)
        removed = 0
        with self._lock:
            for provider in PUBLIC_ADVISORY_ENDPOINTS:
                directory = self.directory / provider
                if directory.is_symlink():
                    raise ValueError("Public advisory cache directory is invalid.")
                if not directory.exists():
                    continue
                if not directory.is_dir():
                    raise ValueError("Public advisory cache directory is invalid.")
                for path in directory.iterdir():
                    if path.suffix != ".json" or not re.fullmatch(r"[a-f0-9]{64}", path.stem):
                        continue
                    if path.is_symlink() or not path.is_file():
                        raise ValueError("Public advisory cache entry is invalid.")
                    remove = False
                    try:
                        raw = json.loads(path.read_text(encoding="utf-8"))
                        fetched_at = _parse_utc_timestamp(raw["fetched_at"])
                        remove = (
                            not isinstance(raw, dict)
                            or raw.get("schema") != PUBLIC_ADVISORY_CACHE_SCHEMA
                            or raw.get("provider") != provider
                            or raw.get("key") != path.stem
                            or current > fetched_at + timedelta(seconds=self.retention_seconds)
                        )
                    except (KeyError, TypeError, ValueError, OSError):
                        remove = True
                    if remove:
                        path.unlink()
                        removed += 1
        return removed

    def operational_summary(self, *, now: datetime | None = None) -> tuple[PublicAdvisoryCacheSummary, ...]:
        """Return aggregate cache health without keys, identities, bodies or paths."""

        current = now or self.clock()
        if current.tzinfo is None or current.utcoffset() is None:
            raise ValueError("Public advisory cache summary requires an aware clock.")
        current = current.astimezone(timezone.utc)
        summaries: list[PublicAdvisoryCacheSummary] = []
        with self._lock:
            for provider in PUBLIC_ADVISORY_ENDPOINTS:
                entries = fresh = stale = invalid = total_bytes = 0
                latest: datetime | None = None
                truncated = False
                directory = self.directory / provider
                if directory.is_symlink() or (directory.exists() and not directory.is_dir()):
                    raise ValueError("Public advisory cache directory is invalid.")
                if directory.exists():
                    for path in directory.iterdir():
                        if entries >= MAX_OPERATIONAL_CACHE_ENTRIES:
                            truncated = True
                            break
                        if path.suffix != ".json" or not re.fullmatch(r"[a-f0-9]{64}", path.stem):
                            continue
                        entries += 1
                        try:
                            if path.is_symlink() or not path.is_file():
                                raise ValueError
                            total_bytes += min(path.stat().st_size, self.max_response_bytes * 2)
                            raw = json.loads(path.read_text(encoding="utf-8"))
                            fetched_at = _parse_utc_timestamp(raw["fetched_at"])
                            expires_at = _parse_utc_timestamp(raw["expires_at"])
                            if raw.get("schema") != PUBLIC_ADVISORY_CACHE_SCHEMA or raw.get("provider") != provider or raw.get("key") != path.stem:
                                raise ValueError
                            latest = fetched_at if latest is None or fetched_at > latest else latest
                            if expires_at >= current:
                                fresh += 1
                            else:
                                stale += 1
                        except (KeyError, OSError, TypeError, ValueError):
                            invalid += 1
                summaries.append(PublicAdvisoryCacheSummary(
                    provider, entries, fresh, stale, invalid, total_bytes, latest, truncated,
                ))
        return tuple(summaries)

    def _path(self, provider: PublicAdvisoryProvider, key: str) -> Path:
        if provider not in PUBLIC_ADVISORY_ENDPOINTS or not re.fullmatch(r"[a-f0-9]{64}", key):
            raise ValueError("Invalid public advisory cache key.")
        return self.directory / provider / f"{key}.json"


class PublicAdvisoryEgressClient:
    """Bounded egress to fixed public advisory providers only."""

    def __init__(
        self,
        *,
        enabled: bool,
        nvd_enabled: bool = False,
        timeout_seconds: float,
        max_response_bytes: int,
        max_concurrency: int,
        max_retries: int,
        max_batch_components: int,
        namespace_policy: PublicAdvisoryNamespacePolicy | None = None,
        http_transport: httpx.BaseTransport | None = None,
        cache: PublicAdvisoryResponseCache | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        self.enabled = enabled
        self.nvd_enabled = nvd_enabled
        self.timeout_seconds = timeout_seconds
        self.max_response_bytes = max_response_bytes
        self.max_retries = max_retries
        self.max_batch_components = max_batch_components
        self.namespace_policy = namespace_policy or PublicAdvisoryNamespacePolicy()
        self.http_transport = http_transport
        self.cache = cache
        self.sleep = sleep
        self.clock = clock
        self._semaphore = threading.BoundedSemaphore(max_concurrency)
        self._circuit_lock = threading.Lock()
        self._provider_failures: dict[PublicAdvisoryProvider, tuple[int, datetime | None]] = {}

    @classmethod
    def from_settings(
        cls,
        settings: Any,
        *,
        http_transport: httpx.BaseTransport | None = None,
    ) -> "PublicAdvisoryEgressClient":
        return cls(
            enabled=settings.public_advisory_egress_enabled,
            nvd_enabled=settings.public_advisory_nvd_enabled,
            timeout_seconds=settings.public_advisory_timeout_seconds,
            max_response_bytes=settings.public_advisory_max_response_bytes,
            max_concurrency=settings.public_advisory_max_concurrency,
            max_retries=settings.public_advisory_max_retries,
            max_batch_components=settings.public_advisory_max_batch_components,
            namespace_policy=PublicAdvisoryNamespacePolicy.from_entries(
                settings.public_advisory_private_package_rules,
                public_pypi_packages=settings.public_advisory_public_pypi_packages,
                public_go_modules=settings.public_advisory_public_go_modules,
                public_composer_packages=settings.public_advisory_public_composer_packages,
                public_maven_packages=settings.public_advisory_public_maven_packages,
                public_nuget_packages=settings.public_advisory_public_nuget_packages,
            ),
            http_transport=http_transport,
            cache=PublicAdvisoryResponseCache(
                settings.public_advisories_dir,
                ttl_seconds=settings.public_advisory_cache_ttl_seconds,
                max_response_bytes=settings.public_advisory_max_response_bytes,
                retention_seconds=settings.public_advisory_cache_retention_seconds,
            ),
        )

    def query_osv_batch(
        self,
        components: Iterable[PublicComponentIdentity],
        *,
        namespace_policy: PublicAdvisoryNamespacePolicy | None = None,
        organization_authorizer: Callable[[PublicComponentIdentity], bool] | None = None,
    ) -> PublicAdvisoryEgressResult:
        """Call OSV's fixed batch endpoint and finish bounded per-query pages."""

        policy = namespace_policy or self.namespace_policy
        if namespace_policy is not None and not namespace_policy.is_safe_overlay_of(self.namespace_policy):
            return self._result("osv", "invalid_request")
        queries = []
        for component in components:
            query = normalize_osv_component_identity(component, namespace_policy=policy)
            if query is None:
                continue
            if not policy.allows_organization_identity(component):
                continue
            if (
                component.ecosystem == "pypi"
                and not component.operator_attested_public_sbom
                and not policy.allows_attested_public_pypi(component)
            ):
                continue
            if component.ecosystem == "go" and not policy.allows_attested_public_go(component):
                continue
            if (
                component.ecosystem == "composer"
                and not component.operator_attested_public_sbom
                and not policy.allows_attested_public_composer(component)
            ):
                continue
            if (
                component.ecosystem == "maven"
                and not component.operator_attested_public_sbom
                and not policy.allows_attested_public_maven(component)
            ):
                continue
            if (
                component.ecosystem == "nuget"
                and not component.operator_attested_public_sbom
                and not policy.allows_attested_public_nuget(component)
            ):
                continue
            # This callback reads durable tenant state immediately before the
            # request is assembled. A concurrent revoke fails the whole batch
            # closed instead of sending a partially stale approval set.
            if organization_authorizer is not None and not organization_authorizer(component):
                return self._result("osv", "invalid_request")
            if len(queries) >= self.max_batch_components:
                return self._result("osv", "invalid_request")
            queries.append(query)
        if not queries:
            return self._result("osv", "invalid_request")
        return self._send_osv_batch_cached(queries, cache_key=public_advisory_cache_key("osv", queries))

    def has_active_offline_snapshot(self) -> bool:
        return self.active_offline_snapshot_id() is not None

    def active_offline_snapshot_id(self) -> str | None:
        if self.cache is None:
            return None
        try:
            from app.offline_advisory_snapshots import get_active_offline_advisory_snapshot

            snapshot = get_active_offline_advisory_snapshot(self.cache.directory)
            value = snapshot.get("snapshot_id") if isinstance(snapshot, dict) else None
            return value if isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value) else None
        except Exception:
            return None

    def has_active_offline_provider(self, provider: PublicAdvisoryProvider) -> bool:
        if self.cache is None:
            return False
        try:
            from app.offline_advisory_snapshots import get_active_offline_advisory_snapshot

            snapshot = get_active_offline_advisory_snapshot(self.cache.directory)
            return isinstance(snapshot, dict) and provider in snapshot.get("providers", [])
        except Exception:
            return False

    def fetch_github_global_advisories(self) -> PublicAdvisoryEgressResult:
        return self._send_cached("github_advisories", cache_key=public_advisory_cache_key("github_advisories", []))

    def fetch_github_advisory(self, ghsa_id: object) -> PublicAdvisoryEgressResult:
        """Fetch one already-normalized public GHSA, never a project component.

        The only variable query value is an identifier that must have crossed
        the OSV normalizer first.  The endpoint, path, method, pagination cap,
        headers and all other query parameters remain constants in this module.
        """

        normalized_identifier = normalize_github_advisory_identifier(ghsa_id)
        if normalized_identifier is None:
            return self._result("github_advisories", "invalid_request")
        query_parameters = {"ghsa_id": normalized_identifier, "per_page": "1"}
        return self._send_cached(
            "github_advisories",
            query_params=query_parameters,
            cache_key=public_advisory_cache_key("github_advisories", [{"ghsa_id": normalized_identifier}]),
        )

    def fetch_cisa_kev_feed(self) -> PublicAdvisoryEgressResult:
        return self._send_cached("cisa_kev", cache_key=public_advisory_cache_key("cisa_kev", []))

    def fetch_nvd_cve(self, cve_id: object) -> PublicAdvisoryEgressResult:
        """Fetch one exact CVE; package identities and CPE selectors are forbidden."""

        normalized = normalize_nvd_cve_identifier(cve_id)
        if normalized is None:
            return self._result("nvd", "invalid_request")
        if not self.nvd_enabled and not self.has_active_offline_provider("nvd"):
            return self._result("nvd", "disabled")
        return self._send_cached(
            "nvd",
            query_params={"cveId": normalized},
            cache_key=public_advisory_cache_key("nvd", [{"cve_id": normalized}]),
            nvd_cve_id=normalized,
        )

    def _send_cached(
        self,
        provider: PublicAdvisoryProvider,
        *,
        cache_key: str,
        json_payload: dict[str, Any] | None = None,
        query_params: dict[str, str] | None = None,
        osv_advisory_id: str | None = None,
        nvd_cve_id: str | None = None,
    ) -> PublicAdvisoryEgressResult:
        now = self.clock()
        offline_only = not self.enabled or (provider == "nvd" and not self.nvd_enabled)
        cached = self.cache.get(provider, cache_key, now=now) if self.cache is not None and not offline_only else None
        if offline_only:
            cached = self._offline_cache_entry(provider, cache_key, now=now)
        if cached is not None and cached.is_fresh_at(now):
            return self._result(
                provider,
                "success",
                body=cached.body,
                cache_status="fresh",
                fetched_at=cached.fetched_at,
                expires_at=cached.expires_at,
                pages=cached.pages,
                offline_snapshot_id=cached.offline_snapshot_id,
            )

        if offline_only:
            if cached is None:
                return self._result(provider, "disabled")
            return self._result(
                provider,
                "stale_cached",
                body=cached.body,
                pages=cached.pages,
                cache_status="stale",
                fetched_at=cached.fetched_at,
                expires_at=cached.expires_at,
                offline_snapshot_id=cached.offline_snapshot_id,
            )

        result = self._send(
            provider,
            json_payload=json_payload,
            query_params=query_params,
            osv_advisory_id=osv_advisory_id,
            nvd_cve_id=nvd_cve_id,
            cache_status="stale" if cached is not None else "miss",
        )
        if result.succeeded and self.cache is not None and result.body is not None:
            entry = self.cache.put(provider, cache_key, result.body, pages=result.pages or 1, now=now)
            if entry is not None:
                return self._result(
                    provider,
                    result.status,
                    body=result.body,
                    attempts=result.attempts,
                    pages=result.pages,
                    cache_status=result.cache_status,
                    fetched_at=entry.fetched_at,
                    expires_at=entry.expires_at,
                )
            return result
        if cached is not None:
            return self._result(
                provider,
                "stale_cached",
                body=cached.body,
                attempts=result.attempts,
                pages=cached.pages,
                cache_status="stale",
                fetched_at=cached.fetched_at,
                expires_at=cached.expires_at,
                offline_snapshot_id=cached.offline_snapshot_id,
            )
        return result

    def _send_osv_batch_cached(self, queries: list[dict[str, Any]], *, cache_key: str) -> PublicAdvisoryEgressResult:
        """Return a complete bounded OSV batch without retaining page tokens.

        Querybatch exposes a continuation token for each result, not for the
        batch as a whole.  We reconstruct one result list in input order and
        cache only that final provider response plus the safe page count.  A
        token is neither stored, logged nor accepted from a caller.
        """

        now = self.clock()
        offline_only = not self.enabled
        cached = self.cache.get("osv", cache_key, now=now) if self.cache is not None and not offline_only else None
        if offline_only:
            cached = self._offline_cache_entry("osv", cache_key, now=now)
        if cached is not None and cached.is_fresh_at(now):
            return self._result(
                "osv",
                "success",
                body=cached.body,
                cache_status="fresh",
                fetched_at=cached.fetched_at,
                expires_at=cached.expires_at,
                pages=cached.pages,
                offline_snapshot_id=cached.offline_snapshot_id,
            )

        if offline_only:
            if cached is None:
                return self._result("osv", "disabled")
            return self._result(
                "osv",
                "stale_cached",
                body=cached.body,
                pages=cached.pages,
                cache_status="stale",
                fetched_at=cached.fetched_at,
                expires_at=cached.expires_at,
                offline_snapshot_id=cached.offline_snapshot_id,
            )

        result = self._send_osv_batch_pages(queries, cache_status="stale" if cached is not None else "miss")
        if result.succeeded and self.cache is not None and result.body is not None:
            entry = self.cache.put("osv", cache_key, result.body, pages=result.pages, now=now)
            if entry is not None:
                return self._result(
                    "osv",
                    "success",
                    body=result.body,
                    attempts=result.attempts,
                    pages=result.pages,
                    cache_status=result.cache_status,
                    fetched_at=entry.fetched_at,
                    expires_at=entry.expires_at,
                )
        if cached is not None:
            return self._result(
                "osv",
                "stale_cached",
                body=cached.body,
                attempts=result.attempts,
                pages=cached.pages,
                cache_status="stale",
                fetched_at=cached.fetched_at,
                expires_at=cached.expires_at,
                offline_snapshot_id=cached.offline_snapshot_id,
            )
        return result

    def _offline_cache_entry(
        self,
        provider: PublicAdvisoryProvider,
        cache_key: str,
        *,
        now: datetime,
    ) -> PublicAdvisoryCacheEntry | None:
        if self.cache is None:
            return None
        try:
            from app.offline_advisory_snapshots import get_active_offline_cache_entry

            return get_active_offline_cache_entry(self.cache.directory, provider, cache_key, now=now)
        except Exception:
            return None

    def _send_osv_batch_pages(
        self,
        queries: list[dict[str, Any]],
        *,
        cache_status: PublicAdvisoryCacheStatus,
    ) -> PublicAdvisoryEgressResult:
        """Follow only valid OSV tokens for a fixed, finite number of pages."""

        active_queries = [(index, query) for index, query in enumerate(queries)]
        merged_results: list[list[Any]] = [[] for _ in queries]
        attempts = 0
        pages = 0
        while active_queries:
            if pages >= MAX_OSV_QUERYBATCH_PAGES:
                return self._result("osv", "pagination_incomplete", attempts=attempts, pages=pages, cache_status=cache_status)
            response = self._send(
                "osv",
                json_payload={"queries": [query for _, query in active_queries]},
                cache_status=cache_status,
            )
            attempts += response.attempts
            if not response.succeeded or response.body is None:
                # Once a page token has been seen, a failure cannot be treated
                # as a complete response even if earlier pages were valid.
                status: PublicAdvisoryStatus = "pagination_incomplete" if pages else response.status
                return self._result("osv", status, attempts=attempts, pages=pages, cache_status=cache_status)
            payload = _osv_batch_page_payload(response.body, expected_results=len(active_queries))
            if payload is None:
                return self._result("osv", "invalid_source_response", attempts=attempts, pages=pages, cache_status=cache_status)
            pages += 1
            next_queries: list[tuple[int, dict[str, Any]]] = []
            for (index, original_query), raw_result in zip(active_queries, payload["results"], strict=True):
                # Protobuf JSON omits an empty repeated field, so OSV encodes a
                # clean batch result as ``{}``, not necessarily
                # ``{"vulns": []}``.
                raw_vulnerabilities = raw_result.get("vulns", [])
                merged_results[index].extend(raw_vulnerabilities)
                if len(merged_results[index]) > MAX_OSV_VULNERABILITIES_PER_QUERY:
                    return self._result("osv", "pagination_incomplete", attempts=attempts, pages=pages, cache_status=cache_status)
                next_token = raw_result.get("next_page_token")
                if next_token is not None:
                    if not _is_safe_osv_page_token(next_token):
                        return self._result("osv", "invalid_source_response", attempts=attempts, pages=pages, cache_status=cache_status)
                    next_queries.append((index, {**original_query, "page_token": next_token}))
            active_queries = next_queries

        # Querybatch is intentionally non-hydrated: normally it returns only
        # advisory IDs and modification timestamps. Fetch each unique ID from
        # OSV's fixed vulnerability route before normalisation. A complete
        # advisory already present in a deterministic fixture remains valid,
        # which keeps the ordinary suite offline without weakening validation.
        lightweight_ids = {
            advisory_id
            for values in merged_results
            for value in values
            if not _is_hydrated_osv_advisory(value)
            if (advisory_id := normalize_osv_advisory_identifier(value.get("id") if isinstance(value, dict) else None))
        }
        if len(lightweight_ids) > MAX_OSV_ADVISORIES_PER_BATCH:
            return self._result("osv", "pagination_incomplete", attempts=attempts, pages=pages, cache_status=cache_status)
        hydrated_by_id: dict[str, dict[str, Any]] = {}
        for advisory_id in sorted(lightweight_ids):
            hydrated = self._send_cached(
                "osv",
                cache_key=public_advisory_cache_key("osv", [{"advisory_id": advisory_id}]),
                osv_advisory_id=advisory_id,
            )
            attempts += hydrated.attempts
            if not hydrated.succeeded or hydrated.body is None:
                return self._result("osv", hydrated.status, attempts=attempts, pages=pages, cache_status=cache_status)
            try:
                hydrated_payload = json.loads(hydrated.body)
            except (TypeError, ValueError, UnicodeDecodeError):
                return self._result("osv", "invalid_source_response", attempts=attempts, pages=pages, cache_status=cache_status)
            if not _is_valid_osv_advisory(hydrated_payload, advisory_id):
                return self._result("osv", "invalid_source_response", attempts=attempts, pages=pages, cache_status=cache_status)
            hydrated_by_id[advisory_id] = hydrated_payload

        hydrated_results: list[dict[str, list[Any]]] = []
        for values in merged_results:
            hydrated_values: list[Any] = []
            for value in values:
                if _is_hydrated_osv_advisory(value):
                    hydrated_values.append(value)
                    continue
                advisory_id = normalize_osv_advisory_identifier(value.get("id") if isinstance(value, dict) else None)
                if advisory_id is None or advisory_id not in hydrated_by_id:
                    return self._result("osv", "invalid_source_response", attempts=attempts, pages=pages, cache_status=cache_status)
                hydrated_values.append(hydrated_by_id[advisory_id])
            hydrated_results.append({"vulns": hydrated_values})

        body = json.dumps({"results": hydrated_results}, separators=(",", ":")).encode("utf-8")
        if len(body) > self.max_response_bytes:
            return self._result("osv", "response_too_large", attempts=attempts, pages=pages, cache_status=cache_status)
        return self._result("osv", "success", body=body, attempts=attempts, pages=pages, cache_status=cache_status)

    def _send(
        self,
        provider: PublicAdvisoryProvider,
        *,
        json_payload: dict[str, Any] | None = None,
        query_params: dict[str, str] | None = None,
        osv_advisory_id: str | None = None,
        nvd_cve_id: str | None = None,
        cache_status: PublicAdvisoryCacheStatus = "not_used",
    ) -> PublicAdvisoryEgressResult:
        if not self.enabled:
            return self._result(provider, "disabled")
        fixed_endpoint = (
            _fixed_osv_advisory_endpoint(osv_advisory_id)
            if provider == "osv" and osv_advisory_id is not None
            else _fixed_provider_endpoint(provider)
        )
        if fixed_endpoint is None:
            # The mapping is internal, but treat an unexpected future edit as
            # an unavailable source rather than permitting a new destination
            # or exposing the malformed value through telemetry.
            return self._result(provider, "source_error")
        if self._provider_circuit_is_open(provider):
            return self._result(provider, "circuit_open", cache_status=cache_status)
        if not self._semaphore.acquire(blocking=False):
            return self._result(provider, "concurrency_limited")

        try:
            method, endpoint = fixed_endpoint
            attempts = 0
            while True:
                attempts += 1
                try:
                    with httpx.Client(
                        follow_redirects=False,
                        timeout=httpx.Timeout(self.timeout_seconds),
                        transport=self.http_transport,
                        trust_env=False,
                    ) as client:
                        with client.stream(
                            method,
                            endpoint,
                            json=json_payload,
                            params=query_params,
                            headers=_provider_headers(provider),
                        ) as response:
                            response_status = _response_status(response.status_code)
                            if response_status == "success":
                                body = _read_bounded_response(response, self.max_response_bytes)
                                if body is None:
                                    return self._result(provider, "response_too_large", attempts=attempts, cache_status=cache_status)
                                if not _is_json_content_type(response.headers.get("content-type")):
                                    return self._result(provider, "invalid_content_type", attempts=attempts, cache_status=cache_status)
                                expected_results = len(json_payload.get("queries", [])) if provider == "osv" and isinstance(json_payload, dict) else None
                                if not _is_expected_provider_response(
                                    provider,
                                    body,
                                    expected_results=expected_results,
                                    expected_osv_advisory_id=osv_advisory_id,
                                    expected_nvd_cve_id=nvd_cve_id,
                                ):
                                    return self._result(provider, "invalid_source_response", attempts=attempts, cache_status=cache_status)
                                self._record_provider_success(provider)
                                return self._result(provider, "success", body=body, attempts=attempts, pages=1, cache_status=cache_status)
                except httpx.TimeoutException:
                    response_status = "timed_out"
                except httpx.TransportError:
                    response_status = "unavailable"
                except Exception:
                    response_status = "source_error"

                if response_status in {"source_error", "timed_out", "unavailable"} and attempts <= self.max_retries:
                    self.sleep(0.1 * attempts)
                    continue
                if response_status in {"rate_limited", "timed_out", "unavailable"}:
                    self._record_provider_failure(provider)
                return self._result(provider, response_status, attempts=attempts, cache_status=cache_status)
        finally:
            self._semaphore.release()

    def _provider_circuit_is_open(self, provider: PublicAdvisoryProvider) -> bool:
        now = self.clock()
        if now.tzinfo is None or now.utcoffset() is None:
            return True
        current = now.astimezone(timezone.utc)
        with self._circuit_lock:
            failures, opened_until = self._provider_failures.get(provider, (0, None))
            if opened_until is None:
                return False
            if current < opened_until:
                return True
            self._provider_failures[provider] = (0, None)
            return False

    def _record_provider_failure(self, provider: PublicAdvisoryProvider) -> None:
        now = self.clock()
        if now.tzinfo is None or now.utcoffset() is None:
            return
        current = now.astimezone(timezone.utc)
        with self._circuit_lock:
            failures, _ = self._provider_failures.get(provider, (0, None))
            failures += 1
            opened_until = (
                current + timedelta(seconds=PROVIDER_CIRCUIT_COOLDOWN_SECONDS)
                if failures >= PROVIDER_CIRCUIT_FAILURE_THRESHOLD
                else None
            )
            self._provider_failures[provider] = (failures, opened_until)

    def _record_provider_success(self, provider: PublicAdvisoryProvider) -> None:
        with self._circuit_lock:
            self._provider_failures.pop(provider, None)

    @staticmethod
    def _result(
        provider: PublicAdvisoryProvider,
        status: PublicAdvisoryStatus,
        *,
        body: bytes | None = None,
        attempts: int = 0,
        pages: int = 0,
        cache_status: PublicAdvisoryCacheStatus = "not_used",
        fetched_at: datetime | None = None,
        expires_at: datetime | None = None,
        offline_snapshot_id: str | None = None,
    ) -> PublicAdvisoryEgressResult:
        # Never log a package, version, endpoint, response body, project, owner,
        # filesystem path, or source hash. Provider/status are enough to operate it.
        log_audit_event(
            "public_advisory.egress",
            provider=provider,
            status=status,
            attempts=attempts,
            pages=pages,
            cache_status=cache_status,
            fetched_at=_render_utc_timestamp(fetched_at) if fetched_at is not None else None,
            expires_at=_render_utc_timestamp(expires_at) if expires_at is not None else None,
            response_bytes=len(body) if body is not None else None,
        )
        return PublicAdvisoryEgressResult(
            provider=provider,
            status=status,
            body=body,
            attempts=attempts,
            pages=pages,
            cache_status=cache_status,
            fetched_at=fetched_at,
            expires_at=expires_at,
            offline_snapshot_id=offline_snapshot_id,
        )


def normalize_osv_component_identity(
    component: PublicComponentIdentity,
    *,
    namespace_policy: PublicAdvisoryNamespacePolicy | None = None,
) -> dict[str, Any] | None:
    """Produce OSV's minimal package identity or reject unsafe/non-public shapes.

    The initial integration intentionally declines scoped npm packages.  A scope
    can identify a private namespace, and Inspectra has no safe evidence that it
    is public.  Later support requires explicit namespace-governance work.
    """

    if not isinstance(component, PublicComponentIdentity):
        return None
    if not _is_safe_exact_version(component.version):
        return None
    normalized_name = _normalize_component_name(component.ecosystem, component.name)
    if normalized_name is None:
        return None
    if namespace_policy is not None and namespace_policy.excludes(component):
        return None
    normalized_version = component.version.strip()
    if component.ecosystem == "npm":
        if normalized_name.startswith("@"):
            return None
        osv_ecosystem = "npm"
    elif component.ecosystem == "pypi":
        osv_ecosystem = "PyPI"
    elif component.ecosystem == "go":
        osv_ecosystem = "Go"
    elif component.ecosystem == "cargo":
        osv_ecosystem = "crates.io"
    elif component.ecosystem == "composer":
        osv_ecosystem = "Packagist"
    elif component.ecosystem == "maven":
        osv_ecosystem = "Maven"
    elif component.ecosystem == "nuget":
        osv_ecosystem = "NuGet"
        normalized_version = canonicalize_nuget_version(component.version) or ""
        if not normalized_version:
            return None
    else:  # pragma: no cover - defensive for callers beyond the type contract.
        return None
    return {
        "package": {"ecosystem": osv_ecosystem, "name": normalized_name},
        "version": normalized_version,
    }


def _normalize_component_name(ecosystem: object, value: object) -> str | None:
    if not isinstance(value, str):
        return None
    if ecosystem == "npm":
        normalized_name = value.strip().lower()
        return normalized_name if _NPM_PACKAGE_NAME.fullmatch(normalized_name) else None
    if ecosystem == "pypi":
        candidate = value.strip().lower()
        return _PYPI_NORMALIZATION.sub("-", candidate) if _PYPI_PACKAGE_NAME.fullmatch(candidate) else None
    if ecosystem == "go":
        candidate = value.strip()
        if candidate != candidate.lower() or len(candidate) > 300:
            return None
        if not re.fullmatch(r"[a-z0-9][a-z0-9._~-]*(?:/[a-z0-9][a-z0-9._~+\-]*)+", candidate):
            return None
        return candidate if "." in candidate.split("/", 1)[0] else None
    if ecosystem == "cargo":
        candidate = value.strip()
        return candidate if len(candidate) <= 128 and _CARGO_PACKAGE_NAME.fullmatch(candidate) else None
    if ecosystem == "composer":
        candidate = value.strip()
        return candidate if len(candidate) <= 200 and candidate == candidate.lower() and _COMPOSER_PACKAGE_NAME.fullmatch(candidate) else None
    if ecosystem == "maven":
        candidate = value.strip()
        return candidate if len(candidate) <= 321 and candidate == candidate.lower() and _MAVEN_PACKAGE_NAME.fullmatch(candidate) else None
    if ecosystem == "nuget":
        candidate = value.strip().lower()
        return candidate if len(candidate) <= 200 and re.fullmatch(r"[a-z0-9][a-z0-9_.-]*", candidate) else None
    return None


def normalize_public_component_name(ecosystem: object, value: object) -> str | None:
    """Expose the canonical public-package grammar without accepting versions or URLs."""

    return _normalize_component_name(ecosystem, value)


def normalize_github_advisory_identifier(value: object) -> str | None:
    """Accept only one syntactically valid public GHSA identifier."""

    if not isinstance(value, str):
        return None
    normalized = value.strip().upper()
    return normalized if _GHSA_IDENTIFIER.fullmatch(normalized) else None


def normalize_nvd_cve_identifier(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip().upper()
    return normalized if _CVE_IDENTIFIER.fullmatch(normalized) else None


def normalize_osv_advisory_identifier(value: object) -> str | None:
    """Accept only a provider-returned identifier safe for OSV's fixed path."""

    if not isinstance(value, str):
        return None
    normalized = value.strip()
    return normalized if _OSV_ADVISORY_IDENTIFIER.fullmatch(normalized) else None


def _is_safe_exact_version(value: object) -> bool:
    if not isinstance(value, str):
        return False
    normalized = value.strip()
    return bool(normalized) and len(normalized) <= 200 and not any(
        character.isspace()
        or ord(character) < 32
        or character in {"/", "\\", "?", "#", "@"}
        or character in _VERSION_SPECIFIER_MARKERS
        for character in normalized
    )


def _response_status(status_code: int) -> PublicAdvisoryStatus:
    if status_code == 200:
        return "success"
    if status_code in {301, 302, 303, 307, 308}:
        return "redirect_blocked"
    if status_code == 429:
        return "rate_limited"
    if status_code in {408, 504}:
        return "timed_out"
    if status_code in {500, 502, 503}:
        return "unavailable"
    return "provider_rejected"


def _fixed_provider_endpoint(provider: PublicAdvisoryProvider) -> tuple[str, str] | None:
    """Return a verified internal destination or fail closed without egress.

    The public-advisory client deliberately has no caller-supplied endpoint.
    This additional check protects that invariant against a future internal
    refactor: approved providers have one HTTPS host and one path, with no
    userinfo, port, query or fragment.  DNS/firewall enforcement remains a
    deployment responsibility documented separately.
    """

    try:
        method, endpoint = PUBLIC_ADVISORY_ENDPOINTS[provider]
        expected_method, expected_host, expected_path = _PUBLIC_ADVISORY_ENDPOINT_INVARIANTS[provider]
        parsed = urlsplit(endpoint)
        port = parsed.port
    except (KeyError, TypeError, ValueError):
        return None
    if not isinstance(method, str) or not isinstance(endpoint, str):
        return None
    if (
        method != expected_method
        or parsed.scheme != "https"
        or parsed.hostname != expected_host
        or port is not None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path != expected_path
        or parsed.query
        or parsed.fragment
    ):
        return None
    return method, endpoint


def _fixed_osv_advisory_endpoint(advisory_id: object) -> tuple[str, str] | None:
    """Build one OSV detail route from a strictly validated provider ID."""

    normalized = normalize_osv_advisory_identifier(advisory_id)
    if normalized is None:
        return None
    endpoint = f"{OSV_VULNERABILITY_URL_PREFIX}{normalized}"
    try:
        parsed = urlsplit(endpoint)
        port = parsed.port
    except (TypeError, ValueError):
        return None
    if (
        parsed.scheme != "https"
        or parsed.hostname != "api.osv.dev"
        or port is not None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path != f"/v1/vulns/{normalized}"
        or parsed.query
        or parsed.fragment
    ):
        return None
    return "GET", endpoint


def _provider_headers(provider: PublicAdvisoryProvider) -> dict[str, str]:
    headers = {
        "Accept": "application/json",
        "User-Agent": "Inspectra-public-advisory/0.1",
    }
    if provider == "github_advisories":
        # Static vendor headers only: callers cannot introduce an access token
        # or negotiate a different API version through this egress boundary.
        headers["Accept"] = "application/vnd.github+json"
        headers["X-GitHub-Api-Version"] = "2022-11-28"
    return headers


def _read_bounded_response(response: httpx.Response, maximum: int) -> bytes | None:
    content_length = response.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > maximum:
                return None
        except ValueError:
            return None
    chunks: list[bytes] = []
    total = 0
    for chunk in response.iter_bytes():
        total += len(chunk)
        if total > maximum:
            return None
        chunks.append(chunk)
    return b"".join(chunks)


def _is_json_content_type(value: object) -> bool:
    """Require an explicit JSON media type before accepting provider data."""

    if not isinstance(value, str):
        return False
    media_type = value.split(";", 1)[0].strip().lower()
    return media_type == "application/json" or media_type.endswith("+json")


def _is_expected_provider_response(
    provider: PublicAdvisoryProvider,
    body: bytes,
    *,
    expected_results: int | None = None,
    expected_osv_advisory_id: str | None = None,
    expected_nvd_cve_id: str | None = None,
) -> bool:
    """Apply bounded provider-root checks before cache persistence.

    This deliberately avoids project correlation. It rejects HTML, invalid
    JSON, incorrect roots and unbounded collections before cache persistence;
    the global KEV catalog also crosses its schema-only normalizer here because
    it carries no project identity.
    """

    try:
        payload = json.loads(body)
    except (TypeError, ValueError, UnicodeDecodeError):
        return False
    if provider == "osv":
        if expected_osv_advisory_id is not None:
            return _is_valid_osv_advisory(payload, expected_osv_advisory_id)
        return _is_valid_osv_batch_page(payload, expected_results=expected_results)
    if provider == "github_advisories":
        return isinstance(payload, list) and len(payload) <= MAX_GITHUB_ADVISORIES_PER_LOOKUP and all(
            isinstance(advisory, dict) for advisory in payload
        )
    if provider == "nvd":
        vulnerabilities = payload.get("vulnerabilities") if isinstance(payload, dict) else None
        total = payload.get("totalResults") if isinstance(payload, dict) else None
        if not (
            payload.get("format") == "NVD_CVE"
            and payload.get("version") == "2.0"
            and isinstance(total, int)
            and not isinstance(total, bool)
            and total in {0, 1}
            and isinstance(vulnerabilities, list)
            and len(vulnerabilities) <= MAX_NVD_CVES_PER_LOOKUP
            and len(vulnerabilities) == total
        ):
            return False
        if total == 0:
            return expected_nvd_cve_id is not None
        item = vulnerabilities[0]
        returned_id = item.get("cve", {}).get("id") if isinstance(item, dict) else None
        return normalize_nvd_cve_identifier(returned_id) == expected_nvd_cve_id
    if provider == "cisa_kev":
        from app.cisa_kev import normalize_cisa_kev_feed

        return normalize_cisa_kev_feed(payload).status == "ready"
    return False


def _osv_batch_page_payload(body: bytes, *, expected_results: int) -> dict[str, Any] | None:
    """Decode a page already accepted by the transport, defensively again."""

    try:
        payload = json.loads(body)
    except (TypeError, ValueError, UnicodeDecodeError):
        return None
    return payload if _is_valid_osv_batch_page(payload, expected_results=expected_results) else None


def _is_valid_osv_batch_page(payload: object, *, expected_results: int | None) -> bool:
    if not isinstance(payload, dict) or not isinstance(expected_results, int) or expected_results < 1:
        return False
    results = payload.get("results")
    if not isinstance(results, list) or len(results) != expected_results:
        return False
    for result in results:
        if not isinstance(result, dict):
            return False
        raw_vulnerabilities = result.get("vulns", [])
        if not isinstance(raw_vulnerabilities, list) or len(raw_vulnerabilities) > MAX_OSV_VULNERABILITIES_PER_PAGE:
            return False
        if any(
            not isinstance(vulnerability, dict)
            or normalize_osv_advisory_identifier(vulnerability.get("id")) is None
            for vulnerability in raw_vulnerabilities
        ):
            return False
        if "next_page_token" in result and not _is_safe_osv_page_token(result.get("next_page_token")):
            return False
    return True


def _is_hydrated_osv_advisory(value: object) -> bool:
    return (
        isinstance(value, dict)
        and normalize_osv_advisory_identifier(value.get("id")) is not None
        and isinstance(value.get("affected"), list)
    )


def _is_valid_osv_advisory(payload: object, expected_identifier: str) -> bool:
    return (
        isinstance(payload, dict)
        and normalize_osv_advisory_identifier(payload.get("id")) == expected_identifier
        and isinstance(payload.get("affected"), list)
        and isinstance(payload.get("modified"), str)
        and len(payload.get("modified", "")) <= 80
    )


def _is_safe_osv_page_token(value: object) -> bool:
    return isinstance(value, str) and bool(_OSV_PAGE_TOKEN.fullmatch(value)) and len(value) <= MAX_OSV_PAGE_TOKEN_LENGTH


def public_advisory_cache_key(provider: PublicAdvisoryProvider, queries: list[dict[str, Any]]) -> str:
    """Return a one-way cache key without retaining component or project values."""

    if provider not in PUBLIC_ADVISORY_ENDPOINTS:
        raise ValueError("Unknown public advisory provider.")
    payload = json.dumps({"provider": provider, "queries": queries}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _parse_utc_timestamp(value: object) -> datetime:
    if not isinstance(value, str):
        raise ValueError("Invalid cached timestamp.")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Cached timestamp requires timezone.")
    return parsed.astimezone(timezone.utc)


def _render_utc_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
