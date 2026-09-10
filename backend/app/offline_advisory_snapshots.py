"""Atomic, checksum-bound imports of bounded public advisory responses.

The operator supplies a local JSON file and its SHA-256 through a separate
channel.  Inspectra never downloads a bundle, accepts a URL, or executes its
contents.  Imported query identities are reduced to the same one-way cache key
used by live egress before persistence.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import base64
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Literal
from uuid import uuid4

from app.cisa_kev import normalize_cisa_kev_feed
from app.nvd_advisories import normalize_nvd_cve_response
from app.public_advisories import normalize_osv_batch_response
from app.public_advisory_egress import (
    MAX_OSV_QUERYBATCH_PAGES,
    PublicAdvisoryCacheEntry,
    PublicAdvisoryProvider,
    PublicComponentIdentity,
    _is_expected_provider_response,
    normalize_github_advisory_identifier,
    normalize_nvd_cve_identifier,
    normalize_osv_component_identity,
    public_advisory_cache_key,
)


OFFLINE_ADVISORY_BUNDLE_CONTRACT_VERSION = "2026-09-09.1"
OFFLINE_ADVISORY_SNAPSHOT_SCHEMA = "2026-09-09.1"
OFFLINE_ADVISORY_BUNDLE_KIND = "inspectra_public_advisory_offline_bundle"
MAX_OFFLINE_BUNDLE_BYTES = 16 * 1024 * 1024
MAX_OFFLINE_ENTRIES = 5_000
MAX_OFFLINE_IDENTITIES_PER_ENTRY = 100
MAX_OFFLINE_ENTRY_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_OFFLINE_TOTAL_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_OFFLINE_VALIDITY = timedelta(days=30)
_DIGEST = re.compile(r"^[a-f0-9]{64}$")
_ALLOWED_ENTRY_KEYS = frozenset({"provider", "identities", "lookup_id", "pages", "response"})
_ALLOWED_BUNDLE_KEYS = frozenset({"contract_version", "kind", "created_at", "expires_at", "entries"})


class OfflineAdvisorySnapshotError(RuntimeError):
    """A controlled error code that never contains paths or provider bodies."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def import_offline_advisory_bundle(
    bundle_path: Path,
    destination: Path,
    *,
    expected_sha256: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Validate completely, then atomically publish an active safe snapshot."""

    expected = expected_sha256.strip().lower() if isinstance(expected_sha256, str) else ""
    if not _DIGEST.fullmatch(expected):
        raise OfflineAdvisorySnapshotError("expected_sha256_invalid")
    raw = _read_bounded_regular_file(bundle_path)
    if hashlib.sha256(raw).hexdigest() != expected:
        raise OfflineAdvisorySnapshotError("bundle_checksum_mismatch")
    payload = _strict_json_object(raw)
    current = _aware_utc(now or datetime.now(timezone.utc))
    safe = _normalize_bundle(payload, bundle_sha256=expected, imported_at=current)
    snapshot_id = safe["snapshot_id"]
    root = destination / "offline"
    snapshots = root / "snapshots"
    _safe_directory_boundary(destination, root, snapshots)
    history_path = snapshots / f"{snapshot_id}.json"
    active_path = root / "active.json"
    encoded = _canonical_json(safe)
    try:
        snapshots.mkdir(parents=True, exist_ok=True)
        if history_path.exists():
            if history_path.is_symlink() or not history_path.is_file() or history_path.read_bytes() != encoded:
                raise OfflineAdvisorySnapshotError("snapshot_history_conflict")
            raise OfflineAdvisorySnapshotError("snapshot_already_imported")
        else:
            _atomic_write_new(history_path, encoded)
        _atomic_replace(active_path, encoded)
    except OfflineAdvisorySnapshotError:
        raise
    except OSError as exc:
        raise OfflineAdvisorySnapshotError("snapshot_publish_failed") from exc
    return _snapshot_summary(safe)


def activate_offline_advisory_snapshot(
    destination: Path,
    snapshot_id: str,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Atomically roll back/forward to an already validated retained snapshot."""

    if not isinstance(snapshot_id, str) or not _DIGEST.fullmatch(snapshot_id):
        raise OfflineAdvisorySnapshotError("snapshot_id_invalid")
    root = destination / "offline"
    snapshots = root / "snapshots"
    _safe_directory_boundary(destination, root, snapshots)
    path = snapshots / f"{snapshot_id}.json"
    safe = _read_persisted_snapshot(path)
    current = _aware_utc(now or datetime.now(timezone.utc))
    if _parse_timestamp(safe["expires_at"]) < current:
        raise OfflineAdvisorySnapshotError("snapshot_expired")
    try:
        _atomic_replace(root / "active.json", _canonical_json(safe))
    except OSError as exc:
        raise OfflineAdvisorySnapshotError("snapshot_publish_failed") from exc
    return _snapshot_summary(safe)


def get_active_offline_advisory_snapshot(destination: Path) -> dict[str, Any] | None:
    path = destination / "offline" / "active.json"
    if not path.exists():
        return None
    return _snapshot_summary(_read_persisted_snapshot(path))


def get_active_offline_cache_entry(
    destination: Path,
    provider: PublicAdvisoryProvider,
    key: str,
    *,
    now: datetime,
) -> PublicAdvisoryCacheEntry | None:
    """Resolve a digest key without exposing the identities stored in the bundle."""

    if not _DIGEST.fullmatch(key):
        return None
    try:
        safe = _read_persisted_snapshot(destination / "offline" / "active.json")
    except OfflineAdvisorySnapshotError:
        return None
    fetched_at = _parse_timestamp(safe["imported_at"])
    expires_at = _parse_timestamp(safe["expires_at"])
    current = _aware_utc(now)
    # Keep expired evidence available as a stale fallback for at most the same
    # bounded 30-day window allowed to a bundle. It can never become `fresh`.
    if current > expires_at + MAX_OFFLINE_VALIDITY:
        return None
    for entry in safe["entries"]:
        if entry["provider"] != provider or entry["key"] != key:
            continue
        try:
            body = base64.b64decode(entry["body"], validate=True)
        except (TypeError, ValueError):
            return None
        return PublicAdvisoryCacheEntry(
            provider=provider,
            body=body,
            fetched_at=fetched_at,
            expires_at=expires_at,
            pages=entry["pages"],
            offline_snapshot_id=safe["snapshot_id"],
        )
    return None


def _normalize_bundle(payload: dict[str, Any], *, bundle_sha256: str, imported_at: datetime) -> dict[str, Any]:
    if set(payload) != _ALLOWED_BUNDLE_KEYS:
        raise OfflineAdvisorySnapshotError("bundle_contract_invalid")
    if payload.get("contract_version") != OFFLINE_ADVISORY_BUNDLE_CONTRACT_VERSION:
        raise OfflineAdvisorySnapshotError("bundle_contract_invalid")
    if payload.get("kind") != OFFLINE_ADVISORY_BUNDLE_KIND:
        raise OfflineAdvisorySnapshotError("bundle_contract_invalid")
    created_at = _parse_timestamp(payload.get("created_at"))
    expires_at = _parse_timestamp(payload.get("expires_at"))
    if (
        created_at > imported_at + timedelta(minutes=5)
        or expires_at <= created_at
        or expires_at - created_at > MAX_OFFLINE_VALIDITY
        or expires_at <= imported_at
    ):
        raise OfflineAdvisorySnapshotError("bundle_freshness_invalid")
    raw_entries = payload.get("entries")
    if not isinstance(raw_entries, list) or not raw_entries or len(raw_entries) > MAX_OFFLINE_ENTRIES:
        raise OfflineAdvisorySnapshotError("bundle_entries_invalid")
    entries: list[dict[str, Any]] = []
    total_bytes = 0
    seen: set[tuple[str, str]] = set()
    for raw_entry in raw_entries:
        normalized = _normalize_entry(raw_entry)
        total_bytes += len(base64.b64decode(normalized["body"], validate=True))
        if total_bytes > MAX_OFFLINE_TOTAL_RESPONSE_BYTES:
            raise OfflineAdvisorySnapshotError("bundle_response_limit_exceeded")
        identity = (normalized["provider"], normalized["key"])
        if identity in seen:
            raise OfflineAdvisorySnapshotError("bundle_entry_duplicate")
        seen.add(identity)
        entries.append(normalized)
    core = {
        "schema": OFFLINE_ADVISORY_SNAPSHOT_SCHEMA,
        "bundle_sha256": bundle_sha256,
        "created_at": _render_timestamp(created_at),
        "expires_at": _render_timestamp(expires_at),
        "entries": sorted(entries, key=lambda value: (value["provider"], value["key"])),
    }
    snapshot_id = hashlib.sha256(_canonical_json(core)).hexdigest()
    return {
        **core,
        "snapshot_id": snapshot_id,
        "imported_at": _render_timestamp(imported_at),
    }


def _normalize_entry(raw: object) -> dict[str, Any]:
    if not isinstance(raw, dict) or not set(raw).issubset(_ALLOWED_ENTRY_KEYS):
        raise OfflineAdvisorySnapshotError("bundle_entry_invalid")
    provider = raw.get("provider")
    if provider not in {"osv", "github_advisories", "nvd", "cisa_kev"}:
        raise OfflineAdvisorySnapshotError("bundle_entry_invalid")
    pages = raw.get("pages", 1)
    if not isinstance(pages, int) or isinstance(pages, bool) or not 1 <= pages <= MAX_OSV_QUERYBATCH_PAGES:
        raise OfflineAdvisorySnapshotError("bundle_entry_invalid")
    if provider != "osv" and pages != 1:
        raise OfflineAdvisorySnapshotError("bundle_entry_invalid")
    response = raw.get("response")
    body = _canonical_json(response)
    if len(body) > MAX_OFFLINE_ENTRY_RESPONSE_BYTES:
        raise OfflineAdvisorySnapshotError("bundle_response_limit_exceeded")

    expected_results: int | None = None
    expected_osv_advisory_id: str | None = None
    expected_nvd_cve_id: str | None = None
    if provider == "osv":
        raw_identities = raw.get("identities")
        if (
            raw.get("lookup_id") is not None
            or not isinstance(raw_identities, list)
            or not raw_identities
            or len(raw_identities) > MAX_OFFLINE_IDENTITIES_PER_ENTRY
        ):
            raise OfflineAdvisorySnapshotError("bundle_entry_invalid")
        identities = [_normalize_identity(value) for value in raw_identities]
        expected_results = len(identities)
        key_values = [normalize_osv_component_identity(value) for value in identities]
        if any(value is None for value in key_values):
            raise OfflineAdvisorySnapshotError("bundle_identity_invalid")
        normalization = normalize_osv_batch_response(identities, response)
        if normalization.status != "ready" or normalization.errors:
            raise OfflineAdvisorySnapshotError("bundle_response_invalid")
        key = public_advisory_cache_key("osv", key_values)
    elif provider == "github_advisories":
        if raw.get("identities") is not None:
            raise OfflineAdvisorySnapshotError("bundle_entry_invalid")
        lookup_id = normalize_github_advisory_identifier(raw.get("lookup_id"))
        if lookup_id is None:
            raise OfflineAdvisorySnapshotError("bundle_identity_invalid")
        if not isinstance(response, list) or any(
            not isinstance(value, dict) or normalize_github_advisory_identifier(value.get("ghsa_id")) != lookup_id
            for value in response
        ):
            raise OfflineAdvisorySnapshotError("bundle_response_invalid")
        key = public_advisory_cache_key("github_advisories", [{"ghsa_id": lookup_id}])
    elif provider == "nvd":
        if raw.get("identities") is not None:
            raise OfflineAdvisorySnapshotError("bundle_entry_invalid")
        lookup_id = normalize_nvd_cve_identifier(raw.get("lookup_id"))
        if lookup_id is None or normalize_nvd_cve_response(lookup_id, response).status not in {"ready", "not_found"}:
            raise OfflineAdvisorySnapshotError("bundle_response_invalid")
        expected_nvd_cve_id = lookup_id
        key = public_advisory_cache_key("nvd", [{"cve_id": lookup_id}])
    else:
        if raw.get("identities") is not None or raw.get("lookup_id") is not None:
            raise OfflineAdvisorySnapshotError("bundle_entry_invalid")
        normalization = normalize_cisa_kev_feed(response)
        if normalization.status != "ready" or normalization.errors:
            raise OfflineAdvisorySnapshotError("bundle_response_invalid")
        key = public_advisory_cache_key("cisa_kev", [])

    if not _is_expected_provider_response(
        provider,
        body,
        expected_results=expected_results,
        expected_osv_advisory_id=expected_osv_advisory_id,
        expected_nvd_cve_id=expected_nvd_cve_id,
    ):
        raise OfflineAdvisorySnapshotError("bundle_response_invalid")
    return {
        "provider": provider,
        "key": key,
        "pages": pages,
        "body": base64.b64encode(body).decode("ascii"),
        "response_sha256": hashlib.sha256(body).hexdigest(),
    }


def _normalize_identity(raw: object) -> PublicComponentIdentity:
    if not isinstance(raw, dict) or set(raw) != {"ecosystem", "name", "version"}:
        raise OfflineAdvisorySnapshotError("bundle_identity_invalid")
    try:
        identity = PublicComponentIdentity(
            ecosystem=raw["ecosystem"],
            name=raw["name"],
            version=raw["version"],
        )
    except TypeError as exc:
        raise OfflineAdvisorySnapshotError("bundle_identity_invalid") from exc
    normalized = normalize_osv_component_identity(identity)
    # Scoped npm names remain potentially private even when syntactically valid.
    if normalized is None or (identity.ecosystem == "npm" and normalized["package"]["name"].startswith("@")):
        raise OfflineAdvisorySnapshotError("bundle_identity_invalid")
    return identity


def _read_bounded_regular_file(path: Path) -> bytes:
    try:
        if path.is_symlink() or not path.is_file():
            raise OfflineAdvisorySnapshotError("bundle_file_invalid")
        if path.stat().st_size > MAX_OFFLINE_BUNDLE_BYTES:
            raise OfflineAdvisorySnapshotError("bundle_size_exceeded")
        raw = path.read_bytes()
    except OfflineAdvisorySnapshotError:
        raise
    except OSError as exc:
        raise OfflineAdvisorySnapshotError("bundle_file_unavailable") from exc
    if len(raw) > MAX_OFFLINE_BUNDLE_BYTES:
        raise OfflineAdvisorySnapshotError("bundle_size_exceeded")
    return raw


def _strict_json_object(raw: bytes) -> dict[str, Any]:
    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise OfflineAdvisorySnapshotError("bundle_duplicate_json_key")
            result[key] = value
        return result

    try:
        value = json.loads(raw, object_pairs_hook=pairs)
    except OfflineAdvisorySnapshotError:
        raise
    except (TypeError, ValueError, UnicodeDecodeError) as exc:
        raise OfflineAdvisorySnapshotError("bundle_json_invalid") from exc
    if not isinstance(value, dict):
        raise OfflineAdvisorySnapshotError("bundle_contract_invalid")
    return value


def _read_persisted_snapshot(path: Path) -> dict[str, Any]:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_OFFLINE_BUNDLE_BYTES * 2:
            raise OfflineAdvisorySnapshotError("snapshot_invalid")
        value = json.loads(path.read_text(encoding="utf-8"))
    except OfflineAdvisorySnapshotError:
        raise
    except (OSError, TypeError, ValueError) as exc:
        raise OfflineAdvisorySnapshotError("snapshot_invalid") from exc
    required = {"schema", "snapshot_id", "bundle_sha256", "created_at", "imported_at", "expires_at", "entries"}
    if not isinstance(value, dict) or set(value) != required or value.get("schema") != OFFLINE_ADVISORY_SNAPSHOT_SCHEMA:
        raise OfflineAdvisorySnapshotError("snapshot_invalid")
    if not _DIGEST.fullmatch(str(value.get("snapshot_id", ""))) or not _DIGEST.fullmatch(str(value.get("bundle_sha256", ""))):
        raise OfflineAdvisorySnapshotError("snapshot_invalid")
    created_at = _parse_timestamp(value.get("created_at"))
    imported_at = _parse_timestamp(value.get("imported_at"))
    expires_at = _parse_timestamp(value.get("expires_at"))
    if (
        expires_at <= created_at
        or expires_at - created_at > MAX_OFFLINE_VALIDITY
        or imported_at < created_at - timedelta(minutes=5)
    ):
        raise OfflineAdvisorySnapshotError("snapshot_invalid")
    entries = value.get("entries")
    if not isinstance(entries, list) or not entries or len(entries) > MAX_OFFLINE_ENTRIES:
        raise OfflineAdvisorySnapshotError("snapshot_invalid")
    seen: set[tuple[str, str]] = set()
    total_bytes = 0
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"provider", "key", "pages", "body", "response_sha256"}:
            raise OfflineAdvisorySnapshotError("snapshot_invalid")
        provider = entry["provider"]
        pages = entry["pages"]
        response_sha256 = entry["response_sha256"]
        if (
            provider not in {"osv", "github_advisories", "nvd", "cisa_kev"}
            or not _DIGEST.fullmatch(str(entry["key"]))
            or not isinstance(pages, int)
            or isinstance(pages, bool)
            or not 1 <= pages <= MAX_OSV_QUERYBATCH_PAGES
            or (provider != "osv" and pages != 1)
            or not isinstance(response_sha256, str)
            or not _DIGEST.fullmatch(response_sha256)
        ):
            raise OfflineAdvisorySnapshotError("snapshot_invalid")
        identity = (provider, entry["key"])
        if identity in seen:
            raise OfflineAdvisorySnapshotError("snapshot_invalid")
        seen.add(identity)
        try:
            body = base64.b64decode(entry["body"], validate=True)
        except (TypeError, ValueError) as exc:
            raise OfflineAdvisorySnapshotError("snapshot_invalid") from exc
        total_bytes += len(body)
        if (
            len(body) > MAX_OFFLINE_ENTRY_RESPONSE_BYTES
            or total_bytes > MAX_OFFLINE_TOTAL_RESPONSE_BYTES
            or hashlib.sha256(body).hexdigest() != response_sha256
        ):
            raise OfflineAdvisorySnapshotError("snapshot_invalid")
    core = {key: value[key] for key in ("schema", "bundle_sha256", "created_at", "expires_at", "entries")}
    if hashlib.sha256(_canonical_json(core)).hexdigest() != value["snapshot_id"]:
        raise OfflineAdvisorySnapshotError("snapshot_invalid")
    return value


def _snapshot_summary(value: dict[str, Any]) -> dict[str, Any]:
    providers = sorted({entry["provider"] for entry in value["entries"]})
    return {
        "contract_version": OFFLINE_ADVISORY_SNAPSHOT_SCHEMA,
        "snapshot_id": value["snapshot_id"],
        "bundle_sha256": value["bundle_sha256"],
        "created_at": value["created_at"],
        "imported_at": value["imported_at"],
        "expires_at": value["expires_at"],
        "entry_count": len(value["entries"]),
        "providers": providers,
    }


def _safe_directory_boundary(destination: Path, root: Path, snapshots: Path) -> None:
    if destination.is_symlink() or root.is_symlink() or snapshots.is_symlink():
        raise OfflineAdvisorySnapshotError("snapshot_directory_invalid")


def _atomic_write_new(path: Path, body: bytes) -> None:
    temporary = path.with_suffix(f".tmp-{uuid4().hex}")
    try:
        with temporary.open("xb") as handle:
            handle.write(body)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def _atomic_replace(path: Path, body: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(f".tmp-{uuid4().hex}")
    try:
        with temporary.open("xb") as handle:
            handle.write(body)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise OfflineAdvisorySnapshotError("bundle_json_invalid") from exc


def _parse_timestamp(value: object) -> datetime:
    if not isinstance(value, str):
        raise OfflineAdvisorySnapshotError("bundle_timestamp_invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise OfflineAdvisorySnapshotError("bundle_timestamp_invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise OfflineAdvisorySnapshotError("bundle_timestamp_invalid")
    return parsed.astimezone(timezone.utc)


def _aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise OfflineAdvisorySnapshotError("clock_invalid")
    return value.astimezone(timezone.utc).replace(microsecond=0)


def _render_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
