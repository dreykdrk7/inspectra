"""Defensive, CVE-only normalization for the fixed CISA KEV catalog.

The catalog is a public, global feed.  This module receives no project data and
does not infer package/CPE relationships: it can only attach a signal when a
previously normalized advisory already carries the exact same CVE identifier.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
from typing import Any, Literal


CISA_KEV_CONTRACT_VERSION = "2026-09-09.2"
CISA_KEV_CATALOG_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
MAX_CISA_KEV_ENTRIES = 5000
MAX_CISA_KEV_FIELD_LENGTH = 1024
_CVE_IDENTIFIER = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_SAFE_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_CATALOG_VERSION = re.compile(r"^\d{4}\.\d{2}\.\d{2}$")
_CATALOG_KEYS = frozenset({"title", "catalogVersion", "dateReleased", "count", "vulnerabilities"})
_ENTRY_KEYS = frozenset(
    {
        "cveID",
        "vendorProject",
        "product",
        "vulnerabilityName",
        "dateAdded",
        "shortDescription",
        "requiredAction",
        "dueDate",
        "knownRansomwareCampaignUse",
        "notes",
    }
)
MAX_CISA_KEV_CATALOG_AGE = timedelta(days=7)


@dataclass(frozen=True)
class CisaKevSignal:
    contract_version: str
    provider: Literal["cisa_kev"]
    status: Literal["known_exploited", "not_listed", "unavailable", "not_evaluated"]
    cve_id: str | None
    catalog_version: str | None
    date_released: str | None
    date_added: str | None
    due_date: str | None
    required_action: str | None
    known_ransomware_campaign_use: str | None
    source_url: str
    evidence_digest: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class CisaKevFeedNormalization:
    status: Literal["ready", "invalid_source_response"]
    signals_by_cve: dict[str, CisaKevSignal]
    catalog_version: str | None = None
    date_released: str | None = None
    freshness: Literal["current", "stale", "unknown"] = "unknown"
    errors: tuple[str, ...] = ()


def normalize_cisa_kev_feed(
    payload: object,
    *,
    observed_at: datetime | None = None,
) -> CisaKevFeedNormalization:
    """Return only safe CVE-keyed KEV signals from the fixed catalog format.

    A malformed unrelated row is ignored but represented in coverage errors.
    Conflicting duplicate CVEs invalidate the feed because choosing one version
    silently would fabricate provenance for a risk-prioritisation signal.
    """

    if not isinstance(payload, dict):
        return CisaKevFeedNormalization("invalid_source_response", {}, errors=("cisa_kev_response_not_object",))
    if set(payload) != _CATALOG_KEYS:
        return CisaKevFeedNormalization("invalid_source_response", {}, errors=("cisa_kev_schema_changed",))
    catalog_version = _safe_text(payload.get("catalogVersion"), 128)
    date_released = _safe_timestamp(payload.get("dateReleased"))
    entries = payload.get("vulnerabilities")
    count = payload.get("count")
    if (
        catalog_version is None
        or _CATALOG_VERSION.fullmatch(catalog_version) is None
        or date_released is None
        or not isinstance(entries, list)
        or len(entries) > MAX_CISA_KEV_ENTRIES
        or not isinstance(count, int)
        or isinstance(count, bool)
        or count != len(entries)
    ):
        return CisaKevFeedNormalization("invalid_source_response", {}, errors=("cisa_kev_response_invalid",))
    freshness = _catalog_freshness(date_released, observed_at)
    if freshness == "future":
        return CisaKevFeedNormalization("invalid_source_response", {}, errors=("cisa_kev_release_date_invalid",))

    signals: dict[str, CisaKevSignal] = {}
    invalid_entries = 0
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != _ENTRY_KEYS:
            return CisaKevFeedNormalization(
                "invalid_source_response",
                {},
                catalog_version=catalog_version,
                date_released=date_released,
                freshness="unknown",
                errors=("cisa_kev_schema_changed",),
            )
        signal = _signal_from_entry(entry, catalog_version=catalog_version, date_released=date_released)
        if signal is None:
            invalid_entries += 1
            continue
        existing = signals.get(signal.cve_id or "")
        if existing is not None and existing != signal:
            return CisaKevFeedNormalization(
                "invalid_source_response",
                {},
                catalog_version=catalog_version,
                date_released=date_released,
                errors=("cisa_kev_conflicting_duplicate_cve",),
            )
        signals[signal.cve_id or ""] = signal
    errors = ("cisa_kev_invalid_entries",) if invalid_entries else ()
    return CisaKevFeedNormalization(
        "ready",
        signals,
        catalog_version=catalog_version,
        date_released=date_released,
        freshness="stale" if freshness == "stale" else "current",
        errors=errors,
    )


def cisa_kev_not_listed_signal(
    cve_id: object,
    *,
    catalog_version: str | None,
    date_released: str | None,
) -> CisaKevSignal | None:
    normalized_cve = normalize_cve_identifier(cve_id)
    if normalized_cve is None:
        return None
    return _signal(
        status="not_listed",
        cve_id=normalized_cve,
        catalog_version=catalog_version,
        date_released=date_released,
        date_added=None,
        due_date=None,
        required_action=None,
        known_ransomware_campaign_use=None,
    )


def cisa_kev_unavailable_signal(cve_id: object) -> CisaKevSignal | None:
    normalized_cve = normalize_cve_identifier(cve_id)
    if normalized_cve is None:
        return None
    return _signal(
        status="unavailable",
        cve_id=normalized_cve,
        catalog_version=None,
        date_released=None,
        date_added=None,
        due_date=None,
        required_action=None,
        known_ransomware_campaign_use=None,
    )


def cisa_kev_not_evaluated_signal() -> CisaKevSignal:
    return _signal(
        status="not_evaluated",
        cve_id=None,
        catalog_version=None,
        date_released=None,
        date_added=None,
        due_date=None,
        required_action=None,
        known_ransomware_campaign_use=None,
    )


def normalize_cve_identifier(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip().upper()
    return normalized if _CVE_IDENTIFIER.fullmatch(normalized) else None


def _signal_from_entry(entry: object, *, catalog_version: str, date_released: str) -> CisaKevSignal | None:
    if not isinstance(entry, dict):
        return None
    cve_id = normalize_cve_identifier(entry.get("cveID"))
    date_added = _safe_date(entry.get("dateAdded"))
    required_action = _safe_text(entry.get("requiredAction"), MAX_CISA_KEV_FIELD_LENGTH)
    if cve_id is None or date_added is None or required_action is None:
        return None
    return _signal(
        status="known_exploited",
        cve_id=cve_id,
        catalog_version=catalog_version,
        date_released=date_released,
        date_added=date_added,
        due_date=_safe_date(entry.get("dueDate")),
        required_action=required_action,
        known_ransomware_campaign_use=_safe_text(entry.get("knownRansomwareCampaignUse"), 32),
    )


def _signal(
    *,
    status: Literal["known_exploited", "not_listed", "unavailable", "not_evaluated"],
    cve_id: str | None,
    catalog_version: str | None,
    date_released: str | None,
    date_added: str | None,
    due_date: str | None,
    required_action: str | None,
    known_ransomware_campaign_use: str | None,
) -> CisaKevSignal:
    evidence = {
        "provider": "cisa_kev",
        "status": status,
        "cve_id": cve_id,
        "catalog_version": catalog_version,
        "date_released": date_released,
        "date_added": date_added,
        "due_date": due_date,
        "required_action": required_action,
        "known_ransomware_campaign_use": known_ransomware_campaign_use,
        "source_url": CISA_KEV_CATALOG_URL,
    }
    digest = hashlib.sha256(json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    return CisaKevSignal(
        contract_version=CISA_KEV_CONTRACT_VERSION,
        provider="cisa_kev",
        status=status,
        cve_id=cve_id,
        catalog_version=catalog_version,
        date_released=date_released,
        date_added=date_added,
        due_date=due_date,
        required_action=required_action,
        known_ransomware_campaign_use=known_ransomware_campaign_use,
        source_url=CISA_KEV_CATALOG_URL,
        evidence_digest=digest,
    )


def _safe_date(value: object) -> str | None:
    return value if isinstance(value, str) and _SAFE_DATE.fullmatch(value) else None


def _safe_timestamp(value: object) -> str | None:
    """Accept CISA's catalog-release date or an offset-aware timestamp."""

    if _safe_date(value) is not None:
        return value
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _catalog_freshness(date_released: str, observed_at: datetime | None) -> Literal["current", "stale", "future"]:
    if observed_at is None:
        return "current"
    if observed_at.tzinfo is None or observed_at.utcoffset() is None:
        return "future"
    observed = observed_at.astimezone(timezone.utc)
    released = datetime.fromisoformat(date_released.replace("Z", "+00:00"))
    if released.tzinfo is None:
        released = released.replace(tzinfo=timezone.utc)
    released = released.astimezone(timezone.utc)
    if released.date() > observed.date():
        return "future"
    return "stale" if observed - released > MAX_CISA_KEV_CATALOG_AGE else "current"


def _safe_text(value: object, maximum: int) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    if not normalized or len(normalized) > maximum or any(ord(character) < 32 for character in normalized):
        return None
    return normalized
