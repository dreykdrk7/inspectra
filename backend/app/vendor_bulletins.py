"""Static, no-egress policy for official vendor security-bulletin evidence.

An upstream advisory may contain arbitrary references.  Inspectra does not
fetch them or infer publisher ownership from a domain.  This module promotes a
reference only when a reviewed, versioned internal policy binds one exact
public component to an official security-advisory path and the final GHSA is
already an alias on the normalized advisory.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Iterable
from urllib.parse import urlsplit

from app.public_advisories import PublicAdvisoryReference
from app.public_advisory_egress import PublicComponentIdentity, normalize_github_advisory_identifier, normalize_osv_component_identity


VENDOR_BULLETIN_POLICY_VERSION = "2026-09-05.1"
MAX_VENDOR_BULLETINS_PER_ADVISORY = 2


@dataclass(frozen=True)
class VendorBulletinPolicy:
    ecosystem: str
    component_name: str
    publisher: str
    host: str
    path_prefix: str


@dataclass(frozen=True)
class VendorBulletinEvidence:
    publisher: str
    advisory_id: str
    url: str
    policy_version: str = VENDOR_BULLETIN_POLICY_VERSION


# Adding an entry is a code-review decision: it requires proof that the
# publisher controls the path and that it is an advisory endpoint, not merely a
# release-note or changelog page.  This small initial list deliberately avoids
# a user-configurable host/URL allowlist and does not widen public egress.
_POLICIES = (
    VendorBulletinPolicy(
        ecosystem="npm",
        component_name="react",
        publisher="React",
        host="github.com",
        path_prefix="/react/react/security/advisories/",
    ),
    VendorBulletinPolicy(
        ecosystem="npm",
        component_name="lodash",
        publisher="Lodash",
        host="github.com",
        path_prefix="/lodash/lodash/security/advisories/",
    ),
)
_SAFE_GHSA_PATH = re.compile(r"^GHSA-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$")


def official_vendor_bulletins(
    component: PublicComponentIdentity,
    aliases: Iterable[str],
    references: Iterable[PublicAdvisoryReference],
) -> tuple[VendorBulletinEvidence, ...]:
    """Retain only policy-bound public advisory links; no network is opened."""

    normalized = normalize_osv_component_identity(component)
    if normalized is None:
        return ()
    expected_aliases = {
        normalized_alias
        for alias in aliases
        if (normalized_alias := normalize_github_advisory_identifier(alias)) is not None
    }
    if not expected_aliases:
        return ()
    policy = next(
        (
            candidate
            for candidate in _POLICIES
            if candidate.ecosystem == component.ecosystem and candidate.component_name == normalized["package"]["name"]
        ),
        None,
    )
    if policy is None:
        return ()
    evidence: list[VendorBulletinEvidence] = []
    for reference in references:
        url = _policy_bound_bulletin_url(reference, policy, expected_aliases)
        if url is None or any(item.url == url for item in evidence):
            continue
        advisory_id = url.rsplit("/", 1)[-1]
        evidence.append(VendorBulletinEvidence(publisher=policy.publisher, advisory_id=advisory_id, url=url))
        if len(evidence) >= MAX_VENDOR_BULLETINS_PER_ADVISORY:
            break
    return tuple(evidence)


def _policy_bound_bulletin_url(
    reference: object,
    policy: VendorBulletinPolicy,
    expected_aliases: set[str],
) -> str | None:
    if not isinstance(reference, PublicAdvisoryReference) or reference.kind != "reference":
        return None
    try:
        parsed = urlsplit(reference.url)
        port = parsed.port
    except (TypeError, ValueError):
        return None
    if (
        parsed.scheme != "https"
        or parsed.hostname != policy.host
        or port is not None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or not parsed.path.startswith(policy.path_prefix)
    ):
        return None
    advisory_id = parsed.path.removeprefix(policy.path_prefix)
    if not _SAFE_GHSA_PATH.fullmatch(advisory_id) or advisory_id not in expected_aliases:
        return None
    return reference.url
