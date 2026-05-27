from __future__ import annotations

import ipaddress
import re

from fastapi import HTTPException, status


DOMAIN_PATTERN = re.compile(r"^[a-z0-9.-]+$")
BLOCKED_DOMAIN_SUFFIXES = (".local", ".localhost", ".internal", ".test", ".invalid")
BLOCKED_DOMAIN_NAMES = {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"}


def normalize_domain(raw_domain: str) -> str:
    value = raw_domain.strip()
    if not value:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Domain is required.")
    if any(character.isspace() for character in value):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Domain must not contain spaces.")
    if "://" in value or "/" in value or "?" in value or "#" in value or "@" in value or ":" in value:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Enter a domain name, not a URL.")

    value = value.rstrip(".").lower()
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="IP literals are not accepted for domain audits.")

    try:
        ascii_domain = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Domain could not be normalized.") from exc

    if ascii_domain in BLOCKED_DOMAIN_NAMES or ascii_domain.endswith(BLOCKED_DOMAIN_SUFFIXES):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Internal or reserved domain names are not accepted.")
    if "." not in ascii_domain:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Domain must include at least one dot.")
    if len(ascii_domain) > 253 or not DOMAIN_PATTERN.fullmatch(ascii_domain):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Domain contains unsupported characters.")

    labels = ascii_domain.split(".")
    for label in labels:
        if not label or len(label) > 63:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Domain label length is invalid.")
        if label.startswith("-") or label.endswith("-"):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Domain labels must not start or end with hyphen.")
    return ascii_domain


def normalize_subdomain_candidate(root_domain: str, raw_candidate: str) -> str:
    root = normalize_domain(root_domain)
    value = raw_candidate.strip()
    if not value:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Subdomain candidate must not be empty.")
    if "*" in value:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Wildcard subdomain candidates are not accepted.")
    if any(character.isspace() for character in value):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Subdomain candidate must not contain spaces.")
    if "://" in value or "/" in value or "?" in value or "#" in value or "@" in value or ":" in value:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Enter subdomain labels or FQDNs, not URLs.")
    if value.endswith("."):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Trailing dots are not accepted in subdomain candidates.")

    candidate = value.rstrip(".").lower()
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        pass
    else:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="IP literals are not accepted as subdomain candidates.")

    fqdn = f"{candidate}.{root}" if "." not in candidate else candidate
    normalized = normalize_domain(fqdn)
    if normalized == root or not normalized.endswith(f".{root}"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Subdomain candidate must be inside the root domain.")
    return normalized


def normalize_subdomain_candidates(root_domain: str, raw_candidates: list[str], max_candidates: int) -> list[str]:
    if not raw_candidates:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="At least one subdomain candidate is required.")
    if len(raw_candidates) > max_candidates:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Too many subdomain candidates. Maximum allowed is {max_candidates}.",
        )
    normalized: list[str] = []
    seen: set[str] = set()
    for candidate in raw_candidates:
        fqdn = normalize_subdomain_candidate(root_domain, candidate)
        if fqdn in seen:
            continue
        seen.add(fqdn)
        normalized.append(fqdn)
    if not normalized:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="At least one unique subdomain candidate is required.")
    return normalized
