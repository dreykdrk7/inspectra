from __future__ import annotations

import ipaddress
import re
import socket
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from fastapi import HTTPException, status


METADATA_IPS = {ipaddress.ip_address("169.254.169.254")}
METADATA_HOSTS = {"metadata.google.internal"}
LOCALHOST_HOSTS = {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"}
REDACTED_QUERY_VALUE = "REDACTED"
SENSITIVE_QUERY_PARAM_NAMES = {
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "api_key",
    "apikey",
    "key",
    "secret",
    "client_secret",
    "password",
    "passwd",
    "pwd",
    "session",
    "sessionid",
    "sid",
    "auth",
    "authorization",
    "jwt",
    "bearer",
    "sig",
    "signature",
    "code",
    "state",
    "x-amz-signature",
    "x-amz-credential",
    "x-amz-security-token",
    "awsaccesskeyid",
}
SENSITIVE_QUERY_PARAM_FRAGMENTS = ("token", "secret", "password", "passwd", "session", "auth", "signature", "api_key", "apikey")
URL_PATTERN = re.compile(r"https?://[^\s<>()\"']+")


def normalize_web_url(raw_url: str) -> str:
    value = raw_url.strip()
    if not value:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="URL is required.")

    try:
        parsed = urlsplit(value)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid URL.") from exc

    if parsed.scheme not in {"http", "https"}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Only http and https URLs are accepted.")
    if not parsed.netloc or not parsed.hostname:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="URL must be absolute and include a host.")
    if parsed.username or parsed.password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="URL credentials are not accepted.")

    try:
        parsed.port
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid URL port.") from exc

    path = parsed.path or "/"
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), path, parsed.query, ""))


def validate_web_target_url(raw_url: str, *, allow_private_targets: bool, allowed_ports: tuple[int, ...]) -> str:
    normalized = normalize_web_url(raw_url)
    parsed = urlsplit(normalized)
    host = parsed.hostname or ""
    if host.lower().rstrip(".") in METADATA_HOSTS:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cloud metadata targets are not allowed.")

    port = web_target_port(parsed.scheme, parsed.port)
    validate_allowed_port(port, allowed_ports)
    if host.lower().rstrip(".") in LOCALHOST_HOSTS and not allow_private_targets:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target resolves to a blocked address range: loopback address.",
        )
    try:
        addresses = {ipaddress.ip_address(host)}
    except ValueError:
        try:
            addresses = resolve_host_addresses(host, port)
        except HTTPException:
            # The runner performs the same validation from its egress context. Backend DNS can be unavailable
            # when it stays on the internal Compose network, so DNS failure here should not prevent a queued job.
            return normalized
    for address in addresses:
        blocked_reason = blocked_ip_reason(address, allow_private_targets=allow_private_targets)
        if blocked_reason:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Target resolves to a blocked address range: {blocked_reason}.",
            )
    return normalized


def has_query_string(url: str) -> bool:
    try:
        return bool(urlsplit(url).query)
    except ValueError:
        return False


def query_redaction_summary(url: str) -> dict[str, object]:
    try:
        query = urlsplit(url).query
    except ValueError:
        query = ""
    _, redacted_params = redact_query_params(query)
    return {
        "query_string_present": bool(query),
        "query_params_redacted": bool(redacted_params),
        "redacted_query_params": redacted_params,
    }


def redact_url_query(url: str) -> str:
    try:
        parsed = urlsplit(url)
    except ValueError:
        return url
    redacted_query, _ = redact_query_params(parsed.query)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, redacted_query, parsed.fragment))


def redact_query_params(query: str) -> tuple[str, list[str]]:
    if not query:
        return "", []
    pairs = parse_qsl(query, keep_blank_values=True)
    redacted: list[tuple[str, str]] = []
    redacted_names: list[str] = []
    for name, value in pairs:
        if is_sensitive_query_param(name):
            redacted.append((name, REDACTED_QUERY_VALUE))
            redacted_names.append(name)
        else:
            redacted.append((name, value))
    return urlencode(redacted, doseq=True), sorted(set(redacted_names), key=str.lower)


def is_sensitive_query_param(name: str) -> bool:
    normalized = name.strip().lower()
    return normalized in SENSITIVE_QUERY_PARAM_NAMES or any(fragment in normalized for fragment in SENSITIVE_QUERY_PARAM_FRAGMENTS)


def redact_text_urls(value: str) -> str:
    return URL_PATTERN.sub(lambda match: redact_url_query(match.group(0)), value)


def web_target_port(scheme: str, explicit_port: int | None) -> int:
    return explicit_port or (443 if scheme == "https" else 80)


def validate_allowed_port(port: int, allowed_ports: tuple[int, ...]) -> None:
    if port not in allowed_ports:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Target port {port} is not allowed for web audits.",
        )


def resolve_host_addresses(host: str, port: int) -> set[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Target host could not be resolved.") from exc

    addresses: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
    for info in infos:
        sockaddr = info[4]
        if not sockaddr:
            continue
        try:
            addresses.add(ipaddress.ip_address(sockaddr[0]))
        except ValueError:
            continue
    if not addresses:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Target host did not resolve to an IP address.")
    return addresses


def blocked_ip_reason(address: ipaddress.IPv4Address | ipaddress.IPv6Address, *, allow_private_targets: bool) -> str | None:
    if address in METADATA_IPS:
        return "cloud metadata address"
    if address.is_unspecified:
        return "unspecified address"
    if address.is_link_local:
        return "link-local address"
    if address.is_multicast:
        return "multicast address"
    if not allow_private_targets and address.is_loopback:
        return "loopback address"
    if not allow_private_targets and address.is_private:
        return "private address"
    if address.is_reserved and not (allow_private_targets and (address.is_loopback or address.is_private)):
        return "reserved address"
    return None
