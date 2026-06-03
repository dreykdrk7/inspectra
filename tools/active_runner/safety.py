from __future__ import annotations

import ipaddress
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


REDACTED = "[REDACTED]"
METADATA_IPS = {ipaddress.ip_address("169.254.169.254")}
METADATA_HOSTS = {"metadata.google.internal"}
LOCALHOST_HOSTS = {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"}
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
    "signature",
    "sig",
    "code",
    "state",
}
SENSITIVE_QUERY_PARAM_FRAGMENTS = ("token", "secret", "password", "passwd", "session", "auth", "signature", "api_key", "apikey")
HOST_PATTERN = re.compile(r"^[a-z0-9.-]+$", re.IGNORECASE)
URL_PATTERN = re.compile(r"https?://[^\s<>()\"']+", re.IGNORECASE)
PRIVATE_KEY_PATTERN = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL)
AUTHORIZATION_BEARER_PATTERN = re.compile(r"Authorization:\s*Bearer\s+[A-Za-z0-9._~+/=-]+", re.IGNORECASE)
SECRET_ASSIGNMENT_PATTERN = re.compile(
    r"(?i)\b(token|api[_-]?key|secret|client[_-]?secret|password|passwd|pwd)\s*[:=]\s*[^&\s]+"
)
SHELL_LIKE_FRAGMENTS = ("&&", "||", "$(", "`", ";", "\n", "\r", "<", ">", "\\")

BLOCKED_REASON_MESSAGES = {
    "authorization_missing": "Active checks require explicit confirmation that you own or are authorized to test the target.",
    "active_disabled": "Active checks are disabled in this environment.",
    "unsupported_scheme": "This target type is not supported for active checks.",
    "url_credentials_rejected": "URLs with embedded credentials are not accepted.",
    "target_parse_failed": "This target could not be parsed as an allowed active target.",
    "target_cidr_rejected": "Broad network ranges are not accepted for this active mode.",
    "target_range_rejected": "Target ranges are not accepted for this active mode.",
    "wildcard_rejected": "Wildcard targets are not accepted for this active mode.",
    "private_range_blocked": "This target is blocked by the active safety policy.",
    "loopback_requires_local_lab": "This target requires explicit local-lab mode, which is not enabled.",
    "metadata_target_blocked": "This target is blocked by the active safety policy.",
    "link_local_blocked": "This target is blocked by the active safety policy.",
    "multicast_blocked": "This target is blocked by the active safety policy.",
    "broadcast_blocked": "This target is blocked by the active safety policy.",
    "unspecified_address_blocked": "This target is blocked by the active safety policy.",
    "overlong_hostname": "This target is not accepted because the hostname is too long.",
    "invalid_idna": "This target could not be normalized safely.",
    "suspicious_target_input": "This target is blocked by the active safety policy.",
    "unknown_profile": "This active profile is not available.",
    "live_mode_not_available": "Live active checks are not available in this phase.",
    "limits_exceed_dry_run": "Dry-run limits must not allow network requests.",
    "nmap_not_allowed": "Nmap runtime is not enabled for this phase.",
    "live_traffic_confirmation_missing": "Live HTTP header probes require explicit confirmation that one HTTP HEAD request will be sent.",
    "live_url_required": "Live HTTP header probes require one explicit http or https URL.",
    "live_header_probe_mode_required": "This active mode is not available for the HTTP header probe.",
    "limits_exceed_http_header_probe": "HTTP header probe limits exceed the v0 safety policy.",
    "dns_resolution_failed": "DNS resolution failed before any HTTP request was sent.",
    "dns_answers_limit_exceeded": "DNS answers exceeded the active probe limit.",
    "resolved_ip_blocked": "A resolved address is blocked by the active safety policy.",
}


def blocked_reason(code: str) -> dict[str, str]:
    return {"code": code, "message": BLOCKED_REASON_MESSAGES.get(code, "This target is blocked by the active safety policy.")}


def redact_sensitive_text(value: str) -> str:
    text = PRIVATE_KEY_PATTERN.sub(REDACTED, value)
    text = AUTHORIZATION_BEARER_PATTERN.sub(REDACTED, text)
    text = URL_PATTERN.sub(lambda match: redact_url_for_display(match.group(0)), text)
    return SECRET_ASSIGNMENT_PATTERN.sub(lambda match: f"{match.group(1)}={REDACTED}", text)


def redact_url_for_display(value: str) -> str:
    try:
        parsed = urlsplit(value.strip())
    except ValueError:
        return REDACTED
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    if not scheme or not host:
        return REDACTED
    netloc = host
    try:
        port = parsed.port
    except ValueError:
        port = None
    if port is not None:
        netloc = f"{netloc}:{port}"
    if parsed.username or parsed.password:
        netloc = f"{REDACTED}@{netloc}"
    path = parsed.path or "/"
    redacted_query, _ = redact_query_params(parsed.query)
    return urlunsplit((scheme, netloc, path, redacted_query, ""))


def redact_query_params(query: str) -> tuple[str, list[str]]:
    if not query:
        return "", []
    redacted: list[tuple[str, str]] = []
    redacted_names: list[str] = []
    for name, value in parse_qsl(query, keep_blank_values=True):
        if is_sensitive_query_param(name):
            redacted.append((name, "REDACTED"))
            redacted_names.append(name)
        else:
            redacted.append((name, value))
    return urlencode(redacted, doseq=True), sorted(set(redacted_names), key=str.lower)


def is_sensitive_query_param(name: str) -> bool:
    normalized = name.strip().lower()
    return normalized in SENSITIVE_QUERY_PARAM_NAMES or any(fragment in normalized for fragment in SENSITIVE_QUERY_PARAM_FRAGMENTS)


def normalize_target(raw_target: str) -> tuple[dict[str, object], list[dict[str, str]]]:
    raw = raw_target.strip()
    safe_raw = redact_sensitive_text(raw)
    if not raw:
        return unknown_target("", safe_raw), [blocked_reason("target_parse_failed")]
    if has_suspicious_input(raw):
        return unknown_target(raw, safe_raw), [blocked_reason("suspicious_target_input")]
    if "*" in raw:
        return unknown_target(raw, safe_raw), [blocked_reason("wildcard_rejected")]
    if is_target_range(raw):
        return unknown_target(raw, safe_raw), [blocked_reason("target_range_rejected")]
    if is_cidr(raw):
        return unknown_target(raw, safe_raw), [blocked_reason("target_cidr_rejected")]
    if "://" in raw:
        return normalize_url_target(raw, safe_raw)
    return normalize_host_or_ip_target(raw, safe_raw)


def unknown_target(raw: str, safe_raw: str) -> dict[str, object]:
    return {
        "raw": safe_raw,
        "normalized": None,
        "type": "unknown",
        "scheme": None,
        "host": None,
        "port": None,
        "path": None,
        "query_redacted": "",
        "classification": "rejected",
        "local_lab": False,
    }


def normalize_url_target(raw: str, safe_raw: str) -> tuple[dict[str, object], list[dict[str, str]]]:
    try:
        parsed = urlsplit(raw)
    except ValueError:
        return unknown_target(raw, safe_raw), [blocked_reason("target_parse_failed")]
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        return unknown_target(raw, safe_raw), [blocked_reason("unsupported_scheme")]
    if parsed.username or parsed.password:
        return unknown_target(raw, redact_url_for_display(raw)), [blocked_reason("url_credentials_rejected")]
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        return unknown_target(raw, safe_raw), [blocked_reason("target_parse_failed")]
    host, host_reasons = normalize_hostname_text(host)
    if host_reasons:
        return unknown_target(raw, safe_raw), host_reasons
    try:
        port = parsed.port
    except ValueError:
        return unknown_target(raw, safe_raw), [blocked_reason("target_parse_failed")]
    classification, ip_reason = classify_host(host)
    if ip_reason:
        return unknown_target(raw, safe_raw), [blocked_reason(ip_reason)]
    explicit_port = port is not None
    port = port or (443 if scheme == "https" else 80)
    path = parsed.path or "/"
    redacted_query, _ = redact_query_params(parsed.query)
    netloc = host
    if explicit_port:
        netloc = f"{netloc}:{port}"
    normalized = urlunsplit((scheme, netloc, path, redacted_query, ""))
    return (
        {
            "raw": redact_url_for_display(raw),
            "normalized": normalized,
            "type": "url",
            "scheme": scheme,
            "host": host,
            "port": port,
            "path": path,
            "query_redacted": redacted_query,
            "classification": classification,
            "local_lab": False,
        },
        [],
    )


def normalize_host_or_ip_target(raw: str, safe_raw: str) -> tuple[dict[str, object], list[dict[str, str]]]:
    if any(separator in raw for separator in ("/", "?", "#", "@", ":")):
        return unknown_target(raw, safe_raw), [blocked_reason("target_parse_failed")]
    try:
        address = ipaddress.ip_address(raw)
    except ValueError:
        host, host_reasons = normalize_hostname_text(raw.lower().rstrip("."))
        if host_reasons:
            return unknown_target(raw, safe_raw), host_reasons
        classification, ip_reason = classify_host(host)
        if ip_reason:
            return unknown_target(raw, safe_raw), [blocked_reason(ip_reason)]
        return (
            {
                "raw": safe_raw,
                "normalized": host,
                "type": "hostname",
                "scheme": None,
                "host": host,
                "port": None,
                "path": None,
                "query_redacted": "",
                "classification": classification,
                "local_lab": False,
            },
            [],
        )
    reason = blocked_ip_reason(address)
    if reason:
        return unknown_target(raw, safe_raw), [blocked_reason(reason)]
    return (
        {
            "raw": safe_raw,
            "normalized": str(address),
            "type": "ip",
            "scheme": None,
            "host": str(address),
            "port": None,
            "path": None,
            "query_redacted": "",
            "classification": "single_public_ip",
            "local_lab": False,
        },
        [],
    )


def normalize_hostname_text(host: str) -> tuple[str, list[dict[str, str]]]:
    if len(host) > 253:
        return host, [blocked_reason("overlong_hostname")]
    try:
        ascii_host = host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return host, [blocked_reason("invalid_idna")]
    if not ascii_host or not HOST_PATTERN.fullmatch(ascii_host):
        return ascii_host, [blocked_reason("target_parse_failed")]
    labels = ascii_host.split(".")
    for label in labels:
        if not label or len(label) > 63 or label.startswith("-") or label.endswith("-"):
            return ascii_host, [blocked_reason("target_parse_failed")]
    return ascii_host, []


def classify_host(host: str) -> tuple[str, str | None]:
    normalized = host.lower().rstrip(".")
    if normalized in METADATA_HOSTS:
        return "blocked", "metadata_target_blocked"
    if normalized in LOCALHOST_HOSTS:
        return "loopback", "loopback_requires_local_lab"
    try:
        address = ipaddress.ip_address(normalized)
    except ValueError:
        return "public_hostname", None
    reason = blocked_ip_reason(address)
    if reason:
        return "blocked", reason
    return "single_public_ip", None


def blocked_ip_reason(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
    if address in METADATA_IPS:
        return "metadata_target_blocked"
    if address.is_unspecified:
        return "unspecified_address_blocked"
    if address.is_link_local:
        return "link_local_blocked"
    if address.is_multicast:
        return "multicast_blocked"
    if address.is_loopback:
        return "loopback_requires_local_lab"
    if address.version == 4 and str(address) == "255.255.255.255":
        return "broadcast_blocked"
    if address.is_private:
        return "private_range_blocked"
    return None


def has_suspicious_input(value: str) -> bool:
    lowered = value.lower()
    if "authorization:" in lowered or PRIVATE_KEY_PATTERN.search(value):
        return True
    return any(fragment in value for fragment in SHELL_LIKE_FRAGMENTS)


def is_cidr(value: str) -> bool:
    if "/" not in value or "://" in value:
        return False
    try:
        ipaddress.ip_network(value, strict=False)
    except ValueError:
        return False
    return True


def is_target_range(value: str) -> bool:
    return bool(re.fullmatch(r"\s*[0-9a-fA-F:.]+(?:\s*-\s*[0-9a-fA-F:.]+)+\s*", value))
