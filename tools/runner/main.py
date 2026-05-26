from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import http.client
from http.cookies import SimpleCookie
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import struct
import subprocess
import tarfile
import time
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit
import zipfile

from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel

try:
    import tomllib
except ModuleNotFoundError:  # Python < 3.11 in local test environments.
    tomllib = None


DATA_DIR = Path(os.getenv("INSPECTRA_DATA_DIR", "/app/data")).resolve()
MAX_OUTPUT_CHARS = 120_000


class PdfAnalysisRequest(BaseModel):
    file_id: str
    relative_path: str


class ImageAnalysisRequest(BaseModel):
    file_id: str
    relative_path: str


class ManifestAnalysisRequest(BaseModel):
    file_id: str
    relative_path: str
    original_filename: str | None = None


class ArchiveAnalysisRequest(BaseModel):
    file_id: str
    relative_path: str
    original_filename: str | None = None


class WebBasicAnalysisRequest(BaseModel):
    url: str
    allow_private_targets: bool | None = None
    timeout_seconds: float | None = None
    max_response_bytes: int | None = None
    max_redirects: int | None = None


def positive_float_from_env(name: str, default: float) -> float:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    try:
        value = float(raw_value)
    except ValueError as exc:
        raise ValueError(f"{name} must be a positive number.") from exc
    if value <= 0:
        raise ValueError(f"{name} must be greater than zero.")
    return value


def positive_int_from_env(name: str, default: int) -> int:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    try:
        value = int(raw_value)
    except ValueError as exc:
        raise ValueError(f"{name} must be a positive integer.") from exc
    if value <= 0:
        raise ValueError(f"{name} must be greater than zero.")
    return value


def bool_from_env(name: str, default: bool) -> bool:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    normalized = raw_value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be a boolean value.")


COMMAND_TIMEOUT_SECONDS = positive_float_from_env("INSPECTRA_TOOL_TIMEOUT_SECONDS", 10.0)
ARCHIVE_MAX_ENTRIES = positive_int_from_env("INSPECTRA_ARCHIVE_MAX_ENTRIES", 5000)
ARCHIVE_MAX_TOTAL_UNCOMPRESSED_BYTES = positive_int_from_env("INSPECTRA_ARCHIVE_MAX_TOTAL_UNCOMPRESSED_BYTES", 209_715_200)
ARCHIVE_MAX_ENTRY_NAME_LENGTH = positive_int_from_env("INSPECTRA_ARCHIVE_MAX_ENTRY_NAME_LENGTH", 512)
ARCHIVE_MAX_LISTED_ENTRIES = positive_int_from_env("INSPECTRA_ARCHIVE_MAX_LISTED_ENTRIES", 200)
ARCHIVE_MAX_ZIP_CENTRAL_DIRECTORY_BYTES = positive_int_from_env("INSPECTRA_ARCHIVE_MAX_ZIP_CENTRAL_DIRECTORY_BYTES", 8_388_608)
ARCHIVE_SUSPICIOUS_COMPRESSION_RATIO = 100.0
PROJECT_ARCHIVE_MAX_MANIFESTS = positive_int_from_env("INSPECTRA_PROJECT_ARCHIVE_MAX_MANIFESTS", 25)
PROJECT_ARCHIVE_MAX_MANIFEST_BYTES = positive_int_from_env("INSPECTRA_PROJECT_ARCHIVE_MAX_MANIFEST_BYTES", 1_048_576)
PROJECT_ARCHIVE_MAX_TOTAL_MANIFEST_BYTES = positive_int_from_env("INSPECTRA_PROJECT_ARCHIVE_MAX_TOTAL_MANIFEST_BYTES", 5_242_880)
PROJECT_ARCHIVE_MAX_ARCHIVE_ENTRIES = positive_int_from_env("INSPECTRA_PROJECT_ARCHIVE_MAX_ARCHIVE_ENTRIES", ARCHIVE_MAX_ENTRIES)
WEB_ALLOW_PRIVATE_TARGETS = bool_from_env("INSPECTRA_WEB_ALLOW_PRIVATE_TARGETS", False)
WEB_TIMEOUT_SECONDS = positive_float_from_env("INSPECTRA_WEB_TIMEOUT_SECONDS", 10.0)
WEB_MAX_RESPONSE_BYTES = positive_int_from_env("INSPECTRA_WEB_MAX_RESPONSE_BYTES", 1_048_576)
WEB_MAX_REDIRECTS = positive_int_from_env("INSPECTRA_WEB_MAX_REDIRECTS", 5)
ZIP_EOCD_SIGNATURE = b"PK\x05\x06"
ZIP_EOCD_MIN_SIZE = 22
ZIP_EOCD_MAX_COMMENT_SIZE = 65_535
ZIP_EOCD_SCAN_SIZE = ZIP_EOCD_MIN_SIZE + ZIP_EOCD_MAX_COMMENT_SIZE
ZIP16_MAX_FIELD = 0xFFFF
ZIP32_MAX_FIELD = 0xFFFFFFFF
WEB_SECURITY_HEADERS = (
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
    "Cross-Origin-Embedder-Policy",
)
METADATA_IPS = {ipaddress.ip_address("169.254.169.254")}
METADATA_HOSTS = {"metadata.google.internal"}
SECURITY_TXT_FIELDS = {
    "contact",
    "expires",
    "encryption",
    "acknowledgments",
    "preferred-languages",
    "canonical",
    "policy",
    "hiring",
}


@dataclass(frozen=True)
class ZipMetadataPreflight:
    total_entries: int | None
    central_directory_bytes: int | None
    reason: str | None = None


app = FastAPI(
    title="Inspectra Audit Tools",
    summary="Internal containerized tool runner for passive audit tasks.",
    version="0.1.0",
)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "inspectra-audit-tools"}


@app.post("/analyze/pdf")
async def analyze_pdf(request: PdfAnalysisRequest) -> dict[str, Any]:
    pdf_path = resolve_data_path(request.relative_path)
    if not pdf_path.exists() or not pdf_path.is_file():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="PDF not found.")
    if pdf_path.suffix.lower() != ".pdf":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Expected a PDF file.")

    with pdf_path.open("rb") as handle:
        header = handle.read(5)
    if header != b"%PDF-":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid PDF header.")

    pdfinfo = run_command(["pdfinfo", str(pdf_path)])
    exiftool = run_command(["exiftool", "-json", "-n", str(pdf_path)])
    qpdf = run_command(["qpdf", "--check", str(pdf_path)])
    mime = run_command(["file", "--brief", "--mime-type", str(pdf_path)])

    parsed_pdfinfo = parse_key_value_output(pdfinfo["stdout"])
    parsed_exiftool = parse_exiftool_json(exiftool["stdout"])
    tool_outputs = {
        "pdfinfo": pdfinfo,
        "exiftool": exiftool,
        "qpdf": qpdf,
        "file": mime,
    }
    warnings = build_passive_warnings(parsed_pdfinfo, tool_outputs, mime)
    timed_out_tools = [name for name, output in tool_outputs.items() if output["timed_out"]]

    return {
        "file_id": request.file_id,
        "analyzer": "inspectra-pdf-basic",
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "hashes": calculate_hashes(pdf_path),
        "metadata": {
            "pdfinfo": parsed_pdfinfo,
            "exiftool": parsed_exiftool,
        },
        "validation": {
            "mime_type": mime["stdout"].strip(),
            "qpdf_ok": qpdf["exit_code"] == 0,
            "warnings": warnings,
            "timed_out_tools": timed_out_tools,
        },
        "tool_outputs": tool_outputs,
    }


@app.post("/analyze/image")
async def analyze_image(request: ImageAnalysisRequest) -> dict[str, Any]:
    image_path = resolve_data_path(request.relative_path)
    if not image_path.exists() or not image_path.is_file():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Image not found.")

    with image_path.open("rb") as handle:
        header = handle.read(16)
    detected_format = detect_image_format(header)
    if detected_format is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Expected a JPEG, PNG, or WebP image.")

    file_output = run_command(["file", "--brief", str(image_path)])
    mime = run_command(["file", "--brief", "--mime-type", str(image_path)])
    exiftool = run_command(["exiftool", "-json", "-n", str(image_path)])

    parsed_exiftool = parse_exiftool_json(exiftool["stdout"])
    tool_outputs = {
        "file": file_output,
        "file_mime": mime,
        "exiftool": exiftool,
    }
    warnings = build_image_warnings(tool_outputs, mime)
    timed_out_tools = [name for name, output in tool_outputs.items() if output["timed_out"]]

    return {
        "file_id": request.file_id,
        "analyzer": "inspectra-image-basic",
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "hashes": calculate_hashes(image_path),
        "identification": {
            "detected_format": detected_format,
            "file_output": file_output["stdout"].strip(),
            "mime_type": mime["stdout"].strip(),
        },
        "metadata": {
            "exiftool": parsed_exiftool,
        },
        "privacy_indicators": build_privacy_indicators(parsed_exiftool),
        "validation": {
            "mime_type": mime["stdout"].strip(),
            "warnings": warnings,
            "timed_out_tools": timed_out_tools,
        },
        "tool_outputs": tool_outputs,
    }


@app.post("/analyze/manifest")
async def analyze_manifest(request: ManifestAnalysisRequest) -> dict[str, Any]:
    manifest_path = resolve_data_path(request.relative_path)
    if not manifest_path.exists() or not manifest_path.is_file():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Manifest not found.")

    original_filename = Path(request.original_filename or manifest_path.name).name
    manifest_type = detect_manifest_type(original_filename)
    if manifest_type is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Expected package.json, requirements.txt, or pyproject.toml.",
        )

    try:
        raw_text = manifest_path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Manifest must be valid UTF-8 text.") from exc

    if "\x00" in raw_text:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Manifest must be a text file.")

    if manifest_type == "package_json":
        parsed, findings, errors = analyze_package_json_manifest(raw_text)
    elif manifest_type == "requirements_txt":
        parsed, findings, errors = analyze_requirements_manifest(raw_text)
    else:
        parsed, findings, errors = analyze_pyproject_manifest(raw_text)

    dependency_groups = parsed.get("dependencies", {})
    total_dependencies = sum(len(items) for items in dependency_groups.values() if isinstance(items, list))

    return {
        "file_id": request.file_id,
        "analyzer": "manifest_basic",
        "manifest_type": manifest_type,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "hashes": calculate_hashes(manifest_path),
        "file_identification": {
            "size_bytes": manifest_path.stat().st_size,
            "original_filename": original_filename,
        },
        "parsed": parsed,
        "summary": {
            "total_dependencies": total_dependencies,
            "dependency_groups": list(dependency_groups),
            "informational_findings_count": len(findings),
        },
        "findings": findings,
        "errors": errors,
    }


@app.post("/analyze/archive")
async def analyze_archive(request: ArchiveAnalysisRequest) -> dict[str, Any]:
    archive_path = resolve_data_path(request.relative_path)
    if not archive_path.exists() or not archive_path.is_file():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Archive not found.")

    original_filename = Path(request.original_filename or archive_path.name).name
    archive_type = detect_archive_type(archive_path, original_filename)
    if archive_type == "unknown":
        return build_archive_result(
            request.file_id,
            archive_path,
            original_filename,
            archive_type,
            entries_sample=[],
            detected_manifests=[],
            findings=[],
            summary=empty_archive_summary(total_compressed_bytes=archive_path.stat().st_size),
            errors=["Unsupported or corrupt archive. Inspectra did not extract or execute any content."],
        )

    try:
        if archive_type == "zip":
            analysis = analyze_zip_archive(archive_path)
        else:
            analysis = analyze_tar_archive(archive_path)
    except (OSError, tarfile.TarError, zipfile.BadZipFile) as exc:
        return build_archive_result(
            request.file_id,
            archive_path,
            original_filename,
            archive_type,
            entries_sample=[],
            detected_manifests=[],
            findings=[],
            summary=empty_archive_summary(total_compressed_bytes=archive_path.stat().st_size),
            errors=[f"Archive could not be parsed safely: {exc}"],
        )

    return build_archive_result(request.file_id, archive_path, original_filename, archive_type, **analysis)


@app.post("/analyze/project-archive")
async def analyze_project_archive(request: ArchiveAnalysisRequest) -> dict[str, Any]:
    archive_path = resolve_data_path(request.relative_path)
    if not archive_path.exists() or not archive_path.is_file():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Archive not found.")

    original_filename = Path(request.original_filename or archive_path.name).name
    archive_type = detect_archive_type(archive_path, original_filename)
    if archive_type == "unknown":
        return build_project_archive_result(
            request.file_id,
            archive_path,
            original_filename,
            archive_type,
            empty_project_archive_analysis(
                errors=["Unsupported or corrupt archive. Inspectra did not extract, install, or execute any content."]
            ),
        )

    try:
        analysis = analyze_project_archive_manifests(archive_path, archive_type)
    except (OSError, tarfile.TarError, zipfile.BadZipFile) as exc:
        analysis = empty_project_archive_analysis(errors=[f"Archive could not be parsed safely: {exc}"])

    return build_project_archive_result(request.file_id, archive_path, original_filename, archive_type, analysis)


@app.post("/analyze/web-basic")
async def analyze_web_basic(request: WebBasicAnalysisRequest) -> dict[str, Any]:
    allow_private = WEB_ALLOW_PRIVATE_TARGETS if request.allow_private_targets is None else request.allow_private_targets
    timeout_seconds = request.timeout_seconds or WEB_TIMEOUT_SECONDS
    max_response_bytes = request.max_response_bytes or WEB_MAX_RESPONSE_BYTES
    max_redirects = request.max_redirects if request.max_redirects is not None else WEB_MAX_REDIRECTS

    if timeout_seconds <= 0 or max_response_bytes <= 0 or max_redirects < 0:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Web analysis limits must be positive.")

    try:
        return analyze_web_basic_target(
            request.url,
            allow_private_targets=allow_private,
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
            max_redirects=max_redirects,
        )
    except HTTPException:
        raise
    except (OSError, ssl.SSLError, http.client.HTTPException, UnicodeError) as exc:
        normalized_url = normalize_web_url(request.url)
        error_message = f"Web analysis failed safely: {exc.__class__.__name__}: {exc}"
        tls = {
            "present": urlsplit(normalized_url).scheme == "https",
            "errors": [error_message] if urlsplit(normalized_url).scheme == "https" else [],
        }
        return build_web_result(
            original_url=request.url,
            normalized_url=normalized_url,
            final_url=normalized_url,
            http_result={},
            redirects=[],
            tls=tls,
            robots_txt={"checked": False, "errors": []},
            security_txt={"checked": False, "errors": []},
            findings=[
                make_finding(
                    "web_request_failed",
                    "Web request could not be completed",
                    "low",
                    "Inspectra could not complete the bounded HTTP/HTTPS request.",
                    error_message,
                    "Review target reachability, TLS configuration, and authorization scope manually.",
                )
            ],
            errors=[error_message],
        )


def analyze_web_basic_target(
    raw_url: str,
    *,
    allow_private_targets: bool,
    timeout_seconds: float,
    max_response_bytes: int,
    max_redirects: int,
) -> dict[str, Any]:
    original_url = raw_url
    normalized_url = normalize_web_url(raw_url)
    current_url = normalized_url
    redirects: list[dict[str, Any]] = []
    findings: list[dict[str, str]] = []
    errors: list[str] = []
    http_result: dict[str, Any] = {}

    for _ in range(max_redirects + 1):
        http_result = fetch_http_once(
            current_url,
            allow_private_targets=allow_private_targets,
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
        )
        status_code = int(http_result.get("status_code") or 0)
        location = header_value(as_dict(http_result.get("response_headers")), "Location")
        if status_code not in {301, 302, 303, 307, 308} or not location:
            break
        if len(redirects) >= max_redirects:
            errors.append("Redirect limit reached before a final response was reached.")
            findings.append(
                make_finding(
                    "web_redirect_limit_reached",
                    "Redirect limit reached",
                    "low",
                    "Inspectra stopped following redirects after the configured limit.",
                    f"{max_redirects} redirects followed",
                    "Review the redirect chain manually if this target is expected.",
                )
            )
            break
        next_url = normalize_web_url(urljoin(current_url, location))
        validate_web_url_allowed(next_url, allow_private_targets=allow_private_targets)
        if urlsplit(next_url).hostname != urlsplit(current_url).hostname:
            findings.append(
                make_finding(
                    "web_cross_host_redirect",
                    "Redirect points to a different host",
                    "info",
                    "The response redirects to a different host. This can be expected, but should be understood for authorized assessments.",
                    f"{current_url} -> {next_url}",
                    "Confirm the redirect destination is in scope before deeper testing.",
                )
            )
        redirects.append({"from_url": current_url, "to_url": next_url, "status_code": status_code})
        current_url = next_url

    final_url = current_url
    tls = inspect_tls(final_url, allow_private_targets=allow_private_targets, timeout_seconds=timeout_seconds)
    robots_txt = fetch_robots_txt(final_url, allow_private_targets, timeout_seconds, max_response_bytes)
    security_txt = fetch_security_txt(final_url, allow_private_targets, timeout_seconds, max_response_bytes)
    security_headers = evaluate_security_headers(as_dict(http_result.get("response_headers")))
    cookies = parse_response_cookies(http_result.get("set_cookie_headers", []))
    findings.extend(
        build_web_findings(
            final_url,
            http_result,
            security_headers,
            cookies,
            tls,
            robots_txt,
            security_txt,
            redirects,
        )
    )

    return build_web_result(
        original_url=original_url,
        normalized_url=normalized_url,
        final_url=final_url,
        http_result=http_result,
        redirects=redirects,
        tls=tls,
        robots_txt=robots_txt,
        security_txt=security_txt,
        findings=dedupe_findings(findings),
        errors=errors,
        security_headers=security_headers,
        cookies=cookies,
    )


def fetch_http_once(
    raw_url: str,
    *,
    allow_private_targets: bool,
    timeout_seconds: float,
    max_response_bytes: int,
) -> dict[str, Any]:
    url = normalize_web_url(raw_url)
    validate_web_url_allowed(url, allow_private_targets=allow_private_targets)
    parsed = urlsplit(url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    target = urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
    connection_class = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
    connection = connection_class(host, port=port, timeout=timeout_seconds)
    try:
        connection.request(
            "GET",
            target,
            headers={
                "User-Agent": "Inspectra/0.1 passive-web-audit",
                "Accept": "*/*",
                "Connection": "close",
            },
        )
        response = connection.getresponse()
        headers = response.getheaders()
        body, truncated = read_limited_response(response, max_response_bytes)
    finally:
        connection.close()

    public_headers = public_header_mapping(headers)
    return {
        "method": "GET",
        "url": url,
        "status_code": response.status,
        "reason": response.reason,
        "response_headers": public_headers,
        "set_cookie_headers": [value for name, value in headers if name.lower() == "set-cookie"],
        "content_type": header_value(public_headers, "Content-Type"),
        "bytes_read": len(body),
        "response_truncated": truncated,
    }


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
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or "/", parsed.query, ""))


def validate_web_url_allowed(raw_url: str, *, allow_private_targets: bool) -> None:
    parsed = urlsplit(normalize_web_url(raw_url))
    host = parsed.hostname or ""
    if host.lower().rstrip(".") in METADATA_HOSTS:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cloud metadata targets are not allowed.")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    for address in resolve_web_host(host, port):
        reason = blocked_web_ip_reason(address, allow_private_targets=allow_private_targets)
        if reason:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Target resolves to a blocked address range: {reason}.")


def resolve_web_host(host: str, port: int) -> set[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Target host could not be resolved.") from exc
    addresses: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
    for info in infos:
        try:
            addresses.add(ipaddress.ip_address(info[4][0]))
        except (IndexError, ValueError):
            continue
    if not addresses:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Target host did not resolve to an IP address.")
    return addresses


def blocked_web_ip_reason(address: ipaddress.IPv4Address | ipaddress.IPv6Address, *, allow_private_targets: bool) -> str | None:
    if address in METADATA_IPS:
        return "cloud metadata address"
    if address.is_unspecified:
        return "unspecified address"
    if address.is_link_local:
        return "link-local address"
    if not allow_private_targets and address.is_loopback:
        return "loopback address"
    if not allow_private_targets and address.is_private:
        return "private address"
    if not allow_private_targets and address.is_reserved:
        return "reserved address"
    return None


def read_limited_response(response: http.client.HTTPResponse, max_bytes: int) -> tuple[bytes, bool]:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = response.read(min(64 * 1024, max_bytes + 1 - total))
        if not chunk:
            break
        total += len(chunk)
        chunks.append(chunk)
        if total > max_bytes:
            return b"".join(chunks)[:max_bytes], True
    return b"".join(chunks), False


def public_header_mapping(headers: list[tuple[str, str]]) -> dict[str, Any]:
    mapped: dict[str, Any] = {}
    for name, value in headers:
        canonical = canonical_header_name(name)
        existing = mapped.get(canonical)
        if existing is None:
            mapped[canonical] = value
        elif isinstance(existing, list):
            existing.append(value)
        else:
            mapped[canonical] = [existing, value]
    return mapped


def canonical_header_name(name: str) -> str:
    return "-".join(part[:1].upper() + part[1:].lower() for part in name.split("-"))


def header_value(headers: dict[str, Any], name: str) -> str | None:
    lowered = name.lower()
    for key, value in headers.items():
        if key.lower() != lowered:
            continue
        if isinstance(value, list):
            return ", ".join(str(item) for item in value)
        return str(value)
    return None


def evaluate_security_headers(headers: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        name: {
            "present": header_value(headers, name) is not None,
            "value": header_value(headers, name),
        }
        for name in WEB_SECURITY_HEADERS
    }


def parse_response_cookies(raw_cookies: Any) -> list[dict[str, Any]]:
    if not isinstance(raw_cookies, list):
        return []
    parsed: list[dict[str, Any]] = []
    for raw_cookie in raw_cookies:
        cookie = SimpleCookie()
        try:
            cookie.load(str(raw_cookie))
        except Exception:
            parsed.append({"name": "unparsed", "raw": str(raw_cookie), "parse_error": True})
            continue
        for morsel in cookie.values():
            parsed.append(
                {
                    "name": morsel.key,
                    "secure": bool(morsel["secure"]),
                    "httponly": bool(morsel["httponly"]),
                    "samesite": morsel["samesite"] or None,
                    "domain": morsel["domain"] or None,
                    "path": morsel["path"] or None,
                    "max_age": morsel["max-age"] or None,
                    "expires": morsel["expires"] or None,
                }
            )
    return parsed


def inspect_tls(raw_url: str, *, allow_private_targets: bool, timeout_seconds: float) -> dict[str, Any]:
    parsed = urlsplit(normalize_web_url(raw_url))
    if parsed.scheme != "https":
        return {"present": False, "errors": []}
    validate_web_url_allowed(raw_url, allow_private_targets=allow_private_targets)
    host = parsed.hostname or ""
    port = parsed.port or 443
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout_seconds) as raw_socket:
            with context.wrap_socket(raw_socket, server_hostname=host) as tls_socket:
                cert = tls_socket.getpeercert()
                return {
                    "present": True,
                    "version": tls_socket.version(),
                    "cipher": tls_socket.cipher()[0] if tls_socket.cipher() else None,
                    "certificate": summarize_certificate(cert),
                    "errors": [],
                }
    except (OSError, ssl.SSLError, ValueError) as exc:
        return {"present": True, "errors": [f"TLS inspection failed: {exc.__class__.__name__}: {exc}"]}


def summarize_certificate(cert: dict[str, Any]) -> dict[str, Any]:
    not_before = parse_cert_time(cert.get("notBefore"))
    not_after = parse_cert_time(cert.get("notAfter"))
    days_until_expiration = None
    if not_after:
        days_until_expiration = int((not_after - datetime.now(timezone.utc)).total_seconds() // 86400)
    return {
        "subject": cert_name_dict(cert.get("subject")),
        "issuer": cert_name_dict(cert.get("issuer")),
        "not_before": not_before.isoformat() if not_before else None,
        "not_after": not_after.isoformat() if not_after else None,
        "days_until_expiration": days_until_expiration,
        "subject_alt_names": [value for kind, value in cert.get("subjectAltName", []) if kind == "DNS"],
    }


def cert_name_dict(value: Any) -> dict[str, str]:
    result: dict[str, str] = {}
    if not isinstance(value, tuple):
        return result
    for group in value:
        for key, item in group:
            result[str(key)] = str(item)
    return result


def parse_cert_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromtimestamp(ssl.cert_time_to_seconds(value), tz=timezone.utc)
    except (ValueError, OSError):
        return None


def fetch_robots_txt(base_url: str, allow_private_targets: bool, timeout_seconds: float, max_response_bytes: int) -> dict[str, Any]:
    url = base_path_url(base_url, "/robots.txt")
    return fetch_text_resource(url, allow_private_targets, timeout_seconds, min(max_response_bytes, 64 * 1024), resource_type="robots")


def fetch_security_txt(base_url: str, allow_private_targets: bool, timeout_seconds: float, max_response_bytes: int) -> dict[str, Any]:
    candidates = ["/.well-known/security.txt", "/security.txt"]
    results = [
        fetch_text_resource(base_path_url(base_url, path), allow_private_targets, timeout_seconds, min(max_response_bytes, 64 * 1024), resource_type="security")
        for path in candidates
    ]
    selected = next((item for item in results if item.get("present")), results[0])
    selected["candidates"] = [{"url": item.get("url"), "status_code": item.get("status_code"), "present": item.get("present")} for item in results]
    return selected


def base_path_url(base_url: str, path: str) -> str:
    parsed = urlsplit(normalize_web_url(base_url))
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def fetch_text_resource(
    url: str,
    allow_private_targets: bool,
    timeout_seconds: float,
    max_response_bytes: int,
    *,
    resource_type: str,
) -> dict[str, Any]:
    try:
        response = fetch_http_once(
            url,
            allow_private_targets=allow_private_targets,
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
        )
    except (HTTPException, OSError, ssl.SSLError, http.client.HTTPException) as exc:
        return {"checked": True, "url": url, "present": False, "errors": [str(exc)]}
    status_code = int(response.get("status_code") or 0)
    present = status_code == 200
    # fetch_http_once intentionally does not retain body in the public HTTP result; fetch again with a small helper here.
    text = fetch_body_text(url, allow_private_targets, timeout_seconds, max_response_bytes) if present else ""
    summary: dict[str, Any] = {
        "checked": True,
        "url": url,
        "present": present,
        "status_code": status_code,
        "content_type": response.get("content_type"),
        "bytes_read": response.get("bytes_read", 0),
        "errors": [],
    }
    if resource_type == "robots":
        lines = [line.strip() for line in text.splitlines() if line.strip()][:20]
        summary["sample_lines"] = lines
        summary["has_disallow"] = any(line.lower().startswith("disallow:") for line in lines)
        summary["has_sitemap"] = any(line.lower().startswith("sitemap:") for line in lines)
    else:
        summary["fields"] = parse_security_txt_fields(text)
    return summary


def fetch_body_text(url: str, allow_private_targets: bool, timeout_seconds: float, max_response_bytes: int) -> str:
    validate_web_url_allowed(url, allow_private_targets=allow_private_targets)
    parsed = urlsplit(url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    target = urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
    connection_class = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
    connection = connection_class(host, port=port, timeout=timeout_seconds)
    try:
        connection.request("GET", target, headers={"User-Agent": "Inspectra/0.1 passive-web-audit", "Connection": "close"})
        response = connection.getresponse()
        body, _ = read_limited_response(response, max_response_bytes)
        return body.decode("utf-8", errors="replace")
    finally:
        connection.close()


def parse_security_txt_fields(text: str) -> dict[str, list[str]]:
    fields: dict[str, list[str]] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, value = [part.strip() for part in line.split(":", 1)]
        normalized = key.lower()
        if normalized in SECURITY_TXT_FIELDS:
            fields.setdefault(key, []).append(value)
    return fields


def build_web_findings(
    final_url: str,
    http_result: dict[str, Any],
    security_headers: dict[str, dict[str, Any]],
    cookies: list[dict[str, Any]],
    tls: dict[str, Any],
    robots_txt: dict[str, Any],
    security_txt: dict[str, Any],
    redirects: list[dict[str, Any]],
) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    scheme = urlsplit(final_url).scheme
    headers = as_dict(http_result.get("response_headers"))
    if scheme == "http":
        findings.append(make_finding("web_http_without_https", "Target uses HTTP", "low", "The final URL uses HTTP rather than HTTPS.", final_url, "Prefer HTTPS for production services."))
    if scheme == "https" and not security_headers["Strict-Transport-Security"]["present"]:
        findings.append(make_finding("web_hsts_missing", "HSTS header is absent", "low", "HSTS is not present on the HTTPS response.", final_url, "Consider HSTS after confirming HTTPS is consistently available."))
    if not security_headers["Content-Security-Policy"]["present"]:
        findings.append(make_finding("web_csp_missing", "Content-Security-Policy header is absent", "info", "A CSP header was not observed. This is a hardening indicator, not a vulnerability by itself.", final_url, "Review whether a Content-Security-Policy is appropriate for this application."))
    if not security_headers["X-Content-Type-Options"]["present"]:
        findings.append(make_finding("web_x_content_type_options_missing", "X-Content-Type-Options header is absent", "info", "The response does not include X-Content-Type-Options.", final_url, "Consider setting X-Content-Type-Options: nosniff."))
    csp_value = str(security_headers["Content-Security-Policy"].get("value") or "")
    if not security_headers["X-Frame-Options"]["present"] and "frame-ancestors" not in csp_value.lower():
        findings.append(make_finding("web_frame_protection_missing", "Frame embedding policy was not observed", "info", "Neither X-Frame-Options nor a CSP frame-ancestors directive was observed.", final_url, "Review clickjacking protections for pages that need them."))
    if header_value(headers, "Server"):
        findings.append(make_finding("web_server_header_present", "Server header is present", "info", "The response includes a Server header.", header_value(headers, "Server") or "", "Confirm exposed server details are intentional."))
    if header_value(headers, "X-Powered-By"):
        findings.append(make_finding("web_x_powered_by_present", "X-Powered-By header is present", "info", "The response includes an X-Powered-By header.", header_value(headers, "X-Powered-By") or "", "Confirm exposed framework details are intentional."))
    for cookie in cookies:
        cookie_name = str(cookie.get("name") or "cookie")
        if scheme == "https" and not cookie.get("secure"):
            findings.append(make_finding("web_cookie_missing_secure", "Cookie without Secure flag", "low", "A Set-Cookie value was observed without the Secure attribute on an HTTPS response.", cookie_name, "Set Secure for cookies that should only be sent over HTTPS."))
        if not cookie.get("httponly"):
            findings.append(make_finding("web_cookie_missing_httponly", "Cookie without HttpOnly flag", "info", "A Set-Cookie value was observed without HttpOnly.", cookie_name, "Use HttpOnly for cookies that do not need JavaScript access."))
        if not cookie.get("samesite"):
            findings.append(make_finding("web_cookie_missing_samesite", "Cookie without SameSite attribute", "info", "A Set-Cookie value was observed without SameSite.", cookie_name, "Set a SameSite policy appropriate for the application."))
        if str(cookie.get("samesite") or "").lower() == "none" and not cookie.get("secure"):
            findings.append(make_finding("web_cookie_samesite_none_without_secure", "SameSite=None cookie without Secure", "low", "SameSite=None should be paired with Secure in modern browsers.", cookie_name, "Add Secure or review whether SameSite=None is necessary."))
    cert = as_dict(tls.get("certificate"))
    days = cert.get("days_until_expiration")
    if isinstance(days, int) and days < 0:
        findings.append(make_finding("web_tls_certificate_expired", "TLS certificate appears expired", "medium", "The certificate notAfter date is in the past.", str(days), "Renew and validate the certificate chain."))
    elif isinstance(days, int) and days < 30:
        findings.append(make_finding("web_tls_certificate_expiring", "TLS certificate expires soon", "low", "The certificate expires in less than 30 days.", f"{days} days", "Plan certificate renewal before expiry."))
    if tls.get("errors"):
        findings.append(make_finding("web_tls_inspection_error", "TLS inspection reported an error", "low", "Inspectra could not complete TLS certificate inspection.", "; ".join(tls.get("errors", [])), "Review certificate and network behavior manually."))
    if not security_txt.get("present"):
        findings.append(make_finding("web_security_txt_absent", "security.txt was not observed", "info", "Inspectra did not observe security.txt at the common locations checked.", final_url, "Consider publishing security.txt if appropriate for the service."))
    if robots_txt.get("present") and robots_txt.get("has_disallow"):
        findings.append(make_finding("web_robots_disallow_present", "robots.txt contains Disallow entries", "info", "robots.txt includes Disallow directives. This is informational and not a security control.", str(robots_txt.get("sample_lines", [])), "Review disclosed paths manually and avoid treating robots.txt as access control."))
    if redirects:
        findings.append(make_finding("web_redirects_present", "Redirects were observed", "info", "The target returned one or more redirects.", f"{len(redirects)} redirects", "Confirm redirect destinations remain in authorized scope."))
    return findings


def dedupe_findings(findings: list[dict[str, str]]) -> list[dict[str, str]]:
    seen: set[tuple[str, str]] = set()
    unique: list[dict[str, str]] = []
    for finding in findings:
        key = (finding.get("id", ""), finding.get("evidence", ""))
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


def build_web_result(
    *,
    original_url: str,
    normalized_url: str,
    final_url: str,
    http_result: dict[str, Any],
    redirects: list[dict[str, Any]],
    tls: dict[str, Any],
    robots_txt: dict[str, Any],
    security_txt: dict[str, Any],
    findings: list[dict[str, str]],
    errors: list[str],
    security_headers: dict[str, dict[str, Any]] | None = None,
    cookies: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    parsed = urlsplit(final_url)
    headers = as_dict(http_result.get("response_headers"))
    security_headers = security_headers or evaluate_security_headers(headers)
    cookies = cookies or []
    return {
        "analyzer": "web_basic",
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "target": {
            "original_url": original_url,
            "normalized_url": normalized_url,
            "final_url": final_url,
            "scheme": parsed.scheme,
            "host": parsed.hostname,
        },
        "http": {
            "status_code": http_result.get("status_code"),
            "redirects": redirects,
            "response_headers": headers,
            "content_type": http_result.get("content_type"),
            "bytes_read": http_result.get("bytes_read", 0),
            "response_truncated": http_result.get("response_truncated", False),
            "server": header_value(headers, "Server"),
            "x_powered_by": header_value(headers, "X-Powered-By"),
        },
        "security_headers": security_headers,
        "cookies": cookies,
        "tls": tls or {"present": False, "errors": []},
        "robots_txt": robots_txt,
        "security_txt": security_txt,
        "findings": findings,
        "errors": errors,
        "summary": {
            "findings_count": len(findings),
            "missing_security_headers_count": sum(1 for item in security_headers.values() if not item.get("present")),
            "cookies_count": len(cookies),
            "redirects_count": len(redirects),
            "tls_present": bool((tls or {}).get("present")),
            "security_txt_present": bool(security_txt.get("present")),
            "robots_txt_present": bool(robots_txt.get("present")),
        },
    }


def resolve_data_path(relative_path: str) -> Path:
    candidate = (DATA_DIR / relative_path).resolve()
    if candidate != DATA_DIR and DATA_DIR not in candidate.parents:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Path escapes data directory.")
    return candidate


def detect_image_format(header: bytes) -> str | None:
    if header.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if header.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if len(header) >= 12 and header[:4] == b"RIFF" and header[8:12] == b"WEBP":
        return "webp"
    return None


def detect_manifest_type(filename: str) -> str | None:
    normalized = filename.lower()
    if normalized == "package.json" or normalized.endswith("-package.json"):
        return "package_json"
    if normalized == "requirements.txt" or normalized.endswith("-requirements.txt"):
        return "requirements_txt"
    if normalized == "pyproject.toml" or normalized.endswith("-pyproject.toml"):
        return "pyproject_toml"
    return None


def analyze_package_json_manifest(raw_text: str) -> tuple[dict[str, Any], list[dict[str, str]], list[str]]:
    errors: list[str] = []
    findings: list[dict[str, str]] = []
    try:
        payload = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        return empty_manifest_parse(), findings, [f"package.json parse error: {exc.msg}"]
    if not isinstance(payload, dict):
        return empty_manifest_parse(), findings, ["package.json root value is not an object."]

    dependency_groups: dict[str, list[dict[str, str]]] = {}
    for group in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        dependencies = payload.get(group)
        if isinstance(dependencies, dict):
            dependency_groups[group] = normalize_mapping_dependencies(dependencies)

    scripts = stringify_mapping(payload.get("scripts"))
    engines = stringify_mapping(payload.get("engines"))
    project = {
        "name": payload.get("name") if isinstance(payload.get("name"), str) else None,
        "version": payload.get("version") if isinstance(payload.get("version"), str) else None,
    }

    if scripts:
        findings.append(
            make_finding(
                "package_scripts_present",
                "package.json declares scripts",
                "info",
                "The manifest contains npm scripts. Inspectra does not execute them; review them before running package manager commands.",
                ", ".join(sorted(scripts)),
                "Review scripts manually before installing or running this project.",
            )
        )
    for name, command in scripts.items():
        if is_sensitive_script(name, command):
            findings.append(
                make_finding(
                    "package_sensitive_lifecycle_script",
                    "Lifecycle script should be reviewed",
                    "medium",
                    "Lifecycle scripts such as install, preinstall, postinstall, and prepare can run during package manager workflows.",
                    f"{name}: {command}",
                    "Confirm the script is expected before running package manager commands locally or in CI.",
                )
            )

    findings.extend(find_dependency_indicators(dependency_groups))
    return {
        "project": {key: value for key, value in project.items() if value},
        "dependencies": dependency_groups,
        "scripts": scripts,
        "engines": engines,
    }, findings, errors


def analyze_requirements_manifest(raw_text: str) -> tuple[dict[str, Any], list[dict[str, str]], list[str]]:
    findings: list[dict[str, str]] = []
    dependencies: list[dict[str, str]] = []

    for line_number, raw_line in enumerate(raw_text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        line = strip_inline_comment(line)
        if not line:
            continue

        if starts_with_any(line, ("--extra-index-url", "--index-url", "--find-links")):
            findings.append(
                make_finding(
                    "requirements_custom_index",
                    "Custom package index or link source",
                    "medium",
                    "The requirements file references an alternate index or link source. This is an informational supply-chain signal.",
                    f"line {line_number}: {line}",
                    "Confirm the configured package source is trusted and expected.",
                )
            )
            continue

        if line == "-e" or line.startswith("-e "):
            dependencies.append(
                {
                    "name": parse_editable_name(line),
                    "specifier": line,
                    "source": f"line {line_number}",
                    "declared_requirement": line,
                    "source_type": "editable",
                }
            )
            findings.append(
                make_finding(
                    "requirements_editable_install",
                    "Editable install reference",
                    "medium",
                    "Editable installs can point at local paths or VCS sources. Inspectra records this without installing anything.",
                    f"line {line_number}: {line}",
                    "Review the referenced source before installing this requirements file.",
                )
            )
            if contains_external_or_local_source(line):
                findings.append(make_dependency_source_finding(f"line {line_number}", line))
            continue

        if line.startswith("-"):
            findings.append(
                make_finding(
                    "requirements_option_present",
                    "Requirements option present",
                    "info",
                    "The file contains a pip option. Inspectra does not execute pip and records this for manual review.",
                    f"line {line_number}: {line}",
                    "Check that this option is expected before using the file with pip.",
                )
            )
            continue

        dependency = parse_requirement_dependency(line, line_number)
        dependencies.append(dependency)
        if "==" not in dependency["specifier"]:
            findings.append(
                make_finding(
                    "requirements_dependency_not_exactly_pinned",
                    "Dependency is not exactly pinned",
                    "low",
                    "The dependency line does not use an exact == pin. This is not a vulnerability, but it can reduce repeatability.",
                    f"line {line_number}: {line}",
                    "Consider exact pins or a lockfile in workflows that require deterministic installs.",
                )
            )
        if contains_external_or_local_source(line):
            findings.append(make_dependency_source_finding(f"line {line_number}", line))

    return {
        "project": {},
        "dependencies": {"dependencies": dependencies},
        "scripts": {},
        "engines": {},
    }, findings, []


def analyze_pyproject_manifest(raw_text: str) -> tuple[dict[str, Any], list[dict[str, str]], list[str]]:
    payload, errors = parse_toml_document(raw_text)
    findings: list[dict[str, str]] = []
    if payload is None:
        return empty_manifest_parse(), findings, errors

    project = as_dict(payload.get("project"))
    tool = as_dict(payload.get("tool"))
    poetry = as_dict(as_dict(tool.get("poetry")).copy()) if tool else {}
    dependency_groups: dict[str, list[dict[str, str]]] = {}

    project_dependencies = project.get("dependencies") if project else None
    if isinstance(project_dependencies, list):
        dependency_groups["dependencies"] = [normalize_pep508_dependency(item) for item in project_dependencies if isinstance(item, str)]

    optional_dependencies = as_dict(project.get("optional-dependencies")) if project else {}
    for group_name, dependencies in optional_dependencies.items():
        if isinstance(dependencies, list):
            dependency_groups[f"optional:{group_name}"] = [
                normalize_pep508_dependency(item) for item in dependencies if isinstance(item, str)
            ]

    poetry_dependencies = as_dict(poetry.get("dependencies"))
    if poetry_dependencies:
        dependency_groups["poetry:dependencies"] = [
            normalize_poetry_dependency(name, specifier)
            for name, specifier in poetry_dependencies.items()
            if name.lower() != "python"
        ]

    poetry_groups = as_dict(poetry.get("group"))
    for group_name, group_payload in poetry_groups.items():
        group_dependencies = as_dict(as_dict(group_payload).get("dependencies"))
        if group_dependencies:
            dependency_groups[f"poetry:{group_name}"] = [
                normalize_poetry_dependency(name, specifier)
                for name, specifier in group_dependencies.items()
                if name.lower() != "python"
            ]

    findings.extend(find_dependency_indicators(dependency_groups))
    return {
        "project": {
            key: value
            for key, value in {
                "name": project.get("name") if project else None,
                "version": project.get("version") if project else None,
            }.items()
            if isinstance(value, str)
        },
        "dependencies": dependency_groups,
        "scripts": {},
        "engines": {},
    }, findings, errors


def empty_manifest_parse() -> dict[str, Any]:
    return {"project": {}, "dependencies": {}, "scripts": {}, "engines": {}}


def normalize_mapping_dependencies(dependencies: dict[str, Any]) -> list[dict[str, str]]:
    normalized: list[dict[str, str]] = []
    for name, specifier in sorted(dependencies.items()):
        if not isinstance(name, str):
            continue
        specifier_text = stringify_manifest_value(specifier)
        normalized.append(
            {
                "name": name,
                "specifier": specifier_text,
                "declared_requirement": f"{name}: {specifier_text}" if specifier_text else name,
                "source_type": classify_dependency_source_hint("package_json", name, specifier_text),
            }
        )
    return normalized


def stringify_mapping(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {str(key): stringify_manifest_value(item) for key, item in value.items()}


def parse_requirement_dependency(line: str, line_number: int) -> dict[str, str]:
    requirement = line.split(";", 1)[0].strip()
    match = re.match(r"^([A-Za-z0-9_.-]+(?:\[[^\]]+\])?)(.*)$", requirement)
    if not match:
        return {
            "name": requirement,
            "specifier": line,
            "source": f"line {line_number}",
            "declared_requirement": line,
            "source_type": classify_dependency_source_hint("requirements_txt", requirement, line, line),
        }
    name = match.group(1)
    specifier = match.group(2).strip() or ""
    return {
        "name": name,
        "specifier": specifier,
        "source": f"line {line_number}",
        "declared_requirement": line,
        "source_type": classify_dependency_source_hint("requirements_txt", name, specifier, line),
    }


def parse_editable_name(line: str) -> str:
    egg_match = re.search(r"[#&]egg=([A-Za-z0-9_.-]+)", line)
    if egg_match:
        return egg_match.group(1)
    return "editable-reference"


def normalize_pep508_dependency(value: str) -> dict[str, str]:
    match = re.match(r"^([A-Za-z0-9_.-]+(?:\[[^\]]+\])?)(.*)$", value.strip())
    if not match:
        stripped = value.strip()
        return {
            "name": stripped,
            "specifier": "",
            "declared_requirement": stripped,
            "source_type": classify_dependency_source_hint("pyproject_toml", stripped, "", stripped),
        }
    name = match.group(1)
    specifier = match.group(2).strip()
    return {
        "name": name,
        "specifier": specifier,
        "declared_requirement": value.strip(),
        "source_type": classify_dependency_source_hint("pyproject_toml", name, specifier, value.strip()),
    }


def normalize_poetry_dependency(name: str, specifier: Any) -> dict[str, str]:
    specifier_text = stringify_manifest_value(specifier)
    return {
        "name": name,
        "specifier": specifier_text,
        "declared_requirement": f"{name}: {specifier_text}" if specifier_text else name,
        "source_type": classify_dependency_source_hint("pyproject_toml", name, specifier_text),
    }


def find_dependency_indicators(dependency_groups: dict[str, list[dict[str, str]]]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for group, dependencies in dependency_groups.items():
        for dependency in dependencies:
            name = dependency.get("name", "unknown")
            specifier = dependency.get("specifier", "")
            evidence = f"{group}: {name} {specifier}".strip()
            if is_broad_dependency_range(specifier):
                findings.append(
                    make_finding(
                        "dependency_broad_range",
                        "Dependency uses a very broad range",
                        "low",
                        "A dependency uses a very broad version selector such as * or latest. This is an informational repeatability signal.",
                        evidence,
                        "Prefer a deliberate version range or lockfile for reproducible environments.",
                    )
                )
            if contains_external_or_local_source(specifier):
                findings.append(make_dependency_source_finding(group, evidence))
            elif specifier and not has_exact_pin(specifier):
                findings.append(
                    make_finding(
                        "dependency_not_exactly_pinned",
                        "Dependency is not exactly pinned",
                        "info",
                        "The dependency does not use an exact == pin. This is not a vulnerability; it is a signal to review reproducibility needs.",
                        evidence,
                        "Use exact pins or lockfiles where deterministic builds matter.",
                    )
                )
    return findings


def make_dependency_source_finding(source: str, evidence: str) -> dict[str, str]:
    return make_finding(
        "dependency_external_or_local_source",
        "Dependency references URL, VCS, or local source",
        "medium",
        "The dependency appears to reference a URL, VCS, or local path. This can be legitimate, but should be reviewed as a supply-chain signal.",
        f"{source}: {evidence}",
        "Confirm the referenced source is trusted, pinned, and expected.",
    )


def is_sensitive_script(name: str, command: str) -> bool:
    sensitive_names = {"postinstall", "preinstall", "prepare", "install"}
    lowered = f"{name} {command}".lower()
    return name.lower() in sensitive_names or any(script_name in lowered for script_name in sensitive_names)


def is_broad_dependency_range(specifier: str) -> bool:
    normalized = specifier.strip().lower()
    return normalized in {"*", "latest"}


def has_exact_pin(specifier: str) -> bool:
    return "==" in specifier


def contains_external_or_local_source(value: str) -> bool:
    normalized = value.lower()
    source_markers = ("http://", "https://", "git+", "git://", "github:", "gitlab:", "file:", "path =")
    return any(marker in normalized for marker in source_markers)


def classify_dependency_source_hint(
    manifest_type: str,
    name: str,
    specifier: str,
    declared_requirement: str | None = None,
) -> str:
    declared = declared_requirement or f"{name} {specifier}".strip()
    if manifest_type == "package_json":
        return classify_npm_source_hint(name, specifier)
    return classify_python_source_hint(name, specifier, declared)


def classify_npm_source_hint(name: str, specifier: str) -> str:
    value = specifier.strip()
    lowered = value.lower()
    if not re.fullmatch(r"(?:@[A-Za-z0-9][A-Za-z0-9._~-]*/)?[A-Za-z0-9][A-Za-z0-9._~-]*", name):
        return "unknown"
    if not value:
        return "registry"
    if lowered.startswith("workspace:"):
        return "workspace"
    if lowered.startswith(("file:", "link:", "portal:")) or looks_like_local_dependency_path(value):
        return "local"
    if lowered.startswith("npm:"):
        return "alias"
    if looks_like_vcs_dependency(value) or re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:#[^\s]+)?", value):
        return "vcs"
    if looks_like_url_dependency(value):
        return "url"
    return "registry"


def classify_python_source_hint(name: str, specifier: str, declared_requirement: str) -> str:
    combined = " ".join(part for part in (name.strip(), specifier.strip(), declared_requirement.strip()) if part)
    lowered = combined.lower()
    if lowered.startswith("-e ") or lowered == "-e" or specifier.strip().startswith("-e "):
        return "editable"
    if specifier.strip().startswith(("--", "-r", "-c")) or lowered.startswith(("--", "-r ", "-c ")):
        return "unknown"
    if looks_like_local_dependency_path(name) or looks_like_local_dependency_path(specifier):
        return "local"
    if " @ " in combined or specifier.strip().startswith("@"):
        reference = combined.split("@", 1)[1].strip()
        if looks_like_vcs_dependency(reference):
            return "vcs"
        if reference.lower().startswith("file:") or looks_like_local_dependency_path(reference):
            return "local"
        if looks_like_url_dependency(reference):
            return "url"
        return "unknown"
    if looks_like_vcs_dependency(combined):
        return "vcs"
    if looks_like_url_dependency(combined):
        return "url"
    if "file:" in lowered or "path =" in lowered:
        return "local"
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*(?:\[[A-Za-z0-9_,._-]+\])?", name):
        return "unknown"
    return "registry"


def looks_like_url_dependency(value: str) -> bool:
    return bool(re.search(r"(?:^|\s)[A-Za-z][A-Za-z0-9+.-]*://", value))


def looks_like_vcs_dependency(value: str) -> bool:
    normalized = value.lower()
    markers = ("git+", "git://", "git@", "hg+", "svn+", "bzr+", "github:", "gitlab:", "bitbucket:")
    return any(marker in normalized for marker in markers)


def looks_like_local_dependency_path(value: str) -> bool:
    normalized = value.strip().lower()
    if re.match(r"^[a-z]:[\\/]", normalized):
        return True
    return normalized.startswith(("./", "../", ".\\", "..\\", "/", "\\", "~", "file:"))


def starts_with_any(value: str, prefixes: tuple[str, ...]) -> bool:
    return any(value.startswith(prefix) for prefix in prefixes)


def strip_inline_comment(line: str) -> str:
    return line.split(" #", 1)[0].strip()


def detect_archive_type(path: Path, original_filename: str) -> str:
    normalized_name = original_filename.lower()
    try:
        if normalized_name.endswith(".zip") and zipfile.is_zipfile(path):
            return "zip"
        if normalized_name.endswith((".tar.gz", ".tgz")) and tarfile.is_tarfile(path):
            return "tar_gz"
        if normalized_name.endswith(".tar") and tarfile.is_tarfile(path):
            return "tar"
        if zipfile.is_zipfile(path):
            return "zip"
        if tarfile.is_tarfile(path):
            return "tar_gz" if normalized_name.endswith((".tar.gz", ".tgz")) else "tar"
    except OSError:
        return "unknown"
    return "unknown"


def inspect_zip_metadata_preflight(path: Path) -> ZipMetadataPreflight:
    file_size = path.stat().st_size
    with path.open("rb") as handle:
        handle.seek(max(0, file_size - ZIP_EOCD_SCAN_SIZE))
        tail = handle.read(ZIP_EOCD_SCAN_SIZE)

    eocd_offset = tail.rfind(ZIP_EOCD_SIGNATURE)
    if eocd_offset < 0 or len(tail) - eocd_offset < ZIP_EOCD_MIN_SIZE:
        return ZipMetadataPreflight(None, None, "metadata_preflight_unavailable")

    try:
        (
            _signature,
            disk_number,
            central_directory_disk,
            entries_this_disk,
            total_entries,
            central_directory_bytes,
            central_directory_offset,
            comment_length,
        ) = struct.unpack_from("<4s4H2LH", tail, eocd_offset)
    except struct.error:
        return ZipMetadataPreflight(None, None, "metadata_preflight_unavailable")

    if eocd_offset + ZIP_EOCD_MIN_SIZE + comment_length > len(tail):
        return ZipMetadataPreflight(None, None, "metadata_preflight_unavailable")
    if disk_number or central_directory_disk or entries_this_disk != total_entries:
        return ZipMetadataPreflight(total_entries, central_directory_bytes, "multi_disk_zip")
    if (
        total_entries == ZIP16_MAX_FIELD
        or entries_this_disk == ZIP16_MAX_FIELD
        or central_directory_bytes == ZIP32_MAX_FIELD
        or central_directory_offset == ZIP32_MAX_FIELD
    ):
        return ZipMetadataPreflight(total_entries, central_directory_bytes, "zip64_metadata")
    return ZipMetadataPreflight(total_entries, central_directory_bytes)


def zip_preflight_block_reason(preflight: ZipMetadataPreflight, max_entries: int) -> str | None:
    if preflight.reason:
        return preflight.reason
    if preflight.total_entries is not None and preflight.total_entries > max_entries:
        return "too_many_entries"
    if (
        preflight.central_directory_bytes is not None
        and preflight.central_directory_bytes > ARCHIVE_MAX_ZIP_CENTRAL_DIRECTORY_BYTES
    ):
        return "central_directory_too_large"
    return None


def add_zip_preflight_summary(summary: dict[str, Any], preflight: ZipMetadataPreflight) -> None:
    if preflight.total_entries is not None:
        summary["zip_entries_declared"] = preflight.total_entries
    if preflight.central_directory_bytes is not None:
        summary["zip_central_directory_bytes"] = preflight.central_directory_bytes


def zip_preflight_finding(reason: str, preflight: ZipMetadataPreflight, max_entries: int) -> dict[str, str]:
    evidence_parts = [f"configured entry limit: {max_entries}"]
    if preflight.total_entries is not None:
        evidence_parts.append(f"declared ZIP entries: {preflight.total_entries}")
    if preflight.central_directory_bytes is not None:
        evidence_parts.append(f"central directory bytes: {preflight.central_directory_bytes}")
    evidence_parts.append(f"central directory byte limit: {ARCHIVE_MAX_ZIP_CENTRAL_DIRECTORY_BYTES}")
    evidence = "; ".join(evidence_parts)

    if reason == "too_many_entries":
        return make_finding(
            "archive_zip_entry_limit_preflight",
            "ZIP entry limit reached during metadata preflight",
            "medium",
            "The ZIP central directory declares more entries than Inspectra will inspect in this phase, so detailed metadata parsing was skipped before opening the ZIP with Python's zipfile parser.",
            evidence,
            "Review the archive in a constrained environment or raise limits only for trusted inputs.",
        )
    if reason == "central_directory_too_large":
        return make_finding(
            "archive_zip_central_directory_too_large",
            "ZIP central directory exceeds configured metadata limit",
            "medium",
            "The ZIP central directory is large enough to be a possible resource-consumption indicator, so detailed metadata parsing was skipped.",
            evidence,
            "Keep upload size limits conservative and inspect this archive manually in a constrained environment if needed.",
        )
    if reason == "zip64_metadata":
        return make_finding(
            "archive_zip64_metadata_requires_review",
            "ZIP64 metadata requires manual review",
            "low",
            "The standard ZIP end-of-central-directory record uses ZIP64 sentinel values. Inspectra does not parse ZIP64 metadata in this MVP and skips detailed ZIP metadata to avoid over-trusting incomplete limits.",
            evidence,
            "Inspect ZIP64 archives in a constrained workflow before extraction or increase support in a dedicated hardening phase.",
        )
    if reason == "multi_disk_zip":
        return make_finding(
            "archive_multidisk_zip_unsupported",
            "Multi-disk ZIP metadata is not supported",
            "low",
            "The ZIP metadata indicates a multi-disk archive. Inspectra skips detailed analysis for this format in the MVP.",
            evidence,
            "Review the archive with tooling that explicitly supports multi-disk ZIP files.",
        )
    return make_finding(
        "archive_zip_metadata_preflight_unavailable",
        "ZIP metadata preflight was inconclusive",
        "low",
        "Inspectra could not confidently parse the standard ZIP end-of-central-directory metadata before opening the archive.",
        evidence,
        "Treat this result as incomplete and review the archive in a constrained environment if it is expected.",
    )


def blocked_zip_archive_analysis(path: Path, preflight: ZipMetadataPreflight, reason: str) -> dict[str, Any]:
    summary = empty_archive_summary(total_compressed_bytes=path.stat().st_size)
    summary["truncated"] = True
    add_zip_preflight_summary(summary, preflight)
    finding = zip_preflight_finding(reason, preflight, ARCHIVE_MAX_ENTRIES)
    findings = [finding]
    summary["findings_count"] = len(findings)
    return {
        "entries_sample": [],
        "detected_manifests": [],
        "findings": findings,
        "summary": summary,
        "errors": [],
    }


def analyze_zip_archive(path: Path) -> dict[str, Any]:
    entries_sample: list[dict[str, Any]] = []
    detected_manifests: list[dict[str, str]] = []
    findings: list[dict[str, str]] = []
    seen_findings: set[str] = set()
    summary = empty_archive_summary()
    preflight = inspect_zip_metadata_preflight(path)
    blocked_reason = zip_preflight_block_reason(preflight, ARCHIVE_MAX_ENTRIES)
    if blocked_reason:
        return blocked_zip_archive_analysis(path, preflight, blocked_reason)
    add_zip_preflight_summary(summary, preflight)

    with zipfile.ZipFile(path) as archive:
        for index, info in enumerate(archive.filelist, start=1):
            if index > ARCHIVE_MAX_ENTRIES:
                summary["truncated"] = True
                add_archive_finding(
                    findings,
                    seen_findings,
                    "archive_too_many_entries",
                    "Archive entry limit reached",
                    "medium",
                    "The archive contains more entries than Inspectra will inspect in this phase.",
                    f"Processed {ARCHIVE_MAX_ENTRIES} entries; additional entries were not listed.",
                    "Review the archive with stricter limits or split it into smaller packages before extraction.",
                )
                break

            mode = (info.external_attr >> 16) or None
            entry_type = "directory" if info.is_dir() else "symlink" if mode and stat.S_ISLNK(mode) else "file"
            record_archive_entry(
                summary,
                entries_sample,
                detected_manifests,
                findings,
                seen_findings,
                {
                    "path": info.filename,
                    "type": entry_type,
                    "size": info.file_size,
                    "compressed_size": info.compress_size,
                    "mode": format_file_mode(mode),
                    "mode_int": mode,
                    "link_target": None,
                },
            )

    finalize_archive_summary(summary, findings, seen_findings)
    return {
        "entries_sample": entries_sample,
        "detected_manifests": detected_manifests,
        "findings": findings,
        "summary": summary,
        "errors": [],
    }


def analyze_tar_archive(path: Path) -> dict[str, Any]:
    entries_sample: list[dict[str, Any]] = []
    detected_manifests: list[dict[str, str]] = []
    findings: list[dict[str, str]] = []
    seen_findings: set[str] = set()
    summary = empty_archive_summary(total_compressed_bytes=path.stat().st_size)

    with tarfile.open(path, "r:*") as archive:
        for index, member in enumerate(archive, start=1):
            if index > ARCHIVE_MAX_ENTRIES:
                summary["truncated"] = True
                add_archive_finding(
                    findings,
                    seen_findings,
                    "archive_too_many_entries",
                    "Archive entry limit reached",
                    "medium",
                    "The archive contains more entries than Inspectra will inspect in this phase.",
                    f"Processed {ARCHIVE_MAX_ENTRIES} entries; additional entries were not listed.",
                    "Review the archive with stricter limits or split it into smaller packages before extraction.",
                )
                break

            record_archive_entry(
                summary,
                entries_sample,
                detected_manifests,
                findings,
                seen_findings,
                {
                    "path": member.name,
                    "type": tar_member_type(member),
                    "size": member.size,
                    "compressed_size": None,
                    "mode": format_file_mode(member.mode),
                    "mode_int": member.mode,
                    "link_target": member.linkname or None,
                },
            )

    finalize_archive_summary(summary, findings, seen_findings)
    return {
        "entries_sample": entries_sample,
        "detected_manifests": detected_manifests,
        "findings": findings,
        "summary": summary,
        "errors": [],
    }


def build_archive_result(
    file_id: str,
    path: Path,
    original_filename: str,
    archive_type: str,
    *,
    entries_sample: list[dict[str, Any]],
    detected_manifests: list[dict[str, str]],
    findings: list[dict[str, str]],
    summary: dict[str, Any],
    errors: list[str],
) -> dict[str, Any]:
    summary["findings_count"] = len(findings)
    return {
        "file_id": file_id,
        "analyzer": "archive_basic",
        "archive_type": archive_type,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "hashes": calculate_hashes(path),
        "file_identification": {
            "size_bytes": path.stat().st_size,
            "original_filename": original_filename,
        },
        "limits": {
            "max_entries": ARCHIVE_MAX_ENTRIES,
            "max_total_uncompressed_bytes": ARCHIVE_MAX_TOTAL_UNCOMPRESSED_BYTES,
            "max_entry_name_length": ARCHIVE_MAX_ENTRY_NAME_LENGTH,
            "max_listed_entries": ARCHIVE_MAX_LISTED_ENTRIES,
            "max_zip_central_directory_bytes": ARCHIVE_MAX_ZIP_CENTRAL_DIRECTORY_BYTES,
        },
        "summary": summary,
        "entries_sample": entries_sample,
        "detected_manifests": detected_manifests,
        "findings": findings,
        "errors": errors,
    }


def analyze_project_archive_manifests(path: Path, archive_type: str) -> dict[str, Any]:
    analysis = empty_project_archive_analysis()
    state = {
        "total_manifest_bytes": 0,
        "parseable_manifests_seen": 0,
    }

    if archive_type == "zip":
        preflight = inspect_zip_metadata_preflight(path)
        blocked_reason = zip_preflight_block_reason(preflight, PROJECT_ARCHIVE_MAX_ARCHIVE_ENTRIES)
        add_zip_preflight_summary(analysis["summary"], preflight)
        if blocked_reason:
            add_project_zip_preflight_finding(analysis, preflight, blocked_reason)
            finalize_project_archive_analysis(analysis)
            return analysis
        with zipfile.ZipFile(path) as archive:
            for index, info in enumerate(archive.filelist, start=1):
                if should_stop_project_archive_scan(index, analysis):
                    break
                mode = (info.external_attr >> 16) or None
                entry = {
                    "path": info.filename,
                    "type": "directory" if info.is_dir() else "symlink" if mode and stat.S_ISLNK(mode) else "file",
                    "size": info.file_size,
                    "mode_int": mode,
                    "mode": format_file_mode(mode),
                    "link_target": None,
                }
                process_project_archive_entry(
                    analysis,
                    state,
                    entry,
                    lambda entry_info=info: archive.open(entry_info),
                )
    else:
        with tarfile.open(path, "r:*") as archive:
            for index, member in enumerate(archive, start=1):
                if should_stop_project_archive_scan(index, analysis):
                    break
                entry = {
                    "path": member.name,
                    "type": tar_member_type(member),
                    "size": member.size,
                    "mode_int": member.mode,
                    "mode": format_file_mode(member.mode),
                    "link_target": member.linkname or None,
                    "member": member,
                }
                process_project_archive_entry(
                    analysis,
                    state,
                    entry,
                    lambda tar_member=member: archive.extractfile(tar_member),
                )

    finalize_project_archive_analysis(analysis)
    return analysis


def empty_project_archive_analysis(errors: list[str] | None = None) -> dict[str, Any]:
    return {
        "summary": {
            "total_entries_seen": 0,
            "supported_manifests_found": 0,
            "supported_manifests_parsed": 0,
            "unsupported_manifests_detected": 0,
            "total_dependencies": 0,
            "dependency_groups": [],
            "findings_count": 0,
            "truncated": False,
        },
        "supported_manifests": [],
        "unsupported_manifests": [],
        "parsed_manifests": [],
        "findings": [],
        "errors": errors or [],
    }


def build_project_archive_result(
    file_id: str,
    path: Path,
    original_filename: str,
    archive_type: str,
    analysis: dict[str, Any],
) -> dict[str, Any]:
    summary = as_dict(analysis.get("summary"))
    findings = analysis.get("findings") if isinstance(analysis.get("findings"), list) else []
    summary["findings_count"] = len(findings)
    return {
        "file_id": file_id,
        "analyzer": "project_archive_basic",
        "archive_type": archive_type,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "hashes": calculate_hashes(path),
        "file_identification": {
            "size_bytes": path.stat().st_size,
            "original_filename": original_filename,
        },
        "limits": {
            "max_manifests": PROJECT_ARCHIVE_MAX_MANIFESTS,
            "max_manifest_bytes": PROJECT_ARCHIVE_MAX_MANIFEST_BYTES,
            "max_total_manifest_bytes": PROJECT_ARCHIVE_MAX_TOTAL_MANIFEST_BYTES,
            "max_archive_entries": PROJECT_ARCHIVE_MAX_ARCHIVE_ENTRIES,
            "max_zip_central_directory_bytes": ARCHIVE_MAX_ZIP_CENTRAL_DIRECTORY_BYTES,
        },
        "summary": summary,
        "supported_manifests": analysis.get("supported_manifests", []),
        "unsupported_manifests": analysis.get("unsupported_manifests", []),
        "parsed_manifests": analysis.get("parsed_manifests", []),
        "findings": findings,
        "errors": analysis.get("errors", []),
    }


def should_stop_project_archive_scan(index: int, analysis: dict[str, Any]) -> bool:
    summary = as_dict(analysis["summary"])
    if index > PROJECT_ARCHIVE_MAX_ARCHIVE_ENTRIES:
        summary["truncated"] = True
        add_project_finding(
            analysis,
            "project_archive_entry_limit_reached",
            "Archive entry scan limit reached",
            "medium",
            "Inspectra stopped scanning archive metadata after the configured entry limit.",
            f"Processed {PROJECT_ARCHIVE_MAX_ARCHIVE_ENTRIES} entries.",
            "Review the archive with stricter limits or split it before deeper inspection.",
        )
        return True
    summary["total_entries_seen"] = index
    return False


def add_project_zip_preflight_finding(
    analysis: dict[str, Any],
    preflight: ZipMetadataPreflight,
    reason: str,
) -> None:
    summary = as_dict(analysis["summary"])
    summary["truncated"] = True
    finding = zip_preflight_finding(reason, preflight, PROJECT_ARCHIVE_MAX_ARCHIVE_ENTRIES)
    scoped = dict(finding)
    scoped["id"] = f"project_{scoped['id']}"
    analysis["findings"].append(scoped)


def process_project_archive_entry(
    analysis: dict[str, Any],
    state: dict[str, int],
    entry: dict[str, Any],
    open_entry,
) -> None:
    path = str(entry["path"])
    manifest_name = detect_archive_manifest(path)
    if manifest_name is None:
        return

    manifest_type = supported_project_manifest_type(path)
    entry_type = str(entry["type"])
    size_bytes = int(entry.get("size") or 0)
    flags, depth = archive_entry_flags(path, entry.get("mode_int"))
    manifest_record = {
        "path": path,
        "manifest_name": manifest_name,
        "manifest_type": manifest_type or manifest_name,
        "size_bytes": size_bytes,
        "entry_type": entry_type,
        "mode": entry.get("mode"),
        "depth": depth,
        "flags": flags,
    }
    if entry.get("link_target"):
        manifest_record["link_target"] = entry["link_target"]

    if manifest_type is None:
        manifest_record["reason"] = "detected_but_not_parsed_in_this_phase"
        analysis["unsupported_manifests"].append(manifest_record)
        analysis["summary"]["unsupported_manifests_detected"] += 1
        return

    analysis["summary"]["supported_manifests_found"] += 1
    state["parseable_manifests_seen"] += 1

    skip_reason = project_manifest_skip_reason(manifest_record, state)
    if skip_reason:
        manifest_record["status"] = "skipped"
        manifest_record["reason"] = skip_reason
        analysis["supported_manifests"].append(manifest_record)
        add_project_manifest_skip_finding(analysis, path, skip_reason, size_bytes)
        return

    try:
        stream = open_entry()
        if stream is None:
            raise ValueError("entry could not be opened as a regular file")
        with stream:
            raw_bytes = read_limited_stream(stream, PROJECT_ARCHIVE_MAX_MANIFEST_BYTES)
    except (OSError, ValueError, zipfile.BadZipFile, tarfile.TarError) as exc:
        manifest_record["status"] = "skipped"
        manifest_record["reason"] = "manifest_read_error"
        analysis["supported_manifests"].append(manifest_record)
        add_project_finding(
            analysis,
            "project_archive_manifest_read_error",
            "Manifest could not be read safely",
            "low",
            "A supported manifest entry could not be read from the archive within Inspectra limits.",
            f"{path}: {exc}",
            "Review this manifest manually in a constrained environment if it is expected.",
        )
        return

    state["total_manifest_bytes"] += len(raw_bytes)
    try:
        raw_text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        manifest_record["status"] = "skipped"
        manifest_record["reason"] = "manifest_utf8_decode_error"
        analysis["supported_manifests"].append(manifest_record)
        add_project_finding(
            analysis,
            "project_archive_manifest_decode_error",
            "Manifest is not valid UTF-8 text",
            "low",
            "A supported manifest entry could not be decoded as UTF-8 text.",
            f"{path}: {exc}",
            "Review this file manually before treating it as a dependency manifest.",
        )
        return

    parsed, parser_findings, parser_errors = parse_manifest_text_by_type(manifest_type, raw_text)
    dependency_groups = parsed.get("dependencies", {})
    dependency_count = sum(len(items) for items in dependency_groups.values() if isinstance(items, list))
    parsed_record = {
        "path": path,
        "manifest_type": manifest_type,
        "size_bytes": size_bytes,
        "parsed": parsed,
        "summary": {
            "total_dependencies": dependency_count,
            "dependency_groups": list(dependency_groups),
            "informational_findings_count": len(parser_findings),
        },
        "findings": parser_findings,
        "errors": parser_errors,
    }
    manifest_record["status"] = "parsed"
    analysis["supported_manifests"].append(manifest_record)
    analysis["parsed_manifests"].append(parsed_record)
    analysis["summary"]["supported_manifests_parsed"] += 1
    analysis["summary"]["total_dependencies"] += dependency_count
    add_dependency_groups(analysis["summary"], dependency_groups)

    for finding in parser_findings:
        analysis["findings"].append(scope_manifest_parser_finding(path, finding))
    if parser_errors:
        add_project_finding(
            analysis,
            "project_archive_manifest_parse_error",
            "Manifest parser reported errors",
            "low",
            "A supported manifest was read but could not be fully parsed.",
            f"{path}: {'; '.join(parser_errors)}",
            "Review the manifest syntax manually before relying on the extracted dependency data.",
        )


def project_manifest_skip_reason(manifest_record: dict[str, Any], state: dict[str, int]) -> str | None:
    flags = as_dict(manifest_record.get("flags"))
    path = str(manifest_record["path"])
    size_bytes = int(manifest_record.get("size_bytes") or 0)
    if flags.get("path_traversal"):
        return "path_traversal"
    if flags.get("absolute_path") or flags.get("windows_absolute_path"):
        return "absolute_path"
    if manifest_record.get("entry_type") != "file":
        return f"not_regular_file:{manifest_record.get('entry_type')}"
    if len(path) > ARCHIVE_MAX_ENTRY_NAME_LENGTH:
        return "entry_name_too_long"
    if size_bytes > PROJECT_ARCHIVE_MAX_MANIFEST_BYTES:
        return "manifest_too_large"
    if state["parseable_manifests_seen"] > PROJECT_ARCHIVE_MAX_MANIFESTS:
        return "too_many_supported_manifests"
    if state["total_manifest_bytes"] + size_bytes > PROJECT_ARCHIVE_MAX_TOTAL_MANIFEST_BYTES:
        return "total_manifest_bytes_limit"
    return None


def add_project_manifest_skip_finding(analysis: dict[str, Any], path: str, reason: str, size_bytes: int) -> None:
    finding_id = f"project_archive_{reason}"
    if reason == "manifest_too_large":
        title = "Manifest omitted because it exceeds the size limit"
        level = "medium"
        evidence = f"{path}: {size_bytes} bytes"
    elif reason == "too_many_supported_manifests":
        title = "Supported manifest limit reached"
        level = "medium"
        evidence = path
        analysis["summary"]["truncated"] = True
    elif reason == "total_manifest_bytes_limit":
        title = "Total manifest byte limit reached"
        level = "medium"
        evidence = path
        analysis["summary"]["truncated"] = True
    elif reason == "path_traversal":
        title = "Manifest path uses traversal"
        level = "medium"
        evidence = path
    elif reason == "absolute_path":
        title = "Manifest path is absolute"
        level = "medium"
        evidence = path
    elif reason == "entry_name_too_long":
        title = "Manifest entry name is unusually long"
        level = "low"
        evidence = path[:240]
    else:
        finding_id = "project_archive_manifest_not_regular_file"
        title = "Manifest omitted because it is not a regular file"
        level = "low"
        evidence = f"{path}: {reason}"

    add_project_finding(
        analysis,
        finding_id,
        title,
        level,
        "Inspectra detected a supported manifest but did not parse it because of a defensive limit or unsafe archive metadata.",
        evidence,
        "Review the archive manually in a constrained environment if this manifest is expected.",
    )


def finalize_project_archive_analysis(analysis: dict[str, Any]) -> None:
    ecosystems = {
        ecosystem
        for ecosystem in (
            project_manifest_ecosystem(item.get("manifest_type", ""))
            for item in analysis["supported_manifests"] + analysis["unsupported_manifests"]
        )
        if ecosystem
    }
    if len(ecosystems) > 1:
        add_project_finding(
            analysis,
            "project_archive_multiple_ecosystems",
            "Multiple dependency ecosystems detected",
            "info",
            "The archive contains manifests from multiple ecosystems. This is informational and may require separate review paths.",
            ", ".join(sorted(ecosystems)),
            "Review each ecosystem with the appropriate workflow before installing or running anything.",
        )
    analysis["summary"]["findings_count"] = len(analysis["findings"])


def parse_manifest_text_by_type(manifest_type: str, raw_text: str) -> tuple[dict[str, Any], list[dict[str, str]], list[str]]:
    if "\x00" in raw_text:
        return empty_manifest_parse(), [], ["Manifest contains NUL bytes and was not parsed as text."]
    if manifest_type == "package_json":
        return analyze_package_json_manifest(raw_text)
    if manifest_type == "requirements_txt":
        return analyze_requirements_manifest(raw_text)
    return analyze_pyproject_manifest(raw_text)


def supported_project_manifest_type(path: str) -> str | None:
    basename = path.replace("\\", "/").lower().rsplit("/", 1)[-1]
    return {
        "package.json": "package_json",
        "requirements.txt": "requirements_txt",
        "pyproject.toml": "pyproject_toml",
    }.get(basename)


def project_manifest_ecosystem(manifest_type: str) -> str | None:
    normalized = manifest_type.lower()
    if normalized in {"package_json", "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"}:
        return "javascript"
    if normalized in {"requirements_txt", "pyproject_toml", "requirements.txt", "pyproject.toml", "poetry.lock", "pipfile", "pipfile.lock"}:
        return "python"
    if normalized in {"go.mod", "go.sum"}:
        return "go"
    if normalized in {"cargo.toml", "cargo.lock"}:
        return "rust"
    if normalized in {"pom.xml", "build.gradle"}:
        return "jvm"
    if normalized in {"composer.json", "composer.lock"}:
        return "php"
    if normalized in {"dockerfile", "docker-compose.yml", "compose.yml"}:
        return "container"
    return None


def add_dependency_groups(summary: dict[str, Any], dependency_groups: dict[str, Any]) -> None:
    existing = set(summary.get("dependency_groups", []))
    for group in dependency_groups:
        existing.add(str(group))
    summary["dependency_groups"] = sorted(existing)


def scope_manifest_parser_finding(path: str, finding: dict[str, str]) -> dict[str, str]:
    scoped = dict(finding)
    evidence = scoped.get("evidence", "")
    scoped["evidence"] = f"{path}: {evidence}" if evidence else path
    return scoped


def read_limited_stream(stream, max_bytes: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = stream.read(min(64 * 1024, max_bytes + 1 - total))
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise ValueError(f"manifest exceeded {max_bytes} bytes")
        chunks.append(chunk)
    return b"".join(chunks)


def add_project_finding(
    analysis: dict[str, Any],
    finding_id: str,
    title: str,
    level: str,
    description: str,
    evidence: str,
    recommendation: str,
) -> None:
    analysis["findings"].append(make_finding(finding_id, title, level, description, evidence, recommendation))


def empty_archive_summary(total_compressed_bytes: int = 0) -> dict[str, Any]:
    return {
        "total_entries": 0,
        "total_uncompressed_bytes": 0,
        "total_compressed_bytes": total_compressed_bytes,
        "directories": 0,
        "files": 0,
        "symlinks": 0,
        "hardlinks": 0,
        "executables": 0,
        "nested_archives": 0,
        "sensitive_name_matches": 0,
        "path_traversal_entries": 0,
        "absolute_path_entries": 0,
        "manifest_files_detected": 0,
        "findings_count": 0,
        "truncated": False,
    }


def record_archive_entry(
    summary: dict[str, Any],
    entries_sample: list[dict[str, Any]],
    detected_manifests: list[dict[str, str]],
    findings: list[dict[str, str]],
    seen_findings: set[str],
    entry: dict[str, Any],
) -> None:
    path = str(entry["path"])
    entry_type = str(entry["type"])
    mode_int = entry.get("mode_int")
    flags, depth = archive_entry_flags(path, mode_int)
    manifest_type = detect_archive_manifest(path)

    summary["total_entries"] += 1
    summary["total_uncompressed_bytes"] += int(entry.get("size") or 0)
    compressed_size = entry.get("compressed_size")
    if isinstance(compressed_size, int):
        summary["total_compressed_bytes"] += compressed_size
    if entry_type == "directory":
        summary["directories"] += 1
    elif entry_type == "symlink":
        summary["symlinks"] += 1
    elif entry_type == "hardlink":
        summary["hardlinks"] += 1
    elif entry_type == "file":
        summary["files"] += 1

    if flags["executable"]:
        summary["executables"] += 1
    if flags["nested_archive"]:
        summary["nested_archives"] += 1
    if flags["sensitive_name"]:
        summary["sensitive_name_matches"] += 1
    if flags["path_traversal"]:
        summary["path_traversal_entries"] += 1
    if flags["absolute_path"] or flags["windows_absolute_path"]:
        summary["absolute_path_entries"] += 1
    if manifest_type:
        summary["manifest_files_detected"] += 1
        if len(detected_manifests) < ARCHIVE_MAX_LISTED_ENTRIES:
            detected_manifests.append({"path": path, "manifest_type": manifest_type})

    public_entry = {
        "path": path,
        "type": entry_type,
        "size": entry.get("size"),
        "compressed_size": compressed_size,
        "mode": entry.get("mode"),
        "depth": depth,
        "flags": flags,
    }
    if entry.get("link_target"):
        public_entry["link_target"] = entry["link_target"]
    if len(entries_sample) < ARCHIVE_MAX_LISTED_ENTRIES:
        entries_sample.append(public_entry)

    add_entry_findings(path, entry_type, flags, findings, seen_findings)
    if len(path) > ARCHIVE_MAX_ENTRY_NAME_LENGTH:
        add_archive_finding(
            findings,
            seen_findings,
            "archive_entry_name_too_long",
            "Archive entry name is unusually long",
            "low",
            "At least one archive entry name exceeds the configured review limit.",
            path[:240],
            "Review long entry names before extraction, especially in automated tooling.",
        )
    if manifest_type:
        add_archive_finding(
            findings,
            seen_findings,
            "archive_manifest_files_detected",
            "Project manifest files detected",
            "info",
            "The archive contains dependency or project manifest files. Inspectra only records their presence in this phase.",
            path,
            "Use manifest analysis on trusted, extracted files in a controlled workflow if deeper review is needed.",
        )


def add_entry_findings(
    path: str,
    entry_type: str,
    flags: dict[str, bool],
    findings: list[dict[str, str]],
    seen_findings: set[str],
) -> None:
    if flags["path_traversal"]:
        add_archive_finding(
            findings,
            seen_findings,
            "archive_path_traversal_entry",
            "Archive entry uses path traversal",
            "medium",
            "An entry contains .. path segments. This is a possible extraction risk if a tool does not normalize paths safely.",
            path,
            "Extract only with tooling that rejects traversal paths and review the archive manually.",
        )
    if flags["absolute_path"] or flags["windows_absolute_path"]:
        add_archive_finding(
            findings,
            seen_findings,
            "archive_absolute_path_entry",
            "Archive entry uses an absolute path",
            "medium",
            "An entry appears to target an absolute path. This is a possible extraction risk in unsafe workflows.",
            path,
            "Extract only with tooling that strips or rejects absolute paths.",
        )
    if entry_type == "symlink":
        add_archive_finding(
            findings,
            seen_findings,
            "archive_symlink_entry",
            "Archive contains symlinks",
            "low",
            "Symlinks can be legitimate, but they should be reviewed before extraction.",
            path,
            "Confirm symlink targets are expected before extracting the archive.",
        )
    if entry_type == "hardlink":
        add_archive_finding(
            findings,
            seen_findings,
            "archive_hardlink_entry",
            "Archive contains hardlinks",
            "low",
            "Hardlinks can affect extraction behavior and should be reviewed.",
            path,
            "Confirm hardlink targets are expected before extracting the archive.",
        )
    if flags["executable"]:
        add_archive_finding(
            findings,
            seen_findings,
            "archive_executable_entry",
            "Executable permissions detected",
            "info",
            "At least one entry has executable permission bits set. Inspectra does not execute it.",
            path,
            "Review executable files before running anything extracted from the archive.",
        )
    if flags["sensitive_name"]:
        add_archive_finding(
            findings,
            seen_findings,
            "archive_sensitive_name_entry",
            "Potentially sensitive filename detected",
            "medium",
            "An entry name resembles a secret, credential, or local configuration file.",
            path,
            "Review whether this file should be present before sharing or extracting the archive.",
        )
    if flags["nested_archive"]:
        add_archive_finding(
            findings,
            seen_findings,
            "archive_nested_archive_entry",
            "Nested archive detected",
            "low",
            "The archive contains another compressed file. Nested archives can hide additional content and increase extraction cost.",
            path,
            "Inspect nested archives separately before extraction or distribution.",
        )


def finalize_archive_summary(summary: dict[str, Any], findings: list[dict[str, str]], seen_findings: set[str]) -> None:
    total_uncompressed = int(summary["total_uncompressed_bytes"])
    total_compressed = int(summary["total_compressed_bytes"])
    if total_uncompressed > ARCHIVE_MAX_TOTAL_UNCOMPRESSED_BYTES:
        add_archive_finding(
            findings,
            seen_findings,
            "archive_uncompressed_size_limit_exceeded",
            "Archive uncompressed size exceeds configured limit",
            "medium",
            "The estimated total uncompressed size exceeds the configured passive analysis limit.",
            f"{total_uncompressed} bytes",
            "Treat this as an archive bomb indicator and inspect in a constrained environment before extraction.",
        )
    if total_compressed > 0 and total_uncompressed / total_compressed >= ARCHIVE_SUSPICIOUS_COMPRESSION_RATIO:
        add_archive_finding(
            findings,
            seen_findings,
            "archive_high_compression_ratio",
            "Archive has a high compression ratio",
            "medium",
            "The estimated uncompressed size is much larger than the compressed size. This can be legitimate but should be reviewed.",
            f"{total_uncompressed} bytes uncompressed / {total_compressed} bytes compressed",
            "Validate manually before extraction, especially in automated systems.",
        )
    summary["findings_count"] = len(findings)


def archive_entry_flags(path: str, mode: int | None) -> tuple[dict[str, bool], int]:
    normalized = path.replace("\\", "/")
    parts = [part for part in normalized.split("/") if part]
    flags = {
        "path_traversal": any(part == ".." for part in parts),
        "absolute_path": normalized.startswith("/"),
        "windows_absolute_path": bool(re.match(r"^[A-Za-z]:[\\/]", path)),
        "executable": bool(mode and mode & 0o111),
        "hidden_path": any(part.startswith(".") and part not in {".", ".."} for part in parts),
        "nested_archive": is_nested_archive_path(normalized),
        "sensitive_name": is_sensitive_archive_path(normalized),
        "manifest_file": detect_archive_manifest(normalized) is not None,
    }
    return flags, len(parts)


def tar_member_type(member: tarfile.TarInfo) -> str:
    if member.isdir():
        return "directory"
    if member.issym():
        return "symlink"
    if member.islnk():
        return "hardlink"
    if member.isfile():
        return "file"
    return "unknown"


def detect_archive_manifest(path: str) -> str | None:
    normalized = path.replace("\\", "/").lower().lstrip("/")
    basename = normalized.rsplit("/", 1)[-1]
    manifest_names = {
        "package.json",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "requirements.txt",
        "pyproject.toml",
        "poetry.lock",
        "pipfile",
        "pipfile.lock",
        "go.mod",
        "go.sum",
        "cargo.toml",
        "cargo.lock",
        "pom.xml",
        "build.gradle",
        "composer.json",
        "composer.lock",
        "dockerfile",
        "docker-compose.yml",
        "compose.yml",
    }
    if basename in manifest_names:
        return basename
    return None


def is_nested_archive_path(path: str) -> bool:
    lowered = path.lower()
    return lowered.endswith((".zip", ".tar", ".tar.gz", ".tgz", ".7z", ".rar"))


def is_sensitive_archive_path(path: str) -> bool:
    normalized = path.replace("\\", "/").lower().lstrip("/")
    parts = [part for part in normalized.split("/") if part]
    basename = parts[-1] if parts else normalized
    if basename in {".env", "id_rsa", "id_dsa", ".npmrc", ".pypirc", "kubeconfig"}:
        return True
    if basename.startswith(".env."):
        return True
    if basename.endswith((".pem", ".key", ".p12", ".pfx")):
        return True
    if any(part in {"credentials", "secrets", "kubeconfig"} for part in parts):
        return True
    return normalized.endswith(".docker/config.json")


def format_file_mode(mode: int | None) -> str | None:
    if mode is None:
        return None
    return oct(mode & 0o7777)


def add_archive_finding(
    findings: list[dict[str, str]],
    seen_findings: set[str],
    finding_id: str,
    title: str,
    level: str,
    description: str,
    evidence: str,
    recommendation: str,
) -> None:
    if finding_id in seen_findings:
        return
    findings.append(make_finding(finding_id, title, level, description, evidence, recommendation))
    seen_findings.add(finding_id)


def make_finding(
    finding_id: str,
    title: str,
    level: str,
    description: str,
    evidence: str,
    recommendation: str,
) -> dict[str, str]:
    return {
        "id": finding_id,
        "title": title,
        "level": level,
        "description": description,
        "evidence": evidence,
        "recommendation": recommendation,
    }


def parse_toml_document(raw_text: str) -> tuple[dict[str, Any] | None, list[str]]:
    if tomllib is not None:
        try:
            return tomllib.loads(raw_text), []
        except tomllib.TOMLDecodeError as exc:
            return None, [f"pyproject.toml parse error: {exc}"]
    try:
        return parse_simple_toml(raw_text), []
    except ValueError as exc:
        return None, [f"pyproject.toml parse error: {exc}"]


def parse_simple_toml(raw_text: str) -> dict[str, Any]:
    root: dict[str, Any] = {}
    current: dict[str, Any] = root
    pending_array: tuple[dict[str, Any], str, list[str]] | None = None

    for raw_line in raw_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        if pending_array is not None:
            container, key, values = pending_array
            if line.startswith("]"):
                container[key] = values
                pending_array = None
                continue
            values.extend(parse_array_items(line.rstrip(",")))
            if line.endswith("]"):
                container[key] = values
                pending_array = None
            continue

        if line.startswith("[") and line.endswith("]"):
            section = line.strip("[]").strip()
            current = root
            for part in section.split("."):
                current = current.setdefault(part, {})
            continue

        if "=" not in line:
            continue
        key, value = [part.strip() for part in line.split("=", 1)]
        if value == "[":
            pending_array = (current, key, [])
            continue
        current[key] = parse_toml_value(value)

    if pending_array is not None:
        raise ValueError("unterminated array")
    return root


def parse_toml_value(value: str) -> Any:
    stripped = value.strip().rstrip(",")
    if stripped.startswith('"') and stripped.endswith('"'):
        return stripped[1:-1]
    if stripped.startswith("'") and stripped.endswith("'"):
        return stripped[1:-1]
    if stripped.startswith("[") and stripped.endswith("]"):
        return parse_array_items(stripped[1:-1])
    if stripped.startswith("{") and stripped.endswith("}"):
        return parse_inline_table(stripped[1:-1])
    return stripped


def parse_array_items(value: str) -> list[str]:
    items: list[str] = []
    for match in re.finditer(r'"([^"]*)"|\'([^\']*)\'', value):
        items.append(match.group(1) if match.group(1) is not None else match.group(2))
    return items


def parse_inline_table(value: str) -> dict[str, str]:
    table: dict[str, str] = {}
    for item in value.split(","):
        if "=" not in item:
            continue
        key, raw_value = [part.strip() for part in item.split("=", 1)]
        parsed = parse_toml_value(raw_value)
        table[key] = stringify_manifest_value(parsed)
    return table


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def stringify_manifest_value(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)):
        return str(value)
    if isinstance(value, dict):
        return ", ".join(f"{key} = {stringify_manifest_value(item)}" for key, item in value.items())
    if isinstance(value, list):
        return ", ".join(stringify_manifest_value(item) for item in value)
    return str(value)


def run_command(args: list[str]) -> dict[str, Any]:
    started = time.perf_counter()
    try:
        completed = subprocess.run(
            args,
            capture_output=True,
            check=False,
            text=True,
            timeout=COMMAND_TIMEOUT_SECONDS,
        )
        duration_ms = round((time.perf_counter() - started) * 1000, 2)
        return {
            "command": args[0],
            "args": args[1:-1],
            "exit_code": completed.returncode,
            "duration_ms": duration_ms,
            "stdout": truncate(completed.stdout),
            "stderr": truncate(completed.stderr),
            "timed_out": False,
            "timeout_seconds": COMMAND_TIMEOUT_SECONDS,
        }
    except subprocess.TimeoutExpired as exc:
        duration_ms = round((time.perf_counter() - started) * 1000, 2)
        return {
            "command": args[0],
            "args": args[1:-1],
            "exit_code": None,
            "duration_ms": duration_ms,
            "stdout": truncate(to_text(exc.stdout)),
            "stderr": truncate(to_text(exc.stderr)),
            "timed_out": True,
            "timeout_seconds": COMMAND_TIMEOUT_SECONDS,
        }
    except FileNotFoundError as exc:
        duration_ms = round((time.perf_counter() - started) * 1000, 2)
        return {
            "command": args[0],
            "args": args[1:-1],
            "exit_code": None,
            "duration_ms": duration_ms,
            "stdout": "",
            "stderr": str(exc),
            "timed_out": False,
            "timeout_seconds": COMMAND_TIMEOUT_SECONDS,
        }


def to_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def truncate(value: str) -> str:
    if len(value) <= MAX_OUTPUT_CHARS:
        return value
    return value[:MAX_OUTPUT_CHARS] + "\n[output truncated]"


def calculate_hashes(path: Path) -> dict[str, str]:
    sha256 = hashlib.sha256()
    sha512 = hashlib.sha512()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            sha256.update(chunk)
            sha512.update(chunk)
    return {"sha256": sha256.hexdigest(), "sha512": sha512.hexdigest()}


def parse_key_value_output(output: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for line in output.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        parsed[key.strip()] = value.strip()
    return parsed


def parse_exiftool_json(output: str) -> dict[str, Any]:
    if not output.strip():
        return {}
    try:
        payload = json.loads(output)
    except json.JSONDecodeError:
        return {"_parse_error": "exiftool output was not valid JSON"}
    if isinstance(payload, list) and payload:
        return payload[0]
    if isinstance(payload, dict):
        return payload
    return {}


def build_passive_warnings(pdfinfo: dict[str, str], tool_outputs: dict[str, dict[str, Any]], mime: dict[str, Any]) -> list[str]:
    warnings: list[str] = []
    mime_type = mime["stdout"].strip()
    if mime_type and mime_type != "application/pdf":
        warnings.append(f"Unexpected MIME type: {mime_type}")
    for tool_name, output in tool_outputs.items():
        if output["timed_out"]:
            warnings.append(f"{tool_name} timed out.")
    qpdf = tool_outputs["qpdf"]
    if not qpdf["timed_out"] and qpdf["exit_code"] != 0:
        warnings.append("qpdf reported validation issues.")
    if pdfinfo.get("Encrypted", "").lower().startswith("yes"):
        warnings.append("PDF is encrypted; metadata and validation may be incomplete.")
    return warnings


def build_image_warnings(tool_outputs: dict[str, dict[str, Any]], mime: dict[str, Any]) -> list[str]:
    warnings: list[str] = []
    mime_type = mime["stdout"].strip()
    if mime_type and mime_type not in {"image/jpeg", "image/png", "image/webp"}:
        warnings.append(f"Unexpected MIME type: {mime_type}")
    for tool_name, output in tool_outputs.items():
        if output["timed_out"]:
            warnings.append(f"{tool_name} timed out.")
        elif output["exit_code"] != 0:
            warnings.append(f"{tool_name} reported issues.")
    return warnings


def build_privacy_indicators(metadata: dict[str, Any]) -> dict[str, Any]:
    present_fields = set(metadata)

    gps_fields = sorted(field for field in present_fields if field.startswith("GPS"))
    author_fields = sorted(field for field in present_fields if field in {"Artist", "Author", "By-line", "Creator", "OwnerName"})
    serial_fields = sorted(field for field in present_fields if "Serial" in field)
    software_fields = sorted(
        field for field in present_fields if field in {"CreatorTool", "ProcessingSoftware", "Software"} or "Software" in field
    )
    device_fields = sorted(field for field in present_fields if field in {"Make", "Model", "LensModel", "DeviceManufacturer", "DeviceModel"})

    return {
        "gps_present": bool(gps_fields),
        "author_or_creator_present": bool(author_fields),
        "serial_number_present": bool(serial_fields),
        "software_or_toolchain_present": bool(software_fields),
        "device_info_present": bool(device_fields),
        "fields": {
            "gps": gps_fields,
            "author_or_creator": author_fields,
            "serial_number": serial_fields,
            "software_or_toolchain": software_fields,
            "device": device_fields,
        },
    }
