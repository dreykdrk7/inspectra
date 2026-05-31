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
from typing import Any, Callable
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit
from uuid import uuid4
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
    max_files: int | None = None
    max_file_bytes: int | None = None
    max_total_bytes: int | None = None


class WebBasicAnalysisRequest(BaseModel):
    url: str
    allow_private_targets: bool | None = None
    timeout_seconds: float | None = None
    max_response_bytes: int | None = None
    max_redirects: int | None = None
    allowed_ports: list[int] | None = None


class DomainBasicAnalysisRequest(BaseModel):
    domain: str
    timeout_seconds: float | None = None


class SubdomainInventoryAnalysisRequest(BaseModel):
    root_domain: str
    subdomains: list[str]
    timeout_seconds: float | None = None
    max_candidates: int | None = None
    wildcard_checks: int | None = None
    global_deadline_seconds: float | None = None


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


def non_negative_int_from_env(name: str, default: int) -> int:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    try:
        value = int(raw_value)
    except ValueError as exc:
        raise ValueError(f"{name} must be a non-negative integer.") from exc
    if value < 0:
        raise ValueError(f"{name} must be zero or greater.")
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


def ports_from_env(name: str, default: tuple[int, ...]) -> tuple[int, ...]:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    ports: list[int] = []
    for item in raw_value.split(","):
        value = item.strip()
        if not value:
            continue
        try:
            port = int(value)
        except ValueError as exc:
            raise ValueError(f"{name} must be a comma-separated list of TCP ports.") from exc
        if port < 1 or port > 65535:
            raise ValueError(f"{name} ports must be between 1 and 65535.")
        ports.append(port)
    if not ports:
        raise ValueError(f"{name} must include at least one TCP port.")
    return tuple(sorted(set(ports)))


def parse_allowed_ports(values: list[int]) -> tuple[int, ...]:
    ports: list[int] = []
    for value in values:
        if value < 1 or value > 65535:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Allowed web ports must be between 1 and 65535.")
        ports.append(int(value))
    if not ports:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="At least one web port must be allowed.")
    return tuple(sorted(set(ports)))


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
DJANGO_CONFIG_MAX_FILES = positive_int_from_env("INSPECTRA_DJANGO_CONFIG_MAX_FILES", 100)
DJANGO_CONFIG_MAX_FILE_BYTES = positive_int_from_env("INSPECTRA_DJANGO_CONFIG_MAX_FILE_BYTES", 524_288)
DJANGO_CONFIG_MAX_TOTAL_BYTES = positive_int_from_env("INSPECTRA_DJANGO_CONFIG_MAX_TOTAL_BYTES", 2_097_152)
DOCKER_CONFIG_MAX_FILES = positive_int_from_env("INSPECTRA_DOCKER_CONFIG_MAX_FILES", 100)
DOCKER_CONFIG_MAX_FILE_BYTES = positive_int_from_env("INSPECTRA_DOCKER_CONFIG_MAX_FILE_BYTES", 524_288)
DOCKER_CONFIG_MAX_TOTAL_BYTES = positive_int_from_env("INSPECTRA_DOCKER_CONFIG_MAX_TOTAL_BYTES", 2_097_152)
SECRETS_REVIEW_MAX_FILES = positive_int_from_env("INSPECTRA_SECRETS_REVIEW_MAX_FILES", 100)
SECRETS_REVIEW_MAX_FILE_BYTES = positive_int_from_env("INSPECTRA_SECRETS_REVIEW_MAX_FILE_BYTES", 524_288)
SECRETS_REVIEW_MAX_TOTAL_BYTES = positive_int_from_env("INSPECTRA_SECRETS_REVIEW_MAX_TOTAL_BYTES", 2_097_152)
WEB_ALLOW_PRIVATE_TARGETS = bool_from_env("INSPECTRA_WEB_ALLOW_PRIVATE_TARGETS", False)
WEB_TIMEOUT_SECONDS = positive_float_from_env("INSPECTRA_WEB_TIMEOUT_SECONDS", 10.0)
WEB_MAX_RESPONSE_BYTES = positive_int_from_env("INSPECTRA_WEB_MAX_RESPONSE_BYTES", 1_048_576)
WEB_MAX_REDIRECTS = positive_int_from_env("INSPECTRA_WEB_MAX_REDIRECTS", 5)
WEB_ALLOWED_PORTS = ports_from_env("INSPECTRA_WEB_ALLOWED_PORTS", (80, 443))
DOMAIN_DNS_TIMEOUT_SECONDS = positive_float_from_env("INSPECTRA_DOMAIN_DNS_TIMEOUT_SECONDS", 5.0)
SUBDOMAIN_MAX_CANDIDATES = positive_int_from_env("INSPECTRA_SUBDOMAIN_MAX_CANDIDATES", 100)
SUBDOMAIN_WILDCARD_CHECKS = non_negative_int_from_env("INSPECTRA_SUBDOMAIN_WILDCARD_CHECKS", 2)
SUBDOMAIN_GLOBAL_DEADLINE_SECONDS = positive_float_from_env("INSPECTRA_SUBDOMAIN_GLOBAL_DEADLINE_SECONDS", 30.0)
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
LOCALHOST_HOSTS = {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"}
SENSITIVE_RESPONSE_HEADERS = {"set-cookie", "authorization", "proxy-authorization", "x-api-key", "x-auth-token"}
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
DOMAIN_PATTERN = re.compile(r"^[a-z0-9.-]+$")
BLOCKED_DOMAIN_SUFFIXES = (".local", ".localhost", ".internal", ".test", ".invalid")
BLOCKED_DOMAIN_NAMES = {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"}
DNS_RECORD_TYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15, "TXT": 16, "AAAA": 28, "CAA": 257}
DNS_TYPE_NAMES = {value: key for key, value in DNS_RECORD_TYPES.items()}
DNS_MAX_RECORDS_PER_TYPE = 30
DNS_MAX_STRING_LENGTH = 512
SENSITIVE_TEXT_FRAGMENTS = ("token", "secret", "password", "passwd", "api_key", "apikey")
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


@app.post("/analyze/django-config")
async def analyze_django_config(request: ArchiveAnalysisRequest) -> dict[str, Any]:
    archive_path = resolve_data_path(request.relative_path)
    if not archive_path.exists() or not archive_path.is_file():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Archive not found.")

    original_filename = Path(request.original_filename or archive_path.name).name
    limits = django_config_limits(request)
    archive_type = detect_archive_type(archive_path, original_filename)
    if archive_type == "unknown":
        return build_django_config_result(
            request.file_id,
            archive_path,
            original_filename,
            archive_type,
            empty_django_config_analysis(
                errors=["Unsupported or corrupt archive. Inspectra did not extract, import, install, or execute any content."]
            ),
            **limits,
        )

    try:
        analysis = analyze_django_config_archive(archive_path, archive_type, **limits)
    except (OSError, tarfile.TarError, zipfile.BadZipFile) as exc:
        analysis = empty_django_config_analysis(errors=[f"Archive could not be parsed safely: {exc}"])

    return build_django_config_result(request.file_id, archive_path, original_filename, archive_type, analysis, **limits)


@app.post("/analyze/docker-config")
async def analyze_docker_config(request: ArchiveAnalysisRequest) -> dict[str, Any]:
    archive_path = resolve_data_path(request.relative_path)
    if not archive_path.exists() or not archive_path.is_file():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Archive not found.")

    original_filename = Path(request.original_filename or archive_path.name).name
    limits = docker_config_limits(request)
    archive_type = detect_archive_type(archive_path, original_filename)
    if archive_type == "unknown":
        return build_docker_config_result(
            request.file_id,
            archive_path,
            original_filename,
            archive_type,
            empty_docker_config_analysis(
                errors=["Unsupported or corrupt archive. Inspectra did not extract, build, install, or execute any content."]
            ),
            **limits,
        )

    try:
        analysis = analyze_docker_config_archive(archive_path, archive_type, **limits)
    except (OSError, tarfile.TarError, zipfile.BadZipFile) as exc:
        analysis = empty_docker_config_analysis(errors=[f"Archive could not be parsed safely: {exc}"])

    return build_docker_config_result(request.file_id, archive_path, original_filename, archive_type, analysis, **limits)


@app.post("/analyze/secrets-review")
async def analyze_secrets_review(request: ArchiveAnalysisRequest) -> dict[str, Any]:
    archive_path = resolve_data_path(request.relative_path)
    if not archive_path.exists() or not archive_path.is_file():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Archive not found.")

    original_filename = Path(request.original_filename or archive_path.name).name
    limits = secrets_review_limits(request)
    archive_type = detect_archive_type(archive_path, original_filename)
    if archive_type == "unknown":
        return build_secrets_review_result(
            request.file_id,
            archive_path,
            original_filename,
            archive_type,
            empty_secrets_review_analysis(
                errors=["Unsupported or corrupt archive. Inspectra did not extract, validate secrets, install, or execute any content."]
            ),
            **limits,
        )

    try:
        analysis = analyze_secrets_review_archive(archive_path, archive_type, **limits)
    except (OSError, tarfile.TarError, zipfile.BadZipFile) as exc:
        analysis = empty_secrets_review_analysis(errors=[f"Archive could not be parsed safely: {exc}"])

    return build_secrets_review_result(request.file_id, archive_path, original_filename, archive_type, analysis, **limits)


@app.post("/analyze/web-basic")
async def analyze_web_basic(request: WebBasicAnalysisRequest) -> dict[str, Any]:
    allow_private = WEB_ALLOW_PRIVATE_TARGETS if request.allow_private_targets is None else request.allow_private_targets
    timeout_seconds = request.timeout_seconds or WEB_TIMEOUT_SECONDS
    max_response_bytes = request.max_response_bytes or WEB_MAX_RESPONSE_BYTES
    max_redirects = request.max_redirects if request.max_redirects is not None else WEB_MAX_REDIRECTS
    allowed_ports = parse_allowed_ports(request.allowed_ports) if request.allowed_ports is not None else WEB_ALLOWED_PORTS

    if timeout_seconds <= 0 or max_response_bytes <= 0 or max_redirects < 0:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Web analysis limits must be positive.")

    try:
        return analyze_web_basic_target(
            request.url,
            allow_private_targets=allow_private,
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
            max_redirects=max_redirects,
            allowed_ports=allowed_ports,
        )
    except HTTPException:
        raise
    except (OSError, ssl.SSLError, http.client.HTTPException, UnicodeError) as exc:
        normalized_url = normalize_web_url(request.url)
        error_message = redact_text_urls(f"Web analysis failed safely: {exc.__class__.__name__}: {exc}")
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
            allowed_ports=allowed_ports,
        )


@app.post("/analyze/domain-basic")
async def analyze_domain_basic(request: DomainBasicAnalysisRequest) -> dict[str, Any]:
    timeout_seconds = request.timeout_seconds or DOMAIN_DNS_TIMEOUT_SECONDS
    if timeout_seconds <= 0:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Domain DNS timeout must be positive.")
    normalized_domain = normalize_domain(request.domain)
    return analyze_domain_basic_target(normalized_domain, timeout_seconds=timeout_seconds)


@app.post("/analyze/subdomains-basic")
async def analyze_subdomains_basic(request: SubdomainInventoryAnalysisRequest) -> dict[str, Any]:
    timeout_seconds = DOMAIN_DNS_TIMEOUT_SECONDS if request.timeout_seconds is None else request.timeout_seconds
    if timeout_seconds <= 0:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Domain DNS timeout must be positive.")
    max_candidates = SUBDOMAIN_MAX_CANDIDATES if request.max_candidates is None else request.max_candidates
    wildcard_checks = SUBDOMAIN_WILDCARD_CHECKS if request.wildcard_checks is None else request.wildcard_checks
    global_deadline_seconds = (
        SUBDOMAIN_GLOBAL_DEADLINE_SECONDS
        if request.global_deadline_seconds is None
        else request.global_deadline_seconds
    )
    if max_candidates <= 0:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Subdomain candidate limit must be positive.")
    if wildcard_checks < 0:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Wildcard check count must not be negative.")
    if global_deadline_seconds <= 0:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Subdomain global deadline must be positive.")
    if len(request.subdomains) > max_candidates:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Too many subdomain candidates. Maximum allowed is {max_candidates}.",
        )
    normalized_root = normalize_domain(request.root_domain)
    return analyze_subdomains_basic_target(
        normalized_root,
        request.subdomains,
        timeout_seconds=timeout_seconds,
        max_candidates=max_candidates,
        wildcard_checks=wildcard_checks,
        global_deadline_seconds=global_deadline_seconds,
    )


def analyze_web_basic_target(
    raw_url: str,
    *,
    allow_private_targets: bool,
    timeout_seconds: float,
    max_response_bytes: int,
    max_redirects: int,
    allowed_ports: tuple[int, ...],
) -> dict[str, Any]:
    original_url = raw_url
    normalized_url = normalize_web_url(raw_url)
    current_url = normalized_url
    redirects: list[dict[str, Any]] = []
    findings: list[dict[str, str]] = []
    errors: list[str] = []
    http_result: dict[str, Any] = {}
    seen_urls = {current_url}

    for _ in range(max_redirects + 1):
        http_result = fetch_http_once(
            current_url,
            allow_private_targets=allow_private_targets,
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
            allowed_ports=allowed_ports,
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
        validate_web_url_allowed(next_url, allow_private_targets=allow_private_targets, allowed_ports=allowed_ports)
        if next_url in seen_urls:
            errors.append("Redirect loop detected before a final response was reached.")
            findings.append(
                make_finding(
                    "web_redirect_loop_detected",
                    "Redirect loop detected",
                    "low",
                    "Inspectra stopped following redirects after observing a repeated target URL.",
                    f"{redact_url_query(current_url)} -> {redact_url_query(next_url)}",
                    "Review the redirect chain manually if this target is expected.",
                )
            )
            break
        if urlsplit(next_url).hostname != urlsplit(current_url).hostname:
            findings.append(
                make_finding(
                    "web_cross_host_redirect",
                    "Redirect points to a different host",
                    "info",
                    "The response redirects to a different host. This can be expected, but should be understood for authorized assessments.",
                    f"{redact_url_query(current_url)} -> {redact_url_query(next_url)}",
                    "Confirm the redirect destination is in scope before deeper testing.",
                )
            )
        redirects.append({"from_url": redact_url_query(current_url), "to_url": redact_url_query(next_url), "status_code": status_code})
        current_url = next_url
        seen_urls.add(current_url)

    final_url = current_url
    tls = inspect_tls(final_url, allow_private_targets=allow_private_targets, timeout_seconds=timeout_seconds, allowed_ports=allowed_ports)
    robots_txt = fetch_robots_txt(final_url, allow_private_targets, timeout_seconds, max_response_bytes, allowed_ports)
    security_txt = fetch_security_txt(final_url, allow_private_targets, timeout_seconds, max_response_bytes, allowed_ports)
    security_headers = evaluate_security_headers(as_dict(http_result.get("response_headers")))
    cookies = parse_response_cookies(http_result.get("set_cookie_headers", []))
    findings.extend(
        build_web_findings(
            redact_url_query(final_url),
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
        allowed_ports=allowed_ports,
    )


def fetch_http_once(
    raw_url: str,
    *,
    allow_private_targets: bool,
    timeout_seconds: float,
    max_response_bytes: int,
    allowed_ports: tuple[int, ...],
) -> dict[str, Any]:
    url = normalize_web_url(raw_url)
    validate_web_url_allowed(url, allow_private_targets=allow_private_targets, allowed_ports=allowed_ports)
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

    public_headers = public_header_mapping(headers, base_url=url)
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


def validate_web_url_allowed(raw_url: str, *, allow_private_targets: bool, allowed_ports: tuple[int, ...]) -> None:
    parsed = urlsplit(normalize_web_url(raw_url))
    host = parsed.hostname or ""
    if host.lower().rstrip(".") in METADATA_HOSTS:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cloud metadata targets are not allowed.")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if port not in allowed_ports:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Target port {port} is not allowed for web audits.")
    if host.lower().rstrip(".") in LOCALHOST_HOSTS and not allow_private_targets:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Target resolves to a blocked address range: loopback address.")
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
    if address.is_multicast:
        return "multicast address"
    if not allow_private_targets and address.is_loopback:
        return "loopback address"
    if not allow_private_targets and address.is_private:
        return "private address"
    if address.is_reserved and not (allow_private_targets and (address.is_loopback or address.is_private)):
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


def public_header_mapping(headers: list[tuple[str, str]], base_url: str | None = None) -> dict[str, Any]:
    mapped: dict[str, Any] = {}
    for name, value in headers:
        canonical = canonical_header_name(name)
        lowered = name.lower()
        if lowered in SENSITIVE_RESPONSE_HEADERS:
            public_value = "[redacted]"
        elif lowered == "location" and base_url:
            public_value = redact_url_query(urljoin(base_url, value))
        else:
            public_value = redact_text_urls(value)
        existing = mapped.get(canonical)
        if existing is None:
            mapped[canonical] = public_value
        elif isinstance(existing, list):
            existing.append(public_value)
        else:
            mapped[canonical] = [existing, public_value]
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
            parsed.append({"name": "unparsed", "parse_error": True, "value_redacted": True})
            continue
        for morsel in cookie.values():
            parsed.append(
                {
                    "name": morsel.key,
                    "value_redacted": True,
                    "value_length": len(morsel.value),
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


def inspect_tls(raw_url: str, *, allow_private_targets: bool, timeout_seconds: float, allowed_ports: tuple[int, ...]) -> dict[str, Any]:
    parsed = urlsplit(normalize_web_url(raw_url))
    if parsed.scheme != "https":
        return {"present": False, "errors": []}
    validate_web_url_allowed(raw_url, allow_private_targets=allow_private_targets, allowed_ports=allowed_ports)
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
        return {"present": True, "errors": [redact_text_urls(f"TLS inspection failed: {exc.__class__.__name__}: {exc}")]}


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


def fetch_robots_txt(
    base_url: str,
    allow_private_targets: bool,
    timeout_seconds: float,
    max_response_bytes: int,
    allowed_ports: tuple[int, ...],
) -> dict[str, Any]:
    url = base_path_url(base_url, "/robots.txt")
    return fetch_text_resource(url, allow_private_targets, timeout_seconds, min(max_response_bytes, 64 * 1024), allowed_ports, resource_type="robots")


def fetch_security_txt(
    base_url: str,
    allow_private_targets: bool,
    timeout_seconds: float,
    max_response_bytes: int,
    allowed_ports: tuple[int, ...],
) -> dict[str, Any]:
    candidates = ["/.well-known/security.txt", "/security.txt"]
    results = [
        fetch_text_resource(
            base_path_url(base_url, path),
            allow_private_targets,
            timeout_seconds,
            min(max_response_bytes, 64 * 1024),
            allowed_ports,
            resource_type="security",
        )
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
    allowed_ports: tuple[int, ...],
    *,
    resource_type: str,
) -> dict[str, Any]:
    try:
        response = fetch_http_once(
            url,
            allow_private_targets=allow_private_targets,
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
            allowed_ports=allowed_ports,
        )
    except (HTTPException, OSError, ssl.SSLError, http.client.HTTPException) as exc:
        return {"checked": True, "url": redact_url_query(url), "present": False, "errors": [redact_text_urls(str(exc))]}
    status_code = int(response.get("status_code") or 0)
    present = status_code == 200
    # fetch_http_once intentionally does not retain body in the public HTTP result; fetch again with a small helper here.
    text = fetch_body_text(url, allow_private_targets, timeout_seconds, max_response_bytes, allowed_ports) if present else ""
    summary: dict[str, Any] = {
        "checked": True,
        "url": redact_url_query(url),
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


def fetch_body_text(
    url: str,
    allow_private_targets: bool,
    timeout_seconds: float,
    max_response_bytes: int,
    allowed_ports: tuple[int, ...],
) -> str:
    validate_web_url_allowed(url, allow_private_targets=allow_private_targets, allowed_ports=allowed_ports)
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
    allowed_ports: tuple[int, ...] | None = None,
) -> dict[str, Any]:
    parsed = urlsplit(final_url)
    headers = as_dict(http_result.get("response_headers"))
    security_headers = security_headers or evaluate_security_headers(headers)
    cookies = cookies or []
    query_redaction = combined_query_redaction_summary([original_url, normalized_url, final_url])
    return {
        "analyzer": "web_basic",
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "target": {
            "original_url": redact_url_query(original_url),
            "normalized_url": redact_url_query(normalized_url),
            "final_url": redact_url_query(final_url),
            "scheme": parsed.scheme,
            "host": parsed.hostname,
            "port": parsed.port or (443 if parsed.scheme == "https" else 80),
            "allowed_ports": list(allowed_ports or ()),
            **query_redaction,
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


def combined_query_redaction_summary(urls: list[str]) -> dict[str, object]:
    query_present = False
    redacted_names: list[str] = []
    for url in urls:
        summary = query_redaction_summary(url)
        query_present = query_present or bool(summary["query_string_present"])
        redacted_names.extend(str(name) for name in summary["redacted_query_params"])
    names = sorted(set(redacted_names), key=str.lower)
    return {
        "query_string_present": query_present,
        "query_params_redacted": bool(names),
        "redacted_query_params": names,
    }


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

    for label in ascii_domain.split("."):
        if not label or len(label) > 63:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Domain label length is invalid.")
        if label.startswith("-") or label.endswith("-"):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Domain labels must not start or end with hyphen.")
    return ascii_domain


def analyze_domain_basic_target(domain: str, *, timeout_seconds: float) -> dict[str, Any]:
    checked_at = datetime.now(timezone.utc).isoformat()
    dns: dict[str, Any] = {}
    errors: list[str] = []
    for record_type in ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "CAA", "SOA"):
        records, record_errors = query_dns_record(domain, record_type, timeout_seconds)
        dns[record_type] = records[:DNS_MAX_RECORDS_PER_TYPE]
        errors.extend(record_errors)

    dmarc_records, dmarc_errors = query_dns_record(f"_dmarc.{domain}", "TXT", timeout_seconds)
    errors.extend(dmarc_errors)

    www_dns: dict[str, Any] = {}
    if domain.startswith("www."):
        www_dns = {"checked": False, "reason": "Target domain already starts with www."}
    else:
        www_domain = f"www.{domain}"
        www_errors: list[str] = []
        www_dns = {"checked": True, "domain": www_domain}
        for record_type in ("A", "AAAA", "CNAME"):
            records, record_errors = query_dns_record(www_domain, record_type, timeout_seconds)
            www_dns[record_type] = records[:DNS_MAX_RECORDS_PER_TYPE]
            www_errors.extend(record_errors)
        www_dns["errors"] = www_errors
        errors.extend(www_errors)
    dns["www"] = www_dns

    spf = parse_spf_records(as_string_list(dns.get("TXT")))
    dmarc = parse_dmarc_records(as_string_list(dmarc_records))
    email_security = {
        "spf": spf,
        "dmarc": dmarc,
        "dkim": {
            "checked": False,
            "status": "not_checked",
            "reason": "DKIM selectors are not brute-forced in this passive baseline.",
        },
    }
    findings = build_domain_findings(domain, dns, email_security)
    summary = build_domain_summary(dns, email_security, findings)
    return {
        "analyzer": "domain_basic",
        "target": {
            "domain": domain,
            "normalized_domain": domain,
            "checked_at": checked_at,
        },
        "dns": dns,
        "email_security": email_security,
        "findings": findings,
        "summary": summary,
        "errors": dedupe_strings(errors),
    }


def analyze_subdomains_basic_target(
    root_domain: str,
    raw_candidates: list[str],
    *,
    timeout_seconds: float,
    max_candidates: int,
    wildcard_checks: int,
    global_deadline_seconds: float,
) -> dict[str, Any]:
    checked_at = datetime.now(timezone.utc).isoformat()
    started_at = time.monotonic()

    def deadline_reached() -> bool:
        return time.monotonic() - started_at >= global_deadline_seconds

    candidates, accepted_fqdns, candidate_findings = normalize_subdomain_candidate_list(
        root_domain,
        raw_candidates,
        max_candidates=max_candidates,
    )
    results: list[dict[str, Any]] = []
    errors: list[str] = []
    findings: list[dict[str, str]] = list(candidate_findings)

    deadline_hit = False
    processed_fqdns: set[str] = set()

    for fqdn in accepted_fqdns:
        if deadline_reached():
            deadline_hit = True
            break
        result, result_errors, result_findings = resolve_subdomain_candidate(
            root_domain,
            fqdn,
            timeout_seconds,
            deadline_reached=deadline_reached,
        )
        results.append(result)
        processed_fqdns.add(fqdn)
        errors.extend(result_errors)
        findings.extend(result_findings)
        if result.get("deadline_reached"):
            deadline_hit = True
            break

    pending_fqdns = [fqdn for fqdn in accepted_fqdns if fqdn not in processed_fqdns]
    if deadline_hit:
        results.extend(make_skipped_subdomain_result(fqdn) for fqdn in pending_fqdns)

    wildcard_dns = analyze_subdomain_wildcard_dns(
        root_domain,
        timeout_seconds=timeout_seconds,
        wildcard_checks=wildcard_checks,
        deadline_reached=deadline_reached,
    )
    errors.extend(as_string_list(wildcard_dns.get("errors")))
    if wildcard_dns.get("deadline_reached"):
        deadline_hit = True
    if wildcard_dns.get("possible"):
        findings.append(
            make_finding(
                "subdomain_wildcard_dns_possible",
                "Wildcard DNS may be present",
                "low",
                "One or more random probe names under the root domain resolved. This is a heuristic indicator for manual review.",
                str(wildcard_dns.get("probes", [])),
                "Confirm whether wildcard DNS is expected before relying on unresolved candidate counts.",
            )
        )

    processed_results = [result for result in results if result.get("status") != "skipped"]
    unresolved_count = sum(1 for result in processed_results if not result.get("resolves"))
    if len(processed_results) >= 3 and unresolved_count / len(processed_results) >= 0.5:
        findings.append(
            make_finding(
                "subdomain_many_candidates_unresolved",
                "Many submitted candidates did not resolve",
                "info",
                "At least half of the accepted candidates did not return A, AAAA, or CNAME records.",
                f"{unresolved_count} of {len(processed_results)} processed candidates unresolved",
                "Confirm the submitted inventory is current and authorized.",
            )
        )

    candidate_limit_reached = len(raw_candidates) > max_candidates
    truncated = deadline_hit or candidate_limit_reached
    if deadline_hit:
        findings.append(
            make_finding(
                "subdomain_global_deadline_reached",
                "Subdomain inventory stopped by global deadline",
                "low",
                "The controlled inventory returned partial results because the configured global deadline was reached.",
                f"deadline: {global_deadline_seconds}s; processed: {len(processed_results)}; pending: {len(pending_fqdns)}",
                "Reduce candidate count, review DNS resolver responsiveness, or increase the deadline only in authorized controlled environments.",
            )
        )

    findings = dedupe_findings(findings)
    summary = build_subdomain_inventory_summary(
        raw_candidates,
        candidates,
        results,
        findings,
        wildcard_dns,
        truncated=truncated,
        deadline_reached=deadline_hit,
    )
    limits = {
        "global_deadline_seconds": global_deadline_seconds,
        "dns_timeout_seconds": timeout_seconds,
        "max_candidates": max_candidates,
        "wildcard_checks": max(0, min(wildcard_checks, 2)),
    }
    return {
        "analyzer": "subdomain_inventory_basic",
        "target": {
            "root_domain": root_domain,
            "normalized_root_domain": root_domain,
            "checked_at": checked_at,
        },
        "summary": summary,
        "limits": limits,
        "truncation_reason": "global_deadline_reached" if deadline_hit else ("candidate_limit_reached" if candidate_limit_reached else None),
        "candidates": candidates,
        "results": results,
        "wildcard_dns": wildcard_dns,
        "findings": findings,
        "errors": dedupe_strings(errors),
    }


def normalize_subdomain_candidate_list(
    root_domain: str,
    raw_candidates: list[str],
    *,
    max_candidates: int,
) -> tuple[list[dict[str, Any]], list[str], list[dict[str, str]]]:
    candidates: list[dict[str, Any]] = []
    accepted_fqdns: list[str] = []
    findings: list[dict[str, str]] = []
    seen: set[str] = set()

    if not raw_candidates:
        return (
            [{"input": "", "fqdn": None, "status": "rejected", "rejection_reason": "At least one candidate is required."}],
            [],
            [
                make_finding(
                    "subdomain_candidate_rejected",
                    "Subdomain candidate was rejected",
                    "info",
                    "A submitted candidate could not be normalized within the authorized root domain.",
                    "empty candidate list",
                    "Submit explicit labels or FQDNs that are inside the authorized root domain.",
                )
            ],
        )

    if len(raw_candidates) > max_candidates:
        raw_candidates = raw_candidates[:max_candidates]
        findings.append(
            make_finding(
                "subdomain_candidate_limit_reached",
                "Subdomain candidate limit reached",
                "low",
                "The submitted candidate list exceeded the configured limit and was truncated before DNS resolution.",
                f"configured limit: {max_candidates}",
                "Submit a smaller explicit inventory or raise the limit only for authorized workflows.",
            )
        )

    for raw_candidate in raw_candidates:
        candidate_text = str(raw_candidate)
        try:
            fqdn = normalize_subdomain_candidate(root_domain, candidate_text)
        except ValueError as exc:
            reason = str(exc)
            candidates.append({"input": candidate_text, "fqdn": None, "status": "rejected", "rejection_reason": reason})
            findings.append(
                make_finding(
                    "subdomain_candidate_rejected",
                    "Subdomain candidate was rejected",
                    "info",
                    "A submitted candidate could not be normalized within the authorized root domain.",
                    f"{candidate_text}: {reason}",
                    "Submit explicit labels or FQDNs that are inside the authorized root domain.",
                )
            )
            continue
        if fqdn in seen:
            candidates.append({"input": candidate_text, "fqdn": fqdn, "status": "rejected", "rejection_reason": "Duplicate candidate."})
            findings.append(
                make_finding(
                    "subdomain_duplicate_candidate",
                    "Duplicate subdomain candidate removed",
                    "info",
                    "A submitted candidate normalized to an already accepted FQDN.",
                    fqdn,
                    "Deduplicate candidate lists before submission when possible.",
                )
            )
            continue
        seen.add(fqdn)
        accepted_fqdns.append(fqdn)
        candidates.append({"input": candidate_text, "fqdn": fqdn, "status": "accepted"})

    return candidates, accepted_fqdns, findings


def normalize_subdomain_candidate(root_domain: str, raw_candidate: str) -> str:
    value = raw_candidate.strip()
    if not value:
        raise ValueError("Candidate is empty.")
    if "*" in value:
        raise ValueError("Wildcard candidates are not accepted.")
    if any(character.isspace() for character in value):
        raise ValueError("Candidate must not contain spaces.")
    if "://" in value or "/" in value or "?" in value or "#" in value or "@" in value or ":" in value:
        raise ValueError("Candidate must be a label or FQDN, not a URL.")
    if value.endswith("."):
        raise ValueError("Trailing dots are not accepted in subdomain candidates.")

    candidate = value.rstrip(".").lower()
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        pass
    else:
        raise ValueError("IP literals are not accepted.")

    fqdn = f"{candidate}.{root_domain}" if "." not in candidate else candidate
    try:
        normalized = normalize_domain(fqdn)
    except HTTPException as exc:
        detail = exc.detail if isinstance(exc.detail, str) else "Domain validation failed."
        raise ValueError(detail) from exc
    if normalized == root_domain or not normalized.endswith(f".{root_domain}"):
        raise ValueError("Candidate is outside the root domain.")
    return normalized


def resolve_subdomain_candidate(
    root_domain: str,
    fqdn: str,
    timeout_seconds: float,
    *,
    deadline_reached: Callable[[], bool] | None = None,
) -> tuple[dict[str, Any], list[str], list[dict[str, str]]]:
    result: dict[str, Any] = {
        "fqdn": fqdn,
        "resolves": False,
        "status": "processed",
        "A": [],
        "AAAA": [],
        "CNAME": [],
        "private_or_reserved_ip_detected": False,
        "errors": [],
    }
    errors: list[str] = []
    findings: list[dict[str, str]] = []
    for record_type in ("A", "AAAA", "CNAME"):
        if deadline_reached is not None and deadline_reached():
            result["status"] = "partial"
            result["deadline_reached"] = True
            result["skip_reason"] = "global_deadline_reached"
            errors.append(f"{record_type} query skipped because the global subdomain inventory deadline was reached.")
            break
        records, record_errors = query_dns_record(fqdn, record_type, timeout_seconds)
        result[record_type] = records[:DNS_MAX_RECORDS_PER_TYPE]
        errors.extend(record_errors)
    result["errors"] = errors
    result["resolves"] = any(result.get(record_type) for record_type in ("A", "AAAA", "CNAME"))

    ip_records = as_string_list(result.get("A")) + as_string_list(result.get("AAAA"))
    private_ips = [address for address in ip_records if is_private_or_reserved_ip(address)]
    if private_ips:
        result["private_or_reserved_ip_detected"] = True
        result["private_or_reserved_ips"] = private_ips[:DNS_MAX_RECORDS_PER_TYPE]
        findings.append(
            make_finding(
                "subdomain_private_or_reserved_ip",
                "Subdomain resolves to private or reserved IP",
                "low",
                "A submitted candidate returned an IP address that appears private, loopback, link-local, multicast, unspecified, or reserved.",
                f"{fqdn}: {', '.join(private_ips)}",
                "Confirm whether this host is intended for internal use and avoid exposing private inventory unintentionally.",
            )
        )

    external_cnames = [name for name in as_string_list(result.get("CNAME")) if not domain_within_root(name, root_domain)]
    if external_cnames:
        result["external_cname_detected"] = True
        findings.append(
            make_finding(
                "subdomain_external_cname",
                "Subdomain CNAME points outside root domain",
                "info",
                "A submitted candidate has a CNAME target outside the authorized root domain. This can be normal for SaaS/CDN services.",
                f"{fqdn}: {', '.join(external_cnames)}",
                "Confirm the external target is expected and managed by an authorized provider.",
            )
        )

    return result, errors, findings


def make_skipped_subdomain_result(fqdn: str) -> dict[str, Any]:
    return {
        "fqdn": fqdn,
        "resolves": False,
        "status": "skipped",
        "skip_reason": "global_deadline_reached",
        "deadline_reached": True,
        "A": [],
        "AAAA": [],
        "CNAME": [],
        "private_or_reserved_ip_detected": False,
        "errors": ["Skipped because the global subdomain inventory deadline was reached."],
    }


def analyze_subdomain_wildcard_dns(
    root_domain: str,
    *,
    timeout_seconds: float,
    wildcard_checks: int,
    deadline_reached: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    checks = max(0, min(wildcard_checks, 2))
    if checks == 0:
        return {"checked": False, "possible": False, "probes_count": 0, "notes": "Wildcard DNS check disabled.", "errors": []}
    if deadline_reached is not None and deadline_reached():
        return {
            "checked": False,
            "possible": False,
            "probes_count": 0,
            "notes": "Wildcard DNS skipped because the global deadline was reached.",
            "skipped_reason": "global_deadline_reached",
            "deadline_reached": True,
            "errors": [],
        }

    probes: list[dict[str, Any]] = []
    errors: list[str] = []
    for _ in range(checks):
        if deadline_reached is not None and deadline_reached():
            return {
                "checked": bool(probes),
                "possible": False,
                "partial": bool(probes),
                "deadline_reached": True,
                "skipped_reason": "global_deadline_reached",
                "probes_count": len(probes),
                "probes": probes,
                "notes": "Wildcard DNS check stopped because the global deadline was reached.",
                "errors": dedupe_strings(errors),
            }
        probe_name = f"inspectra-wildcard-{uuid4().hex[:12]}.{root_domain}"
        probe: dict[str, Any] = {"fqdn": probe_name, "resolves": False, "A": [], "AAAA": [], "CNAME": []}
        for record_type in ("A", "AAAA", "CNAME"):
            if deadline_reached is not None and deadline_reached():
                probe["deadline_reached"] = True
                probe["skip_reason"] = "global_deadline_reached"
                errors.append(f"{record_type} wildcard query skipped because the global subdomain inventory deadline was reached.")
                probes.append(probe)
                return {
                    "checked": True,
                    "possible": False,
                    "partial": True,
                    "deadline_reached": True,
                    "skipped_reason": "global_deadline_reached",
                    "probes_count": len(probes),
                    "probes": probes,
                    "notes": "Wildcard DNS check stopped because the global deadline was reached.",
                    "errors": dedupe_strings(errors),
                }
            records, record_errors = query_dns_record(probe_name, record_type, timeout_seconds)
            probe[record_type] = records[:DNS_MAX_RECORDS_PER_TYPE]
            errors.extend(record_errors)
        probe["resolves"] = any(probe.get(record_type) for record_type in ("A", "AAAA", "CNAME"))
        probes.append(probe)

    possible = bool(probes) and all(bool(probe.get("resolves")) for probe in probes)
    return {
        "checked": True,
        "possible": possible,
        "probes_count": len(probes),
        "probes": probes,
        "notes": "Heuristic check using bounded random labels; not a brute-force discovery mechanism.",
        "errors": dedupe_strings(errors),
    }


def build_subdomain_inventory_summary(
    raw_candidates: list[str],
    candidates: list[dict[str, Any]],
    results: list[dict[str, Any]],
    findings: list[dict[str, str]],
    wildcard_dns: dict[str, Any],
    *,
    truncated: bool,
    deadline_reached: bool,
) -> dict[str, Any]:
    accepted = [candidate for candidate in candidates if candidate.get("status") == "accepted"]
    rejected = [candidate for candidate in candidates if candidate.get("status") == "rejected"]
    processed_results = [result for result in results if result.get("status") != "skipped"]
    resolved_count = sum(1 for result in processed_results if result.get("resolves"))
    cname_count = sum(1 for result in processed_results if result.get("CNAME"))
    private_ip_count = sum(1 for result in processed_results if result.get("private_or_reserved_ip_detected"))
    processed_count = len(processed_results)
    pending_count = max(0, len(accepted) - processed_count)
    return {
        "candidates_submitted": len(raw_candidates),
        "candidates_accepted": len(accepted),
        "candidates_rejected": len(rejected),
        "candidates_processed": processed_count,
        "candidates_pending": pending_count,
        "resolved_count": resolved_count,
        "unresolved_count": max(0, processed_count - resolved_count),
        "cname_count": cname_count,
        "private_ip_count": private_ip_count,
        "findings_count": len(findings),
        "wildcard_dns_possible": bool(wildcard_dns.get("possible")),
        "truncated": truncated,
        "deadline_reached": deadline_reached,
    }


def is_private_or_reserved_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(
        (
            address.is_private,
            address.is_loopback,
            address.is_link_local,
            address.is_reserved,
            address.is_multicast,
            address.is_unspecified,
        )
    )


def domain_within_root(value: str, root_domain: str) -> bool:
    normalized = value.rstrip(".").lower()
    return normalized == root_domain or normalized.endswith(f".{root_domain}")


def query_dns_record(domain: str, record_type: str, timeout_seconds: float) -> tuple[list[Any], list[str]]:
    qtype = DNS_RECORD_TYPES[record_type]
    query_id = int.from_bytes(os.urandom(2), "big")
    query = build_dns_query(domain, qtype, query_id)
    errors: list[str] = []
    nameservers = dns_nameservers()
    if not nameservers:
        return [], ["No DNS nameservers were configured for the runner."]
    for nameserver in nameservers:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout_seconds)
                sock.sendto(query, (nameserver, 53))
                response, _ = sock.recvfrom(4096)
            records, truncated = parse_dns_response(response, query_id, qtype)
            record_errors = [f"{record_type} response was truncated; TCP fallback is not used in this passive MVP."] if truncated else []
            return records, record_errors
        except (OSError, ValueError) as exc:
            errors.append(f"{record_type} query via {nameserver} failed safely: {exc.__class__.__name__}.")
    return [], errors[:3]


def dns_nameservers() -> list[str]:
    try:
        with Path("/etc/resolv.conf").open("r", encoding="utf-8") as handle:
            return parse_dns_nameserver_lines(handle)
    except OSError:
        return []


def parse_dns_nameserver_lines(lines: Any) -> list[str]:
    nameservers: list[str] = []
    for line in lines:
        stripped = line.strip()
        if not stripped.startswith("nameserver"):
            continue
        parts = stripped.split()
        if len(parts) >= 2:
            try:
                address = ipaddress.ip_address(parts[1])
            except ValueError:
                continue
            if isinstance(address, ipaddress.IPv4Address):
                nameservers.append(str(address))
    return nameservers[:3]


def build_dns_query(domain: str, qtype: int, query_id: int) -> bytes:
    labels = domain.rstrip(".").split(".")
    question = b"".join(bytes([len(label)]) + label.encode("ascii") for label in labels) + b"\x00"
    return struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0) + question + struct.pack("!HH", qtype, 1)


def parse_dns_response(data: bytes, query_id: int, expected_qtype: int) -> tuple[list[Any], bool]:
    if len(data) < 12:
        raise ValueError("DNS response too short.")
    response_id, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", data[:12])
    if response_id != query_id:
        raise ValueError("DNS response ID mismatch.")
    rcode = flags & 0x000F
    truncated = bool(flags & 0x0200)
    if rcode == 3:
        return [], truncated
    if rcode != 0:
        raise ValueError(f"DNS response code {rcode}.")

    offset = 12
    for _ in range(qdcount):
        _, offset = parse_dns_name(data, offset)
        offset += 4
    records: list[Any] = []
    for _ in range(ancount):
        _, offset = parse_dns_name(data, offset)
        if offset + 10 > len(data):
            raise ValueError("DNS answer is truncated.")
        rtype, rclass, _, rdlength = struct.unpack("!HHIH", data[offset : offset + 10])
        offset += 10
        rdata_offset = offset
        offset += rdlength
        if rclass != 1 or rtype != expected_qtype:
            continue
        decoded = decode_dns_rdata(data, rdata_offset, rdlength, rtype)
        if decoded is not None:
            records.append(decoded)
    return records[:DNS_MAX_RECORDS_PER_TYPE], truncated


def parse_dns_name(data: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    jumped = False
    next_offset = offset
    seen_offsets: set[int] = set()
    while True:
        if offset >= len(data):
            raise ValueError("DNS name exceeds response length.")
        length = data[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise ValueError("DNS compression pointer is truncated.")
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if pointer in seen_offsets:
                raise ValueError("DNS compression pointer loop detected.")
            seen_offsets.add(pointer)
            if not jumped:
                next_offset = offset + 2
            offset = pointer
            jumped = True
            continue
        if length == 0:
            if not jumped:
                next_offset = offset + 1
            break
        offset += 1
        if offset + length > len(data):
            raise ValueError("DNS label exceeds response length.")
        labels.append(data[offset : offset + length].decode("ascii", errors="replace"))
        offset += length
        if not jumped:
            next_offset = offset
    return ".".join(labels), next_offset


def decode_dns_rdata(data: bytes, offset: int, rdlength: int, rtype: int) -> Any:
    end = offset + rdlength
    if end > len(data):
        raise ValueError("DNS rdata exceeds response length.")
    if rtype == DNS_RECORD_TYPES["A"] and rdlength == 4:
        return str(ipaddress.IPv4Address(data[offset:end]))
    if rtype == DNS_RECORD_TYPES["AAAA"] and rdlength == 16:
        return str(ipaddress.IPv6Address(data[offset:end]))
    if rtype in {DNS_RECORD_TYPES["NS"], DNS_RECORD_TYPES["CNAME"]}:
        name, _ = parse_dns_name(data, offset)
        return name.rstrip(".")
    if rtype == DNS_RECORD_TYPES["MX"]:
        if rdlength < 3:
            return None
        preference = struct.unpack("!H", data[offset : offset + 2])[0]
        exchange, _ = parse_dns_name(data, offset + 2)
        return {"preference": preference, "exchange": exchange.rstrip(".")}
    if rtype == DNS_RECORD_TYPES["TXT"]:
        chunks: list[str] = []
        cursor = offset
        while cursor < end:
            length = data[cursor]
            cursor += 1
            chunks.append(data[cursor : cursor + length].decode("utf-8", errors="replace"))
            cursor += length
        return truncate_string(redact_sensitive_text("".join(chunks)))
    if rtype == DNS_RECORD_TYPES["CAA"]:
        if rdlength < 2:
            return None
        flags = data[offset]
        tag_length = data[offset + 1]
        tag_start = offset + 2
        tag_end = tag_start + tag_length
        if tag_end > end:
            return None
        tag = data[tag_start:tag_end].decode("ascii", errors="replace")
        value = data[tag_end:end].decode("utf-8", errors="replace")
        return {"flags": flags, "tag": tag, "value": truncate_string(value)}
    if rtype == DNS_RECORD_TYPES["SOA"]:
        mname, cursor = parse_dns_name(data, offset)
        rname, cursor = parse_dns_name(data, cursor)
        if cursor + 20 > end:
            return None
        serial, refresh, retry, expire, minimum = struct.unpack("!IIIII", data[cursor : cursor + 20])
        return {
            "mname": mname.rstrip("."),
            "rname": rname.rstrip("."),
            "serial": serial,
            "refresh": refresh,
            "retry": retry,
            "expire": expire,
            "minimum": minimum,
        }
    return None


def parse_spf_records(txt_records: list[str]) -> dict[str, Any]:
    records = [record for record in txt_records if record.lower().startswith("v=spf1")]
    mechanisms: list[str] = []
    includes: list[str] = []
    redirect: str | None = None
    all_mechanism: str | None = None
    all_mechanisms: list[str] = []
    uses = {"a": False, "mx": False, "ip4": False, "ip6": False}
    for record in records:
        for token in record.split()[1:]:
            mechanisms.append(token)
            normalized = token.lower()
            bare = normalized[1:] if normalized[:1] in {"+", "-", "~", "?"} else normalized
            if bare == "all":
                value = normalized[:1] + "all" if normalized[:1] in {"+", "-", "~", "?"} else "+all"
                all_mechanisms.append(value)
                if all_mechanism is None:
                    all_mechanism = value
            if bare.startswith("include:"):
                includes.append(token.split(":", 1)[1])
            if bare.startswith("redirect="):
                redirect = token.split("=", 1)[1]
            for key in uses:
                if bare == key or bare.startswith(f"{key}:"):
                    uses[key] = True
    return {
        "present": bool(records),
        "record_count": len(records),
        "records": records,
        "all_mechanism": all_mechanism,
        "all_mechanisms": all_mechanisms,
        "includes": includes,
        "redirect": redirect,
        "mechanisms": mechanisms,
        **uses,
    }


def parse_dmarc_records(txt_records: list[str]) -> dict[str, Any]:
    records = [record for record in txt_records if record.lower().startswith("v=dmarc1")]
    tags: dict[str, str] = {}
    if records:
        for part in records[0].split(";"):
            if "=" not in part:
                continue
            key, value = part.strip().split("=", 1)
            tags[key.lower()] = value.strip()
    pct: int | None = None
    if tags.get("pct"):
        try:
            pct = int(tags["pct"])
        except ValueError:
            pct = None
    return {
        "present": bool(records),
        "record_count": len(records),
        "records": records,
        "policy": tags.get("p"),
        "rua": tags.get("rua"),
        "ruf": tags.get("ruf"),
        "pct": pct,
        "adkim": tags.get("adkim"),
        "aspf": tags.get("aspf"),
    }


def build_domain_findings(domain: str, dns: dict[str, Any], email_security: dict[str, Any]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    spf = as_dict(email_security.get("spf"))
    dmarc = as_dict(email_security.get("dmarc"))
    ns_records = as_string_list(dns.get("NS"))
    mx_records = dns.get("MX") if isinstance(dns.get("MX"), list) else []
    caa_records = dns.get("CAA") if isinstance(dns.get("CAA"), list) else []
    www = as_dict(dns.get("www"))

    if not ns_records:
        findings.append(make_finding("domain_ns_absent", "No NS records observed", "low", "No NS records were returned for the domain.", domain, "Confirm delegated DNS manually."))
    elif len(ns_records) == 1:
        findings.append(make_finding("domain_single_nameserver", "Only one NS record observed", "info", "A single nameserver was returned. This may be intentional, but reduces DNS redundancy.", ns_records[0], "Review DNS redundancy with the domain owner."))
    elif ns_look_same_provider(ns_records):
        findings.append(make_finding("domain_ns_same_provider_indicator", "Nameservers appear provider-concentrated", "info", "All observed nameservers appear to share a similar parent domain. This is an indicator for manual review only.", ", ".join(ns_records), "Confirm DNS provider concentration is intentional."))

    if not mx_records:
        findings.append(make_finding("domain_mx_absent", "No MX records observed", "info", "No MX records were returned. The domain may not receive email.", domain, "Confirm whether inbound email is expected for this domain."))
    if not spf.get("present"):
        findings.append(make_finding("domain_spf_absent", "SPF record was not observed", "low", "No TXT record beginning with v=spf1 was observed.", domain, "Publish SPF if the domain sends email."))
    if int(spf.get("record_count") or 0) > 1:
        findings.append(make_finding("domain_multiple_spf_records", "Multiple SPF records observed", "low", "Multiple SPF records can cause SPF evaluation failures.", str(spf.get("records")), "Keep a single SPF record per domain."))
    all_mechanisms = as_string_list(spf.get("all_mechanisms"))
    if spf.get("all_mechanism") == "+all" or "+all" in all_mechanisms:
        findings.append(make_finding("domain_spf_plus_all", "SPF uses +all", "medium", "The SPF policy appears to allow all senders.", str(spf.get("records")), "Replace +all with a stricter all mechanism after validating mail flows."))
    if spf.get("all_mechanism") == "?all" or "?all" in all_mechanisms:
        findings.append(make_finding("domain_spf_neutral_all", "SPF uses ?all", "low", "The SPF policy ends with a neutral all mechanism.", str(spf.get("records")), "Review whether a stricter SPF policy is appropriate."))

    if not dmarc.get("present"):
        findings.append(make_finding("domain_dmarc_absent", "DMARC record was not observed", "low", "No DMARC TXT record was observed at _dmarc.", f"_dmarc.{domain}", "Publish DMARC after validating email authentication alignment."))
    elif str(dmarc.get("policy") or "").lower() == "none":
        findings.append(make_finding("domain_dmarc_policy_none", "DMARC policy is p=none", "low", "DMARC is present in monitoring mode.", str(dmarc.get("records")), "Move toward quarantine or reject after reviewing reports."))
    if isinstance(dmarc.get("pct"), int) and int(dmarc["pct"]) < 100:
        findings.append(make_finding("domain_dmarc_pct_partial", "DMARC pct is below 100", "info", "DMARC policy is applied to less than 100 percent of matching mail.", str(dmarc.get("pct")), "Confirm staged rollout is intentional."))

    if not caa_records:
        findings.append(make_finding("domain_caa_absent", "CAA records were not observed", "info", "No CAA records were returned. This is not a vulnerability by itself.", domain, "Consider CAA records if certificate issuance should be constrained."))

    if www.get("checked") and not any(www.get(record_type) for record_type in ("A", "AAAA", "CNAME")):
        findings.append(make_finding("domain_www_not_resolving", "www host did not resolve", "info", "The www host did not return A, AAAA, or CNAME records.", str(www.get("domain")), "Confirm whether www should resolve."))

    sensitive_txt = [record for record in as_string_list(dns.get("TXT")) if contains_sensitive_text(record)]
    if sensitive_txt:
        findings.append(make_finding("domain_txt_sensitive_indicator", "TXT record contains sensitive-looking text", "low", "A TXT record contains words commonly associated with secrets. Inspectra redacts obvious values, but manual review is needed.", str(sensitive_txt[:3]), "Review whether TXT records expose sensitive material."))
    return dedupe_findings(findings)


def build_domain_summary(dns: dict[str, Any], email_security: dict[str, Any], findings: list[dict[str, str]]) -> dict[str, Any]:
    spf = as_dict(email_security.get("spf"))
    dmarc = as_dict(email_security.get("dmarc"))
    www = as_dict(dns.get("www"))
    records_found_count = 0
    for key, value in dns.items():
        if key == "www":
            continue
        if isinstance(value, list):
            records_found_count += len(value)
    return {
        "records_found_count": records_found_count,
        "findings_count": len(findings),
        "spf_present": bool(spf.get("present")),
        "dmarc_present": bool(dmarc.get("present")),
        "dmarc_policy": dmarc.get("policy"),
        "caa_present": bool(dns.get("CAA")),
        "mx_present": bool(dns.get("MX")),
        "www_resolves": bool(www.get("checked") and any(www.get(record_type) for record_type in ("A", "AAAA", "CNAME"))),
    }


def ns_look_same_provider(ns_records: list[str]) -> bool:
    suffixes = {".".join(record.lower().rstrip(".").split(".")[-2:]) for record in ns_records if "." in record}
    return len(ns_records) > 1 and len(suffixes) == 1


def redact_sensitive_text(value: str) -> str:
    pattern = re.compile(r"(?i)\b(token|secret|password|passwd|api_key|apikey|key)(\s*[=:]\s*)([^\s;]+)")
    return pattern.sub(lambda match: f"{match.group(1)}{match.group(2)}[redacted]", truncate_string(value))


def contains_sensitive_text(value: str) -> bool:
    lowered = value.lower()
    return any(fragment in lowered for fragment in SENSITIVE_TEXT_FRAGMENTS)


def truncate_string(value: str, limit: int = DNS_MAX_STRING_LENGTH) -> str:
    suffix = "...[truncated]"
    return value if len(value) <= limit else value[: max(0, limit - len(suffix))] + suffix


def as_string_list(value: Any) -> list[str]:
    return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []


def dedupe_strings(values: list[str]) -> list[str]:
    deduped: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        deduped.append(value)
    return deduped


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


def django_config_limits(request: ArchiveAnalysisRequest) -> dict[str, int]:
    max_files = DJANGO_CONFIG_MAX_FILES if request.max_files is None else request.max_files
    max_file_bytes = DJANGO_CONFIG_MAX_FILE_BYTES if request.max_file_bytes is None else request.max_file_bytes
    max_total_bytes = DJANGO_CONFIG_MAX_TOTAL_BYTES if request.max_total_bytes is None else request.max_total_bytes
    if max_files <= 0 or max_file_bytes <= 0 or max_total_bytes <= 0:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Django config analysis limits must be positive.")
    return {"max_files": max_files, "max_file_bytes": max_file_bytes, "max_total_bytes": max_total_bytes}


def analyze_django_config_archive(
    path: Path,
    archive_type: str,
    *,
    max_files: int,
    max_file_bytes: int,
    max_total_bytes: int,
) -> dict[str, Any]:
    analysis = empty_django_config_analysis()
    state = {
        "files_read": 0,
        "total_bytes_read": 0,
        "max_files": max_files,
        "max_file_bytes": max_file_bytes,
        "max_total_bytes": max_total_bytes,
    }

    if archive_type == "zip":
        preflight = inspect_zip_metadata_preflight(path)
        blocked_reason = zip_preflight_block_reason(preflight, ARCHIVE_MAX_ENTRIES)
        add_zip_preflight_summary(analysis["summary"], preflight)
        if blocked_reason:
            summary = as_dict(analysis["summary"])
            summary["truncated"] = True
            finding = zip_preflight_finding(blocked_reason, preflight, ARCHIVE_MAX_ENTRIES)
            scoped = dict(finding)
            scoped["id"] = f"django_config_{scoped['id']}"
            analysis["findings"].append(scoped)
            finalize_django_config_analysis(analysis)
            return analysis
        with zipfile.ZipFile(path) as archive:
            for index, info in enumerate(archive.filelist, start=1):
                if should_stop_django_archive_scan(index, analysis):
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
                process_django_config_entry(
                    analysis,
                    state,
                    entry,
                    lambda entry_info=info: archive.open(entry_info),
                )
    else:
        with tarfile.open(path, "r:*") as archive:
            for index, member in enumerate(archive, start=1):
                if should_stop_django_archive_scan(index, analysis):
                    break
                entry = {
                    "path": member.name,
                    "type": tar_member_type(member),
                    "size": member.size,
                    "mode_int": member.mode,
                    "mode": format_file_mode(member.mode),
                    "link_target": member.linkname or None,
                }
                process_django_config_entry(
                    analysis,
                    state,
                    entry,
                    lambda tar_member=member: archive.extractfile(tar_member),
                )

    finalize_django_config_analysis(analysis)
    return analysis


def empty_django_config_analysis(errors: list[str] | None = None) -> dict[str, Any]:
    return {
        "summary": {
            "files_considered": 0,
            "files_read": 0,
            "settings_files_detected": 0,
            "deployment_files_detected": 0,
            "env_files_detected": 0,
            "dependency_files_detected": 0,
            "findings_count": 0,
            "secrets_redacted_count": 0,
            "truncated": False,
        },
        "detected_files": [],
        "django_signals": {
            "debug": {"status": "not_found", "files": []},
            "secret_key": {"status": "not_found", "files": []},
            "allowed_hosts": {"status": "not_found", "files": []},
            "cookies": {},
            "https_security": {},
            "cors": {"status": "not_found", "files": []},
            "database": {"status": "not_found", "files": []},
            "static_media": {},
            "deployment": {},
        },
        "_missing_setting_observations": {},
        "findings": [],
        "errors": errors or [],
    }


def build_django_config_result(
    file_id: str,
    path: Path,
    original_filename: str,
    archive_type: str,
    analysis: dict[str, Any],
    *,
    max_files: int,
    max_file_bytes: int,
    max_total_bytes: int,
) -> dict[str, Any]:
    summary = as_dict(analysis.get("summary"))
    findings = analysis.get("findings") if isinstance(analysis.get("findings"), list) else []
    summary["findings_count"] = len(findings)
    return {
        "file_id": file_id,
        "analyzer": "django_config_basic",
        "archive_type": archive_type,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "hashes": calculate_hashes(path),
        "file_identification": {
            "size_bytes": path.stat().st_size,
            "original_filename": original_filename,
        },
        "limits": {
            "max_files": max_files,
            "max_file_bytes": max_file_bytes,
            "max_total_bytes": max_total_bytes,
            "max_archive_entries": ARCHIVE_MAX_ENTRIES,
            "max_entry_name_length": ARCHIVE_MAX_ENTRY_NAME_LENGTH,
            "max_zip_central_directory_bytes": ARCHIVE_MAX_ZIP_CENTRAL_DIRECTORY_BYTES,
        },
        "summary": summary,
        "detected_files": analysis.get("detected_files", []),
        "django_signals": analysis.get("django_signals", {}),
        "findings": findings,
        "errors": analysis.get("errors", []),
    }


def should_stop_django_archive_scan(index: int, analysis: dict[str, Any]) -> bool:
    summary = as_dict(analysis["summary"])
    if index > ARCHIVE_MAX_ENTRIES:
        summary["truncated"] = True
        add_django_finding(
            analysis,
            "django_config_entry_limit_reached",
            "Archive entry scan limit reached",
            "medium",
            "Inspectra stopped scanning archive metadata after the configured entry limit.",
            f"Processed {ARCHIVE_MAX_ENTRIES} entries.",
            "Review the archive with stricter limits or split it before deeper inspection.",
        )
        return True
    return False


def process_django_config_entry(
    analysis: dict[str, Any],
    state: dict[str, int],
    entry: dict[str, Any],
    open_entry,
) -> None:
    path = str(entry["path"])
    category = classify_django_config_candidate(path)
    if category is None:
        return

    summary = as_dict(analysis["summary"])
    summary["files_considered"] += 1
    increment_django_category_counts(summary, category, path)

    entry_type = str(entry["type"])
    size_bytes = int(entry.get("size") or 0)
    flags, depth = archive_entry_flags(path, entry.get("mode_int"))
    record = {
        "path": path,
        "category": category,
        "entry_type": entry_type,
        "size_bytes": size_bytes,
        "mode": entry.get("mode"),
        "depth": depth,
        "flags": flags,
        "read": False,
        "skip_reason": None,
    }
    if entry.get("link_target"):
        record["link_target"] = entry["link_target"]

    skip_reason = django_config_skip_reason(record, state)
    if skip_reason:
        record["skip_reason"] = skip_reason
        analysis["detected_files"].append(record)
        add_django_skip_finding(analysis, path, skip_reason, size_bytes)
        return

    try:
        stream = open_entry()
        if stream is None:
            raise ValueError("entry could not be opened as a regular file")
        with stream:
            raw_bytes = read_limited_stream(stream, state["max_file_bytes"])
    except (OSError, ValueError, zipfile.BadZipFile, tarfile.TarError) as exc:
        record["skip_reason"] = "read_error"
        analysis["detected_files"].append(record)
        add_django_finding(
            analysis,
            "django_config_file_read_error",
            "Config file could not be read safely",
            "low",
            "A candidate Django configuration file could not be read from the archive within Inspectra limits.",
            f"{path}: {exc}",
            "Review this file manually in a constrained environment if it is expected.",
            file_path=path,
        )
        return

    state["files_read"] += 1
    state["total_bytes_read"] += len(raw_bytes)
    summary["files_read"] = state["files_read"]
    record["read"] = True
    record["bytes_read"] = len(raw_bytes)
    analysis["detected_files"].append(record)

    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        record["skip_reason"] = "utf8_decode_error"
        record["read"] = False
        add_django_finding(
            analysis,
            "django_config_file_decode_error",
            "Config file is not valid UTF-8 text",
            "low",
            "A candidate Django configuration file could not be decoded as UTF-8 text.",
            f"{path}: {exc}",
            "Review this file manually before relying on the static analysis result.",
            file_path=path,
        )
        return

    _redacted_text, redacted_count = redact_django_secret_text(text)
    summary["secrets_redacted_count"] += redacted_count
    analyze_django_config_text(analysis, path, category, text)


def classify_django_config_candidate(path: str) -> str | None:
    normalized = normalize_archive_entry_path(path)
    basename = normalized.rsplit("/", 1)[-1]
    basename_lower = basename.lower()
    parts = [part.lower() for part in normalized.split("/") if part]

    if is_django_env_template_name(basename_lower):
        return "env_template"
    if is_django_sensitive_env_name(basename_lower):
        return "env_sensitive"
    if basename in {"Dockerfile", "Procfile"} or basename_lower in {"dockerfile", "procfile", "docker-compose.yml", "compose.yml", "nginx.conf", "gunicorn.conf.py"}:
        return "deployment"
    if basename_lower.endswith(".service"):
        return "deployment"
    if len(parts) >= 2 and parts[-2] == "nginx" and basename_lower.endswith(".conf"):
        return "deployment"
    if basename_lower in {"requirements.txt", "pyproject.toml", "pipfile", "poetry.lock", "package.json"}:
        return "dependencies"
    if basename_lower in {"manage.py", "urls.py", "wsgi.py", "asgi.py", "settings.py"}:
        return "django_config"
    if len(parts) >= 2 and parts[-2] == "settings" and basename_lower.endswith(".py"):
        return "django_config"
    if len(parts) >= 3 and parts[-3:-1] == ["config", "settings"] and basename_lower.endswith(".py"):
        return "django_config"
    return None


def is_django_env_template_name(basename: str) -> bool:
    if basename in {"env.example", "env.template", "env.sample", "sample.env"}:
        return True
    return basename.startswith(".env") and any(marker in basename for marker in ("example", "sample", "template"))


def is_django_sensitive_env_name(basename: str) -> bool:
    return basename == ".env" or basename == ".envrc" or basename.startswith(".env.")


def normalize_archive_entry_path(path: str) -> str:
    normalized = path.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized.lstrip("/")


def increment_django_category_counts(summary: dict[str, Any], category: str, path: str) -> None:
    basename = normalize_archive_entry_path(path).rsplit("/", 1)[-1].lower()
    if category == "django_config" and ("settings" in basename or "/settings/" in normalize_archive_entry_path(path).lower()):
        summary["settings_files_detected"] += 1
    if category == "deployment":
        summary["deployment_files_detected"] += 1
    if category in {"env_template", "env_sensitive"}:
        summary["env_files_detected"] += 1
    if category == "dependencies":
        summary["dependency_files_detected"] += 1


def django_config_skip_reason(record: dict[str, Any], state: dict[str, int]) -> str | None:
    flags = as_dict(record.get("flags"))
    path = str(record["path"])
    size_bytes = int(record.get("size_bytes") or 0)
    if record.get("category") == "env_sensitive":
        return "sensitive_env_not_read"
    if flags.get("path_traversal"):
        return "path_traversal"
    if flags.get("absolute_path") or flags.get("windows_absolute_path"):
        return "absolute_path"
    if record.get("entry_type") != "file":
        return f"not_regular_file:{record.get('entry_type')}"
    if len(path) > ARCHIVE_MAX_ENTRY_NAME_LENGTH:
        return "entry_name_too_long"
    if size_bytes > state["max_file_bytes"]:
        return "file_too_large"
    if state["files_read"] >= state["max_files"]:
        return "too_many_files"
    if state["total_bytes_read"] + size_bytes > state["max_total_bytes"]:
        return "total_bytes_limit"
    return None


def add_django_skip_finding(analysis: dict[str, Any], path: str, reason: str, size_bytes: int) -> None:
    if reason == "sensitive_env_not_read":
        add_django_finding(
            analysis,
            "django_config_env_file_present",
            "Sensitive .env file detected but not read",
            "low",
            "A real .env file was present inside the archive. Inspectra records its presence but does not read the content in this phase.",
            path,
            "Avoid sharing real environment files and review whether this archive should include local secrets.",
            file_path=path,
        )
        return
    if reason in {"file_too_large", "too_many_files", "total_bytes_limit"}:
        analysis["summary"]["truncated"] = True
    titles = {
        "path_traversal": "Config file path uses traversal",
        "absolute_path": "Config file path is absolute",
        "entry_name_too_long": "Config file entry name is unusually long",
        "file_too_large": "Config file omitted because it exceeds the size limit",
        "too_many_files": "Django config file limit reached",
        "total_bytes_limit": "Total Django config byte limit reached",
    }
    level = "medium" if reason in {"path_traversal", "absolute_path", "file_too_large", "too_many_files", "total_bytes_limit"} else "low"
    evidence = f"{path}: {size_bytes} bytes" if reason == "file_too_large" else path[:240]
    if reason.startswith("not_regular_file"):
        title = "Config file omitted because it is not a regular file"
        evidence = f"{path}: {reason}"
        level = "low"
    else:
        title = titles.get(reason, "Config file skipped by defensive limit")
    add_django_finding(
        analysis,
        f"django_config_{reason.split(':', 1)[0]}",
        title,
        level,
        "Inspectra detected a Django-related file but did not read it because of a defensive limit or unsafe archive metadata.",
        evidence,
        "Review the archive manually in a constrained environment if this file is expected.",
        file_path=path,
    )


def analyze_django_config_text(analysis: dict[str, Any], path: str, category: str, text: str) -> None:
    if category == "django_config":
        analyze_django_settings_text(analysis, path, text)
    elif category == "dependencies":
        analyze_django_dependency_text(analysis, path, text)
    elif category == "deployment":
        analyze_django_deployment_text(analysis, path, text)
    elif category == "env_template":
        note_signal(analysis, "deployment", "env_templates", path)


LOWER_CONFIDENCE_DJANGO_CONTEXTS = {"development", "test", "local", "example"}


def django_active_config_text(text: str) -> str:
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


def django_file_context(path: str) -> str:
    normalized = normalize_archive_entry_path(path).lower()
    parts = [part for part in normalized.split("/") if part]
    basename = parts[-1] if parts else normalized
    stem = basename.rsplit(".", 1)[0]
    directories = set(parts[:-1])

    if basename == "conftest.py" or stem in {"test", "tests"} or directories.intersection({"test", "tests"}):
        return "test"
    if directories.intersection({"docs", "doc", "examples", "example", "samples", "sample"}) or stem in {"example", "sample"}:
        return "example"
    if stem in {"dev", "development"} or directories.intersection({"dev", "development"}):
        return "development"
    if stem == "local" or "local" in directories:
        return "local"
    if stem in {"prod", "production"} or directories.intersection({"prod", "production"}):
        return "production"
    if basename == "settings.py" or stem == "base":
        return "shared"
    return "ambiguous"


def django_contextual_level(level: str, context: str) -> str:
    if context in LOWER_CONFIDENCE_DJANGO_CONTEXTS and level in {"medium", "low"}:
        return "info"
    return level


def contextual_setting_evidence(setting_name: str, value: str, context: str) -> str:
    evidence = safe_setting_evidence(setting_name, value)
    if context:
        return f"{evidence} (context: {context})"
    return evidence


def analyze_django_settings_text(analysis: dict[str, Any], path: str, text: str) -> None:
    active_text = django_active_config_text(text)
    lowered = active_text.lower()
    context = django_file_context(path)
    if re.search(r"(?im)^\s*DEBUG\s*=\s*True\b", active_text) or re.search(r"(?i)DEBUG[^\n#]*(?:default\s*=\s*True|default:\s*True)", active_text):
        update_signal(analysis, "debug", "enabled_or_default_true", path)
        add_django_finding(
            analysis,
            "django_debug_enabled",
            "Django DEBUG appears enabled or defaults to true",
            django_contextual_level("medium", context),
            "A settings file appears to enable DEBUG or use an insecure default.",
            contextual_setting_evidence("DEBUG", "True/default=True", context),
            "Ensure DEBUG is false in production and controlled by deployment-specific configuration.",
            file_path=path,
            context=context,
        )
    elif re.search(r"(?im)^\s*DEBUG\s*=\s*False\b", active_text):
        update_signal(analysis, "debug", "disabled_literal", path)

    if re.search(r"(?im)^\s*SECRET_KEY\s*=\s*['\"][^'\"]{8,}['\"]", active_text):
        update_signal(analysis, "secret_key", "hardcoded", path)
        add_django_finding(
            analysis,
            "django_secret_key_hardcoded",
            "Django SECRET_KEY appears hardcoded",
            django_contextual_level("medium", context),
            "A settings file appears to assign SECRET_KEY directly to a string literal.",
            contextual_setting_evidence("SECRET_KEY", "[REDACTED]", context),
            "Load SECRET_KEY from a protected environment secret without committing the value.",
            file_path=path,
            context=context,
        )
    elif re.search(r"(?is)SECRET_KEY[^\n]*(?:get|config|env)\([^)\n]*,\s*['\"][^'\"]+['\"]", active_text) or re.search(
        r"(?is)SECRET_KEY[^\n]*(?:default\s*=\s*['\"][^'\"]+['\"])", active_text
    ):
        update_signal(analysis, "secret_key", "fallback_hardcoded", path)
        add_django_finding(
            analysis,
            "django_secret_key_fallback_hardcoded",
            "Django SECRET_KEY has a hardcoded fallback",
            django_contextual_level("medium", context),
            "A settings file appears to read SECRET_KEY from configuration but provide a string fallback.",
            contextual_setting_evidence("SECRET_KEY", "[REDACTED fallback]", context),
            "Avoid production fallbacks for SECRET_KEY; fail closed when the secret is absent.",
            file_path=path,
            context=context,
        )
    elif "secret_key" in lowered:
        update_signal(analysis, "secret_key", "referenced", path)

    if re.search(r"(?is)ALLOWED_HOSTS\s*=\s*\[[^\]]*['\"]\*['\"]", active_text) or re.search(
        r"(?is)ALLOWED_HOSTS\s*=\s*\[[^\]]*['\"]0\.0\.0\.0['\"]", active_text
    ):
        update_signal(analysis, "allowed_hosts", "wildcard", path)
        add_django_finding(
            analysis,
            "django_allowed_hosts_wildcard",
            "Django ALLOWED_HOSTS appears overly broad",
            django_contextual_level("medium", context),
            "ALLOWED_HOSTS appears to include a wildcard or 0.0.0.0.",
            contextual_setting_evidence("ALLOWED_HOSTS", "[REDACTED broad host list]", context),
            "Use explicit production hostnames and review environment-specific host handling.",
            file_path=path,
            context=context,
        )
    elif re.search(r"(?im)^\s*ALLOWED_HOSTS\s*=\s*\[\s*\]", active_text):
        update_signal(analysis, "allowed_hosts", "empty_literal", path)
        add_django_finding(
            analysis,
            "django_allowed_hosts_empty",
            "Django ALLOWED_HOSTS appears empty",
            django_contextual_level("low", context),
            "ALLOWED_HOSTS is an empty literal in a settings file. This may be intentional for development but should be reviewed for deployment.",
            contextual_setting_evidence("ALLOWED_HOSTS", "[]", context),
            "Confirm production settings provide explicit hostnames.",
            file_path=path,
            context=context,
        )
    elif "allowed_hosts" in lowered:
        update_signal(analysis, "allowed_hosts", "referenced", path)

    analyze_django_cookie_settings(analysis, path, active_text, context)
    analyze_django_https_settings(analysis, path, active_text, context)
    analyze_django_header_settings(analysis, path, active_text, context)
    analyze_django_database_settings(analysis, path, active_text, context)
    analyze_django_static_media_settings(analysis, path, active_text)
    analyze_django_cors_settings(analysis, path, active_text, context)


def analyze_django_cookie_settings(analysis: dict[str, Any], path: str, text: str, context: str) -> None:
    for setting_name in ("CSRF_COOKIE_SECURE", "SESSION_COOKIE_SECURE"):
        if re.search(rf"(?im)^\s*{setting_name}\s*=\s*True\b", text):
            note_signal(analysis, "cookies", setting_name.lower(), path, "true")
        else:
            record_django_missing_setting(
                analysis,
                f"django_{setting_name.lower()}_not_true",
                f"{setting_name} was not observed as true",
                "low",
                f"Inspectra did not observe {setting_name} = True in this settings file.",
                safe_setting_evidence(setting_name, "not observed as True"),
                "Confirm secure cookie settings in the production settings module.",
                file_path=path,
                context=context,
            )
    for setting_name in ("CSRF_COOKIE_HTTPONLY", "SESSION_COOKIE_HTTPONLY", "CSRF_COOKIE_SAMESITE", "SESSION_COOKIE_SAMESITE"):
        if setting_name.lower() in text.lower():
            note_signal(analysis, "cookies", setting_name.lower(), path, "referenced")
    if re.search(r"(?is)CSRF_TRUSTED_ORIGINS\s*=\s*\[[^\]]*['\"]http://", text) or re.search(
        r"(?is)CSRF_TRUSTED_ORIGINS\s*=\s*\[[^\]]*['\"][^'\"]*\*[^'\"]*['\"]", text
    ):
        add_django_finding(
            analysis,
            "django_csrf_trusted_origins_broad_or_http",
            "CSRF trusted origins may be broad or use HTTP",
            django_contextual_level("low", context),
            "CSRF_TRUSTED_ORIGINS appears to include HTTP or wildcard-like origins.",
            contextual_setting_evidence("CSRF_TRUSTED_ORIGINS", "[REDACTED origins]", context),
            "Review CSRF trusted origins for production HTTPS origins only.",
            file_path=path,
            context=context,
        )


def analyze_django_https_settings(analysis: dict[str, Any], path: str, text: str, context: str) -> None:
    if re.search(r"(?im)^\s*SECURE_SSL_REDIRECT\s*=\s*True\b", text):
        note_signal(analysis, "https_security", "secure_ssl_redirect", path, "true")
    else:
        record_django_missing_setting(
            analysis,
            "django_secure_ssl_redirect_not_true",
            "SECURE_SSL_REDIRECT was not observed as true",
            "low",
            "Inspectra did not observe SECURE_SSL_REDIRECT = True in this settings file.",
            safe_setting_evidence("SECURE_SSL_REDIRECT", "not observed as True"),
            "Confirm HTTPS redirect behavior at Django or the reverse proxy for production.",
            file_path=path,
            context=context,
        )
    hsts_match = re.search(r"(?im)^\s*SECURE_HSTS_SECONDS\s*=\s*(\d+)", text)
    if not hsts_match or int(hsts_match.group(1)) == 0:
        record_django_missing_setting(
            analysis,
            "django_hsts_missing_or_zero",
            "HSTS setting was not observed or appears disabled",
            "info",
            "SECURE_HSTS_SECONDS was absent or set to zero in a settings file.",
            safe_setting_evidence("SECURE_HSTS_SECONDS", hsts_match.group(1) if hsts_match else "not observed"),
            "Enable HSTS only after validating HTTPS is consistently available.",
            file_path=path,
            context=context,
        )
    for setting_name in ("SECURE_HSTS_INCLUDE_SUBDOMAINS", "SECURE_HSTS_PRELOAD", "SECURE_PROXY_SSL_HEADER", "USE_X_FORWARDED_HOST"):
        if setting_name.lower() in text.lower():
            note_signal(analysis, "https_security", setting_name.lower(), path, "referenced")


def analyze_django_header_settings(analysis: dict[str, Any], path: str, text: str, context: str) -> None:
    if re.search(r"(?im)^\s*SECURE_CONTENT_TYPE_NOSNIFF\s*=\s*False\b", text):
        add_django_finding(
            analysis,
            "django_content_type_nosniff_false",
            "SECURE_CONTENT_TYPE_NOSNIFF appears disabled",
            django_contextual_level("low", context),
            "A settings file explicitly sets SECURE_CONTENT_TYPE_NOSNIFF to False.",
            contextual_setting_evidence("SECURE_CONTENT_TYPE_NOSNIFF", "False", context),
            "Use the Django default or explicitly enable nosniff protection.",
            file_path=path,
            context=context,
        )
    if not re.search(r"(?im)^\s*X_FRAME_OPTIONS\s*=", text):
        record_django_missing_setting(
            analysis,
            "django_x_frame_options_not_observed",
            "X_FRAME_OPTIONS was not observed",
            "info",
            "Inspectra did not observe an explicit X_FRAME_OPTIONS setting.",
            safe_setting_evidence("X_FRAME_OPTIONS", "not observed"),
            "Confirm clickjacking protections are covered by Django defaults or deployment headers.",
            file_path=path,
            context=context,
        )
    if "secure_referrer_policy" in text.lower():
        note_signal(analysis, "https_security", "secure_referrer_policy", path, "referenced")


def analyze_django_database_settings(analysis: dict[str, Any], path: str, text: str, context: str) -> None:
    lowered = text.lower()
    if "databases" not in lowered:
        return
    update_signal(analysis, "database", "referenced", path)
    if "sqlite3" in lowered:
        note_signal(analysis, "database", "sqlite_detected", path, "true")
        add_django_finding(
            analysis,
            "django_sqlite_detected",
            "SQLite database configuration detected",
            django_contextual_level("info", context),
            "SQLite appears in DATABASES. This can be appropriate for development but should be reviewed for production VPS deployments.",
            contextual_setting_evidence("DATABASES", "sqlite3", context),
            "Confirm the production database engine is intentional.",
            file_path=path,
            context=context,
        )
    if re.search(r"(?is)['\"]PASSWORD['\"]\s*:\s*['\"][^'\"]+['\"]", text) or re.search(
        r"(?im)^\s*(?:DB_)?PASSWORD\s*=\s*['\"][^'\"]+['\"]", text
    ):
        update_signal(analysis, "database", "hardcoded_password", path)
        add_django_finding(
            analysis,
            "django_database_password_hardcoded",
            "Database password appears hardcoded",
            django_contextual_level("medium", context),
            "A database password-like value appears hardcoded in configuration text.",
            contextual_setting_evidence("DATABASES.PASSWORD", "[REDACTED]", context),
            "Load database credentials from protected runtime secrets.",
            file_path=path,
            context=context,
        )


def analyze_django_static_media_settings(analysis: dict[str, Any], path: str, text: str) -> None:
    for setting_name in ("STATIC_ROOT", "STATIC_URL", "MEDIA_ROOT", "MEDIA_URL"):
        if setting_name.lower() in text.lower():
            note_signal(analysis, "static_media", setting_name.lower(), path, "referenced")
    if "whitenoise" in text.lower():
        note_signal(analysis, "static_media", "whitenoise", path, "referenced")


def analyze_django_cors_settings(analysis: dict[str, Any], path: str, text: str, context: str) -> None:
    if re.search(r"(?im)^\s*CORS_ALLOW_ALL_ORIGINS\s*=\s*True\b", text) or re.search(
        r"(?im)^\s*CORS_ORIGIN_ALLOW_ALL\s*=\s*True\b", text
    ) or re.search(r"(?is)CORS_ALLOWED_ORIGINS\s*=\s*\[[^\]]*['\"]\*['\"]", text):
        update_signal(analysis, "cors", "allow_all", path)
        add_django_finding(
            analysis,
            "django_cors_allow_all",
            "CORS configuration appears overly permissive",
            django_contextual_level("medium", context),
            "CORS settings appear to allow all origins.",
            contextual_setting_evidence("CORS", "[REDACTED broad origin policy]", context),
            "Restrict CORS origins to the expected frontend origins for production.",
            file_path=path,
            context=context,
        )
    elif "cors_" in text.lower():
        update_signal(analysis, "cors", "referenced", path)


def analyze_django_dependency_text(analysis: dict[str, Any], path: str, text: str) -> None:
    basename = normalize_archive_entry_path(path).rsplit("/", 1)[-1].lower()
    if re.search(r"(?im)^\s*django(?:[<>=~! ]|$)", text) or "django" in text.lower():
        note_signal(analysis, "deployment", "django_dependency_detected", path, "true")
    if basename == "package.json":
        note_signal(analysis, "deployment", "package_json_present", path, "true")


def analyze_django_deployment_text(analysis: dict[str, Any], path: str, text: str) -> None:
    basename = normalize_archive_entry_path(path).rsplit("/", 1)[-1].lower()
    note_signal(analysis, "deployment", basename.replace(".", "_").replace("-", "_"), path, "present")
    active_text = django_active_config_text(text)
    lowered = active_text.lower()
    if "runserver" in lowered:
        add_django_finding(
            analysis,
            "django_deployment_runserver_detected",
            "Django development server command detected",
            "medium",
            "A deployment file appears to run Django with manage.py runserver.",
            "manage.py runserver",
            "Use a production WSGI/ASGI server such as gunicorn or uvicorn behind a reverse proxy.",
            file_path=path,
        )
    if "gunicorn" in lowered or "uvicorn" in lowered:
        note_signal(analysis, "deployment", "production_server_hint", path, "present")
    if re.search(r"(?im)^\s*DEBUG\s*=\s*True\b|DEBUG=True", active_text):
        add_django_finding(
            analysis,
            "django_deployment_debug_env_true",
            "Deployment file sets DEBUG=True",
            "medium",
            "A deployment file appears to set DEBUG=True.",
            safe_setting_evidence("DEBUG", "True"),
            "Ensure production deployment variables set DEBUG=False.",
            file_path=path,
        )
    if re.search(r"(?im)SECRET_KEY\s*[:=]\s*[^$\s][^\n]+", active_text):
        add_django_finding(
            analysis,
            "django_deployment_secret_key_hardcoded",
            "Deployment file appears to contain SECRET_KEY",
            "medium",
            "A deployment file appears to contain a SECRET_KEY value rather than only referencing an external secret.",
            safe_setting_evidence("SECRET_KEY", "[REDACTED]"),
            "Move secrets to protected runtime secret storage or an uncommitted environment file.",
            file_path=path,
        )
    if "env_file" in lowered and ".env" in lowered:
        add_django_finding(
            analysis,
            "django_deployment_env_file_reference",
            "Deployment references an .env file",
            "info",
            "A deployment file references an .env file. Inspectra does not read real .env content.",
            ".env reference",
            "Confirm the referenced environment file is not committed with secrets.",
            file_path=path,
        )
    if basename in {"docker-compose.yml", "compose.yml"}:
        for port in ("5432", "3306", "6379"):
            if re.search(rf"(?m)['\"]?\d*:?{port}:{port}['\"]?", active_text):
                add_django_finding(
                    analysis,
                    f"django_compose_exposes_{port}",
                    f"docker-compose exposes service port {port}",
                    "low",
                    "docker-compose appears to publish a database or cache service port on the host.",
                    f"{port}:{port}",
                    "Confirm the service should be exposed outside the Compose network.",
                    file_path=path,
                )


def update_signal(analysis: dict[str, Any], group: str, status_value: str, path: str) -> None:
    signal = as_dict(analysis["django_signals"].setdefault(group, {}))
    signal["status"] = status_value
    files = signal.setdefault("files", [])
    if isinstance(files, list) and path not in files:
        files.append(path)
    analysis["django_signals"][group] = signal


def note_signal(analysis: dict[str, Any], group: str, key: str, path: str, value: str = "observed") -> None:
    signal = as_dict(analysis["django_signals"].setdefault(group, {}))
    signal[key] = value
    files = signal.setdefault("files", [])
    if isinstance(files, list) and path not in files:
        files.append(path)
    analysis["django_signals"][group] = signal


def redact_django_secret_text(text: str) -> tuple[str, int]:
    redacted_lines: list[str] = []
    count = 0
    for line in text.splitlines():
        if django_line_contains_secret_key(line):
            redacted, changed = redact_django_secret_line(line)
            redacted_lines.append(redacted)
            count += int(changed)
        else:
            redacted_lines.append(line)
    return "\n".join(redacted_lines), count


def django_line_contains_secret_key(line: str) -> bool:
    return bool(re.search(r"(?i)(SECRET_KEY|PASSWORD|PASS|TOKEN|API_KEY|SECRET|DATABASE_URL|REDIS_URL|EMAIL_HOST_PASSWORD|AWS_SECRET_ACCESS_KEY|PRIVATE_KEY)", line))


def redact_django_secret_line(line: str) -> tuple[str, bool]:
    if "=" in line:
        key, _value = line.split("=", 1)
        return f"{key}= [REDACTED]", True
    if ":" in line:
        key, _value = line.split(":", 1)
        return f"{key}: [REDACTED]", True
    return "[REDACTED]", True


def safe_setting_evidence(setting_name: str, value: str) -> str:
    return f"{setting_name} = {value}"


def record_django_missing_setting(
    analysis: dict[str, Any],
    finding_id: str,
    title: str,
    level: str,
    description: str,
    evidence: str,
    recommendation: str,
    *,
    file_path: str,
    context: str,
) -> None:
    observations = as_dict(analysis.setdefault("_missing_setting_observations", {}))
    observation = as_dict(observations.get(finding_id))
    if not observation:
        observation = {
            "id": finding_id,
            "title": title,
            "level": level,
            "description": description,
            "evidence": evidence,
            "recommendation": recommendation,
            "files": [],
            "contexts": [],
        }
    files = observation.setdefault("files", [])
    if isinstance(files, list) and file_path not in files:
        files.append(file_path)
    contexts = observation.setdefault("contexts", [])
    if isinstance(contexts, list) and context not in contexts:
        contexts.append(context)
    observations[finding_id] = observation
    analysis["_missing_setting_observations"] = observations


def add_grouped_django_missing_setting_findings(analysis: dict[str, Any]) -> None:
    observations = as_dict(analysis.get("_missing_setting_observations"))
    for observation in observations.values():
        if not isinstance(observation, dict):
            continue
        files = [str(item) for item in observation.get("files", []) if isinstance(item, str)]
        contexts = [str(item) for item in observation.get("contexts", []) if isinstance(item, str)]
        if not files:
            continue
        context_set = set(contexts)
        base_level = str(observation.get("level") or "info")
        level = "info" if context_set and context_set.issubset(LOWER_CONFIDENCE_DJANGO_CONTEXTS) else base_level
        file_preview = ", ".join(files[:8])
        if len(files) > 8:
            file_preview = f"{file_preview}, ... (+{len(files) - 8} more)"
        context_preview = ", ".join(sorted(context_set)) if context_set else "unknown"
        description = str(observation.get("description") or "")
        if len(files) > 1:
            description = f"{description} This finding is grouped across {len(files)} inspected settings files to reduce duplicate noise."
        if context_set and context_set.issubset(LOWER_CONFIDENCE_DJANGO_CONTEXTS):
            description = f"{description} The observed files appear to be development, test, local, or example settings, so Inspectra reports this as lower-confidence review context."
        add_django_finding(
            analysis,
            str(observation.get("id") or "django_setting_not_observed"),
            str(observation.get("title") or "Django setting was not observed"),
            level,
            description,
            f"{observation.get('evidence')}; files: {file_preview}; contexts: {context_preview}",
            str(observation.get("recommendation") or "Review the relevant production settings manually."),
            context="grouped",
        )


def add_django_finding(
    analysis: dict[str, Any],
    finding_id: str,
    title: str,
    level: str,
    description: str,
    evidence: str,
    recommendation: str,
    *,
    file_path: str | None = None,
    context: str | None = None,
) -> None:
    finding = make_finding(finding_id, title, level, description, evidence, recommendation)
    if file_path:
        finding["file_path"] = file_path
    if context:
        finding["context"] = context
    analysis["findings"].append(finding)


def finalize_django_config_analysis(analysis: dict[str, Any]) -> None:
    add_grouped_django_missing_setting_findings(analysis)
    analysis.pop("_missing_setting_observations", None)
    if analysis["summary"]["settings_files_detected"] == 0:
        add_django_finding(
            analysis,
            "django_settings_not_detected",
            "Django settings file was not detected",
            "info",
            "Inspectra did not detect a settings.py or settings package in the archive candidates it inspected.",
            "settings.py not observed",
            "Confirm the archive contains the intended Django configuration files.",
        )
    analysis["findings"] = dedupe_findings(analysis["findings"])
    analysis["summary"]["findings_count"] = len(analysis["findings"])


def docker_config_limits(request: ArchiveAnalysisRequest) -> dict[str, int]:
    max_files = DOCKER_CONFIG_MAX_FILES if request.max_files is None else request.max_files
    max_file_bytes = DOCKER_CONFIG_MAX_FILE_BYTES if request.max_file_bytes is None else request.max_file_bytes
    max_total_bytes = DOCKER_CONFIG_MAX_TOTAL_BYTES if request.max_total_bytes is None else request.max_total_bytes
    if max_files <= 0 or max_file_bytes <= 0 or max_total_bytes <= 0:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Docker config analysis limits must be positive.")
    return {"max_files": max_files, "max_file_bytes": max_file_bytes, "max_total_bytes": max_total_bytes}


def analyze_docker_config_archive(
    path: Path,
    archive_type: str,
    *,
    max_files: int,
    max_file_bytes: int,
    max_total_bytes: int,
) -> dict[str, Any]:
    analysis = empty_docker_config_analysis()
    state = {
        "files_read": 0,
        "total_bytes_read": 0,
        "max_files": max_files,
        "max_file_bytes": max_file_bytes,
        "max_total_bytes": max_total_bytes,
    }

    if archive_type == "zip":
        preflight = inspect_zip_metadata_preflight(path)
        blocked_reason = zip_preflight_block_reason(preflight, ARCHIVE_MAX_ENTRIES)
        add_zip_preflight_summary(analysis["summary"], preflight)
        if blocked_reason:
            analysis["summary"]["truncated"] = True
            finding = zip_preflight_finding(blocked_reason, preflight, ARCHIVE_MAX_ENTRIES)
            scoped = dict(finding)
            scoped["id"] = f"docker_config_{scoped['id']}"
            analysis["findings"].append(scoped)
            finalize_docker_config_analysis(analysis)
            return analysis
        with zipfile.ZipFile(path) as archive:
            for index, info in enumerate(archive.filelist, start=1):
                if should_stop_docker_archive_scan(index, analysis):
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
                process_docker_config_entry(
                    analysis,
                    state,
                    entry,
                    lambda entry_info=info: archive.open(entry_info),
                )
    else:
        with tarfile.open(path, "r:*") as archive:
            for index, member in enumerate(archive, start=1):
                if should_stop_docker_archive_scan(index, analysis):
                    break
                entry = {
                    "path": member.name,
                    "type": tar_member_type(member),
                    "size": member.size,
                    "mode_int": member.mode,
                    "mode": format_file_mode(member.mode),
                    "link_target": member.linkname or None,
                }
                process_docker_config_entry(
                    analysis,
                    state,
                    entry,
                    lambda tar_member=member: archive.extractfile(tar_member),
                )

    finalize_docker_config_analysis(analysis)
    return analysis


def empty_docker_config_analysis(errors: list[str] | None = None) -> dict[str, Any]:
    return {
        "summary": {
            "files_considered": 0,
            "files_reviewed": 0,
            "dockerfiles_detected": 0,
            "compose_files_detected": 0,
            "dockerignore_files_detected": 0,
            "services_detected": 0,
            "findings_count": 0,
            "secrets_redacted_count": 0,
            "truncated": False,
        },
        "files_detected": [],
        "files_reviewed": [],
        "dockerfile_stages": [],
        "compose_services": [],
        "findings": [],
        "redaction_notes": [],
        "errors": errors or [],
    }


def build_docker_config_result(
    file_id: str,
    path: Path,
    original_filename: str,
    archive_type: str,
    analysis: dict[str, Any],
    *,
    max_files: int,
    max_file_bytes: int,
    max_total_bytes: int,
) -> dict[str, Any]:
    summary = as_dict(analysis.get("summary"))
    findings = analysis.get("findings") if isinstance(analysis.get("findings"), list) else []
    summary["findings_count"] = len(findings)
    return {
        "file_id": file_id,
        "analyzer": "docker_config_basic",
        "archive_type": archive_type,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "hashes": calculate_hashes(path),
        "file_identification": {
            "size_bytes": path.stat().st_size,
            "original_filename": original_filename,
        },
        "limits": {
            "max_files": max_files,
            "max_file_bytes": max_file_bytes,
            "max_total_bytes": max_total_bytes,
            "max_archive_entries": ARCHIVE_MAX_ENTRIES,
            "max_entry_name_length": ARCHIVE_MAX_ENTRY_NAME_LENGTH,
            "max_zip_central_directory_bytes": ARCHIVE_MAX_ZIP_CENTRAL_DIRECTORY_BYTES,
        },
        "summary": summary,
        "files_detected": analysis.get("files_detected", []),
        "files_reviewed": analysis.get("files_reviewed", []),
        "dockerfile_stages": analysis.get("dockerfile_stages", []),
        "compose_services": analysis.get("compose_services", []),
        "findings": findings,
        "redaction_notes": analysis.get("redaction_notes", []),
        "errors": analysis.get("errors", []),
        "truncated": bool(summary.get("truncated")),
    }


def should_stop_docker_archive_scan(index: int, analysis: dict[str, Any]) -> bool:
    summary = as_dict(analysis["summary"])
    if index > ARCHIVE_MAX_ENTRIES:
        summary["truncated"] = True
        add_docker_finding(
            analysis,
            "docker_config_entry_limit_reached",
            "Archive entry scan limit reached",
            "medium",
            "Inspectra stopped scanning archive metadata after the configured entry limit.",
            f"Processed {ARCHIVE_MAX_ENTRIES} entries.",
            "Review the archive with stricter limits or split it before deeper inspection.",
        )
        return True
    return False


def process_docker_config_entry(
    analysis: dict[str, Any],
    state: dict[str, int],
    entry: dict[str, Any],
    open_entry,
) -> None:
    path = str(entry["path"])
    category = classify_docker_config_candidate(path)
    if category is None:
        return

    summary = as_dict(analysis["summary"])
    summary["files_considered"] += 1
    increment_docker_category_counts(summary, category)

    entry_type = str(entry["type"])
    size_bytes = int(entry.get("size") or 0)
    context = docker_file_context(path)
    flags, depth = archive_entry_flags(path, entry.get("mode_int"))
    record = {
        "path": path,
        "category": category,
        "context": context,
        "entry_type": entry_type,
        "size_bytes": size_bytes,
        "mode": entry.get("mode"),
        "depth": depth,
        "flags": flags,
        "read": False,
        "skip_reason": None,
    }
    if entry.get("link_target"):
        record["link_target"] = entry["link_target"]

    skip_reason = docker_config_skip_reason(record, state)
    if skip_reason:
        record["skip_reason"] = skip_reason
        analysis["files_detected"].append(record)
        add_docker_skip_finding(analysis, path, skip_reason, size_bytes, context)
        return

    try:
        stream = open_entry()
        if stream is None:
            raise ValueError("entry could not be opened as a regular file")
        with stream:
            raw_bytes = read_limited_stream(stream, state["max_file_bytes"])
    except (OSError, ValueError, zipfile.BadZipFile, tarfile.TarError) as exc:
        record["skip_reason"] = "read_error"
        analysis["files_detected"].append(record)
        add_docker_finding(
            analysis,
            "docker_config_file_read_error",
            "Docker config file could not be read safely",
            "low",
            "A candidate Docker configuration file could not be read from the archive within Inspectra limits.",
            f"{path}: {exc}",
            "Review this file manually in a constrained environment if it is expected.",
            file_path=path,
            context=context,
        )
        return

    state["files_read"] += 1
    state["total_bytes_read"] += len(raw_bytes)
    summary["files_reviewed"] = state["files_read"]
    record["read"] = True
    record["bytes_read"] = len(raw_bytes)
    analysis["files_detected"].append(record)
    analysis["files_reviewed"].append(
        {"path": path, "category": category, "context": context, "size_bytes": size_bytes, "bytes_read": len(raw_bytes)}
    )

    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        record["skip_reason"] = "utf8_decode_error"
        record["read"] = False
        add_docker_finding(
            analysis,
            "docker_config_file_decode_error",
            "Docker config file is not valid UTF-8 text",
            "low",
            "A candidate Docker configuration file could not be decoded as UTF-8 text.",
            f"{path}: {exc}",
            "Review this file manually before relying on the static analysis result.",
            file_path=path,
            context=context,
        )
        return

    _redacted_text, redacted_count = redact_django_secret_text(text)
    summary["secrets_redacted_count"] += redacted_count
    analyze_docker_config_text(analysis, path, category, context, text)


def classify_docker_config_candidate(path: str) -> str | None:
    normalized = normalize_archive_entry_path(path)
    basename = normalized.rsplit("/", 1)[-1]
    basename_lower = basename.lower()
    if basename == "Dockerfile" or basename_lower.startswith("dockerfile."):
        return "dockerfile"
    if basename_lower == ".dockerignore":
        return "dockerignore"
    if is_docker_compose_filename(basename_lower):
        return "compose"
    return None


def is_docker_compose_filename(basename: str) -> bool:
    if basename in {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}:
        return True
    return bool(re.match(r"^(?:docker-)?compose\.[a-z0-9_.-]+\.(?:ya?ml)$", basename))


def increment_docker_category_counts(summary: dict[str, Any], category: str) -> None:
    if category == "dockerfile":
        summary["dockerfiles_detected"] += 1
    elif category == "compose":
        summary["compose_files_detected"] += 1
    elif category == "dockerignore":
        summary["dockerignore_files_detected"] += 1


def docker_config_skip_reason(record: dict[str, Any], state: dict[str, int]) -> str | None:
    flags = as_dict(record.get("flags"))
    path = str(record["path"])
    size_bytes = int(record.get("size_bytes") or 0)
    if flags.get("path_traversal"):
        return "path_traversal"
    if flags.get("absolute_path") or flags.get("windows_absolute_path"):
        return "absolute_path"
    if record.get("entry_type") != "file":
        return f"not_regular_file:{record.get('entry_type')}"
    if len(path) > ARCHIVE_MAX_ENTRY_NAME_LENGTH:
        return "entry_name_too_long"
    if size_bytes > state["max_file_bytes"]:
        return "file_too_large"
    if state["files_read"] >= state["max_files"]:
        return "too_many_files"
    if state["total_bytes_read"] + size_bytes > state["max_total_bytes"]:
        return "total_bytes_limit"
    return None


def add_docker_skip_finding(analysis: dict[str, Any], path: str, reason: str, size_bytes: int, context: str) -> None:
    if reason in {"file_too_large", "too_many_files", "total_bytes_limit"}:
        analysis["summary"]["truncated"] = True
    titles = {
        "path_traversal": "Docker config path uses traversal",
        "absolute_path": "Docker config path is absolute",
        "entry_name_too_long": "Docker config entry name is unusually long",
        "file_too_large": "Docker config file omitted because it exceeds the size limit",
        "too_many_files": "Docker config file limit reached",
        "total_bytes_limit": "Total Docker config byte limit reached",
    }
    level = "medium" if reason in {"path_traversal", "absolute_path", "file_too_large", "too_many_files", "total_bytes_limit"} else "low"
    evidence = f"{path}: {size_bytes} bytes" if reason == "file_too_large" else path[:240]
    if reason.startswith("not_regular_file"):
        title = "Docker config file omitted because it is not a regular file"
        evidence = f"{path}: {reason}"
        level = "low"
    else:
        title = titles.get(reason, "Docker config file skipped by defensive limit")
    add_docker_finding(
        analysis,
        f"docker_config_{reason.split(':', 1)[0]}",
        title,
        level,
        "Inspectra detected a Docker-related file but did not read it because of a defensive limit or unsafe archive metadata.",
        evidence,
        "Review the archive manually in a constrained environment if this file is expected.",
        file_path=path,
        context=context,
    )


LOWER_CONFIDENCE_DOCKER_CONTEXTS = {"development", "test", "local", "example"}


def docker_file_context(path: str) -> str:
    normalized = normalize_archive_entry_path(path).lower()
    parts = [part for part in normalized.split("/") if part]
    basename = parts[-1] if parts else normalized
    directories = set(parts[:-1])
    name_tokens = set(re.split(r"[^a-z0-9]+", basename))
    all_tokens = set(parts[:-1]) | name_tokens

    if directories.intersection({"docs", "doc", "examples", "example", "samples", "sample"}) or all_tokens.intersection(
        {"example", "examples", "sample", "samples"}
    ):
        return "example"
    if all_tokens.intersection({"test", "tests", "testing"}):
        return "test"
    if "override" in name_tokens or all_tokens.intersection({"dev", "development"}):
        return "development"
    if "local" in all_tokens:
        return "local"
    if all_tokens.intersection({"prod", "production"}) or "deploy" in directories:
        return "production"
    if normalized in {"dockerfile", "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}:
        return "shared"
    return "ambiguous"


def docker_contextual_level(level: str, context: str) -> str:
    if context not in LOWER_CONFIDENCE_DOCKER_CONTEXTS:
        return level
    if level == "medium":
        return "low"
    if level == "low":
        return "info"
    return level


def docker_active_config_text(text: str) -> str:
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


def analyze_docker_config_text(analysis: dict[str, Any], path: str, category: str, context: str, text: str) -> None:
    if category == "dockerfile":
        analyze_dockerfile_text(analysis, path, context, text)
    elif category == "compose":
        analyze_docker_compose_text(analysis, path, context, text)


def analyze_dockerfile_text(analysis: dict[str, Any], path: str, context: str, text: str) -> None:
    active_text = docker_active_config_text(text)
    user_matches = re.findall(r"(?im)^\s*USER\s+([^\s#]+)", active_text)
    from_matches = list(re.finditer(r"(?im)^\s*FROM\s+([^\s#]+)(?:\s+AS\s+([^\s#]+))?", active_text))

    if not user_matches:
        add_docker_finding(
            analysis,
            "docker_missing_user_directive",
            "Dockerfile does not declare a USER",
            docker_contextual_level("low", context),
            "Inspectra did not observe a USER directive in this Dockerfile. Containers may run as the image default user.",
            docker_contextual_evidence("USER", "not observed", context),
            "Review whether the runtime image should set a non-root user.",
            file_path=path,
            context=context,
        )
    for user in user_matches:
        normalized_user = user.strip().strip("\"'").lower()
        if normalized_user in {"root", "0"}:
            add_docker_finding(
                analysis,
                "docker_runs_as_root",
                "Dockerfile declares root as runtime user",
                docker_contextual_level("medium", context),
                "A USER directive appears to select root. This is a review indicator, not a confirmed vulnerability.",
                docker_contextual_evidence("USER", "root", context),
                "Use a dedicated non-root runtime user where practical.",
                file_path=path,
                context=context,
            )

    for match in from_matches:
        image = match.group(1)
        stage = match.group(2) or None
        analysis["dockerfile_stages"].append(
            {
                "file_path": path,
                "context": context,
                "base_image": redact_docker_secret_text(image),
                "stage": stage,
                "user_observed": bool(user_matches),
                "healthcheck_observed": bool(re.search(r"(?im)^\s*HEALTHCHECK\b", active_text)),
            }
        )
        if docker_image_uses_latest_tag(image):
            add_docker_finding(
                analysis,
                "docker_latest_tag",
                "Docker base image uses latest tag",
                docker_contextual_level("low", context),
                "A FROM directive uses the mutable latest tag.",
                docker_contextual_evidence("FROM", redact_docker_secret_text(image), context),
                "Pin base images to an explicit version tag or digest when the deployment process requires repeatability.",
                file_path=path,
                context=context,
            )
        elif docker_image_unpinned(image):
            add_docker_finding(
                analysis,
                "docker_unpinned_base_image",
                "Docker base image is not pinned by tag or digest",
                docker_contextual_level("low", context),
                "A FROM directive does not include a tag or digest.",
                docker_contextual_evidence("FROM", redact_docker_secret_text(image), context),
                "Use an explicit version tag or digest where reproducible builds are expected.",
                file_path=path,
                context=context,
            )

    if re.search(r"(?is)\b(?:curl|wget)\b[^\n|]*\|[^\n]*(?:sh|bash)\b", active_text):
        add_docker_finding(
            analysis,
            "docker_suspicious_curl_pipe_shell",
            "Dockerfile pipes downloaded content to a shell",
            docker_contextual_level("medium", context),
            "A Dockerfile command appears to pipe curl or wget output directly to sh/bash.",
            docker_contextual_evidence("RUN", "curl/wget | sh/bash", context),
            "Prefer verified downloads and explicit checksums before executing installer scripts.",
            file_path=path,
            context=context,
        )


def docker_image_uses_latest_tag(image: str) -> bool:
    image_without_digest = image.split("@", 1)[0]
    return image_without_digest.lower().endswith(":latest")


def docker_image_unpinned(image: str) -> bool:
    if "@" in image:
        return False
    name = image.rsplit("/", 1)[-1]
    return ":" not in name


def analyze_docker_compose_text(analysis: dict[str, Any], path: str, context: str, text: str) -> None:
    active_text = docker_active_config_text(text)
    lowered = active_text.lower()
    service_names = docker_compose_service_names(active_text)
    for service_name in service_names:
        analysis["compose_services"].append({"file_path": path, "name": service_name, "context": context})

    if re.search(r"(?im)^\s*privileged\s*:\s*true\b", active_text):
        add_docker_finding(
            analysis,
            "docker_privileged_container",
            "Compose service appears privileged",
            docker_contextual_level("medium", context),
            "A Compose file appears to set privileged: true for a service.",
            docker_contextual_evidence("privileged", "true", context),
            "Avoid privileged containers unless they are explicitly required and isolated.",
            file_path=path,
            context=context,
        )
    if re.search(r"(?im)^\s*network_mode\s*:\s*['\"]?host['\"]?\s*$", active_text):
        add_docker_finding(
            analysis,
            "docker_host_network",
            "Compose service uses host network mode",
            docker_contextual_level("medium", context),
            "A Compose file appears to set network_mode: host.",
            docker_contextual_evidence("network_mode", "host", context),
            "Confirm host networking is intentional and not used as a shortcut for normal service networking.",
            file_path=path,
            context=context,
        )
    if re.search(r"(?im)^\s*(?:pid|ipc)\s*:\s*['\"]?host['\"]?\s*$", active_text):
        add_docker_finding(
            analysis,
            "docker_host_pid_or_ipc",
            "Compose service uses host pid/ipc namespace",
            docker_contextual_level("medium", context),
            "A Compose file appears to share host pid or ipc namespaces.",
            docker_contextual_evidence("pid/ipc", "host", context),
            "Use host pid/ipc only for tightly controlled operational cases.",
            file_path=path,
            context=context,
        )
    if "/var/run/docker.sock" in lowered:
        add_docker_finding(
            analysis,
            "docker_socket_mount",
            "Compose file mounts the Docker socket",
            docker_contextual_level("medium", context),
            "A Compose volume appears to mount /var/run/docker.sock.",
            "/var/run/docker.sock",
            "Avoid exposing the Docker socket to application containers unless a narrowly scoped control-plane use case requires it.",
            file_path=path,
            context=context,
        )
    for port in ("5432", "3306", "6379", "27017"):
        if re.search(rf"(?m)['\"]?(?:\d{{1,3}}(?:\.\d{{1,3}}){{3}}:)?{port}:{port}(?:/(?:tcp|udp))?['\"]?", active_text):
            add_docker_finding(
                analysis,
                "docker_published_database_port",
                f"Compose file publishes service port {port}",
                docker_contextual_level("low", context),
                "A Compose file appears to publish a database or cache service port on the host.",
                f"{port}:{port}",
                "Confirm the service should be exposed outside the Compose network.",
                file_path=path,
                context=context,
            )
    for evidence in docker_real_env_file_references(active_text):
        add_docker_finding(
            analysis,
            "docker_env_file_real_reference",
            "Compose file references a real env file",
            docker_contextual_level("low", context),
            "A Compose file references an .env file that appears to be a real environment file. Inspectra records the reference but does not read that file.",
            evidence,
            "Keep real env files out of shared archives and use sample/template files for review packages.",
            file_path=path,
            context=context,
        )
    for line in active_text.splitlines():
        if docker_line_contains_sensitive_env_name(line):
            add_docker_finding(
                analysis,
                "docker_sensitive_env_name",
                "Compose file contains a sensitive-looking environment name",
                docker_contextual_level("low", context),
                "A Compose environment entry uses a secret-like name. Inspectra redacts the value and reports this as a review indicator.",
                docker_contextual_evidence("environment", redact_docker_secret_text(line.strip()), context),
                "Prefer runtime secret injection and avoid committing real secret values.",
                file_path=path,
                context=context,
            )


def docker_compose_service_names(text: str) -> list[str]:
    names: list[str] = []
    in_services = False
    services_indent = 0
    for line in text.splitlines():
        if re.match(r"^\s*services\s*:\s*$", line):
            in_services = True
            services_indent = len(line) - len(line.lstrip())
            continue
        if not in_services:
            continue
        stripped = line.strip()
        if not stripped:
            continue
        indent = len(line) - len(line.lstrip())
        if indent <= services_indent:
            break
        if indent == services_indent + 2 and stripped.endswith(":"):
            name = stripped[:-1].strip().strip("\"'")
            if name and name not in names:
                names.append(name[:120])
    return names


def docker_real_env_file_references(text: str) -> list[str]:
    references: list[str] = []
    capture = False
    env_indent = 0
    for line in text.splitlines():
        if re.match(r"^\s*env_file\s*:", line):
            capture = True
            env_indent = len(line) - len(line.lstrip())
            _, value = line.split(":", 1)
            maybe = value.strip().strip("\"'")
            if is_docker_real_env_reference(maybe):
                references.append(f"env_file: {maybe}")
            continue
        if not capture:
            continue
        stripped = line.strip()
        indent = len(line) - len(line.lstrip())
        if not stripped:
            continue
        if indent <= env_indent:
            capture = False
            continue
        if stripped.startswith("-"):
            maybe = stripped[1:].strip().strip("\"'")
            if is_docker_real_env_reference(maybe):
                references.append(f"env_file: {maybe}")
    return sorted(set(references))


def is_docker_real_env_reference(value: str) -> bool:
    basename = value.replace("\\", "/").rsplit("/", 1)[-1].lower()
    if not basename.startswith(".env"):
        return False
    return not any(marker in basename for marker in ("example", "sample", "template"))


def docker_line_contains_sensitive_env_name(line: str) -> bool:
    return bool(re.search(r"(?i)\b(PASSWORD|PASS|TOKEN|API_KEY|SECRET|DATABASE_URL|REDIS_URL|PRIVATE_KEY)\b", line))


def redact_docker_secret_text(text: str) -> str:
    redacted, _count = redact_django_secret_text(text)
    redacted = re.sub(
        r"(?i)\b([a-z][a-z0-9+.-]*://)([^:\s/@]+):([^@\s]+)@",
        r"\1\2:[REDACTED]@",
        redacted,
    )
    return redacted


def docker_contextual_evidence(name: str, value: str, context: str) -> str:
    evidence = safe_setting_evidence(name, value)
    if context:
        return f"{evidence} (context: {context})"
    return evidence


def add_docker_finding(
    analysis: dict[str, Any],
    finding_id: str,
    title: str,
    level: str,
    description: str,
    evidence: str,
    recommendation: str,
    *,
    file_path: str | None = None,
    context: str | None = None,
) -> None:
    finding = make_finding(finding_id, title, level, description, redact_docker_secret_text(evidence), recommendation)
    if file_path:
        finding["file_path"] = file_path
    if context:
        finding["context"] = context
    analysis["findings"].append(finding)


def finalize_docker_config_analysis(analysis: dict[str, Any]) -> None:
    if analysis["summary"]["secrets_redacted_count"]:
        analysis["redaction_notes"] = [
            "Secret-like values in Docker/Compose evidence are redacted on a best-effort basis.",
        ]
    analysis["findings"] = dedupe_findings(analysis["findings"])
    analysis["summary"]["services_detected"] = len(analysis["compose_services"])
    analysis["summary"]["findings_count"] = len(analysis["findings"])


def secrets_review_limits(request: ArchiveAnalysisRequest) -> dict[str, int]:
    max_files = SECRETS_REVIEW_MAX_FILES if request.max_files is None else request.max_files
    max_file_bytes = SECRETS_REVIEW_MAX_FILE_BYTES if request.max_file_bytes is None else request.max_file_bytes
    max_total_bytes = SECRETS_REVIEW_MAX_TOTAL_BYTES if request.max_total_bytes is None else request.max_total_bytes
    if max_files <= 0 or max_file_bytes <= 0 or max_total_bytes <= 0:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Secrets review analysis limits must be positive.")
    return {"max_files": max_files, "max_file_bytes": max_file_bytes, "max_total_bytes": max_total_bytes}


def analyze_secrets_review_archive(
    path: Path,
    archive_type: str,
    *,
    max_files: int,
    max_file_bytes: int,
    max_total_bytes: int,
) -> dict[str, Any]:
    analysis = empty_secrets_review_analysis()
    state = {
        "files_read": 0,
        "total_bytes_read": 0,
        "max_files": max_files,
        "max_file_bytes": max_file_bytes,
        "max_total_bytes": max_total_bytes,
    }

    if archive_type == "zip":
        preflight = inspect_zip_metadata_preflight(path)
        blocked_reason = zip_preflight_block_reason(preflight, ARCHIVE_MAX_ENTRIES)
        add_zip_preflight_summary(analysis["summary"], preflight)
        if blocked_reason:
            analysis["summary"]["truncated"] = True
            finding = zip_preflight_finding(blocked_reason, preflight, ARCHIVE_MAX_ENTRIES)
            scoped = dict(finding)
            scoped["id"] = f"secrets_review_{scoped['id']}"
            analysis["findings"].append(scoped)
            finalize_secrets_review_analysis(analysis)
            return analysis
        with zipfile.ZipFile(path) as archive:
            for index, info in enumerate(archive.filelist, start=1):
                if should_stop_secrets_review_archive_scan(index, analysis):
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
                process_secrets_review_entry(
                    analysis,
                    state,
                    entry,
                    lambda entry_info=info: archive.open(entry_info),
                )
    else:
        with tarfile.open(path, "r:*") as archive:
            for index, member in enumerate(archive, start=1):
                if should_stop_secrets_review_archive_scan(index, analysis):
                    break
                entry = {
                    "path": member.name,
                    "type": tar_member_type(member),
                    "size": member.size,
                    "mode_int": member.mode,
                    "mode": format_file_mode(member.mode),
                    "link_target": member.linkname or None,
                }
                process_secrets_review_entry(
                    analysis,
                    state,
                    entry,
                    lambda tar_member=member: archive.extractfile(tar_member),
                )

    finalize_secrets_review_analysis(analysis)
    return analysis


def empty_secrets_review_analysis(errors: list[str] | None = None) -> dict[str, Any]:
    return {
        "summary": {
            "files_considered": 0,
            "files_reviewed": 0,
            "sensitive_files_detected": 0,
            "findings_count": 0,
            "high_confidence_count": 0,
            "redacted_values_count": 0,
            "truncated": False,
        },
        "files_detected": [],
        "files_reviewed": [],
        "sensitive_files": [],
        "findings": [],
        "redaction_notes": [],
        "errors": errors or [],
    }


def build_secrets_review_result(
    file_id: str,
    path: Path,
    original_filename: str,
    archive_type: str,
    analysis: dict[str, Any],
    *,
    max_files: int,
    max_file_bytes: int,
    max_total_bytes: int,
) -> dict[str, Any]:
    summary = as_dict(analysis.get("summary"))
    findings = analysis.get("findings") if isinstance(analysis.get("findings"), list) else []
    summary["findings_count"] = len(findings)
    return {
        "file_id": file_id,
        "analyzer": "secrets_review_basic",
        "archive_type": archive_type,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "hashes": calculate_hashes(path),
        "file_identification": {
            "size_bytes": path.stat().st_size,
            "original_filename": original_filename,
        },
        "limits": {
            "max_files": max_files,
            "max_file_bytes": max_file_bytes,
            "max_total_bytes": max_total_bytes,
            "max_archive_entries": ARCHIVE_MAX_ENTRIES,
            "max_entry_name_length": ARCHIVE_MAX_ENTRY_NAME_LENGTH,
            "max_zip_central_directory_bytes": ARCHIVE_MAX_ZIP_CENTRAL_DIRECTORY_BYTES,
        },
        "summary": summary,
        "files_detected": analysis.get("files_detected", []),
        "files_reviewed": analysis.get("files_reviewed", []),
        "sensitive_files": analysis.get("sensitive_files", []),
        "findings": findings,
        "redaction_notes": analysis.get("redaction_notes", []),
        "errors": analysis.get("errors", []),
        "truncated": bool(summary.get("truncated")),
    }


def should_stop_secrets_review_archive_scan(index: int, analysis: dict[str, Any]) -> bool:
    if index > ARCHIVE_MAX_ENTRIES:
        analysis["summary"]["truncated"] = True
        add_secrets_review_finding(
            analysis,
            "secrets_review_entry_limit_reached",
            "Archive entry scan limit reached",
            "medium",
            "high",
            "limit",
            "Inspectra stopped scanning archive metadata after the configured entry limit.",
            f"Processed {ARCHIVE_MAX_ENTRIES} entries.",
            "Review the archive with stricter limits or split it before deeper inspection.",
            redacted=False,
        )
        return True
    return False


def process_secrets_review_entry(
    analysis: dict[str, Any],
    state: dict[str, int],
    entry: dict[str, Any],
    open_entry,
) -> None:
    path = str(entry["path"])
    category = classify_secrets_review_candidate(path)
    if category is None:
        return

    summary = as_dict(analysis["summary"])
    summary["files_considered"] += 1
    entry_type = str(entry["type"])
    size_bytes = int(entry.get("size") or 0)
    context = secrets_review_file_context(path, category)
    flags, depth = archive_entry_flags(path, entry.get("mode_int"))
    record = {
        "path": path,
        "category": category,
        "context": context,
        "entry_type": entry_type,
        "size_bytes": size_bytes,
        "mode": entry.get("mode"),
        "depth": depth,
        "flags": flags,
        "read": False,
        "skip_reason": None,
    }
    if entry.get("link_target"):
        record["link_target"] = entry["link_target"]

    skip_reason = secrets_review_skip_reason(record, state)
    if skip_reason:
        record["skip_reason"] = skip_reason
        analysis["files_detected"].append(record)
        if skip_reason == "real_env_file_not_read":
            add_secrets_review_sensitive_file(analysis, record)
        else:
            add_secrets_review_skip_finding(analysis, path, skip_reason, size_bytes, context)
        return

    try:
        stream = open_entry()
        if stream is None:
            raise ValueError("entry could not be opened as a regular file")
        with stream:
            raw_bytes = read_limited_stream(stream, state["max_file_bytes"])
    except (OSError, ValueError, zipfile.BadZipFile, tarfile.TarError) as exc:
        record["skip_reason"] = "read_error"
        analysis["files_detected"].append(record)
        add_secrets_review_finding(
            analysis,
            "secrets_review_file_read_error",
            "Candidate file could not be read safely",
            "low",
            "medium",
            "archive",
            "A candidate secrets-review file could not be read from the archive within Inspectra limits.",
            f"{path}: {exc}",
            "Review this file manually in a constrained environment if it is expected.",
            file_path=path,
            context=context,
            redacted=False,
        )
        return

    state["total_bytes_read"] += len(raw_bytes)
    if b"\x00" in raw_bytes:
        record["skip_reason"] = "binary_or_non_text"
        analysis["files_detected"].append(record)
        add_secrets_review_skip_finding(analysis, path, "binary_or_non_text", size_bytes, context)
        return

    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        record["skip_reason"] = "binary_or_non_text"
        analysis["files_detected"].append(record)
        add_secrets_review_skip_finding(analysis, path, "binary_or_non_text", size_bytes, context)
        return

    state["files_read"] += 1
    summary["files_reviewed"] = state["files_read"]
    record["read"] = True
    record["bytes_read"] = len(raw_bytes)
    analysis["files_detected"].append(record)
    analysis["files_reviewed"].append(
        {"path": path, "category": category, "context": context, "size_bytes": size_bytes, "bytes_read": len(raw_bytes)}
    )
    analyze_secrets_review_text(analysis, path, category, context, text)


def classify_secrets_review_candidate(path: str) -> str | None:
    normalized = normalize_archive_entry_path(path)
    basename = normalized.rsplit("/", 1)[-1]
    basename_lower = basename.lower()
    parts = [part.lower() for part in normalized.split("/") if part]

    if is_secrets_env_template_name(basename_lower):
        return "env_template"
    if is_secrets_sensitive_env_name(basename_lower):
        return "env_sensitive"
    if is_secrets_ci_candidate(normalized, basename_lower):
        return "ci_config"
    if is_secrets_infra_candidate(normalized, basename_lower):
        return "infra_config"
    if basename == "Dockerfile" or basename_lower.startswith("dockerfile.") or is_docker_compose_filename(basename_lower):
        return "docker_config"
    if basename_lower in {
        "settings.py",
        "config.py",
        "appsettings.json",
        "application.yml",
        "application.yaml",
        "config.yml",
        "config.yaml",
        "package.json",
        "pyproject.toml",
    }:
        return "app_config"
    if basename_lower.endswith(".py") and len(parts) >= 2 and parts[-2] in {"config", "settings"}:
        return "app_config"
    return None


def is_secrets_env_template_name(basename: str) -> bool:
    if basename in {"env.example", "env.template", "env.sample", "sample.env"}:
        return True
    return basename.startswith(".env") and any(marker in basename for marker in ("example", "sample", "template"))


def is_secrets_sensitive_env_name(basename: str) -> bool:
    return basename == ".env" or basename == ".envrc" or basename.startswith(".env.")


def is_secrets_ci_candidate(normalized: str, basename: str) -> bool:
    lower = normalized.lower()
    if lower.startswith(".github/workflows/") and basename.endswith((".yml", ".yaml")):
        return True
    return basename in {".gitlab-ci.yml", "bitbucket-pipelines.yml", "azure-pipelines.yml"}


def is_secrets_infra_candidate(normalized: str, basename: str) -> bool:
    lower = normalized.lower()
    if basename.endswith(".tf"):
        return True
    if basename == "values.yaml" or (basename.startswith("values") and basename.endswith((".yml", ".yaml"))):
        return True
    if basename in {"deployment.yaml", "deployment.yml", "secret.yaml", "secret.yml", "configmap.yaml", "configmap.yml"}:
        return True
    return lower.endswith(".k8s.yaml") or lower.endswith(".k8s.yml")


def secrets_review_skip_reason(record: dict[str, Any], state: dict[str, int]) -> str | None:
    flags = as_dict(record.get("flags"))
    path = str(record["path"])
    size_bytes = int(record.get("size_bytes") or 0)
    if flags.get("path_traversal"):
        return "path_traversal"
    if flags.get("absolute_path") or flags.get("windows_absolute_path"):
        return "absolute_path"
    if record.get("entry_type") != "file":
        return f"not_regular_file:{record.get('entry_type')}"
    if record.get("category") == "env_sensitive":
        return "real_env_file_not_read"
    if len(path) > ARCHIVE_MAX_ENTRY_NAME_LENGTH:
        return "entry_name_too_long"
    if size_bytes > state["max_file_bytes"]:
        return "file_too_large"
    if state["files_read"] >= state["max_files"]:
        return "too_many_files"
    if state["total_bytes_read"] + size_bytes > state["max_total_bytes"]:
        return "total_bytes_limit"
    return None


def add_secrets_review_sensitive_file(analysis: dict[str, Any], record: dict[str, Any]) -> None:
    analysis["summary"]["sensitive_files_detected"] += 1
    sensitive = {
        "path": record["path"],
        "category": record["category"],
        "context": record.get("context"),
        "read": False,
        "skip_reason": "real_env_file_not_read",
        "size_bytes": record.get("size_bytes"),
    }
    analysis["sensitive_files"].append(sensitive)
    add_secrets_review_finding(
        analysis,
        "real_env_file_present_not_read",
        "Real environment file detected but not read",
        contextual_secret_level("low", str(record.get("context") or "")),
        "high",
        "sensitive_file",
        "A real .env-style file was present in the archive. Inspectra records its presence but does not read or store its content.",
        str(record["path"])[:240],
        "Remove real environment files from shared archives and use sample/template files for review packages.",
        file_path=str(record["path"]),
        context=str(record.get("context") or ""),
        redacted=False,
    )


def add_secrets_review_skip_finding(analysis: dict[str, Any], path: str, reason: str, size_bytes: int, context: str) -> None:
    if reason in {"file_too_large", "too_many_files", "total_bytes_limit"}:
        analysis["summary"]["truncated"] = True
    titles = {
        "path_traversal": "Secrets review path uses traversal",
        "absolute_path": "Secrets review path is absolute",
        "entry_name_too_long": "Secrets review entry name is unusually long",
        "file_too_large": "Secrets review file omitted because it exceeds the size limit",
        "too_many_files": "Secrets review file limit reached",
        "total_bytes_limit": "Total secrets review byte limit reached",
        "binary_or_non_text": "Secrets review candidate is not UTF-8 text",
    }
    level = "medium" if reason in {"path_traversal", "absolute_path", "file_too_large", "too_many_files", "total_bytes_limit"} else "low"
    evidence = f"{path}: {size_bytes} bytes" if reason == "file_too_large" else path[:240]
    if reason.startswith("not_regular_file"):
        title = "Secrets review candidate omitted because it is not a regular file"
        evidence = f"{path}: {reason}"
        level = "low"
    else:
        title = titles.get(reason, "Secrets review candidate skipped by defensive limit")
    add_secrets_review_finding(
        analysis,
        f"secrets_review_{reason.split(':', 1)[0]}",
        title,
        level,
        "medium",
        "archive",
        "Inspectra detected a secrets-review candidate but did not read it because of a defensive limit or unsafe archive metadata.",
        evidence,
        "Review the archive manually in a constrained environment if this file is expected.",
        file_path=path,
        context=context,
        redacted=False,
    )


LOWER_CONFIDENCE_SECRET_CONTEXTS = {"development", "test", "local", "example"}
PLACEHOLDER_SECRET_VALUES = {
    "changeme",
    "change-me",
    "change_me",
    "password",
    "example",
    "secret",
    "dummy",
    "todo",
    "replace-me",
    "replace_me",
    "replace",
    "your-secret",
    "your_secret",
}
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)^\s*(?:-\s*)?(?:export\s+)?(?:ARG\s+|ENV\s+)?([A-Z0-9_.-]*(?:SECRET_KEY|DJANGO_SECRET_KEY|CLIENT_SECRET|PRIVATE_KEY|DATABASE_URL|REDIS_URL|API_KEY|PASSWORD|TOKEN|SECRET|PASS)[A-Z0-9_.-]*)\s*[:=]\s*(.+?)\s*$"
)
DATABASE_URL_RE = re.compile(r"(?i)\b((?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?)://[^\s'\"<>]+)")
REDIS_URL_RE = re.compile(r"(?i)\b(redis://[^\s'\"<>]+)")
BASIC_AUTH_URL_RE = re.compile(r"(?i)\b(https?://[^\s'\"<>/@:]+:[^\s'\"<>/@]+@[^\s'\"<>]+)")
JWT_RE = re.compile(r"\b[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
PRIVATE_KEY_BLOCK_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----", re.IGNORECASE)


def secrets_review_file_context(path: str, category: str = "") -> str:
    normalized = normalize_archive_entry_path(path).lower()
    parts = [part for part in normalized.split("/") if part]
    basename = parts[-1] if parts else normalized
    directories = set(parts[:-1])
    name_tokens = set(re.split(r"[^a-z0-9]+", basename))
    all_tokens = set(parts[:-1]) | name_tokens

    if directories.intersection({"docs", "doc", "examples", "example", "samples", "sample"}) or all_tokens.intersection(
        {"example", "examples", "sample", "samples", "template"}
    ):
        return "example"
    if all_tokens.intersection({"test", "tests", "testing"}):
        return "test"
    if all_tokens.intersection({"dev", "development"}):
        return "development"
    if "local" in all_tokens:
        return "local"
    if all_tokens.intersection({"prod", "production"}) or "deploy" in directories:
        return "production"
    if category in {"env_template", "env_sensitive"}:
        return "example" if category == "env_template" else "ambiguous"
    if len(parts) == 1:
        return "shared"
    return "ambiguous"


def active_secret_lines(text: str) -> list[tuple[int, str]]:
    lines: list[tuple[int, str]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("//"):
            continue
        lines.append((line_number, line))
    return lines


def strip_inline_secret_comment(value: str) -> str:
    for marker in (" #", " //"):
        if marker in value:
            value = value.split(marker, 1)[0]
    return value.strip().strip(",").strip()


def normalize_secret_value(value: str) -> str:
    return strip_inline_secret_comment(value).strip().strip("\"'").strip()


def is_placeholder_secret_value(value: str) -> bool:
    normalized = normalize_secret_value(value).lower()
    normalized = re.sub(r"[^a-z0-9_-]+", "", normalized)
    return normalized in PLACEHOLDER_SECRET_VALUES or normalized.startswith(("your", "replace"))


def contextual_secret_level(level: str, context: str) -> str:
    if context not in LOWER_CONFIDENCE_SECRET_CONTEXTS:
        return level
    if level == "medium":
        return "low"
    if level == "low":
        return "info"
    return level


def contextual_secret_confidence(confidence: str, context: str) -> str:
    if context not in LOWER_CONFIDENCE_SECRET_CONTEXTS:
        return confidence
    if confidence == "high":
        return "medium"
    if confidence == "medium":
        return "low"
    return confidence


def analyze_secrets_review_text(analysis: dict[str, Any], path: str, category: str, context: str, text: str) -> None:
    active_lines = active_secret_lines(text)
    active_text = "\n".join(line for _line_number, line in active_lines)

    if PRIVATE_KEY_BLOCK_RE.search(active_text):
        add_secrets_review_finding(
            analysis,
            "private_key_block_detected",
            "Private key block detected",
            contextual_secret_level("medium", context),
            contextual_secret_confidence("high", context),
            "private_key",
            "A PEM-style private key block was observed in a text candidate. Inspectra redacted the key material and did not validate it.",
            "PRIVATE_KEY_BLOCK_REDACTED",
            "Remove private keys from archives and rotate them if this archive left trusted storage.",
            file_path=path,
            context=context,
        )

    for line_number, line in active_lines:
        analyze_secret_assignment_line(analysis, path, category, context, line_number, line)

    for match in DATABASE_URL_RE.finditer(active_text):
        if url_contains_userinfo(match.group(1)):
            add_url_secret_finding(
                analysis,
                "database_url_with_credentials",
                "Database URL with credentials observed",
                "credential_url",
                match.group(1),
                path,
                context,
            )
    for match in REDIS_URL_RE.finditer(active_text):
        if url_contains_userinfo(match.group(1)):
            add_url_secret_finding(
                analysis,
                "redis_url_with_credentials",
                "Redis URL with credentials observed",
                "credential_url",
                match.group(1),
                path,
                context,
            )
    for match in BASIC_AUTH_URL_RE.finditer(active_text):
        add_url_secret_finding(
            analysis,
            "basic_auth_url",
            "URL with embedded credentials observed",
            "credential_url",
            match.group(1),
            path,
            context,
        )
    for _match in JWT_RE.finditer(active_text):
        add_secrets_review_finding(
            analysis,
            "jwt_like_value",
            "JWT-like value observed",
            contextual_secret_level("medium", context),
            contextual_secret_confidence("high", context),
            "token",
            "A three-segment JWT-like value was observed. Inspectra redacted the value and did not validate it.",
            "JWT-like value=[REDACTED]",
            "Avoid storing real tokens in archives and rotate the value if this package was shared outside trusted storage.",
            file_path=path,
            context=context,
        )

    if category == "infra_config" and path.lower().endswith(".tf"):
        analyze_terraform_secret_defaults(analysis, path, context, active_text)


def analyze_secret_assignment_line(
    analysis: dict[str, Any],
    path: str,
    category: str,
    context: str,
    line_number: int,
    line: str,
) -> None:
    match = SECRET_ASSIGNMENT_RE.match(line)
    if not match:
        return
    key = match.group(1).strip().strip("\"'")
    value = normalize_secret_value(match.group(2))
    if not value:
        return

    placeholder = is_placeholder_secret_value(value)
    finding_id = "weak_placeholder_secret" if placeholder else "secret_like_assignment"
    level = "info" if placeholder else "medium"
    confidence = "low" if placeholder else "medium"
    title = "Placeholder secret-like value observed" if placeholder else "Secret-like assignment observed"
    description = (
        "A secret-like key uses a placeholder value. This is usually expected in examples but should not be copied into production."
        if placeholder
        else "A secret-like key appears to have an inline value. Inspectra redacted the value and did not validate it."
    )
    evidence = f"{key}=[REDACTED]"
    recommendation = (
        "Keep placeholders clearly marked and ensure production values are injected through an approved secret mechanism."
        if placeholder
        else "Move real secret values to an approved runtime secret mechanism and rotate if this archive was shared outside trusted storage."
    )
    add_secrets_review_finding(
        analysis,
        finding_id,
        title,
        contextual_secret_level(level, context),
        contextual_secret_confidence(confidence, context),
        "secret_assignment",
        description,
        evidence,
        recommendation,
        file_path=path,
        context=context,
        line=line_number,
    )

    if category == "ci_config" and not placeholder:
        add_secrets_review_finding(
            analysis,
            "ci_secret_exposed_inline",
            "CI configuration contains an inline secret-like value",
            contextual_secret_level("medium", context),
            contextual_secret_confidence("high", context),
            "ci",
            "A CI/CD configuration appears to define a secret-like value inline. Inspectra redacted the value and did not validate it.",
            evidence,
            "Use the CI provider's secret store instead of inline values.",
            file_path=path,
            context=context,
            line=line_number,
        )
    if category == "docker_config" and not placeholder:
        lower_path = normalize_archive_entry_path(path).lower()
        if lower_path.rsplit("/", 1)[-1].startswith("dockerfile") or line.lstrip().upper().startswith(("ARG ", "ENV ")):
            add_secrets_review_finding(
                analysis,
                "secret_in_docker_build_arg",
                "Dockerfile contains a secret-like build argument or environment value",
                contextual_secret_level("medium", context),
                contextual_secret_confidence("medium", context),
                "docker",
                "A Dockerfile line appears to define a secret-like value. Inspectra redacted the value and did not validate it.",
                evidence,
                "Avoid baking secrets into images or build args; use runtime secret injection where possible.",
                file_path=path,
                context=context,
                line=line_number,
            )
        elif "compose" in lower_path:
            add_secrets_review_finding(
                analysis,
                "secret_in_compose_environment",
                "Compose environment contains a secret-like value",
                contextual_secret_level("medium", context),
                contextual_secret_confidence("medium", context),
                "compose",
                "A Compose environment entry appears to define a secret-like value. Inspectra redacted the value and did not validate it.",
                evidence,
                "Use runtime secret injection or env files kept out of shared archives.",
                file_path=path,
                context=context,
                line=line_number,
            )
    if category == "infra_config" and not placeholder and is_kubernetes_secret_context(path, line):
        add_secrets_review_finding(
            analysis,
            "secret_in_k8s_manifest_plaintext",
            "Kubernetes manifest contains plaintext secret-like data",
            contextual_secret_level("medium", context),
            contextual_secret_confidence("high", context),
            "kubernetes",
            "A Kubernetes-related manifest appears to include plaintext secret-like data. Inspectra redacted the value and did not validate it.",
            evidence,
            "Use Kubernetes Secret handling carefully and avoid sharing plaintext secret values in archives.",
            file_path=path,
            context=context,
            line=line_number,
        )


def analyze_terraform_secret_defaults(analysis: dict[str, Any], path: str, context: str, text: str) -> None:
    pattern = re.compile(
        r"(?is)variable\s+['\"]([^'\"]*(?:secret|password|token|key)[^'\"]*)['\"]\s*\{(?:(?!\n\}).)*?default\s*=\s*(['\"])(.*?)\2"
    )
    for match in pattern.finditer(text):
        name = match.group(1)
        value = normalize_secret_value(match.group(3))
        if not value or is_placeholder_secret_value(value):
            continue
        add_secrets_review_finding(
            analysis,
            "secret_in_terraform_variable_default",
            "Terraform variable default contains a secret-like value",
            contextual_secret_level("medium", context),
            contextual_secret_confidence("high", context),
            "terraform",
            "A Terraform variable with a secret-like name appears to define a default value. Inspectra redacted the value and did not validate it.",
            f"variable {name} default=[REDACTED]",
            "Avoid committing real secret defaults in Terraform variables; inject values through a secure workflow.",
            file_path=path,
            context=context,
        )


def is_kubernetes_secret_context(path: str, line: str) -> bool:
    lower_path = normalize_archive_entry_path(path).lower()
    stripped = line.strip().lower()
    return lower_path.endswith((".k8s.yaml", ".k8s.yml")) or lower_path.rsplit("/", 1)[-1] in {"secret.yaml", "secret.yml"} or stripped.startswith(("stringdata:", "data:"))


def url_contains_userinfo(value: str) -> bool:
    parsed = urlsplit(value)
    return bool(parsed.username or parsed.password or ("@" in parsed.netloc and parsed.netloc.split("@", 1)[0]))


def add_url_secret_finding(
    analysis: dict[str, Any],
    finding_id: str,
    title: str,
    category: str,
    url: str,
    path: str,
    context: str,
) -> None:
    add_secrets_review_finding(
        analysis,
        finding_id,
        title,
        contextual_secret_level("medium", context),
        contextual_secret_confidence("high", context),
        category,
        "A URL appears to include embedded credentials. Inspectra redacted the credential value and did not validate it.",
        safe_secret_url_evidence(url),
        "Move credentials out of URLs and rotate them if this archive was shared outside trusted storage.",
        file_path=path,
        context=context,
    )


def safe_secret_url_evidence(value: str) -> str:
    parsed = urlsplit(value)
    host = parsed.hostname or "host"
    try:
        port_value = parsed.port
    except ValueError:
        port_value = None
    port = f":{port_value}" if port_value else ""
    path = parsed.path or ""
    return f"{parsed.scheme}://[REDACTED]@{host}{port}{path}"


def redact_secrets_review_text(text: str) -> str:
    redacted = PRIVATE_KEY_BLOCK_RE.sub("PRIVATE_KEY_BLOCK_REDACTED", text)
    redacted = re.sub(
        r"(?i)\b([a-z][a-z0-9+.-]*://)([^:\s/@]+):([^@\s]+)@",
        r"\1[REDACTED]@",
        redacted,
    )
    redacted = re.sub(
        r"(?i)\b([a-z][a-z0-9+.-]*://):([^@\s]+)@",
        r"\1[REDACTED]@",
        redacted,
    )
    redacted = re.sub(
        r"(?i)\b([A-Z0-9_.-]*(?:SECRET_KEY|DJANGO_SECRET_KEY|CLIENT_SECRET|PRIVATE_KEY|DATABASE_URL|REDIS_URL|API_KEY|PASSWORD|TOKEN|SECRET|PASS)[A-Z0-9_.-]*)(\s*[:=]\s*)(['\"]?)[^\s,'\"}\]]+",
        r"\1\2\3[REDACTED]",
        redacted,
    )
    redacted = JWT_RE.sub("JWT-like value=[REDACTED]", redacted)
    return redacted


def add_secrets_review_finding(
    analysis: dict[str, Any],
    finding_id: str,
    title: str,
    level: str,
    confidence: str,
    category: str,
    description: str,
    evidence: str,
    recommendation: str,
    *,
    file_path: str | None = None,
    context: str | None = None,
    line: int | None = None,
    redacted: bool = True,
) -> None:
    finding = make_finding(
        finding_id,
        title,
        level,
        redact_secrets_review_text(description),
        redact_secrets_review_text(evidence),
        redact_secrets_review_text(recommendation),
    )
    finding["confidence"] = confidence
    finding["category"] = category
    if file_path:
        finding["file_path"] = file_path
    if context:
        finding["context"] = context
    if line is not None:
        finding["line"] = str(line)
    if redacted:
        analysis["summary"]["redacted_values_count"] += 1
    analysis["findings"].append(finding)


def finalize_secrets_review_analysis(analysis: dict[str, Any]) -> None:
    analysis["findings"] = dedupe_findings(analysis["findings"])
    analysis["summary"]["findings_count"] = len(analysis["findings"])
    analysis["summary"]["high_confidence_count"] = sum(1 for finding in analysis["findings"] if finding.get("confidence") == "high")
    if analysis["summary"]["redacted_values_count"]:
        analysis["redaction_notes"] = [
            "Secret-like values are redacted before storage and export on a best-effort basis.",
        ]


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
