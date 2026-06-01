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
NODE_PACKAGE_CONFIG_MAX_FILES = positive_int_from_env("INSPECTRA_NODE_PACKAGE_CONFIG_MAX_FILES", 100)
NODE_PACKAGE_CONFIG_MAX_FILE_BYTES = positive_int_from_env("INSPECTRA_NODE_PACKAGE_CONFIG_MAX_FILE_BYTES", 524_288)
NODE_PACKAGE_CONFIG_MAX_TOTAL_BYTES = positive_int_from_env("INSPECTRA_NODE_PACKAGE_CONFIG_MAX_TOTAL_BYTES", 2_097_152)
CI_CD_CONFIG_MAX_FILES = positive_int_from_env("INSPECTRA_CI_CD_CONFIG_MAX_FILES", 100)
CI_CD_CONFIG_MAX_FILE_BYTES = positive_int_from_env("INSPECTRA_CI_CD_CONFIG_MAX_FILE_BYTES", 524_288)
CI_CD_CONFIG_MAX_TOTAL_BYTES = positive_int_from_env("INSPECTRA_CI_CD_CONFIG_MAX_TOTAL_BYTES", 2_097_152)
K8S_CONFIG_MAX_FILES = positive_int_from_env("INSPECTRA_K8S_CONFIG_MAX_FILES", 100)
K8S_CONFIG_MAX_FILE_BYTES = positive_int_from_env("INSPECTRA_K8S_CONFIG_MAX_FILE_BYTES", 524_288)
K8S_CONFIG_MAX_TOTAL_BYTES = positive_int_from_env("INSPECTRA_K8S_CONFIG_MAX_TOTAL_BYTES", 2_097_152)
TERRAFORM_CONFIG_MAX_FILES = positive_int_from_env("INSPECTRA_TERRAFORM_CONFIG_MAX_FILES", 100)
TERRAFORM_CONFIG_MAX_FILE_BYTES = positive_int_from_env("INSPECTRA_TERRAFORM_CONFIG_MAX_FILE_BYTES", 524_288)
TERRAFORM_CONFIG_MAX_TOTAL_BYTES = positive_int_from_env("INSPECTRA_TERRAFORM_CONFIG_MAX_TOTAL_BYTES", 2_097_152)
NGINX_CONFIG_MAX_FILES = positive_int_from_env("INSPECTRA_NGINX_CONFIG_MAX_FILES", 100)
NGINX_CONFIG_MAX_FILE_BYTES = positive_int_from_env("INSPECTRA_NGINX_CONFIG_MAX_FILE_BYTES", 524_288)
NGINX_CONFIG_MAX_TOTAL_BYTES = positive_int_from_env("INSPECTRA_NGINX_CONFIG_MAX_TOTAL_BYTES", 2_097_152)
COMPOSE_CONFIG_MAX_FILES = positive_int_from_env("INSPECTRA_COMPOSE_CONFIG_MAX_FILES", 100)
COMPOSE_CONFIG_MAX_FILE_BYTES = positive_int_from_env("INSPECTRA_COMPOSE_CONFIG_MAX_FILE_BYTES", 524_288)
COMPOSE_CONFIG_MAX_TOTAL_BYTES = positive_int_from_env("INSPECTRA_COMPOSE_CONFIG_MAX_TOTAL_BYTES", 2_097_152)
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


@app.post("/analyze/node-package-config")
async def analyze_node_package_config(request: ArchiveAnalysisRequest) -> dict[str, Any]:
    archive_path = resolve_data_path(request.relative_path)
    if not archive_path.exists() or not archive_path.is_file():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Archive not found.")

    original_filename = Path(request.original_filename or archive_path.name).name
    limits = node_package_config_limits(request)
    archive_type = detect_archive_type(archive_path, original_filename)
    if archive_type == "unknown":
        return build_node_package_config_result(
            request.file_id,
            archive_path,
            original_filename,
            archive_type,
            empty_node_package_config_analysis(
                errors=["Unsupported or corrupt archive. Inspectra did not install packages, execute scripts, or contact registries."]
            ),
            **limits,
        )

    try:
        analysis = analyze_node_package_config_archive(archive_path, archive_type, **limits)
    except (OSError, tarfile.TarError, zipfile.BadZipFile) as exc:
        analysis = empty_node_package_config_analysis(errors=[f"Archive could not be parsed safely: {exc}"])

    return build_node_package_config_result(request.file_id, archive_path, original_filename, archive_type, analysis, **limits)


@app.post("/analyze/ci-cd-config")
async def analyze_ci_cd_config(request: ArchiveAnalysisRequest) -> dict[str, Any]:
    archive_path = resolve_data_path(request.relative_path)
    if not archive_path.exists() or not archive_path.is_file():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Archive not found.")

    original_filename = Path(request.original_filename or archive_path.name).name
    limits = ci_cd_config_limits(request)
    archive_type = detect_archive_type(archive_path, original_filename)
    if archive_type == "unknown":
        return build_ci_cd_config_result(
            request.file_id,
            archive_path,
            original_filename,
            archive_type,
            empty_ci_cd_config_analysis(
                errors=["Unsupported or corrupt archive. Inspectra did not execute workflows, scripts, actions, or provider calls."]
            ),
            **limits,
        )

    try:
        analysis = analyze_ci_cd_config_archive(archive_path, archive_type, **limits)
    except (OSError, tarfile.TarError, zipfile.BadZipFile) as exc:
        analysis = empty_ci_cd_config_analysis(errors=[f"Archive could not be parsed safely: {exc}"])

    return build_ci_cd_config_result(request.file_id, archive_path, original_filename, archive_type, analysis, **limits)


@app.post("/analyze/k8s-config")
async def analyze_k8s_config(request: ArchiveAnalysisRequest) -> dict[str, Any]:
    archive_path = resolve_data_path(request.relative_path)
    if not archive_path.exists() or not archive_path.is_file():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Archive not found.")

    original_filename = Path(request.original_filename or archive_path.name).name
    limits = k8s_config_limits(request)
    archive_type = detect_archive_type(archive_path, original_filename)
    if archive_type == "unknown":
        return build_k8s_config_result(
            request.file_id,
            archive_path,
            original_filename,
            archive_type,
            empty_k8s_config_analysis(
                errors=["Unsupported or corrupt archive. Inspectra did not run kubectl, render manifests, contact clusters, or execute content."]
            ),
            **limits,
        )

    try:
        analysis = analyze_k8s_config_archive(archive_path, archive_type, **limits)
    except (OSError, tarfile.TarError, zipfile.BadZipFile) as exc:
        analysis = empty_k8s_config_analysis(errors=[f"Archive could not be parsed safely: {exc}"])

    return build_k8s_config_result(request.file_id, archive_path, original_filename, archive_type, analysis, **limits)


@app.post("/analyze/terraform-config")
async def analyze_terraform_config(request: ArchiveAnalysisRequest) -> dict[str, Any]:
    archive_path = resolve_data_path(request.relative_path)
    if not archive_path.exists() or not archive_path.is_file():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Archive not found.")

    original_filename = Path(request.original_filename or archive_path.name).name
    limits = terraform_config_limits(request)
    archive_type = detect_archive_type(archive_path, original_filename)
    if archive_type == "unknown":
        return build_terraform_config_result(
            request.file_id,
            archive_path,
            original_filename,
            archive_type,
            empty_terraform_config_analysis(
                errors=["Unsupported or corrupt archive. Inspectra did not run Terraform, OpenTofu, Terragrunt, providers, modules, or cloud calls."]
            ),
            **limits,
        )

    try:
        analysis = analyze_terraform_config_archive(archive_path, archive_type, **limits)
    except (OSError, tarfile.TarError, zipfile.BadZipFile) as exc:
        analysis = empty_terraform_config_analysis(errors=[f"Archive could not be parsed safely: {exc}"])

    return build_terraform_config_result(request.file_id, archive_path, original_filename, archive_type, analysis, **limits)


@app.post("/analyze/nginx-config")
async def analyze_nginx_config(request: ArchiveAnalysisRequest) -> dict[str, Any]:
    archive_path = resolve_data_path(request.relative_path)
    if not archive_path.exists() or not archive_path.is_file():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Archive not found.")

    original_filename = Path(request.original_filename or archive_path.name).name
    limits = nginx_config_limits(request)
    archive_type = detect_archive_type(archive_path, original_filename)
    if archive_type == "unknown":
        return build_nginx_config_result(
            request.file_id,
            archive_path,
            original_filename,
            archive_type,
            empty_nginx_config_analysis(
                errors=["Unsupported or corrupt archive. Inspectra did not run Nginx, resolve includes, contact servers, or perform network calls."]
            ),
            **limits,
        )

    try:
        analysis = analyze_nginx_config_archive(archive_path, archive_type, **limits)
    except (OSError, tarfile.TarError, zipfile.BadZipFile) as exc:
        analysis = empty_nginx_config_analysis(errors=[f"Archive could not be parsed safely: {exc}"])

    return build_nginx_config_result(request.file_id, archive_path, original_filename, archive_type, analysis, **limits)


@app.post("/analyze/compose-config")
async def analyze_compose_config(request: ArchiveAnalysisRequest) -> dict[str, Any]:
    archive_path = resolve_data_path(request.relative_path)
    if not archive_path.exists() or not archive_path.is_file():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Archive not found.")

    original_filename = Path(request.original_filename or archive_path.name).name
    limits = compose_config_limits(request)
    archive_type = detect_archive_type(archive_path, original_filename)
    if archive_type == "unknown":
        return build_compose_config_result(
            request.file_id,
            archive_path,
            original_filename,
            archive_type,
            empty_compose_config_analysis(
                errors=["Unsupported or corrupt archive. Inspectra did not run Docker, Docker Compose, pull images, or read env/secret files."]
            ),
            **limits,
        )

    try:
        analysis = analyze_compose_config_archive(archive_path, archive_type, **limits)
    except (OSError, tarfile.TarError, zipfile.BadZipFile) as exc:
        analysis = empty_compose_config_analysis(errors=[f"Archive could not be parsed safely: {exc}"])

    return build_compose_config_result(request.file_id, archive_path, original_filename, archive_type, analysis, **limits)


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
JWT_RE = re.compile(r"\b[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b")
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
        finding["line"] = line
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


def node_package_config_limits(request: ArchiveAnalysisRequest) -> dict[str, int]:
    max_files = NODE_PACKAGE_CONFIG_MAX_FILES if request.max_files is None else request.max_files
    max_file_bytes = NODE_PACKAGE_CONFIG_MAX_FILE_BYTES if request.max_file_bytes is None else request.max_file_bytes
    max_total_bytes = NODE_PACKAGE_CONFIG_MAX_TOTAL_BYTES if request.max_total_bytes is None else request.max_total_bytes
    if max_files <= 0 or max_file_bytes <= 0 or max_total_bytes <= 0:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Node package config analysis limits must be positive.")
    return {"max_files": max_files, "max_file_bytes": max_file_bytes, "max_total_bytes": max_total_bytes}


def analyze_node_package_config_archive(
    path: Path,
    archive_type: str,
    *,
    max_files: int,
    max_file_bytes: int,
    max_total_bytes: int,
) -> dict[str, Any]:
    analysis = empty_node_package_config_analysis()
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
            scoped["id"] = f"node_package_config_{scoped['id']}"
            analysis["findings"].append(scoped)
            finalize_node_package_config_analysis(analysis)
            return analysis
        with zipfile.ZipFile(path) as archive:
            for index, info in enumerate(archive.filelist, start=1):
                if should_stop_node_package_config_archive_scan(index, analysis):
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
                process_node_package_config_entry(
                    analysis,
                    state,
                    entry,
                    lambda entry_info=info: archive.open(entry_info),
                )
    else:
        with tarfile.open(path, "r:*") as archive:
            for index, member in enumerate(archive, start=1):
                if should_stop_node_package_config_archive_scan(index, analysis):
                    break
                entry = {
                    "path": member.name,
                    "type": tar_member_type(member),
                    "size": member.size,
                    "mode_int": member.mode,
                    "mode": format_file_mode(member.mode),
                    "link_target": member.linkname or None,
                }
                process_node_package_config_entry(
                    analysis,
                    state,
                    entry,
                    lambda tar_member=member: archive.extractfile(tar_member),
                )

    finalize_node_package_config_analysis(analysis)
    return analysis


def empty_node_package_config_analysis(errors: list[str] | None = None) -> dict[str, Any]:
    return {
        "summary": {
            "files_considered": 0,
            "files_reviewed": 0,
            "package_manifests_detected": 0,
            "lockfiles_detected": 0,
            "package_manager_configs_detected": 0,
            "packages_detected": 0,
            "scripts_detected": 0,
            "findings_count": 0,
            "redacted_values_count": 0,
            "truncated": False,
        },
        "files_detected": [],
        "files_reviewed": [],
        "packages": [],
        "scripts": [],
        "dependency_groups": [],
        "package_manager_config_signals": [],
        "lockfile_signals": [],
        "findings": [],
        "redaction_notes": [],
        "errors": errors or [],
    }


def build_node_package_config_result(
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
        "analyzer": "node_package_config_basic",
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
        "packages": analysis.get("packages", []),
        "scripts": analysis.get("scripts", []),
        "dependency_groups": analysis.get("dependency_groups", []),
        "package_manager_config_signals": analysis.get("package_manager_config_signals", []),
        "lockfile_signals": analysis.get("lockfile_signals", []),
        "findings": findings,
        "redaction_notes": analysis.get("redaction_notes", []),
        "errors": analysis.get("errors", []),
        "truncated": bool(summary.get("truncated")),
    }


def should_stop_node_package_config_archive_scan(index: int, analysis: dict[str, Any]) -> bool:
    if index > ARCHIVE_MAX_ENTRIES:
        analysis["summary"]["truncated"] = True
        add_node_package_config_finding(
            analysis,
            "node_package_config_entry_limit_reached",
            "Archive entry scan limit reached",
            "medium",
            "high",
            "limit",
            "Inspectra stopped scanning archive metadata after the configured entry limit.",
            f"Processed {ARCHIVE_MAX_ENTRIES} entries.",
            "Review the archive with stricter limits or split it before deeper inspection.",
        )
        return True
    return False


def process_node_package_config_entry(
    analysis: dict[str, Any],
    state: dict[str, int],
    entry: dict[str, Any],
    open_entry,
) -> None:
    path = str(entry["path"])
    category = classify_node_package_config_candidate(path)
    if category is None:
        return

    summary = as_dict(analysis["summary"])
    summary["files_considered"] += 1
    increment_node_package_config_category_counts(summary, category)

    entry_type = str(entry["type"])
    size_bytes = int(entry.get("size") or 0)
    context = node_package_config_file_context(path, category)
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

    skip_reason = node_package_config_skip_reason(record, state)
    if skip_reason:
        record["skip_reason"] = skip_reason
        analysis["files_detected"].append(record)
        add_node_package_config_skip_finding(analysis, path, skip_reason, size_bytes, context)
        if category in {"lockfile", "lockfile_binary"} and skip_reason in {
            "binary_lockfile_not_read",
            "file_too_large",
            "total_bytes_limit",
        }:
            note_node_lockfile(analysis, path, category, context, read=False, skip_reason=skip_reason)
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
        add_node_package_config_finding(
            analysis,
            "node_package_config_file_read_error",
            "Node package config file could not be read safely",
            "low",
            "medium",
            "archive",
            "A candidate Node package configuration file could not be read from the archive within Inspectra limits.",
            f"{path}: {exc}",
            "Review this file manually in a constrained environment if it is expected.",
            file_path=path,
            context=context,
        )
        return

    state["total_bytes_read"] += len(raw_bytes)
    if b"\x00" in raw_bytes:
        record["skip_reason"] = "binary_or_non_text"
        analysis["files_detected"].append(record)
        add_node_package_config_skip_finding(analysis, path, "binary_or_non_text", size_bytes, context)
        return

    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        record["skip_reason"] = "binary_or_non_text"
        analysis["files_detected"].append(record)
        add_node_package_config_skip_finding(analysis, path, "binary_or_non_text", size_bytes, context)
        return

    state["files_read"] += 1
    summary["files_reviewed"] = state["files_read"]
    record["read"] = True
    record["bytes_read"] = len(raw_bytes)
    analysis["files_detected"].append(record)
    analysis["files_reviewed"].append(
        {"path": path, "category": category, "context": context, "size_bytes": size_bytes, "bytes_read": len(raw_bytes)}
    )
    analyze_node_package_config_text(analysis, path, category, context, text)


def classify_node_package_config_candidate(path: str) -> str | None:
    normalized = normalize_archive_entry_path(path)
    basename = normalized.rsplit("/", 1)[-1]
    basename_lower = basename.lower()
    lower = normalized.lower()

    if is_secrets_env_template_name(basename_lower):
        return "env_template"
    if is_secrets_sensitive_env_name(basename_lower):
        return "env_sensitive"
    if basename_lower == "package.json":
        return "package_manifest"
    if basename_lower in {"package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock"}:
        return "lockfile"
    if basename_lower == "bun.lockb":
        return "lockfile_binary"
    if basename_lower in {".npmrc", ".yarnrc", ".yarnrc.yml", "pnpm-workspace.yaml", "lerna.json", "turbo.json", "nx.json", "rush.json"}:
        return "package_manager_config"
    if is_node_js_ts_config_candidate(lower, basename_lower):
        return "js_ts_config"
    if is_node_ci_candidate(lower, basename_lower):
        return "ci_config"
    if basename_lower in {".releaserc", ".releaserc.json"} or basename_lower.startswith("release.config."):
        return "publishing_config"
    if lower.endswith(".changeset/config.json"):
        return "publishing_config"
    return None


def is_node_js_ts_config_candidate(normalized: str, basename: str) -> bool:
    if basename == "tsconfig.json" or (basename.startswith("tsconfig.") and basename.endswith(".json")):
        return True
    if basename.startswith((".eslintrc", "eslint.config.", "vite.config.", "webpack.config.", "rollup.config.", "next.config.", "nuxt.config.", "jest.config.", "vitest.config.")):
        return True
    return False


def is_node_ci_candidate(normalized: str, basename: str) -> bool:
    if normalized.startswith(".github/workflows/") and basename.endswith((".yml", ".yaml")):
        return True
    return basename == ".gitlab-ci.yml"


def increment_node_package_config_category_counts(summary: dict[str, Any], category: str) -> None:
    if category == "package_manifest":
        summary["package_manifests_detected"] += 1
    elif category in {"lockfile", "lockfile_binary"}:
        summary["lockfiles_detected"] += 1
    elif category == "package_manager_config":
        summary["package_manager_configs_detected"] += 1


def node_package_config_skip_reason(record: dict[str, Any], state: dict[str, int]) -> str | None:
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
    if record.get("category") == "lockfile_binary":
        return "binary_lockfile_not_read"
    if len(path) > ARCHIVE_MAX_ENTRY_NAME_LENGTH:
        return "entry_name_too_long"
    if size_bytes > state["max_file_bytes"]:
        return "file_too_large"
    if state["files_read"] >= state["max_files"]:
        return "too_many_files"
    if state["total_bytes_read"] + size_bytes > state["max_total_bytes"]:
        return "total_bytes_limit"
    return None


def add_node_package_config_skip_finding(analysis: dict[str, Any], path: str, reason: str, size_bytes: int, context: str) -> None:
    if reason in {"file_too_large", "too_many_files", "total_bytes_limit", "binary_lockfile_not_read"}:
        analysis["summary"]["truncated"] = True if reason in {"file_too_large", "too_many_files", "total_bytes_limit"} else analysis["summary"]["truncated"]
    titles = {
        "path_traversal": "Node package config path uses traversal",
        "absolute_path": "Node package config path is absolute",
        "entry_name_too_long": "Node package config entry name is unusually long",
        "file_too_large": "Node package config file omitted because it exceeds the size limit",
        "too_many_files": "Node package config file limit reached",
        "total_bytes_limit": "Total Node package config byte limit reached",
        "binary_or_non_text": "Node package config candidate is not UTF-8 text",
        "binary_lockfile_not_read": "Binary Node lockfile detected but not read",
        "real_env_file_not_read": "Real environment file detected but not read",
    }
    level = "medium" if reason in {"path_traversal", "absolute_path", "file_too_large", "too_many_files", "total_bytes_limit"} else "low"
    if reason in {"real_env_file_not_read", "binary_lockfile_not_read", "binary_or_non_text"}:
        level = "info"
    evidence = f"{path}: {size_bytes} bytes" if reason == "file_too_large" else path[:240]
    if reason.startswith("not_regular_file"):
        title = "Node package config candidate omitted because it is not a regular file"
        evidence = f"{path}: {reason}"
        level = "low"
    else:
        title = titles.get(reason, "Node package config candidate skipped by defensive limit")
    add_node_package_config_finding(
        analysis,
        f"node_package_config_{reason.split(':', 1)[0]}",
        title,
        node_contextual_level(level, context),
        node_contextual_confidence("high" if reason in {"path_traversal", "absolute_path", "real_env_file_not_read"} else "medium", context),
        "archive",
        "Inspectra detected a Node-related file but did not read it because of a defensive limit, unsupported binary format, or unsafe archive metadata.",
        evidence,
        "Review the archive manually in a constrained environment if this file is expected.",
        file_path=path,
        context=context,
    )


LOWER_CONFIDENCE_NODE_CONTEXTS = {"development", "test", "local", "example"}
NODE_LIFECYCLE_SCRIPTS = {"preinstall", "install", "postinstall", "prepare", "prepublish", "prepack", "postpack"}
NODE_DEPENDENCY_GROUPS = ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies")
NODE_SECRET_NAME_RE = re.compile(
    r"(?i)(SECRET_KEY|CLIENT_SECRET|PRIVATE_KEY|DATABASE_URL|REDIS_URL|API_KEY|PASSWORD|TOKEN|SECRET|PASS|AUTH|[A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|API_KEY|KEY)[A-Z0-9_]*)"
)


def node_package_config_file_context(path: str, category: str = "") -> str:
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
    if all_tokens.intersection({"test", "tests", "testing", "jest", "vitest"}):
        return "test"
    if all_tokens.intersection({"dev", "development", "override"}):
        return "development"
    if "local" in all_tokens:
        return "local"
    if all_tokens.intersection({"prod", "production", "release", "publish"}) or "deploy" in directories:
        return "production"
    if len(parts) == 1 and category in {"package_manifest", "lockfile", "package_manager_config"}:
        return "shared"
    if category == "env_template":
        return "example"
    return "ambiguous"


def node_contextual_level(level: str, context: str) -> str:
    if context not in LOWER_CONFIDENCE_NODE_CONTEXTS:
        return level
    if level == "medium":
        return "low"
    if level == "low":
        return "info"
    return level


def node_contextual_confidence(confidence: str, context: str) -> str:
    if context not in LOWER_CONFIDENCE_NODE_CONTEXTS:
        return confidence
    if confidence == "high":
        return "medium"
    if confidence == "medium":
        return "low"
    return confidence


def active_node_config_lines(text: str) -> list[tuple[int, str]]:
    lines: list[tuple[int, str]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("//") or stripped.startswith(";"):
            continue
        lines.append((line_number, line))
    return lines


def active_node_npmrc_lines(text: str) -> list[tuple[int, str]]:
    lines: list[tuple[int, str]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith(";"):
            continue
        lines.append((line_number, line))
    return lines


def analyze_node_package_config_text(analysis: dict[str, Any], path: str, category: str, context: str, text: str) -> None:
    basename = normalize_archive_entry_path(path).rsplit("/", 1)[-1].lower()
    if category == "package_manifest":
        analyze_node_package_json(analysis, path, context, text)
    elif category == "lockfile":
        note_node_lockfile(analysis, path, category, context, read=True)
    elif category == "package_manager_config" and basename == ".npmrc":
        analyze_node_npmrc(analysis, path, context, text)
    elif category == "js_ts_config":
        analyze_node_js_ts_config_text(analysis, path, context, text)
    elif category in {"env_template", "ci_config", "publishing_config", "package_manager_config"}:
        analyze_node_text_for_script_like_patterns(analysis, path, category, context, text)


def analyze_node_package_json(analysis: dict[str, Any], path: str, context: str, text: str) -> None:
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        add_node_package_config_finding(
            analysis,
            "node_package_json_parse_error",
            "package.json could not be parsed",
            "low",
            "medium",
            "package_manifest",
            "A package.json candidate could not be parsed as strict JSON. Inspectra did not execute or install anything.",
            f"{path}: {exc.msg}",
            "Review this manifest manually if it is expected to be valid JSON.",
            file_path=path,
            context=context,
        )
        return
    if not isinstance(parsed, dict):
        add_node_package_config_finding(
            analysis,
            "node_package_json_not_object",
            "package.json root is not an object",
            "low",
            "medium",
            "package_manifest",
            "A package.json candidate did not contain a JSON object at the root.",
            path,
            "Review the manifest manually if it is expected.",
            file_path=path,
            context=context,
        )
        return

    package_name = str(parsed.get("name") or "")
    package_record = {
        "path": path,
        "context": context,
        "name": package_name or None,
        "version": parsed.get("version") if isinstance(parsed.get("version"), str) else None,
        "private": parsed.get("private") if isinstance(parsed.get("private"), bool) else None,
        "package_manager": parsed.get("packageManager") if isinstance(parsed.get("packageManager"), str) else None,
    }
    analysis["packages"].append(package_record)
    analysis["summary"]["packages_detected"] = len(analysis["packages"])
    if package_record["package_manager"]:
        analysis.setdefault("_package_manager_hints", []).append({"path": path, "manager": str(package_record["package_manager"]).split("@", 1)[0].lower()})

    analyze_node_package_metadata(analysis, path, context, parsed)
    analyze_node_package_scripts(analysis, path, context, parsed.get("scripts"))
    analyze_node_package_dependencies(analysis, path, context, parsed)


def analyze_node_package_metadata(analysis: dict[str, Any], path: str, context: str, parsed: dict[str, Any]) -> None:
    if parsed.get("private") is not True:
        add_node_package_config_finding(
            analysis,
            "package_private_false_or_missing",
            "Package is not clearly private",
            node_contextual_level("info", context),
            node_contextual_confidence("medium", context),
            "package_metadata",
            "The package manifest does not set private: true. This is a publication-safety review indicator, not a finding by itself.",
            "private=true not observed",
            "If this package should never be published, set private: true.",
            file_path=path,
            context=context,
        )
    if not isinstance(parsed.get("packageManager"), str):
        add_node_package_config_finding(
            analysis,
            "package_manager_missing",
            "Package manager hint is missing",
            "info",
            node_contextual_confidence("medium", context),
            "package_metadata",
            "The package manifest does not declare a packageManager field.",
            "packageManager not observed",
            "Consider declaring packageManager to reduce package-manager ambiguity.",
            file_path=path,
            context=context,
        )
    if not isinstance(parsed.get("engines"), dict):
        add_node_package_config_finding(
            analysis,
            "engines_missing",
            "Node engines field is missing",
            "info",
            node_contextual_confidence("low", context),
            "package_metadata",
            "The package manifest does not declare runtime engine constraints.",
            "engines not observed",
            "Consider documenting supported Node.js versions if deployment reproducibility matters.",
            file_path=path,
            context=context,
        )
    if not parsed.get("license"):
        add_node_package_config_finding(
            analysis,
            "license_missing",
            "Package license metadata is missing",
            "info",
            node_contextual_confidence("low", context),
            "package_metadata",
            "The package manifest does not declare a license field.",
            "license not observed",
            "Add clear license metadata where appropriate.",
            file_path=path,
            context=context,
        )
    if not parsed.get("repository"):
        add_node_package_config_finding(
            analysis,
            "repository_missing",
            "Package repository metadata is missing",
            "info",
            node_contextual_confidence("low", context),
            "package_metadata",
            "The package manifest does not declare repository metadata.",
            "repository not observed",
            "Add repository metadata where useful for maintenance and provenance review.",
            file_path=path,
            context=context,
        )
    publish_config = parsed.get("publishConfig")
    if isinstance(publish_config, dict) and isinstance(publish_config.get("registry"), str):
        registry = safe_node_registry_evidence(str(publish_config["registry"]))
        add_node_package_config_finding(
            analysis,
            "publish_config_registry_present",
            "Package declares publish registry",
            node_contextual_level("info", context),
            node_contextual_confidence("medium", context),
            "package_metadata",
            "The package manifest declares publishConfig.registry.",
            f"publishConfig.registry={registry}",
            "Confirm the publish registry is intentional before publishing.",
            file_path=path,
            context=context,
        )


def analyze_node_package_scripts(analysis: dict[str, Any], path: str, context: str, scripts: Any) -> None:
    if not isinstance(scripts, dict):
        return
    for raw_name, raw_value in scripts.items():
        if not isinstance(raw_name, str) or not isinstance(raw_value, str):
            continue
        script_name = raw_name[:120]
        excerpt = safe_node_script_excerpt(raw_value)
        analysis["scripts"].append({"path": path, "context": context, "name": script_name, "excerpt": excerpt})
        analysis["summary"]["scripts_detected"] = len(analysis["scripts"])
        if script_name in NODE_LIFECYCLE_SCRIPTS:
            add_node_package_config_finding(
                analysis,
                "lifecycle_script_present",
                "Package lifecycle script is present",
                node_contextual_level("low", context),
                node_contextual_confidence("medium", context),
                "script",
                "The package manifest defines a lifecycle script. Inspectra does not execute scripts; this is a review indicator.",
                f"{script_name}: {excerpt}",
                "Review lifecycle scripts before running package managers in this project.",
                file_path=path,
                context=context,
            )
        if script_name == "postinstall":
            add_node_package_config_finding(
                analysis,
                "postinstall_script_present",
                "postinstall script is present",
                node_contextual_level("low", context),
                node_contextual_confidence("medium", context),
                "script",
                "The package manifest defines a postinstall script. Inspectra does not execute it.",
                f"postinstall: {excerpt}",
                "Review postinstall behavior before installing dependencies.",
                file_path=path,
                context=context,
            )
        if script_name == "prepare":
            add_node_package_config_finding(
                analysis,
                "prepare_script_present",
                "prepare script is present",
                node_contextual_level("low", context),
                node_contextual_confidence("medium", context),
                "script",
                "The package manifest defines a prepare script. Prepare can run during package workflows.",
                f"prepare: {excerpt}",
                "Review prepare behavior before publishing or installing from Git sources.",
                file_path=path,
                context=context,
            )
        if script_name in {"preinstall", "install"}:
            add_node_package_config_finding(
                analysis,
                "install_script_present",
                "install-time script is present",
                node_contextual_level("low", context),
                node_contextual_confidence("medium", context),
                "script",
                "The package manifest defines an install-time script. Inspectra does not execute it.",
                f"{script_name}: {excerpt}",
                "Review install-time behavior before running package managers.",
                file_path=path,
                context=context,
            )
        if node_script_uses_curl_pipe_shell(raw_value):
            add_node_package_config_finding(
                analysis,
                "script_uses_shell_curl_pipe",
                "Script pipes downloaded content to a shell",
                node_contextual_level("medium", context),
                node_contextual_confidence("high", context),
                "script",
                "A package script appears to pipe curl or wget output to sh/bash. Inspectra reports this as a review indicator.",
                f"{script_name}: curl/wget | sh/bash",
                "Prefer verified downloads and explicit checksums before executing installer scripts.",
                file_path=path,
                context=context,
            )
        if NODE_SECRET_NAME_RE.search(raw_value):
            add_node_package_config_finding(
                analysis,
                "script_references_env_secret_name",
                "Script references a sensitive-looking environment name",
                node_contextual_level("low", context),
                node_contextual_confidence("medium", context),
                "script",
                "A package script references a secret-like name. Inspectra redacts sensitive values and does not execute the script.",
                f"{script_name}: {safe_node_script_excerpt(raw_value)}",
                "Review script secret handling and avoid committing inline secrets.",
                file_path=path,
                context=context,
            )


def analyze_node_package_dependencies(analysis: dict[str, Any], path: str, context: str, parsed: dict[str, Any]) -> None:
    for group_name in NODE_DEPENDENCY_GROUPS:
        group = parsed.get(group_name)
        if not isinstance(group, dict):
            continue
        entries: list[dict[str, Any]] = []
        for raw_name, raw_spec in group.items():
            if not isinstance(raw_name, str):
                continue
            specifier = str(raw_spec)
            redacted_spec, count = redact_node_secret_text(specifier)
            analysis["summary"]["redacted_values_count"] += count
            entries.append({"name": raw_name[:180], "specifier": redacted_spec[:240], "source_type": classify_node_dependency_source(specifier)})
            add_node_dependency_findings(analysis, path, context, group_name, raw_name, specifier)
        if entries:
            analysis["dependency_groups"].append({"path": path, "context": context, "group": group_name, "dependencies": entries})
            if group_name == "optionalDependencies":
                add_node_package_config_finding(
                    analysis,
                    "optional_dependencies_present",
                    "optionalDependencies are present",
                    node_contextual_level("info", context),
                    node_contextual_confidence("low", context),
                    "dependency",
                    "The package declares optional dependencies. This is informational and may affect install-time behavior.",
                    f"optionalDependencies count={len(entries)}",
                    "Review optional dependencies if reproducibility or platform-specific installs matter.",
                    file_path=path,
                    context=context,
                )


def add_node_dependency_findings(
    analysis: dict[str, Any],
    path: str,
    context: str,
    group_name: str,
    dependency_name: str,
    specifier: str,
) -> None:
    source_type = classify_node_dependency_source(specifier)
    evidence = safe_node_dependency_evidence(group_name, dependency_name, specifier)
    if specifier.strip() == "*":
        add_node_package_config_finding(
            analysis,
            "wildcard_dependency_version",
            "Dependency uses wildcard version",
            node_contextual_level("low", context),
            node_contextual_confidence("medium", context),
            "dependency",
            "A dependency is declared with a wildcard version.",
            evidence,
            "Use a narrower version policy where reproducibility matters.",
            file_path=path,
            context=context,
        )
    if node_dependency_is_broad_range(specifier):
        add_node_package_config_finding(
            analysis,
            "broad_dependency_range",
            "Dependency uses a broad version range",
            node_contextual_level("low", context),
            node_contextual_confidence("medium", context),
            "dependency",
            "A dependency uses a broad or floating version declaration.",
            evidence,
            "Review whether this range is intentional for the project.",
            file_path=path,
            context=context,
        )
    elif node_dependency_is_unpinned_range(specifier):
        add_node_package_config_finding(
            analysis,
            "unpinned_dependency_range",
            "Dependency uses an unpinned version range",
            node_contextual_level("low", context),
            node_contextual_confidence("medium", context),
            "dependency",
            "A dependency uses a non-exact semver range.",
            evidence,
            "Use lockfiles and review whether the version policy matches the deployment workflow.",
            file_path=path,
            context=context,
        )

    source_findings = {
        "git": ("git_dependency_reference", "Dependency references a Git source"),
        "url": ("url_dependency_reference", "Dependency references a URL source"),
        "file": ("file_dependency_reference", "Dependency references a local file source"),
        "workspace": ("workspace_dependency_reference", "Dependency uses a workspace reference"),
        "alias": ("alias_dependency_reference", "Dependency uses npm alias syntax"),
    }
    if source_type in source_findings:
        finding_id, title = source_findings[source_type]
        add_node_package_config_finding(
            analysis,
            finding_id,
            title,
            node_contextual_level("low", context),
            node_contextual_confidence("medium", context),
            "dependency",
            "The dependency source is not a plain registry semver declaration. This is a review indicator, not a malicious-package verdict.",
            evidence,
            "Review non-registry or indirect dependency references before installing in trusted environments.",
            file_path=path,
            context=context,
        )


def classify_node_dependency_source(specifier: str) -> str:
    value = specifier.strip().lower()
    if value.startswith("workspace:"):
        return "workspace"
    if value.startswith("npm:"):
        return "alias"
    if value.startswith("file:") or value.startswith(("../", "./", "/")):
        return "file"
    if value.startswith(("git+", "git://", "github:", "gitlab:", "bitbucket:")) or "github.com/" in value:
        return "git"
    if value.startswith(("http://", "https://")):
        return "url"
    return "registry"


def node_dependency_is_broad_range(specifier: str) -> bool:
    value = specifier.strip().lower()
    return value in {"", "*", "x", "latest"} or value.startswith((">=", ">", "<=", "<")) or "||" in value


def node_dependency_is_unpinned_range(specifier: str) -> bool:
    value = specifier.strip()
    if not value or classify_node_dependency_source(value) != "registry":
        return False
    if value.startswith(("^", "~")):
        return True
    return bool(re.search(r"[<>=*xX|]", value))


def safe_node_dependency_evidence(group_name: str, dependency_name: str, specifier: str) -> str:
    redacted, _count = redact_node_secret_text(specifier)
    return f"{group_name}.{dependency_name}={redacted[:220]}"


def analyze_node_npmrc(analysis: dict[str, Any], path: str, context: str, text: str) -> None:
    for line_number, line in active_node_npmrc_lines(text):
        stripped = line.strip()
        if "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        key = key.strip()
        value = value.strip()
        lower_key = key.lower()
        if node_npmrc_key_is_auth_like(lower_key):
            analysis["package_manager_config_signals"].append(
                {"path": path, "context": context, "key": key[:160], "value": "[REDACTED]", "line": line_number}
            )
            add_node_package_config_finding(
                analysis,
                "npmrc_token_reference_detected",
                ".npmrc contains an auth-like value",
                node_contextual_level("medium", context),
                node_contextual_confidence("high", context),
                "package_manager_config",
                ".npmrc includes token/auth-like configuration. Inspectra redacted the value and did not validate it.",
                f"{key}=[REDACTED]",
                "Use scoped package-manager auth carefully and avoid sharing real tokens in archives.",
                file_path=path,
                context=context,
                line=line_number,
                redacted=True,
            )
        if lower_key.endswith("registry") or lower_key == "registry":
            registry = safe_node_registry_evidence(value)
            analysis["package_manager_config_signals"].append(
                {"path": path, "context": context, "key": key[:160], "value": registry, "line": line_number}
            )
            add_node_package_config_finding(
                analysis,
                "npmrc_registry_override",
                ".npmrc overrides a registry",
                node_contextual_level("low", context),
                node_contextual_confidence("medium", context),
                "package_manager_config",
                ".npmrc appears to override a package registry.",
                f"{key}={registry}",
                "Confirm the registry override is intentional before installing or publishing packages.",
                file_path=path,
                context=context,
                line=line_number,
            )
        if lower_key == "strict-ssl" and value.lower() == "false":
            add_node_package_config_finding(
                analysis,
                "npmrc_strict_ssl_disabled",
                ".npmrc disables strict SSL",
                node_contextual_level("medium", context),
                node_contextual_confidence("high", context),
                "package_manager_config",
                ".npmrc sets strict-ssl=false.",
                "strict-ssl=false",
                "Avoid disabling TLS verification for package-manager operations.",
                file_path=path,
                context=context,
                line=line_number,
            )
        if lower_key == "ignore-scripts":
            add_node_package_config_finding(
                analysis,
                "npmrc_ignore_scripts_configured",
                ".npmrc configures ignore-scripts",
                "info",
                node_contextual_confidence("medium", context),
                "package_manager_config",
                ".npmrc configures ignore-scripts. This affects install-time behavior and should be understood.",
                f"ignore-scripts={value[:80]}",
                "Confirm the setting matches the intended dependency workflow.",
                file_path=path,
                context=context,
                line=line_number,
            )
        if lower_key == "unsafe-perm" and value.lower() == "true":
            add_node_package_config_finding(
                analysis,
                "npmrc_unsafe_perm_enabled",
                ".npmrc enables unsafe-perm",
                node_contextual_level("medium", context),
                node_contextual_confidence("high", context),
                "package_manager_config",
                ".npmrc sets unsafe-perm=true.",
                "unsafe-perm=true",
                "Review whether elevated install script permissions are required.",
                file_path=path,
                context=context,
                line=line_number,
            )


def node_npmrc_key_is_auth_like(lower_key: str) -> bool:
    return any(token in lower_key for token in ("_authtoken", "_auth", "_password", "password", "token", "secret", "api_key", "apikey"))


def analyze_node_js_ts_config_text(analysis: dict[str, Any], path: str, context: str, text: str) -> None:
    active_text = "\n".join(line for _line_number, line in active_node_config_lines(text))
    basename = normalize_archive_entry_path(path).rsplit("/", 1)[-1].lower()
    if basename.startswith("tsconfig") and re.search(r"(?i)[\"']?skipLibCheck[\"']?\s*:\s*true\b", active_text):
        add_node_package_config_finding(
            analysis,
            "tsconfig_skip_lib_check_hint",
            "tsconfig enables skipLibCheck",
            "info",
            node_contextual_confidence("low", context),
            "typescript_config",
            "A TypeScript config appears to set skipLibCheck=true. This is an informational build-hygiene signal.",
            "skipLibCheck=true",
            "Confirm the tradeoff is intentional for this project.",
            file_path=path,
            context=context,
        )
    if basename.startswith("vite.config") and re.search(r"(?is)\bhost\s*:\s*['\"](?:0\.0\.0\.0|::)['\"]", active_text):
        add_node_package_config_finding(
            analysis,
            "vite_dev_host_exposed_hint",
            "Vite dev server host appears broadly exposed",
            node_contextual_level("low", context),
            node_contextual_confidence("medium", context),
            "dev_server_config",
            "A Vite config appears to set dev server host to a broad bind address.",
            "server.host=0.0.0.0",
            "Confirm this is only used in authorized local or containerized development environments.",
            file_path=path,
            context=context,
        )
    if basename.startswith("webpack.config") and re.search(r"(?is)\bhost\s*:\s*['\"](?:0\.0\.0\.0|::)['\"]", active_text):
        add_node_package_config_finding(
            analysis,
            "webpack_dev_server_exposed_hint",
            "webpack dev server host appears broadly exposed",
            node_contextual_level("low", context),
            node_contextual_confidence("medium", context),
            "dev_server_config",
            "A webpack config appears to set dev server host to a broad bind address.",
            "devServer.host=0.0.0.0",
            "Confirm this is only used in authorized local or containerized development environments.",
            file_path=path,
            context=context,
        )
    if re.search(r"(?i)\b(?:sourcemap|sourceMap|devtool)\s*[:=]\s*['\"]?(?:true|source-map|inline-source-map)", active_text):
        add_node_package_config_finding(
            analysis,
            "source_maps_enabled_hint",
            "Source maps appear enabled in config",
            "info",
            node_contextual_confidence("low", context),
            "build_config",
            "A JavaScript build config appears to enable source maps.",
            "source maps enabled hint",
            "Confirm source map behavior matches the deployment context.",
            file_path=path,
            context=context,
        )


def analyze_node_text_for_script_like_patterns(analysis: dict[str, Any], path: str, category: str, context: str, text: str) -> None:
    active_text = "\n".join(line for _line_number, line in active_node_config_lines(text))
    if node_script_uses_curl_pipe_shell(active_text):
        add_node_package_config_finding(
            analysis,
            "script_uses_shell_curl_pipe",
            "Config text pipes downloaded content to a shell",
            node_contextual_level("medium", context),
            node_contextual_confidence("medium", context),
            "script",
            "A candidate config file appears to pipe curl or wget output to sh/bash.",
            "curl/wget | sh/bash",
            "Prefer verified downloads and explicit checksums before executing installer scripts.",
            file_path=path,
            context=context,
        )


def node_script_uses_curl_pipe_shell(value: str) -> bool:
    return bool(re.search(r"(?is)\b(?:curl|wget)\b[^\n|]*\|[^\n]*(?:sh|bash)\b", value))


def note_node_lockfile(
    analysis: dict[str, Any],
    path: str,
    category: str,
    context: str,
    *,
    read: bool,
    skip_reason: str | None = None,
) -> None:
    basename = normalize_archive_entry_path(path).rsplit("/", 1)[-1].lower()
    manager = node_lockfile_manager(basename)
    signal = {"path": path, "context": context, "lockfile": basename, "manager": manager, "read": read}
    if skip_reason:
        signal["skip_reason"] = skip_reason
    analysis["lockfile_signals"].append(signal)
    analysis.setdefault("_lockfile_managers", []).append({"path": path, "manager": manager})
    if basename in {"package-lock.json", "npm-shrinkwrap.json"}:
        add_node_package_config_finding(
            analysis,
            "package_lock_present",
            "npm package lockfile detected",
            "info",
            node_contextual_confidence("low", context),
            "lockfile",
            "An npm package lockfile is present. This is informational for package-manager consistency review.",
            basename,
            "Confirm the lockfile matches the package manager used by the project.",
            file_path=path,
            context=context,
        )
    if skip_reason in {"file_too_large", "total_bytes_limit", "binary_lockfile_not_read"}:
        add_node_package_config_finding(
            analysis,
            "lockfile_large_or_truncated",
            "Lockfile was not fully reviewed",
            node_contextual_level("low", context),
            node_contextual_confidence("medium", context),
            "lockfile",
            "A lockfile was skipped or truncated because of format or size limits.",
            f"{basename}: {skip_reason}",
            "Review this lockfile manually if lockfile consistency matters.",
            file_path=path,
            context=context,
        )


def node_lockfile_manager(basename: str) -> str:
    if basename in {"package-lock.json", "npm-shrinkwrap.json"}:
        return "npm"
    if basename == "pnpm-lock.yaml":
        return "pnpm"
    if basename == "yarn.lock":
        return "yarn"
    if basename in {"bun.lock", "bun.lockb"}:
        return "bun"
    return "unknown"


def finalize_node_package_config_analysis(analysis: dict[str, Any]) -> None:
    lockfile_managers = {item.get("manager") for item in analysis.get("_lockfile_managers", []) if item.get("manager")}
    if len(lockfile_managers) > 1:
        add_node_package_config_finding(
            analysis,
            "multiple_lockfiles_present",
            "Multiple package-manager lockfiles detected",
            "low",
            "medium",
            "lockfile",
            "The archive contains lockfiles for more than one package manager.",
            ", ".join(sorted(lockfile_managers)),
            "Confirm the intended package manager and remove stale lockfiles if they are not used.",
        )
    for hint in analysis.get("_package_manager_hints", []):
        manager = hint.get("manager")
        if manager and lockfile_managers and manager not in lockfile_managers:
            add_node_package_config_finding(
                analysis,
                "package_manager_mismatch",
                "Package manager hint does not match observed lockfiles",
                "low",
                "medium",
                "lockfile",
                "The packageManager field appears inconsistent with observed lockfiles.",
                f"packageManager={manager}; lockfiles={', '.join(sorted(lockfile_managers))}",
                "Confirm stale lockfiles are removed and the intended package manager is documented.",
                file_path=hint.get("path") if isinstance(hint.get("path"), str) else None,
            )
    analysis["findings"] = dedupe_findings(analysis["findings"])
    analysis["summary"]["findings_count"] = len(analysis["findings"])
    if analysis["summary"]["redacted_values_count"]:
        analysis["redaction_notes"] = [
            "Secret-like values in Node package configuration evidence are redacted before storage and export on a best-effort basis.",
        ]


def safe_node_script_excerpt(value: str) -> str:
    redacted, _count = redact_node_secret_text(value)
    collapsed = re.sub(r"\s+", " ", redacted).strip()
    return collapsed[:220]


def safe_node_registry_evidence(value: str) -> str:
    try:
        parsed = urlsplit(value)
    except ValueError:
        parsed = None
    if parsed and parsed.scheme and parsed.hostname:
        host = parsed.hostname
        try:
            port = parsed.port
        except ValueError:
            port = None
        if port:
            host = f"{host}:{port}"
        return f"{parsed.scheme}://{host}"
    redacted, _count = redact_node_secret_text(value)
    return redacted[:180]


def redact_node_secret_text(text: str) -> tuple[str, int]:
    redacted = text
    count = 0

    def apply(pattern: str, replacement: str, value: str, flags: int = 0) -> str:
        nonlocal count
        updated, replacements = re.subn(pattern, replacement, value, flags=flags)
        count += replacements
        return updated

    redacted = redact_secrets_review_text(redacted)
    if redacted != text:
        count += 1
    redacted = apply(
        r"(?i)([_A-Z0-9.-]*(?:_authToken|_auth|_password|password|token|api_key|apikey|secret|key)[_A-Z0-9.-]*\s*[:=]\s*)(['\"]?)[^\s,'\"}\]]+",
        r"\1\2[REDACTED]",
        redacted,
    )
    redacted = apply(
        r"(?i)\b([a-z][a-z0-9+.-]*://)([^:\s/@]+):([^@\s]+)@",
        r"\1[REDACTED]@",
        redacted,
    )
    redacted = apply(
        r"(?i)([?&](?:token|api_key|apikey|key|secret|password|code|state)=)[^&\s'\"<>]+",
        r"\1[REDACTED]",
        redacted,
    )
    return redacted, count


def add_node_package_config_finding(
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
    redacted: bool = False,
) -> None:
    safe_description, description_redactions = redact_node_secret_text(description)
    safe_evidence, evidence_redactions = redact_node_secret_text(evidence)
    safe_recommendation, recommendation_redactions = redact_node_secret_text(recommendation)
    redaction_count = description_redactions + evidence_redactions + recommendation_redactions
    if redacted and redaction_count == 0:
        redaction_count = 1
    analysis["summary"]["redacted_values_count"] += redaction_count

    finding = make_finding(finding_id, title, level, safe_description, safe_evidence, safe_recommendation)
    finding["confidence"] = confidence
    finding["category"] = category
    if file_path:
        finding["file_path"] = file_path
    if context:
        finding["context"] = context
    if line is not None:
        finding["line"] = line
    analysis["findings"].append(finding)


def ci_cd_config_limits(request: ArchiveAnalysisRequest) -> dict[str, int]:
    max_files = CI_CD_CONFIG_MAX_FILES if request.max_files is None else request.max_files
    max_file_bytes = CI_CD_CONFIG_MAX_FILE_BYTES if request.max_file_bytes is None else request.max_file_bytes
    max_total_bytes = CI_CD_CONFIG_MAX_TOTAL_BYTES if request.max_total_bytes is None else request.max_total_bytes
    if max_files <= 0 or max_file_bytes <= 0 or max_total_bytes <= 0:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="CI/CD config analysis limits must be positive.")
    return {"max_files": max_files, "max_file_bytes": max_file_bytes, "max_total_bytes": max_total_bytes}


def analyze_ci_cd_config_archive(
    path: Path,
    archive_type: str,
    *,
    max_files: int,
    max_file_bytes: int,
    max_total_bytes: int,
) -> dict[str, Any]:
    analysis = empty_ci_cd_config_analysis()
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
            scoped["id"] = f"ci_cd_config_{scoped['id']}"
            analysis["findings"].append(scoped)
            finalize_ci_cd_config_analysis(analysis)
            return analysis
        with zipfile.ZipFile(path) as archive:
            for index, info in enumerate(archive.filelist, start=1):
                if should_stop_ci_cd_config_archive_scan(index, analysis):
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
                process_ci_cd_config_entry(
                    analysis,
                    state,
                    entry,
                    lambda entry_info=info: archive.open(entry_info),
                )
    else:
        with tarfile.open(path, "r:*") as archive:
            for index, member in enumerate(archive, start=1):
                if should_stop_ci_cd_config_archive_scan(index, analysis):
                    break
                entry = {
                    "path": member.name,
                    "type": tar_member_type(member),
                    "size": member.size,
                    "mode_int": member.mode,
                    "mode": format_file_mode(member.mode),
                    "link_target": member.linkname or None,
                }
                process_ci_cd_config_entry(
                    analysis,
                    state,
                    entry,
                    lambda tar_member=member: archive.extractfile(tar_member),
                )

    finalize_ci_cd_config_analysis(analysis)
    return analysis


def empty_ci_cd_config_analysis(errors: list[str] | None = None) -> dict[str, Any]:
    return {
        "summary": {
            "files_considered": 0,
            "files_reviewed": 0,
            "workflow_files_detected": 0,
            "jobs_detected": 0,
            "steps_detected": 0,
            "triggers_detected": 0,
            "findings_count": 0,
            "redacted_values_count": 0,
            "truncated": False,
        },
        "files_detected": [],
        "files_reviewed": [],
        "workflows": [],
        "jobs": [],
        "triggers": [],
        "permissions": [],
        "actions": [],
        "service_containers": [],
        "publish_deploy_signals": [],
        "findings": [],
        "redaction_notes": [],
        "errors": errors or [],
    }


def build_ci_cd_config_result(
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
        "analyzer": "ci_cd_config_basic",
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
        "workflows": analysis.get("workflows", []),
        "jobs": analysis.get("jobs", []),
        "triggers": analysis.get("triggers", []),
        "permissions": analysis.get("permissions", []),
        "actions": analysis.get("actions", []),
        "service_containers": analysis.get("service_containers", []),
        "publish_deploy_signals": analysis.get("publish_deploy_signals", []),
        "findings": findings,
        "redaction_notes": analysis.get("redaction_notes", []),
        "errors": analysis.get("errors", []),
        "truncated": bool(summary.get("truncated")),
    }


def should_stop_ci_cd_config_archive_scan(index: int, analysis: dict[str, Any]) -> bool:
    if index > ARCHIVE_MAX_ENTRIES:
        analysis["summary"]["truncated"] = True
        add_ci_cd_config_finding(
            analysis,
            "ci_cd_config_entry_limit_reached",
            "Archive entry scan limit reached",
            "medium",
            "high",
            "limit",
            "Inspectra stopped scanning archive metadata after the configured entry limit.",
            f"Processed {ARCHIVE_MAX_ENTRIES} entries.",
            "Review the archive with stricter limits or split it before deeper inspection.",
        )
        return True
    return False


def process_ci_cd_config_entry(
    analysis: dict[str, Any],
    state: dict[str, int],
    entry: dict[str, Any],
    open_entry,
) -> None:
    path = str(entry["path"])
    category = classify_ci_cd_config_candidate(path)
    if category is None:
        return

    summary = as_dict(analysis["summary"])
    summary["files_considered"] += 1
    if category != "env_sensitive":
        summary["workflow_files_detected"] += 1

    entry_type = str(entry["type"])
    size_bytes = int(entry.get("size") or 0)
    provider = ci_cd_provider_for_category(category)
    context = ci_cd_config_file_context(path, category)
    flags, depth = archive_entry_flags(path, entry.get("mode_int"))
    record = {
        "path": path,
        "category": category,
        "provider": provider,
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

    skip_reason = ci_cd_config_skip_reason(record, state)
    if skip_reason:
        record["skip_reason"] = skip_reason
        analysis["files_detected"].append(record)
        add_ci_cd_config_skip_finding(analysis, path, skip_reason, size_bytes, context)
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
        add_ci_cd_config_finding(
            analysis,
            "ci_cd_config_file_read_error",
            "CI/CD config file could not be read safely",
            "low",
            "medium",
            "archive",
            "A candidate CI/CD configuration file could not be read from the archive within Inspectra limits.",
            f"{path}: {exc}",
            "Review this file manually in a constrained environment if it is expected.",
            file_path=path,
            context=context,
            provider=provider,
        )
        return

    state["total_bytes_read"] += len(raw_bytes)
    if b"\x00" in raw_bytes:
        record["skip_reason"] = "binary_or_non_text"
        analysis["files_detected"].append(record)
        add_ci_cd_config_skip_finding(analysis, path, "binary_or_non_text", size_bytes, context)
        return

    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        record["skip_reason"] = "binary_or_non_text"
        analysis["files_detected"].append(record)
        add_ci_cd_config_skip_finding(analysis, path, "binary_or_non_text", size_bytes, context)
        return

    state["files_read"] += 1
    summary["files_reviewed"] = state["files_read"]
    record["read"] = True
    record["bytes_read"] = len(raw_bytes)
    analysis["files_detected"].append(record)
    analysis["files_reviewed"].append(
        {
            "path": path,
            "category": category,
            "provider": provider,
            "context": context,
            "size_bytes": size_bytes,
            "bytes_read": len(raw_bytes),
        }
    )
    analyze_ci_cd_config_text(analysis, path, category, provider, context, text)


def classify_ci_cd_config_candidate(path: str) -> str | None:
    normalized = normalize_archive_entry_path(path)
    lower = normalized.lower()
    basename = lower.rsplit("/", 1)[-1]

    if is_secrets_sensitive_env_name(basename):
        return "env_sensitive"
    if ".github/workflows/" in lower and basename.endswith((".yml", ".yaml")):
        return "github_workflow"
    if basename in {"action.yml", "action.yaml"} and (".github/actions/" in lower or "/" not in normalized):
        return "github_action"
    if basename in {".gitlab-ci.yml", ".gitlab-ci.yaml"} or (".gitlab/ci/" in lower and basename.endswith((".yml", ".yaml"))):
        return "gitlab_ci"
    if basename in {"bitbucket-pipelines.yml", "bitbucket-pipelines.yaml"}:
        return "bitbucket_pipeline"
    if basename in {"azure-pipelines.yml", "azure-pipelines.yaml"} or (lower.startswith(".azure-pipelines/") and basename.endswith((".yml", ".yaml"))):
        return "azure_pipeline"
    if lower in {".circleci/config.yml", ".circleci/config.yaml"}:
        return "circleci"
    if basename == "jenkinsfile" or basename.startswith("jenkinsfile."):
        return "jenkins"
    if basename == "buildkite.yml" or lower == ".buildkite/pipeline.yml":
        return "buildkite"
    if basename in {"drone.yml", ".drone.yml"}:
        return "drone"
    if basename in {"woodpecker.yml", ".woodpecker.yml"}:
        return "woodpecker"
    if basename in {".releaserc", ".releaserc.json"} or basename.startswith("release.config."):
        return "release_config"
    if lower.endswith(".changeset/config.json"):
        return "release_config"
    return None


def ci_cd_provider_for_category(category: str) -> str:
    return {
        "github_workflow": "github_actions",
        "github_action": "github_actions",
        "gitlab_ci": "gitlab_ci",
        "bitbucket_pipeline": "bitbucket_pipelines",
        "azure_pipeline": "azure_pipelines",
        "circleci": "circleci",
        "jenkins": "jenkins",
        "buildkite": "buildkite",
        "drone": "drone",
        "woodpecker": "woodpecker",
        "release_config": "release_config",
        "env_sensitive": "env",
    }.get(category, "generic_ci")


def ci_cd_config_skip_reason(record: dict[str, Any], state: dict[str, int]) -> str | None:
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


def add_ci_cd_config_skip_finding(analysis: dict[str, Any], path: str, reason: str, size_bytes: int, context: str) -> None:
    if reason in {"file_too_large", "too_many_files", "total_bytes_limit"}:
        analysis["summary"]["truncated"] = True
    level = "medium" if reason in {"path_traversal", "absolute_path", "file_too_large", "too_many_files", "total_bytes_limit"} else "low"
    if reason in {"real_env_file_not_read", "binary_or_non_text"}:
        level = "info"
    title = {
        "path_traversal": "CI/CD config path uses traversal",
        "absolute_path": "CI/CD config path is absolute",
        "entry_name_too_long": "CI/CD config entry name is unusually long",
        "file_too_large": "CI/CD config file omitted because it exceeds the size limit",
        "too_many_files": "CI/CD config file limit reached",
        "total_bytes_limit": "Total CI/CD config byte limit reached",
        "binary_or_non_text": "CI/CD config candidate is not UTF-8 text",
        "real_env_file_not_read": "Real environment file detected but not read",
    }.get(reason, "CI/CD config candidate skipped by defensive limit")
    if reason.startswith("not_regular_file"):
        title = "CI/CD config candidate omitted because it is not a regular file"
        level = "low"
    evidence = f"{path}: {reason}" if reason.startswith("not_regular_file") else f"{path}: {size_bytes} bytes" if reason == "file_too_large" else path[:240]
    add_ci_cd_config_finding(
        analysis,
        f"ci_cd_config_{reason.split(':', 1)[0]}",
        title,
        ci_cd_contextual_level(level, context),
        ci_cd_contextual_confidence("high" if reason in {"path_traversal", "absolute_path", "real_env_file_not_read"} else "medium", context),
        "archive",
        "Inspectra detected a CI/CD-related file but did not read it because of a defensive limit, unsupported format, or unsafe archive metadata.",
        evidence,
        "Review the archive manually in a constrained environment if this file is expected.",
        file_path=path,
        context=context,
    )


LOWER_CONFIDENCE_CI_CD_CONTEXTS = {"development", "test", "local", "example"}
CI_SECRET_NAME_RE = re.compile(
    r"(?i)(SECRET_KEY|CLIENT_SECRET|PRIVATE_KEY|DATABASE_URL|REDIS_URL|API_KEY|PASSWORD|TOKEN|SECRET|PASS|AUTH|[A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|API_KEY|KEY)[A-Z0-9_]*)"
)
CI_ASSIGNMENT_RE = re.compile(r"(?i)\b([A-Z0-9_.-]*(?:SECRET|TOKEN|PASSWORD|API_KEY|PRIVATE_KEY|CLIENT_SECRET|KEY)[A-Z0-9_.-]*)\s*[:=]\s*([^\s,'\"}\]]+)")
CI_URL_USERINFO_RE = re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^:\s/@]+:[^@\s]+@")
CI_FULL_SHA_RE = re.compile(r"^[a-f0-9]{40}$", re.IGNORECASE)


def ci_cd_config_file_context(path: str, category: str = "") -> str:
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
    if all_tokens.intersection({"test", "tests", "testing", "ci-test"}):
        return "test"
    if all_tokens.intersection({"dev", "development"}):
        return "development"
    if "local" in all_tokens:
        return "local"
    if all_tokens.intersection({"prod", "production", "release", "publish", "deploy"}) or "deploy" in directories:
        return "production"
    if category in {"github_workflow", "gitlab_ci", "bitbucket_pipeline", "azure_pipeline", "circleci"}:
        return "shared"
    return "ambiguous"


def ci_cd_contextual_level(level: str, context: str) -> str:
    if context not in LOWER_CONFIDENCE_CI_CD_CONTEXTS:
        return level
    if level == "medium":
        return "low"
    if level == "low":
        return "info"
    return level


def ci_cd_contextual_confidence(confidence: str, context: str) -> str:
    if context not in LOWER_CONFIDENCE_CI_CD_CONTEXTS:
        return confidence
    if confidence == "high":
        return "medium"
    if confidence == "medium":
        return "low"
    return confidence


def active_ci_cd_config_lines(text: str) -> list[tuple[int, str]]:
    lines: list[tuple[int, str]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("//"):
            continue
        lines.append((line_number, line))
    return lines


def analyze_ci_cd_config_text(analysis: dict[str, Any], path: str, category: str, provider: str, context: str, text: str) -> None:
    lines = active_ci_cd_config_lines(text)
    active_text = "\n".join(line for _line_number, line in lines)
    workflow = {
        "path": path,
        "provider": provider,
        "context": context,
        "category": category,
        "read": True,
    }
    analysis["workflows"].append(workflow)

    job_names = extract_ci_cd_job_names(lines)
    step_count = count_ci_cd_steps(lines)
    for job_name in job_names:
        analysis["jobs"].append({"path": path, "provider": provider, "context": context, "job": job_name})
    analysis["summary"]["jobs_detected"] += len(job_names)
    analysis["summary"]["steps_detected"] += step_count

    analyze_ci_cd_triggers(analysis, path, provider, context, active_text)
    analyze_ci_cd_permissions(analysis, path, provider, context, active_text)
    analyze_ci_cd_actions_and_images(analysis, path, provider, context, lines)
    analyze_ci_cd_secret_and_script_signals(analysis, path, provider, context, lines)
    analyze_ci_cd_publish_deploy_signals(analysis, path, provider, context, lines, active_text)
    analyze_ci_cd_misc_signals(analysis, path, provider, context, lines, active_text)


def extract_ci_cd_job_names(lines: list[tuple[int, str]]) -> list[str]:
    names: list[str] = []
    in_jobs = False
    for _line_number, line in lines:
        stripped = line.strip()
        if re.match(r"jobs\s*:\s*$", stripped):
            in_jobs = True
            continue
        if in_jobs:
            match = re.match(r"([A-Za-z0-9_.-]+)\s*:\s*$", stripped)
            if match and match.group(1) not in {"steps", "runs-on", "permissions", "env", "strategy", "with", "services"}:
                names.append(match.group(1))
            if stripped and not line.startswith((" ", "\t", "-")) and not match:
                in_jobs = False
    return names[:100]


def count_ci_cd_steps(lines: list[tuple[int, str]]) -> int:
    return sum(1 for _line_number, line in lines if re.search(r"^\s*-\s+(?:name|run|uses)\s*:", line))


def add_ci_cd_trigger(analysis: dict[str, Any], path: str, provider: str, context: str, trigger: str, line: int | None = None) -> None:
    analysis["triggers"].append({"path": path, "provider": provider, "context": context, "trigger": trigger, **({"line": line} if line else {})})
    analysis["summary"]["triggers_detected"] = len(analysis["triggers"])


def analyze_ci_cd_triggers(analysis: dict[str, Any], path: str, provider: str, context: str, active_text: str) -> None:
    checks = [
        ("pull_request_target", "pull_request_target_used", "GitHub pull_request_target trigger is present", "medium"),
        ("workflow_dispatch", "workflow_dispatch_with_inputs", "Manual workflow dispatch trigger is present", "low"),
        ("schedule", "schedule_trigger_present", "Scheduled workflow trigger is present", "low"),
        ("pull_request", "broad_pull_request_trigger", "Pull request trigger appears broad", "low"),
        ("push", "broad_push_trigger", "Push trigger appears broad", "low"),
    ]
    for trigger, finding_id, title, level in checks:
        if re.search(rf"(?m)^\s*(?:-\s*)?{re.escape(trigger)}\s*:", active_text) or re.search(rf"(?m)^\s*-\s*{re.escape(trigger)}\s*$", active_text):
            add_ci_cd_trigger(analysis, path, provider, context, trigger)
            add_ci_cd_config_finding(
                analysis,
                finding_id,
                title,
                ci_cd_contextual_level(level, context),
                ci_cd_contextual_confidence("medium", context),
                "trigger",
                "A CI/CD trigger was observed. This is a review indicator, not evidence of exploitability.",
                trigger,
                "Confirm this trigger matches the intended trust boundary for the workflow.",
                file_path=path,
                context=context,
                provider=provider,
            )


def analyze_ci_cd_permissions(analysis: dict[str, Any], path: str, provider: str, context: str, active_text: str) -> None:
    if provider != "github_actions":
        return
    if "permissions" not in active_text:
        add_ci_cd_config_finding(
            analysis,
            "github_permissions_missing",
            "GitHub workflow has no explicit permissions block",
            ci_cd_contextual_level("low", context),
            ci_cd_contextual_confidence("medium", context),
            "permissions",
            "No explicit GitHub Actions permissions block was observed in this workflow.",
            "permissions: not found",
            "Declare least-privilege workflow permissions where practical.",
            file_path=path,
            context=context,
            provider=provider,
        )
        return
    permission_checks = [
        (r"permissions\s*:\s*write-all\b", "github_permissions_write_all", "GitHub workflow grants write-all permissions", "medium", "write-all"),
        (r"id-token\s*:\s*write\b", "id_token_write_permission", "GitHub workflow grants id-token write permission", "medium", "id-token: write"),
        (r"contents\s*:\s*write\b", "contents_write_permission", "GitHub workflow grants contents write permission", "low", "contents: write"),
        (r"packages\s*:\s*write\b", "packages_write_permission", "GitHub workflow grants packages write permission", "low", "packages: write"),
    ]
    for pattern, finding_id, title, level, evidence in permission_checks:
        if re.search(pattern, active_text, flags=re.IGNORECASE):
            analysis["permissions"].append({"path": path, "provider": provider, "context": context, "permission": evidence})
            add_ci_cd_config_finding(
                analysis,
                finding_id,
                title,
                ci_cd_contextual_level(level, context),
                ci_cd_contextual_confidence("high" if level == "medium" else "medium", context),
                "permissions",
                "A write-capable CI/CD permission was observed. This is a review indicator.",
                evidence,
                "Confirm the permission is required and scoped to the smallest practical workflow surface.",
                file_path=path,
                context=context,
                provider=provider,
            )


def analyze_ci_cd_actions_and_images(
    analysis: dict[str, Any],
    path: str,
    provider: str,
    context: str,
    lines: list[tuple[int, str]],
) -> None:
    for line_number, line in lines:
        stripped = line.strip()
        uses_match = re.search(r"\buses\s*:\s*['\"]?([^'\"\s#]+)", stripped, flags=re.IGNORECASE)
        if uses_match:
            action_ref = uses_match.group(1)
            analysis["actions"].append({"path": path, "provider": provider, "context": context, "action": action_ref, "line": line_number})
            if "@" in action_ref and not action_ref.startswith(("./", "../")):
                _action, ref = action_ref.rsplit("@", 1)
                if not CI_FULL_SHA_RE.fullmatch(ref):
                    finding_id = "github_action_uses_branch_ref" if ref.lower() in {"main", "master", "latest"} else "github_action_unpinned_ref"
                    title = "Action reference is not pinned to a full commit SHA"
                    add_ci_cd_config_finding(
                        analysis,
                        finding_id,
                        title,
                        ci_cd_contextual_level("low", context),
                        ci_cd_contextual_confidence("medium", context),
                        "actions",
                        "A workflow action reference is not pinned to a full commit SHA. This is a supply-chain review indicator.",
                        action_ref[:220],
                        "Consider pinning third-party actions to immutable commit SHAs where reproducibility matters.",
                        file_path=path,
                        context=context,
                        provider=provider,
                        line=line_number,
                    )
                    if ref.lower() in {"main", "master", "latest"}:
                        add_ci_cd_config_finding(
                            analysis,
                            "github_action_uses_latest_or_master",
                            "Action reference uses a floating branch-like ref",
                            ci_cd_contextual_level("low", context),
                            ci_cd_contextual_confidence("medium", context),
                            "actions",
                            "A workflow action uses latest/master/main style ref.",
                            action_ref[:220],
                            "Review whether this mutable reference is intentional.",
                            file_path=path,
                            context=context,
                            provider=provider,
                            line=line_number,
                        )
        image_match = re.search(r"\bimage\s*:\s*['\"]?([^'\"\s#]+)", stripped, flags=re.IGNORECASE)
        if image_match:
            image_ref = image_match.group(1)
            if ci_cd_image_uses_latest(image_ref):
                add_ci_cd_config_finding(
                    analysis,
                    "docker_image_latest_tag",
                    "CI service/container image uses latest tag",
                    ci_cd_contextual_level("low", context),
                    ci_cd_contextual_confidence("medium", context),
                    "image",
                    "A CI/CD image reference appears to use the latest tag.",
                    image_ref[:220],
                    "Consider pinning images to explicit versions or digests where reproducibility matters.",
                    file_path=path,
                    context=context,
                    provider=provider,
                    line=line_number,
                )
            elif ci_cd_image_is_unpinned(image_ref):
                add_ci_cd_config_finding(
                    analysis,
                    "docker_image_unpinned",
                    "CI service/container image is unpinned",
                    ci_cd_contextual_level("low", context),
                    ci_cd_contextual_confidence("medium", context),
                    "image",
                    "A CI/CD image reference appears to lack a tag or digest.",
                    image_ref[:220],
                    "Consider explicit image versions or digests where reproducibility matters.",
                    file_path=path,
                    context=context,
                    provider=provider,
                    line=line_number,
                )


def ci_cd_image_uses_latest(image_ref: str) -> bool:
    return image_ref.lower().endswith(":latest")


def ci_cd_image_is_unpinned(image_ref: str) -> bool:
    if "@" in image_ref:
        return False
    tail = image_ref.rsplit("/", 1)[-1]
    return ":" not in tail


def analyze_ci_cd_secret_and_script_signals(
    analysis: dict[str, Any],
    path: str,
    provider: str,
    context: str,
    lines: list[tuple[int, str]],
) -> None:
    for line_number, line in lines:
        stripped = line.strip()
        if "${{ secrets." in stripped or "$CI_" in stripped and "SECRET" in stripped.upper():
            add_ci_cd_config_finding(
                analysis,
                "ci_secret_reference_present",
                "CI secret-store reference is present",
                "info",
                ci_cd_contextual_confidence("medium", context),
                "secrets",
                "The workflow references a provider secret context. This is informational and does not expose the secret value.",
                safe_ci_cd_script_excerpt(stripped),
                "Confirm secret scopes and event triggers match the intended trust boundary.",
                file_path=path,
                context=context,
                provider=provider,
                line=line_number,
            )
        if re.search(r"(?i)(?:^|[\s/:])\.env(?:\.|$|\s)", stripped):
            add_ci_cd_config_finding(
                analysis,
                "ci_env_file_reference",
                "Workflow references an env file",
                "info",
                ci_cd_contextual_confidence("medium", context),
                "secrets",
                "A CI/CD line appears to reference an env file. Inspectra does not read real env file content.",
                safe_ci_cd_script_excerpt(stripped),
                "Confirm real env files are not committed or shared in archives.",
                file_path=path,
                context=context,
                provider=provider,
                line=line_number,
            )
        assignment = CI_ASSIGNMENT_RE.search(stripped)
        if assignment and not ci_cd_value_is_placeholder(assignment.group(2)):
            add_ci_cd_config_finding(
                analysis,
                "inline_secret_like_env",
                "Inline secret-like environment value observed",
                ci_cd_contextual_level("medium", context),
                ci_cd_contextual_confidence("high", context),
                "secrets",
                "A CI/CD config line appears to define a secret-like value inline. Inspectra redacted the value and did not validate it.",
                safe_ci_cd_script_excerpt(stripped),
                "Move real secrets to the provider secret store and rotate if this archive was shared.",
                file_path=path,
                context=context,
                provider=provider,
                line=line_number,
                redacted=True,
            )
        if re.search(r"(?i)\b(?:run|script|command)\s*:", stripped) and CI_SECRET_NAME_RE.search(stripped):
            add_ci_cd_config_finding(
                analysis,
                "secret_in_ci_script",
                "CI script references a secret-like name",
                ci_cd_contextual_level("low", context),
                ci_cd_contextual_confidence("medium", context),
                "secrets",
                "A CI/CD script references a secret-like variable name. This is a review indicator.",
                safe_ci_cd_script_excerpt(stripped),
                "Confirm the value is injected safely and not printed to logs.",
                file_path=path,
                context=context,
                provider=provider,
                line=line_number,
            )
        if ci_cd_curl_pipe_shell(stripped):
            add_ci_cd_config_finding(
                analysis,
                "ci_curl_pipe_shell",
                "CI script pipes downloaded content to shell",
                ci_cd_contextual_level("medium", context),
                ci_cd_contextual_confidence("high", context),
                "script",
                "A CI/CD script appears to pipe curl or wget output directly to sh/bash.",
                safe_ci_cd_script_excerpt(stripped),
                "Prefer verified downloads and explicit checksums before executing installer scripts.",
                file_path=path,
                context=context,
                provider=provider,
                line=line_number,
            )
        if ci_cd_remote_script_execution(stripped):
            add_ci_cd_config_finding(
                analysis,
                "ci_remote_script_execution",
                "CI script appears to fetch and execute remote code",
                ci_cd_contextual_level("medium", context),
                ci_cd_contextual_confidence("medium", context),
                "script",
                "A CI/CD script appears to download and execute remote code.",
                safe_ci_cd_script_excerpt(stripped),
                "Review remote execution paths and pin/verifiably fetch artifacts where possible.",
                file_path=path,
                context=context,
                provider=provider,
                line=line_number,
            )
        if re.search(r"(?i)\b(?:npm|yarn|pnpm)\s+(?:install|add)\s+-g\b", stripped):
            add_ci_cd_config_finding(
                analysis,
                "ci_install_and_execute_global_tool",
                "CI script installs a global tool",
                ci_cd_contextual_level("low", context),
                ci_cd_contextual_confidence("medium", context),
                "script",
                "A CI/CD script installs a global tool. This is a package execution review indicator.",
                safe_ci_cd_script_excerpt(stripped),
                "Pin tools and review install-time script behavior before running in trusted CI.",
                file_path=path,
                context=context,
                provider=provider,
                line=line_number,
            )
        if CI_SECRET_NAME_RE.search(stripped):
            add_ci_cd_config_finding(
                analysis,
                "ci_script_references_secret_name",
                "CI line references a secret-like name",
                "info",
                ci_cd_contextual_confidence("low", context),
                "secrets",
                "A CI/CD line references a secret-like name. This is an informational review signal.",
                safe_ci_cd_script_excerpt(stripped),
                "Confirm secret references are scoped and not echoed into logs.",
                file_path=path,
                context=context,
                provider=provider,
                line=line_number,
            )


def ci_cd_value_is_placeholder(value: str) -> bool:
    return value.strip().strip("'\"").lower() in {"changeme", "change-me", "example", "dummy", "secret", "password", "todo", "replace-me"}


def ci_cd_curl_pipe_shell(value: str) -> bool:
    return bool(re.search(r"(?is)\b(?:curl|wget)\b[^\n|]*\|[^\n]*(?:sh|bash)\b", value))


def ci_cd_remote_script_execution(value: str) -> bool:
    return bool(re.search(r"(?is)\b(?:curl|wget)\b[^\n]*(?:https?://)[^\n]*(?:&&|;|\|)[^\n]*(?:sh|bash)\b", value))


def analyze_ci_cd_publish_deploy_signals(
    analysis: dict[str, Any],
    path: str,
    provider: str,
    context: str,
    lines: list[tuple[int, str]],
    active_text: str,
) -> None:
    signals = [
        (r"\bnpm\s+publish\b", "npm_publish_job_detected", "npm publish command detected", "publish"),
        (r"\bdocker\s+push\b", "docker_push_job_detected", "Docker push command detected", "deploy"),
        (r"\b(?:aws|gcloud|az|kubectl|helm|terraform|serverless)\b[^\n]*(?:deploy|apply|push|sync|update)", "cloud_deploy_job_detected", "Cloud or infrastructure deploy command detected", "deploy"),
    ]
    for line_number, line in lines:
        for pattern, finding_id, title, category in signals:
            if re.search(pattern, line, flags=re.IGNORECASE):
                signal = {
                    "path": path,
                    "provider": provider,
                    "context": context,
                    "signal": finding_id,
                    "line": line_number,
                    "evidence": safe_ci_cd_script_excerpt(line),
                }
                analysis["publish_deploy_signals"].append(signal)
                add_ci_cd_config_finding(
                    analysis,
                    finding_id,
                    title,
                    ci_cd_contextual_level("low", context),
                    ci_cd_contextual_confidence("medium", context),
                    category,
                    "A publish or deploy command was observed. This is a review indicator, not proof the workflow runs in production.",
                    safe_ci_cd_script_excerpt(line),
                    "Confirm triggers, permissions, and environment protections around publish/deploy jobs.",
                    file_path=path,
                    context=context,
                    provider=provider,
                    line=line_number,
                )
    if re.search(r"(?im)^\s*environment\s*:\s*['\"]?production['\"]?\s*$", active_text) or context == "production":
        add_ci_cd_config_finding(
            analysis,
            "production_environment_deploy",
            "Workflow references a production/deploy context",
            ci_cd_contextual_level("low", context),
            ci_cd_contextual_confidence("medium", context),
            "deploy",
            "The workflow path or content appears to reference production, deploy, release, or publish context.",
            "production/deploy context",
            "Confirm environment protections and approval requirements.",
            file_path=path,
            context=context,
            provider=provider,
        )


def analyze_ci_cd_misc_signals(
    analysis: dict[str, Any],
    path: str,
    provider: str,
    context: str,
    lines: list[tuple[int, str]],
    active_text: str,
) -> None:
    if re.search(r"(?i)\bruns-on\s*:\s*(?:\[.*)?self-hosted\b", active_text):
        add_ci_cd_config_finding(
            analysis,
            "self_hosted_runner_used",
            "Workflow uses a self-hosted runner",
            "info",
            ci_cd_contextual_confidence("medium", context),
            "runner",
            "A self-hosted runner label was observed. This is informational unless combined with risky triggers or permissions.",
            "runs-on: self-hosted",
            "Confirm runner isolation and repository trust boundaries.",
            file_path=path,
            context=context,
            provider=provider,
        )
    for line_number, line in lines:
        lower = line.lower()
        if "upload-artifact" in lower:
            add_ci_cd_config_finding(
                analysis,
                "ci_artifact_upload_present",
                "Artifact upload step present",
                "info",
                ci_cd_contextual_confidence("low", context),
                "artifact",
                "A CI/CD artifact upload step was observed.",
                safe_ci_cd_script_excerpt(line),
                "Confirm artifacts do not include secrets or unnecessary build outputs.",
                file_path=path,
                context=context,
                provider=provider,
                line=line_number,
            )
        if "download-artifact" in lower:
            add_ci_cd_config_finding(
                analysis,
                "ci_artifact_download_present",
                "Artifact download step present",
                "info",
                ci_cd_contextual_confidence("low", context),
                "artifact",
                "A CI/CD artifact download step was observed.",
                safe_ci_cd_script_excerpt(line),
                "Confirm artifact trust boundaries before using downloaded outputs.",
                file_path=path,
                context=context,
                provider=provider,
                line=line_number,
            )
        if "actions/cache" in lower or re.search(r"(?i)\bcache\s*:", line):
            add_ci_cd_config_finding(
                analysis,
                "ci_cache_key_broad",
                "CI cache usage present",
                "info",
                ci_cd_contextual_confidence("low", context),
                "cache",
                "CI cache configuration was observed. Broad cache keys can affect reproducibility and trust boundaries.",
                safe_ci_cd_script_excerpt(line),
                "Confirm cache keys are tied to dependency lockfiles or other appropriate inputs.",
                file_path=path,
                context=context,
                provider=provider,
                line=line_number,
            )


def safe_ci_cd_script_excerpt(value: str) -> str:
    redacted, _count = redact_ci_cd_secret_text(value)
    collapsed = re.sub(r"\s+", " ", redacted).strip()
    return collapsed[:240]


def redact_ci_cd_secret_text(text: str) -> tuple[str, int]:
    redacted, count = redact_node_secret_text(text)
    updated, replacements = re.subn(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
        "[REDACTED PRIVATE KEY]",
        redacted,
        flags=re.IGNORECASE | re.DOTALL,
    )
    redacted = updated
    count += replacements
    return redacted, count


def finalize_ci_cd_config_analysis(analysis: dict[str, Any]) -> None:
    analysis["findings"] = dedupe_findings(analysis["findings"])
    analysis["summary"]["findings_count"] = len(analysis["findings"])
    if analysis["summary"]["redacted_values_count"]:
        analysis["redaction_notes"] = [
            "Secret-like values in CI/CD configuration evidence are redacted before storage and export on a best-effort basis.",
        ]


def add_ci_cd_config_finding(
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
    provider: str | None = None,
    job: str | None = None,
    step: str | None = None,
    line: int | None = None,
    redacted: bool = False,
) -> None:
    safe_description, description_redactions = redact_ci_cd_secret_text(description)
    safe_evidence, evidence_redactions = redact_ci_cd_secret_text(evidence)
    safe_recommendation, recommendation_redactions = redact_ci_cd_secret_text(recommendation)
    redaction_count = description_redactions + evidence_redactions + recommendation_redactions
    if redacted and redaction_count == 0:
        redaction_count = 1
    analysis["summary"]["redacted_values_count"] += redaction_count

    finding = make_finding(finding_id, title, level, safe_description, safe_evidence, safe_recommendation)
    finding["confidence"] = confidence
    finding["category"] = category
    if file_path:
        finding["file_path"] = file_path
    if context:
        finding["context"] = context
    if provider:
        finding["provider"] = provider
    if job:
        finding["job"] = job
    if step:
        finding["step"] = step
    if line is not None:
        finding["line"] = line
    analysis["findings"].append(finding)


def k8s_config_limits(request: ArchiveAnalysisRequest) -> dict[str, int]:
    max_files = K8S_CONFIG_MAX_FILES if request.max_files is None else request.max_files
    max_file_bytes = K8S_CONFIG_MAX_FILE_BYTES if request.max_file_bytes is None else request.max_file_bytes
    max_total_bytes = K8S_CONFIG_MAX_TOTAL_BYTES if request.max_total_bytes is None else request.max_total_bytes
    if max_files <= 0 or max_file_bytes <= 0 or max_total_bytes <= 0:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Kubernetes config analysis limits must be positive.")
    return {"max_files": max_files, "max_file_bytes": max_file_bytes, "max_total_bytes": max_total_bytes}


def analyze_k8s_config_archive(
    path: Path,
    archive_type: str,
    *,
    max_files: int,
    max_file_bytes: int,
    max_total_bytes: int,
) -> dict[str, Any]:
    analysis = empty_k8s_config_analysis()
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
            scoped["id"] = f"k8s_config_{scoped['id']}"
            analysis["findings"].append(scoped)
            finalize_k8s_config_analysis(analysis)
            return analysis
        with zipfile.ZipFile(path) as archive:
            for index, info in enumerate(archive.filelist, start=1):
                if should_stop_k8s_config_archive_scan(index, analysis):
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
                process_k8s_config_entry(
                    analysis,
                    state,
                    entry,
                    lambda entry_info=info: archive.open(entry_info),
                )
    else:
        with tarfile.open(path, "r:*") as archive:
            for index, member in enumerate(archive, start=1):
                if should_stop_k8s_config_archive_scan(index, analysis):
                    break
                entry = {
                    "path": member.name,
                    "type": tar_member_type(member),
                    "size": member.size,
                    "mode_int": member.mode,
                    "mode": format_file_mode(member.mode),
                    "link_target": member.linkname or None,
                }
                process_k8s_config_entry(
                    analysis,
                    state,
                    entry,
                    lambda tar_member=member: archive.extractfile(tar_member),
                )

    finalize_k8s_config_analysis(analysis)
    return analysis


def empty_k8s_config_analysis(errors: list[str] | None = None) -> dict[str, Any]:
    return {
        "summary": {
            "files_considered": 0,
            "files_reviewed": 0,
            "manifest_files_detected": 0,
            "resources_detected": 0,
            "workloads_detected": 0,
            "services_detected": 0,
            "secrets_detected": 0,
            "rbac_resources_detected": 0,
            "findings_count": 0,
            "redacted_values_count": 0,
            "truncated": False,
        },
        "files_detected": [],
        "files_reviewed": [],
        "resources": [],
        "workloads": [],
        "containers": [],
        "services": [],
        "ingress": [],
        "rbac": [],
        "secrets": [],
        "helm_kustomize_signals": [],
        "findings": [],
        "redaction_notes": [],
        "errors": errors or [],
    }


def build_k8s_config_result(
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
        "analyzer": "k8s_config_basic",
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
        "resources": analysis.get("resources", []),
        "workloads": analysis.get("workloads", []),
        "containers": analysis.get("containers", []),
        "services": analysis.get("services", []),
        "ingress": analysis.get("ingress", []),
        "rbac": analysis.get("rbac", []),
        "secrets": analysis.get("secrets", []),
        "helm_kustomize_signals": analysis.get("helm_kustomize_signals", []),
        "findings": findings,
        "redaction_notes": analysis.get("redaction_notes", []),
        "errors": analysis.get("errors", []),
        "truncated": bool(summary.get("truncated")),
    }


def should_stop_k8s_config_archive_scan(index: int, analysis: dict[str, Any]) -> bool:
    if index > ARCHIVE_MAX_ENTRIES:
        analysis["summary"]["truncated"] = True
        add_k8s_config_finding(
            analysis,
            "k8s_config_entry_limit_reached",
            "Archive entry scan limit reached",
            "medium",
            "high",
            "limit",
            "Inspectra stopped scanning archive metadata after the configured entry limit.",
            f"Processed {ARCHIVE_MAX_ENTRIES} entries.",
            "Review the archive with stricter limits or split it before deeper inspection.",
        )
        return True
    return False


def process_k8s_config_entry(
    analysis: dict[str, Any],
    state: dict[str, int],
    entry: dict[str, Any],
    open_entry,
) -> None:
    path = str(entry["path"])
    category = classify_k8s_config_candidate(path)
    if category is None:
        return

    summary = as_dict(analysis["summary"])
    summary["files_considered"] += 1
    if category != "env_sensitive":
        summary["manifest_files_detected"] += 1

    entry_type = str(entry["type"])
    size_bytes = int(entry.get("size") or 0)
    context = k8s_config_file_context(path, category)
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

    skip_reason = k8s_config_skip_reason(record, state)
    if skip_reason:
        record["skip_reason"] = skip_reason
        analysis["files_detected"].append(record)
        add_k8s_config_skip_finding(analysis, path, skip_reason, size_bytes, context)
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
        add_k8s_config_finding(
            analysis,
            "k8s_config_file_read_error",
            "Kubernetes config candidate could not be read safely",
            "low",
            "medium",
            "archive",
            "A Kubernetes-related candidate file could not be read from the archive within Inspectra limits.",
            f"{path}: {exc}",
            "Review this file manually in a constrained environment if it is expected.",
            file_path=path,
            context=context,
        )
        return

    state["total_bytes_read"] += len(raw_bytes)
    if b"\x00" in raw_bytes:
        record["skip_reason"] = "binary_or_non_text"
        analysis["files_detected"].append(record)
        add_k8s_config_skip_finding(analysis, path, "binary_or_non_text", size_bytes, context)
        return

    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        record["skip_reason"] = "binary_or_non_text"
        analysis["files_detected"].append(record)
        add_k8s_config_skip_finding(analysis, path, "binary_or_non_text", size_bytes, context)
        return

    state["files_read"] += 1
    summary["files_reviewed"] = state["files_read"]
    record["read"] = True
    record["bytes_read"] = len(raw_bytes)
    analysis["files_detected"].append(record)
    analysis["files_reviewed"].append(
        {"path": path, "category": category, "context": context, "size_bytes": size_bytes, "bytes_read": len(raw_bytes)}
    )
    analyze_k8s_config_text(analysis, path, category, context, text)


def classify_k8s_config_candidate(path: str) -> str | None:
    normalized = normalize_archive_entry_path(path)
    lower = normalized.lower()
    basename = lower.rsplit("/", 1)[-1]
    parts = [part for part in lower.split("/") if part]

    if is_secrets_sensitive_env_name(basename):
        return "env_sensitive"
    if basename == "chart.yaml":
        return "helm_chart"
    if basename in {"kustomization.yaml", "kustomization.yml"}:
        return "kustomize_config"
    if basename == "values.yaml" or (basename.startswith("values") and basename.endswith((".yaml", ".yml"))):
        return "helm_values"
    if "/templates/" in lower and basename.endswith((".yaml", ".yml")):
        return "helm_template"
    if lower.endswith((".k8s.yaml", ".k8s.yml")):
        return "k8s_manifest"
    if basename in K8S_COMMON_RESOURCE_FILENAMES:
        return "k8s_manifest"
    if basename.endswith((".yaml", ".yml")) and any(part in {"k8s", "kubernetes", "manifests", "deploy"} for part in parts[:-1]):
        return "k8s_manifest"
    if basename.endswith((".yaml", ".yml")):
        return "yaml_candidate"
    return None


K8S_COMMON_RESOURCE_FILENAMES = {
    "deployment.yaml",
    "deployment.yml",
    "service.yaml",
    "service.yml",
    "ingress.yaml",
    "ingress.yml",
    "secret.yaml",
    "secret.yml",
    "configmap.yaml",
    "configmap.yml",
    "cronjob.yaml",
    "job.yaml",
    "daemonset.yaml",
    "statefulset.yaml",
    "role.yaml",
    "rolebinding.yaml",
    "clusterrole.yaml",
    "clusterrolebinding.yaml",
    "serviceaccount.yaml",
}


def k8s_config_skip_reason(record: dict[str, Any], state: dict[str, int]) -> str | None:
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


def add_k8s_config_skip_finding(analysis: dict[str, Any], path: str, reason: str, size_bytes: int, context: str) -> None:
    if reason in {"file_too_large", "too_many_files", "total_bytes_limit"}:
        analysis["summary"]["truncated"] = True
    titles = {
        "path_traversal": "Kubernetes config path uses traversal",
        "absolute_path": "Kubernetes config path is absolute",
        "entry_name_too_long": "Kubernetes config entry name is unusually long",
        "file_too_large": "Kubernetes config file omitted because it exceeds the size limit",
        "too_many_files": "Kubernetes config file limit reached",
        "total_bytes_limit": "Total Kubernetes config byte limit reached",
        "binary_or_non_text": "Kubernetes config candidate is not UTF-8 text",
        "real_env_file_not_read": "Real environment file detected but not read",
    }
    level = "medium" if reason in {"path_traversal", "absolute_path", "file_too_large", "too_many_files", "total_bytes_limit"} else "low"
    if reason in {"binary_or_non_text", "real_env_file_not_read"}:
        level = "info"
    evidence = f"{path}: {size_bytes} bytes" if reason == "file_too_large" else path[:240]
    if reason.startswith("not_regular_file"):
        title = "Kubernetes config candidate omitted because it is not a regular file"
        evidence = f"{path}: {reason}"
        level = "low"
    else:
        title = titles.get(reason, "Kubernetes config candidate skipped by defensive limit")
    add_k8s_config_finding(
        analysis,
        f"k8s_config_{reason.split(':', 1)[0]}",
        title,
        k8s_contextual_level(level, context),
        k8s_contextual_confidence("high" if reason in {"path_traversal", "absolute_path", "real_env_file_not_read"} else "medium", context),
        "archive",
        "Inspectra detected a Kubernetes-related file but did not read it because of a defensive limit, unsupported format, or unsafe archive metadata.",
        evidence,
        "Review the archive manually in a constrained environment if this file is expected.",
        file_path=path,
        context=context,
    )


LOWER_CONFIDENCE_K8S_CONTEXTS = {"development", "test", "local", "example"}
K8S_WORKLOAD_KINDS = {"Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "ReplicaSet", "ReplicationController"}
K8S_RBAC_KINDS = {"Role", "RoleBinding", "ClusterRole", "ClusterRoleBinding"}
K8S_CLUSTER_SCOPED_KINDS = {"Namespace", "ClusterRole", "ClusterRoleBinding", "CustomResourceDefinition"}
K8S_SECRET_KEY_RE = re.compile(
    r"(?i)(SECRET_KEY|CLIENT_SECRET|PRIVATE_KEY|DATABASE_URL|REDIS_URL|API_KEY|PASSWORD|TOKEN|SECRET|PASS|AUTH|KEY)"
)


def k8s_config_file_context(path: str, category: str = "") -> str:
    normalized = normalize_archive_entry_path(path).lower()
    parts = [part for part in normalized.split("/") if part]
    basename = parts[-1] if parts else normalized
    name_tokens = set(re.split(r"[^a-z0-9]+", basename))
    directories = set(parts[:-1])
    all_tokens = set(parts[:-1]) | name_tokens

    if directories.intersection({"docs", "doc", "examples", "example", "samples", "sample"}) or all_tokens.intersection(
        {"example", "examples", "sample", "samples", "template", "templates"}
    ):
        return "example"
    if all_tokens.intersection({"test", "tests", "testing"}):
        return "test"
    if all_tokens.intersection({"dev", "development"}):
        return "development"
    if "local" in all_tokens:
        return "local"
    if all_tokens.intersection({"prod", "production", "release", "deploy"}) or "deploy" in directories:
        return "production"
    if category in {"k8s_manifest", "helm_chart", "helm_values", "kustomize_config"} and len(parts) <= 2:
        return "shared"
    return "ambiguous"


def k8s_contextual_level(level: str, context: str) -> str:
    if context not in LOWER_CONFIDENCE_K8S_CONTEXTS:
        return level
    if level == "medium":
        return "low"
    if level == "low":
        return "info"
    return level


def k8s_contextual_confidence(confidence: str, context: str) -> str:
    if context not in LOWER_CONFIDENCE_K8S_CONTEXTS:
        return confidence
    if confidence == "high":
        return "medium"
    if confidence == "medium":
        return "low"
    return confidence


def analyze_k8s_config_text(analysis: dict[str, Any], path: str, category: str, context: str, text: str) -> None:
    if category in {"helm_chart", "helm_values", "helm_template", "kustomize_config"}:
        analyze_k8s_context_file(analysis, path, category, context, text)
        return
    for document_lines in split_k8s_documents(text):
        active_lines = active_k8s_lines(document_lines)
        if not active_lines:
            continue
        analyze_k8s_document(analysis, path, category, context, active_lines)


def analyze_k8s_context_file(analysis: dict[str, Any], path: str, category: str, context: str, text: str) -> None:
    if category.startswith("helm"):
        signal = {"path": path, "category": category, "context": context, "rendered": False}
        analysis["helm_kustomize_signals"].append(signal)
        if category == "helm_template":
            add_k8s_config_finding(
                analysis,
                "helm_template_detected_not_rendered",
                "Helm template detected but not rendered",
                "info",
                "high",
                "helm",
                "A Helm template file was detected. Inspectra records it as context and does not render templates in this phase.",
                f"{path}: helm template not rendered",
                "Render and validate Helm output in a controlled workflow when deeper review is required.",
                file_path=path,
                context=context,
            )
    if category == "kustomize_config":
        analysis["helm_kustomize_signals"].append({"path": path, "category": category, "context": context, "built": False})
        add_k8s_config_finding(
            analysis,
            "kustomize_detected_not_built",
            "Kustomize configuration detected but not built",
            "info",
            "high",
            "kustomize",
            "A Kustomize configuration file was detected. Inspectra records it as context and does not build overlays in this phase.",
            f"{path}: kustomize not built",
            "Build and validate Kustomize output in a controlled workflow when deeper review is required.",
            file_path=path,
            context=context,
        )
    if category == "helm_values":
        for line_number, line in active_k8s_lines(list(enumerate(text.splitlines(), start=1))):
            key = k8s_mapping_key(line)
            if key and K8S_SECRET_KEY_RE.search(key):
                add_k8s_config_finding(
                    analysis,
                    "values_secret_like_key",
                    "Helm values file contains a secret-like key",
                    k8s_contextual_level("low", context),
                    k8s_contextual_confidence("medium", context),
                    "helm",
                    "A Helm values key appears secret-like. Inspectra redacted any value and did not render templates.",
                    f"key {key}=[REDACTED]",
                    "Keep real secrets out of values files shared in archives.",
                    file_path=path,
                    context=context,
                    line=line_number,
                    redacted=True,
                )


def split_k8s_documents(text: str) -> list[list[tuple[int, str]]]:
    documents: list[list[tuple[int, str]]] = []
    current: list[tuple[int, str]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if line.strip() == "---":
            if current:
                documents.append(current)
                current = []
            continue
        current.append((line_number, line))
    if current:
        documents.append(current)
    return documents


def active_k8s_lines(lines: list[tuple[int, str]]) -> list[tuple[int, str]]:
    active: list[tuple[int, str]] = []
    for line_number, line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("//"):
            continue
        active.append((line_number, line))
    return active


def analyze_k8s_document(
    analysis: dict[str, Any],
    path: str,
    category: str,
    context: str,
    lines: list[tuple[int, str]],
) -> None:
    kind = k8s_first_scalar(lines, "kind")
    if not kind:
        return
    metadata = k8s_metadata(lines)
    resource_name = metadata.get("name")
    namespace = metadata.get("namespace")
    resource = {
        "path": path,
        "context": context,
        "kind": kind,
        "name": resource_name,
        "namespace": namespace,
    }
    analysis["resources"].append(resource)
    analysis["summary"]["resources_detected"] = len(analysis["resources"])
    if kind in K8S_WORKLOAD_KINDS:
        analysis["workloads"].append(resource)
        analysis["summary"]["workloads_detected"] = len(analysis["workloads"])
    if kind == "Service":
        analysis["services"].append(resource)
        analysis["summary"]["services_detected"] = len(analysis["services"])
    if kind == "Ingress":
        analysis["ingress"].append(resource)
    if kind in K8S_RBAC_KINDS:
        analysis["rbac"].append(resource)
        analysis["summary"]["rbac_resources_detected"] = len(analysis["rbac"])
    if kind == "Secret":
        analysis["secrets"].append(resource)
        analysis["summary"]["secrets_detected"] = len(analysis["secrets"])

    analyze_k8s_namespace(analysis, path, context, kind, resource_name, namespace)
    if kind == "Secret":
        analyze_k8s_secret(analysis, path, context, kind, resource_name, namespace, lines)
    if kind == "ConfigMap":
        analyze_k8s_configmap(analysis, path, context, kind, resource_name, namespace, lines)
    if kind in K8S_WORKLOAD_KINDS:
        analyze_k8s_workload(analysis, path, context, kind, resource_name, namespace, lines)
    if kind == "Service":
        analyze_k8s_service(analysis, path, context, kind, resource_name, namespace, lines)
    if kind == "Ingress":
        analyze_k8s_ingress(analysis, path, context, kind, resource_name, namespace, lines)
    if kind == "ClusterRole":
        analyze_k8s_clusterrole(analysis, path, context, kind, resource_name, namespace, lines)


def analyze_k8s_namespace(
    analysis: dict[str, Any],
    path: str,
    context: str,
    kind: str,
    resource_name: str | None,
    namespace: str | None,
) -> None:
    if kind in K8S_CLUSTER_SCOPED_KINDS:
        return
    if namespace and namespace != "default":
        return
    evidence = f"kind={kind}; metadata.name={resource_name or 'unknown'}; namespace={namespace or '[missing]'}"
    add_k8s_config_finding(
        analysis,
        "namespace_missing_or_default",
        "Resource uses default or missing namespace",
        k8s_contextual_level("low", context),
        k8s_contextual_confidence("medium", context),
        "namespace",
        "A namespaced Kubernetes resource has no namespace or uses the default namespace. This is a review indicator.",
        evidence,
        "Use explicit namespaces where practical and review default namespace usage.",
        file_path=path,
        context=context,
        kind=kind,
        resource_name=resource_name,
        namespace=namespace,
        field_path="metadata.namespace",
    )


def analyze_k8s_secret(
    analysis: dict[str, Any],
    path: str,
    context: str,
    kind: str,
    resource_name: str | None,
    namespace: str | None,
    lines: list[tuple[int, str]],
) -> None:
    for section, finding_id, title in [
        ("stringData", "k8s_secret_stringdata_present", "Kubernetes Secret stringData contains plaintext values"),
        ("data", "k8s_secret_plaintext_data", "Kubernetes Secret data entries are present"),
    ]:
        for line_number, key in k8s_section_keys(lines, section):
            evidence = f"kind=Secret; metadata.name={resource_name or 'unknown'}; key {key}=[REDACTED]"
            add_k8s_config_finding(
                analysis,
                finding_id,
                title,
                k8s_contextual_level("medium", context),
                k8s_contextual_confidence("high", context),
                "secrets",
                "A Kubernetes Secret contains secret material. Inspectra records only key names and a redacted placeholder.",
                evidence,
                "Avoid sharing plaintext secret material in archives and review secret distribution separately.",
                file_path=path,
                context=context,
                line=line_number,
                kind=kind,
                resource_name=resource_name,
                namespace=namespace,
                field_path=section,
                redacted=True,
            )


def analyze_k8s_configmap(
    analysis: dict[str, Any],
    path: str,
    context: str,
    kind: str,
    resource_name: str | None,
    namespace: str | None,
    lines: list[tuple[int, str]],
) -> None:
    for line_number, key in k8s_section_keys(lines, "data"):
        if not K8S_SECRET_KEY_RE.search(key):
            continue
        add_k8s_config_finding(
            analysis,
            "k8s_configmap_secret_like_key",
            "ConfigMap contains a secret-like key",
            k8s_contextual_level("medium", context),
            k8s_contextual_confidence("medium", context),
            "config",
            "A ConfigMap key appears secret-like. Inspectra redacted any value and did not validate it.",
            f"kind=ConfigMap; metadata.name={resource_name or 'unknown'}; key {key}=[REDACTED]",
            "Move real secret values to an approved secret mechanism and avoid sharing them in ConfigMaps.",
            file_path=path,
            context=context,
            line=line_number,
            kind=kind,
            resource_name=resource_name,
            namespace=namespace,
            field_path=f"data.{key}",
            redacted=True,
        )


def analyze_k8s_workload(
    analysis: dict[str, Any],
    path: str,
    context: str,
    kind: str,
    resource_name: str | None,
    namespace: str | None,
    lines: list[tuple[int, str]],
) -> None:
    text = "\n".join(line for _line_number, line in lines)
    containers = k8s_extract_containers(lines)
    for container in containers:
        image_ref = container.get("image")
        safe_image_ref = redact_k8s_secret_text(str(image_ref))[0] if image_ref else None
        analysis["containers"].append(
            {
                "path": path,
                "context": context,
                "kind": kind,
                "resource_name": resource_name,
                "namespace": namespace,
                "container": container.get("name"),
                "image": safe_image_ref,
            }
        )
    if re.search(r"(?im)^\s*hostNetwork\s*:\s*true\s*$", text):
        add_k8s_resource_finding(analysis, "host_network_enabled", "Workload enables hostNetwork", "medium", "pod_security", path, context, kind, resource_name, namespace, "spec.hostNetwork")
    if re.search(r"(?im)^\s*hostPID\s*:\s*true\s*$", text):
        add_k8s_resource_finding(analysis, "host_pid_enabled", "Workload enables hostPID", "medium", "pod_security", path, context, kind, resource_name, namespace, "spec.hostPID")
    if re.search(r"(?im)^\s*hostIPC\s*:\s*true\s*$", text):
        add_k8s_resource_finding(analysis, "host_ipc_enabled", "Workload enables hostIPC", "medium", "pod_security", path, context, kind, resource_name, namespace, "spec.hostIPC")
    if re.search(r"(?im)^\s*hostPath\s*:\s*$", text):
        add_k8s_resource_finding(analysis, "host_path_volume_present", "Workload uses a hostPath volume", "medium", "volume", path, context, kind, resource_name, namespace, "spec.volumes.hostPath")
    if "/var/run/docker.sock" in text:
        add_k8s_resource_finding(analysis, "docker_socket_mount", "Workload references the Docker socket", "medium", "volume", path, context, kind, resource_name, namespace, "volumeMounts/hostPath")
    for line_number, line in lines:
        stripped = line.strip()
        container = k8s_nearest_container(lines, line_number)
        if re.search(r"(?i)^privileged\s*:\s*true\s*$", stripped):
            add_k8s_resource_finding(
                analysis,
                "privileged_container",
                "Container is configured as privileged",
                "medium",
                "pod_security",
                path,
                context,
                kind,
                resource_name,
                namespace,
                "securityContext.privileged",
                container=container,
                line=line_number,
            )
        if re.search(r"(?i)^allowPrivilegeEscalation\s*:\s*true\s*$", stripped):
            add_k8s_resource_finding(
                analysis,
                "allow_privilege_escalation_true",
                "Container allows privilege escalation",
                "medium",
                "pod_security",
                path,
                context,
                kind,
                resource_name,
                namespace,
                "securityContext.allowPrivilegeEscalation",
                container=container,
                line=line_number,
            )
        image_match = re.match(r"image\s*:\s*['\"]?([^'\"\s#]+)", stripped, flags=re.IGNORECASE)
        if image_match:
            analyze_k8s_image(analysis, path, context, kind, resource_name, namespace, container, image_match.group(1), line_number)
    analyze_k8s_env(analysis, path, context, kind, resource_name, namespace, lines)
    if "resources:" not in text:
        add_k8s_resource_finding(analysis, "resource_limits_missing", "Workload container resources limits were not observed", "low", "resources", path, context, kind, resource_name, namespace, "containers.resources.limits")
        add_k8s_resource_finding(analysis, "resource_requests_missing", "Workload container resources requests were not observed", "low", "resources", path, context, kind, resource_name, namespace, "containers.resources.requests")
    else:
        if "limits:" not in text:
            add_k8s_resource_finding(analysis, "resource_limits_missing", "Workload container resource limits were not observed", "low", "resources", path, context, kind, resource_name, namespace, "containers.resources.limits")
        if "requests:" not in text:
            add_k8s_resource_finding(analysis, "resource_requests_missing", "Workload container resource requests were not observed", "low", "resources", path, context, kind, resource_name, namespace, "containers.resources.requests")
    if "livenessProbe:" not in text:
        add_k8s_resource_finding(analysis, "liveness_probe_missing", "Workload liveness probe was not observed", "low", "reliability", path, context, kind, resource_name, namespace, "containers.livenessProbe")
    if "readinessProbe:" not in text:
        add_k8s_resource_finding(analysis, "readiness_probe_missing", "Workload readiness probe was not observed", "low", "reliability", path, context, kind, resource_name, namespace, "containers.readinessProbe")
    if re.search(r"(?im)^\s*replicas\s*:\s*1\s*$", text):
        add_k8s_resource_finding(analysis, "replicas_singleton_hint", "Workload declares a single replica", "low", "reliability", path, context, kind, resource_name, namespace, "spec.replicas")


def analyze_k8s_image(
    analysis: dict[str, Any],
    path: str,
    context: str,
    kind: str,
    resource_name: str | None,
    namespace: str | None,
    container: str | None,
    image_ref: str,
    line: int,
) -> None:
    if image_ref.lower().endswith(":latest"):
        add_k8s_resource_finding(
            analysis,
            "image_latest_tag",
            "Container image uses latest tag",
            "low",
            "image",
            path,
            context,
            kind,
            resource_name,
            namespace,
            "containers.image",
            container=container,
            line=line,
            evidence_extra=f"image={image_ref[:160]}",
        )
    elif "@" not in image_ref:
        add_k8s_resource_finding(
            analysis,
            "image_missing_digest",
            "Container image is not pinned by digest",
            "low",
            "image",
            path,
            context,
            kind,
            resource_name,
            namespace,
            "containers.image",
            container=container,
            line=line,
            evidence_extra=f"image={image_ref[:160]}",
        )


def analyze_k8s_env(
    analysis: dict[str, Any],
    path: str,
    context: str,
    kind: str,
    resource_name: str | None,
    namespace: str | None,
    lines: list[tuple[int, str]],
) -> None:
    for index, (line_number, line) in enumerate(lines):
        stripped = line.strip()
        name_match = re.match(r"-?\s*name\s*:\s*['\"]?([^'\"\s#]+)", stripped)
        if name_match and K8S_SECRET_KEY_RE.search(name_match.group(1)):
            following_lines: list[str] = []
            for _next_number, next_line in lines[index + 1 : index + 6]:
                if re.match(r"\s*-\s*name\s*:", next_line):
                    break
                following_lines.append(next_line)
            nearby = "\n".join(following_lines)
            if re.search(r"(?im)^\s*value\s*:", nearby) and "valueFrom:" not in nearby:
                key = name_match.group(1)
                add_k8s_config_finding(
                    analysis,
                    "env_secret_like_value",
                    "Container env contains a secret-like inline value",
                    k8s_contextual_level("medium", context),
                    k8s_contextual_confidence("medium", context),
                    "secrets",
                    "A container environment variable with a secret-like name appears to have an inline value. Inspectra redacted the value.",
                    f"kind={kind}; metadata.name={resource_name or 'unknown'}; env {key}=[REDACTED]",
                    "Use Kubernetes Secret references or another approved runtime secret mechanism for sensitive values.",
                    file_path=path,
                    context=context,
                    line=line_number,
                    kind=kind,
                    resource_name=resource_name,
                    namespace=namespace,
                    field_path=f"env.{key}",
                    redacted=True,
                )
        if "secretRef:" in stripped or "secretKeyRef:" in stripped:
            add_k8s_config_finding(
                analysis,
                "env_from_secret_reference",
                "Workload references a Kubernetes Secret",
                "info",
                k8s_contextual_confidence("medium", context),
                "secrets",
                "A workload references a Kubernetes Secret. Inspectra does not resolve or read referenced secret values.",
                f"kind={kind}; metadata.name={resource_name or 'unknown'}; field={stripped.split(':', 1)[0]}",
                "Confirm referenced secrets are scoped and distributed through the intended runtime mechanism.",
                file_path=path,
                context=context,
                line=line_number,
                kind=kind,
                resource_name=resource_name,
                namespace=namespace,
            )


def analyze_k8s_service(
    analysis: dict[str, Any],
    path: str,
    context: str,
    kind: str,
    resource_name: str | None,
    namespace: str | None,
    lines: list[tuple[int, str]],
) -> None:
    service_type = k8s_first_scalar(lines, "type")
    if service_type:
        analysis["services"][-1]["type"] = service_type
    if service_type == "LoadBalancer":
        level = "medium" if context == "production" else "low"
        add_k8s_resource_finding(analysis, "service_type_loadbalancer", "Service exposes a LoadBalancer", level, "service", path, context, kind, resource_name, namespace, "spec.type")
    if service_type == "NodePort":
        level = "medium" if context == "production" else "low"
        add_k8s_resource_finding(analysis, "service_type_nodeport", "Service exposes a NodePort", level, "service", path, context, kind, resource_name, namespace, "spec.type")


def analyze_k8s_ingress(
    analysis: dict[str, Any],
    path: str,
    context: str,
    kind: str,
    resource_name: str | None,
    namespace: str | None,
    lines: list[tuple[int, str]],
) -> None:
    text = "\n".join(line for _line_number, line in lines)
    if "tls:" not in text:
        add_k8s_resource_finding(analysis, "ingress_tls_missing", "Ingress TLS block was not observed", "low", "ingress", path, context, kind, resource_name, namespace, "spec.tls")


def analyze_k8s_clusterrole(
    analysis: dict[str, Any],
    path: str,
    context: str,
    kind: str,
    resource_name: str | None,
    namespace: str | None,
    lines: list[tuple[int, str]],
) -> None:
    if k8s_block_has_wildcard(lines, "verbs"):
        add_k8s_resource_finding(analysis, "clusterrole_wildcard_verbs", "ClusterRole uses wildcard verbs", "medium", "rbac", path, context, kind, resource_name, namespace, "rules.verbs")
    if k8s_block_has_wildcard(lines, "resources"):
        add_k8s_resource_finding(analysis, "clusterrole_wildcard_resources", "ClusterRole uses wildcard resources", "medium", "rbac", path, context, kind, resource_name, namespace, "rules.resources")


def add_k8s_resource_finding(
    analysis: dict[str, Any],
    finding_id: str,
    title: str,
    level: str,
    category: str,
    path: str,
    context: str,
    kind: str,
    resource_name: str | None,
    namespace: str | None,
    field_path: str,
    *,
    container: str | None = None,
    line: int | None = None,
    evidence_extra: str | None = None,
) -> None:
    parts = [f"kind={kind}", f"metadata.name={resource_name or 'unknown'}", f"field={field_path}"]
    if namespace:
        parts.append(f"namespace={namespace}")
    if container:
        parts.append(f"container={container}")
    if evidence_extra:
        parts.append(evidence_extra)
    add_k8s_config_finding(
        analysis,
        finding_id,
        title,
        k8s_contextual_level(level, context),
        k8s_contextual_confidence("high" if level == "medium" else "medium", context),
        category,
        "A Kubernetes manifest review indicator was observed. Inspectra does not contact a cluster or validate runtime state.",
        "; ".join(parts),
        "Review the manifest in the intended deployment context and apply least-privilege hardening where appropriate.",
        file_path=path,
        context=context,
        line=line,
        kind=kind,
        resource_name=resource_name,
        namespace=namespace,
        container=container,
        field_path=field_path,
    )


def k8s_first_scalar(lines: list[tuple[int, str]], key: str) -> str | None:
    pattern = re.compile(rf"^\s*{re.escape(key)}\s*:\s*['\"]?([^'\"\s#]+)")
    for _line_number, line in lines:
        match = pattern.match(line)
        if match:
            return match.group(1).strip()
    return None


def k8s_metadata(lines: list[tuple[int, str]]) -> dict[str, str | None]:
    metadata: dict[str, str | None] = {"name": None, "namespace": None}
    in_metadata = False
    metadata_indent = 0
    for _line_number, line in lines:
        stripped = line.strip()
        indent = len(line) - len(line.lstrip(" "))
        if re.match(r"metadata\s*:\s*$", stripped):
            in_metadata = True
            metadata_indent = indent
            continue
        if in_metadata and stripped and indent <= metadata_indent:
            in_metadata = False
        if in_metadata:
            for key in ("name", "namespace"):
                match = re.match(rf"{key}\s*:\s*['\"]?([^'\"\s#]+)", stripped)
                if match:
                    metadata[key] = match.group(1).strip()
    return metadata


def k8s_section_keys(lines: list[tuple[int, str]], section: str) -> list[tuple[int, str]]:
    keys: list[tuple[int, str]] = []
    in_section = False
    section_indent = 0
    for line_number, line in lines:
        stripped = line.strip()
        indent = len(line) - len(line.lstrip(" "))
        if re.match(rf"{re.escape(section)}\s*:\s*$", stripped):
            in_section = True
            section_indent = indent
            continue
        if in_section and stripped and indent <= section_indent:
            in_section = False
        if not in_section:
            continue
        match = re.match(r"['\"]?([A-Za-z0-9_.-]+)['\"]?\s*:", stripped)
        if match:
            keys.append((line_number, match.group(1)))
    return keys[:100]


def k8s_mapping_key(line: str) -> str | None:
    match = re.match(r"\s*['\"]?([A-Za-z0-9_.-]+)['\"]?\s*:", line)
    return match.group(1) if match else None


def k8s_extract_containers(lines: list[tuple[int, str]]) -> list[dict[str, Any]]:
    containers: list[dict[str, Any]] = []
    in_containers = False
    containers_indent = 0
    current: dict[str, Any] | None = None
    for line_number, line in lines:
        stripped = line.strip()
        indent = len(line) - len(line.lstrip(" "))
        if re.match(r"(?:initContainers|containers)\s*:\s*$", stripped):
            in_containers = True
            containers_indent = indent
            current = None
            continue
        if in_containers and stripped and indent <= containers_indent:
            in_containers = False
            current = None
        if not in_containers:
            continue
        name_match = re.match(r"-\s*name\s*:\s*['\"]?([^'\"\s#]+)", stripped)
        if name_match:
            current = {"name": name_match.group(1), "line": line_number}
            containers.append(current)
            continue
        image_match = re.match(r"image\s*:\s*['\"]?([^'\"\s#]+)", stripped, flags=re.IGNORECASE)
        if image_match and current is not None:
            current["image"] = image_match.group(1)
    return containers[:100]


def k8s_nearest_container(lines: list[tuple[int, str]], line_number: int) -> str | None:
    name: str | None = None
    for current_line_number, line in lines:
        if current_line_number > line_number:
            break
        match = re.match(r"\s*-\s*name\s*:\s*['\"]?([^'\"\s#]+)", line.strip())
        if match:
            name = match.group(1)
    return name


def k8s_block_has_wildcard(lines: list[tuple[int, str]], key: str) -> bool:
    in_block = False
    block_indent = 0
    for _line_number, line in lines:
        stripped = line.strip()
        indent = len(line) - len(line.lstrip(" "))
        if re.match(rf"{re.escape(key)}\s*:\s*\[.*['\"]?\*['\"]?.*\]\s*$", stripped):
            return True
        if re.match(rf"{re.escape(key)}\s*:\s*$", stripped):
            in_block = True
            block_indent = indent
            continue
        if in_block and stripped and indent <= block_indent:
            in_block = False
        if in_block and re.match(r"-\s*['\"]?\*['\"]?\s*$", stripped):
            return True
    return False


def redact_k8s_secret_text(text: str) -> tuple[str, int]:
    redacted, count = redact_ci_cd_secret_text(text)
    if "[REDACTED PRIVATE KEY]" in redacted:
        redacted = redacted.replace("[REDACTED PRIVATE KEY]", "[REDACTED]")

    def apply(pattern: str, replacement: str) -> None:
        nonlocal redacted, count
        redacted, replacements = re.subn(pattern, replacement, redacted, flags=re.IGNORECASE)
        count += replacements

    apply(r"\b(?:[a-z0-9._-]*user|username|login):(?:[a-z0-9._-]*(?:pass|password|secret|token|key)[a-z0-9._-]*)\b", "[REDACTED]")
    apply(r"(\b(?:password|token|secret|api_key|apikey|private_key|client_secret|key)\b\s*[:=]\s*)(['\"]?)[^\s,'\"}\]]+", r"\1\2[REDACTED]")
    return redacted, count


def finalize_k8s_config_analysis(analysis: dict[str, Any]) -> None:
    analysis["findings"] = dedupe_findings(analysis["findings"])
    analysis["summary"]["findings_count"] = len(analysis["findings"])
    if analysis["summary"]["redacted_values_count"]:
        analysis["redaction_notes"] = [
            "Secret-like Kubernetes manifest values are redacted before storage on a best-effort basis.",
        ]


def add_k8s_config_finding(
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
    kind: str | None = None,
    resource_name: str | None = None,
    namespace: str | None = None,
    container: str | None = None,
    field_path: str | None = None,
    redacted: bool = False,
) -> None:
    safe_description, description_redactions = redact_k8s_secret_text(description)
    safe_evidence, evidence_redactions = redact_k8s_secret_text(evidence)
    safe_recommendation, recommendation_redactions = redact_k8s_secret_text(recommendation)
    redaction_count = description_redactions + evidence_redactions + recommendation_redactions
    if redacted and redaction_count == 0:
        redaction_count = 1
    analysis["summary"]["redacted_values_count"] += redaction_count

    finding = make_finding(finding_id, title, level, safe_description, safe_evidence, safe_recommendation)
    finding["confidence"] = confidence
    finding["category"] = category
    if file_path:
        finding["file_path"] = file_path
    if context:
        finding["context"] = context
    if line is not None:
        finding["line"] = line
    if kind:
        finding["kind"] = kind
    if resource_name:
        finding["resource_name"] = resource_name
    if namespace:
        finding["namespace"] = namespace
    if container:
        finding["container"] = container
    if field_path:
        finding["field_path"] = field_path
    analysis["findings"].append(finding)


def terraform_config_limits(request: ArchiveAnalysisRequest) -> dict[str, int]:
    max_files = TERRAFORM_CONFIG_MAX_FILES if request.max_files is None else request.max_files
    max_file_bytes = TERRAFORM_CONFIG_MAX_FILE_BYTES if request.max_file_bytes is None else request.max_file_bytes
    max_total_bytes = TERRAFORM_CONFIG_MAX_TOTAL_BYTES if request.max_total_bytes is None else request.max_total_bytes
    if max_files <= 0 or max_file_bytes <= 0 or max_total_bytes <= 0:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Terraform config analysis limits must be positive.")
    return {"max_files": max_files, "max_file_bytes": max_file_bytes, "max_total_bytes": max_total_bytes}


def analyze_terraform_config_archive(
    path: Path,
    archive_type: str,
    *,
    max_files: int,
    max_file_bytes: int,
    max_total_bytes: int,
) -> dict[str, Any]:
    analysis = empty_terraform_config_analysis()
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
            scoped["id"] = f"terraform_config_{scoped['id']}"
            analysis["findings"].append(scoped)
            finalize_terraform_config_analysis(analysis)
            return analysis
        with zipfile.ZipFile(path) as archive:
            for index, info in enumerate(archive.filelist, start=1):
                if should_stop_terraform_config_archive_scan(index, analysis):
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
                process_terraform_config_entry(
                    analysis,
                    state,
                    entry,
                    lambda entry_info=info: archive.open(entry_info),
                )
    else:
        with tarfile.open(path, "r:*") as archive:
            for index, member in enumerate(archive, start=1):
                if should_stop_terraform_config_archive_scan(index, analysis):
                    break
                entry = {
                    "path": member.name,
                    "type": tar_member_type(member),
                    "size": member.size,
                    "mode_int": member.mode,
                    "mode": format_file_mode(member.mode),
                    "link_target": member.linkname or None,
                }
                process_terraform_config_entry(
                    analysis,
                    state,
                    entry,
                    lambda tar_member=member: archive.extractfile(tar_member),
                )

    finalize_terraform_config_analysis(analysis)
    return analysis


def empty_terraform_config_analysis(errors: list[str] | None = None) -> dict[str, Any]:
    return {
        "summary": {
            "files_considered": 0,
            "files_reviewed": 0,
            "terraform_files_detected": 0,
            "tfvars_files_detected": 0,
            "state_files_detected": 0,
            "providers_detected": 0,
            "backends_detected": 0,
            "modules_detected": 0,
            "resources_detected": 0,
            "findings_count": 0,
            "redacted_values_count": 0,
            "truncated": False,
        },
        "files_detected": [],
        "files_reviewed": [],
        "providers": [],
        "backends": [],
        "modules": [],
        "resources": [],
        "variables": [],
        "outputs": [],
        "state_files": [],
        "findings": [],
        "redaction_notes": [],
        "errors": errors or [],
        "_required_version_observed": False,
        "_lockfile_observed": False,
        "_terraform_contexts": [],
        "_terraform_hcl_files_reviewed": 0,
    }


def build_terraform_config_result(
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
        "analyzer": "terraform_config_basic",
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
        "providers": analysis.get("providers", []),
        "backends": analysis.get("backends", []),
        "modules": analysis.get("modules", []),
        "resources": analysis.get("resources", []),
        "variables": analysis.get("variables", []),
        "outputs": analysis.get("outputs", []),
        "state_files": analysis.get("state_files", []),
        "findings": findings,
        "redaction_notes": analysis.get("redaction_notes", []),
        "errors": analysis.get("errors", []),
        "truncated": bool(summary.get("truncated")),
    }


def should_stop_terraform_config_archive_scan(index: int, analysis: dict[str, Any]) -> bool:
    if index > ARCHIVE_MAX_ENTRIES:
        analysis["summary"]["truncated"] = True
        add_terraform_config_finding(
            analysis,
            "terraform_config_entry_limit_reached",
            "Archive entry scan limit reached",
            "medium",
            "high",
            "limit",
            "Inspectra stopped scanning archive metadata after the configured entry limit.",
            f"Processed {ARCHIVE_MAX_ENTRIES} entries.",
            "Review the archive with stricter limits or split it before deeper inspection.",
        )
        return True
    return False


def process_terraform_config_entry(
    analysis: dict[str, Any],
    state: dict[str, int],
    entry: dict[str, Any],
    open_entry,
) -> None:
    path = str(entry["path"])
    category = classify_terraform_config_candidate(path)
    if category is None:
        return

    summary = as_dict(analysis["summary"])
    summary["files_considered"] += 1
    if category == "state_file":
        summary["state_files_detected"] += 1
    elif category == "tfvars":
        summary["tfvars_files_detected"] += 1
    else:
        summary["terraform_files_detected"] += 1

    entry_type = str(entry["type"])
    size_bytes = int(entry.get("size") or 0)
    context = terraform_config_file_context(path, category)
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

    skip_reason = terraform_config_skip_reason(record, state)
    if skip_reason:
        record["skip_reason"] = skip_reason
        analysis["files_detected"].append(record)
        if skip_reason == "terraform_state_file_not_read":
            add_terraform_state_file(analysis, record)
        else:
            add_terraform_config_skip_finding(analysis, path, skip_reason, size_bytes, context)
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
        add_terraform_config_finding(
            analysis,
            "terraform_config_file_read_error",
            "Terraform config candidate could not be read safely",
            "low",
            "medium",
            "archive",
            "A Terraform-related candidate file could not be read from the archive within Inspectra limits.",
            f"{path}: {exc}",
            "Review this file manually in a constrained environment if it is expected.",
            file_path=path,
            context=context,
        )
        return

    state["total_bytes_read"] += len(raw_bytes)
    if b"\x00" in raw_bytes:
        record["skip_reason"] = "binary_or_non_text"
        analysis["files_detected"].append(record)
        add_terraform_config_skip_finding(analysis, path, "binary_or_non_text", size_bytes, context)
        return

    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        record["skip_reason"] = "binary_or_non_text"
        analysis["files_detected"].append(record)
        add_terraform_config_skip_finding(analysis, path, "binary_or_non_text", size_bytes, context)
        return

    state["files_read"] += 1
    summary["files_reviewed"] = state["files_read"]
    record["read"] = True
    record["bytes_read"] = len(raw_bytes)
    analysis["files_detected"].append(record)
    analysis["files_reviewed"].append(
        {"path": path, "category": category, "context": context, "size_bytes": size_bytes, "bytes_read": len(raw_bytes)}
    )
    if category in {"terraform", "terragrunt"}:
        analysis["_terraform_contexts"].append(context)
        analysis["_terraform_hcl_files_reviewed"] += 1
    analyze_terraform_config_text(analysis, path, category, context, text)


def classify_terraform_config_candidate(path: str) -> str | None:
    normalized = normalize_archive_entry_path(path)
    lower = normalized.lower()
    basename = lower.rsplit("/", 1)[-1]
    if basename == "terraform.tfstate" or basename.endswith(".tfstate") or basename.endswith(".tfstate.backup"):
        return "state_file"
    if basename == ".terraform.lock.hcl":
        return "lockfile"
    if basename == "terragrunt.hcl" or (basename.startswith("terragrunt") and basename.endswith(".hcl")):
        return "terragrunt"
    if lower.endswith((".auto.tfvars.json", ".tfvars.json", ".auto.tfvars", ".tfvars")):
        return "tfvars"
    if lower.endswith((".tf.json", ".tf")):
        return "terraform"
    return None


def terraform_config_skip_reason(record: dict[str, Any], state: dict[str, int]) -> str | None:
    flags = as_dict(record.get("flags"))
    path = str(record["path"])
    size_bytes = int(record.get("size_bytes") or 0)
    if flags.get("path_traversal"):
        return "path_traversal"
    if flags.get("absolute_path") or flags.get("windows_absolute_path"):
        return "absolute_path"
    if record.get("entry_type") != "file":
        return f"not_regular_file:{record.get('entry_type')}"
    if record.get("category") == "state_file":
        return "terraform_state_file_not_read"
    if len(path) > ARCHIVE_MAX_ENTRY_NAME_LENGTH:
        return "entry_name_too_long"
    if size_bytes > state["max_file_bytes"]:
        return "file_too_large"
    if state["files_read"] >= state["max_files"]:
        return "too_many_files"
    if state["total_bytes_read"] + size_bytes > state["max_total_bytes"]:
        return "total_bytes_limit"
    return None


def add_terraform_state_file(analysis: dict[str, Any], record: dict[str, Any]) -> None:
    state_file = {
        "path": record["path"],
        "category": "state_file",
        "context": record.get("context"),
        "read": False,
        "skip_reason": "terraform_state_file_not_read",
        "size_bytes": record.get("size_bytes"),
        "warning": "Terraform state files can contain secrets and are detected but not read in v1.",
    }
    analysis["state_files"].append(state_file)
    add_terraform_config_finding(
        analysis,
        "terraform_state_file_present",
        "Terraform state file detected but not read",
        terraform_contextual_level("medium", str(record.get("context") or "")),
        terraform_contextual_confidence("high", str(record.get("context") or "")),
        "state",
        "A Terraform state file was present in the archive. Inspectra records its presence but does not read or store its content.",
        f"{record['path']}: state file not read",
        "Avoid sharing Terraform state files in review archives; keep state in an approved backend with appropriate access controls.",
        file_path=str(record["path"]),
        context=str(record.get("context") or ""),
    )


def add_terraform_config_skip_finding(analysis: dict[str, Any], path: str, reason: str, size_bytes: int, context: str) -> None:
    if reason in {"file_too_large", "too_many_files", "total_bytes_limit"}:
        analysis["summary"]["truncated"] = True
    titles = {
        "path_traversal": "Terraform config path uses traversal",
        "absolute_path": "Terraform config path is absolute",
        "entry_name_too_long": "Terraform config entry name is unusually long",
        "file_too_large": "Terraform config file omitted because it exceeds the size limit",
        "too_many_files": "Terraform config file limit reached",
        "total_bytes_limit": "Total Terraform config byte limit reached",
        "binary_or_non_text": "Terraform config candidate is not UTF-8 text",
    }
    level = "medium" if reason in {"path_traversal", "absolute_path", "file_too_large", "too_many_files", "total_bytes_limit"} else "low"
    evidence = f"{path}: {size_bytes} bytes" if reason == "file_too_large" else path[:240]
    if reason.startswith("not_regular_file"):
        title = "Terraform config candidate omitted because it is not a regular file"
        evidence = f"{path}: {reason}"
        level = "low"
    else:
        title = titles.get(reason, "Terraform config candidate skipped by defensive limit")
    add_terraform_config_finding(
        analysis,
        f"terraform_config_{reason.split(':', 1)[0]}",
        title,
        terraform_contextual_level(level, context),
        terraform_contextual_confidence("high" if reason in {"path_traversal", "absolute_path"} else "medium", context),
        "archive",
        "Inspectra detected a Terraform-related file but did not read it because of a defensive limit, unsupported format, or unsafe archive metadata.",
        evidence,
        "Review the archive manually in a constrained environment if this file is expected.",
        file_path=path,
        context=context,
    )


LOWER_CONFIDENCE_TERRAFORM_CONTEXTS = {"development", "test", "local", "example"}
TERRAFORM_SECRET_KEY_RE = re.compile(
    r"(?i)(SECRET_KEY|CLIENT_SECRET|PRIVATE_KEY|DATABASE_URL|REDIS_URL|API_KEY|PASSWORD|TOKEN|SECRET|PASS|ACCESS_KEY|SECRET_ACCESS_KEY|SESSION_TOKEN|CONNECTION_STRING|CERTIFICATE|CREDENTIAL)"
)


def terraform_config_file_context(path: str, category: str = "") -> str:
    normalized = normalize_archive_entry_path(path).lower()
    parts = [part for part in normalized.split("/") if part]
    basename = parts[-1] if parts else normalized
    directories = set(parts[:-1])
    name_tokens = set(re.split(r"[^a-z0-9]+", basename))
    all_tokens = set(parts[:-1]) | name_tokens

    if directories.intersection({"docs", "doc", "examples", "example", "samples", "sample"}) or all_tokens.intersection(
        {"example", "examples", "sample", "samples", "template", "templates", "sandbox"}
    ):
        return "example"
    if all_tokens.intersection({"test", "tests", "testing"}):
        return "test"
    if all_tokens.intersection({"dev", "development"}):
        return "development"
    if "local" in all_tokens:
        return "local"
    if all_tokens.intersection({"prod", "production", "live", "release", "deploy"}) or "deploy" in directories:
        return "production"
    if category in {"terraform", "tfvars", "lockfile"} and len(parts) <= 2:
        return "shared"
    return "ambiguous"


def terraform_contextual_level(level: str, context: str) -> str:
    if context not in LOWER_CONFIDENCE_TERRAFORM_CONTEXTS:
        return level
    if level == "medium":
        return "low"
    if level == "low":
        return "info"
    return level


def terraform_contextual_confidence(confidence: str, context: str) -> str:
    if context not in LOWER_CONFIDENCE_TERRAFORM_CONTEXTS:
        return confidence
    if confidence == "high":
        return "medium"
    if confidence == "medium":
        return "low"
    return confidence


def active_terraform_lines(text: str) -> list[tuple[int, str]]:
    active: list[tuple[int, str]] = []
    in_block_comment = False
    for line_number, line in enumerate(text.splitlines(), start=1):
        current = line
        if in_block_comment:
            if "*/" in current:
                current = current.split("*/", 1)[1]
                in_block_comment = False
            else:
                continue
        while "/*" in current:
            before, after = current.split("/*", 1)
            if "*/" in after:
                current = before + after.split("*/", 1)[1]
                continue
            current = before
            in_block_comment = True
            break
        stripped = current.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("//"):
            continue
        active.append((line_number, current))
    return active


def strip_terraform_inline_comment(value: str) -> str:
    for marker in (" #", " //"):
        if marker in value:
            value = value.split(marker, 1)[0]
    return value.strip().rstrip(",").strip()


def normalize_terraform_value(value: str) -> str:
    return strip_terraform_inline_comment(value).strip().strip("\"'").strip()


def terraform_secret_like_key(key: str) -> bool:
    return bool(TERRAFORM_SECRET_KEY_RE.search(key.replace("-", "_")))


def terraform_blocks(lines: list[tuple[int, str]]) -> list[dict[str, Any]]:
    blocks: list[dict[str, Any]] = []
    index = 0
    block_re = re.compile(r"^\s*(resource|provider|terraform|backend|module|variable|output|locals|data)\b(.*?)\{", re.IGNORECASE)
    while index < len(lines):
        line_number, line = lines[index]
        match = block_re.match(line)
        if not match:
            index += 1
            continue
        start_index = index
        block_type = match.group(1).lower()
        labels = re.findall(r"['\"]([^'\"]+)['\"]", match.group(2))
        body: list[tuple[int, str]] = [(line_number, line)]
        depth = line.count("{") - line.count("}")
        index += 1
        while depth > 0 and index < len(lines):
            next_line_number, next_line = lines[index]
            body.append((next_line_number, next_line))
            depth += next_line.count("{") - next_line.count("}")
            index += 1
        blocks.append({"type": block_type, "labels": labels, "line": line_number, "lines": body})
        index = start_index + 1
    return blocks


def terraform_block_text(block: dict[str, Any]) -> str:
    return "\n".join(str(line) for _line_number, line in block.get("lines", []))


def terraform_block_attr(block: dict[str, Any], key: str) -> tuple[int, str] | None:
    pattern = re.compile(rf"^\s*{re.escape(key)}\s*=\s*(.+?)\s*$", re.IGNORECASE)
    for line_number, line in block.get("lines", []):
        match = pattern.match(str(line))
        if match:
            return int(line_number), normalize_terraform_value(match.group(1))
        inline = re.search(rf"\b{re.escape(key)}\s*=\s*(.+?)(?:\s+[A-Za-z0-9_.-]+\s*=|\s*\}}|$)", str(line), flags=re.IGNORECASE)
        if inline:
            return int(line_number), normalize_terraform_value(inline.group(1))
    return None


def terraform_block_secret_attrs(block: dict[str, Any]) -> list[tuple[int, str]]:
    attrs: list[tuple[int, str]] = []
    for line_number, line in block.get("lines", []):
        for match in re.finditer(r"\b([A-Za-z0-9_.-]+)\s*=\s*([^{}\n]+)", str(line)):
            key = match.group(1)
            value = normalize_terraform_value(match.group(2))
            if value and terraform_secret_like_key(key):
                attrs.append((int(line_number), key))
    return attrs


def analyze_terraform_config_text(analysis: dict[str, Any], path: str, category: str, context: str, text: str) -> None:
    lines = active_terraform_lines(text)
    active_text = "\n".join(line for _line_number, line in lines)

    if category == "lockfile":
        analysis["_lockfile_observed"] = True
        return
    if category == "tfvars":
        analyze_terraform_tfvars(analysis, path, context, lines)
        return

    blocks = terraform_blocks(lines)
    if re.search(r"(?i)\brequired_version\s*=", active_text):
        analysis["_required_version_observed"] = True
    analyze_terraform_required_providers(analysis, path, context, lines, active_text)

    if PRIVATE_KEY_BLOCK_RE.search(active_text):
        add_terraform_config_finding(
            analysis,
            "terraform_plaintext_private_key_hint",
            "Plaintext private key material observed",
            terraform_contextual_level("medium", context),
            terraform_contextual_confidence("high", context),
            "secrets",
            "A private-key-like block was observed in Terraform-related text. Inspectra redacted the material and did not validate it.",
            "private_key=[REDACTED]",
            "Remove private key material from Terraform archives and rotate it if this archive was shared outside trusted storage.",
            file_path=path,
            context=context,
            redacted=True,
        )

    for block in blocks:
        block_type = str(block["type"])
        labels = [str(label) for label in block.get("labels", [])]
        if block_type == "provider":
            analyze_terraform_provider_block(analysis, path, context, block, labels)
        elif block_type == "backend":
            analyze_terraform_backend_block(analysis, path, context, block, labels)
        elif block_type == "module":
            analyze_terraform_module_block(analysis, path, context, block, labels)
        elif block_type == "resource":
            analyze_terraform_resource_block(analysis, path, context, block, labels)
        elif block_type == "variable":
            analyze_terraform_variable_block(analysis, path, context, block, labels)
        elif block_type == "output":
            analyze_terraform_output_block(analysis, path, context, block, labels)


def analyze_terraform_tfvars(analysis: dict[str, Any], path: str, context: str, lines: list[tuple[int, str]]) -> None:
    for line_number, line in lines:
        match = re.match(r"\s*['\"]?([A-Za-z0-9_.-]+)['\"]?\s*[:=]\s*(.+?)\s*$", line)
        if not match:
            continue
        key = match.group(1)
        value = normalize_terraform_value(match.group(2))
        if value and terraform_secret_like_key(key):
            add_terraform_config_finding(
                analysis,
                "terraform_tfvars_secret_like_key",
                "tfvars contains a secret-like key",
                terraform_contextual_level("medium", context),
                terraform_contextual_confidence("high", context),
                "secrets",
                "A Terraform variable values file contains a secret-like key with an inline value. Inspectra redacted the value.",
                f"{key}=[REDACTED]",
                "Avoid committing real secret values in tfvars files; inject them through an approved secret workflow.",
                file_path=path,
                context=context,
                line=line_number,
                block_type="tfvars",
                field_path=key,
                redacted=True,
            )


def analyze_terraform_provider_block(
    analysis: dict[str, Any],
    path: str,
    context: str,
    block: dict[str, Any],
    labels: list[str],
) -> None:
    provider = labels[0] if labels else "unknown"
    analysis["providers"].append({"path": path, "context": context, "provider": provider, "line": block.get("line")})
    analysis["summary"]["providers_detected"] = len(analysis["providers"])
    for line_number, key in terraform_block_secret_attrs(block):
        add_terraform_config_finding(
            analysis,
            "terraform_provider_credentials_hint",
            "Provider block contains credential-like configuration",
            terraform_contextual_level("medium", context),
            terraform_contextual_confidence("high", context),
            "secrets",
            "A provider block contains an attribute with a credential-like name. Inspectra redacted the value and did not contact the provider.",
            f"provider={provider}; {key}=[REDACTED]",
            "Use environment-based or managed identity credentials outside shared archives where possible.",
            file_path=path,
            context=context,
            line=line_number,
            provider=provider,
            block_type="provider",
            field_path=key,
            redacted=True,
        )


def analyze_terraform_backend_block(
    analysis: dict[str, Any],
    path: str,
    context: str,
    block: dict[str, Any],
    labels: list[str],
) -> None:
    backend_type = labels[0] if labels else "unknown"
    analysis["backends"].append({"path": path, "context": context, "type": backend_type, "line": block.get("line")})
    analysis["summary"]["backends_detected"] = len(analysis["backends"])
    for line_number, key in terraform_block_secret_attrs(block):
        finding_id = "terraform_backend_credentials_hint" if re.search(r"(?i)(access|secret|token|password|key)", key) else "terraform_backend_config_secret_like"
        add_terraform_config_finding(
            analysis,
            finding_id,
            "Backend block contains secret-like configuration",
            terraform_contextual_level("medium", context),
            terraform_contextual_confidence("high", context),
            "secrets",
            "A Terraform backend block contains an attribute with a secret-like name. Inspectra redacted the value and did not access remote state.",
            f"backend={backend_type}; {key}=[REDACTED]",
            "Keep backend credentials out of shared archives and use approved backend authentication mechanisms.",
            file_path=path,
            context=context,
            line=line_number,
            block_type="backend",
            field_path=key,
            redacted=True,
        )


def analyze_terraform_module_block(
    analysis: dict[str, Any],
    path: str,
    context: str,
    block: dict[str, Any],
    labels: list[str],
) -> None:
    module_name = labels[0] if labels else "unknown"
    source_attr = terraform_block_attr(block, "source")
    version_attr = terraform_block_attr(block, "version")
    source = source_attr[1] if source_attr else None
    safe_source = redact_terraform_secret_text(source)[0][:240] if source else None
    analysis["modules"].append({"path": path, "context": context, "name": module_name, "source": safe_source, "line": block.get("line")})
    analysis["summary"]["modules_detected"] = len(analysis["modules"])
    if source and terraform_module_source_needs_pin(source, bool(version_attr)):
        add_terraform_config_finding(
            analysis,
            "terraform_module_source_unpinned",
            "Module source appears unpinned",
            terraform_contextual_level("low", context),
            terraform_contextual_confidence("medium", context),
            "module",
            "A Terraform module source appears to reference a remote or registry source without an obvious immutable ref or version.",
            f"module={module_name}; source={safe_source or '[REDACTED]'}",
            "Pin remote modules to reviewed versions or immutable references where repeatability matters.",
            file_path=path,
            context=context,
            line=source_attr[0] if source_attr else None,
            block_type="module",
            field_path="source",
        )


def terraform_module_source_needs_pin(source: str, has_version: bool) -> bool:
    normalized = normalize_terraform_value(source).lower()
    if normalized.startswith(("./", "../")):
        return False
    if has_version:
        return False
    if "?" in normalized and "ref=" in normalized:
        return False
    return any(marker in normalized for marker in ("git::", "github.com", "gitlab.com", "http://", "https://", "terraform-"))


def analyze_terraform_variable_block(
    analysis: dict[str, Any],
    path: str,
    context: str,
    block: dict[str, Any],
    labels: list[str],
) -> None:
    variable_name = labels[0] if labels else "unknown"
    analysis["variables"].append({"path": path, "context": context, "name": variable_name, "line": block.get("line")})
    default_attr = terraform_block_attr(block, "default")
    if default_attr and terraform_secret_like_key(variable_name) and normalize_terraform_value(default_attr[1]).lower() not in {"", "null"}:
        add_terraform_config_finding(
            analysis,
            "terraform_variable_default_secret_like",
            "Terraform variable default contains a secret-like value",
            terraform_contextual_level("medium", context),
            terraform_contextual_confidence("high", context),
            "secrets",
            "A Terraform variable with a secret-like name declares a default value. Inspectra redacted the value.",
            f"variable={variable_name}; default=[REDACTED]",
            "Avoid committing real secret defaults; inject sensitive values through a secure workflow.",
            file_path=path,
            context=context,
            line=default_attr[0],
            block_type="variable",
            field_path=f"variable.{variable_name}.default",
            redacted=True,
        )


def analyze_terraform_output_block(
    analysis: dict[str, Any],
    path: str,
    context: str,
    block: dict[str, Any],
    labels: list[str],
) -> None:
    output_name = labels[0] if labels else "unknown"
    sensitive_attr = terraform_block_attr(block, "sensitive")
    sensitive_value = normalize_terraform_value(sensitive_attr[1]).lower() if sensitive_attr else ""
    analysis["outputs"].append(
        {
            "path": path,
            "context": context,
            "name": output_name,
            "sensitive": sensitive_value == "true" if sensitive_attr else None,
            "line": block.get("line"),
        }
    )
    value_attr = terraform_block_attr(block, "value")
    if value_attr and terraform_secret_like_key(output_name) and sensitive_value != "true":
        add_terraform_config_finding(
            analysis,
            "terraform_output_sensitive_false_secret_like",
            "Secret-like Terraform output is not marked sensitive",
            terraform_contextual_level("medium", context),
            terraform_contextual_confidence("high", context),
            "secrets",
            "A Terraform output with a secret-like name is not marked sensitive. Inspectra redacted the output value.",
            f"output={output_name}; value=[REDACTED]; sensitive={sensitive_value or 'missing'}",
            "Mark secret-like outputs as sensitive and avoid exposing raw credential material.",
            file_path=path,
            context=context,
            line=value_attr[0],
            block_type="output",
            field_path=f"output.{output_name}.value",
            redacted=True,
        )


def analyze_terraform_resource_block(
    analysis: dict[str, Any],
    path: str,
    context: str,
    block: dict[str, Any],
    labels: list[str],
) -> None:
    resource_type = labels[0] if labels else "unknown"
    resource_name = labels[1] if len(labels) > 1 else "unknown"
    provider = resource_type.split("_", 1)[0] if "_" in resource_type else None
    analysis["resources"].append(
        {
            "path": path,
            "context": context,
            "provider": provider,
            "resource_type": resource_type,
            "resource_name": resource_name,
            "line": block.get("line"),
        }
    )
    analysis["summary"]["resources_detected"] = len(analysis["resources"])
    block_text = terraform_block_text(block)
    analyze_terraform_resource_secret_hints(analysis, path, context, block, resource_type, resource_name, provider, block_text)
    analyze_terraform_aws_resource_hints(analysis, path, context, block, resource_type, resource_name, provider, block_text)


def analyze_terraform_resource_secret_hints(
    analysis: dict[str, Any],
    path: str,
    context: str,
    block: dict[str, Any],
    resource_type: str,
    resource_name: str,
    provider: str | None,
    block_text: str,
) -> None:
    if PRIVATE_KEY_BLOCK_RE.search(block_text) or re.search(r"(?im)^\s*private_key\s*=", block_text):
        add_terraform_resource_finding(
            analysis,
            "terraform_plaintext_private_key_hint",
            "Plaintext private key material observed",
            "medium",
            "secrets",
            path,
            context,
            resource_type,
            resource_name,
            "private_key",
            provider=provider,
            line=int(block.get("line") or 0) or None,
            evidence_extra="private_key=[REDACTED]",
            redacted=True,
        )
    if re.search(r"(?ims)^\s*(?:user_data|metadata_startup_script)\s*=", block_text) and (
        TERRAFORM_SECRET_KEY_RE.search(block_text) or PRIVATE_KEY_BLOCK_RE.search(block_text)
    ):
        add_terraform_resource_finding(
            analysis,
            "terraform_secret_in_user_data_hint",
            "user_data or startup script contains secret-like material",
            "medium",
            "secrets",
            path,
            context,
            resource_type,
            resource_name,
            "user_data",
            provider=provider,
            line=int(block.get("line") or 0) or None,
            evidence_extra="user_data=[REDACTED]",
            redacted=True,
        )


def analyze_terraform_aws_resource_hints(
    analysis: dict[str, Any],
    path: str,
    context: str,
    block: dict[str, Any],
    resource_type: str,
    resource_name: str,
    provider: str | None,
    block_text: str,
) -> None:
    if resource_type in {"aws_security_group", "aws_security_group_rule"}:
        has_ipv4_world = "0.0.0.0/0" in block_text
        has_ipv6_world = "::/0" in block_text
        if has_ipv4_world:
            add_terraform_resource_finding(analysis, "aws_security_group_ingress_any_ipv4", "AWS security group allows ingress from any IPv4 address", "medium", "network", path, context, resource_type, resource_name, "ingress.cidr_blocks", provider=provider, line=int(block.get("line") or 0) or None)
        if has_ipv6_world:
            add_terraform_resource_finding(analysis, "aws_security_group_ingress_any_ipv6", "AWS security group allows ingress from any IPv6 address", "medium", "network", path, context, resource_type, resource_name, "ingress.ipv6_cidr_blocks", provider=provider, line=int(block.get("line") or 0) or None)
        if (has_ipv4_world or has_ipv6_world) and re.search(r"(?im)(?:from_port|to_port|port)\s*=\s*22\b", block_text):
            add_terraform_resource_finding(analysis, "aws_security_group_ssh_open_world", "AWS security group exposes SSH to the world", "medium", "network", path, context, resource_type, resource_name, "ingress.22", provider=provider, line=int(block.get("line") or 0) or None)
        if (has_ipv4_world or has_ipv6_world) and re.search(r"(?im)(?:from_port|to_port|port)\s*=\s*3389\b", block_text):
            add_terraform_resource_finding(analysis, "aws_security_group_rdp_open_world", "AWS security group exposes RDP to the world", "medium", "network", path, context, resource_type, resource_name, "ingress.3389", provider=provider, line=int(block.get("line") or 0) or None)
    if resource_type.startswith("aws_iam_"):
        if re.search(r"(?is)(?:actions?|Action)\"?\s*[:=]\s*(?:\[)?\s*[\"']\*[\"']", block_text):
            add_terraform_resource_finding(analysis, "aws_iam_policy_wildcard_action", "AWS IAM policy uses wildcard action", "medium", "iam", path, context, resource_type, resource_name, "policy.Action", provider=provider, line=int(block.get("line") or 0) or None)
        if re.search(r"(?is)(?:resources?|Resource)\"?\s*[:=]\s*(?:\[)?\s*[\"']\*[\"']", block_text):
            add_terraform_resource_finding(analysis, "aws_iam_policy_wildcard_resource", "AWS IAM policy uses wildcard resource", "medium", "iam", path, context, resource_type, resource_name, "policy.Resource", provider=provider, line=int(block.get("line") or 0) or None)
    if resource_type in {"aws_s3_bucket_acl", "aws_s3_bucket_policy", "aws_s3_bucket_public_access_block"}:
        if re.search(r"(?i)public-read|public-read-write|principal\s*=\s*['\"]?\*|block_public_(?:acls|policy)\s*=\s*false|restrict_public_buckets\s*=\s*false", block_text):
            add_terraform_resource_finding(analysis, "aws_s3_bucket_public_access_risk", "AWS S3 configuration has a public-access review indicator", "medium", "storage", path, context, resource_type, resource_name, "s3.public_access", provider=provider, line=int(block.get("line") or 0) or None)


def analyze_terraform_required_providers(
    analysis: dict[str, Any],
    path: str,
    context: str,
    lines: list[tuple[int, str]],
    active_text: str,
) -> None:
    if "required_providers" not in active_text:
        return
    provider_names = set(re.findall(r"(?im)^\s*([A-Za-z0-9_-]+)\s*=\s*\{", active_text))
    versions = re.findall(r"(?im)^\s*version\s*=\s*['\"]([^'\"]+)['\"]", active_text)
    if not versions and provider_names:
        add_terraform_config_finding(
            analysis,
            "terraform_provider_version_unpinned",
            "Required provider version was not observed",
            terraform_contextual_level("low", context),
            terraform_contextual_confidence("medium", context),
            "provider",
            "A required_providers block was observed without an obvious version constraint. Inspectra did not initialize providers.",
            f"{path}: required_providers without version",
            "Pin provider versions with reviewed constraints and commit the lockfile for repeatability.",
            file_path=path,
            context=context,
            block_type="required_providers",
        )
        return
    for line_number, line in lines:
        match = re.match(r"\s*version\s*=\s*['\"]([^'\"]+)['\"]", line)
        if not match:
            continue
        version = match.group(1).strip()
        if not re.fullmatch(r"=?\s*\d+(?:\.\d+){1,3}", version):
            add_terraform_config_finding(
                analysis,
                "terraform_provider_version_unpinned",
                "Required provider version appears broad",
                terraform_contextual_level("low", context),
                terraform_contextual_confidence("medium", context),
                "provider",
                "A provider version constraint appears broad or floating. Inspectra did not initialize or download providers.",
                f"version={version}",
                "Use reviewed provider version constraints and lockfiles for repeatable runs.",
                file_path=path,
                context=context,
                line=line_number,
                block_type="required_providers",
                field_path="version",
            )


def add_terraform_resource_finding(
    analysis: dict[str, Any],
    finding_id: str,
    title: str,
    level: str,
    category: str,
    path: str,
    context: str,
    resource_type: str,
    resource_name: str,
    field_path: str,
    *,
    provider: str | None = None,
    line: int | None = None,
    evidence_extra: str | None = None,
    redacted: bool = False,
) -> None:
    parts = [f"resource_type={resource_type}", f"resource_name={resource_name}", f"field={field_path}"]
    if provider:
        parts.append(f"provider={provider}")
    if evidence_extra:
        parts.append(evidence_extra)
    add_terraform_config_finding(
        analysis,
        finding_id,
        title,
        terraform_contextual_level(level, context),
        terraform_contextual_confidence("high" if level == "medium" else "medium", context),
        category,
        "A Terraform static review indicator was observed. Inspectra does not run Terraform, evaluate plans, or contact cloud providers.",
        "; ".join(parts),
        "Review the configuration in the intended environment and apply least-privilege or hardening controls where appropriate.",
        file_path=path,
        context=context,
        line=line,
        provider=provider,
        resource_type=resource_type,
        resource_name=resource_name,
        block_type="resource",
        field_path=field_path,
        redacted=redacted,
    )


def redact_terraform_secret_text(text: str | None) -> tuple[str, int]:
    if text is None:
        return "", 0
    redacted, count = redact_k8s_secret_text(str(text))
    redacted = redacted.replace("[REDACTED PRIVATE KEY]", "[REDACTED]").replace("PRIVATE_KEY_BLOCK_REDACTED", "[REDACTED]")

    def apply(pattern: str, replacement: str) -> None:
        nonlocal redacted, count
        redacted, replacements = re.subn(pattern, replacement, redacted, flags=re.IGNORECASE)
        count += replacements

    apply(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----", "[REDACTED]")
    apply(r"\bAKIA[0-9A-Z]{16}\b", "[REDACTED]")
    apply(r"\b(?:[a-z0-9._-]*user|username|login):(?:[a-z0-9._-]*(?:pass|password|secret|token|key)[a-z0-9._-]*)\b", "[REDACTED]")
    apply(
        r"(\b(?:access_key|secret_key|secret_access_key|session_token|client_secret|password|token|api_key|apikey|private_key|connection_string|certificate|credential)\b\s*[:=]\s*)(['\"]?)[^\s,'\"}\]]+",
        r"\1\2[REDACTED]",
    )
    return redacted, count


def finalize_terraform_config_analysis(analysis: dict[str, Any]) -> None:
    contexts = [str(context) for context in analysis.get("_terraform_contexts", []) if isinstance(context, str)]
    has_terraform_files = bool(analysis.get("_terraform_hcl_files_reviewed"))
    if has_terraform_files and not analysis.get("_required_version_observed"):
        context = "production" if "production" in contexts else "shared"
        add_terraform_config_finding(
            analysis,
            "terraform_required_version_missing",
            "Terraform required_version was not observed",
            terraform_contextual_level("low", context),
            terraform_contextual_confidence("medium", context),
            "versioning",
            "No Terraform required_version constraint was observed in reviewed Terraform files. Inspectra did not run Terraform.",
            "terraform.required_version missing",
            "Declare reviewed Terraform/OpenTofu version constraints where repeatability matters.",
            context=context,
            block_type="terraform",
        )
    if has_terraform_files and not analysis.get("_lockfile_observed"):
        context = "production" if "production" in contexts else "shared"
        add_terraform_config_finding(
            analysis,
            "terraform_lockfile_missing",
            "Terraform lockfile was not observed",
            terraform_contextual_level("low", context),
            terraform_contextual_confidence("medium", context),
            "versioning",
            "No .terraform.lock.hcl file was observed in the archive. Inspectra did not initialize providers.",
            ".terraform.lock.hcl missing",
            "Commit and review lockfiles for workflows that require reproducible provider selections.",
            context=context,
        )
    if has_terraform_files and not analysis["backends"] and "production" in contexts:
        add_terraform_config_finding(
            analysis,
            "terraform_remote_backend_missing",
            "Remote backend was not observed in production-like Terraform paths",
            "low",
            "backend",
            "Production-like Terraform files were observed without an obvious backend block. Inspectra did not access state.",
            "terraform.backend missing",
            "Confirm state is stored and protected through the intended backend for production environments.",
            context="production",
            block_type="backend",
        )
    analysis["findings"] = dedupe_findings(analysis["findings"])
    analysis["summary"]["findings_count"] = len(analysis["findings"])
    if analysis["summary"]["redacted_values_count"]:
        analysis["redaction_notes"] = [
            "Secret-like Terraform/OpenTofu/Terragrunt values are redacted before storage on a best-effort basis.",
            "Terraform state files are detected but not read in this analyzer.",
        ]
    analysis.pop("_required_version_observed", None)
    analysis.pop("_lockfile_observed", None)
    analysis.pop("_terraform_contexts", None)
    analysis.pop("_terraform_hcl_files_reviewed", None)


def add_terraform_config_finding(
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
    provider: str | None = None,
    resource_type: str | None = None,
    resource_name: str | None = None,
    block_type: str | None = None,
    field_path: str | None = None,
    redacted: bool = False,
) -> None:
    safe_description, description_redactions = redact_terraform_secret_text(description)
    safe_evidence, evidence_redactions = redact_terraform_secret_text(evidence)
    safe_recommendation, recommendation_redactions = redact_terraform_secret_text(recommendation)
    redaction_count = description_redactions + evidence_redactions + recommendation_redactions
    if redacted and redaction_count == 0:
        redaction_count = 1
    analysis["summary"]["redacted_values_count"] += redaction_count

    finding = make_finding(finding_id, title, level, safe_description, safe_evidence, safe_recommendation)
    finding["confidence"] = confidence
    finding["category"] = category
    if file_path:
        finding["file_path"] = file_path
    if context:
        finding["context"] = context
    if line is not None:
        finding["line"] = line
    if provider:
        finding["provider"] = provider
    if resource_type:
        finding["resource_type"] = resource_type
    if resource_name:
        finding["resource_name"] = resource_name
    if block_type:
        finding["block_type"] = block_type
    if field_path:
        finding["field_path"] = field_path
    analysis["findings"].append(finding)


def nginx_config_limits(request: ArchiveAnalysisRequest) -> dict[str, int]:
    max_files = NGINX_CONFIG_MAX_FILES if request.max_files is None else request.max_files
    max_file_bytes = NGINX_CONFIG_MAX_FILE_BYTES if request.max_file_bytes is None else request.max_file_bytes
    max_total_bytes = NGINX_CONFIG_MAX_TOTAL_BYTES if request.max_total_bytes is None else request.max_total_bytes
    if max_files <= 0 or max_file_bytes <= 0 or max_total_bytes <= 0:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Nginx config analysis limits must be positive.")
    return {"max_files": max_files, "max_file_bytes": max_file_bytes, "max_total_bytes": max_total_bytes}


def analyze_nginx_config_archive(
    path: Path,
    archive_type: str,
    *,
    max_files: int,
    max_file_bytes: int,
    max_total_bytes: int,
) -> dict[str, Any]:
    analysis = empty_nginx_config_analysis()
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
            scoped["id"] = f"nginx_config_{scoped['id']}"
            analysis["findings"].append(scoped)
            finalize_nginx_config_analysis(analysis)
            return analysis
        with zipfile.ZipFile(path) as archive:
            for index, info in enumerate(archive.filelist, start=1):
                if should_stop_nginx_config_archive_scan(index, analysis):
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
                process_nginx_config_entry(
                    analysis,
                    state,
                    entry,
                    lambda entry_info=info: archive.open(entry_info),
                )
    else:
        with tarfile.open(path, "r:*") as archive:
            for index, member in enumerate(archive, start=1):
                if should_stop_nginx_config_archive_scan(index, analysis):
                    break
                entry = {
                    "path": member.name,
                    "type": tar_member_type(member),
                    "size": member.size,
                    "mode_int": member.mode,
                    "mode": format_file_mode(member.mode),
                    "link_target": member.linkname or None,
                }
                process_nginx_config_entry(
                    analysis,
                    state,
                    entry,
                    lambda tar_member=member: archive.extractfile(tar_member),
                )

    finalize_nginx_config_analysis(analysis)
    return analysis


def empty_nginx_config_analysis(errors: list[str] | None = None) -> dict[str, Any]:
    return {
        "summary": {
            "files_considered": 0,
            "files_reviewed": 0,
            "nginx_files_detected": 0,
            "server_blocks_detected": 0,
            "location_blocks_detected": 0,
            "upstream_blocks_detected": 0,
            "includes_detected": 0,
            "tls_servers_detected": 0,
            "findings_count": 0,
            "redacted_values_count": 0,
            "truncated": False,
        },
        "files_detected": [],
        "files_reviewed": [],
        "servers": [],
        "locations": [],
        "upstreams": [],
        "includes": [],
        "directives": [],
        "findings": [],
        "redaction_notes": [],
        "errors": errors or [],
        "_server_states": [],
        "_location_states": [],
    }


def build_nginx_config_result(
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
        "analyzer": "nginx_config_basic",
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
        "servers": analysis.get("servers", []),
        "locations": analysis.get("locations", []),
        "upstreams": analysis.get("upstreams", []),
        "includes": analysis.get("includes", []),
        "directives": analysis.get("directives", []),
        "findings": findings,
        "redaction_notes": analysis.get("redaction_notes", []),
        "errors": analysis.get("errors", []),
        "truncated": bool(summary.get("truncated")),
    }


def should_stop_nginx_config_archive_scan(index: int, analysis: dict[str, Any]) -> bool:
    if index > ARCHIVE_MAX_ENTRIES:
        analysis["summary"]["truncated"] = True
        add_nginx_config_finding(
            analysis,
            "nginx_config_entry_limit_reached",
            "Archive entry scan limit reached",
            "medium",
            "high",
            "limit",
            "Inspectra stopped scanning archive metadata after the configured entry limit.",
            f"Processed {ARCHIVE_MAX_ENTRIES} entries.",
            "Review the archive with stricter limits or split it before deeper inspection.",
        )
        return True
    return False


def process_nginx_config_entry(
    analysis: dict[str, Any],
    state: dict[str, int],
    entry: dict[str, Any],
    open_entry,
) -> None:
    path = str(entry["path"])
    category = classify_nginx_config_candidate(path)
    if category is None:
        return

    summary = as_dict(analysis["summary"])
    summary["files_considered"] += 1
    summary["nginx_files_detected"] += 1

    entry_type = str(entry["type"])
    size_bytes = int(entry.get("size") or 0)
    context = nginx_config_file_context(path, category)
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

    skip_reason = nginx_config_skip_reason(record, state)
    if skip_reason:
        record["skip_reason"] = skip_reason
        analysis["files_detected"].append(record)
        add_nginx_config_skip_finding(analysis, path, skip_reason, size_bytes, context)
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
        add_nginx_config_finding(
            analysis,
            "nginx_config_file_read_error",
            "Nginx config candidate could not be read safely",
            "low",
            "medium",
            "archive",
            "A Nginx-related candidate file could not be read from the archive within Inspectra limits.",
            f"{path}: {exc}",
            "Review this file manually in a constrained environment if it is expected.",
            file_path=path,
            context=context,
        )
        return

    state["total_bytes_read"] += len(raw_bytes)
    if b"\x00" in raw_bytes:
        record["skip_reason"] = "binary_or_non_text"
        analysis["files_detected"].append(record)
        add_nginx_config_skip_finding(analysis, path, "binary_or_non_text", size_bytes, context)
        return

    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        record["skip_reason"] = "binary_or_non_text"
        analysis["files_detected"].append(record)
        add_nginx_config_skip_finding(analysis, path, "binary_or_non_text", size_bytes, context)
        return

    state["files_read"] += 1
    summary["files_reviewed"] = state["files_read"]
    record["read"] = True
    record["bytes_read"] = len(raw_bytes)
    analysis["files_detected"].append(record)
    analysis["files_reviewed"].append(
        {"path": path, "category": category, "context": context, "size_bytes": size_bytes, "bytes_read": len(raw_bytes)}
    )
    analyze_nginx_config_text(analysis, path, category, context, text)


def classify_nginx_config_candidate(path: str) -> str | None:
    normalized = normalize_archive_entry_path(path)
    lower = normalized.lower()
    basename = lower.rsplit("/", 1)[-1]
    parts = [part for part in lower.split("/") if part]
    if basename == "nginx.conf" or basename.endswith(".conf"):
        return "nginx_config"
    if any(segment in parts for segment in {"sites-available", "sites-enabled"}):
        return "nginx_config"
    return None


def nginx_config_skip_reason(record: dict[str, Any], state: dict[str, int]) -> str | None:
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


def add_nginx_config_skip_finding(analysis: dict[str, Any], path: str, reason: str, size_bytes: int, context: str) -> None:
    if reason in {"file_too_large", "too_many_files", "total_bytes_limit"}:
        analysis["summary"]["truncated"] = True
    titles = {
        "path_traversal": "Nginx config path uses traversal",
        "absolute_path": "Nginx config path is absolute",
        "entry_name_too_long": "Nginx config entry name is unusually long",
        "file_too_large": "Nginx config file omitted because it exceeds the size limit",
        "too_many_files": "Nginx config file limit reached",
        "total_bytes_limit": "Total Nginx config byte limit reached",
        "binary_or_non_text": "Nginx config candidate is not UTF-8 text",
    }
    level = "medium" if reason in {"path_traversal", "absolute_path", "file_too_large", "too_many_files", "total_bytes_limit"} else "low"
    evidence = f"{path}: {size_bytes} bytes" if reason == "file_too_large" else path[:240]
    if reason.startswith("not_regular_file"):
        title = "Nginx config candidate omitted because it is not a regular file"
        evidence = f"{path}: {reason}"
        level = "low"
    else:
        title = titles.get(reason, "Nginx config candidate skipped by defensive limit")
    add_nginx_config_finding(
        analysis,
        f"nginx_config_{reason.split(':', 1)[0]}",
        title,
        nginx_contextual_level(level, context),
        nginx_contextual_confidence("high" if reason in {"path_traversal", "absolute_path"} else "medium", context),
        "archive",
        "Inspectra detected a Nginx-related file but did not read it because of a defensive limit, unsupported format, or unsafe archive metadata.",
        evidence,
        "Review the archive manually in a constrained environment if this file is expected.",
        file_path=path,
        context=context,
    )


LOWER_CONFIDENCE_NGINX_CONTEXTS = {"development", "test", "local", "example"}
NGINX_SECRET_KEY_RE = re.compile(
    r"(?i)(authorization|cookie|session|secret|token|api[_-]?key|client[_-]?secret|password|passwd|private[_-]?key|credential|auth)"
)
NGINX_HIDDEN_LOCATION_RE = re.compile(r"(?i)(?:^|/)(?:\.git|\.svn|\.hg|\.env)(?:$|/)")
NGINX_SENSITIVE_LOCATION_RE = re.compile(r"(?i)(?:^|/)(?:wp-config\.php|config\.php|adminer\.php|phpinfo\.php|server-status|status)(?:$|/)")
NGINX_BACKUP_LOCATION_RE = re.compile(r"(?i)(?:~|\.bak$|\.backup$|\.old$|\.orig$|\.save$|\.swp$|\.sql$|\.zip$|\.tar$|\.gz$)")


def nginx_config_file_context(path: str, category: str = "") -> str:
    normalized = normalize_archive_entry_path(path).lower()
    parts = [part for part in normalized.split("/") if part]
    basename = parts[-1] if parts else normalized
    directories = set(parts[:-1])
    name_tokens = set(re.split(r"[^a-z0-9]+", basename))
    all_tokens = set(parts[:-1]) | name_tokens

    if directories.intersection({"docs", "doc", "examples", "example", "samples", "sample"}) or all_tokens.intersection(
        {"example", "examples", "sample", "samples", "template", "templates", "sandbox"}
    ):
        return "example"
    if all_tokens.intersection({"test", "tests", "testing"}):
        return "test"
    if all_tokens.intersection({"dev", "development"}):
        return "development"
    if "local" in all_tokens:
        return "local"
    if (
        all_tokens.intersection({"prod", "production", "live", "release", "deploy", "edge", "gateway"})
        or directories.intersection({"sites-enabled", "conf.d", "reverse-proxy"})
        or "deploy" in directories
    ):
        return "production"
    if basename == "nginx.conf":
        return "shared"
    return "ambiguous"


def nginx_contextual_level(level: str, context: str) -> str:
    if context not in LOWER_CONFIDENCE_NGINX_CONTEXTS:
        return level
    if level == "medium":
        return "low"
    if level == "low":
        return "info"
    return level


def nginx_contextual_confidence(confidence: str, context: str) -> str:
    if context not in LOWER_CONFIDENCE_NGINX_CONTEXTS:
        return confidence
    if confidence == "high":
        return "medium"
    if confidence == "medium":
        return "low"
    return confidence


def strip_nginx_comment(line: str) -> str:
    quote: str | None = None
    escaped = False
    result: list[str] = []
    for char in line:
        if escaped:
            result.append(char)
            escaped = False
            continue
        if char == "\\":
            result.append(char)
            escaped = True
            continue
        if quote:
            if char == quote:
                quote = None
            result.append(char)
            continue
        if char in {"'", '"'}:
            quote = char
            result.append(char)
            continue
        if char == "#":
            break
        result.append(char)
    return "".join(result)


def split_nginx_tokens(statement: str) -> list[str]:
    tokens: list[str] = []
    current: list[str] = []
    quote: str | None = None
    escaped = False
    for char in statement.strip():
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if quote:
            if char == quote:
                quote = None
            else:
                current.append(char)
            continue
        if char in {"'", '"'}:
            quote = char
            continue
        if char.isspace():
            if current:
                tokens.append("".join(current))
                current = []
            continue
        current.append(char)
    if current:
        tokens.append("".join(current))
    return tokens


def redact_nginx_secret_text(text: str | None) -> tuple[str, int]:
    if text is None:
        return "", 0
    redacted, count = redact_terraform_secret_text(str(text))

    def apply(pattern: str, replacement: str, flags: int = re.IGNORECASE) -> None:
        nonlocal redacted, count
        redacted, replacements = re.subn(pattern, replacement, redacted, flags=flags)
        count += replacements

    apply(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----", "[REDACTED]", re.IGNORECASE)
    apply(r"\b(https?://)([^/\s:@;\"']+):([^@\s/;\"']+)@([^\s;\"']+)", r"\1[REDACTED]@\4")
    apply(r"\bAuthorization\s*:\s*(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+", "Authorization: [REDACTED]")
    apply(r"\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+", "[REDACTED]")
    apply(r"\b(?:proxy_set_header|add_header|set)\s+([A-Za-z0-9_$-]*(?:token|secret|password|api[_-]?key|authorization|cookie)[A-Za-z0-9_$-]*)\s+[^;\n]+", r"\1 [REDACTED]")
    apply(r"(\b(?:password|token|secret|api[_-]?key|client[_-]?secret|authorization|cookie|session)\b\s*[:=]\s*)[^;\s,\"']+", r"\1[REDACTED]")
    apply(r"(\bAuthorization\s+)(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+", r"\1[REDACTED]")
    redacted = redacted.replace("[REDACTED PRIVATE KEY]", "[REDACTED]").replace("PRIVATE_KEY_BLOCK_REDACTED", "[REDACTED]")
    return redacted, count


def nginx_args_evidence(args: list[str]) -> str:
    if any(NGINX_SECRET_KEY_RE.search(arg) for arg in args):
        if args and NGINX_SECRET_KEY_RE.search(args[0]) and len(args) > 1:
            return f"{args[0]} [REDACTED]"
        return "[REDACTED]"
    safe, _ = redact_nginx_secret_text(" ".join(args))
    return safe[:240]


def current_nginx_frame(stack: list[dict[str, Any]], block_type: str | None = None) -> dict[str, Any] | None:
    for frame in reversed(stack):
        if block_type is None or frame.get("block_type") == block_type:
            return frame
    return None


def current_nginx_server_state(analysis: dict[str, Any], stack: list[dict[str, Any]]) -> dict[str, Any] | None:
    frame = current_nginx_frame(stack, "server")
    if not frame:
        return None
    index = frame.get("server_index")
    states = analysis.get("_server_states", [])
    if isinstance(index, int) and 0 <= index < len(states):
        return states[index]
    return None


def current_nginx_location_state(analysis: dict[str, Any], stack: list[dict[str, Any]]) -> dict[str, Any] | None:
    frame = current_nginx_frame(stack, "location")
    if not frame:
        return None
    index = frame.get("location_index")
    states = analysis.get("_location_states", [])
    if isinstance(index, int) and 0 <= index < len(states):
        return states[index]
    return None


def analyze_nginx_config_text(analysis: dict[str, Any], path: str, category: str, context: str, text: str) -> None:
    if PRIVATE_KEY_BLOCK_RE.search(text):
        add_nginx_config_finding(
            analysis,
            "nginx_variable_secret_like_value",
            "Nginx config contains private key-like material",
            nginx_contextual_level("medium", context),
            nginx_contextual_confidence("high", context),
            "secrets",
            "Private key-like material appeared in a Nginx config candidate. Inspectra redacted the value.",
            "private_key=[REDACTED]",
            "Do not commit private key material in Nginx configuration archives.",
            file_path=path,
            context=context,
            redacted=True,
        )

    stack: list[dict[str, Any]] = []
    pending = ""
    pending_line = 0
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = strip_nginx_comment(raw_line).strip()
        if not line:
            continue

        while "{" in line:
            before, after = line.split("{", 1)
            before = before.strip()
            if before:
                start_nginx_block(analysis, stack, path, context, before, line_number)
            line = after.strip()

        close_count = line.count("}")
        if close_count:
            line = line.replace("}", " ").strip()

        if line:
            parts = line.split(";")
            for index, part in enumerate(parts):
                fragment = part.strip()
                if fragment:
                    if not pending:
                        pending_line = line_number
                    pending = f"{pending} {fragment}".strip()
                if index < len(parts) - 1 and pending:
                    process_nginx_directive(analysis, stack, path, context, pending, pending_line or line_number)
                    pending = ""
                    pending_line = 0

        for _ in range(close_count):
            if stack:
                stack.pop()
    if pending:
        safe_pending, redactions = redact_nginx_secret_text(pending)
        analysis["summary"]["redacted_values_count"] += redactions
        analysis["errors"].append(f"{path}: unterminated directive near line {pending_line or 'unknown'}: {safe_pending[:120]}")


def start_nginx_block(
    analysis: dict[str, Any],
    stack: list[dict[str, Any]],
    path: str,
    context: str,
    statement: str,
    line_number: int,
) -> None:
    tokens = split_nginx_tokens(statement)
    if not tokens:
        return
    block_type = tokens[0].lower()
    args = tokens[1:]
    frame: dict[str, Any] = {"block_type": block_type, "args": args, "line": line_number}

    if block_type == "server":
        server = {
            "path": path,
            "context": context,
            "line": line_number,
            "server_name": None,
            "listen": [],
            "tls": False,
        }
        state = {
            **server,
            "headers": set(),
            "hsts_seen": False,
            "hsts_max_age": None,
            "ssl_protocols_seen": False,
            "https_redirect": False,
            "default_server": False,
            "cors_origin_wildcard": False,
            "cors_credentials": False,
        }
        analysis["servers"].append(server)
        analysis["_server_states"].append(state)
        frame["server_index"] = len(analysis["_server_states"]) - 1
    elif block_type == "location":
        location_path = " ".join(args) or "unknown"
        server_state = current_nginx_server_state(analysis, stack)
        location = {
            "path": path,
            "context": context,
            "line": line_number,
            "location": location_path,
            "server_name": server_state.get("server_name") if server_state else None,
        }
        state = {
            **location,
            "proxy_pass": None,
            "proxy_headers": set(),
            "cors_origin_wildcard": False,
            "cors_credentials": False,
        }
        analysis["locations"].append(location)
        analysis["_location_states"].append(state)
        frame["location_index"] = len(analysis["_location_states"]) - 1
        if NGINX_HIDDEN_LOCATION_RE.search(location_path):
            add_nginx_config_finding(
                analysis,
                "nginx_hidden_files_exposed",
                "Nginx location may expose hidden or sensitive files",
                nginx_contextual_level("medium", context),
                nginx_contextual_confidence("high", context),
                "exposure",
                "A location path targets hidden or sensitive-looking files. Inspectra does not contact the server.",
                f"location={location_path}",
                "Confirm the location is denied or protected in the effective Nginx configuration.",
                file_path=path,
                context=context,
                line=line_number,
                block_type="location",
                location=location_path,
            )
        if NGINX_BACKUP_LOCATION_RE.search(location_path):
            add_nginx_config_finding(
                analysis,
                "nginx_backup_files_exposed",
                "Nginx location may expose backup files",
                nginx_contextual_level("medium", context),
                nginx_contextual_confidence("medium", context),
                "exposure",
                "A location path appears to match backup/archive file patterns.",
                f"location={location_path}",
                "Deny access to backup and temporary files at the edge.",
                file_path=path,
                context=context,
                line=line_number,
                block_type="location",
                location=location_path,
            )
        if NGINX_SENSITIVE_LOCATION_RE.search(location_path):
            add_nginx_config_finding(
                analysis,
                "nginx_sensitive_location_exposed",
                "Nginx location may expose sensitive application paths",
                nginx_contextual_level("medium", context),
                nginx_contextual_confidence("medium", context),
                "exposure",
                "A location path targets sensitive-looking application or status paths. Inspectra does not contact the server.",
                f"location={location_path}",
                "Confirm sensitive paths are denied, removed, or protected in the effective Nginx configuration.",
                file_path=path,
                context=context,
                line=line_number,
                block_type="location",
                location=location_path,
            )
    elif block_type == "upstream":
        upstream = {
            "path": path,
            "context": context,
            "line": line_number,
            "name": args[0] if args else "unknown",
        }
        analysis["upstreams"].append(upstream)
        frame["upstream"] = upstream["name"]

    stack.append(frame)


def process_nginx_directive(
    analysis: dict[str, Any],
    stack: list[dict[str, Any]],
    path: str,
    context: str,
    statement: str,
    line_number: int,
) -> None:
    tokens = split_nginx_tokens(statement)
    if not tokens:
        return
    directive = tokens[0].lower()
    args = tokens[1:]
    block = current_nginx_frame(stack)
    block_type = str(block.get("block_type")) if block else "global"
    server_state = current_nginx_server_state(analysis, stack)
    location_state = current_nginx_location_state(analysis, stack)
    server_name = server_state.get("server_name") if server_state else None
    location_path = location_state.get("location") if location_state else None
    upstream_frame = current_nginx_frame(stack, "upstream")
    upstream_name = upstream_frame.get("upstream") if upstream_frame else None
    safe_args = nginx_args_evidence(args)
    analysis["directives"].append(
        {
            "path": path,
            "context": context,
            "line": line_number,
            "directive": directive,
            "arguments": safe_args,
            "block_type": block_type,
            "server_name": server_name,
            "location": location_path,
            "upstream": upstream_name,
        }
    )

    is_cors_header = directive == "add_header" and bool(args) and args[0].lower().startswith("access-control-allow-")
    if not is_cors_header and (NGINX_SECRET_KEY_RE.search(directive) or (args and NGINX_SECRET_KEY_RE.search(" ".join(args)))):
        if directive in {"add_header", "proxy_set_header"} or directive.startswith("$") or directive == "set":
            add_nginx_config_finding(
                analysis,
                "nginx_header_secret_like_value" if directive in {"add_header", "proxy_set_header"} else "nginx_variable_secret_like_value",
                "Nginx directive contains secret-like material",
                nginx_contextual_level("medium", context),
                nginx_contextual_confidence("medium", context),
                "secrets",
                "A Nginx directive contains a secret-like key or value. Inspectra redacted the evidence.",
                f"directive={directive}; value=[REDACTED]",
                "Move credentials and sensitive tokens out of committed Nginx config.",
                file_path=path,
                context=context,
                line=line_number,
                block_type=block_type,
                server_name=server_name,
                location=location_path,
                directive=directive,
                redacted=True,
            )
    if directive == "include":
        analyze_nginx_include(analysis, path, context, args, line_number, block_type)
    elif directive == "listen" and server_state is not None:
        listen_value = " ".join(args)
        server_state["listen"].append(listen_value)
        server_record = analysis["servers"][analysis["_server_states"].index(server_state)]
        server_record["listen"] = list(server_state["listen"])
        if "ssl" in listen_value.lower() or re.search(r"(?<!\d)443(?!\d)", listen_value):
            server_state["tls"] = True
            server_record["tls"] = True
        if "default_server" in listen_value.lower():
            server_state["default_server"] = True
            add_nginx_config_finding(
                analysis,
                "nginx_default_server_public_hint",
                "Nginx default_server is present",
                nginx_contextual_level("medium", context),
                nginx_contextual_confidence("medium", context),
                "exposure",
                "A default_server listener was observed. Inspectra does not validate whether it is externally reachable.",
                f"listen={nginx_args_evidence(args)}",
                "Confirm default virtual hosts expose only intended responses in production.",
                file_path=path,
                context=context,
                line=line_number,
                block_type="server",
                directive=directive,
                server_name=server_name,
            )
    elif directive == "server_name" and server_state is not None:
        server_name_value = " ".join(args)
        server_state["server_name"] = server_name_value
        server_record = analysis["servers"][analysis["_server_states"].index(server_state)]
        server_record["server_name"] = server_name_value
    elif directive in {"ssl_certificate", "ssl_certificate_key"} and server_state is not None:
        server_state["tls"] = True
        server_record = analysis["servers"][analysis["_server_states"].index(server_state)]
        server_record["tls"] = True
        if directive == "ssl_certificate_key":
            add_nginx_config_finding(
                analysis,
                "nginx_ssl_certificate_key_path_present",
                "Nginx TLS private key path is present",
                "info",
                nginx_contextual_confidence("medium", context),
                "tls",
                "A ssl_certificate_key directive was observed. Inspectra records the path as context and does not read certificate files.",
                f"directive=ssl_certificate_key; path={safe_args}",
                "Confirm private key files are stored outside committed archives and protected by deployment controls.",
                file_path=path,
                context=context,
                line=line_number,
                block_type=block_type,
                directive=directive,
                server_name=server_name,
            )
    elif directive == "ssl_protocols" and server_state is not None:
        server_state["ssl_protocols_seen"] = True
        protocol_text = " ".join(args).lower()
        if any(protocol in protocol_text for protocol in ("sslv2", "sslv3", "tlsv1 ", "tlsv1;", "tlsv1.0", "tlsv1.1")) or "tlsv1.1" in protocol_text:
            add_nginx_config_finding(
                analysis,
                "nginx_ssl_protocol_legacy_enabled",
                "Legacy TLS protocol appears enabled",
                nginx_contextual_level("medium", context),
                nginx_contextual_confidence("high", context),
                "tls",
                "The ssl_protocols directive includes legacy protocol names.",
                f"ssl_protocols={safe_args}",
                "Prefer modern TLS protocol versions for production listeners.",
                file_path=path,
                context=context,
                line=line_number,
                block_type=block_type,
                directive=directive,
                server_name=server_name,
            )
    elif directive == "add_header":
        analyze_nginx_add_header(analysis, path, context, args, line_number, block_type, server_state, location_state, server_name, location_path)
    elif directive == "return" and server_state is not None:
        if any("https://" in arg.lower() for arg in args):
            server_state["https_redirect"] = True
    elif directive == "server_tokens" and args and args[0].lower() == "on":
        add_nginx_config_finding(
            analysis,
            "nginx_server_tokens_on",
            "Nginx server_tokens is enabled",
            nginx_contextual_level("medium", context),
            nginx_contextual_confidence("high", context),
            "exposure",
            "The server_tokens directive is set to on.",
            "server_tokens on",
            "Disable server_tokens for production edge configurations unless explicitly required.",
            file_path=path,
            context=context,
            line=line_number,
            block_type=block_type,
            directive=directive,
            server_name=server_name,
            location=location_path,
        )
    elif directive == "autoindex" and args and args[0].lower() == "on":
        add_nginx_config_finding(
            analysis,
            "nginx_autoindex_on",
            "Nginx autoindex is enabled",
            nginx_contextual_level("medium", context),
            nginx_contextual_confidence("high", context),
            "exposure",
            "The autoindex directive is enabled in a Nginx context.",
            "autoindex on",
            "Disable directory listings unless the listing is intentional and access controlled.",
            file_path=path,
            context=context,
            line=line_number,
            block_type=block_type,
            directive=directive,
            server_name=server_name,
            location=location_path,
        )
    elif directive == "stub_status":
        add_nginx_config_finding(
            analysis,
            "nginx_stub_status_public_hint",
            "Nginx stub_status endpoint is present",
            nginx_contextual_level("medium", context),
            nginx_contextual_confidence("medium", context),
            "exposure",
            "A stub_status directive was observed. Inspectra does not validate access control or network reachability.",
            f"location={location_path or 'unknown'}; stub_status",
            "Restrict stub_status endpoints to trusted networks or remove them from public virtual hosts.",
            file_path=path,
            context=context,
            line=line_number,
            block_type=block_type,
            directive=directive,
            server_name=server_name,
            location=location_path,
        )
    elif directive == "proxy_pass":
        analyze_nginx_proxy_pass(analysis, path, context, args, line_number, block_type, location_state, server_name, location_path)
    elif directive == "proxy_ssl_verify" and args and args[0].lower() == "off":
        add_nginx_config_finding(
            analysis,
            "nginx_proxy_ssl_verify_off",
            "Nginx proxy SSL verification is disabled",
            nginx_contextual_level("medium", context),
            nginx_contextual_confidence("high", context),
            "proxy",
            "The proxy_ssl_verify directive is set to off.",
            "proxy_ssl_verify off",
            "Enable upstream TLS verification where HTTPS upstreams are used.",
            file_path=path,
            context=context,
            line=line_number,
            block_type=block_type,
            directive=directive,
            server_name=server_name,
            location=location_path,
        )
    elif directive == "proxy_set_header" and location_state is not None:
        header_name = args[0].lower() if args else ""
        if header_name in {"host", "x-forwarded-proto", "x-forwarded-for"}:
            location_state["proxy_headers"].add(header_name)
    elif directive == "client_max_body_size":
        analyze_nginx_body_size(analysis, path, context, args, line_number, block_type, server_name, location_path)
    elif directive in {"proxy_read_timeout", "proxy_connect_timeout", "keepalive_timeout"}:
        analyze_nginx_timeout(analysis, path, context, directive, args, line_number, block_type, server_name, location_path)
    elif directive == "access_log" and args and args[0].lower() == "off":
        add_nginx_config_finding(
            analysis,
            "nginx_access_log_off",
            "Nginx access logging is disabled",
            nginx_contextual_level("low", context),
            nginx_contextual_confidence("high", context),
            "logging",
            "The access_log directive is set to off.",
            "access_log off",
            "Confirm request logging expectations for this edge path.",
            file_path=path,
            context=context,
            line=line_number,
            block_type=block_type,
            directive=directive,
        )
    elif directive == "error_log" and any(arg.lower() == "debug" for arg in args):
        add_nginx_config_finding(
            analysis,
            "nginx_error_log_debug",
            "Nginx error_log is configured at debug level",
            nginx_contextual_level("medium", context),
            nginx_contextual_confidence("high", context),
            "logging",
            "The error_log directive includes debug level logging.",
            f"error_log={safe_args}",
            "Avoid debug logging in production edge configs unless temporarily needed.",
            file_path=path,
            context=context,
            line=line_number,
            block_type=block_type,
            directive=directive,
        )
    elif directive == "auth_basic" and args and args[0].lower() != "off" and NGINX_SECRET_KEY_RE.search(" ".join(args)):
        add_nginx_config_finding(
            analysis,
            "nginx_basic_auth_inline_secret_hint",
            "Nginx auth_basic contains secret-like inline text",
            nginx_contextual_level("medium", context),
            nginx_contextual_confidence("medium", context),
            "secrets",
            "An auth_basic directive contains secret-like inline text. Inspectra redacted the evidence.",
            "auth_basic=[REDACTED]",
            "Use auth_basic_user_file or an external identity layer; do not commit inline secrets.",
            file_path=path,
            context=context,
            line=line_number,
            block_type=block_type,
            directive=directive,
            redacted=True,
        )


def analyze_nginx_include(analysis: dict[str, Any], path: str, context: str, args: list[str], line_number: int, block_type: str) -> None:
    target = args[0] if args else ""
    safe_target, redactions = redact_nginx_secret_text(target)
    analysis["summary"]["redacted_values_count"] += redactions
    include = {
        "path": path,
        "context": context,
        "line": line_number,
        "target": safe_target,
        "absolute": target.startswith("/"),
        "glob": any(char in target for char in "*?["),
        "resolved": False,
    }
    analysis["includes"].append(include)
    if target.startswith("/"):
        add_nginx_config_finding(
            analysis,
            "nginx_include_absolute_path",
            "Nginx include uses an absolute path",
            "info",
            nginx_contextual_confidence("high", context),
            "include",
            "An include directive references an absolute path. Inspectra records it as context but does not read host paths.",
            f"include={safe_target}",
            "Confirm included files are present and reviewed in the deployment environment.",
            file_path=path,
            context=context,
            line=line_number,
            block_type=block_type,
            directive="include",
        )
    if any(char in target for char in "*?["):
        add_nginx_config_finding(
            analysis,
            "nginx_include_glob_detected",
            "Nginx include uses a glob pattern",
            "info",
            nginx_contextual_confidence("high", context),
            "include",
            "An include directive uses a glob. Inspectra does not expand include patterns.",
            f"include={safe_target}",
            "Review the effective include set in the target deployment workflow.",
            file_path=path,
            context=context,
            line=line_number,
            block_type=block_type,
            directive="include",
        )
    add_nginx_config_finding(
        analysis,
        "nginx_include_not_resolved",
        "Nginx include was detected but not resolved",
        nginx_contextual_level("low", context),
        nginx_contextual_confidence("high", context),
        "include",
        "Inspectra detected an include directive and intentionally did not resolve it in v1.",
        f"include={safe_target}",
        "Ensure referenced include files are included in review archives or reviewed separately.",
        file_path=path,
        context=context,
        line=line_number,
        block_type=block_type,
        directive="include",
    )


def analyze_nginx_add_header(
    analysis: dict[str, Any],
    path: str,
    context: str,
    args: list[str],
    line_number: int,
    block_type: str,
    server_state: dict[str, Any] | None,
    location_state: dict[str, Any] | None,
    server_name: str | None,
    location_path: str | None,
) -> None:
    if not args:
        return
    header_name = args[0].lower()
    header_value = " ".join(args[1:])
    target = location_state or server_state
    if target is not None:
        target.setdefault("headers", set()).add(header_name)
    if header_name == "strict-transport-security":
        if target is not None:
            target["hsts_seen"] = True
            max_age = nginx_hsts_max_age(header_value)
            target["hsts_max_age"] = max_age
        max_age = nginx_hsts_max_age(header_value)
        if max_age is not None and max_age < 15_552_000:
            add_nginx_config_finding(
                analysis,
                "nginx_hsts_low_max_age",
                "Nginx HSTS max-age appears low",
                nginx_contextual_level("low", context),
                nginx_contextual_confidence("medium", context),
                "tls",
                "Strict-Transport-Security is present with a low max-age value.",
                f"max-age={max_age}",
                "Review HSTS policy and max-age for production HTTPS services.",
                file_path=path,
                context=context,
                line=line_number,
                block_type=block_type,
                directive="add_header",
                server_name=server_name,
                location=location_path,
            )
    if header_name == "access-control-allow-origin" and "*" in header_value:
        if target is not None:
            target["cors_origin_wildcard"] = True
        add_nginx_config_finding(
            analysis,
            "nginx_cors_wildcard_origin",
            "Nginx CORS allows wildcard origin",
            nginx_contextual_level("low", context),
            nginx_contextual_confidence("high", context),
            "cors",
            "Access-Control-Allow-Origin is configured with a wildcard.",
            "Access-Control-Allow-Origin=*",
            "Confirm wildcard CORS is intended and does not combine with credentialed requests.",
            file_path=path,
            context=context,
            line=line_number,
            block_type=block_type,
            directive="add_header",
            server_name=server_name,
            location=location_path,
        )
    if header_name == "access-control-allow-credentials" and "true" in header_value.lower():
        if target is not None:
            target["cors_credentials"] = True
    if target and target.get("cors_origin_wildcard") and target.get("cors_credentials"):
        add_nginx_config_finding(
            analysis,
            "nginx_cors_credentials_with_wildcard",
            "Nginx CORS credentials are combined with wildcard origin",
            nginx_contextual_level("medium", context),
            nginx_contextual_confidence("high", context),
            "cors",
            "CORS appears to allow credentials while also allowing wildcard origins.",
            "Access-Control-Allow-Origin=*; Access-Control-Allow-Credentials=true",
            "Avoid combining credentialed CORS with wildcard origins.",
            file_path=path,
            context=context,
            line=line_number,
            block_type=block_type,
            directive="add_header",
            server_name=server_name,
            location=location_path,
        )


def nginx_hsts_max_age(value: str) -> int | None:
    match = re.search(r"max-age\s*=\s*(\d+)", value, flags=re.IGNORECASE)
    if not match:
        return None
    try:
        return int(match.group(1))
    except ValueError:
        return None


def analyze_nginx_proxy_pass(
    analysis: dict[str, Any],
    path: str,
    context: str,
    args: list[str],
    line_number: int,
    block_type: str,
    location_state: dict[str, Any] | None,
    server_name: str | None,
    location_path: str | None,
) -> None:
    if not args:
        return
    target = args[0]
    safe_target, redactions = redact_nginx_secret_text(target)
    analysis["summary"]["redacted_values_count"] += redactions
    if location_state is not None:
        location_state["proxy_pass"] = safe_target
    if re.match(r"(?i)^http://", target):
        add_nginx_config_finding(
            analysis,
            "nginx_proxy_pass_http_upstream",
            "Nginx proxies to an HTTP upstream",
            nginx_contextual_level("low", context),
            nginx_contextual_confidence("high", context),
            "proxy",
            "A proxy_pass target uses http://. Inspectra does not contact the upstream.",
            f"proxy_pass={safe_target}",
            "Confirm whether plaintext upstream transport is acceptable for this deployment path.",
            file_path=path,
            context=context,
            line=line_number,
            block_type=block_type,
            directive="proxy_pass",
            server_name=server_name,
            location=location_path,
        )
    if re.match(r"(?i)^https?://[^/\s:@;\"']+:[^@\s/;\"']+@", target):
        add_nginx_config_finding(
            analysis,
            "nginx_proxy_pass_credentials_hint",
            "Nginx proxy_pass URL contains credentials",
            nginx_contextual_level("medium", context),
            nginx_contextual_confidence("high", context),
            "secrets",
            "A proxy_pass URL contains userinfo credentials. Inspectra redacted the credential material.",
            "proxy_pass=[REDACTED]",
            "Move upstream credentials out of committed proxy URLs and into approved secret handling.",
            file_path=path,
            context=context,
            line=line_number,
            block_type=block_type,
            directive="proxy_pass",
            server_name=server_name,
            location=location_path,
            redacted=True,
        )


def parse_nginx_size_bytes(value: str) -> int | None:
    match = re.match(r"(?i)^\s*(\d+)([kmg])?\s*$", value)
    if not match:
        return None
    number = int(match.group(1))
    unit = (match.group(2) or "").lower()
    multiplier = {"k": 1024, "m": 1024 * 1024, "g": 1024 * 1024 * 1024}.get(unit, 1)
    return number * multiplier


def analyze_nginx_body_size(
    analysis: dict[str, Any],
    path: str,
    context: str,
    args: list[str],
    line_number: int,
    block_type: str,
    server_name: str | None,
    location_path: str | None,
) -> None:
    if not args:
        return
    value = args[0].lower()
    size = parse_nginx_size_bytes(value)
    if value == "0" or (size is not None and size > 100 * 1024 * 1024):
        add_nginx_config_finding(
            analysis,
            "nginx_client_max_body_size_unlimited_or_large",
            "Nginx client_max_body_size appears unlimited or large",
            nginx_contextual_level("low", context),
            nginx_contextual_confidence("high", context),
            "limits",
            "client_max_body_size is configured as unlimited or larger than the conservative review threshold.",
            f"client_max_body_size={value}",
            "Confirm upload/body size limits match the service's expected abuse controls.",
            file_path=path,
            context=context,
            line=line_number,
            block_type=block_type,
            directive="client_max_body_size",
            server_name=server_name,
            location=location_path,
        )


def parse_nginx_duration_seconds(value: str) -> int | None:
    match = re.match(r"(?i)^\s*(\d+)(ms|s|m|h)?\s*$", value)
    if not match:
        return None
    number = int(match.group(1))
    unit = (match.group(2) or "s").lower()
    if unit == "ms":
        return max(1, number // 1000)
    return number * {"s": 1, "m": 60, "h": 3600}.get(unit, 1)


def analyze_nginx_timeout(
    analysis: dict[str, Any],
    path: str,
    context: str,
    directive: str,
    args: list[str],
    line_number: int,
    block_type: str,
    server_name: str | None,
    location_path: str | None,
) -> None:
    if not args:
        return
    seconds = parse_nginx_duration_seconds(args[0])
    if seconds is None or seconds <= 300:
        return
    finding_id = "nginx_proxy_read_timeout_high" if directive == "proxy_read_timeout" else "nginx_proxy_connect_timeout_high"
    title = "Nginx proxy timeout appears high"
    add_nginx_config_finding(
        analysis,
        finding_id,
        title,
        nginx_contextual_level("low", context),
        nginx_contextual_confidence("medium", context),
        "limits",
        "A proxy timeout is above the conservative review threshold.",
        f"{directive}={args[0]}",
        "Confirm timeout values match expected service behavior and resource protection.",
        file_path=path,
        context=context,
        line=line_number,
        block_type=block_type,
        directive=directive,
        server_name=server_name,
        location=location_path,
    )


def finalize_nginx_config_analysis(analysis: dict[str, Any]) -> None:
    for server in analysis.get("_server_states", []):
        finalize_nginx_server_state(analysis, server)
    for location in analysis.get("_location_states", []):
        finalize_nginx_location_state(analysis, location)
    analysis["summary"]["server_blocks_detected"] = len(analysis.get("servers", []))
    analysis["summary"]["location_blocks_detected"] = len(analysis.get("locations", []))
    analysis["summary"]["upstream_blocks_detected"] = len(analysis.get("upstreams", []))
    analysis["summary"]["includes_detected"] = len(analysis.get("includes", []))
    analysis["summary"]["tls_servers_detected"] = len([server for server in analysis.get("_server_states", []) if server.get("tls")])
    analysis["findings"] = dedupe_findings(analysis["findings"])
    analysis["summary"]["findings_count"] = len(analysis["findings"])
    if analysis["summary"]["redacted_values_count"]:
        analysis["redaction_notes"] = [
            "Secret-like Nginx/reverse-proxy values are redacted before storage on a best-effort basis.",
            "Nginx include directives are detected but not resolved by this analyzer.",
        ]
    analysis.pop("_server_states", None)
    analysis.pop("_location_states", None)


def finalize_nginx_server_state(analysis: dict[str, Any], server: dict[str, Any]) -> None:
    path = str(server.get("path") or "")
    context = str(server.get("context") or "ambiguous")
    server_name = server.get("server_name")
    line = int(server.get("line") or 0) or None
    headers = {str(header).lower() for header in server.get("headers", set())}
    if server.get("tls"):
        if not server.get("ssl_protocols_seen"):
            add_nginx_config_finding(
                analysis,
                "nginx_ssl_protocols_missing",
                "Nginx TLS server lacks an explicit ssl_protocols directive",
                nginx_contextual_level("low", context),
                nginx_contextual_confidence("medium", context),
                "tls",
                "A TLS-looking server block does not include an obvious ssl_protocols directive in the reviewed file.",
                f"server_name={server_name or 'unknown'}; ssl_protocols missing",
                "Confirm effective TLS protocol configuration in reviewed Nginx config.",
                file_path=path,
                context=context,
                line=line,
                block_type="server",
                server_name=server_name,
            )
        if not server.get("hsts_seen"):
            add_nginx_config_finding(
                analysis,
                "nginx_hsts_missing",
                "Nginx TLS server lacks an obvious HSTS header",
                nginx_contextual_level("low", context),
                nginx_contextual_confidence("medium", context),
                "tls",
                "A TLS-looking server block does not include a Strict-Transport-Security header in the reviewed file.",
                f"server_name={server_name or 'unknown'}; HSTS missing",
                "Confirm HSTS policy for HTTPS production services.",
                file_path=path,
                context=context,
                line=line,
                block_type="server",
                server_name=server_name,
            )
    listens = " ".join(str(item) for item in server.get("listen", []))
    if re.search(r"(?<!\d)80(?!\d)", listens) and not server.get("tls") and not server.get("https_redirect"):
        add_nginx_config_finding(
            analysis,
            "nginx_https_redirect_missing",
            "Nginx HTTP listener lacks an obvious HTTPS redirect",
            nginx_contextual_level("low", context),
            nginx_contextual_confidence("low", context),
            "tls",
            "A port 80 listener was observed without an obvious return to HTTPS in the same server block.",
            f"server_name={server_name or 'unknown'}; listen={listens or 'unknown'}",
            "Confirm HTTP-to-HTTPS redirect behavior in the effective config if HTTPS is expected.",
            file_path=path,
            context=context,
            line=line,
            block_type="server",
            server_name=server_name,
        )

    required_headers = {
        "x-frame-options": "nginx_x_frame_options_missing",
        "content-security-policy": "nginx_content_security_policy_missing",
        "x-content-type-options": "nginx_x_content_type_options_missing",
        "referrer-policy": "nginx_referrer_policy_missing",
    }
    missing = [(header, finding_id) for header, finding_id in required_headers.items() if header not in headers]
    for header, finding_id in missing:
        add_nginx_config_finding(
            analysis,
            finding_id,
            f"Nginx {header} header was not observed",
            nginx_contextual_level("low", context),
            nginx_contextual_confidence("low", context),
            "headers",
            "A common security header was not observed in the reviewed server block. Includes and inheritance are not resolved in v1.",
            f"server_name={server_name or 'unknown'}; missing={header}",
            "Review effective edge headers and add this header where appropriate.",
            file_path=path,
            context=context,
            line=line,
            block_type="server",
            server_name=server_name,
        )
    if missing:
        add_nginx_config_finding(
            analysis,
            "nginx_security_headers_missing",
            "Nginx common security headers are missing",
            nginx_contextual_level("low", context),
            nginx_contextual_confidence("low", context),
            "headers",
            "One or more common security headers were not observed in the reviewed server block.",
            f"server_name={server_name or 'unknown'}; missing_headers={','.join(header for header, _ in missing)}",
            "Review effective response headers for this virtual host.",
            file_path=path,
            context=context,
            line=line,
            block_type="server",
            server_name=server_name,
        )


def finalize_nginx_location_state(analysis: dict[str, Any], location: dict[str, Any]) -> None:
    if not location.get("proxy_pass"):
        return
    path = str(location.get("path") or "")
    context = str(location.get("context") or "ambiguous")
    line = int(location.get("line") or 0) or None
    headers = {str(header).lower() for header in location.get("proxy_headers", set())}
    checks = {
        "host": "nginx_proxy_set_header_host_missing",
        "x-forwarded-proto": "nginx_proxy_set_header_x_forwarded_proto_missing",
        "x-forwarded-for": "nginx_proxy_set_header_x_forwarded_for_missing",
    }
    for header, finding_id in checks.items():
        if header in headers:
            continue
        add_nginx_config_finding(
            analysis,
            finding_id,
            f"Nginx proxy header {header} was not observed",
            nginx_contextual_level("low", context),
            nginx_contextual_confidence("low", context),
            "proxy",
            "A proxy_pass location lacks an obvious forwarding header in the reviewed file.",
            f"location={location.get('location') or 'unknown'}; missing={header}",
            "Confirm upstream applications receive the intended proxy headers.",
            file_path=path,
            context=context,
            line=line,
            block_type="location",
            location=str(location.get("location") or ""),
            server_name=location.get("server_name"),
        )


def add_nginx_config_finding(
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
    block_type: str | None = None,
    server_name: str | None = None,
    location: str | None = None,
    upstream: str | None = None,
    directive: str | None = None,
    redacted: bool = False,
) -> None:
    safe_description, description_redactions = redact_nginx_secret_text(description)
    safe_evidence, evidence_redactions = redact_nginx_secret_text(evidence)
    safe_recommendation, recommendation_redactions = redact_nginx_secret_text(recommendation)
    redaction_count = description_redactions + evidence_redactions + recommendation_redactions
    if redacted and redaction_count == 0:
        redaction_count = 1
    analysis["summary"]["redacted_values_count"] += redaction_count

    finding = make_finding(finding_id, title, level, safe_description, safe_evidence, safe_recommendation)
    finding["confidence"] = confidence
    finding["category"] = category
    if file_path:
        finding["file_path"] = file_path
    if context:
        finding["context"] = context
    if line is not None:
        finding["line"] = line
    if block_type:
        finding["block_type"] = block_type
    if server_name:
        finding["server_name"] = server_name
    if location:
        finding["location"] = location
    if upstream:
        finding["upstream"] = upstream
    if directive:
        finding["directive"] = directive
    analysis["findings"].append(finding)


def compose_config_limits(request: ArchiveAnalysisRequest) -> dict[str, int]:
    max_files = COMPOSE_CONFIG_MAX_FILES if request.max_files is None else request.max_files
    max_file_bytes = COMPOSE_CONFIG_MAX_FILE_BYTES if request.max_file_bytes is None else request.max_file_bytes
    max_total_bytes = COMPOSE_CONFIG_MAX_TOTAL_BYTES if request.max_total_bytes is None else request.max_total_bytes
    if max_files <= 0 or max_file_bytes <= 0 or max_total_bytes <= 0:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Compose config analysis limits must be positive.")
    return {"max_files": max_files, "max_file_bytes": max_file_bytes, "max_total_bytes": max_total_bytes}


def analyze_compose_config_archive(
    path: Path,
    archive_type: str,
    *,
    max_files: int,
    max_file_bytes: int,
    max_total_bytes: int,
) -> dict[str, Any]:
    analysis = empty_compose_config_analysis()
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
            scoped["id"] = f"compose_config_{scoped['id']}"
            analysis["findings"].append(scoped)
            finalize_compose_config_analysis(analysis)
            return analysis
        with zipfile.ZipFile(path) as archive:
            for index, info in enumerate(archive.filelist, start=1):
                if should_stop_compose_config_archive_scan(index, analysis):
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
                process_compose_config_entry(
                    analysis,
                    state,
                    entry,
                    lambda entry_info=info: archive.open(entry_info),
                )
    else:
        with tarfile.open(path, "r:*") as archive:
            for index, member in enumerate(archive, start=1):
                if should_stop_compose_config_archive_scan(index, analysis):
                    break
                entry = {
                    "path": member.name,
                    "type": tar_member_type(member),
                    "size": member.size,
                    "mode_int": member.mode,
                    "mode": format_file_mode(member.mode),
                    "link_target": member.linkname or None,
                }
                process_compose_config_entry(
                    analysis,
                    state,
                    entry,
                    lambda tar_member=member: archive.extractfile(tar_member),
                )

    finalize_compose_config_analysis(analysis)
    return analysis


def empty_compose_config_analysis(errors: list[str] | None = None) -> dict[str, Any]:
    return {
        "summary": {
            "files_considered": 0,
            "files_reviewed": 0,
            "compose_files_detected": 0,
            "services_detected": 0,
            "networks_detected": 0,
            "volumes_detected": 0,
            "secrets_detected": 0,
            "published_ports_detected": 0,
            "env_files_detected": 0,
            "findings_count": 0,
            "redacted_values_count": 0,
            "truncated": False,
        },
        "files_detected": [],
        "files_reviewed": [],
        "services": [],
        "ports": [],
        "volumes": [],
        "networks": [],
        "secrets": [],
        "env_files": [],
        "build_contexts": [],
        "images": [],
        "findings": [],
        "redaction_notes": [],
        "errors": errors or [],
        "_compose_file_count": 0,
        "_compose_contexts": [],
        "_override_paths": [],
        "_profiles": [],
    }


def build_compose_config_result(
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
        "analyzer": "compose_config_basic",
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
        "services": analysis.get("services", []),
        "ports": analysis.get("ports", []),
        "volumes": analysis.get("volumes", []),
        "networks": analysis.get("networks", []),
        "secrets": analysis.get("secrets", []),
        "env_files": analysis.get("env_files", []),
        "build_contexts": analysis.get("build_contexts", []),
        "images": analysis.get("images", []),
        "findings": findings,
        "redaction_notes": analysis.get("redaction_notes", []),
        "errors": analysis.get("errors", []),
        "truncated": bool(summary.get("truncated")),
    }


def should_stop_compose_config_archive_scan(index: int, analysis: dict[str, Any]) -> bool:
    if index > ARCHIVE_MAX_ENTRIES:
        analysis["summary"]["truncated"] = True
        add_compose_config_finding(
            analysis,
            "compose_config_entry_limit_reached",
            "Archive entry scan limit reached",
            "medium",
            "high",
            "limit",
            "Inspectra stopped scanning archive metadata after the configured entry limit.",
            f"Processed {ARCHIVE_MAX_ENTRIES} entries.",
            "Review the archive with stricter limits or split it before deeper inspection.",
        )
        return True
    return False


def process_compose_config_entry(
    analysis: dict[str, Any],
    state: dict[str, int],
    entry: dict[str, Any],
    open_entry,
) -> None:
    path = str(entry["path"])
    category = classify_compose_config_candidate(path)
    if category is None:
        return

    summary = as_dict(analysis["summary"])
    summary["files_considered"] += 1
    if category == "compose":
        summary["compose_files_detected"] += 1
        analysis["_compose_file_count"] += 1

    entry_type = str(entry["type"])
    size_bytes = int(entry.get("size") or 0)
    context = compose_config_file_context(path, category)
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

    skip_reason = compose_config_skip_reason(record, state)
    if skip_reason:
        record["skip_reason"] = skip_reason
        analysis["files_detected"].append(record)
        if skip_reason == "real_env_file_not_read":
            add_compose_env_file_sensitive(analysis, record)
        else:
            add_compose_config_skip_finding(analysis, path, skip_reason, size_bytes, context)
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
        safe_error, redactions = redact_compose_secret_text(str(exc))
        analysis["summary"]["redacted_values_count"] += redactions
        add_compose_config_finding(
            analysis,
            "compose_config_file_read_error",
            "Compose config candidate could not be read safely",
            "low",
            "medium",
            "archive",
            "A Compose-related candidate file could not be read from the archive within Inspectra limits.",
            f"{path}: {safe_error}",
            "Review this file manually in a constrained environment if it is expected.",
            file_path=path,
            context=context,
        )
        return

    state["total_bytes_read"] += len(raw_bytes)
    if b"\x00" in raw_bytes:
        record["skip_reason"] = "binary_or_non_text"
        analysis["files_detected"].append(record)
        add_compose_config_skip_finding(analysis, path, "binary_or_non_text", size_bytes, context)
        return

    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        record["skip_reason"] = "binary_or_non_text"
        analysis["files_detected"].append(record)
        add_compose_config_skip_finding(analysis, path, "binary_or_non_text", size_bytes, context)
        return

    state["files_read"] += 1
    summary["files_reviewed"] = state["files_read"]
    record["read"] = True
    record["bytes_read"] = len(raw_bytes)
    analysis["files_detected"].append(record)
    analysis["files_reviewed"].append(
        {"path": path, "category": category, "context": context, "size_bytes": size_bytes, "bytes_read": len(raw_bytes)}
    )
    analysis["_compose_contexts"].append(context)
    if is_compose_override_path(path):
        analysis["_override_paths"].append(path)
    analyze_compose_config_text(analysis, path, category, context, text)


def classify_compose_config_candidate(path: str) -> str | None:
    normalized = normalize_archive_entry_path(path)
    lower = normalized.lower()
    basename = lower.rsplit("/", 1)[-1]
    parts = [part for part in lower.split("/") if part]
    if is_compose_sensitive_env_name(basename):
        return "env_sensitive"
    if is_compose_filename(basename):
        return "compose"
    if basename.endswith((".yml", ".yaml")):
        parent = parts[-2] if len(parts) >= 2 else ""
        grandparent = parts[-3] if len(parts) >= 3 else ""
        if parent == "stacks":
            return "compose"
        if parent == "compose" and grandparent in {"deploy", "docker", "infra"}:
            return "compose"
    return None


def is_compose_filename(basename: str) -> bool:
    if basename in {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}:
        return True
    return bool(re.match(r"^(?:docker-)?compose\.[a-z0-9_.-]+\.(?:ya?ml)$", basename))


def is_compose_sensitive_env_name(basename: str) -> bool:
    return basename == ".env" or basename == ".envrc" or basename.startswith(".env.")


def compose_config_skip_reason(record: dict[str, Any], state: dict[str, int]) -> str | None:
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


def add_compose_config_skip_finding(analysis: dict[str, Any], path: str, reason: str, size_bytes: int, context: str) -> None:
    if reason in {"file_too_large", "too_many_files", "total_bytes_limit"}:
        analysis["summary"]["truncated"] = True
    titles = {
        "path_traversal": "Compose config path uses traversal",
        "absolute_path": "Compose config path is absolute",
        "entry_name_too_long": "Compose config entry name is unusually long",
        "file_too_large": "Compose config file omitted because it exceeds the size limit",
        "too_many_files": "Compose config file limit reached",
        "total_bytes_limit": "Total Compose config byte limit reached",
        "binary_or_non_text": "Compose config candidate is not UTF-8 text",
    }
    level = "medium" if reason in {"path_traversal", "absolute_path", "file_too_large", "too_many_files", "total_bytes_limit"} else "low"
    if reason == "binary_or_non_text":
        level = "info"
    evidence = f"{path}: {size_bytes} bytes" if reason == "file_too_large" else path[:240]
    if reason.startswith("not_regular_file"):
        title = "Compose config candidate omitted because it is not a regular file"
        evidence = f"{path}: {reason}"
        level = "low"
    else:
        title = titles.get(reason, "Compose config candidate skipped by defensive limit")
    add_compose_config_finding(
        analysis,
        f"compose_config_{reason.split(':', 1)[0]}",
        title,
        compose_contextual_level(level, context),
        compose_contextual_confidence("high" if reason in {"path_traversal", "absolute_path"} else "medium", context),
        "archive",
        "Inspectra detected a Compose-related file but did not read it because of a defensive limit, unsupported format, or unsafe archive metadata.",
        evidence,
        "Review the archive manually in a constrained environment if this file is expected.",
        file_path=path,
        context=context,
    )


def add_compose_env_file_sensitive(analysis: dict[str, Any], record: dict[str, Any]) -> None:
    env_file = {
        "path": record["path"],
        "context": record.get("context"),
        "source": "archive",
        "read": False,
        "skip_reason": "real_env_file_not_read",
        "size_bytes": record.get("size_bytes"),
    }
    analysis["env_files"].append(env_file)
    add_compose_config_finding(
        analysis,
        "compose_env_file_sensitive_present",
        "Real Compose environment file detected but not read",
        compose_contextual_level("low", str(record.get("context") or "")),
        "high",
        "secrets",
        "A .env-style file was present in the archive. Inspectra records its presence but does not read or store its content.",
        str(record["path"])[:240],
        "Keep real env files out of shared archives and use sample files for review packages.",
        file_path=str(record["path"]),
        context=str(record.get("context") or ""),
    )


LOWER_CONFIDENCE_COMPOSE_CONTEXTS = {"development", "test", "local", "example"}
COMPOSE_SECRET_KEY_RE = re.compile(
    r"(?i)(secret|token|api[_-]?key|apikey|password|passwd|client[_-]?secret|private[_-]?key|credential|database_url|redis_url|auth)"
)
COMPOSE_CREDENTIAL_URL_RE = re.compile(r"(?i)\b(?:[a-z][a-z0-9+.-]*://)[^\s'\"<>/@:]*:[^\s'\"<>/@]+@[^\s'\"<>]+")
COMPOSE_DB_PORTS = {5432, 3306, 33060, 6379, 27017, 27018, 27019, 11211, 9200, 9300, 1433, 1521, 9042}
COMPOSE_ADMIN_PORTS = {3000, 5601, 8000, 8001, 8080, 8081, 8088, 9000, 9090, 9091, 15672}
COMPOSE_SENSITIVE_PORTS = {22, 2375, 2376, 3389, 5000, 6443, 8200, 9200, 9300}
COMPOSE_SENSITIVE_HOST_PATHS = (
    "/etc",
    "/root",
    "/root/.ssh",
    "/home",
    "/var/lib/docker",
    "/var/run",
    "/run/docker.sock",
    "/var/run/docker.sock",
)


@dataclass
class ComposeYamlLine:
    number: int
    indent: int
    text: str


def compose_config_file_context(path: str, category: str = "") -> str:
    normalized = normalize_archive_entry_path(path).lower()
    parts = [part for part in normalized.split("/") if part]
    basename = parts[-1] if parts else normalized
    directories = set(parts[:-1])
    name_tokens = set(re.split(r"[^a-z0-9]+", basename))
    all_tokens = set(parts[:-1]) | name_tokens

    if directories.intersection({"docs", "doc", "examples", "example", "samples", "sample"}) or all_tokens.intersection(
        {"example", "examples", "sample", "samples", "template", "templates", "sandbox"}
    ):
        return "example"
    if all_tokens.intersection({"test", "tests", "testing"}):
        return "test"
    if all_tokens.intersection({"dev", "development"}):
        return "development"
    if "local" in all_tokens or "override" in name_tokens:
        return "local"
    if all_tokens.intersection({"prod", "production", "live", "deploy", "release", "stacks", "server", "vps"}) or directories.intersection(
        {"deploy", "stacks"}
    ):
        return "production"
    if basename in {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}:
        return "shared"
    if category == "env_sensitive":
        return "ambiguous"
    return "ambiguous"


def compose_contextual_level(level: str, context: str) -> str:
    if context not in LOWER_CONFIDENCE_COMPOSE_CONTEXTS:
        return level
    if level == "medium":
        return "low"
    if level == "low":
        return "info"
    return level


def compose_contextual_confidence(confidence: str, context: str) -> str:
    if context not in LOWER_CONFIDENCE_COMPOSE_CONTEXTS:
        return confidence
    if confidence == "high":
        return "medium"
    if confidence == "medium":
        return "low"
    return confidence


def is_compose_override_path(path: str) -> bool:
    basename = normalize_archive_entry_path(path).lower().rsplit("/", 1)[-1]
    return "override" in set(re.split(r"[^a-z0-9]+", basename))


def strip_compose_comment(line: str) -> str:
    quote: str | None = None
    escaped = False
    result: list[str] = []
    for char in line:
        if escaped:
            result.append(char)
            escaped = False
            continue
        if char == "\\":
            result.append(char)
            escaped = True
            continue
        if quote:
            if char == quote:
                quote = None
            result.append(char)
            continue
        if char in {"'", '"'}:
            quote = char
            result.append(char)
            continue
        if char == "#":
            break
        result.append(char)
    return "".join(result).rstrip()


def active_compose_lines(text: str) -> list[ComposeYamlLine]:
    active: list[ComposeYamlLine] = []
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        cleaned = strip_compose_comment(raw_line)
        if not cleaned.strip() or cleaned.lstrip() == "---":
            continue
        indent = len(cleaned) - len(cleaned.lstrip(" "))
        active.append(ComposeYamlLine(line_number, indent, cleaned.strip()))
    return active


def compose_key_value(text: str) -> tuple[str, str] | None:
    if text.startswith("-"):
        return None
    match = re.match(r"['\"]?([A-Za-z0-9_.-]+)['\"]?\s*:\s*(.*)$", text)
    if not match:
        return None
    return match.group(1), match.group(2).strip()


def compose_section(lines: list[ComposeYamlLine], section: str) -> tuple[ComposeYamlLine, list[ComposeYamlLine]] | None:
    for index, line in enumerate(lines):
        key_value = compose_key_value(line.text)
        if not key_value or line.indent != 0 or key_value[0] != section:
            continue
        nested: list[ComposeYamlLine] = []
        for next_line in lines[index + 1 :]:
            if next_line.indent <= line.indent:
                break
            nested.append(next_line)
        return line, nested
    return None


def compose_child_blocks(lines: list[ComposeYamlLine], parent_indent: int) -> list[dict[str, Any]]:
    direct_candidates = [line for line in lines if line.indent > parent_indent and not line.text.startswith("-") and compose_key_value(line.text)]
    if not direct_candidates:
        return []
    direct_indent = min(line.indent for line in direct_candidates)
    direct_indices = [index for index, line in enumerate(lines) if line.indent == direct_indent and not line.text.startswith("-") and compose_key_value(line.text)]
    blocks: list[dict[str, Any]] = []
    for ordinal, index in enumerate(direct_indices):
        line = lines[index]
        key, value = compose_key_value(line.text) or ("", "")
        next_index = direct_indices[ordinal + 1] if ordinal + 1 < len(direct_indices) else len(lines)
        nested = [nested_line for nested_line in lines[index + 1 : next_index] if nested_line.indent > line.indent]
        blocks.append({"key": key, "value": value, "line": line.number, "indent": line.indent, "lines": nested})
    return blocks


def compose_direct_fields(lines: list[ComposeYamlLine], parent_indent: int) -> list[dict[str, Any]]:
    return compose_child_blocks(lines, parent_indent)


def compose_find_field(fields: list[dict[str, Any]], key: str) -> dict[str, Any] | None:
    for field in fields:
        if field.get("key") == key:
            return field
    return None


def compose_unquote(value: str) -> str:
    stripped = value.strip().strip(",")
    if len(stripped) >= 2 and stripped[0] == stripped[-1] and stripped[0] in {"'", '"'}:
        return stripped[1:-1]
    return stripped


def compose_split_inline_items(value: str) -> list[str]:
    stripped = value.strip()
    if not (stripped.startswith("[") and stripped.endswith("]")):
        return []
    inner = stripped[1:-1]
    items: list[str] = []
    current: list[str] = []
    quote: str | None = None
    escaped = False
    for char in inner:
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == "\\":
            current.append(char)
            escaped = True
            continue
        if quote:
            if char == quote:
                quote = None
            current.append(char)
            continue
        if char in {"'", '"'}:
            quote = char
            current.append(char)
            continue
        if char == ",":
            item = "".join(current).strip()
            if item:
                items.append(compose_unquote(item))
            current = []
            continue
        current.append(char)
    item = "".join(current).strip()
    if item:
        items.append(compose_unquote(item))
    return items


def compose_inline_map(value: str) -> dict[str, str]:
    stripped = value.strip()
    if not (stripped.startswith("{") and stripped.endswith("}")):
        return {}
    mapping: dict[str, str] = {}
    for item in compose_split_inline_items(f"[{stripped[1:-1]}]"):
        separator = ":" if ":" in item else "=" if "=" in item else None
        if not separator:
            continue
        key, raw_value = [part.strip() for part in item.split(separator, 1)]
        mapping[compose_unquote(key)] = compose_unquote(raw_value)
    return mapping


def compose_sequence_blocks(lines: list[ComposeYamlLine]) -> list[dict[str, Any]]:
    blocks: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    current_indent = 0
    for line in lines:
        if line.text.startswith("-"):
            if current is not None:
                blocks.append(current)
            current_indent = line.indent
            current = {"line": line.number, "indent": current_indent, "value": line.text[1:].strip(), "lines": []}
            continue
        if current is not None and line.indent > current_indent:
            current["lines"].append(line)
    if current is not None:
        blocks.append(current)
    return blocks


def compose_sequence_value_is_mapping(value: str) -> bool:
    stripped = value.strip()
    if not stripped or stripped[0] in {"'", '"'}:
        return False
    return compose_key_value(stripped) is not None


def compose_mapping_from_sequence_block(block: dict[str, Any]) -> dict[str, str]:
    mapping: dict[str, str] = {}
    value = str(block.get("value") or "").strip()
    key_value = compose_key_value(value) if compose_sequence_value_is_mapping(value) else None
    if key_value:
        mapping[key_value[0]] = compose_unquote(key_value[1])
    for line in block.get("lines", []):
        if not isinstance(line, ComposeYamlLine):
            continue
        nested_key_value = compose_key_value(line.text)
        if nested_key_value:
            mapping[nested_key_value[0]] = compose_unquote(nested_key_value[1])
    return mapping


def compose_field_scalar_values(field: dict[str, Any] | None) -> list[tuple[int, str]]:
    if not field:
        return []
    values: list[tuple[int, str]] = []
    value = str(field.get("value") or "").strip()
    if value:
        inline_items = compose_split_inline_items(value)
        if inline_items:
            values.extend((int(field.get("line") or 0), item) for item in inline_items)
        elif value not in {"[]", "{}"}:
            values.append((int(field.get("line") or 0), compose_unquote(value)))
    for block in compose_sequence_blocks(field.get("lines", [])):
        item = str(block.get("value") or "").strip()
        if item and not compose_sequence_value_is_mapping(item):
            values.append((int(block.get("line") or 0), compose_unquote(item)))
    return values


def compose_bool(value: str | None) -> bool | None:
    if value is None:
        return None
    normalized = compose_unquote(value).strip().lower()
    if normalized in {"true", "yes", "on", "1"}:
        return True
    if normalized in {"false", "no", "off", "0"}:
        return False
    return None


def redact_compose_secret_text(text: str | None) -> tuple[str, int]:
    if text is None:
        return "", 0
    redacted, count = redact_nginx_secret_text(str(text))

    def apply(pattern: str, replacement: str, flags: int = re.IGNORECASE) -> None:
        nonlocal redacted, count
        redacted, replacements = re.subn(pattern, replacement, redacted, flags=flags)
        count += replacements

    apply(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----", "[REDACTED]", re.IGNORECASE)
    apply(r"\b([a-z][a-z0-9+.-]*://)([^/\s:@;\"']*):([^@\s/;\"']+)@([^\s;\"']+)", r"\1[REDACTED]@\4")
    apply(
        r"(\b[A-Z0-9_.-]*(?:SECRET|TOKEN|PASSWORD|PASS|API_KEY|APIKEY|CLIENT_SECRET|PRIVATE_KEY|DATABASE_URL|REDIS_URL|CREDENTIAL)[A-Z0-9_.-]*\b\s*[:=]\s*)(['\"]?)[^\s,'\"}\]]+",
        r"\1\2[REDACTED]",
    )
    redacted = redacted.replace("[REDACTED PRIVATE KEY]", "[REDACTED]").replace("PRIVATE_KEY_BLOCK_REDACTED", "[REDACTED]")
    return redacted, count


def compose_safe_value(value: str | None) -> str:
    safe, _ = redact_compose_secret_text(value or "")
    return safe


def compose_secret_value(value: str) -> bool:
    if not value:
        return False
    stripped = compose_unquote(value).strip()
    if not stripped or re.fullmatch(r"\$\{[^}]+\}", stripped):
        return False
    if COMPOSE_CREDENTIAL_URL_RE.search(stripped) or PRIVATE_KEY_BLOCK_RE.search(stripped):
        return True
    return not is_placeholder_secret_value(stripped)


def analyze_compose_config_text(analysis: dict[str, Any], path: str, category: str, context: str, text: str) -> None:
    active_lines = active_compose_lines(text)
    active_text = "\n".join(line.text for line in active_lines)
    if any(raw_line.startswith("\t") for raw_line in text.splitlines()):
        analysis["errors"].append(f"{path}: tab indentation observed; Compose parsing is best-effort.")
        add_compose_config_finding(
            analysis,
            "compose_unsupported_or_malformed_yaml",
            "Compose YAML has unsupported or malformed-looking indentation",
            "info",
            "medium",
            "structure",
            "A Compose candidate contains tab indentation. Inspectra did not run docker compose config.",
            f"{path}: tab indentation",
            "Validate the file in a controlled workflow before relying on this static review.",
            file_path=path,
            context=context,
        )
    if PRIVATE_KEY_BLOCK_RE.search(active_text):
        add_compose_config_finding(
            analysis,
            "compose_plaintext_private_key_hint",
            "Compose file contains private key-like material",
            compose_contextual_level("medium", context),
            compose_contextual_confidence("high", context),
            "secrets",
            "Private key-like material appeared in a Compose candidate. Inspectra redacted the value.",
            "private_key=[REDACTED]",
            "Do not commit private key material in Compose configuration archives.",
            file_path=path,
            context=context,
            redacted=True,
        )
    for match in COMPOSE_CREDENTIAL_URL_RE.finditer(active_text):
        safe_url, redactions = redact_compose_secret_text(match.group(0))
        analysis["summary"]["redacted_values_count"] += redactions
        add_compose_config_finding(
            analysis,
            "compose_credential_url_hint",
            "Compose file contains a credential-bearing URL",
            compose_contextual_level("medium", context),
            compose_contextual_confidence("high", context),
            "secrets",
            "A URL with embedded credentials was observed in Compose text. Inspectra redacted the credential material.",
            f"url={safe_url}",
            "Move credentials out of URLs and rotate them if this archive was shared outside trusted storage.",
            file_path=path,
            context=context,
            redacted=True,
        )

    services_section = compose_section(active_lines, "services")
    if not services_section:
        analysis["errors"].append(f"{path}: services section was not observed; Compose parsing is best-effort.")
        add_compose_config_finding(
            analysis,
            "compose_unsupported_or_malformed_yaml",
            "Compose services section was not observed",
            "info",
            "low",
            "structure",
            "A Compose candidate did not include an obvious top-level services section.",
            f"{path}: services missing",
            "Confirm this is a Compose file or review it manually.",
            file_path=path,
            context=context,
        )
    else:
        _section_line, service_lines = services_section
        for service_block in compose_child_blocks(service_lines, 0):
            analyze_compose_service(analysis, path, context, service_block)

    analyze_compose_top_level_networks(analysis, path, context, active_lines)
    analyze_compose_top_level_volumes(analysis, path, context, active_lines)
    analyze_compose_top_level_secrets(analysis, path, context, active_lines)
    if compose_section(active_lines, "profiles"):
        analysis["_profiles"].append(path)


def analyze_compose_service(analysis: dict[str, Any], path: str, context: str, service_block: dict[str, Any]) -> None:
    service = str(service_block.get("key") or "unknown")
    fields = compose_direct_fields(service_block.get("lines", []), int(service_block.get("indent") or 0))
    field_names = {str(field.get("key")) for field in fields}
    service_record = {
        "path": path,
        "context": context,
        "line": service_block.get("line"),
        "name": service,
        "image": None,
        "build": None,
        "ports_count": 0,
        "env_files_count": 0,
    }
    analysis["services"].append(service_record)

    image_field = compose_find_field(fields, "image")
    if image_field and str(image_field.get("value") or "").strip():
        image = compose_unquote(str(image_field.get("value")))
        safe_image = compose_safe_value(image)
        service_record["image"] = safe_image
        image_record = {"path": path, "context": context, "service": service, "image": safe_image, "line": image_field.get("line")}
        analysis["images"].append(image_record)
        analyze_compose_image(analysis, path, context, service, image, int(image_field.get("line") or 0))

    build_field = compose_find_field(fields, "build")
    if build_field:
        analyze_compose_build(analysis, path, context, service, build_field)

    analyze_compose_environment(analysis, path, context, service, compose_find_field(fields, "environment"))
    env_count = analyze_compose_env_file(analysis, path, context, service, compose_find_field(fields, "env_file"))
    service_record["env_files_count"] = env_count
    analyze_compose_service_secrets(analysis, path, context, service, compose_find_field(fields, "secrets"))
    ports_count = analyze_compose_ports(analysis, path, context, service, compose_find_field(fields, "ports"))
    service_record["ports_count"] = ports_count
    analyze_compose_volumes(analysis, path, context, service, compose_find_field(fields, "volumes"))
    analyze_compose_service_networks(analysis, path, context, service, fields)

    if compose_bool(str((compose_find_field(fields, "privileged") or {}).get("value") or "")):
        add_compose_service_finding(analysis, "compose_privileged_true", "Compose service is privileged", "medium", "hardening", path, context, service, "privileged", line=(compose_find_field(fields, "privileged") or {}).get("line"))
    if compose_find_field(fields, "cap_add"):
        add_compose_service_finding(analysis, "compose_cap_add_present", "Compose service adds Linux capabilities", "medium", "hardening", path, context, service, "cap_add", line=compose_find_field(fields, "cap_add").get("line"))
    security_opt = compose_find_field(fields, "security_opt")
    security_opt_text = ""
    if security_opt:
        security_opt_text = "\n".join([str(security_opt.get("value") or ""), *(line.text for line in security_opt.get("lines", []) if isinstance(line, ComposeYamlLine))])
    if security_opt and re.search(r"(?i)(unconfined|seccomp\s*:\s*unconfined|apparmor\s*:\s*unconfined|no-new-privileges\s*:\s*false)", security_opt_text):
        add_compose_service_finding(analysis, "compose_security_opt_disabled_hint", "Compose service disables a security option", "medium", "hardening", path, context, service, "security_opt", line=security_opt.get("line"))
    network_mode = compose_find_field(fields, "network_mode")
    if network_mode and compose_unquote(str(network_mode.get("value") or "")).lower() == "host":
        add_compose_service_finding(analysis, "compose_host_network_mode", "Compose service uses host networking", "medium", "network", path, context, service, "network_mode", line=network_mode.get("line"))
    pid_field = compose_find_field(fields, "pid")
    if pid_field and compose_unquote(str(pid_field.get("value") or "")).lower() == "host":
        add_compose_service_finding(analysis, "compose_pid_host", "Compose service uses host PID namespace", "medium", "hardening", path, context, service, "pid", line=pid_field.get("line"))
    ipc_field = compose_find_field(fields, "ipc")
    if ipc_field and compose_unquote(str(ipc_field.get("value") or "")).lower() == "host":
        add_compose_service_finding(analysis, "compose_ipc_host", "Compose service uses host IPC namespace", "medium", "hardening", path, context, service, "ipc", line=ipc_field.get("line"))
    user_field = compose_find_field(fields, "user")
    if not user_field or compose_unquote(str(user_field.get("value") or "")).lower() in {"", "0", "root", "0:0", "root:root"}:
        add_compose_service_finding(analysis, "compose_user_root_or_missing", "Compose service user is root or missing", "low", "hardening", path, context, service, "user", line=(user_field or {}).get("line"))
    read_only_field = compose_find_field(fields, "read_only")
    if not read_only_field or compose_bool(str(read_only_field.get("value") or "")) is not True:
        add_compose_service_finding(analysis, "compose_read_only_missing", "Compose service read_only was not observed", "low", "hardening", path, context, service, "read_only", line=(read_only_field or {}).get("line"))
    if "healthcheck" not in field_names:
        add_compose_service_finding(analysis, "compose_healthcheck_missing", "Compose service healthcheck was not observed", "low", "reliability", path, context, service, "healthcheck")
    restart_field = compose_find_field(fields, "restart")
    if not restart_field:
        add_compose_service_finding(analysis, "compose_restart_policy_missing", "Compose service restart policy was not observed", "low", "reliability", path, context, service, "restart")
    elif compose_unquote(str(restart_field.get("value") or "")).lower() == "always":
        add_compose_service_finding(analysis, "compose_restart_always_hint", "Compose service uses restart always", "low", "reliability", path, context, service, "restart", line=restart_field.get("line"))
    depends_on = compose_find_field(fields, "depends_on")
    if depends_on and "condition: service_healthy" not in "\n".join(line.text for line in depends_on.get("lines", [])):
        add_compose_service_finding(analysis, "compose_depends_on_without_health_condition", "Compose depends_on lacks an obvious health condition", "low", "reliability", path, context, service, "depends_on", line=depends_on.get("line"))
    if not compose_service_has_resource_limits(fields):
        add_compose_service_finding(analysis, "compose_resource_limits_missing", "Compose service resource limits were not observed", "low", "resources", path, context, service, "deploy.resources.limits")
    if compose_find_field(fields, "links"):
        add_compose_service_finding(analysis, "compose_links_legacy_present", "Compose service uses legacy links", "low", "network", path, context, service, "links", line=compose_find_field(fields, "links").get("line"))
    if compose_find_field(fields, "profiles"):
        analysis["_profiles"].append(path)


def compose_service_has_resource_limits(fields: list[dict[str, Any]]) -> bool:
    if compose_find_field(fields, "mem_limit") or compose_find_field(fields, "cpus"):
        return True
    deploy = compose_find_field(fields, "deploy")
    if not deploy:
        return False
    nested = "\n".join(line.text for line in deploy.get("lines", []))
    return "resources:" in nested and "limits:" in nested


def analyze_compose_environment(
    analysis: dict[str, Any],
    path: str,
    context: str,
    service: str,
    field: dict[str, Any] | None,
) -> None:
    if not field:
        return
    pairs: list[tuple[int, str, str]] = []
    value = str(field.get("value") or "").strip()
    for key, item_value in compose_inline_map(value).items():
        pairs.append((int(field.get("line") or 0), key, item_value))
    for line_number, item in compose_field_scalar_values(field):
        if "=" in item:
            key, item_value = item.split("=", 1)
            pairs.append((line_number, key.strip(), item_value.strip()))
    for nested_line in field.get("lines", []):
        if not isinstance(nested_line, ComposeYamlLine) or nested_line.text.startswith("-"):
            continue
        key_value = compose_key_value(nested_line.text)
        if key_value:
            pairs.append((nested_line.number, key_value[0], compose_unquote(key_value[1])))

    for line_number, key, raw_value in pairs:
        key = compose_unquote(key)
        raw_value = compose_unquote(raw_value)
        key_is_secret = bool(COMPOSE_SECRET_KEY_RE.search(key))
        value_is_secret = bool(COMPOSE_CREDENTIAL_URL_RE.search(raw_value) or PRIVATE_KEY_BLOCK_RE.search(raw_value))
        if key_is_secret:
            add_compose_config_finding(
                analysis,
                "compose_environment_secret_like_key",
                "Compose environment contains a secret-like key",
                compose_contextual_level("low", context),
                compose_contextual_confidence("medium", context),
                "secrets",
                "A Compose environment key appears secret-like. Inspectra records only the key name and redacts values.",
                f"service={service}; env key={key}",
                "Prefer runtime secret injection or env files kept outside shared archives.",
                file_path=path,
                context=context,
                line=line_number,
                service=service,
                field_path=f"environment.{key}",
            )
        if (key_is_secret and compose_secret_value(raw_value)) or value_is_secret:
            add_compose_config_finding(
                analysis,
                "compose_environment_secret_like_value",
                "Compose environment contains a secret-like inline value",
                compose_contextual_level("medium", context),
                compose_contextual_confidence("medium", context),
                "secrets",
                "A Compose environment value appears secret-like. Inspectra redacted the value and did not validate it.",
                f"service={service}; env {key}=[REDACTED]",
                "Move real secret values to an approved runtime secret mechanism and rotate if this archive was shared outside trusted storage.",
                file_path=path,
                context=context,
                line=line_number,
                service=service,
                field_path=f"environment.{key}",
                redacted=True,
            )


def analyze_compose_env_file(
    analysis: dict[str, Any],
    path: str,
    context: str,
    service: str,
    field: dict[str, Any] | None,
) -> int:
    if not field:
        return 0
    count = 0
    for line_number, reference in compose_field_scalar_values(field):
        safe_reference = compose_safe_value(reference)
        env_file = {
            "path": safe_reference,
            "source": "env_file_reference",
            "service": service,
            "file_path": path,
            "context": context,
            "line": line_number,
            "read": False,
            "resolved": False,
        }
        analysis["env_files"].append(env_file)
        count += 1
        add_compose_config_finding(
            analysis,
            "compose_env_file_reference",
            "Compose service references an env_file",
            compose_contextual_level("low", context),
            compose_contextual_confidence("high", context),
            "secrets",
            "An env_file reference was observed. Inspectra records the reference but does not resolve or read it.",
            f"service={service}; env_file={safe_reference}",
            "Keep real env files out of shared archives and review runtime secret injection separately.",
            file_path=path,
            context=context,
            line=line_number,
            service=service,
            field_path="env_file",
        )
        if is_compose_sensitive_env_name(safe_reference.rsplit("/", 1)[-1].lower()):
            add_compose_config_finding(
                analysis,
                "compose_env_file_sensitive_present",
                "Compose env_file references a real env-style file",
                compose_contextual_level("low", context),
                compose_contextual_confidence("high", context),
                "secrets",
                "A Compose env_file reference points at a .env-style file. Inspectra does not read referenced env files.",
                f"service={service}; env_file={safe_reference}",
                "Avoid committing real env files and provide safe examples for review archives.",
                file_path=path,
                context=context,
                line=line_number,
                service=service,
                field_path="env_file",
            )
    return count


def analyze_compose_service_secrets(
    analysis: dict[str, Any],
    path: str,
    context: str,
    service: str,
    field: dict[str, Any] | None,
) -> None:
    if not field:
        return
    for line_number, secret_name in compose_field_scalar_values(field):
        analysis["secrets"].append(
            {"path": path, "context": context, "service": service, "name": compose_safe_value(secret_name), "source": "service_reference", "line": line_number, "read": False}
        )
        add_compose_config_finding(
            analysis,
            "compose_secrets_defined",
            "Compose service references a secret",
            "info",
            compose_contextual_confidence("medium", context),
            "secrets",
            "A Compose secret reference was observed. Inspectra does not read secret file contents.",
            f"service={service}; secret={compose_safe_value(secret_name)}",
            "Confirm secret source files are not included with real values in shared archives.",
            file_path=path,
            context=context,
            line=line_number,
            service=service,
            field_path="secrets",
        )
    for block in compose_sequence_blocks(field.get("lines", [])):
        mapping = compose_mapping_from_sequence_block(block)
        secret_name = mapping.get("source") or mapping.get("target")
        if secret_name:
            analysis["secrets"].append(
                {"path": path, "context": context, "service": service, "name": compose_safe_value(secret_name), "source": "service_reference", "line": block.get("line"), "read": False}
            )


def analyze_compose_ports(
    analysis: dict[str, Any],
    path: str,
    context: str,
    service: str,
    field: dict[str, Any] | None,
) -> int:
    if not field:
        return 0
    count = 0
    for line_number, port_value in compose_field_scalar_values(field):
        port = parse_compose_port(port_value)
        if not port:
            continue
        port["path"] = path
        port["context"] = context
        port["service"] = service
        port["line"] = line_number
        analysis["ports"].append(port)
        count += 1
        analyze_compose_port_findings(analysis, path, context, service, port, line_number)
    for block in compose_sequence_blocks(field.get("lines", [])):
        mapping = compose_mapping_from_sequence_block(block)
        if not mapping:
            continue
        port = parse_compose_port_mapping(mapping)
        if not port:
            continue
        port["path"] = path
        port["context"] = context
        port["service"] = service
        port["line"] = block.get("line")
        analysis["ports"].append(port)
        count += 1
        analyze_compose_port_findings(analysis, path, context, service, port, int(block.get("line") or 0))
    return count


def parse_compose_port(value: str) -> dict[str, Any] | None:
    raw = compose_unquote(value)
    if not raw:
        return None
    protocol = "tcp"
    if "/" in raw:
        raw, protocol = raw.rsplit("/", 1)
    host_ip: str | None = None
    published: str | None = None
    target: str | None = None
    if raw.startswith("[") and "]:" in raw:
        host_ip, remainder = raw.split("]:", 1)
        host_ip = host_ip.strip("[]")
        parts = remainder.split(":")
    else:
        parts = raw.split(":")
    if len(parts) >= 3:
        host_ip = host_ip or parts[0]
        published = parts[-2]
        target = parts[-1]
    elif len(parts) == 2:
        published, target = parts
    elif len(parts) == 1:
        target = parts[0]
    if not target:
        return None
    return {"host_ip": host_ip, "published": published, "target": target, "protocol": protocol, "raw": compose_safe_value(value)}


def parse_compose_port_mapping(mapping: dict[str, str]) -> dict[str, Any] | None:
    target = mapping.get("target")
    if not target:
        return None
    return {
        "host_ip": mapping.get("host_ip") or mapping.get("host_ip".replace("_", "-")),
        "published": mapping.get("published"),
        "target": target,
        "protocol": mapping.get("protocol") or "tcp",
        "raw": "mapping",
    }


def compose_port_numbers(value: str | None) -> set[int]:
    if not value:
        return set()
    numbers: set[int] = set()
    for match in re.finditer(r"\d+", str(value)):
        try:
            numbers.add(int(match.group(0)))
        except ValueError:
            continue
    return numbers


def analyze_compose_port_findings(
    analysis: dict[str, Any],
    path: str,
    context: str,
    service: str,
    port: dict[str, Any],
    line: int,
) -> None:
    host_ip = port.get("host_ip")
    published = str(port.get("published") or "")
    target = str(port.get("target") or "")
    protocol = str(port.get("protocol") or "tcp")
    port_label = f"{published}:{target}" if published else target
    all_interfaces = published and (host_ip in {None, "", "0.0.0.0", "::"})
    if all_interfaces:
        add_compose_service_finding(
            analysis,
            "compose_port_published_all_interfaces",
            "Compose service publishes a port on all interfaces",
            "low",
            "ports",
            path,
            context,
            service,
            "ports",
            line=line,
            port=port_label,
            protocol=protocol,
        )
    numbers = compose_port_numbers(target) | compose_port_numbers(published)
    if numbers.intersection(COMPOSE_DB_PORTS):
        add_compose_service_finding(analysis, "compose_database_port_published", "Compose service publishes a database-like port", "medium", "ports", path, context, service, "ports", line=line, port=port_label, protocol=protocol)
    if numbers.intersection(COMPOSE_ADMIN_PORTS):
        add_compose_service_finding(analysis, "compose_admin_port_published", "Compose service publishes an admin/dashboard-like port", "medium", "ports", path, context, service, "ports", line=line, port=port_label, protocol=protocol)
        add_compose_service_finding(analysis, "compose_dashboard_port_published", "Compose service publishes a dashboard-like port", "medium", "ports", path, context, service, "ports", line=line, port=port_label, protocol=protocol)
    if numbers.intersection(COMPOSE_SENSITIVE_PORTS):
        add_compose_service_finding(analysis, "compose_sensitive_port_published", "Compose service publishes a sensitive port", "medium", "ports", path, context, service, "ports", line=line, port=port_label, protocol=protocol)
    if "-" in target or "-" in published:
        add_compose_service_finding(analysis, "compose_port_range_published", "Compose service publishes a port range", "low", "ports", path, context, service, "ports", line=line, port=port_label, protocol=protocol)


def analyze_compose_volumes(
    analysis: dict[str, Any],
    path: str,
    context: str,
    service: str,
    field: dict[str, Any] | None,
) -> None:
    if not field:
        return
    for line_number, value in compose_field_scalar_values(field):
        volume = parse_compose_volume(value)
        if not volume:
            continue
        record = {"path": path, "context": context, "service": service, "line": line_number, **volume}
        analysis["volumes"].append(record)
        analyze_compose_volume_findings(analysis, path, context, service, record, line_number)
    for block in compose_sequence_blocks(field.get("lines", [])):
        mapping = compose_mapping_from_sequence_block(block)
        if not mapping:
            continue
        volume = {
            "source": compose_safe_value(mapping.get("source") or mapping.get("src") or ""),
            "target": compose_safe_value(mapping.get("target") or mapping.get("dst") or ""),
            "mode": compose_safe_value(mapping.get("mode") or ""),
            "type": mapping.get("type") or "volume",
        }
        record = {"path": path, "context": context, "service": service, "line": block.get("line"), **volume}
        analysis["volumes"].append(record)
        analyze_compose_volume_findings(analysis, path, context, service, record, int(block.get("line") or 0))


def parse_compose_volume(value: str) -> dict[str, str] | None:
    raw = compose_unquote(value)
    if not raw:
        return None
    parts = raw.split(":")
    if len(parts) == 1:
        return {"source": "", "target": compose_safe_value(parts[0]), "mode": "", "type": "volume"}
    source = parts[0]
    target = parts[1]
    mode = parts[2] if len(parts) >= 3 else ""
    volume_type = "bind" if is_compose_host_path(source) else "volume"
    return {"source": compose_safe_value(source), "target": compose_safe_value(target), "mode": compose_safe_value(mode), "type": volume_type}


def is_compose_host_path(path: str) -> bool:
    return path.startswith(("/", "./", "../", "~"))


def compose_path_writeable(mode: str | None) -> bool:
    normalized = (mode or "").lower()
    return "ro" not in {item.strip() for item in normalized.split(",") if item.strip()}


def analyze_compose_volume_findings(
    analysis: dict[str, Any],
    path: str,
    context: str,
    service: str,
    volume: dict[str, Any],
    line: int,
) -> None:
    source = str(volume.get("source") or "")
    target = str(volume.get("target") or "")
    mode = str(volume.get("mode") or "")
    if "/var/run/docker.sock" in {source, target} or source.endswith("/var/run/docker.sock") or target.endswith("/var/run/docker.sock"):
        add_compose_service_finding(analysis, "compose_docker_socket_mounted", "Compose service mounts the Docker socket", "medium", "volumes", path, context, service, "volumes", line=line, host_path=source, container_path=target)
    if source == "/" or target == "/":
        add_compose_service_finding(analysis, "compose_root_host_path_mounted", "Compose service mounts a root path", "medium", "volumes", path, context, service, "volumes", line=line, host_path=source, container_path=target)
    if ".ssh" in source or ".ssh" in target:
        add_compose_service_finding(analysis, "compose_ssh_key_path_mounted", "Compose service mounts an SSH-related path", "medium", "volumes", path, context, service, "volumes", line=line, host_path=source, container_path=target)
    if source.startswith("/var/run") or target.startswith("/var/run"):
        add_compose_service_finding(analysis, "compose_var_run_mounted", "Compose service mounts a var/run path", "medium", "volumes", path, context, service, "volumes", line=line, host_path=source, container_path=target)
    sensitive = source.startswith(COMPOSE_SENSITIVE_HOST_PATHS) or target.startswith(COMPOSE_SENSITIVE_HOST_PATHS)
    if sensitive:
        add_compose_service_finding(analysis, "compose_sensitive_host_path_mounted", "Compose service mounts a sensitive host path", "medium", "volumes", path, context, service, "volumes", line=line, host_path=source, container_path=target)
        if compose_path_writeable(mode):
            add_compose_service_finding(analysis, "compose_bind_mount_writeable_sensitive", "Compose service has a writable sensitive bind mount", "medium", "volumes", path, context, service, "volumes", line=line, host_path=source, container_path=target)
    if volume.get("type") == "volume" and source:
        add_compose_service_finding(analysis, "compose_named_volume_present", "Compose service uses a named volume", "info", "volumes", path, context, service, "volumes", line=line, host_path=source, container_path=target)


def analyze_compose_image(analysis: dict[str, Any], path: str, context: str, service: str, image: str, line: int) -> None:
    safe_image = compose_safe_value(image)
    if image.lower().endswith(":latest"):
        add_compose_service_finding(analysis, "compose_image_latest_tag", "Compose service image uses latest tag", "low", "image", path, context, service, "image", line=line, image=safe_image)
    if "@sha256:" not in image.lower():
        add_compose_service_finding(analysis, "compose_image_missing_digest", "Compose service image is not pinned by digest", "low", "image", path, context, service, "image", line=line, image=safe_image)
        add_compose_service_finding(analysis, "compose_image_unpinned_tag", "Compose service image is not digest pinned", "low", "image", path, context, service, "image", line=line, image=safe_image)


def analyze_compose_build(analysis: dict[str, Any], path: str, context: str, service: str, field: dict[str, Any]) -> None:
    build_context = str(field.get("value") or "").strip()
    if not build_context:
        for line in field.get("lines", []):
            if isinstance(line, ComposeYamlLine):
                key_value = compose_key_value(line.text)
                if key_value and key_value[0] == "context":
                    build_context = key_value[1]
                    break
    safe_context = compose_safe_value(compose_unquote(build_context or "."))
    analysis["build_contexts"].append({"path": path, "context": context, "service": service, "build_context": safe_context, "line": field.get("line")})
    add_compose_service_finding(analysis, "compose_build_context_present", "Compose service has a build context", "info", "build", path, context, service, "build", line=field.get("line"))
    if safe_context.startswith("../") or safe_context == "..":
        add_compose_service_finding(analysis, "compose_build_context_parent_path_hint", "Compose build context references a parent path", "low", "build", path, context, service, "build.context", line=field.get("line"))


def analyze_compose_service_networks(
    analysis: dict[str, Any],
    path: str,
    context: str,
    service: str,
    fields: list[dict[str, Any]],
) -> None:
    network_mode = compose_find_field(fields, "network_mode")
    if network_mode and compose_unquote(str(network_mode.get("value") or "")).lower() == "host":
        analysis["networks"].append({"path": path, "context": context, "service": service, "network_mode": "host", "line": network_mode.get("line")})
    networks_field = compose_find_field(fields, "networks")
    for line_number, network in compose_field_scalar_values(networks_field):
        analysis["networks"].append({"path": path, "context": context, "service": service, "name": compose_safe_value(network), "line": line_number})


def analyze_compose_top_level_networks(analysis: dict[str, Any], path: str, context: str, lines: list[ComposeYamlLine]) -> None:
    section = compose_section(lines, "networks")
    if not section:
        return
    _section_line, network_lines = section
    for block in compose_child_blocks(network_lines, 0):
        name = str(block.get("key") or "")
        nested_text = "\n".join(line.text for line in block.get("lines", []))
        external = re.search(r"(?im)^external\s*:\s*true\s*$", nested_text) is not None
        internal = re.search(r"(?im)^internal\s*:\s*true\s*$", nested_text) is not None
        analysis["networks"].append({"path": path, "context": context, "name": name, "external": external, "internal": internal, "line": block.get("line")})
        if external:
            add_compose_config_finding(
                analysis,
                "compose_external_network_present",
                "Compose external network is present",
                compose_contextual_level("low", context),
                compose_contextual_confidence("medium", context),
                "network",
                "A Compose top-level network is marked external. Inspectra does not validate Docker networks.",
                f"network={name}; external=true",
                "Confirm external network boundaries and consumers in the deployment environment.",
                file_path=path,
                context=context,
                line=block.get("line"),
                network=name,
            )
        if not internal:
            add_compose_config_finding(
                analysis,
                "compose_network_internal_missing",
                "Compose network is not marked internal",
                compose_contextual_level("low", context),
                compose_contextual_confidence("low", context),
                "network",
                "A Compose network does not set internal: true in the reviewed file.",
                f"network={name}; internal missing",
                "Review whether the network should be isolated from external connectivity.",
                file_path=path,
                context=context,
                line=block.get("line"),
                network=name,
            )


def analyze_compose_top_level_volumes(analysis: dict[str, Any], path: str, context: str, lines: list[ComposeYamlLine]) -> None:
    section = compose_section(lines, "volumes")
    if not section:
        return
    _section_line, volume_lines = section
    for block in compose_child_blocks(volume_lines, 0):
        name = str(block.get("key") or "")
        analysis["volumes"].append({"path": path, "context": context, "name": name, "source": "top_level", "line": block.get("line")})
        add_compose_config_finding(
            analysis,
            "compose_named_volume_present",
            "Compose named volume is defined",
            "info",
            compose_contextual_confidence("medium", context),
            "volumes",
            "A top-level Compose named volume was observed.",
            f"volume={name}",
            "Review named volume persistence and backup expectations.",
            file_path=path,
            context=context,
            line=block.get("line"),
        )


def analyze_compose_top_level_secrets(analysis: dict[str, Any], path: str, context: str, lines: list[ComposeYamlLine]) -> None:
    section = compose_section(lines, "secrets")
    if not section:
        return
    _section_line, secret_lines = section
    for block in compose_child_blocks(secret_lines, 0):
        name = str(block.get("key") or "")
        nested_fields = compose_direct_fields(block.get("lines", []), int(block.get("indent") or 0))
        file_field = compose_find_field(nested_fields, "file")
        secret_record = {"path": path, "context": context, "name": name, "line": block.get("line"), "read": False}
        if file_field:
            secret_record["file"] = compose_safe_value(str(file_field.get("value") or ""))
        analysis["secrets"].append(secret_record)
        add_compose_config_finding(
            analysis,
            "compose_secrets_defined",
            "Compose top-level secret is defined",
            "info",
            compose_contextual_confidence("medium", context),
            "secrets",
            "A Compose secret definition was observed. Inspectra does not read secret file contents.",
            f"secret={name}",
            "Confirm secret file sources are protected and not shared with real values.",
            file_path=path,
            context=context,
            line=block.get("line"),
            field_path=f"secrets.{name}",
        )
        if file_field:
            add_compose_config_finding(
                analysis,
                "compose_secret_file_reference",
                "Compose secret references a file",
                compose_contextual_level("low", context),
                compose_contextual_confidence("high", context),
                "secrets",
                "A Compose secret file reference was observed. Inspectra records the path but does not read the referenced file.",
                f"secret={name}; file={compose_safe_value(str(file_field.get('value') or ''))}",
                "Keep real secret files out of shared archives and inject secrets through runtime controls.",
                file_path=path,
                context=context,
                line=file_field.get("line"),
                field_path=f"secrets.{name}.file",
            )


def finalize_compose_config_analysis(analysis: dict[str, Any]) -> None:
    contexts = [str(context) for context in analysis.get("_compose_contexts", []) if isinstance(context, str)]
    if int(analysis.get("_compose_file_count") or 0) > 1:
        context = "production" if "production" in contexts else "shared"
        add_compose_config_finding(
            analysis,
            "compose_multiple_files_detected",
            "Multiple Compose files were detected",
            "info",
            "high",
            "structure",
            "More than one Compose candidate file was detected. Inspectra does not merge Compose files into an effective config.",
            f"compose_files={analysis.get('_compose_file_count')}",
            "Review intended file ordering and overrides in the deployment workflow.",
            context=context,
        )
    for path in analysis.get("_override_paths", []):
        add_compose_config_finding(
            analysis,
            "compose_override_file_detected",
            "Compose override file was detected",
            "info",
            "high",
            "structure",
            "A Compose override-like file was detected. Inspectra records it as context and does not merge files.",
            str(path),
            "Review override usage in the intended deployment workflow.",
            file_path=str(path),
            context=compose_config_file_context(str(path), "compose"),
        )
    if analysis.get("_profiles"):
        add_compose_config_finding(
            analysis,
            "compose_profiles_present",
            "Compose profiles were observed",
            "info",
            "medium",
            "structure",
            "Compose profiles were observed. Inspectra does not evaluate active profiles.",
            "profiles present",
            "Review profile activation in the intended deployment workflow.",
            context="production" if "production" in contexts else "shared",
        )

    analysis["summary"]["services_detected"] = len(analysis.get("services", []))
    analysis["summary"]["networks_detected"] = len(analysis.get("networks", []))
    analysis["summary"]["volumes_detected"] = len(analysis.get("volumes", []))
    analysis["summary"]["secrets_detected"] = len(analysis.get("secrets", []))
    analysis["summary"]["published_ports_detected"] = len(analysis.get("ports", []))
    analysis["summary"]["env_files_detected"] = len(analysis.get("env_files", []))
    analysis["findings"] = dedupe_findings(analysis["findings"])
    analysis["summary"]["findings_count"] = len(analysis["findings"])
    if analysis["summary"]["redacted_values_count"]:
        analysis["redaction_notes"] = [
            "Secret-like Docker Compose values are redacted before storage on a best-effort basis.",
            ".env, env_file, and Compose secret file contents are detected as references but not read by this analyzer.",
        ]
    analysis.pop("_compose_file_count", None)
    analysis.pop("_compose_contexts", None)
    analysis.pop("_override_paths", None)
    analysis.pop("_profiles", None)


def add_compose_service_finding(
    analysis: dict[str, Any],
    finding_id: str,
    title: str,
    level: str,
    category: str,
    path: str,
    context: str,
    service: str,
    field_path: str,
    *,
    line: Any = None,
    image: str | None = None,
    port: str | None = None,
    protocol: str | None = None,
    host_path: str | None = None,
    container_path: str | None = None,
    network: str | None = None,
) -> None:
    parts = [f"service={service}", f"field={field_path}"]
    if image:
        parts.append(f"image={compose_safe_value(image)}")
    if port:
        parts.append(f"port={port}")
    if protocol:
        parts.append(f"protocol={protocol}")
    if host_path:
        parts.append(f"host_path={host_path}")
    if container_path:
        parts.append(f"container_path={container_path}")
    if network:
        parts.append(f"network={network}")
    add_compose_config_finding(
        analysis,
        finding_id,
        title,
        compose_contextual_level(level, context),
        compose_contextual_confidence("high" if level == "medium" else "medium", context),
        category,
        "A Docker Compose static review indicator was observed. Inspectra does not execute Docker Compose or validate runtime state.",
        "; ".join(parts),
        "Review the service in the intended deployment context and apply hardening where appropriate.",
        file_path=path,
        context=context,
        line=int(line) if isinstance(line, int) else None,
        service=service,
        field_path=field_path,
        image=image,
        port=port,
        protocol=protocol,
        host_path=host_path,
        container_path=container_path,
        network=network,
    )


def add_compose_config_finding(
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
    service: str | None = None,
    field_path: str | None = None,
    image: str | None = None,
    port: str | None = None,
    protocol: str | None = None,
    host_path: str | None = None,
    container_path: str | None = None,
    network: str | None = None,
    redacted: bool = False,
) -> None:
    safe_description, description_redactions = redact_compose_secret_text(description)
    safe_evidence, evidence_redactions = redact_compose_secret_text(evidence)
    safe_recommendation, recommendation_redactions = redact_compose_secret_text(recommendation)
    redaction_count = description_redactions + evidence_redactions + recommendation_redactions
    if redacted and redaction_count == 0:
        redaction_count = 1
    analysis["summary"]["redacted_values_count"] += redaction_count

    finding = make_finding(finding_id, title, level, safe_description, safe_evidence, safe_recommendation)
    finding["confidence"] = confidence
    finding["category"] = category
    if file_path:
        finding["file_path"] = file_path
    if context:
        finding["context"] = context
    if line is not None:
        finding["line"] = line
    if service:
        finding["service"] = service
    if field_path:
        finding["field_path"] = field_path
    if image:
        finding["image"] = compose_safe_value(image)
    if port:
        finding["port"] = port
    if protocol:
        finding["protocol"] = protocol
    if host_path:
        finding["host_path"] = compose_safe_value(host_path)
    if container_path:
        finding["container_path"] = compose_safe_value(container_path)
    if network:
        finding["network"] = compose_safe_value(network)
    analysis["findings"].append(finding)


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
