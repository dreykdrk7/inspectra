from __future__ import annotations

from dataclasses import dataclass
import html
import json
import re
import textwrap
from typing import Any, Iterable
from xml.etree import ElementTree

from app.models import JobRecord
from app.web_security import redact_text_urls, redact_url_query

SENSITIVE_RESPONSE_HEADERS = {"set-cookie", "authorization", "proxy-authorization", "x-api-key", "x-auth-token"}
DJANGO_SECRET_KEYWORDS = (
    "DJANGO_SECRET_KEY",
    "SECRET_KEY",
    "CLIENT_SECRET",
    "PASSWORD",
    "PASS",
    "TOKEN",
    "API_KEY",
    "SECRET",
    "DATABASE_URL",
    "REDIS_URL",
    "EMAIL_HOST_PASSWORD",
    "AWS_SECRET_ACCESS_KEY",
    "PRIVATE_KEY",
)
JWT_LIKE_RE = re.compile(r"\b[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b")
SENSITIVE_QUERY_PARAM_RE = re.compile(
    r"(?i)([?&](?:access_token|refresh_token|id_token|api_key|apikey|key|token|secret|password|passwd|pwd|session|sid|auth|authorization|jwt|bearer|sig|signature|client_secret|code|state)=)[^&#\s]+"
)
SECRET_LIKE_MAPPING_TOKENS = (
    "_auth",
    "auth_token",
    "authtoken",
    "secret_key",
    "django_secret_key",
    "client_secret",
    "private_key",
    "database_url",
    "redis_url",
    "api_key",
    "apikey",
    "password",
    "passwd",
    "_password",
    "token",
    "secret",
    "auth",
    "key",
)
ACTIVE_NMAP_BASIC_SENSITIVE_VALUE_KEYS = {
    "address",
    "addresses",
    "args",
    "argv",
    "argv_preview",
    "authorization",
    "banner",
    "banners",
    "cmd",
    "command",
    "command_line",
    "cookie",
    "cookies",
    "credential",
    "credentials",
    "extra_args",
    "header",
    "headers",
    "host",
    "hostname",
    "hostnames",
    "ip",
    "ips",
    "nmap_xml",
    "nse",
    "nse_output",
    "product",
    "ptr_hostname",
    "ptr_hostnames",
    "raw",
    "raw_command",
    "raw_output",
    "raw_stderr",
    "raw_stdout",
    "raw_target",
    "raw_xml",
    "request",
    "response",
    "resolved_address",
    "resolved_addresses",
    "resolved_ip",
    "resolved_ips",
    "script",
    "script_output",
    "scripts",
    "service",
    "service_banner",
    "service_name",
    "service_product",
    "services",
    "stderr",
    "statement",
    "stdout",
    "stylesheet",
    "stylesheet_path",
    "target",
    "target_display",
    "target_url",
    "targets",
    "token",
    "tokens",
    "userinfo",
    "version",
    "xml",
}
ACTIVE_NMAP_BASIC_TOKEN_SOURCE_KEYS = ACTIVE_NMAP_BASIC_SENSITIVE_VALUE_KEYS | {"normalized", "normalized_target"}
ACTIVE_NMAP_BASIC_NO_LIVE_STATES = {
    "blocked_missing_approval",
    "blocked_unconfigured",
    "client_error_controlled",
    "completed_no_live",
    "not_executed",
    "unsafe_lifecycle_result",
}
ACTIVE_NMAP_BASIC_NO_LIVE_OMITTED_KEYS = {
    "argv",
    "banner",
    "banners",
    "command",
    "command_line",
    "cookie",
    "cookies",
    "credential",
    "credentials",
    "evidence",
    "findings",
    "header",
    "headers",
    "nmap_xml",
    "observations",
    "port_observations",
    "ptr",
    "ptr_hostname",
    "ptr_hostnames",
    "raw",
    "raw_command",
    "raw_output",
    "raw_payload",
    "raw_request",
    "raw_stderr",
    "raw_stdout",
    "raw_target",
    "raw_xml",
    "resolved_ip",
    "resolved_ips",
    "service",
    "service_banner",
    "service_details",
    "service_product",
    "stderr",
    "stdout",
    "target",
    "target_url",
    "token",
    "tokens",
    "version",
    "versions",
    "xml",
}
ACTIVE_NMAP_BASIC_NO_LIVE_CAVEATS = [
    "No Nmap executed",
    "No network requests",
    "No DNS queries",
    "No evidence collected",
    "No observations available",
    "Manual validation required",
    "No-live lifecycle record, not a target finding",
]
ACTIVE_NMAP_BASIC_REAL_MINIMAL_CAVEATS = [
    "Observed TCP exposure / review indicator",
    "Manual validation required",
    "No DNS expansion",
    "No raw Nmap output stored",
    "No service, banner, or version evidence stored",
]
ACTIVE_NMAP_BASIC_TEXT_REDACT_PATTERNS = (
    re.compile(r"<\?xml\b.*?</nmaprun\s*>", flags=re.IGNORECASE | re.DOTALL),
    re.compile(r"<nmaprun\b.*?</nmaprun\s*>", flags=re.IGNORECASE | re.DOTALL),
    re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s\"'<>)]+", flags=re.IGNORECASE),
    re.compile(r"\bnmap(?:\s+[^\n\r<>{}\[\]]+){1,64}", flags=re.IGNORECASE),
    re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    re.compile(r"\b(?:[A-F0-9]{1,4}:){2,}[A-F0-9:]{1,}\b", flags=re.IGNORECASE),
    re.compile(r"\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\b", flags=re.IGNORECASE),
    re.compile(r"(?i)\b(?:Cookie|Set-Cookie|X-Api-Key|X-Auth-Token)\s*:\s*[^\n\r;]+"),
    re.compile(r"(?i)\b(?:service(?:_banner)?|banner|product|version)\s*[:=]\s*[^\n\r,;}\]]+"),
    re.compile(r"(?i)\b(?:confirmed vulnerability|exploitable|target is safe|all ports found|full network scan|scan the internet)\b"),
)
ACTIVE_TLS_BASIC_ALLOWED_STATUSES = {
    "handshake_succeeded",
    "handshake_failed",
    "timed_out",
    "certificate_unavailable",
    "tls_error_controlled",
}
ACTIVE_TLS_BASIC_SENSITIVE_VALUE_KEYS = ACTIVE_NMAP_BASIC_SENSITIVE_VALUE_KEYS | {
    "certificate_der",
    "certificate_pem",
    "chain",
    "client_certificate",
    "client_certificates",
    "client_key",
    "der",
    "exception",
    "full_chain",
    "key",
    "pem",
    "private_key",
    "raw_certificate",
    "raw_der",
    "raw_exception",
    "raw_pem",
    "sni",
    "sni_override",
    "sni_overrides",
}
ACTIVE_TLS_BASIC_TOKEN_SOURCE_KEYS = ACTIVE_TLS_BASIC_SENSITIVE_VALUE_KEYS | {"raw_target", "target", "target_url"}
ACTIVE_TLS_BASIC_CAVEATS = [
    "TLS configuration review indicator",
    "Manual validation required",
    "No HTTP request sent",
    "No crawling performed",
    "No target expansion performed",
    "No raw certificate PEM or DER stored",
]
ACTIVE_DNS_INVENTORY_ALLOWED_STATUSES = {"best_effort_inventory", "partial_inventory", "zone_transfer_complete", "not_executed"}
ACTIVE_DNS_INVENTORY_SENSITIVE_VALUE_KEYS = ACTIVE_NMAP_BASIC_SENSITIVE_VALUE_KEYS | {
    "account_id",
    "axfr",
    "command",
    "dns_message",
    "dns_packet",
    "domain",
    "authoritative_nameserver",
    "authoritative_nameservers",
    "nameserver",
    "nameservers",
    "provider_account",
    "provider_api_token",
    "provider_credentials",
    "provider_secret",
    "raw_dns_message",
    "raw_dns_packet",
    "raw_domain",
    "raw_payload",
    "raw_query",
    "raw_resolver_log",
    "raw_response",
    "raw_zone",
    "resolver_log",
    "resolver_logs",
    "target_domain",
    "zone_file",
    "zone_id",
}
ACTIVE_DNS_INVENTORY_TOKEN_SOURCE_KEYS = ACTIVE_DNS_INVENTORY_SENSITIVE_VALUE_KEYS | {
    "domain",
    "name",
    "raw_domain",
    "target_domain",
    "value",
}
ACTIVE_DNS_INVENTORY_CAVEATS = [
    "DNS configuration review indicator",
    "Manual validation required",
    "Best-effort DNS inventory unless authorized AXFR completes",
    "Complete-zone coverage only when coverage_level is zone_transfer_complete",
    "Zone transfer requires explicit authorization",
    "No provider import",
    "No brute-force discovery",
    "No raw DNS packets, resolver logs, or domain values stored",
]


@dataclass(frozen=True)
class ReportSection:
    title: str
    items: list[tuple[str, str]]


def build_report_filename(job: JobRecord, extension: str) -> str:
    return f"inspectra-job-{job.id}.{extension}"


def render_markdown_report(job: JobRecord) -> str:
    sections = build_report_sections(job)
    lines = ["# Inspectra Audit Report", ""]
    for section in sections:
        lines.append(f"## {section.title}")
        lines.append("")
        if section.items:
            for key, value in section.items:
                lines.extend(render_markdown_item(key, value))
        else:
            lines.append("N/A")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_html_report(job: JobRecord) -> str:
    sections = build_report_sections(job)
    badges = f'<span class="badge {html_class(job.status)}">{escape_html(job.status)}</span>'
    if job.source_file_deleted_at:
        badges += '<span class="badge deleted">source deleted</span>'

    body_sections = "\n".join(render_html_section(section) for section in sections)
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Inspectra Audit Report</title>
  <style>
    :root {{ color: #172033; background: #f5f7fb; font-family: Arial, sans-serif; }}
    body {{ margin: 0; padding: 32px; }}
    main {{ max-width: 980px; margin: 0 auto; background: #fff; border: 1px solid #d9e0ea; border-radius: 8px; padding: 28px; }}
    h1 {{ margin: 0 0 8px; font-size: 28px; }}
    h2 {{ margin: 26px 0 12px; padding-top: 18px; border-top: 1px solid #d9e0ea; font-size: 18px; }}
    h2:first-of-type {{ border-top: 0; padding-top: 0; }}
    .subtle {{ color: #66768a; margin: 0 0 20px; }}
    .badge-row {{ display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 18px; }}
    .badge {{ display: inline-block; border-radius: 999px; padding: 4px 10px; background: #e8edf4; color: #425267; font-weight: 700; font-size: 12px; }}
    .completed {{ background: #dff5e7; color: #176139; }}
    .failed {{ background: #ffe2e2; color: #9a242d; }}
    .running, .queued {{ background: #fff3cf; color: #76540a; }}
    .deleted {{ background: #ece7ff; color: #4d3c8f; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ border-bottom: 1px solid #d9e0ea; padding: 8px; text-align: left; vertical-align: top; }}
    th {{ width: 28%; color: #526070; }}
    td {{ overflow-wrap: anywhere; }}
    code {{ font-family: Consolas, monospace; }}
  </style>
</head>
<body>
  <main>
    <h1>Inspectra Audit Report</h1>
    <p class="subtle">Generated locally from an Inspectra job JSON record.</p>
    <div class="badge-row">{badges}</div>
    {body_sections}
  </main>
</body>
</html>
"""


def render_xml_report(job: JobRecord) -> str:
    root = ElementTree.Element("inspectraAuditReport")
    ElementTree.SubElement(root, "title").text = "Inspectra Audit Report"
    job_node = ElementTree.SubElement(root, "job")
    add_text(job_node, "id", job.id)
    add_text(job_node, "auditType", job.audit_type)
    add_text(job_node, "status", job.status)
    add_text(job_node, "fileId", job.file_id or "")
    add_text(job_node, "targetUrl", public_job_target_url(job) or "")
    add_text(job_node, "targetDomain", job.target_domain or "")
    add_text(job_node, "createdAt", job.created_at.isoformat())
    add_text(job_node, "updatedAt", job.updated_at.isoformat())
    add_text(job_node, "error", public_job_error(job))

    file_node = ElementTree.SubElement(root, "file")
    add_text(file_node, "id", job.file_id or "")
    add_text(file_node, "sourceFileDeletedAt", job.source_file_deleted_at.isoformat() if job.source_file_deleted_at else "")

    result = as_dict(job.result)
    public_result = public_result_for_job(job, result)
    append_value(root, "summary", public_result.get("summary", build_summary(job)))
    append_value(root, "hashes", public_result.get("hashes", {}))
    append_value(root, "findings", public_result.get("findings", []))
    append_value(root, "toolResults", public_result.get("tool_outputs", {}))
    append_value(root, "errors", collect_errors(job))
    append_value(root, "sections", {section.title: dict(section.items) for section in build_report_sections(job)})

    return '<?xml version="1.0" encoding="utf-8"?>\n' + ElementTree.tostring(root, encoding="unicode")


def render_pdf_report(job: JobRecord) -> bytes:
    lines = ["Inspectra Audit Report", ""]
    for section in build_report_sections(job):
        lines.append(section.title)
        if not section.items:
            lines.append("  N/A")
        for key, value in section.items:
            lines.extend(wrap_pdf_line(f"{key}: {value}", indent="  "))
        lines.append("")
    return build_simple_pdf(lines)


def build_report_sections(job: JobRecord) -> list[ReportSection]:
    result = public_result_for_job(job, as_dict(job.result))
    job_error = public_job_error(job)
    sections = [
        ReportSection(
            "Job",
            [
                ("Job ID", job.id),
                ("Audit type", job.audit_type),
                ("Status", job.status),
                ("File ID", job.file_id or "N/A"),
                ("Target URL", public_job_target_url(job) or "N/A"),
                ("Target domain", job.target_domain or "N/A"),
                ("Created at", job.created_at.isoformat()),
                ("Updated at", job.updated_at.isoformat()),
                ("Source file deleted", job.source_file_deleted_at.isoformat() if job.source_file_deleted_at else "No"),
                ("Job error", job_error or "N/A"),
            ],
        ),
        ReportSection("Summary", flatten_mapping(build_summary(job))),
        ReportSection("Hashes", flatten_mapping(as_dict(result.get("hashes")))),
    ]

    if job.audit_type == "pdf_basic":
        sections.extend(build_pdf_sections(result))
    elif job.audit_type == "image_basic":
        sections.extend(build_image_sections(result))
    elif job.audit_type == "manifest_basic":
        sections.extend(build_manifest_sections(result))
    elif job.audit_type == "archive_basic":
        sections.extend(build_archive_sections(result))
    elif job.audit_type == "project_archive_basic":
        sections.extend(build_project_archive_sections(result))
    elif job.audit_type == "web_basic":
        sections.extend(build_web_sections(result))
    elif job.audit_type == "domain_basic":
        sections.extend(build_domain_sections(result))
    elif job.audit_type == "subdomain_inventory_basic":
        sections.extend(build_subdomain_inventory_sections(result))
    elif job.audit_type == "django_config_basic":
        sections.extend(build_django_config_sections(result))
    elif job.audit_type == "docker_config_basic":
        sections.extend(build_docker_config_sections(result))
    elif job.audit_type == "secrets_review_basic":
        sections.extend(build_secrets_review_sections(result))
    elif job.audit_type == "node_package_config_basic":
        sections.extend(build_node_package_config_sections(result))
    elif job.audit_type == "ci_cd_config_basic":
        sections.extend(build_ci_cd_config_sections(result))
    elif job.audit_type == "k8s_config_basic":
        sections.extend(build_k8s_config_sections(result))
    elif job.audit_type == "terraform_config_basic":
        sections.extend(build_terraform_config_sections(result))
    elif job.audit_type == "nginx_config_basic":
        sections.extend(build_nginx_config_sections(result))
    elif job.audit_type == "compose_config_basic":
        sections.extend(build_compose_config_sections(result))
    elif job.audit_type == "database_config_basic":
        sections.extend(build_database_config_sections(result))
    elif job.audit_type == "sql_database_config_basic":
        sections.extend(build_sql_database_config_sections(result))
    elif job.audit_type == "redis_config_basic":
        sections.extend(build_redis_config_sections(result))
    elif job.audit_type == "active_network_dry_run":
        sections.extend(build_active_network_dry_run_sections(result))
    elif job.audit_type == "active_http_header_probe":
        sections.extend(build_active_http_header_probe_sections(result))
    elif job.audit_type == "active_nmap_basic":
        sections.extend(build_active_nmap_basic_sections(result))
    elif job.audit_type == "active_tls_basic":
        sections.extend(build_active_tls_basic_sections(result))
    elif job.audit_type == "active_dns_inventory":
        sections.extend(build_active_dns_inventory_sections(result))

    sections.append(ReportSection("Errors And Timeouts", flatten_mapping(collect_errors(job))))
    return sections


def build_pdf_sections(result: dict[str, Any]) -> list[ReportSection]:
    metadata = as_dict(result.get("metadata"))
    validation = as_dict(result.get("validation"))
    tool_outputs = as_dict(result.get("tool_outputs"))
    file_tool = as_dict(tool_outputs.get("file"))
    qpdf = as_dict(tool_outputs.get("qpdf"))
    return [
        ReportSection(
            "PDF Identification",
            [
                ("MIME type", stringify(validation.get("mime_type"))),
                ("file output", stringify(file_tool.get("stdout"))),
            ],
        ),
        ReportSection("pdfinfo", flatten_mapping(as_dict(metadata.get("pdfinfo")))),
        ReportSection("exiftool", flatten_mapping(as_dict(metadata.get("exiftool")))),
        ReportSection(
            "qpdf",
            [
                ("qpdf ok", stringify(validation.get("qpdf_ok"))),
                ("exit code", stringify(qpdf.get("exit_code"))),
                ("stdout", stringify(qpdf.get("stdout"))),
                ("stderr", stringify(qpdf.get("stderr"))),
            ],
        ),
    ]


def build_image_sections(result: dict[str, Any]) -> list[ReportSection]:
    metadata = as_dict(result.get("metadata"))
    return [
        ReportSection("Image Identification", flatten_mapping(as_dict(result.get("identification")))),
        ReportSection("Image Metadata", flatten_mapping(as_dict(metadata.get("exiftool")))),
        ReportSection("Privacy Indicators", flatten_mapping(as_dict(result.get("privacy_indicators")))),
    ]


def build_manifest_sections(result: dict[str, Any]) -> list[ReportSection]:
    parsed = as_dict(result.get("parsed"))
    return [
        ReportSection(
            "Manifest Identification",
            flatten_mapping(as_dict(result.get("file_identification"))) + [("Manifest type", stringify(result.get("manifest_type")))],
        ),
        ReportSection("Project", flatten_mapping(as_dict(parsed.get("project")))),
        ReportSection("Dependencies", flatten_mapping(as_dict(parsed.get("dependencies")))),
        ReportSection("Scripts", flatten_mapping(as_dict(parsed.get("scripts")))),
        ReportSection("Findings", flatten_list(result.get("findings"))),
    ]


def build_archive_sections(result: dict[str, Any]) -> list[ReportSection]:
    return [
        ReportSection(
            "Archive Identification",
            flatten_mapping(as_dict(result.get("file_identification"))) + [("Archive type", stringify(result.get("archive_type")))],
        ),
        ReportSection("Archive Metrics", flatten_mapping(as_dict(result.get("summary")))),
        ReportSection("Detected Manifests", flatten_list(result.get("detected_manifests"))),
        ReportSection("Findings", flatten_list(result.get("findings"))),
        ReportSection("Entries Sample", flatten_list(result.get("entries_sample"))),
    ]


def build_project_archive_sections(result: dict[str, Any]) -> list[ReportSection]:
    return [
        ReportSection(
            "Project Archive Identification",
            flatten_mapping(as_dict(result.get("file_identification"))) + [("Archive type", stringify(result.get("archive_type")))],
        ),
        ReportSection("Project Archive Metrics", flatten_mapping(as_dict(result.get("summary")))),
        ReportSection("Limits", flatten_mapping(as_dict(result.get("limits")))),
        ReportSection("Supported Manifests", flatten_list(result.get("supported_manifests"))),
        ReportSection("Unsupported Manifests", flatten_list(result.get("unsupported_manifests"))),
        ReportSection("Parsed Manifests", flatten_list(result.get("parsed_manifests"))),
        ReportSection("Findings", flatten_list(result.get("findings"))),
    ]


def build_web_sections(result: dict[str, Any]) -> list[ReportSection]:
    public_result = as_dict(redact_web_value(result))
    http = as_dict(public_result.get("http"))
    http["response_headers"] = redact_sensitive_headers(as_dict(http.get("response_headers")))
    if "set_cookie_headers" in http:
        http["set_cookie_headers"] = "[redacted]"
    return [
        ReportSection("Web Target", flatten_mapping(as_dict(public_result.get("target")))),
        ReportSection("HTTP", flatten_mapping(http)),
        ReportSection("Security Headers", flatten_mapping(as_dict(public_result.get("security_headers")))),
        ReportSection("Cookies", flatten_list(public_result.get("cookies"))),
        ReportSection("TLS", flatten_mapping(as_dict(public_result.get("tls")))),
        ReportSection("robots.txt", flatten_mapping(as_dict(public_result.get("robots_txt")))),
        ReportSection("security.txt", flatten_mapping(as_dict(public_result.get("security_txt")))),
        ReportSection("Findings", flatten_list(public_result.get("findings"))),
    ]


def build_domain_sections(result: dict[str, Any]) -> list[ReportSection]:
    dns = as_dict(result.get("dns"))
    email_security = as_dict(result.get("email_security"))
    return [
        ReportSection("Domain Target", flatten_mapping(as_dict(result.get("target")))),
        ReportSection("DNS Records", flatten_mapping({key: value for key, value in dns.items() if key != "www"})),
        ReportSection("www Baseline", flatten_mapping(as_dict(dns.get("www")))),
        ReportSection("SPF", flatten_mapping(as_dict(email_security.get("spf")))),
        ReportSection("DMARC", flatten_mapping(as_dict(email_security.get("dmarc")))),
        ReportSection("DKIM", flatten_mapping(as_dict(email_security.get("dkim")))),
        ReportSection("Findings", flatten_list(result.get("findings"))),
    ]


def build_subdomain_inventory_sections(result: dict[str, Any]) -> list[ReportSection]:
    return [
        ReportSection("Subdomain Target", flatten_mapping(as_dict(result.get("target")))),
        ReportSection("Subdomain Inventory Metrics", flatten_mapping(as_dict(result.get("summary")))),
        ReportSection("Subdomain Inventory Limits", flatten_mapping(as_dict(result.get("limits")))),
        ReportSection("Candidates", flatten_list(result.get("candidates"))),
        ReportSection("DNS Results", flatten_list(result.get("results"))),
        ReportSection("Wildcard DNS", flatten_mapping(as_dict(result.get("wildcard_dns")))),
        ReportSection("Findings", flatten_list(result.get("findings"))),
    ]


def build_django_config_sections(result: dict[str, Any]) -> list[ReportSection]:
    return [
        ReportSection(
            "Django Config Identification",
            flatten_mapping(as_dict(result.get("file_identification"))) + [("Archive type", stringify(result.get("archive_type")))],
        ),
        ReportSection("Django Config Metrics", flatten_mapping(as_dict(result.get("summary")))),
        ReportSection("Django Config Limits", flatten_mapping(as_dict(result.get("limits")))),
        ReportSection("Detected Files", flatten_django_detected_files(result.get("detected_files"))),
        ReportSection("Django Signals", flatten_mapping(as_dict(result.get("django_signals")))),
        ReportSection("Findings", flatten_django_findings(result.get("findings"))),
    ]


def build_docker_config_sections(result: dict[str, Any]) -> list[ReportSection]:
    return [
        ReportSection(
            "Docker Config Identification",
            flatten_mapping(as_dict(result.get("file_identification"))) + [("Archive type", stringify(result.get("archive_type")))],
        ),
        ReportSection("Docker Config Metrics", flatten_mapping(as_dict(result.get("summary")))),
        ReportSection("Docker Config Limits", flatten_mapping(as_dict(result.get("limits")))),
        ReportSection("Files Detected", flatten_docker_detected_files(result.get("files_detected"))),
        ReportSection("Files Reviewed", flatten_list(result.get("files_reviewed"))),
        ReportSection("Dockerfile Stages", flatten_list(result.get("dockerfile_stages"))),
        ReportSection("Compose Services", flatten_list(result.get("compose_services"))),
        ReportSection("Findings", flatten_docker_findings(result.get("findings"))),
        ReportSection("Redaction Notes", flatten_list(result.get("redaction_notes"))),
    ]


def build_secrets_review_sections(result: dict[str, Any]) -> list[ReportSection]:
    return [
        ReportSection(
            "Secrets Review Identification",
            flatten_mapping(as_dict(result.get("file_identification"))) + [("Archive type", stringify(result.get("archive_type")))],
        ),
        ReportSection("Secrets Review Metrics", flatten_mapping(as_dict(result.get("summary")))),
        ReportSection("Secrets Review Limits", flatten_mapping(as_dict(result.get("limits")))),
        ReportSection("Sensitive Files Detected But Not Read", flatten_django_detected_files(result.get("sensitive_files"))),
        ReportSection("Files Detected", flatten_django_detected_files(result.get("files_detected"))),
        ReportSection("Files Reviewed", flatten_list(result.get("files_reviewed"))),
        ReportSection("Findings", flatten_secrets_findings(result.get("findings"))),
        ReportSection("Redaction Notes", flatten_list(result.get("redaction_notes"))),
    ]


def build_node_package_config_sections(result: dict[str, Any]) -> list[ReportSection]:
    return [
        ReportSection(
            "Node Package Config Identification",
            flatten_mapping(as_dict(result.get("file_identification"))) + [("Archive type", stringify(result.get("archive_type")))],
        ),
        ReportSection("Node Package Config Metrics", flatten_mapping(as_dict(result.get("summary")))),
        ReportSection("Node Package Config Limits", flatten_mapping(as_dict(result.get("limits")))),
        ReportSection("Package Workspace Overview", flatten_list(result.get("packages"))),
        ReportSection("Scripts", flatten_list(result.get("scripts"))),
        ReportSection("Dependency Groups", flatten_list(result.get("dependency_groups"))),
        ReportSection("Package Manager Config Signals", flatten_list(result.get("package_manager_config_signals"))),
        ReportSection("Lockfile Signals", flatten_list(result.get("lockfile_signals"))),
        ReportSection("Files Detected", flatten_django_detected_files(result.get("files_detected"))),
        ReportSection("Files Reviewed", flatten_list(result.get("files_reviewed"))),
        ReportSection("Findings", flatten_secrets_findings(result.get("findings"))),
        ReportSection("Redaction Notes", flatten_list(result.get("redaction_notes"))),
    ]


def build_ci_cd_config_sections(result: dict[str, Any]) -> list[ReportSection]:
    return [
        ReportSection(
            "CI/CD Config Identification",
            flatten_mapping(as_dict(result.get("file_identification"))) + [("Archive type", stringify(result.get("archive_type")))],
        ),
        ReportSection("CI/CD Config Metrics", flatten_mapping(as_dict(result.get("summary")))),
        ReportSection("CI/CD Config Limits", flatten_mapping(as_dict(result.get("limits")))),
        ReportSection("Workflow Overview", flatten_list(result.get("workflows"))),
        ReportSection("Triggers", flatten_list(result.get("triggers"))),
        ReportSection("Permissions", flatten_list(result.get("permissions"))),
        ReportSection("Jobs / Steps Overview", flatten_list(result.get("jobs"))),
        ReportSection("Actions / Images", flatten_list(result.get("actions"))),
        ReportSection("Service Containers", flatten_list(result.get("service_containers"))),
        ReportSection("Publish / Deploy Signals", flatten_list(result.get("publish_deploy_signals"))),
        ReportSection("Files Detected", flatten_django_detected_files(result.get("files_detected"))),
        ReportSection("Files Reviewed", flatten_list(result.get("files_reviewed"))),
        ReportSection("Findings", flatten_ci_cd_findings(result.get("findings"))),
        ReportSection("Redaction Notes", flatten_list(result.get("redaction_notes"))),
    ]


def build_k8s_config_sections(result: dict[str, Any]) -> list[ReportSection]:
    return [
        ReportSection(
            "Kubernetes Config Identification",
            flatten_mapping(as_dict(result.get("file_identification"))) + [("Archive type", stringify(result.get("archive_type")))],
        ),
        ReportSection("Kubernetes Config Metrics", flatten_mapping(as_dict(result.get("summary")))),
        ReportSection("Kubernetes Config Limits", flatten_mapping(as_dict(result.get("limits")))),
        ReportSection("Resource Overview", flatten_list(result.get("resources"))),
        ReportSection("Workloads", flatten_list(result.get("workloads"))),
        ReportSection("Containers", flatten_list(result.get("containers"))),
        ReportSection("Services", flatten_list(result.get("services"))),
        ReportSection("Ingress", flatten_list(result.get("ingress"))),
        ReportSection("RBAC", flatten_list(result.get("rbac"))),
        ReportSection("Secrets", flatten_list(result.get("secrets"))),
        ReportSection("Helm / Kustomize Signals", flatten_list(result.get("helm_kustomize_signals"))),
        ReportSection("Files Detected", flatten_django_detected_files(result.get("files_detected"))),
        ReportSection("Files Reviewed", flatten_list(result.get("files_reviewed"))),
        ReportSection("Findings", flatten_k8s_findings(result.get("findings"))),
        ReportSection("Redaction Notes", flatten_list(result.get("redaction_notes"))),
    ]


def build_terraform_config_sections(result: dict[str, Any]) -> list[ReportSection]:
    return [
        ReportSection(
            "Terraform Config Identification",
            flatten_mapping(as_dict(result.get("file_identification"))) + [("Archive type", stringify(result.get("archive_type")))],
        ),
        ReportSection("Terraform Config Metrics", flatten_mapping(as_dict(result.get("summary")))),
        ReportSection("Terraform Config Limits", flatten_mapping(as_dict(result.get("limits")))),
        ReportSection("Files Detected", flatten_django_detected_files(result.get("files_detected"))),
        ReportSection("Files Reviewed", flatten_list(result.get("files_reviewed"))),
        ReportSection("Providers", flatten_list(result.get("providers"))),
        ReportSection("Backends", flatten_list(result.get("backends"))),
        ReportSection("Modules", flatten_list(result.get("modules"))),
        ReportSection("Resources", flatten_list(result.get("resources"))),
        ReportSection("Variables", flatten_list(result.get("variables"))),
        ReportSection("Outputs", flatten_list(result.get("outputs"))),
        ReportSection("State Files Detected But Not Read", flatten_list(result.get("state_files"))),
        ReportSection("Findings", flatten_terraform_findings(result.get("findings"))),
        ReportSection("Redaction Notes", flatten_list(result.get("redaction_notes"))),
    ]


def build_nginx_config_sections(result: dict[str, Any]) -> list[ReportSection]:
    return [
        ReportSection(
            "Nginx Config Identification",
            flatten_mapping(as_dict(result.get("file_identification"))) + [("Archive type", stringify(result.get("archive_type")))],
        ),
        ReportSection("Nginx Config Metrics", flatten_mapping(as_dict(result.get("summary")))),
        ReportSection("Nginx Config Limits", flatten_mapping(as_dict(result.get("limits")))),
        ReportSection("Files Detected", flatten_django_detected_files(result.get("files_detected"))),
        ReportSection("Files Reviewed", flatten_list(result.get("files_reviewed"))),
        ReportSection("Server Blocks", flatten_list(result.get("servers"))),
        ReportSection("Locations", flatten_list(result.get("locations"))),
        ReportSection("Upstreams", flatten_list(result.get("upstreams"))),
        ReportSection("Includes Detected But Not Resolved", flatten_list(result.get("includes"))),
        ReportSection("Directives", flatten_list(result.get("directives"))),
        ReportSection("Findings", flatten_nginx_findings(result.get("findings"))),
        ReportSection("Redaction Notes", flatten_list(result.get("redaction_notes"))),
    ]


def build_compose_config_sections(result: dict[str, Any]) -> list[ReportSection]:
    return [
        ReportSection(
            "Compose Config Identification",
            flatten_mapping(as_dict(result.get("file_identification"))) + [("Archive type", stringify(result.get("archive_type")))],
        ),
        ReportSection("Compose Config Metrics", flatten_mapping(as_dict(result.get("summary")))),
        ReportSection("Compose Config Limits", flatten_mapping(as_dict(result.get("limits")))),
        ReportSection("Files Detected", flatten_django_detected_files(result.get("files_detected"))),
        ReportSection("Files Reviewed", flatten_list(result.get("files_reviewed"))),
        ReportSection("Services", flatten_list(result.get("services"))),
        ReportSection("Images", flatten_list(result.get("images"))),
        ReportSection("Build Contexts", flatten_list(result.get("build_contexts"))),
        ReportSection("Ports / Exposure", flatten_list(result.get("ports"))),
        ReportSection("Volumes / Mounts", flatten_list(result.get("volumes"))),
        ReportSection("Networks", flatten_list(result.get("networks"))),
        ReportSection("Secrets", flatten_list(result.get("secrets"))),
        ReportSection("Env Files Detected But Not Read", flatten_list(result.get("env_files"))),
        ReportSection("Findings", flatten_compose_findings(result.get("findings"))),
        ReportSection("Redaction Notes", flatten_list(result.get("redaction_notes"))),
    ]


def build_database_config_sections(result: dict[str, Any]) -> list[ReportSection]:
    return [
        ReportSection(
            "Database Config Identification",
            flatten_mapping(as_dict(result.get("file_identification"))) + [("Archive type", stringify(result.get("archive_type")))],
        ),
        ReportSection("Database Config Metrics", flatten_mapping(as_dict(result.get("summary")))),
        ReportSection("Database Config Limits", flatten_mapping(as_dict(result.get("limits")))),
        ReportSection("Files Detected", flatten_django_detected_files(result.get("files_detected"))),
        ReportSection("Files Reviewed", flatten_list(result.get("files_reviewed"))),
        ReportSection("Engines Detected", flatten_list(result.get("engines"))),
        ReportSection("PostgreSQL Settings", flatten_list(result.get("postgres_settings"))),
        ReportSection("pg_hba.conf Rules", flatten_list(result.get("pg_hba_rules"))),
        ReportSection("MySQL / MariaDB Settings", flatten_list(result.get("mysql_settings"))),
        ReportSection("Includes Detected But Not Resolved", flatten_list(result.get("includes"))),
        ReportSection("Dumps / Backups Detected But Not Read", flatten_list(result.get("dump_or_backup_files"))),
        ReportSection("Findings", flatten_database_findings(result.get("findings"))),
        ReportSection("Redaction Notes", flatten_list(result.get("redaction_notes"))),
    ]


def build_sql_database_config_sections(result: dict[str, Any]) -> list[ReportSection]:
    return [
        ReportSection(
            "SQL Database Config Identification",
            flatten_mapping(as_dict(result.get("file_identification"))) + [("Archive type", stringify(result.get("archive_type")))],
        ),
        ReportSection("SQL Database Config Metrics", flatten_mapping(as_dict(result.get("summary")))),
        ReportSection("SQL Database Config Limits", flatten_mapping(as_dict(result.get("limits")))),
        ReportSection("Files Detected", flatten_django_detected_files(result.get("files_detected"))),
        ReportSection("Files Reviewed", flatten_list(result.get("files_reviewed"))),
        ReportSection("PostgreSQL Configs", flatten_list(result.get("postgres_configs"))),
        ReportSection("pg_hba.conf Rules", flatten_list(result.get("postgres_hba_rules"))),
        ReportSection("MySQL / MariaDB Configs", flatten_list(result.get("mysql_configs"))),
        ReportSection("Database Settings", flatten_list(result.get("database_settings"))),
        ReportSection("Includes Detected But Not Resolved", flatten_list(result.get("includes"))),
        ReportSection("Sensitive Files Detected But Not Read", flatten_list(result.get("sensitive_files"))),
        ReportSection("Dumps / Backups Detected But Not Read", flatten_list(result.get("dump_or_backup_files"))),
        ReportSection("Data / WAL / Binlog Files Detected But Not Read", flatten_list(result.get("data_files"))),
        ReportSection("Findings", flatten_sql_database_findings(result.get("findings"))),
        ReportSection("Redaction Notes", flatten_list(result.get("redaction_notes"))),
    ]


def build_redis_config_sections(result: dict[str, Any]) -> list[ReportSection]:
    return [
        ReportSection(
            "Redis Config Identification",
            flatten_mapping(as_dict(result.get("file_identification"))) + [("Archive type", stringify(result.get("archive_type")))],
        ),
        ReportSection("Redis Config Metrics", flatten_mapping(as_dict(result.get("summary")))),
        ReportSection("Redis Config Limits", flatten_mapping(as_dict(result.get("limits")))),
        ReportSection("Files Detected", flatten_django_detected_files(result.get("files_detected"))),
        ReportSection("Files Reviewed", flatten_list(result.get("files_reviewed"))),
        ReportSection("Configs", flatten_list(result.get("configs"))),
        ReportSection("Redis Settings", flatten_list(result.get("redis_settings"))),
        ReportSection("Sentinel Settings", flatten_list(result.get("sentinel_settings"))),
        ReportSection("Includes Detected But Not Resolved", flatten_list(result.get("includes"))),
        ReportSection("ACL Files Detected But Not Read", flatten_list(result.get("acl_files"))),
        ReportSection("Dumps / AOF / Backups Detected But Not Read", flatten_list(result.get("dump_or_aof_files"))),
        ReportSection("Findings", flatten_redis_findings(result.get("findings"))),
        ReportSection("Redaction Notes", flatten_list(result.get("redaction_notes"))),
    ]


def build_active_network_dry_run_sections(result: dict[str, Any]) -> list[ReportSection]:
    public_result = as_dict(redact_active_config_value(result))
    raw_json = json.dumps(public_result, indent=2, sort_keys=True)
    return [
        ReportSection(
            "Active Scope Notice",
            [
                ("No network traffic was sent", "Yes"),
                ("Dry-run purpose", "This dry run records planned checks after authorization and target validation."),
                ("Authorization reminder", "Do not scan third-party systems without permission."),
            ],
        ),
        ReportSection("Target Summary", flatten_mapping(as_dict(public_result.get("target")))),
        ReportSection("Authorization Summary", flatten_mapping(as_dict(public_result.get("authorization")))),
        ReportSection("Policy Decision", flatten_mapping(as_dict(public_result.get("policy")))),
        ReportSection("Planned Checks", flatten_list(public_result.get("planned_checks"))),
        ReportSection("Blocked Reasons", flatten_list(public_result.get("blocked_reasons"))),
        ReportSection("Limits", flatten_mapping(as_dict(public_result.get("limits")))),
        ReportSection("Audit Log", flatten_list(public_result.get("audit_log"))),
        ReportSection("Errors", flatten_list(public_result.get("errors"))),
        ReportSection("Redacted Raw JSON", [("Result", raw_json)]),
    ]


def build_active_http_header_probe_sections(result: dict[str, Any]) -> list[ReportSection]:
    public_result = as_dict(redact_active_config_value(result))
    summary = as_dict(public_result.get("summary"))
    request_sent = int(summary.get("network_requests_sent") or 0)
    raw_json = json.dumps(public_result, indent=2, sort_keys=True)
    scope_notice = "One authorized HTTP HEAD request was sent." if request_sent else "No HTTP request was sent."
    return [
        ReportSection(
            "Active Scope Notice",
            [
                ("Live probe scope", scope_notice),
                ("Response body", "Response body was not read."),
                ("Execution model", "Authorized single-target HTTP HEAD header probe; no Nmap, no subprocess, no redirects."),
                ("Authorization reminder", "Do not test third-party systems without permission."),
            ],
        ),
        ReportSection("Target Summary", flatten_mapping(as_dict(public_result.get("target")))),
        ReportSection("Authorization Summary", flatten_mapping(as_dict(public_result.get("authorization")))),
        ReportSection("Policy Decision", flatten_mapping(as_dict(public_result.get("policy")))),
        ReportSection("DNS Policy Summary", flatten_mapping(as_dict(public_result.get("dns")))),
        ReportSection("Request Sent", flatten_mapping(as_dict(public_result.get("request")))),
        ReportSection("Response Headers", flatten_list(as_dict(public_result.get("response")).get("headers"))),
        ReportSection("Observations", flatten_list(public_result.get("observations"))),
        ReportSection("Findings", flatten_list(public_result.get("findings"))),
        ReportSection("Blocked Reasons", flatten_list(public_result.get("blocked_reasons"))),
        ReportSection("Limits", flatten_mapping(as_dict(public_result.get("limits")))),
        ReportSection("Audit Log", flatten_list(public_result.get("audit_log"))),
        ReportSection("Errors", flatten_list(public_result.get("errors"))),
        ReportSection("Redacted Raw JSON", [("Result", raw_json)]),
    ]


def build_active_nmap_basic_sections(result: dict[str, Any]) -> list[ReportSection]:
    public_result = public_active_nmap_basic_result(result)
    summary = as_dict(public_result.get("summary"))
    limits = as_dict(public_result.get("limits"))
    no_live = is_active_nmap_basic_no_live_result(public_result)
    observations = [] if no_live else flatten_active_nmap_basic_observations(public_result.get("port_observations"))
    raw_json = json.dumps(public_result, indent=2, sort_keys=True)
    status_text = stringify(public_result.get("status", "N/A"))
    lifecycle_state = stringify(public_result.get("lifecycle_state", "N/A"))
    observation_count = summary.get("observation_count", public_result.get("observation_count", len(observations)))
    scope_rows = (
        [
            ("Result wording", "No-live lifecycle record, not a target finding. Manual validation required."),
            ("Nmap execution", "No Nmap executed."),
            ("Network activity", "No network requests. No DNS queries."),
            ("Evidence boundary", "No evidence collected. No observations available."),
            ("Authorization boundary", "Operator confirmation is required but is not proof of target ownership."),
        ]
        if no_live
        else [
            ("Result wording", "Observed TCP exposure; Review indicator; Manual validation required."),
            ("Assertion boundary", "No vulnerability confirmation is asserted."),
            ("Authorization boundary", "Operator confirmation is required but is not proof of target ownership."),
            ("Completeness boundary", "This bounded result does not claim complete port coverage."),
        ]
    )
    observation_title = "No-Live Observation Status" if no_live else "Observed TCP Exposure"
    observation_rows = (
        [
            ("Observation status", "No observations available."),
            ("Evidence status", "No evidence collected."),
            ("Validation", "Manual validation required."),
            ("Interpretation", "No-live lifecycle record, not a target finding."),
        ]
        if no_live
        else observations or [("Observation status", "No TCP port observations were provided; manual validation remains required.")]
    )
    caveat_sections = []
    if no_live:
        caveat_sections.append(
            ReportSection(
                "No-Live Caveats",
                [(f"Caveat {index}", caveat) for index, caveat in enumerate(ACTIVE_NMAP_BASIC_NO_LIVE_CAVEATS, start=1)],
            )
        )
    return [
        ReportSection("Active Nmap Basic Scope Notice", scope_rows),
        ReportSection(
            "Active Nmap Basic Summary",
            [
                ("Capability", stringify(public_result.get("capability", "active_nmap_basic"))),
                ("Profile", stringify(public_result.get("profile", "N/A"))),
                ("Result status", status_text),
                ("Lifecycle state", lifecycle_state),
                ("Controlled state", active_nmap_basic_status_label(status_text)),
                ("Observation count", stringify(observation_count)),
            ],
        ),
        *caveat_sections,
        ReportSection(observation_title, observation_rows),
        ReportSection("Limits", flatten_mapping(limits)),
        ReportSection("Redacted Raw JSON", [("Result", raw_json)]),
    ]


def build_active_tls_basic_sections(result: dict[str, Any]) -> list[ReportSection]:
    public_result = public_active_tls_basic_result(result)
    summary = as_dict(public_result.get("summary"))
    handshake = as_dict(public_result.get("handshake"))
    certificate = as_dict(public_result.get("certificate"))
    limits = as_dict(public_result.get("limits"))
    raw_json = json.dumps(public_result, indent=2, sort_keys=True)
    return [
        ReportSection(
            "Active TLS Basic Scope Notice",
            [
                ("Result wording", "TLS configuration review indicator. Manual validation required."),
                ("Assertion boundary", "No vulnerability confirmation is asserted."),
                ("Traffic boundary", "One bounded TLS handshake attempt; no HTTP request or crawling."),
                ("Authorization boundary", "Operator confirmation is required but is not proof of target ownership."),
                ("Redaction boundary", "Target and certificate raw material are redacted before public surfaces."),
            ],
        ),
        ReportSection(
            "Active TLS Basic Summary",
            [
                ("Capability", stringify(public_result.get("capability", "active_tls_basic"))),
                ("Profile", stringify(public_result.get("profile", "N/A"))),
                ("Result status", stringify(public_result.get("result_status", public_result.get("status", "N/A")))),
                ("Target", stringify(public_result.get("target", "[REDACTED_TARGET]"))),
                ("Port", stringify(public_result.get("port", "N/A"))),
                ("Manual validation", stringify(summary.get("manual_validation_required", True))),
                ("Interpretation", stringify(summary.get("result_interpretation", public_result.get("result_interpretation", "N/A")))),
            ],
        ),
        ReportSection(
            "TLS Handshake Review Indicator",
            [
                ("Handshake status", stringify(handshake.get("status", "N/A"))),
                ("Protocol", stringify(handshake.get("protocol", "N/A"))),
                ("Cipher", stringify(handshake.get("cipher", "N/A"))),
            ],
        ),
        ReportSection(
            "Certificate Summary",
            [
                ("Certificate available", stringify(certificate.get("available", False))),
                ("Subject", stringify(certificate.get("subject", "N/A"))),
                ("Issuer", stringify(certificate.get("issuer", "N/A"))),
                ("SAN count", stringify(certificate.get("san_count", 0))),
                ("SAN sample", stringify(certificate.get("san_sample", []))),
                ("Not before", stringify(certificate.get("not_before", "N/A"))),
                ("Not after", stringify(certificate.get("not_after", "N/A"))),
                ("Days until expiry", stringify(certificate.get("days_until_expiry", "N/A"))),
            ],
        ),
        ReportSection("Active TLS Basic Caveats", [(f"Caveat {index}", caveat) for index, caveat in enumerate(ACTIVE_TLS_BASIC_CAVEATS, start=1)]),
        ReportSection("Limits", flatten_mapping(limits)),
        ReportSection("Redacted Raw JSON", [("Result", raw_json)]),
    ]


def build_active_dns_inventory_sections(result: dict[str, Any]) -> list[ReportSection]:
    public_result = public_active_dns_inventory_result(result)
    summary = as_dict(public_result.get("summary"))
    security_records = as_dict(public_result.get("security_records"))
    subdomains = as_dict(public_result.get("subdomains"))
    zone_transfer = as_dict(public_result.get("zone_transfer"))
    limits = as_dict(public_result.get("limits"))
    raw_json = json.dumps(public_result, indent=2, sort_keys=True)
    return [
        ReportSection(
            "Active DNS Inventory Scope Notice",
            [
                ("Result wording", "DNS configuration review indicator. Manual validation required."),
                ("Assertion boundary", "Complete-zone coverage is asserted only when authorized AXFR completes."),
                ("Discovery boundary", "Standard records, fixed candidate subdomain discovery, and optional authorized AXFR only."),
                ("Authorization boundary", "Operator confirmation is required but is not proof of target ownership."),
                ("Redaction boundary", "Domain, DNS values, raw resolver logs, and packets are redacted before public surfaces."),
            ],
        ),
        ReportSection(
            "Active DNS Inventory Summary",
            [
                ("Capability", stringify(public_result.get("capability", "active_dns_inventory"))),
                ("Profile", stringify(public_result.get("profile", "N/A"))),
                ("Result status", stringify(public_result.get("result_status", public_result.get("status", "N/A")))),
                ("Coverage level", stringify(public_result.get("coverage_level", "N/A"))),
                ("Domain", stringify(public_result.get("domain", "[REDACTED_DOMAIN]"))),
                ("Record types", stringify(public_result.get("record_types", []))),
                ("DNS queries sent", stringify(public_result.get("dns_queries_sent", 0))),
                ("Manual validation", stringify(summary.get("manual_validation_required", True))),
                ("Interpretation", stringify(summary.get("result_interpretation", public_result.get("result_interpretation", "N/A")))),
            ],
        ),
        ReportSection("Standard Records", flatten_active_dns_inventory_record_groups(public_result.get("records"))),
        ReportSection("Security Record Indicators", flatten_mapping(security_records)),
        ReportSection("Authorized Zone Transfer", flatten_mapping(zone_transfer)),
        ReportSection(
            "Bounded Subdomain Discovery",
            [
                ("Enabled", stringify(subdomains.get("enabled", False))),
                ("Strategy", stringify(subdomains.get("strategy", "fixed_candidate_allowlist"))),
                ("Candidates checked", stringify(subdomains.get("candidates_checked", 0))),
                ("Query record types", stringify(subdomains.get("query_record_types", []))),
                ("Observed candidate count", stringify(subdomains.get("count", 0))),
                ("Sample", stringify(subdomains.get("sample", []))),
                ("Sample truncated", stringify(subdomains.get("sample_truncated", False))),
            ],
        ),
        ReportSection("Active DNS Inventory Caveats", [(f"Caveat {index}", caveat) for index, caveat in enumerate(ACTIVE_DNS_INVENTORY_CAVEATS, start=1)]),
        ReportSection("Limits", flatten_mapping(limits)),
        ReportSection("Redacted Raw JSON", [("Result", raw_json)]),
    ]


def flatten_active_dns_inventory_record_groups(value: Any) -> list[tuple[str, str]]:
    if not isinstance(value, dict):
        return []
    rows: list[tuple[str, str]] = []
    for record_type in sorted(value):
        group = as_dict(value.get(record_type))
        rows.append((f"{record_type} count", stringify(group.get("count", 0))))
        rows.append((f"{record_type} sample", stringify(group.get("sample", []))))
        rows.append((f"{record_type} truncated", stringify(group.get("truncated", False))))
    return rows


def flatten_active_nmap_basic_observations(value: Any) -> list[tuple[str, str]]:
    if not isinstance(value, list):
        return []
    rows: list[tuple[str, str]] = []
    preferred_keys = (
        ("Port", "port"),
        ("Protocol", "protocol"),
        ("State", "state"),
        ("Reason", "reason"),
    )
    for index, item in enumerate(value, start=1):
        record = as_dict(item)
        if not record:
            rows.append((f"Observation {index}", stringify(redact_active_nmap_basic_value(item))))
            continue
        append_preferred_rows(rows, f"Observation {index}", record, preferred_keys)
        rows.append((f"Observation {index} Interpretation", "Observed TCP exposure; Review indicator; Manual validation required."))
    return rows


def active_nmap_basic_status_label(status_text: str) -> str:
    return {
        "completed": "Completed structured result; observations are review indicators only.",
        "failed": "Controlled failed state; no vulnerability assertion is made.",
        "not_executed": "Not executed; no Nmap ran and manual validation is required.",
        "timed_out": "Controlled timed-out state; output may be incomplete.",
        "nmap_missing": "Controlled missing-tool state; no result assertion is made.",
        "malformed": "Controlled malformed state; parser could not use the payload safely.",
        "truncated": "Controlled truncated state; output was bounded before reporting.",
        "no_ports": "No TCP port observations were provided; this is not a target safety claim.",
    }.get(status_text, "Controlled state; manual validation required.")


def flatten_django_detected_files(value: Any) -> list[tuple[str, str]]:
    if not isinstance(value, list):
        return []
    rows: list[tuple[str, str]] = []
    preferred_keys = (
        ("Path", "path"),
        ("Category", "category"),
        ("Context", "context"),
        ("Read", "read"),
        ("Skip reason", "skip_reason"),
        ("Size bytes", "size_bytes"),
    )
    for index, item in enumerate(value, start=1):
        record = as_dict(item)
        if not record:
            rows.append((f"File {index}", stringify(item)))
            continue
        append_preferred_rows(rows, f"File {index}", record, preferred_keys)
    return rows


def flatten_docker_detected_files(value: Any) -> list[tuple[str, str]]:
    return flatten_django_detected_files(value)


def flatten_django_findings(value: Any) -> list[tuple[str, str]]:
    if not isinstance(value, list):
        return []
    rows: list[tuple[str, str]] = []
    preferred_keys = (
        ("ID", "id"),
        ("Title", "title"),
        ("Level", "level"),
        ("Context", "context"),
        ("File path", "file_path"),
        ("Description", "description"),
        ("Evidence", "evidence"),
        ("Recommendation", "recommendation"),
    )
    for index, item in enumerate(value, start=1):
        record = as_dict(item)
        if not record:
            rows.append((f"Finding {index}", stringify(item)))
            continue
        append_preferred_rows(rows, f"Finding {index}", record, preferred_keys)
    return rows


def flatten_docker_findings(value: Any) -> list[tuple[str, str]]:
    return flatten_django_findings(value)


def flatten_secrets_findings(value: Any) -> list[tuple[str, str]]:
    if not isinstance(value, list):
        return []
    rows: list[tuple[str, str]] = []
    preferred_keys = (
        ("ID", "id"),
        ("Title", "title"),
        ("Level", "level"),
        ("Confidence", "confidence"),
        ("Category", "category"),
        ("Context", "context"),
        ("File path", "file_path"),
        ("Line", "line"),
        ("Description", "description"),
        ("Evidence", "evidence"),
        ("Recommendation", "recommendation"),
    )
    for index, item in enumerate(value, start=1):
        record = as_dict(item)
        if not record:
            rows.append((f"Finding {index}", stringify(item)))
            continue
        append_preferred_rows(rows, f"Finding {index}", record, preferred_keys)
    return rows


def flatten_ci_cd_findings(value: Any) -> list[tuple[str, str]]:
    if not isinstance(value, list):
        return []
    rows: list[tuple[str, str]] = []
    preferred_keys = (
        ("ID", "id"),
        ("Title", "title"),
        ("Level", "level"),
        ("Confidence", "confidence"),
        ("Category", "category"),
        ("Context", "context"),
        ("Provider", "provider"),
        ("File path", "file_path"),
        ("Job", "job"),
        ("Step", "step"),
        ("Line", "line"),
        ("Description", "description"),
        ("Evidence", "evidence"),
        ("Recommendation", "recommendation"),
    )
    for index, item in enumerate(value, start=1):
        record = as_dict(item)
        if not record:
            rows.append((f"Finding {index}", stringify(item)))
            continue
        append_preferred_rows(rows, f"Finding {index}", record, preferred_keys)
    return rows


def flatten_k8s_findings(value: Any) -> list[tuple[str, str]]:
    if not isinstance(value, list):
        return []
    rows: list[tuple[str, str]] = []
    preferred_keys = (
        ("ID", "id"),
        ("Title", "title"),
        ("Level", "level"),
        ("Confidence", "confidence"),
        ("Category", "category"),
        ("Context", "context"),
        ("Kind", "kind"),
        ("Resource name", "resource_name"),
        ("Namespace", "namespace"),
        ("Container", "container"),
        ("Field path", "field_path"),
        ("File path", "file_path"),
        ("Line", "line"),
        ("Description", "description"),
        ("Evidence", "evidence"),
        ("Recommendation", "recommendation"),
    )
    for index, item in enumerate(value, start=1):
        record = as_dict(item)
        if not record:
            rows.append((f"Finding {index}", stringify(item)))
            continue
        append_preferred_rows(rows, f"Finding {index}", record, preferred_keys)
    return rows


def flatten_terraform_findings(value: Any) -> list[tuple[str, str]]:
    if not isinstance(value, list):
        return []
    rows: list[tuple[str, str]] = []
    preferred_keys = (
        ("ID", "id"),
        ("Code", "code"),
        ("Title", "title"),
        ("Level", "level"),
        ("Confidence", "confidence"),
        ("Category", "category"),
        ("Context", "context"),
        ("Provider", "provider"),
        ("Resource type", "resource_type"),
        ("Resource name", "resource_name"),
        ("Block type", "block_type"),
        ("Field path", "field_path"),
        ("File path", "file_path"),
        ("Line", "line"),
        ("Description", "description"),
        ("Evidence", "evidence"),
        ("Recommendation", "recommendation"),
    )
    for index, item in enumerate(value, start=1):
        record = as_dict(item)
        if not record:
            rows.append((f"Finding {index}", stringify(item)))
            continue
        append_preferred_rows(rows, f"Finding {index}", record, preferred_keys)
    return rows


def flatten_nginx_findings(value: Any) -> list[tuple[str, str]]:
    if not isinstance(value, list):
        return []
    rows: list[tuple[str, str]] = []
    preferred_keys = (
        ("ID", "id"),
        ("Code", "code"),
        ("Title", "title"),
        ("Level", "level"),
        ("Confidence", "confidence"),
        ("Category", "category"),
        ("Context", "context"),
        ("Block type", "block_type"),
        ("Server name", "server_name"),
        ("Location", "location"),
        ("Upstream", "upstream"),
        ("Directive", "directive"),
        ("File path", "file_path"),
        ("Line", "line"),
        ("Description", "description"),
        ("Evidence", "evidence"),
        ("Recommendation", "recommendation"),
    )
    for index, item in enumerate(value, start=1):
        record = as_dict(item)
        if not record:
            rows.append((f"Finding {index}", stringify(item)))
            continue
        append_preferred_rows(rows, f"Finding {index}", record, preferred_keys)
    return rows


def flatten_compose_findings(value: Any) -> list[tuple[str, str]]:
    if not isinstance(value, list):
        return []
    rows: list[tuple[str, str]] = []
    preferred_keys = (
        ("ID", "id"),
        ("Code", "code"),
        ("Title", "title"),
        ("Level", "level"),
        ("Confidence", "confidence"),
        ("Category", "category"),
        ("Context", "context"),
        ("Service", "service"),
        ("Field path", "field_path"),
        ("Image", "image"),
        ("Port", "port"),
        ("Protocol", "protocol"),
        ("Host path", "host_path"),
        ("Container path", "container_path"),
        ("Network", "network"),
        ("File path", "file_path"),
        ("Line", "line"),
        ("Description", "description"),
        ("Evidence", "evidence"),
        ("Recommendation", "recommendation"),
    )
    for index, item in enumerate(value, start=1):
        record = as_dict(item)
        if not record:
            rows.append((f"Finding {index}", stringify(item)))
            continue
        append_preferred_rows(rows, f"Finding {index}", record, preferred_keys)
    return rows


def flatten_database_findings(value: Any) -> list[tuple[str, str]]:
    if not isinstance(value, list):
        return []
    rows: list[tuple[str, str]] = []
    preferred_keys = (
        ("ID", "id"),
        ("Code", "code"),
        ("Title", "title"),
        ("Level", "level"),
        ("Confidence", "confidence"),
        ("Category", "category"),
        ("Context", "context"),
        ("Engine", "engine"),
        ("Section", "section"),
        ("Setting", "setting"),
        ("Auth method", "auth_method"),
        ("Address", "address"),
        ("File path", "file_path"),
        ("Line", "line"),
        ("Description", "description"),
        ("Evidence", "evidence"),
        ("Recommendation", "recommendation"),
    )
    for index, item in enumerate(value, start=1):
        record = as_dict(item)
        if not record:
            rows.append((f"Finding {index}", stringify(item)))
            continue
        append_preferred_rows(rows, f"Finding {index}", record, preferred_keys)
    return rows


def flatten_sql_database_findings(value: Any) -> list[tuple[str, str]]:
    return flatten_database_findings(value)


def flatten_redis_findings(value: Any) -> list[tuple[str, str]]:
    if not isinstance(value, list):
        return []
    rows: list[tuple[str, str]] = []
    preferred_keys = (
        ("ID", "id"),
        ("Code", "code"),
        ("Title", "title"),
        ("Level", "level"),
        ("Confidence", "confidence"),
        ("Category", "category"),
        ("Context", "context"),
        ("Config type", "config_type"),
        ("Directive", "directive"),
        ("Setting", "setting"),
        ("Address", "address"),
        ("Port", "port"),
        ("Path", "path"),
        ("File path", "file_path"),
        ("Line", "line"),
        ("Description", "description"),
        ("Evidence", "evidence"),
        ("Recommendation", "recommendation"),
    )
    for index, item in enumerate(value, start=1):
        record = as_dict(item)
        if not record:
            rows.append((f"Finding {index}", stringify(item)))
            continue
        append_preferred_rows(rows, f"Finding {index}", record, preferred_keys)
    return rows


def append_preferred_rows(
    rows: list[tuple[str, str]],
    prefix: str,
    record: dict[str, Any],
    preferred_keys: Iterable[tuple[str, str]],
) -> None:
    emitted: set[str] = set()
    for label, key in preferred_keys:
        value = record.get(key)
        if value is not None and value != "":
            rows.append((f"{prefix} {label}", stringify(value)))
            emitted.add(key)
    for key, value in record.items():
        if key in emitted or value is None or value == "":
            continue
        rows.append((f"{prefix} {key}", stringify(value)))


def build_summary(job: JobRecord) -> dict[str, Any]:
    result = public_result_for_job(job, as_dict(job.result))
    validation = as_dict(result.get("validation"))
    summary = as_dict(result.get("summary"))
    data: dict[str, Any] = {
        "analyzer": result.get("analyzer", "N/A"),
        "completed_at": result.get("completed_at", "N/A"),
        "status": job.status,
    }
    if job.audit_type == "pdf_basic":
        data["qpdf_ok"] = validation.get("qpdf_ok", "N/A")
        data["warnings"] = validation.get("warnings", [])
    elif job.audit_type == "image_basic":
        data["mime_type"] = validation.get("mime_type", "N/A")
        data["warnings"] = validation.get("warnings", [])
        data["privacy_indicators"] = result.get("privacy_indicators", {})
    elif job.audit_type == "manifest_basic":
        data["manifest_type"] = result.get("manifest_type", "N/A")
        data["total_dependencies"] = summary.get("total_dependencies", "N/A")
        data["informational_findings_count"] = summary.get("informational_findings_count", "N/A")
    elif job.audit_type == "archive_basic":
        data["archive_type"] = result.get("archive_type", "N/A")
        data["total_entries"] = summary.get("total_entries", "N/A")
        data["findings_count"] = summary.get("findings_count", "N/A")
        data["truncated"] = summary.get("truncated", "N/A")
    elif job.audit_type == "project_archive_basic":
        data["archive_type"] = result.get("archive_type", "N/A")
        data["supported_manifests_parsed"] = summary.get("supported_manifests_parsed", "N/A")
        data["total_dependencies"] = summary.get("total_dependencies", "N/A")
        data["findings_count"] = summary.get("findings_count", "N/A")
        data["truncated"] = summary.get("truncated", "N/A")
    elif job.audit_type == "web_basic":
        public_result = as_dict(redact_web_value(result))
        http = as_dict(public_result.get("http"))
        http["response_headers"] = redact_sensitive_headers(as_dict(http.get("response_headers")))
        if "set_cookie_headers" in http:
            http["set_cookie_headers"] = "[redacted]"
        target = as_dict(public_result.get("target"))
        fallback_url = redact_url_query(job.target_url) if job.target_url else "N/A"
        data["target_url"] = target.get("final_url", fallback_url)
        data["status_code"] = http.get("status_code", "N/A")
        data["findings_count"] = summary.get("findings_count", "N/A")
        data["redirects_count"] = summary.get("redirects_count", "N/A")
        data["tls_present"] = summary.get("tls_present", "N/A")
    elif job.audit_type == "domain_basic":
        target = as_dict(result.get("target"))
        data["target_domain"] = target.get("normalized_domain", job.target_domain or "N/A")
        data["records_found_count"] = summary.get("records_found_count", "N/A")
        data["findings_count"] = summary.get("findings_count", "N/A")
        data["spf_present"] = summary.get("spf_present", "N/A")
        data["dmarc_present"] = summary.get("dmarc_present", "N/A")
        data["dmarc_policy"] = summary.get("dmarc_policy", "N/A")
        data["caa_present"] = summary.get("caa_present", "N/A")
        data["mx_present"] = summary.get("mx_present", "N/A")
        data["www_resolves"] = summary.get("www_resolves", "N/A")
    elif job.audit_type == "subdomain_inventory_basic":
        target = as_dict(result.get("target"))
        data["root_domain"] = target.get("normalized_root_domain", job.target_domain or "N/A")
        data["candidates_submitted"] = summary.get("candidates_submitted", "N/A")
        data["candidates_accepted"] = summary.get("candidates_accepted", "N/A")
        data["candidates_rejected"] = summary.get("candidates_rejected", "N/A")
        data["resolved_count"] = summary.get("resolved_count", "N/A")
        data["unresolved_count"] = summary.get("unresolved_count", "N/A")
        data["private_ip_count"] = summary.get("private_ip_count", "N/A")
        data["findings_count"] = summary.get("findings_count", "N/A")
        data["wildcard_dns_possible"] = summary.get("wildcard_dns_possible", "N/A")
    elif job.audit_type == "django_config_basic":
        data["archive_type"] = result.get("archive_type", "N/A")
        data["files_read"] = summary.get("files_read", "N/A")
        data["settings_files_detected"] = summary.get("settings_files_detected", "N/A")
        data["deployment_files_detected"] = summary.get("deployment_files_detected", "N/A")
        data["env_files_detected"] = summary.get("env_files_detected", "N/A")
        data["findings_count"] = summary.get("findings_count", "N/A")
        data["secrets_redacted_count"] = summary.get("secrets_redacted_count", "N/A")
        data["truncated"] = summary.get("truncated", "N/A")
    elif job.audit_type == "docker_config_basic":
        data["archive_type"] = result.get("archive_type", "N/A")
        data["files_reviewed"] = summary.get("files_reviewed", "N/A")
        data["dockerfiles_detected"] = summary.get("dockerfiles_detected", "N/A")
        data["compose_files_detected"] = summary.get("compose_files_detected", "N/A")
        data["services_detected"] = summary.get("services_detected", len(result.get("compose_services") or []))
        data["findings_count"] = summary.get("findings_count", "N/A")
        data["secrets_redacted_count"] = summary.get("secrets_redacted_count", "N/A")
        data["truncated"] = summary.get("truncated", "N/A")
        data["errors_count"] = len(result.get("errors") or [])
    elif job.audit_type == "secrets_review_basic":
        data["archive_type"] = result.get("archive_type", "N/A")
        data["files_considered"] = summary.get("files_considered", "N/A")
        data["files_reviewed"] = summary.get("files_reviewed", "N/A")
        data["sensitive_files_detected"] = summary.get("sensitive_files_detected", "N/A")
        data["findings_count"] = summary.get("findings_count", "N/A")
        data["high_confidence_count"] = summary.get("high_confidence_count", "N/A")
        data["redacted_values_count"] = summary.get("redacted_values_count", "N/A")
        data["truncated"] = summary.get("truncated", "N/A")
        data["errors_count"] = len(result.get("errors") or [])
    elif job.audit_type == "node_package_config_basic":
        data["archive_type"] = result.get("archive_type", "N/A")
        data["files_considered"] = summary.get("files_considered", "N/A")
        data["files_reviewed"] = summary.get("files_reviewed", "N/A")
        data["package_manifests_detected"] = summary.get("package_manifests_detected", "N/A")
        data["lockfiles_detected"] = summary.get("lockfiles_detected", "N/A")
        data["package_manager_configs_detected"] = summary.get("package_manager_configs_detected", "N/A")
        data["packages_detected"] = summary.get("packages_detected", "N/A")
        data["scripts_detected"] = summary.get("scripts_detected", "N/A")
        data["findings_count"] = summary.get("findings_count", "N/A")
        data["redacted_values_count"] = summary.get("redacted_values_count", "N/A")
        data["truncated"] = summary.get("truncated", "N/A")
        data["errors_count"] = len(result.get("errors") or [])
    elif job.audit_type == "ci_cd_config_basic":
        data["archive_type"] = result.get("archive_type", "N/A")
        data["files_considered"] = summary.get("files_considered", "N/A")
        data["files_reviewed"] = summary.get("files_reviewed", "N/A")
        data["workflow_files_detected"] = summary.get("workflow_files_detected", "N/A")
        data["jobs_detected"] = summary.get("jobs_detected", "N/A")
        data["steps_detected"] = summary.get("steps_detected", "N/A")
        data["triggers_detected"] = summary.get("triggers_detected", "N/A")
        data["findings_count"] = summary.get("findings_count", "N/A")
        data["redacted_values_count"] = summary.get("redacted_values_count", "N/A")
        data["truncated"] = summary.get("truncated", "N/A")
        data["errors_count"] = len(result.get("errors") or [])
    elif job.audit_type == "k8s_config_basic":
        data["archive_type"] = result.get("archive_type", "N/A")
        data["files_considered"] = summary.get("files_considered", "N/A")
        data["files_reviewed"] = summary.get("files_reviewed", "N/A")
        data["manifest_files_detected"] = summary.get("manifest_files_detected", "N/A")
        data["resources_detected"] = summary.get("resources_detected", "N/A")
        data["workloads_detected"] = summary.get("workloads_detected", "N/A")
        data["services_detected"] = summary.get("services_detected", "N/A")
        data["secrets_detected"] = summary.get("secrets_detected", "N/A")
        data["rbac_resources_detected"] = summary.get("rbac_resources_detected", "N/A")
        data["findings_count"] = summary.get("findings_count", "N/A")
        data["redacted_values_count"] = summary.get("redacted_values_count", "N/A")
        data["truncated"] = summary.get("truncated", "N/A")
        data["errors_count"] = len(result.get("errors") or [])
    elif job.audit_type == "terraform_config_basic":
        data["archive_type"] = result.get("archive_type", "N/A")
        data["files_considered"] = summary.get("files_considered", "N/A")
        data["files_reviewed"] = summary.get("files_reviewed", "N/A")
        data["terraform_files_detected"] = summary.get("terraform_files_detected", "N/A")
        data["tfvars_files_detected"] = summary.get("tfvars_files_detected", "N/A")
        data["state_files_detected"] = summary.get("state_files_detected", "N/A")
        data["providers_detected"] = summary.get("providers_detected", "N/A")
        data["backends_detected"] = summary.get("backends_detected", "N/A")
        data["modules_detected"] = summary.get("modules_detected", "N/A")
        data["resources_detected"] = summary.get("resources_detected", "N/A")
        data["findings_count"] = summary.get("findings_count", "N/A")
        data["redacted_values_count"] = summary.get("redacted_values_count", "N/A")
        data["truncated"] = summary.get("truncated", "N/A")
        data["errors_count"] = len(result.get("errors") or [])
    elif job.audit_type == "nginx_config_basic":
        data["archive_type"] = result.get("archive_type", "N/A")
        data["files_considered"] = summary.get("files_considered", "N/A")
        data["files_reviewed"] = summary.get("files_reviewed", "N/A")
        data["nginx_files_detected"] = summary.get("nginx_files_detected", "N/A")
        data["server_blocks_detected"] = summary.get("server_blocks_detected", "N/A")
        data["location_blocks_detected"] = summary.get("location_blocks_detected", "N/A")
        data["upstream_blocks_detected"] = summary.get("upstream_blocks_detected", "N/A")
        data["includes_detected"] = summary.get("includes_detected", "N/A")
        data["tls_servers_detected"] = summary.get("tls_servers_detected", "N/A")
        data["findings_count"] = summary.get("findings_count", "N/A")
        data["redacted_values_count"] = summary.get("redacted_values_count", "N/A")
        data["truncated"] = summary.get("truncated", "N/A")
        data["errors_count"] = len(result.get("errors") or [])
    elif job.audit_type == "compose_config_basic":
        data["archive_type"] = result.get("archive_type", "N/A")
        data["files_considered"] = summary.get("files_considered", "N/A")
        data["files_reviewed"] = summary.get("files_reviewed", "N/A")
        data["compose_files_detected"] = summary.get("compose_files_detected", "N/A")
        data["services_detected"] = summary.get("services_detected", "N/A")
        data["networks_detected"] = summary.get("networks_detected", "N/A")
        data["volumes_detected"] = summary.get("volumes_detected", "N/A")
        data["secrets_detected"] = summary.get("secrets_detected", "N/A")
        data["published_ports_detected"] = summary.get("published_ports_detected", "N/A")
        data["env_files_detected"] = summary.get("env_files_detected", "N/A")
        data["findings_count"] = summary.get("findings_count", "N/A")
        data["redacted_values_count"] = summary.get("redacted_values_count", "N/A")
        data["truncated"] = summary.get("truncated", "N/A")
        data["errors_count"] = len(result.get("errors") or [])
    elif job.audit_type == "database_config_basic":
        data["archive_type"] = result.get("archive_type", "N/A")
        data["files_considered"] = summary.get("files_considered", "N/A")
        data["files_reviewed"] = summary.get("files_reviewed", "N/A")
        data["database_files_detected"] = summary.get("database_files_detected", "N/A")
        data["postgres_files_detected"] = summary.get("postgres_files_detected", "N/A")
        data["mysql_files_detected"] = summary.get("mysql_files_detected", "N/A")
        data["mariadb_files_detected"] = summary.get("mariadb_files_detected", "N/A")
        data["pg_hba_files_detected"] = summary.get("pg_hba_files_detected", "N/A")
        data["dump_or_backup_files_detected"] = summary.get("dump_or_backup_files_detected", "N/A")
        data["engines_detected"] = summary.get("engines_detected", "N/A")
        data["findings_count"] = summary.get("findings_count", "N/A")
        data["redacted_values_count"] = summary.get("redacted_values_count", "N/A")
        data["truncated"] = summary.get("truncated", "N/A")
        data["errors_count"] = len(result.get("errors") or [])
    elif job.audit_type == "sql_database_config_basic":
        errors = result.get("errors")
        data["archive_type"] = result.get("archive_type", "N/A")
        data["files_considered"] = summary.get("files_considered", "N/A")
        data["files_reviewed"] = summary.get("files_reviewed", "N/A")
        data["postgres_configs_detected"] = summary.get("postgres_configs_detected", "N/A")
        data["postgres_hba_files_detected"] = summary.get("postgres_hba_files_detected", "N/A")
        data["mysql_configs_detected"] = summary.get("mysql_configs_detected", "N/A")
        data["mariadb_configs_detected"] = summary.get("mariadb_configs_detected", "N/A")
        data["dump_or_backup_files_detected"] = summary.get("dump_or_backup_files_detected", "N/A")
        data["data_files_detected"] = summary.get("data_files_detected", "N/A")
        data["findings_count"] = summary.get("findings_count", "N/A")
        data["redacted_values_count"] = summary.get("redacted_values_count", "N/A")
        data["truncated"] = summary.get("truncated", "N/A")
        data["errors_count"] = len(errors) if isinstance(errors, list) else 1 if errors else 0
    elif job.audit_type == "redis_config_basic":
        data["archive_type"] = result.get("archive_type", "N/A")
        data["files_considered"] = summary.get("files_considered", "N/A")
        data["files_reviewed"] = summary.get("files_reviewed", "N/A")
        data["redis_files_detected"] = summary.get("redis_files_detected", "N/A")
        data["sentinel_files_detected"] = summary.get("sentinel_files_detected", "N/A")
        data["acl_files_detected"] = summary.get("acl_files_detected", "N/A")
        data["dump_or_aof_files_detected"] = summary.get("dump_or_aof_files_detected", "N/A")
        data["configs_detected"] = summary.get("configs_detected", "N/A")
        data["findings_count"] = summary.get("findings_count", "N/A")
        data["redacted_values_count"] = summary.get("redacted_values_count", "N/A")
        data["truncated"] = summary.get("truncated", "N/A")
        data["errors_count"] = len(result.get("errors") or [])
    elif job.audit_type in {"active_network_dry_run", "active_http_header_probe"}:
        target = as_dict(result.get("target"))
        policy = as_dict(result.get("policy"))
        blocked_reasons = result.get("blocked_reasons")
        if not isinstance(blocked_reasons, list):
            blocked_reasons = []
        target_display = target.get("normalized") or target.get("raw") or job.target_url or "N/A"
        data["target_display"] = redact_active_secret_text(str(target_display))
        data["mode"] = result.get("mode", "N/A")
        data["profile"] = result.get("profile", "N/A")
        data["allowed"] = policy.get("allowed", summary.get("allowed", "N/A"))
        data["planned_checks_count"] = summary.get("planned_checks_count", "N/A")
        data["blocked_reasons_count"] = summary.get("blocked_reasons_count", "N/A")
        data["network_requests_sent"] = summary.get("network_requests_sent", "N/A")
        data["redirects_followed"] = summary.get("redirects_followed", "N/A")
        data["body_bytes_read"] = summary.get("body_bytes_read", "N/A")
        data["headers_received_count"] = summary.get("headers_received_count", "N/A")
        data["redacted_headers_count"] = summary.get("redacted_headers_count", "N/A")
        data["truncated_headers_count"] = summary.get("truncated_headers_count", "N/A")
        errors = result.get("errors")
        data["errors_count"] = len(errors) if isinstance(errors, list) else 1 if errors else 0
        data["blocked_reason_codes"] = [
            reason.get("code")
            for reason in blocked_reasons
            if isinstance(reason, dict) and reason.get("code") is not None
        ]
        data["policy_version"] = policy.get("policy_version", "N/A")
    elif job.audit_type == "active_nmap_basic":
        limits = as_dict(result.get("limits"))
        result_summary = as_dict(result.get("summary"))
        execution = as_dict(result.get("execution"))
        observations = result.get("port_observations")
        if not isinstance(observations, list):
            observations = []
        no_live = is_active_nmap_basic_no_live_result(result)
        if no_live:
            observations = []
        data["capability"] = result.get("capability", "active_nmap_basic")
        data["profile"] = result.get("profile", "N/A")
        data["result_status"] = result.get("status", "N/A")
        data["lifecycle_state"] = result.get("lifecycle_state", "N/A")
        data["observation_count"] = result_summary.get("observation_count", result.get("observation_count", len(observations)))
        data["open_tcp_observations_count"] = sum(
            1
            for observation in observations
            if isinstance(observation, dict)
            and str(observation.get("protocol", "")).lower() == "tcp"
            and str(observation.get("state", "")).lower() == "open"
        )
        data["output_truncated"] = limits.get("output_truncated", result.get("output_truncated", "N/A"))
        data["stderr_truncated"] = limits.get("stderr_truncated", result.get("stderr_truncated", "N/A"))
        data["timed_out"] = limits.get("timed_out", result.get("timed_out", "N/A"))
        if no_live:
            data["manual_validation_required"] = True
            data["no_live_lifecycle_record"] = True
            data["surface_interpretation"] = "No-live lifecycle record, not a target finding"
            data["nmap_executed"] = execution.get("nmap_executed", False)
            data["network_requests_sent"] = execution.get("network_requests_sent", 0)
            data["dns_queries_sent"] = execution.get("dns_queries_sent", 0)
            data["evidence_collected"] = False
            data["observations_available"] = False
        else:
            data["manual_validation_required"] = True
            data["no_live_lifecycle_record"] = False
            data["surface_interpretation"] = "Observed TCP exposure / review indicator"
            data["nmap_executed"] = execution.get("nmap_executed", False)
            data["network_requests_sent"] = execution.get("network_requests_sent", 0)
            data["dns_queries_sent"] = execution.get("dns_queries_sent", 0)
            data["evidence_collected"] = execution.get("evidence_available", False)
            data["observations_available"] = bool(observations)
            data["evidence_wording"] = "Observed TCP exposure; Review indicator; Manual validation required."
    elif job.audit_type == "active_tls_basic":
        result = public_active_tls_basic_result(result)
        tls_summary = as_dict(result.get("summary"))
        execution = as_dict(result.get("execution"))
        certificate = as_dict(result.get("certificate"))
        handshake = as_dict(result.get("handshake"))
        data["capability"] = result.get("capability", "active_tls_basic")
        data["profile"] = result.get("profile", "N/A")
        data["result_status"] = result.get("result_status", result.get("status", "N/A"))
        data["target_display"] = "[REDACTED_TARGET]"
        data["port"] = result.get("port", "N/A")
        data["handshake_status"] = handshake.get("status", "N/A")
        data["protocol"] = handshake.get("protocol", "N/A")
        data["cipher"] = handshake.get("cipher", "N/A")
        data["certificate_available"] = certificate.get("available", False)
        data["san_count"] = certificate.get("san_count", 0)
        data["days_until_expiry"] = certificate.get("days_until_expiry", "N/A")
        data["manual_validation_required"] = True
        data["surface_interpretation"] = tls_summary.get("result_interpretation", "TLS configuration review indicator")
        data["tls_handshake_attempted"] = execution.get("tls_handshake_attempted", True)
        data["network_requests_sent"] = execution.get("network_requests_sent", 1)
        data["http_requests_sent"] = execution.get("http_requests_sent", 0)
        data["target_expansion_performed"] = execution.get("target_expansion_performed", False)
        data["dns_expansion_performed"] = execution.get("dns_expansion_performed", False)
    elif job.audit_type == "active_dns_inventory":
        result = public_active_dns_inventory_result(result)
        dns_summary = as_dict(result.get("summary"))
        execution = as_dict(result.get("execution"))
        records = as_dict(result.get("records"))
        security_records = as_dict(result.get("security_records"))
        subdomains = as_dict(result.get("subdomains"))
        data["capability"] = result.get("capability", "active_dns_inventory")
        data["profile"] = result.get("profile", "N/A")
        data["result_status"] = result.get("result_status", result.get("status", "N/A"))
        data["coverage_level"] = result.get("coverage_level", "N/A")
        data["target_display"] = "[REDACTED_DOMAIN]"
        data["record_types"] = result.get("record_types", [])
        data["record_count"] = sum(
            int(group.get("count", 0))
            for group in records.values()
            if isinstance(group, dict) and isinstance(group.get("count", 0), int)
        )
        spf = as_dict(security_records.get("spf"))
        dmarc = as_dict(security_records.get("dmarc"))
        caa = as_dict(security_records.get("caa"))
        data["spf_present"] = spf.get("present", False)
        data["dmarc_present"] = dmarc.get("present", False)
        data["caa_present"] = caa.get("present", False)
        data["subdomain_candidates_checked"] = subdomains.get("candidates_checked", 0)
        data["subdomain_observed_count"] = subdomains.get("count", 0)
        data["manual_validation_required"] = True
        data["surface_interpretation"] = dns_summary.get("result_interpretation", "DNS configuration review indicator")
        data["dns_queries_sent"] = execution.get("dns_queries_sent", result.get("dns_queries_sent", 0))
        data["subdomain_queries_sent"] = execution.get("subdomain_queries_sent", result.get("subdomain_queries_sent", 0))
        data["http_requests_sent"] = execution.get("http_requests_sent", 0)
        data["target_expansion_performed"] = execution.get("target_expansion_performed", False)
        data["recursive_discovery_performed"] = execution.get("recursive_discovery_performed", False)
    return data


def redact_sensitive_headers(headers: dict[str, Any]) -> dict[str, Any]:
    redacted: dict[str, Any] = {}
    for key, value in headers.items():
        if str(key).lower() in SENSITIVE_RESPONSE_HEADERS:
            if isinstance(value, list):
                redacted[key] = ["[redacted]" for _ in value]
            else:
                redacted[key] = "[redacted]"
        else:
            redacted[key] = value
    return redacted


def redact_web_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text_urls(value)
    if isinstance(value, list):
        return [redact_web_value(item) for item in value]
    if isinstance(value, dict):
        return {key: redact_web_value(item) for key, item in value.items()}
    return value


def public_result_for_job(job: JobRecord, result: dict[str, Any]) -> dict[str, Any]:
    if job.audit_type == "web_basic":
        return as_dict(redact_web_value(result))
    if job.audit_type == "django_config_basic":
        return as_dict(redact_django_config_value(result))
    if job.audit_type == "docker_config_basic":
        return as_dict(redact_django_config_value(result))
    if job.audit_type == "secrets_review_basic":
        return as_dict(redact_django_config_value(result))
    if job.audit_type == "node_package_config_basic":
        return as_dict(redact_node_package_config_value(result))
    if job.audit_type == "ci_cd_config_basic":
        return as_dict(redact_ci_cd_config_value(result))
    if job.audit_type == "k8s_config_basic":
        return as_dict(redact_k8s_config_value(result))
    if job.audit_type == "terraform_config_basic":
        return as_dict(redact_terraform_config_value(result))
    if job.audit_type == "nginx_config_basic":
        return as_dict(redact_nginx_config_value(result))
    if job.audit_type == "compose_config_basic":
        return as_dict(redact_compose_config_value(result))
    if job.audit_type == "database_config_basic":
        return as_dict(redact_database_config_value(result))
    if job.audit_type == "sql_database_config_basic":
        return as_dict(redact_sql_database_config_value(result))
    if job.audit_type == "redis_config_basic":
        return as_dict(redact_redis_config_value(result))
    if job.audit_type in {"active_network_dry_run", "active_http_header_probe"}:
        return as_dict(redact_active_config_value(result))
    if job.audit_type == "active_nmap_basic":
        return public_active_nmap_basic_result(result)
    if job.audit_type == "active_tls_basic":
        return public_active_tls_basic_result(result)
    if job.audit_type == "active_dns_inventory":
        return public_active_dns_inventory_result(result)
    return result


def public_active_dns_inventory_result(result: dict[str, Any]) -> dict[str, Any]:
    redacted = as_dict(redact_active_dns_inventory_value(result))
    result_status = str(redacted.get("result_status") or redacted.get("status") or "partial_inventory")
    if result_status not in ACTIVE_DNS_INVENTORY_ALLOWED_STATUSES:
        result_status = "partial_inventory"
    coverage_level = str(redacted.get("coverage_level") or result_status)
    if coverage_level not in {"best_effort_inventory", "partial_inventory", "zone_transfer_complete", "not_executed"}:
        coverage_level = result_status

    records = _public_active_dns_inventory_record_groups(redacted.get("records"))
    security_records = _public_active_dns_inventory_security_records(redacted.get("security_records"))
    subdomains = _public_active_dns_inventory_subdomains(redacted.get("subdomains"))
    zone_transfer = _public_active_dns_inventory_zone_transfer(redacted.get("zone_transfer"))
    execution = as_dict(redacted.get("execution"))
    limits = as_dict(redacted.get("limits"))
    errors = redacted.get("errors")
    if not isinstance(errors, list):
        errors = []

    public_result = {
        "audit_type": "active_dns_inventory",
        "capability": "active_dns_inventory",
        "mode": "live_dns_inventory",
        "profile": "dns_inventory_authorized",
        "status": result_status,
        "result_status": result_status,
        "coverage_level": coverage_level,
        "domain": "[REDACTED_DOMAIN]",
        "record_types": redacted.get("record_types") if isinstance(redacted.get("record_types"), list) else [],
        "records": records,
        "security_records": security_records,
        "subdomains": subdomains,
        "zone_transfer": zone_transfer,
        "provider_import": {"attempted": False, "status": "not_attempted"},
        "dns_queries_sent": execution.get("dns_queries_sent", redacted.get("dns_queries_sent", 0)),
        "subdomain_queries_sent": execution.get("subdomain_queries_sent", redacted.get("subdomain_queries_sent", 0)),
        "summary": {
            "manual_validation_required": True,
            "result_interpretation": "DNS configuration review indicator",
            "coverage_level": coverage_level,
            "spf_present": as_dict(security_records.get("spf")).get("present", False),
            "dmarc_present": as_dict(security_records.get("dmarc")).get("present", False),
            "caa_present": as_dict(security_records.get("caa")).get("present", False),
            "subdomain_observed_count": subdomains.get("count", 0),
            "zone_transfer_status": zone_transfer.get("status", "not_attempted"),
            "zone_transfer_records_retained_count": zone_transfer.get("records_retained_count", 0),
        },
        "execution": {
            "dns_queries_sent": execution.get("dns_queries_sent", redacted.get("dns_queries_sent", 0)),
            "subdomain_queries_sent": execution.get("subdomain_queries_sent", redacted.get("subdomain_queries_sent", 0)),
            "http_requests_sent": 0,
            "subprocess_invoked": False,
            "nmap_invoked": False,
            "target_expansion_performed": False,
            "recursive_discovery_performed": False,
            "zone_transfer_attempted": bool(zone_transfer.get("attempted", False)),
            "provider_api_used": False,
            "credential_validation_performed": False,
            "crawling_performed": False,
        },
        "manual_validation_required": True,
        "result_interpretation": "DNS configuration review indicator",
        "errors": [{"code": stringify(as_dict(error).get("code", "dns_query_error"))} for error in errors[:8]],
        "warnings": [],
        "limits": {
            "timeout_seconds": limits.get("timeout_seconds"),
            "allowed_record_types": limits.get("allowed_record_types"),
            "subdomain_candidates": limits.get("subdomain_candidates"),
            "subdomain_record_types": limits.get("subdomain_record_types"),
            "max_records_per_type": limits.get("max_records_per_type"),
            "max_subdomain_sample": limits.get("max_subdomain_sample"),
            "zone_transfer_timeout_seconds": limits.get("zone_transfer_timeout_seconds"),
            "zone_transfer_max_nameservers": limits.get("zone_transfer_max_nameservers"),
            "zone_transfer_max_records": limits.get("zone_transfer_max_records"),
            "zone_transfer_max_bytes": limits.get("zone_transfer_max_bytes"),
            "domain_value_persisted": False,
            "dns_packets_persisted": False,
            "resolver_logs_persisted": False,
            "zone_file_persisted": False,
        },
        "surface_caveats": list(ACTIVE_DNS_INVENTORY_CAVEATS),
    }
    return as_dict(redact_active_dns_inventory_value(public_result))


def _public_active_dns_inventory_record_groups(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    public_records: dict[str, Any] = {}
    for record_type, group_value in value.items():
        normalized_type = str(record_type).upper()
        if normalized_type not in {"A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "CAA"}:
            continue
        group = as_dict(group_value)
        sample = group.get("sample")
        if not isinstance(sample, list):
            sample = []
        public_records[normalized_type] = {
            "count": group.get("count", 0) if isinstance(group.get("count", 0), int) else 0,
            "sample": [_public_active_dns_inventory_record(record) for record in sample[:12]],
            "truncated": bool(group.get("truncated", False)),
        }
    return public_records


def _public_active_dns_inventory_record(value: Any) -> dict[str, Any]:
    record = as_dict(value)
    public = {
        "name": "[REDACTED_DOMAIN]" if record.get("name") == "[REDACTED_DOMAIN]" else "[REDACTED_DNS_NAME]",
        "type": stringify(record.get("type", "UNKNOWN")),
        "value": "[REDACTED_DNS_VALUE]",
        "ttl": record.get("ttl") if isinstance(record.get("ttl"), int) else None,
    }
    if isinstance(record.get("priority"), int):
        public["priority"] = record.get("priority")
    return public


def _public_active_dns_inventory_security_records(value: Any) -> dict[str, Any]:
    records = as_dict(value)
    spf = as_dict(records.get("spf"))
    dmarc = as_dict(records.get("dmarc"))
    caa = as_dict(records.get("caa"))
    return {
        "spf": {
            "checked": True,
            "present": bool(spf.get("present", False)),
            "record_value": "[REDACTED_DNS_VALUE]" if spf.get("present", False) else None,
            "interpretation": "dns_mail_authentication_review_indicator",
        },
        "dmarc": {
            "checked": True,
            "present": bool(dmarc.get("present", False)),
            "record_value": "[REDACTED_DNS_VALUE]" if dmarc.get("present", False) else None,
            "interpretation": "dns_mail_authentication_review_indicator",
        },
        "caa": {
            "checked": True,
            "present": bool(caa.get("present", False)),
            "record_count": caa.get("record_count", 0) if isinstance(caa.get("record_count", 0), int) else 0,
            "interpretation": "dns_certificate_authority_review_indicator",
        },
        "dkim": {"checked": False, "status": "not_attempted"},
    }


def _public_active_dns_inventory_subdomains(value: Any) -> dict[str, Any]:
    subdomains = as_dict(value)
    sample = subdomains.get("sample")
    if not isinstance(sample, list):
        sample = []
    return {
        "enabled": bool(subdomains.get("enabled", False)),
        "strategy": "fixed_candidate_allowlist",
        "candidates_checked": subdomains.get("candidates_checked", 0) if isinstance(subdomains.get("candidates_checked", 0), int) else 0,
        "query_record_types": subdomains.get("query_record_types") if isinstance(subdomains.get("query_record_types"), list) else [],
        "count": subdomains.get("count", 0) if isinstance(subdomains.get("count", 0), int) else 0,
        "sample": [
            {
                "name": "[REDACTED_DNS_NAME]",
                "record_types": item.get("record_types") if isinstance(item, dict) and isinstance(item.get("record_types"), list) else [],
                "record_count": item.get("record_count", 0) if isinstance(item, dict) and isinstance(item.get("record_count", 0), int) else 0,
            }
            for item in sample[:12]
        ],
        "sample_truncated": bool(subdomains.get("sample_truncated", False)),
    }


def _public_active_dns_inventory_zone_transfer(value: Any) -> dict[str, Any]:
    zone_transfer = as_dict(value)
    status_value = stringify(zone_transfer.get("status", "not_attempted"))
    allowed_statuses = {
        "not_attempted",
        "authorization_required",
        "no_authoritative_nameservers",
        "refused",
        "unavailable",
        "timed_out",
        "malformed_response",
        "record_limit_exceeded",
        "zone_transfer_complete",
    }
    if status_value not in allowed_statuses:
        status_value = "unavailable"
    reason_code = stringify(zone_transfer.get("reason_code", status_value))
    public = {
        "attempted": bool(zone_transfer.get("attempted", False)),
        "status": status_value,
        "nameservers_considered": zone_transfer.get("nameservers_considered", 0)
        if isinstance(zone_transfer.get("nameservers_considered", 0), int)
        else 0,
        "nameservers_attempted": zone_transfer.get("nameservers_attempted", 0)
        if isinstance(zone_transfer.get("nameservers_attempted", 0), int)
        else 0,
        "records_received_count": zone_transfer.get("records_received_count", 0)
        if isinstance(zone_transfer.get("records_received_count", 0), int)
        else 0,
        "records_retained_count": zone_transfer.get("records_retained_count", 0)
        if isinstance(zone_transfer.get("records_retained_count", 0), int)
        else 0,
        "truncated": bool(zone_transfer.get("truncated", False)),
    }
    if status_value != "zone_transfer_complete":
        public["reason_code"] = reason_code
    else:
        public["interpretation"] = "zone transfer accepted by authoritative server / high-risk configuration review indicator"
    return public


def public_active_tls_basic_result(result: dict[str, Any]) -> dict[str, Any]:
    redacted = as_dict(redact_active_tls_basic_value(result))
    result_status = str(redacted.get("result_status") or redacted.get("status") or "tls_error_controlled")
    if result_status not in ACTIVE_TLS_BASIC_ALLOWED_STATUSES:
        result_status = "tls_error_controlled"

    handshake = as_dict(redacted.get("handshake"))
    certificate = as_dict(redacted.get("certificate"))
    summary = as_dict(redacted.get("summary"))
    execution = as_dict(redacted.get("execution"))
    limits = as_dict(redacted.get("limits"))
    reason_codes = redacted.get("reason_codes")
    if not isinstance(reason_codes, list):
        reason_codes = []
    san_sample = certificate.get("san_sample")
    if not isinstance(san_sample, list):
        san_sample = []
    errors = redacted.get("errors")
    if not isinstance(errors, list):
        errors = []

    public_result = {
        "audit_type": "active_tls_basic",
        "capability": "active_tls_basic",
        "mode": "live_tls_basic",
        "profile": "tls_handshake_summary",
        "status": result_status,
        "result_status": result_status,
        "target": "[REDACTED_TARGET]",
        "port": redacted.get("port"),
        "handshake": {
            "status": stringify(handshake.get("status", result_status)),
            "protocol": handshake.get("protocol"),
            "cipher": handshake.get("cipher"),
        },
        "certificate": {
            "available": bool(certificate.get("available", False)),
            "subject": certificate.get("subject"),
            "issuer": certificate.get("issuer"),
            "san_count": certificate.get("san_count", 0),
            "san_sample": san_sample[:3],
            "not_before": certificate.get("not_before"),
            "not_after": certificate.get("not_after"),
            "days_until_expiry": certificate.get("days_until_expiry"),
        },
        "summary": {
            "manual_validation_required": True,
            "result_interpretation": "tls_configuration_review_indicator",
            "certificate_available": bool(certificate.get("available", summary.get("certificate_available", False))),
            "san_count": certificate.get("san_count", summary.get("san_count", 0)),
            "reason_codes": [stringify(code) for code in reason_codes[:8]],
        },
        "execution": {
            "tls_handshake_attempted": bool(execution.get("tls_handshake_attempted", True)),
            "network_requests_sent": execution.get("network_requests_sent", 1),
            "http_requests_sent": 0,
            "target_expansion_performed": False,
            "dns_expansion_performed": False,
            "crawling_performed": False,
            "credential_validation_performed": False,
        },
        "manual_validation_required": True,
        "result_interpretation": "tls_configuration_review_indicator",
        "reason_codes": [stringify(code) for code in reason_codes[:8]],
        "errors": [{"code": stringify(as_dict(error).get("code", "tls_error_controlled"))} for error in errors[:8]],
        "warnings": [],
        "limits": {
            "connect_timeout_seconds": limits.get("connect_timeout_seconds"),
            "handshake_timeout_seconds": limits.get("handshake_timeout_seconds"),
            "max_san_sample": limits.get("max_san_sample", 3),
            "max_text_length": limits.get("max_text_length", 160),
            "raw_certificate_persisted": False,
            "raw_target_persisted": False,
        },
        "surface_caveats": list(ACTIVE_TLS_BASIC_CAVEATS),
    }
    return as_dict(redact_active_tls_basic_value(public_result))


def public_active_nmap_basic_result(result: dict[str, Any]) -> dict[str, Any]:
    public_result = as_dict(redact_active_nmap_basic_value(result))
    if not is_active_nmap_basic_no_live_result(public_result):
        summary = as_dict(public_result.get("summary"))
        execution = as_dict(public_result.get("execution"))
        observations = public_result.get("port_observations")
        if not isinstance(observations, list):
            observations = []
        summary.update(
            {
                "manual_validation_required": True,
                "no_live_lifecycle_record": False,
                "nmap_executed": execution.get("nmap_executed", False),
                "network_requests_sent": execution.get("network_requests_sent", 0),
                "dns_queries_sent": execution.get("dns_queries_sent", 0),
                "evidence_collected": execution.get("evidence_available", False),
                "observations_available": bool(observations),
                "surface_interpretation": "Observed TCP exposure / review indicator",
            }
        )
        public_result["summary"] = summary
        public_result["surface_caveats"] = list(ACTIVE_NMAP_BASIC_REAL_MINIMAL_CAVEATS)
        public_result["surface_interpretation"] = "Observed TCP exposure / review indicator"
        return public_result

    for key in ACTIVE_NMAP_BASIC_NO_LIVE_OMITTED_KEYS:
        public_result.pop(key, None)

    summary = as_dict(public_result.get("summary"))
    summary.update(
        {
            "manual_validation_required": True,
            "no_live_lifecycle_record": True,
            "nmap_executed": False,
            "network_requests_sent": 0,
            "dns_queries_sent": 0,
            "evidence_collected": False,
            "observations_available": False,
            "surface_interpretation": "No-live lifecycle record, not a target finding",
        }
    )
    public_result["summary"] = summary
    public_result["execution"] = {
        "nmap_executed": False,
        "network_requests_sent": 0,
        "dns_queries_sent": 0,
        "subprocess_invoked": False,
        "active_tools_real_call_allowed": False,
        "target_expansion_performed": False,
        "evidence_available": False,
    }
    public_result["surface_caveats"] = list(ACTIVE_NMAP_BASIC_NO_LIVE_CAVEATS)
    public_result["surface_interpretation"] = "No-live lifecycle record, not a target finding"
    return public_result


def is_active_nmap_basic_no_live_result(result: dict[str, Any]) -> bool:
    return result.get("lifecycle_state") in ACTIVE_NMAP_BASIC_NO_LIVE_STATES


def public_job_target_url(job: JobRecord) -> str:
    if not job.target_url:
        return ""
    if job.audit_type in {"active_network_dry_run", "active_http_header_probe"}:
        return redact_active_secret_text(job.target_url)
    if job.audit_type == "active_nmap_basic":
        return "[REDACTED_TARGET]"
    if job.audit_type == "active_tls_basic":
        return "[REDACTED_TARGET]"
    if job.audit_type == "active_dns_inventory":
        return "[REDACTED_DOMAIN]"
    return redact_url_query(job.target_url)


def public_job_error(job: JobRecord) -> str:
    if not job.error:
        return ""
    if job.audit_type == "web_basic":
        return redact_text_urls(job.error)
    if job.audit_type == "django_config_basic":
        return redact_django_secret_text(job.error)
    if job.audit_type == "docker_config_basic":
        return redact_django_secret_text(job.error)
    if job.audit_type == "secrets_review_basic":
        return redact_django_secret_text(job.error)
    if job.audit_type == "node_package_config_basic":
        return redact_node_package_secret_text(job.error)
    if job.audit_type == "ci_cd_config_basic":
        return redact_ci_cd_secret_text(job.error)
    if job.audit_type == "k8s_config_basic":
        return redact_k8s_secret_text(job.error)
    if job.audit_type == "terraform_config_basic":
        return redact_terraform_secret_text(job.error)
    if job.audit_type == "nginx_config_basic":
        return redact_nginx_secret_text(job.error)
    if job.audit_type == "compose_config_basic":
        return redact_compose_secret_text(job.error)
    if job.audit_type == "database_config_basic":
        return redact_database_secret_text(job.error)
    if job.audit_type == "sql_database_config_basic":
        return redact_sql_database_secret_text(job.error)
    if job.audit_type == "redis_config_basic":
        return redact_redis_secret_text(job.error)
    if job.audit_type in {"active_network_dry_run", "active_http_header_probe"}:
        return redact_active_secret_text(job.error)
    if job.audit_type == "active_nmap_basic":
        return redact_active_nmap_basic_text(job.error, collect_active_nmap_basic_sensitive_tokens(job.result or {}))
    if job.audit_type == "active_tls_basic":
        return redact_active_tls_basic_text(job.error, collect_active_tls_basic_sensitive_tokens(job.result or {}))
    if job.audit_type == "active_dns_inventory":
        return redact_active_dns_inventory_text(job.error, collect_active_dns_inventory_sensitive_tokens(job.result or {}))
    return job.error


def redact_django_config_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact_django_secret_text(value)
    if isinstance(value, list):
        return [redact_django_config_value(item) for item in value]
    if isinstance(value, dict):
        return {
            key: "[REDACTED]" if is_secret_like_mapping_key(str(key)) else redact_django_config_value(item)
            for key, item in value.items()
        }
    return value


def is_secret_like_mapping_key(key: str) -> bool:
    normalized = key.lower().replace("-", "_")
    if "redacted" in normalized or normalized.endswith("_count"):
        return False
    return any(token in normalized for token in SECRET_LIKE_MAPPING_TOKENS)


def redact_django_secret_text(value: str) -> str:
    redacted = re.sub(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
        "[REDACTED PRIVATE KEY]",
        value,
        flags=re.IGNORECASE | re.DOTALL,
    )
    redacted = re.sub(r"(?i)django-insecure-[^\s'\"<>)\]}]+", "django-insecure-[REDACTED]", redacted)
    redacted = JWT_LIKE_RE.sub("[REDACTED JWT]", redacted)
    redacted = SENSITIVE_QUERY_PARAM_RE.sub(lambda match: f"{match.group(1)}[REDACTED]", redacted)
    redacted = re.sub(
        r"(?i)\b((?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|https?)://)([^@\s/]+)@",
        r"\1[REDACTED]@",
        redacted,
    )
    redacted = re.sub(
        r"(?i)\b((?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|https?)://):([^@\s]+)@",
        r"\1[REDACTED]@",
        redacted,
    )
    keywords = "|".join(re.escape(keyword) for keyword in DJANGO_SECRET_KEYWORDS)
    quoted_pattern = re.compile(rf"(?i)\b({keywords})\b(\s*[:=]\s*)(['\"])(.*?)(['\"])")
    redacted = quoted_pattern.sub(lambda match: f"{match.group(1)}{match.group(2)}{match.group(3)}[REDACTED]{match.group(5)}", redacted)
    bare_pattern = re.compile(rf"(?i)\b({keywords})\b(\s*[:=]\s*)([^\s,}}\n]+)")
    return bare_pattern.sub(lambda match: f"{match.group(1)}{match.group(2)}[REDACTED]", redacted)


def redact_node_package_config_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact_node_package_secret_text(value)
    if isinstance(value, list):
        return [redact_node_package_config_value(item) for item in value]
    if isinstance(value, dict):
        secret_named_value = node_package_record_has_secret_name(value)
        return {
            key: "[REDACTED]"
            if is_node_package_secret_mapping_key(str(key)) or (secret_named_value and str(key).lower() in {"value", "raw_value", "default"})
            else redact_node_package_config_value(item)
            for key, item in value.items()
        }
    return value


def node_package_record_has_secret_name(record: dict[str, Any]) -> bool:
    for marker in ("key", "name", "setting", "variable", "env"):
        candidate = record.get(marker)
        if candidate is not None and is_node_package_secret_mapping_key(str(candidate)):
            return True
    return False


def is_node_package_secret_mapping_key(key: str) -> bool:
    normalized = key.lower().replace("-", "_")
    if "redacted" in normalized or normalized.endswith("_count"):
        return False
    return any(
        token in normalized
        for token in (
            "_auth",
            "auth_token",
            "authtoken",
            "_password",
            "password",
            "passwd",
            "api_key",
            "apikey",
            "private_key",
            "token",
            "secret",
        )
    )


def redact_node_package_secret_text(value: str) -> str:
    redacted = redact_django_secret_text(value)
    redacted = re.sub(
        r"(?i)\b([a-z][a-z0-9+.-]*://)([^:\s/@]+):([^@\s]+)@",
        r"\1[REDACTED]@",
        redacted,
    )
    redacted = re.sub(
        r"(?i)(^|[\s,{])([A-Z0-9_.:/@-]*(?:_authToken|_auth|_password|password|token|api_key|apikey|secret|key)[A-Z0-9_.:/@-]*)(\s*[:=]\s*)(['\"]?)[^\s,'\"}\]]+",
        lambda match: f"{match.group(1)}{match.group(2)}{match.group(3)}{match.group(4)}[REDACTED]",
        redacted,
    )
    return redacted


def redact_ci_cd_config_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact_ci_cd_secret_text(value)
    if isinstance(value, list):
        return [redact_ci_cd_config_value(item) for item in value]
    if isinstance(value, dict):
        secret_named_value = ci_cd_record_has_secret_name(value)
        return {
            key: "[REDACTED]"
            if is_ci_cd_secret_mapping_key(str(key)) or (secret_named_value and str(key).lower() in {"value", "raw_value", "default"})
            else redact_ci_cd_config_value(item)
            for key, item in value.items()
        }
    return value


def ci_cd_record_has_secret_name(record: dict[str, Any]) -> bool:
    for marker in ("key", "name", "setting", "variable", "env"):
        candidate = record.get(marker)
        if candidate is not None and is_ci_cd_secret_mapping_key(str(candidate)):
            return True
    return False


def is_ci_cd_secret_mapping_key(key: str) -> bool:
    normalized = key.lower().replace("-", "_")
    if "redacted" in normalized or normalized.endswith("_count"):
        return False
    return any(
        token in normalized
        for token in (
            "access_token",
            "refresh_token",
            "id_token",
            "auth_token",
            "authtoken",
            "client_secret",
            "private_key",
            "api_key",
            "apikey",
            "password",
            "passwd",
            "token",
            "secret",
        )
    )


def redact_ci_cd_secret_text(value: str) -> str:
    redacted = redact_node_package_secret_text(value).replace("[REDACTED PRIVATE KEY]", "[REDACTED]")
    redacted = re.sub(
        r"(?i)\bAuthorization\s*:\s*(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+",
        "Authorization: [REDACTED]",
        redacted,
    )
    redacted = re.sub(r"(?i)\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+", "[REDACTED]", redacted)
    redacted = re.sub(r"(?i)(\bAuthorization\s+)(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+", r"\1[REDACTED]", redacted)
    return redacted.replace("[REDACTED]]", "[REDACTED]")


def redact_k8s_config_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact_k8s_secret_text(value)
    if isinstance(value, list):
        return [redact_k8s_config_value(item) for item in value]
    if isinstance(value, dict):
        secret_named_value = k8s_record_has_secret_name(value)
        return {
            key: "[REDACTED]"
            if is_k8s_secret_mapping_key(str(key))
            or (secret_named_value and str(key).lower() in {"value", "raw_value", "default", "data", "stringdata", "string_data"})
            else redact_k8s_config_value(item)
            for key, item in value.items()
        }
    return value


def k8s_record_has_secret_name(record: dict[str, Any]) -> bool:
    for marker in ("key", "name", "setting", "variable", "env", "field_path"):
        candidate = record.get(marker)
        if candidate is not None and is_k8s_secret_mapping_key(str(candidate)):
            return True
    return False


def is_k8s_secret_mapping_key(key: str) -> bool:
    normalized = key.lower().replace("-", "_")
    if "redacted" in normalized or normalized.endswith("_count"):
        return False
    if normalized in {"secret", "secrets"}:
        return False
    if normalized in {"data", "stringdata", "string_data"}:
        return True
    return any(
        token in normalized
        for token in (
            "access_token",
            "refresh_token",
            "id_token",
            "auth_token",
            "client_secret",
            "private_key",
            "api_key",
            "apikey",
            "password",
            "passwd",
            "token",
            "secret",
        )
    )


def redact_k8s_secret_text(value: str) -> str:
    redacted = redact_ci_cd_secret_text(value).replace("[REDACTED PRIVATE KEY]", "[REDACTED]")
    return re.sub(
        r"(?i)\b(?:[a-z0-9._-]*user|username|login):(?:[a-z0-9._-]*(?:pass|password|secret|token|key)[a-z0-9._-]*)\b",
        "[REDACTED]",
        redacted,
    )


def redact_terraform_config_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact_terraform_secret_text(value)
    if isinstance(value, list):
        return [redact_terraform_config_value(item) for item in value]
    if isinstance(value, dict):
        secret_named_value = terraform_record_has_secret_name(value)
        return {
            key: "[REDACTED]"
            if is_terraform_secret_mapping_key(str(key))
            or (secret_named_value and str(key).lower() in {"value", "raw_value", "default", "data", "content", "user_data"})
            else redact_terraform_config_value(item)
            for key, item in value.items()
        }
    return value


def terraform_record_has_secret_name(record: dict[str, Any]) -> bool:
    for marker in ("key", "name", "setting", "variable", "field_path", "attribute", "output"):
        candidate = record.get(marker)
        if candidate is not None and is_terraform_secret_mapping_key(str(candidate)):
            return True
    return False


def is_terraform_secret_mapping_key(key: str) -> bool:
    normalized = key.lower().replace("-", "_")
    if "redacted" in normalized or normalized.endswith("_count"):
        return False
    if normalized in {"content", "raw", "raw_content", "state", "state_content", "terraform_state", "tfstate"}:
        return True
    return any(
        token in normalized
        for token in (
            "access_key",
            "secret_key",
            "session_token",
            "client_secret",
            "private_key",
            "api_key",
            "apikey",
            "password",
            "passwd",
            "token",
            "secret",
            "credential",
            "connection_string",
            "user_data",
            "startup_script",
            "certificate",
        )
    )


def redact_terraform_secret_text(value: str) -> str:
    redacted = redact_k8s_secret_text(value).replace("[REDACTED PRIVATE KEY]", "[REDACTED]")
    redacted = re.sub(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
        "[REDACTED]",
        redacted,
        flags=re.IGNORECASE | re.DOTALL,
    )
    redacted = re.sub(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b", "[REDACTED]", redacted)
    redacted = re.sub(r"(?i)\bprivate\s+key\b[^\n,;}\]]*", "[REDACTED]", redacted)
    redacted = re.sub(
        r"(?i)\b([A-Z0-9_.-]*(?:access_key|secret_key|session_token|client_secret|private_key|api_key|apikey|password|passwd|token|secret|credential|connection_string)[A-Z0-9_.-]*)(\s*[:=]\s*)(['\"]?)[^\s,'\"}\]]+",
        lambda match: f"{match.group(1)}{match.group(2)}{match.group(3)}[REDACTED]",
        redacted,
    )
    return redacted


def redact_nginx_config_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact_nginx_secret_text(value)
    if isinstance(value, list):
        return [redact_nginx_config_value(item) for item in value]
    if isinstance(value, dict):
        secret_named_value = nginx_record_has_secret_name(value)
        return {
            key: "[REDACTED]"
            if is_nginx_secret_mapping_key(str(key))
            or (secret_named_value and str(key).lower() in {"value", "raw_value", "default", "data", "content", "arguments"})
            else redact_nginx_config_value(item)
            for key, item in value.items()
        }
    return value


def nginx_record_has_secret_name(record: dict[str, Any]) -> bool:
    for marker in ("key", "name", "setting", "variable", "field_path", "directive", "header", "argument", "arguments"):
        candidate = record.get(marker)
        if candidate is not None and is_nginx_secret_mapping_key(str(candidate)):
            return True
    return False


def is_nginx_secret_mapping_key(key: str) -> bool:
    normalized = key.lower().replace("-", "_")
    if "redacted" in normalized or normalized.endswith("_count"):
        return False
    if normalized in {"content", "raw", "raw_content", "private_key", "certificate_key", "ssl_certificate_key"}:
        return True
    return any(
        token in normalized
        for token in (
            "authorization",
            "bearer",
            "auth_basic",
            "basic_auth",
            "cookie",
            "session",
            "access_token",
            "refresh_token",
            "auth_token",
            "client_secret",
            "private_key",
            "api_key",
            "apikey",
            "password",
            "passwd",
            "token",
            "secret",
            "credential",
        )
    )


def redact_nginx_secret_text(value: str) -> str:
    redacted = redact_terraform_secret_text(value).replace("[REDACTED PRIVATE KEY]", "[REDACTED]")
    redacted = re.sub(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
        "[REDACTED]",
        redacted,
        flags=re.IGNORECASE | re.DOTALL,
    )
    redacted = re.sub(r"(?i)\b([a-z][a-z0-9+.-]*://)([^:\s/@;\"']+):([^@\s/;\"']+)@([^\s;\"']+)", r"\1[REDACTED]@\4", redacted)
    redacted = re.sub(r"(?i)\bAuthorization\s*:\s*(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+", "Authorization: [REDACTED]", redacted)
    redacted = re.sub(r"(?i)\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+", "[REDACTED]", redacted)
    redacted = re.sub(
        r"(?i)\b(?:[a-z0-9._-]*user|username|login):(?:[a-z0-9._-]*(?:pass|password|secret|token|key)[a-z0-9._-]*)\b",
        "[REDACTED]",
        redacted,
    )
    redacted = re.sub(r"(?i)\b(requirepass|masterauth|auth_basic)\s+[^;\s]+", r"\1 [REDACTED]", redacted)
    redacted = re.sub(
        r"(?i)\b([A-Z0-9_$_.-]*(?:authorization|cookie|session|client_secret|private_key|api_key|apikey|password|passwd|token|secret|credential)[A-Z0-9_$_.-]*)(\s*[:=]\s*)(['\"]?)[^\s,'\";}\]]+",
        lambda match: f"{match.group(1)}{match.group(2)}{match.group(3)}[REDACTED]",
        redacted,
    )
    redacted = redacted.replace("PRIVATE KEY", "[REDACTED]")
    return re.sub(r"\[REDACTED\]\]+", "[REDACTED]", redacted)


def redact_compose_config_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact_compose_secret_text(value)
    if isinstance(value, list):
        return [redact_compose_config_value(item) for item in value]
    if isinstance(value, dict):
        secret_named_value = compose_record_has_secret_name(value)
        redacted: dict[Any, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            if is_compose_secret_mapping_key(key_text) or (
                secret_named_value
                and key_text.lower()
                in {"value", "raw_value", "default", "data", "content", "environment", "labels", "command", "entrypoint", "arguments"}
            ):
                redacted[key] = "[REDACTED]"
            else:
                redacted[key] = redact_compose_config_value(item)
        return redacted
    return value


def compose_record_has_secret_name(record: dict[str, Any]) -> bool:
    for marker in (
        "key",
        "name",
        "setting",
        "variable",
        "field_path",
        "env",
        "environment",
        "label",
        "labels",
        "command",
        "entrypoint",
        "arguments",
    ):
        candidate = record.get(marker)
        if candidate is not None and is_compose_secret_mapping_key(str(candidate)):
            return True
    return False


def is_compose_secret_mapping_key(key: str) -> bool:
    normalized = key.lower().replace("-", "_")
    if "redacted" in normalized or normalized.endswith("_count"):
        return False
    if normalized in {"secret", "secrets"}:
        return False
    if normalized in {"content", "raw", "raw_content", "private_key", "env_file_content", "secret_file_content"}:
        return True
    return any(
        token in normalized
        for token in (
            "bearer",
            "cookie",
            "session",
            "access_token",
            "refresh_token",
            "auth_token",
            "client_secret",
            "private_key",
            "api_key",
            "apikey",
            "password",
            "passwd",
            "token",
            "secret",
            "credential",
            "database_url",
            "redis_url",
            "registry_auth",
            "connection_string",
        )
    )


def redact_compose_secret_text(value: str) -> str:
    redacted = redact_nginx_secret_text(value).replace("[REDACTED PRIVATE KEY]", "[REDACTED]")
    redacted = re.sub(
        r"(?i)\b(?:super-secret-password|raw-api-key-[a-z0-9_-]+|[a-z0-9_.-]*should_(?:never|not)_render[a-z0-9_.-]*|db_password_plaintext)\b",
        "[REDACTED]",
        redacted,
    )
    redacted = re.sub(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
        "[REDACTED]",
        redacted,
        flags=re.IGNORECASE | re.DOTALL,
    )
    redacted = re.sub(
        r"(?i)\b([a-z][a-z0-9+.-]*://)([^/\s:@;\"']*):([^@\s/;\"']+)@([^\s;\"']+)",
        r"\1[REDACTED]@\4",
        redacted,
    )
    redacted = re.sub(
        r"(?i)\b([A-Z0-9_$_.-]*(?:authorization|cookie|session|client_secret|private_key|api_key|apikey|password|passwd|token|secret|credential|database_url|redis_url)[A-Z0-9_$_.-]*)(\s*[:=]\s*)(['\"]?)[^\s,'\";}\]]+",
        lambda match: f"{match.group(1)}{match.group(2)}{match.group(3)}[REDACTED]",
        redacted,
    )
    redacted = redacted.replace("PRIVATE KEY", "[REDACTED]")
    return re.sub(r"\[REDACTED\]\]+", "[REDACTED]", redacted)


def redact_database_config_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact_database_secret_text(value)
    if isinstance(value, list):
        return [redact_database_config_value(item) for item in value]
    if isinstance(value, dict):
        secret_named_value = database_record_has_secret_name(value)
        redacted: dict[Any, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            if is_database_secret_mapping_key(key_text) or (
                secret_named_value
                and key_text.lower()
                in {"value", "raw_value", "default", "data", "content", "sql", "statement", "arguments", "connection_string", "dsn"}
            ):
                redacted[key] = "[REDACTED]"
            else:
                redacted[key] = redact_database_config_value(item)
        return redacted
    return value


def database_record_has_secret_name(record: dict[str, Any]) -> bool:
    for marker in (
        "key",
        "name",
        "setting",
        "variable",
        "field_path",
        "attribute",
        "directive",
        "target",
        "environment",
        "env",
        "error",
    ):
        candidate = record.get(marker)
        if candidate is not None and is_database_secret_mapping_key(str(candidate)):
            return True
    return False


def is_database_secret_mapping_key(key: str) -> bool:
    normalized = key.lower().replace("-", "_")
    if "redacted" in normalized or normalized.endswith("_count"):
        return False
    if normalized in {
        "content",
        "raw",
        "raw_content",
        "dump_content",
        "backup_content",
        "sql",
        "statement",
        "private_key",
        "certificate_key",
        "pgpass",
        "pg_service",
        "my_cnf",
        "mylogin_cnf",
        "env_file_content",
        "credential_file_content",
    }:
        return True
    return any(
        token in normalized
        for token in (
            "authorization",
            "access_token",
            "refresh_token",
            "auth_token",
            "client_secret",
            "private_key",
            "api_key",
            "apikey",
            "password",
            "passwd",
            "pgpassword",
            "mysql_pwd",
            "token",
            "secret",
            "credential",
            "database_url",
            "connection_string",
            "conninfo",
            "dsn",
            "primary_conninfo",
            "replication_password",
        )
    )


def redact_database_secret_text(value: str) -> str:
    redacted = redact_compose_secret_text(value).replace("[REDACTED PRIVATE KEY]", "[REDACTED]")
    redacted = re.sub(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
        "[REDACTED]",
        redacted,
        flags=re.IGNORECASE | re.DOTALL,
    )
    redacted = re.sub(r"\bPRIVATE KEY\b", "[REDACTED]", redacted, flags=re.IGNORECASE)
    redacted = re.sub(
        r"(?i)\b((?:postgres(?:ql)?|mysql|mariadb)://)([^/\s:@;\"']*):([^@\s/;\"']+)@([^\s;\"']+)",
        r"\1[REDACTED]@\4",
        redacted,
    )
    redacted = re.sub(
        r"(?i)\b([A-Z0-9_$_.-]*(?:PGPASSWORD|MYSQL_PWD|PASSWORD|PASS|SECRET|TOKEN|API_KEY|APIKEY|CLIENT_SECRET|PRIVATE_KEY|CREDENTIAL|DATABASE_URL|CONNECTION_STRING|CONNINFO|DSN)[A-Z0-9_$_.-]*)(\s*[:=]\s*)(['\"]?)[^\s,'\";}\]]+",
        lambda match: f"{match.group(1)}{match.group(2)}{match.group(3)}[REDACTED]",
        redacted,
    )
    redacted = re.sub(
        r"(?i)\b(?:super-secret-password|raw-db-password-[a-z0-9_-]+|raw-api-key-[a-z0-9_-]+|[a-z0-9_.-]*should_(?:never|not)_render[a-z0-9_.-]*|db_password_plaintext)\b",
        "[REDACTED]",
        redacted,
    )
    redacted = redacted.replace("PRIVATE_KEY_BLOCK_REDACTED", "[REDACTED]")
    return re.sub(r"\[REDACTED\]\]+", "[REDACTED]", redacted)


def redact_sql_database_config_value(value: Any) -> Any:
    return redact_database_config_value(value)


def redact_sql_database_secret_text(value: str) -> str:
    return redact_database_secret_text(value)


def redact_redis_config_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact_redis_secret_text(value)
    if isinstance(value, list):
        return [redact_redis_config_value(item) for item in value]
    if isinstance(value, dict):
        secret_named_value = redis_record_has_secret_name(value)
        redacted: dict[Any, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            if is_redis_secret_mapping_key(key_text) or (
                secret_named_value
                and key_text.lower()
                in {"value", "raw_value", "default", "data", "content", "dump", "aof", "acl", "arguments", "connection_string", "url"}
            ):
                redacted[key] = "[REDACTED]"
            else:
                redacted[key] = redact_redis_config_value(item)
        return redacted
    return value


def redis_record_has_secret_name(record: dict[str, Any]) -> bool:
    for marker in (
        "key",
        "name",
        "setting",
        "directive",
        "target",
        "path",
        "environment",
        "env",
        "error",
        "url",
    ):
        candidate = record.get(marker)
        if candidate is not None and is_redis_secret_mapping_key(str(candidate)):
            return True
    return False


def is_redis_secret_mapping_key(key: str) -> bool:
    normalized = key.lower().replace("-", "_")
    if "redacted" in normalized or normalized.endswith("_count"):
        return False
    if normalized in {
        "content",
        "raw",
        "raw_content",
        "dump_content",
        "aof_content",
        "acl_content",
        "appendonly_content",
        "backup_content",
        "private_key",
        "certificate_key",
        "env_file_content",
        "credential_file_content",
    }:
        return True
    return any(
        token in normalized
        for token in (
            "authorization",
            "access_token",
            "refresh_token",
            "auth_token",
            "auth_pass",
            "requirepass",
            "masterauth",
            "client_secret",
            "private_key",
            "api_key",
            "apikey",
            "password",
            "passwd",
            "redis_password",
            "token",
            "secret",
            "credential",
            "redis_url",
            "connection_string",
            "acl_hash",
        )
    )


def redact_redis_secret_text(value: str) -> str:
    redacted = redact_database_secret_text(value).replace("[REDACTED PRIVATE KEY]", "[REDACTED]")
    redacted = redacted.replace("requirepass [REDACTED] present", "requirepass is present")
    redacted = redacted.replace("masterauth [REDACTED] present", "masterauth is present")
    redacted = re.sub(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
        "[REDACTED]",
        redacted,
        flags=re.IGNORECASE | re.DOTALL,
    )
    redacted = re.sub(r"\bPRIVATE KEY\b", "[REDACTED]", redacted, flags=re.IGNORECASE)
    redacted = re.sub(
        r"(?i)\b(redis(?:s)?://)([^/\s:@;\"']*):([^@\s/;\"']+)@([^\s;\"']+)",
        r"\1[REDACTED]@\4",
        redacted,
    )
    redacted = re.sub(
        r"(?i)\b(requirepass|masterauth)\b\s+(?!(?:is|was|present|missing|configured|observed|detected|not)\b)[^,\n\r;}\]]+",
        r"\1 [REDACTED]",
        redacted,
    )
    redacted = re.sub(r"(?i)\bsentinel\s+auth-pass\s+\S+\s+[^,\n\r;}\]]+", "sentinel auth-pass [REDACTED]", redacted)
    redacted = re.sub(
        r"(?i)\b([A-Z0-9_$_.-]*(?:REDIS_PASSWORD|REQUIREPASS|MASTERAUTH|PASSWORD|PASS|SECRET|TOKEN|API_KEY|APIKEY|CLIENT_SECRET|PRIVATE_KEY|CREDENTIAL|REDIS_URL|CONNECTION_STRING|AUTH_PASS)[A-Z0-9_$_.-]*)(\s*[:=]\s*)(['\"]?)[^\s,'\";}\]]+",
        lambda match: f"{match.group(1)}{match.group(2)}{match.group(3)}[REDACTED]",
        redacted,
    )
    redacted = re.sub(
        r"(?i)\b(?:super-secret-password|raw-redis-password-[a-z0-9_-]+|raw-api-key-[a-z0-9_-]+|[a-z0-9_.-]*should_(?:never|not)_render[a-z0-9_.-]*|ACLHASHSECRET[a-z0-9_.-]*|dump_value_should_not_render|acl_password_hash_should_not_render)\b",
        "[REDACTED]",
        redacted,
    )
    redacted = redacted.replace("PRIVATE_KEY_BLOCK_REDACTED", "[REDACTED]")
    return re.sub(r"\[REDACTED\]\]+", "[REDACTED]", redacted)


def redact_active_config_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact_active_secret_text(value)
    if isinstance(value, list):
        return [redact_active_config_value(item) for item in value]
    if isinstance(value, dict):
        secret_named_value = active_record_has_secret_name(value)
        return {
            key: "[REDACTED]"
            if str(key).lower().replace("-", "_") in {"body", "response_body", "body_text"}
            or is_active_secret_mapping_key(str(key))
            or (secret_named_value and str(key).lower() in {"value", "raw_value", "default", "data", "content", "authorization"})
            else redact_active_config_value(item)
            for key, item in value.items()
        }
    return value


def active_record_has_secret_name(record: dict[str, Any]) -> bool:
    for marker in ("key", "name", "setting", "variable", "field_path", "header", "target", "raw"):
        candidate = record.get(marker)
        if candidate is not None and is_active_secret_mapping_key(str(candidate)):
            return True
    return False


def is_active_secret_mapping_key(key: str) -> bool:
    normalized = key.lower().replace("-", "_")
    if normalized == "authorization" or "redacted" in normalized or normalized.endswith("_count"):
        return False
    return any(
        token in normalized
        for token in (
            "authorization",
            "bearer",
            "cookie",
            "session",
            "access_token",
            "refresh_token",
            "id_token",
            "auth_token",
            "client_secret",
            "private_key",
            "api_key",
            "apikey",
            "password",
            "passwd",
            "pwd",
            "token",
            "secret",
            "credential",
        )
    )


def redact_active_secret_text(value: str) -> str:
    redacted = redact_redis_secret_text(value).replace("[REDACTED PRIVATE KEY]", "[REDACTED]")
    redacted = re.sub(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
        "[REDACTED]",
        redacted,
        flags=re.IGNORECASE | re.DOTALL,
    )
    redacted = re.sub(r"(?i)\bAuthorization\s*:\s*(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+", "Authorization: [REDACTED]", redacted)
    redacted = re.sub(r"(?i)\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+", "[REDACTED]", redacted)
    redacted = re.sub(
        r"(?i)\b([a-z][a-z0-9+.-]*://)([^:\s/@;\"']+):([^@\s/;\"']+)@([^\s;\"']+)",
        r"\1[REDACTED]@\4",
        redacted,
    )
    redacted = SENSITIVE_QUERY_PARAM_RE.sub(lambda match: f"{match.group(1)}[REDACTED]", redacted)
    redacted = re.sub(
        r"(?i)\b([A-Z0-9_$_.-]*(?:authorization|cookie|session|client_secret|private_key|api_key|apikey|password|passwd|pwd|token|secret|credential)[A-Z0-9_$_.-]*)(\s*[:=]\s*)(['\"]?)[^\s,'\";}\]]+",
        lambda match: f"{match.group(1)}{match.group(2)}{match.group(3)}[REDACTED]",
        redacted,
    )
    redacted = redacted.replace("PRIVATE KEY", "[REDACTED]")
    return re.sub(r"\[REDACTED\]\]+", "[REDACTED]", redacted)


def redact_active_nmap_basic_value(value: Any, sensitive_tokens: set[str] | None = None) -> Any:
    tokens = sensitive_tokens if sensitive_tokens is not None else collect_active_nmap_basic_sensitive_tokens(value)
    if isinstance(value, str):
        return redact_active_nmap_basic_text(value, tokens)
    if isinstance(value, list):
        return [redact_active_nmap_basic_value(item, tokens) for item in value]
    if isinstance(value, dict):
        redacted: dict[Any, Any] = {}
        for key, item in value.items():
            normalized_key = str(key).lower().replace("-", "_")
            if normalized_key in ACTIVE_NMAP_BASIC_SENSITIVE_VALUE_KEYS or is_active_secret_mapping_key(str(key)):
                redacted[key] = "[REDACTED]"
            else:
                redacted[key] = redact_active_nmap_basic_value(item, tokens)
        return redacted
    return value


def collect_active_nmap_basic_sensitive_tokens(value: Any) -> set[str]:
    tokens: set[str] = set()

    def collect(item: Any, *, sensitive_context: bool = False) -> None:
        if isinstance(item, str):
            token = item.strip()
            if sensitive_context and 3 <= len(token) <= 256:
                tokens.add(token)
            return
        if isinstance(item, list):
            for child in item:
                collect(child, sensitive_context=sensitive_context)
            return
        if isinstance(item, dict):
            for key, child in item.items():
                normalized_key = str(key).lower().replace("-", "_")
                collect(child, sensitive_context=sensitive_context or normalized_key in ACTIVE_NMAP_BASIC_TOKEN_SOURCE_KEYS)

    collect(value)
    return tokens


def redact_active_nmap_basic_text(value: str, sensitive_tokens: set[str] | None = None) -> str:
    redacted = redact_active_secret_text(value)
    for token in sorted(sensitive_tokens or set(), key=len, reverse=True):
        if token:
            redacted = redacted.replace(token, "[REDACTED]")
    replacements = (
        "[REDACTED_XML]",
        "[REDACTED_XML]",
        "[REDACTED_TARGET]",
        "nmap [REDACTED_COMMAND]",
        "[REDACTED_TARGET]",
        "[REDACTED_TARGET]",
        "[REDACTED_TARGET]",
        "[REDACTED_HEADER]",
        "[REDACTED_BANNER]",
        "[REDACTED_CLAIM]",
    )
    for pattern, replacement in zip(ACTIVE_NMAP_BASIC_TEXT_REDACT_PATTERNS, replacements, strict=True):
        redacted = pattern.sub(replacement, redacted)
    return re.sub(r"\[REDACTED\]\]+", "[REDACTED]", redacted)


def redact_active_tls_basic_value(value: Any, sensitive_tokens: set[str] | None = None) -> Any:
    tokens = sensitive_tokens if sensitive_tokens is not None else collect_active_tls_basic_sensitive_tokens(value)
    if isinstance(value, str):
        return redact_active_tls_basic_text(value, tokens)
    if isinstance(value, list):
        return [redact_active_tls_basic_value(item, tokens) for item in value]
    if isinstance(value, dict):
        redacted: dict[Any, Any] = {}
        for key, item in value.items():
            normalized_key = str(key).lower().replace("-", "_")
            if normalized_key == "target":
                redacted[key] = "[REDACTED_TARGET]"
            elif normalized_key in ACTIVE_TLS_BASIC_SENSITIVE_VALUE_KEYS or is_active_secret_mapping_key(str(key)):
                redacted[key] = "[REDACTED]"
            else:
                redacted[key] = redact_active_tls_basic_value(item, tokens)
        return redacted
    return value


def collect_active_tls_basic_sensitive_tokens(value: Any) -> set[str]:
    tokens: set[str] = set()

    def collect(item: Any, *, sensitive_context: bool = False) -> None:
        if isinstance(item, str):
            token = item.strip()
            if sensitive_context and 3 <= len(token) <= 256:
                tokens.add(token)
            return
        if isinstance(item, list):
            for child in item:
                collect(child, sensitive_context=sensitive_context)
            return
        if isinstance(item, dict):
            for key, child in item.items():
                normalized_key = str(key).lower().replace("-", "_")
                collect(child, sensitive_context=sensitive_context or normalized_key in ACTIVE_TLS_BASIC_TOKEN_SOURCE_KEYS)

    collect(value)
    return tokens


def redact_active_tls_basic_text(value: str, sensitive_tokens: set[str] | None = None) -> str:
    redacted = redact_active_secret_text(value)
    for token in sorted(sensitive_tokens or set(), key=len, reverse=True):
        if token:
            redacted = redacted.replace(token, "[REDACTED]")
    redacted = re.sub(r"-----BEGIN [^-]+-----.*?-----END [^-]+-----", "[REDACTED_CERTIFICATE]", redacted, flags=re.DOTALL)
    redacted = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "[REDACTED_TARGET]", redacted)
    redacted = re.sub(
        r"\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\b",
        "[REDACTED_TARGET]",
        redacted,
        flags=re.IGNORECASE,
    )
    redacted = re.sub(r"(?i)\b(?:confirmed vulnerability|exploitable|target is safe|all certs found|full scan|public scanner)\b", "[REDACTED_CLAIM]", redacted)
    return re.sub(r"\[REDACTED\]\]+", "[REDACTED]", redacted)


def redact_active_dns_inventory_value(value: Any, sensitive_tokens: set[str] | None = None) -> Any:
    tokens = sensitive_tokens if sensitive_tokens is not None else collect_active_dns_inventory_sensitive_tokens(value)
    if isinstance(value, str):
        return redact_active_dns_inventory_text(value, tokens)
    if isinstance(value, list):
        return [redact_active_dns_inventory_value(item, tokens) for item in value]
    if isinstance(value, dict):
        redacted: dict[Any, Any] = {}
        for key, item in value.items():
            normalized_key = str(key).lower().replace("-", "_")
            if normalized_key == "domain":
                redacted[key] = "[REDACTED_DOMAIN]"
            elif normalized_key == "name":
                redacted[key] = "[REDACTED_DNS_NAME]" if item != "[REDACTED_DOMAIN]" else "[REDACTED_DOMAIN]"
            elif normalized_key == "value":
                redacted[key] = "[REDACTED_DNS_VALUE]" if item else item
            elif normalized_key in ACTIVE_DNS_INVENTORY_SENSITIVE_VALUE_KEYS or is_active_secret_mapping_key(str(key)):
                redacted[key] = "[REDACTED]"
            else:
                redacted[key] = redact_active_dns_inventory_value(item, tokens)
        return redacted
    return value


def collect_active_dns_inventory_sensitive_tokens(value: Any) -> set[str]:
    tokens: set[str] = set()

    def collect(item: Any, *, sensitive_context: bool = False) -> None:
        if isinstance(item, str):
            token = item.strip()
            if sensitive_context and 3 <= len(token) <= 512:
                tokens.add(token)
            return
        if isinstance(item, list):
            for child in item:
                collect(child, sensitive_context=sensitive_context)
            return
        if isinstance(item, dict):
            for key, child in item.items():
                normalized_key = str(key).lower().replace("-", "_")
                collect(child, sensitive_context=sensitive_context or normalized_key in ACTIVE_DNS_INVENTORY_TOKEN_SOURCE_KEYS)

    collect(value)
    return tokens


def redact_active_dns_inventory_text(value: str, sensitive_tokens: set[str] | None = None) -> str:
    redacted = redact_active_secret_text(value)
    for token in sorted(sensitive_tokens or set(), key=len, reverse=True):
        if token:
            redacted = redacted.replace(token, "[REDACTED]")
    redacted = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "[REDACTED_DNS_VALUE]", redacted)
    redacted = re.sub(r"\b(?:[A-F0-9]{1,4}:){2,}[A-F0-9:]{1,}\b", "[REDACTED_DNS_VALUE]", redacted, flags=re.IGNORECASE)
    redacted = re.sub(
        r"\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\b",
        "[REDACTED_DOMAIN]",
        redacted,
        flags=re.IGNORECASE,
    )
    redacted = re.sub(r"(?i)\b(?:confirmed vulnerability|exploitable|target is safe|all certs found|full scan|public scanner)\b", "[REDACTED_CLAIM]", redacted)
    return re.sub(r"\[REDACTED\]\]+", "[REDACTED]", redacted)


def collect_errors(job: JobRecord) -> dict[str, Any]:
    result = public_result_for_job(job, as_dict(job.result))
    validation = as_dict(result.get("validation"))
    tool_outputs = as_dict(result.get("tool_outputs"))
    errors: dict[str, Any] = {
        "job_error": public_job_error(job),
        "result_errors": result.get("errors", []),
        "warnings": validation.get("warnings", []),
        "timed_out_tools": validation.get("timed_out_tools", []),
    }
    tool_errors: dict[str, Any] = {}
    for name, output in tool_outputs.items():
        tool = as_dict(output)
        if tool.get("timed_out") or tool.get("stderr") or (tool.get("exit_code") not in (None, 0)):
            tool_errors[name] = {
                "exit_code": tool.get("exit_code"),
                "timed_out": tool.get("timed_out"),
                "stderr": tool.get("stderr"),
            }
    errors["tool_errors"] = tool_errors
    return errors


def render_html_section(section: ReportSection) -> str:
    rows = "\n".join(
        f"<tr><th>{escape_html(key)}</th><td><code>{escape_html(value)}</code></td></tr>" for key, value in section.items
    )
    if not rows:
        rows = '<tr><td colspan="2">N/A</td></tr>'
    return f"<section><h2>{escape_html(section.title)}</h2><table>{rows}</table></section>"


def flatten_mapping(value: dict[str, Any] | None, prefix: str = "") -> list[tuple[str, str]]:
    if not value:
        return []
    rows: list[tuple[str, str]] = []
    for key, item in value.items():
        label = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(item, dict):
            rows.extend(flatten_mapping(item, label))
        elif isinstance(item, list):
            rows.extend(flatten_list(item, label))
        else:
            rows.append((label, stringify(item)))
    return rows


def flatten_list(value: Any, prefix: str = "item") -> list[tuple[str, str]]:
    if not isinstance(value, list):
        return []
    rows: list[tuple[str, str]] = []
    for index, item in enumerate(value, start=1):
        label = f"{prefix} {index}"
        if isinstance(item, dict):
            for key, nested in item.items():
                rows.append((f"{label}.{key}", stringify(nested)))
        else:
            rows.append((label, stringify(item)))
    return rows


def append_value(parent: ElementTree.Element, name: str, value: Any) -> None:
    node = ElementTree.SubElement(parent, xml_tag(name))
    if isinstance(value, dict):
        for key, item in value.items():
            append_value(node, str(key), item)
    elif isinstance(value, list):
        for item in value:
            append_value(node, "item", item)
    else:
        node.text = stringify(value)


def add_text(parent: ElementTree.Element, name: str, value: str) -> None:
    ElementTree.SubElement(parent, name).text = value


def build_simple_pdf(lines: list[str]) -> bytes:
    pages = paginate_pdf_lines(lines)
    objects: list[bytes] = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    page_object_numbers: list[int] = []

    for page_lines in pages:
        content = render_pdf_page_content(page_lines)
        content_number = len(objects) + 2
        page_number = len(objects) + 1
        page_object_numbers.append(page_number)
        objects.append(
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R >> >> /Contents {content_number} 0 R >>".encode(
                "ascii"
            )
        )
        objects.append(f"<< /Length {len(content)} >>\nstream\n".encode("ascii") + content + b"\nendstream")

    kids = " ".join(f"{number} 0 R" for number in page_object_numbers)
    objects[1] = f"<< /Type /Pages /Kids [{kids}] /Count {len(page_object_numbers)} >>".encode("ascii")

    output = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for index, obj in enumerate(objects, start=1):
        offsets.append(len(output))
        output.extend(f"{index} 0 obj\n".encode("ascii"))
        output.extend(obj)
        output.extend(b"\nendobj\n")

    xref_offset = len(output)
    output.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    output.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    output.extend(
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n".encode("ascii")
    )
    return bytes(output)


def paginate_pdf_lines(lines: list[str]) -> list[list[str]]:
    page_size = 46
    if not lines:
        return [["Inspectra Audit Report"]]
    return [lines[index : index + page_size] for index in range(0, len(lines), page_size)]


def render_pdf_page_content(lines: list[str]) -> bytes:
    commands = ["BT", "/F1 10 Tf", "14 TL", "50 748 Td"]
    first = True
    for line in lines:
        if not first:
            commands.append("T*")
        commands.append(f"({pdf_escape(line)}) Tj")
        first = False
    commands.append("ET")
    return "\n".join(commands).encode("latin-1", errors="replace")


def wrap_pdf_line(value: str, indent: str = "") -> list[str]:
    wrapped = textwrap.wrap(value.replace("\n", " "), width=96, subsequent_indent=indent)
    return [f"{indent}{line}" if index == 0 else line for index, line in enumerate(wrapped)] or [indent]


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def stringify(value: Any) -> str:
    if value is None or value == "":
        return "N/A"
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value)


def escape_html(value: str) -> str:
    return html.escape(value, quote=True)


def escape_markdown(value: str) -> str:
    return markdown_inline_value(value)


def render_markdown_item(key: str, value: str) -> list[str]:
    key_text = markdown_inline_value(key)
    if should_render_markdown_block(value):
        return [f"- {key_text}:", markdown_block_value(value)]
    return [f"- {key_text}: {markdown_inline_value(value)}"]


def markdown_inline_value(value: Any) -> str:
    text = normalize_markdown_text(stringify(value), multiline=False)
    delimiter = markdown_code_span_delimiter(text)
    if text.startswith("`") or text.endswith("`"):
        text = f" {text} "
    return f"{delimiter}{text}{delimiter}"


def markdown_block_value(value: Any) -> str:
    text = normalize_markdown_text(stringify(value), multiline=True)
    fence = markdown_fence_delimiter(text)
    return f"{fence}text\n{text}\n{fence}"


def markdown_table_cell(value: Any) -> str:
    text = normalize_markdown_text(stringify(value), multiline=False)
    return markdown_inline_value(text.replace("|", "\\|"))


def markdown_section_text(value: Any) -> str:
    return markdown_block_value(value)


def should_render_markdown_block(value: str) -> bool:
    return "\n" in value or "\r" in value or len(value) > 160


def normalize_markdown_text(value: str, *, multiline: bool) -> str:
    text = value.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "\uFFFD", text)
    if not multiline:
        return re.sub(r"\s*\n\s*", " / ", text)
    return text


def markdown_code_span_delimiter(value: str) -> str:
    max_run = max((len(match.group(0)) for match in re.finditer(r"`+", value)), default=0)
    return "`" * (max_run + 1)


def markdown_fence_delimiter(value: str) -> str:
    max_run = max((len(match.group(0)) for match in re.finditer(r"`+", value)), default=0)
    return "`" * max(3, max_run + 1)


def html_class(value: str) -> str:
    return re.sub(r"[^a-z0-9_-]+", "-", value.lower())


def xml_tag(value: str) -> str:
    tag = re.sub(r"[^A-Za-z0-9_.-]+", "_", value)
    if not tag or not re.match(r"[A-Za-z_]", tag):
        tag = f"item_{tag}"
    return tag


def pdf_escape(value: str) -> str:
    text = value.encode("latin-1", errors="replace").decode("latin-1")
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
