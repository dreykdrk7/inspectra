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
    add_text(job_node, "targetUrl", redact_url_query(job.target_url) if job.target_url else "")
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
                ("Target URL", redact_url_query(job.target_url) if job.target_url else "N/A"),
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
    return result


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
    return redact_node_package_secret_text(value)


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
            "authorization",
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
