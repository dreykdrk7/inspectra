from __future__ import annotations

from dataclasses import dataclass
import html
import json
import re
import textwrap
from typing import Any, Iterable
from xml.etree import ElementTree

from app.models import JobRecord


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
    add_text(job_node, "fileId", job.file_id)
    add_text(job_node, "createdAt", job.created_at.isoformat())
    add_text(job_node, "updatedAt", job.updated_at.isoformat())
    add_text(job_node, "error", job.error or "")

    file_node = ElementTree.SubElement(root, "file")
    add_text(file_node, "id", job.file_id)
    add_text(file_node, "sourceFileDeletedAt", job.source_file_deleted_at.isoformat() if job.source_file_deleted_at else "")

    result = as_dict(job.result)
    append_value(root, "summary", result.get("summary", build_summary(job)))
    append_value(root, "hashes", result.get("hashes", {}))
    append_value(root, "findings", result.get("findings", []))
    append_value(root, "toolResults", result.get("tool_outputs", {}))
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
    result = as_dict(job.result)
    sections = [
        ReportSection(
            "Job",
            [
                ("Job ID", job.id),
                ("Audit type", job.audit_type),
                ("Status", job.status),
                ("File ID", job.file_id),
                ("Created at", job.created_at.isoformat()),
                ("Updated at", job.updated_at.isoformat()),
                ("Source file deleted", job.source_file_deleted_at.isoformat() if job.source_file_deleted_at else "No"),
                ("Job error", job.error or "N/A"),
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


def build_summary(job: JobRecord) -> dict[str, Any]:
    result = as_dict(job.result)
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
    return data


def collect_errors(job: JobRecord) -> dict[str, Any]:
    result = as_dict(job.result)
    validation = as_dict(result.get("validation"))
    tool_outputs = as_dict(result.get("tool_outputs"))
    errors: dict[str, Any] = {
        "job_error": job.error or "",
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
