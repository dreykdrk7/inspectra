from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
from typing import Any

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


COMMAND_TIMEOUT_SECONDS = positive_float_from_env("INSPECTRA_TOOL_TIMEOUT_SECONDS", 10.0)


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
            dependencies.append({"name": parse_editable_name(line), "specifier": line, "source": f"line {line_number}"})
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
    return [
        {"name": name, "specifier": stringify_manifest_value(specifier)}
        for name, specifier in sorted(dependencies.items())
        if isinstance(name, str)
    ]


def stringify_mapping(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {str(key): stringify_manifest_value(item) for key, item in value.items()}


def parse_requirement_dependency(line: str, line_number: int) -> dict[str, str]:
    requirement = line.split(";", 1)[0].strip()
    match = re.match(r"^([A-Za-z0-9_.-]+(?:\[[^\]]+\])?)(.*)$", requirement)
    if not match:
        return {"name": requirement, "specifier": line, "source": f"line {line_number}"}
    return {"name": match.group(1), "specifier": match.group(2).strip() or "", "source": f"line {line_number}"}


def parse_editable_name(line: str) -> str:
    egg_match = re.search(r"[#&]egg=([A-Za-z0-9_.-]+)", line)
    if egg_match:
        return egg_match.group(1)
    return "editable-reference"


def normalize_pep508_dependency(value: str) -> dict[str, str]:
    match = re.match(r"^([A-Za-z0-9_.-]+(?:\[[^\]]+\])?)(.*)$", value.strip())
    if not match:
        return {"name": value.strip(), "specifier": ""}
    return {"name": match.group(1), "specifier": match.group(2).strip()}


def normalize_poetry_dependency(name: str, specifier: Any) -> dict[str, str]:
    return {"name": name, "specifier": stringify_manifest_value(specifier)}


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


def starts_with_any(value: str, prefixes: tuple[str, ...]) -> bool:
    return any(value.startswith(prefix) for prefix in prefixes)


def strip_inline_comment(line: str) -> str:
    return line.split(" #", 1)[0].strip()


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
