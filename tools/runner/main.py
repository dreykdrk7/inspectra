from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
from typing import Any

from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel


DATA_DIR = Path(os.getenv("INSPECTRA_DATA_DIR", "/app/data")).resolve()
MAX_OUTPUT_CHARS = 120_000


class PdfAnalysisRequest(BaseModel):
    file_id: str
    relative_path: str


class ImageAnalysisRequest(BaseModel):
    file_id: str
    relative_path: str


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
