from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import re
from typing import Any
from urllib.parse import quote

from fastapi import HTTPException, status

from app.models import JobRecord


COMPATIBLE_AUDIT_TYPES = {"manifest_basic", "project_archive_basic"}
INCOMPATIBLE_MESSAGE = "SBOM export is only available for dependency manifest jobs"
NOT_READY_MESSAGE = "SBOM export requires a completed manifest analysis job"


@dataclass(frozen=True)
class SbomComponent:
    name: str
    version_or_range: str
    ecosystem: str
    group: str
    source_manifest_path: str
    declared_requirement: str
    package_url: str | None
    bom_ref: str
    spdx_id: str

    @property
    def exact_version(self) -> str | None:
        return extract_exact_version(self.version_or_range, self.ecosystem)


def build_sbom_filename(job: JobRecord, suffix: str) -> str:
    return f"inspectra-job-{job.id}-{suffix}.json"


def generate_cyclonedx_json(job: JobRecord) -> str:
    components = extract_components_from_job(job)
    metadata: dict[str, Any] = {
        "timestamp": current_timestamp(),
        "tools": [{"vendor": "Inspectra", "name": "Inspectra"}],
    }
    project_component = build_project_component(job)
    if project_component:
        metadata["component"] = project_component

    payload = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": metadata,
        "components": [cyclonedx_component(component) for component in components],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"


def generate_spdx_json(job: JobRecord) -> str:
    components = extract_components_from_job(job)
    payload = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"Inspectra SBOM job {job.id}",
        "documentNamespace": f"https://inspectra.local/sbom/{job.id}",
        "creationInfo": {
            "created": current_timestamp(),
            "creators": ["Tool: Inspectra"],
        },
        "packages": [spdx_package(component) for component in components],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"


def extract_components_from_job(job: JobRecord) -> list[SbomComponent]:
    ensure_supported_job(job)
    result = as_dict(job.result)
    manifests = dependency_manifests(job, result)
    components: list[SbomComponent] = []

    for manifest in manifests:
        manifest_type = str(manifest.get("manifest_type") or "")
        ecosystem = ecosystem_for_manifest(manifest_type)
        parsed = as_dict(manifest.get("parsed"))
        dependencies = as_dict(parsed.get("dependencies"))
        source_path = str(manifest.get("source_manifest_path") or manifest.get("path") or manifest_type or "manifest")

        for group, items in dependencies.items():
            if not isinstance(items, list):
                continue
            for item in items:
                dependency = as_dict(item)
                name = str(dependency.get("name") or "").strip()
                if not name:
                    continue
                specifier = str(dependency.get("specifier") or "").strip()
                declared = format_declared_requirement(name, specifier, manifest_type)
                index = len(components) + 1
                package_url = build_package_url(ecosystem, name, specifier)
                components.append(
                    SbomComponent(
                        name=name,
                        version_or_range=specifier,
                        ecosystem=ecosystem,
                        group=str(group),
                        source_manifest_path=source_path,
                        declared_requirement=declared,
                        package_url=package_url,
                        bom_ref=build_bom_ref(ecosystem, source_path, str(group), name, index),
                        spdx_id=build_spdx_id(ecosystem, source_path, str(group), name, index),
                    )
                )

    return components


def ensure_supported_job(job: JobRecord) -> None:
    if job.audit_type not in COMPATIBLE_AUDIT_TYPES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=INCOMPATIBLE_MESSAGE)
    if job.status != "completed" or not job.result:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=NOT_READY_MESSAGE)


def dependency_manifests(job: JobRecord, result: dict[str, Any]) -> list[dict[str, Any]]:
    if job.audit_type == "manifest_basic":
        return [
            {
                "manifest_type": result.get("manifest_type"),
                "source_manifest_path": as_dict(result.get("file_identification")).get("original_filename", "manifest"),
                "parsed": result.get("parsed"),
            }
        ]

    manifests: list[dict[str, Any]] = []
    for item in result.get("parsed_manifests", []):
        manifest = as_dict(item)
        manifests.append(
            {
                "manifest_type": manifest.get("manifest_type"),
                "source_manifest_path": manifest.get("path", "archive manifest"),
                "parsed": manifest.get("parsed"),
            }
        )
    return manifests


def cyclonedx_component(component: SbomComponent) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "type": "library",
        "bom-ref": component.bom_ref,
        "name": component.name,
        "properties": [
            {"name": "inspectra:declared_requirement", "value": component.declared_requirement},
            {"name": "inspectra:dependency_group", "value": component.group},
            {"name": "inspectra:source_manifest", "value": component.source_manifest_path},
            {"name": "inspectra:ecosystem", "value": component.ecosystem},
        ],
    }
    if component.exact_version:
        payload["version"] = component.exact_version
    else:
        payload["properties"].append(
            {
                "name": "inspectra:note",
                "value": "Version is a declared range or unspecified; Inspectra did not resolve packages.",
            }
        )
    if component.package_url:
        payload["purl"] = component.package_url
    return payload


def spdx_package(component: SbomComponent) -> dict[str, Any]:
    package: dict[str, Any] = {
        "name": component.name,
        "SPDXID": component.spdx_id,
        "versionInfo": component.version_or_range or "NOASSERTION",
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "supplier": "NOASSERTION",
        "comment": (
            f"Declared requirement: {component.declared_requirement}; "
            f"dependency group: {component.group}; "
            f"source manifest: {component.source_manifest_path}; "
            f"ecosystem: {component.ecosystem}. "
            "Inspectra records declared dependencies only and does not resolve packages."
        ),
    }
    if component.package_url:
        package["externalRefs"] = [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": component.package_url,
            }
        ]
    return package


def build_project_component(job: JobRecord) -> dict[str, Any] | None:
    result = as_dict(job.result)
    if job.audit_type == "manifest_basic":
        project = as_dict(as_dict(result.get("parsed")).get("project"))
        name = project.get("name")
        if not isinstance(name, str) or not name:
            return None
        payload: dict[str, Any] = {"type": "application", "name": name}
        version = project.get("version")
        if isinstance(version, str) and version:
            payload["version"] = version
        return payload

    parsed_manifests = result.get("parsed_manifests")
    if not isinstance(parsed_manifests, list) or len(parsed_manifests) != 1:
        return None
    project = as_dict(as_dict(as_dict(parsed_manifests[0]).get("parsed")).get("project"))
    name = project.get("name")
    if not isinstance(name, str) or not name:
        return None
    payload = {"type": "application", "name": name}
    version = project.get("version")
    if isinstance(version, str) and version:
        payload["version"] = version
    return payload


def format_declared_requirement(name: str, specifier: str, manifest_type: str) -> str:
    if not specifier:
        return name
    if manifest_type == "package_json":
        return f"{name}: {specifier}"
    if specifier.startswith(("-", "http://", "https://", "git+", "file:")):
        return specifier
    if specifier.startswith(("<", ">", "=", "!", "~")):
        return f"{name}{specifier}"
    return f"{name} {specifier}"


def ecosystem_for_manifest(manifest_type: str) -> str:
    if manifest_type == "package_json":
        return "npm"
    return "pypi"


def build_package_url(ecosystem: str, name: str, specifier: str) -> str | None:
    exact_version = extract_exact_version(specifier, ecosystem)
    if ecosystem == "npm":
        encoded_name = quote(name, safe="/")
        return f"pkg:npm/{encoded_name}@{exact_version}" if exact_version else f"pkg:npm/{encoded_name}"
    if ecosystem == "pypi":
        normalized_name = canonicalize_python_name(name)
        encoded_name = quote(normalized_name, safe="")
        return f"pkg:pypi/{encoded_name}@{exact_version}" if exact_version else f"pkg:pypi/{encoded_name}"
    return None


def extract_exact_version(specifier: str, ecosystem: str) -> str | None:
    value = specifier.strip()
    if not value:
        return None
    if ecosystem == "pypi":
        match = re.fullmatch(r"==\s*([^,;\s]+)", value)
        return match.group(1) if match else None
    if re.fullmatch(r"[0-9][A-Za-z0-9._+\-]*", value):
        return value
    return None


def canonicalize_python_name(name: str) -> str:
    base = name.split("[", 1)[0]
    return re.sub(r"[-_.]+", "-", base).lower()


def build_bom_ref(ecosystem: str, source_path: str, group: str, name: str, index: int) -> str:
    return f"inspectra-{index}-{slugify(ecosystem)}-{slugify(source_path)}-{slugify(group)}-{slugify(name)}"


def build_spdx_id(ecosystem: str, source_path: str, group: str, name: str, index: int) -> str:
    return f"SPDXRef-Package-{index}-{slugify(ecosystem)}-{slugify(source_path)}-{slugify(group)}-{slugify(name)}"


def slugify(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9.-]+", "-", value).strip("-")
    return slug or "item"


def current_timestamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}
