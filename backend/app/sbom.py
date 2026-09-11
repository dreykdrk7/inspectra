from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import re
from typing import Any
from urllib.parse import quote

from app.version_matching import canonicalize_nuget_version, is_supported_maven_version

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
    dependency_source_type: str
    package_url: str | None
    purl_omitted_reason: str | None
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
    project_package = build_spdx_project_package(job)
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
        "packages": ([project_package] if project_package else []) + [spdx_package(component) for component in components],
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
                declared = str(
                    dependency.get("declared_requirement") or format_declared_requirement(name, specifier, manifest_type)
                ).strip()
                index = len(components) + 1
                source_type = classify_dependency_source(ecosystem, manifest_type, name, specifier, declared, dependency)
                if source_type != "registry":
                    # Export the fact that a dependency uses a non-registry
                    # source, not its URL, VCS locator, local path or alias
                    # target. Those values can expose private topology or
                    # credentials and are never needed for a safe SBOM purl.
                    specifier = ""
                    declared = f"{name}: non-registry reference withheld ({source_type})"
                package_url = build_package_url(ecosystem, name, specifier, source_type)
                components.append(
                    SbomComponent(
                        name=name,
                        version_or_range=specifier,
                        ecosystem=ecosystem,
                        group=str(group),
                        source_manifest_path=source_path,
                        declared_requirement=declared,
                        dependency_source_type=source_type,
                        package_url=package_url,
                        purl_omitted_reason=None
                        if package_url
                        else build_purl_omitted_reason(source_type, ecosystem, name),
                        bom_ref=build_bom_ref(ecosystem, source_path, str(group), name, index),
                        spdx_id=build_spdx_id(ecosystem, source_path, str(group), name, index),
                    )
                )

    return deduplicate_components(components)


def deduplicate_components(components: list[SbomComponent]) -> list[SbomComponent]:
    """Collapse exact repeated declarations without merging distinct sources or versions."""

    retained: list[SbomComponent] = []
    seen: set[tuple[str, str, str, str, str]] = set()
    for component in components:
        key = (
            component.ecosystem.lower(),
            component.name.lower(),
            component.version_or_range,
            component.dependency_source_type,
            component.source_manifest_path,
        )
        if key in seen:
            continue
        seen.add(key)
        retained.append(component)
    return retained


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
            {"name": "inspectra:dependency_source_type", "value": component.dependency_source_type},
            {"name": "inspectra:license_status", "value": "unknown_not_observed"},
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
    elif component.purl_omitted_reason:
        payload["properties"].append({"name": "inspectra:purl_omitted_reason", "value": component.purl_omitted_reason})
    return payload


def spdx_package(component: SbomComponent) -> dict[str, Any]:
    package: dict[str, Any] = {
        "name": component.name,
        "SPDXID": component.spdx_id,
        "versionInfo": component.version_or_range or "NOASSERTION",
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "supplier": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "licenseConcluded": "NOASSERTION",
        "comment": (
            f"Declared requirement: {component.declared_requirement}; "
            f"dependency group: {component.group}; "
            f"source manifest: {component.source_manifest_path}; "
            f"ecosystem: {component.ecosystem}; "
            f"dependency source type: {component.dependency_source_type}. "
            "Inspectra records declared dependencies only and does not resolve packages."
        ),
    }
    if component.purl_omitted_reason:
        package["comment"] += f" Package URL omitted: {component.purl_omitted_reason}"
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
        add_declared_project_license(payload, project)
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
    add_declared_project_license(payload, project)
    return payload


def add_declared_project_license(payload: dict[str, Any], project: dict[str, Any]) -> None:
    """Add only a runner-normalized root declaration to CycloneDX metadata."""

    expression = project.get("license")
    if isinstance(expression, str) and expression:
        payload["licenses"] = [{"expression": expression}]
    else:
        payload.setdefault("properties", []).append(
            {"name": "inspectra:license_status", "value": "unknown_not_observed_or_unsupported"}
        )


def build_spdx_project_package(job: JobRecord) -> dict[str, Any] | None:
    component = build_project_component(job)
    if component is None:
        return None
    licenses = component.get("licenses") if isinstance(component.get("licenses"), list) else []
    first = licenses[0] if licenses and isinstance(licenses[0], dict) else {}
    expression = first.get("expression") if isinstance(first.get("expression"), str) else None
    if expression is None:
        # Preserve the established dependency-only SPDX shape unless the root
        # contributes a supported declaration. Unknown root-license state is
        # already explicit on every dependency and in the project review.
        return None
    return {
        "name": component["name"],
        "SPDXID": "SPDXRef-Project",
        "versionInfo": component.get("version", "NOASSERTION"),
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "supplier": "NOASSERTION",
        "licenseDeclared": expression,
        "licenseConcluded": "NOASSERTION",
        "comment": "Root project declaration retained by Inspectra; no legal compatibility or obligation analysis was performed.",
    }


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
    if manifest_type == "go_mod":
        return "go"
    if manifest_type == "cargo_toml":
        return "cargo"
    if manifest_type == "composer_json":
        return "composer"
    if manifest_type == "gradle_build":
        return "maven"
    if manifest_type == "dotnet_project":
        return "nuget"
    return "pypi"


def build_package_url(ecosystem: str, name: str, specifier: str, source_type: str) -> str | None:
    if source_type != "registry":
        return None
    exact_version = extract_exact_version(specifier, ecosystem)
    encoded_version = quote(exact_version, safe="-._~+") if exact_version else None
    if ecosystem == "npm":
        if not is_valid_npm_name(name):
            return None
        encoded_name = quote(name, safe="/")
        return f"pkg:npm/{encoded_name}@{encoded_version}" if encoded_version else f"pkg:npm/{encoded_name}"
    if ecosystem == "pypi":
        if not is_valid_pypi_name(name):
            return None
        normalized_name = canonicalize_python_name(name)
        encoded_name = quote(normalized_name, safe="")
        return f"pkg:pypi/{encoded_name}@{encoded_version}" if encoded_version else f"pkg:pypi/{encoded_name}"
    if ecosystem == "go":
        if not is_valid_go_module_name(name):
            return None
        encoded_name = quote(name, safe="/")
        return f"pkg:golang/{encoded_name}@{encoded_version}" if encoded_version else f"pkg:golang/{encoded_name}"
    if ecosystem == "cargo":
        if not is_valid_cargo_name(name):
            return None
        encoded_name = quote(name, safe="")
        return f"pkg:cargo/{encoded_name}@{encoded_version}" if encoded_version else f"pkg:cargo/{encoded_name}"
    if ecosystem == "composer":
        if not is_valid_composer_name(name):
            return None
        encoded_name = quote(name, safe="/")
        return f"pkg:composer/{encoded_name}@{encoded_version}" if encoded_version else f"pkg:composer/{encoded_name}"
    if ecosystem == "maven":
        if not is_valid_maven_name(name):
            return None
        group, artifact = name.split(":", 1)
        encoded_name = f"{quote(group, safe='.-')}/{quote(artifact, safe='.-')}"
        return f"pkg:maven/{encoded_name}@{encoded_version}" if encoded_version else f"pkg:maven/{encoded_name}"
    if ecosystem == "nuget":
        if not is_valid_nuget_name(name):
            return None
        encoded_name = quote(name.lower(), safe=".-")
        return f"pkg:nuget/{encoded_name}@{encoded_version}" if encoded_version else f"pkg:nuget/{encoded_name}"
    return None


def classify_dependency_source(
    ecosystem: str,
    manifest_type: str,
    name: str,
    specifier: str,
    declared_requirement: str,
    dependency: dict[str, Any],
) -> str:
    explicit_source = normalize_source_type(
        str(dependency.get("dependency_source_type") or dependency.get("source_type") or "").strip()
    )
    inferred_source = infer_dependency_source(ecosystem, manifest_type, name, specifier, declared_requirement)
    if explicit_source and explicit_source != "registry":
        return explicit_source
    if explicit_source == "registry" and inferred_source == "registry":
        return "registry"
    return inferred_source


def infer_dependency_source(ecosystem: str, manifest_type: str, name: str, specifier: str, declared_requirement: str) -> str:
    if ecosystem == "npm" or manifest_type == "package_json":
        return infer_npm_dependency_source(name, specifier)
    return infer_python_dependency_source(name, specifier, declared_requirement)


def infer_npm_dependency_source(name: str, specifier: str) -> str:
    value = specifier.strip()
    lowered = value.lower()
    if not is_valid_npm_name(name):
        return "unknown"
    if not value:
        return "registry"
    if lowered.startswith("workspace:"):
        return "workspace"
    if lowered.startswith(("file:", "link:", "portal:")) or looks_like_local_path(value):
        return "local"
    if lowered.startswith("npm:"):
        return "alias"
    if looks_like_vcs(value) or looks_like_npm_repository_shorthand(value):
        return "vcs"
    if looks_like_url(value):
        return "url"
    return "registry"


def infer_python_dependency_source(name: str, specifier: str, declared_requirement: str) -> str:
    combined = " ".join(part for part in (name.strip(), specifier.strip(), declared_requirement.strip()) if part)
    lowered = combined.lower()
    specifier_value = specifier.strip()
    if lowered.startswith("-e ") or lowered == "-e" or specifier_value.startswith("-e "):
        return "editable"
    if specifier_value.startswith(("--", "-r", "-c")) or lowered.startswith(("--", "-r ", "-c ")):
        return "unknown"
    if looks_like_local_path(name) or looks_like_local_path(specifier_value):
        return "local"
    if " @ " in combined or specifier_value.startswith("@"):
        reference = combined.split("@", 1)[1].strip()
        if looks_like_vcs(reference):
            return "vcs"
        if reference.lower().startswith("file:") or looks_like_local_path(reference):
            return "local"
        if looks_like_url(reference):
            return "url"
        return "unknown"
    if looks_like_vcs(combined):
        return "vcs"
    if looks_like_url(combined):
        return "url"
    if "file:" in lowered or "path =" in lowered:
        return "local"
    if not is_valid_pypi_name(name):
        return "unknown"
    return "registry"


def build_purl_omitted_reason(source_type: str, ecosystem: str, name: str) -> str:
    if source_type == "registry":
        return (
            f"Inspectra could not safely generate a package URL for {name!r} in the {ecosystem} ecosystem; "
            "the declared requirement is preserved."
        )
    if source_type == "unknown":
        return "Dependency source is unknown or ambiguous; Inspectra did not infer a registry package URL."
    return f"Dependency source is {source_type}; its reference is withheld and Inspectra does not infer a registry package URL."


def normalize_source_type(value: str) -> str | None:
    normalized = value.lower()
    if normalized in {"registry", "url", "vcs", "local", "editable", "workspace", "alias", "unknown"}:
        return normalized
    return None


def is_valid_npm_name(name: str) -> bool:
    return bool(re.fullmatch(r"(?:@[A-Za-z0-9][A-Za-z0-9._~-]*/)?[A-Za-z0-9][A-Za-z0-9._~-]*", name))


def is_valid_pypi_name(name: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*(?:\[[A-Za-z0-9_,._-]+\])?", name))


def is_valid_go_module_name(name: str) -> bool:
    if len(name) > 300 or name != name.lower():
        return False
    if not re.fullmatch(r"[a-z0-9][a-z0-9._~-]*(?:/[a-z0-9][a-z0-9._~+\-]*)+", name):
        return False
    return "." in name.split("/", 1)[0]


def is_valid_cargo_name(name: str) -> bool:
    return len(name) <= 128 and bool(re.fullmatch(r"[a-z0-9][a-z0-9_-]*", name))


def is_valid_composer_name(name: str) -> bool:
    return len(name) <= 200 and bool(re.fullmatch(r"[a-z0-9][a-z0-9_.-]*/[a-z0-9][a-z0-9_.-]*", name))


def is_valid_maven_name(name: str) -> bool:
    if len(name) > 321 or name.count(":") != 1:
        return False
    group, artifact = name.split(":", 1)
    return name == name.lower() and bool(re.fullmatch(r"[a-z0-9][a-z0-9_.-]*", group) and re.fullmatch(r"[a-z0-9][a-z0-9_.-]*", artifact))


def is_valid_nuget_name(name: str) -> bool:
    return len(name) <= 200 and name == name.lower() and bool(re.fullmatch(r"[a-z0-9][a-z0-9_.-]*", name))


def looks_like_url(value: str) -> bool:
    return bool(re.search(r"(?:^|\s)[A-Za-z][A-Za-z0-9+.-]*://", value))


def looks_like_vcs(value: str) -> bool:
    lowered = value.lower()
    vcs_markers = ("git+", "git://", "git@", "hg+", "svn+", "bzr+", "github:", "gitlab:", "bitbucket:")
    return any(marker in lowered for marker in vcs_markers)


def looks_like_local_path(value: str) -> bool:
    normalized = value.strip().lower()
    if re.match(r"^[a-z]:[\\/]", normalized):
        return True
    return normalized.startswith(("./", "../", ".\\", "..\\", "/", "\\", "~", "file:"))


def looks_like_npm_repository_shorthand(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:#[^\s]+)?", value.strip()))


def extract_exact_version(specifier: str, ecosystem: str) -> str | None:
    value = specifier.strip()
    if not value:
        return None
    if ecosystem == "pypi":
        match = re.fullmatch(r"==\s*([^,;\s]+)", value)
        return match.group(1) if match else None
    if ecosystem == "go":
        return value if re.fullmatch(r"v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?", value) else None
    if ecosystem == "cargo":
        return value if re.fullmatch(r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?", value) else None
    if ecosystem == "composer":
        matched = re.fullmatch(r"v?((?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)", value)
        return matched.group(1) if matched else None
    if ecosystem == "maven":
        return value if is_supported_maven_version(value) else None
    if ecosystem == "nuget":
        return canonicalize_nuget_version(value)
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
