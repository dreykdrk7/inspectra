"""Public, source-free capability catalog for project archive preflight."""

from __future__ import annotations

from app.config import Settings
from app.execution_profile import build_execution_profile
from app.models import ProjectArchivePreflightResponse
from app.passive_profiles import DEFAULT_PASSIVE_PROFILE, default_passive_analysis_profile


PROJECT_ARCHIVE_PREFLIGHT_CONTRACT_VERSION = "2026-09-09.4"


def build_project_archive_preflight(settings: Settings) -> ProjectArchivePreflightResponse:
    """Describe the current passive project workflow without opening an upload.

    The catalog deliberately contains only stable format names and the backend's
    configured upload bound. Runner limits remain defensive and are reported by
    the completed analysis, because this endpoint must not inspect a selected
    archive or infer per-file coverage before it is submitted.
    """

    return ProjectArchivePreflightResponse(
        contract_version=PROJECT_ARCHIVE_PREFLIGHT_CONTRACT_VERSION,
        status="available",
        accepted_archive_formats=[".zip", ".tar", ".tar.gz", ".tgz"],
        upload_limit_bytes=settings.max_upload_bytes,
        analysis_profile=default_passive_analysis_profile(),
        execution_profile=build_execution_profile(
            settings,
            audit_type="project_archive_basic",
            analysis_profile=DEFAULT_PASSIVE_PROFILE,
        ),
        supported_manifests=[
            {"name": "package.json", "ecosystem": "npm", "coverage": "dependency declarations"},
            {"name": "requirements.txt", "ecosystem": "PyPI", "coverage": "dependency declarations plus aggregate hash evidence for exact pins; digest values are discarded"},
            {"name": "pyproject.toml", "ecosystem": "PyPI", "coverage": "supported dependency declarations"},
            {"name": "Pipfile", "ecosystem": "PyPI", "coverage": "bounded packages/dev-packages declarations; source locators are discarded"},
            {"name": "go.mod", "ecosystem": "Go", "coverage": "exact require declarations; replace targets are discarded"},
            {"name": "Cargo.toml", "ecosystem": "Rust", "coverage": "same-root marker only; dependency resolution comes from a supported Cargo lock"},
            {"name": "composer.json", "ecosystem": "PHP", "coverage": "same-root marker and custom-repository boundary; dependency resolution comes from the lock"},
            {"name": "build.gradle[.kts]", "ecosystem": "JVM", "coverage": "same-root marker only; build DSL is never evaluated"},
            {"name": "*.csproj", "ecosystem": ".NET", "coverage": "same-root marker only; MSBuild content is never evaluated"},
        ],
        exact_resolution=[
            {
                "name": "package-lock.json",
                "ecosystem": "npm",
                "coverage": "exact registry versions only when one npm v2/v3 lockfile matches the manifest root",
            },
            {
                "name": "pnpm-lock.yaml",
                "ecosystem": "npm",
                "coverage": "exact direct local versions only when one pnpm v9 lockfile matches the manifest root; never public-advisory egress",
            },
            {
                "name": "yarn.lock (Classic v1)",
                "ecosystem": "npm",
                "coverage": "exact direct local versions only when one Classic v1 lockfile selector matches the manifest root; Berry remains detected but not resolved; never public-advisory egress",
            },
            {
                "name": "poetry.lock (v2.1)",
                "ecosystem": "PyPI",
                "coverage": "exact direct local versions only when one Poetry v2.1 lockfile matches the pyproject root; never public-advisory egress",
            },
            {
                "name": "Pipfile.lock (v6)",
                "ecosystem": "PyPI",
                "coverage": "exact grouped direct local versions only when one v6 lockfile matches the Pipfile root; hashes and sources are discarded; never public-advisory egress",
            },
            {
                "name": "go.sum",
                "ecosystem": "Go",
                "coverage": "exact local versions only when one go.sum matches the go.mod root; OSV additionally requires an exact operator public-module attestation",
            },
            {
                "name": "Cargo.lock (v3/v4)",
                "ecosystem": "Rust",
                "coverage": "exact crates with supported official crates.io provenance only; sources and checksums are discarded",
            },
            {
                "name": "composer.lock",
                "ecosystem": "PHP",
                "coverage": "exact local versions under the supported structural contract; public origin requires exact operator attestation",
            },
            {
                "name": "gradle.lockfile",
                "ecosystem": "JVM",
                "coverage": "bounded exact coordinates only; configurations are discarded and public origin requires exact operator attestation",
            },
            {
                "name": "packages.lock.json (v1)",
                "ecosystem": ".NET",
                "coverage": "bounded exact versions under an unambiguous target; public origin requires exact operator attestation",
            },
        ],
        detected_not_resolved=[],
        limitations=[
            "The preview does not open, upload, hash, or inspect a selected archive.",
            "The runner applies bounded entry, manifest, and lockfile limits; actual coverage is reported only after analysis.",
            "Unsupported, unsafe, malformed, or over-limit entries remain coverage limitations, not a clean result.",
        ],
        boundaries=[
            "Inspectra does not execute project code or install dependencies.",
            "This preview does not send source contents, paths, or project metadata to public providers.",
            "A project still requires explicit authorization confirmation after a validated archive upload.",
        ],
    )
