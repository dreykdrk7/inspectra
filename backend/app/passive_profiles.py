"""Closed, source-free catalog for passive project analysis profiles.

Profiles are backend-owned declarations, never request-controlled bundles.  A
profile describes what a project analysis may do; the immutable execution
profile records the effective resource contract on every admitted job.
"""

from __future__ import annotations

from app.execution_profile import EXECUTION_RULESET_VERSION
from app.models import PassiveAnalysisProfile


PASSIVE_PROFILE_CONTRACT_VERSION = "2026-09-09.6"
DEFAULT_PASSIVE_PROFILE = "project_archive_basic"


_PROJECT_ARCHIVE_BASIC = PassiveAnalysisProfile(
    contract_version=PASSIVE_PROFILE_CONTRACT_VERSION,
    profile_name=DEFAULT_PASSIVE_PROFILE,
    title="Safe manifest and dependency review",
    ruleset_version=EXECUTION_RULESET_VERSION,
    safe_default=True,
    selection_mode="manifest_driven_closed_catalog",
    execution_mode="passive_no_project_execution",
    network_access="disabled",
    supported_stacks=["npm", "PyPI", "Go", "Rust", "PHP", "JVM", ".NET", "mixed manifest repositories"],
    rules=[
        {
            "id": "archive_safety_limits",
            "category": "archive_safety",
            "applies_to": ["ZIP", "TAR"],
            "description": "Rejects or truncates unsafe paths, links, excessive entries, expansion, manifests, lockfiles, packages, and edges.",
        },
        {
            "id": "manifest_parse_integrity",
            "category": "coverage",
            "applies_to": ["package.json", "requirements.txt", "pyproject.toml", "Pipfile", "go.mod"],
            "description": "Reports unreadable, malformed, unsupported, skipped, or incomplete manifest coverage instead of claiming a clean result.",
        },
        {
            "id": "dependency_repeatability",
            "category": "dependency_hygiene",
            "applies_to": ["npm", "PyPI", "Go", "Rust", "PHP", "JVM", ".NET"],
            "description": "Flags broad or non-exact requirements, reports aggregate hash evidence for exact requirements without retaining digests, and preserves exact lockfile resolution only under the declared pairing policy.",
        },
        {
            "id": "dependency_source_boundary",
            "category": "dependency_hygiene",
            "applies_to": ["npm", "PyPI", "Go", "Rust", "PHP", "JVM", ".NET"],
            "description": "Treats URL, VCS, local, workspace, replacement, private, or ambiguous identities as non-correlatable and withholds their source.",
        },
        {
            "id": "package_execution_indicators",
            "category": "package_execution",
            "applies_to": ["package.json", "requirements.txt"],
            "description": "Reports package scripts and install-affecting options for manual review without executing a package manager.",
        },
        {
            "id": "multi_ecosystem_coverage",
            "category": "coverage",
            "applies_to": ["mixed manifest repositories"],
            "description": "Makes multiple detected ecosystems and their separate coverage visible to the operator.",
        },
        {
            "id": "sensitive_data_indicators",
            "category": "sensitive_data",
            "applies_to": ["supported text configuration"],
            "description": "Detects bounded sensitive-file and credential indicators while persisting only redacted evidence and safe location context.",
        },
        {
            "id": "container_configuration",
            "category": "coverage",
            "applies_to": ["Dockerfile", "Compose"],
            "description": "Applies bounded Dockerfile and Compose configuration rules without building images, resolving references, or starting services.",
        },
        {
            "id": "kubernetes_configuration",
            "category": "coverage",
            "applies_to": ["Kubernetes YAML", "Helm values", "Kustomize context"],
            "description": "Applies bounded Kubernetes configuration indicators without contacting a cluster or rendering templates.",
        },
        {
            "id": "terraform_configuration",
            "category": "coverage",
            "applies_to": ["Terraform", "OpenTofu", "Terragrunt"],
            "description": "Applies bounded infrastructure-as-code indicators without evaluating modules, state, providers, or plans.",
        },
        {
            "id": "declared_license_review",
            "category": "license",
            "applies_to": ["package.json", "pyproject.toml", "CycloneDX", "SPDX"],
            "description": "Inventories only supported root-project SPDX declarations and optionally compares exact identifiers with an operator-owned deny list; it does not make legal conclusions.",
        },
    ],
    exclusions=[
        "Project code, scripts, hooks, build steps, tests, installers, and package managers are never executed.",
        "No network or public-advisory query is enabled by this analysis profile.",
        "Application-framework, database, cache, and proxy deep configuration reviews remain separate capabilities until explicitly integrated.",
        "Dependency licenses, compatibility, obligations, exceptions, and legal conclusions are not inferred.",
        "Unsupported lockfile formats and ambiguous, private, local, Git, URL, or workspace package identities are not resolved as public components.",
        "A partial, truncated, malformed, or unsupported input is reported as a coverage limitation, never as evidence of absence of risk.",
    ],
)


def get_passive_analysis_profile(profile_name: str) -> PassiveAnalysisProfile:
    """Resolve only a server-owned identifier from the closed catalog."""

    if profile_name != DEFAULT_PASSIVE_PROFILE:
        raise ValueError("Unknown passive analysis profile.")
    return _PROJECT_ARCHIVE_BASIC


def default_passive_analysis_profile() -> PassiveAnalysisProfile:
    return get_passive_analysis_profile(DEFAULT_PASSIVE_PROFILE)
