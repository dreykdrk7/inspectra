"""Versioned, non-sensitive contract for passive source worker isolation."""

from __future__ import annotations

from typing import Any


ISOLATED_RUNNER_CONTRACT_VERSION = "2026-09-06.1"
ISOLATED_RUNNER_LIMITS = {
    "source_bytes": 20_971_520,
    "wall_time_seconds": 55.0,
    "cpu_seconds": 45,
    "memory_bytes": 402_653_184,
    "result_bytes": 4_194_304,
    "file_bytes": 33_554_432,
    "open_files": 64,
    "processes": 32,
}
ISOLATED_RUNNER_FILE_AUDIT_TYPES = frozenset(
    {
        "pdf_basic",
        "image_basic",
        "manifest_basic",
        "archive_basic",
        "project_archive_basic",
        "django_config_basic",
        "docker_config_basic",
        "secrets_review_basic",
        "node_package_config_basic",
        "ci_cd_config_basic",
        "k8s_config_basic",
        "terraform_config_basic",
        "nginx_config_basic",
        "compose_config_basic",
        "database_config_basic",
        "sql_database_config_basic",
        "redis_config_basic",
    }
)


def isolated_runner_contract() -> dict[str, Any]:
    return {
        "contract_version": ISOLATED_RUNNER_CONTRACT_VERSION,
        "source_transport": "inline_base64_sha256_v1",
        "source_scope": "single_request",
        "worker_lifecycle": "ephemeral_subprocess",
        "max_concurrent_source_workers": 1,
        "limits": dict(ISOLATED_RUNNER_LIMITS),
        "temporary_storage": "request_scoped_tmpfs_cleanup",
    }
