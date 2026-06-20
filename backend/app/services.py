from __future__ import annotations

from typing import Any, Mapping, Protocol

import httpx

from active_runner.dry_run import run_active_network_dry_run
from active_runner.http_header_probe import run_authorized_http_header_probe
from active_runner.models import ActiveDryRunRequest, ActiveHttpHeaderProbeRequest
from active_runner.nmap_basic.parser import parse_active_nmap_basic_xml
from active_runner.nmap_basic.result import build_active_nmap_basic_result_payload
from app.config import Settings
from app.active_nmap_handoff import ActiveNmapBasicHandoffPlan, ActiveNmapBasicHandoffUnit
from app.project_archive_findings import categorize_project_archive_result
from app.reporting import (
    redact_active_config_value,
    redact_active_secret_text,
    redact_ci_cd_config_value,
    redact_ci_cd_secret_text,
    redact_compose_config_value,
    redact_database_config_value,
    redact_sql_database_config_value,
    redact_sql_database_secret_text,
    redact_k8s_config_value,
    redact_nginx_config_value,
    redact_redis_config_value,
    redact_redis_secret_text,
    redact_terraform_config_value,
)
from app.storage import FileStore, JobStore


ACTIVE_NMAP_BASIC_CONTROLLED_EXECUTION_STATUSES = {
    "completed",
    "failed",
    "timed_out",
    "nmap_missing",
    "not_executed",
}
ACTIVE_NMAP_BASIC_CONTROLLED_REASONS = {
    "raw_bounded",
    "test_double_no_live",
    "mocked_completed",
    "mocked_failed",
    "mocked_timed_out",
    "mocked_nmap_missing",
    "mocked_malformed",
    "mocked_truncated",
    "mocked_no_ports",
    "nmap_nonzero_exit",
    "process_timeout",
    "nmap_missing",
}


class ActiveNmapBasicExecutorAdapter(Protocol):
    adapter_name: str

    def execute(self, unit: ActiveNmapBasicHandoffUnit) -> Mapping[str, Any]:
        """Return a bounded synthetic execution result for one validated target."""


class ActiveNmapBasicNoLiveExecutorAdapter:
    adapter_name = "test_double_no_live"

    def execute(self, unit: ActiveNmapBasicHandoffUnit) -> Mapping[str, Any]:
        return {
            "status": "not_executed",
            "execution_attempted": False,
            "output_truncated": False,
            "stderr_truncated": False,
            "timed_out": False,
            "reason": "test_double_no_live",
        }


class PdfAuditService:
    def __init__(self, settings: Settings, files: FileStore, jobs: JobStore) -> None:
        self.settings = settings
        self.files = files
        self.jobs = jobs

    async def run_pdf_analysis(self, job_id: str) -> None:
        job = self.jobs.update(job_id, status="running")
        stored_file = self.files.get(job.file_id)
        payload = {
            "file_id": stored_file.id,
            "relative_path": self.files.relative_upload_path(stored_file),
        }

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(f"{self.settings.tool_runner_url}/analyze/pdf", json=payload)
                response.raise_for_status()
        except httpx.HTTPError as exc:
            self.jobs.update(job_id, status="failed", error=f"Tool runner request failed: {exc}")
            return

        self.jobs.update(job_id, status="completed", result=response.json())


class ImageAuditService:
    def __init__(self, settings: Settings, files: FileStore, jobs: JobStore) -> None:
        self.settings = settings
        self.files = files
        self.jobs = jobs

    async def run_image_analysis(self, job_id: str) -> None:
        job = self.jobs.update(job_id, status="running")
        stored_file = self.files.get(job.file_id)
        payload = {
            "file_id": stored_file.id,
            "relative_path": self.files.relative_upload_path(stored_file),
        }

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(f"{self.settings.tool_runner_url}/analyze/image", json=payload)
                response.raise_for_status()
        except httpx.HTTPError as exc:
            self.jobs.update(job_id, status="failed", error=f"Tool runner request failed: {exc}")
            return

        self.jobs.update(job_id, status="completed", result=response.json())


class ManifestAuditService:
    def __init__(self, settings: Settings, files: FileStore, jobs: JobStore) -> None:
        self.settings = settings
        self.files = files
        self.jobs = jobs

    async def run_manifest_analysis(self, job_id: str) -> None:
        job = self.jobs.update(job_id, status="running")
        stored_file = self.files.get(job.file_id)
        payload = {
            "file_id": stored_file.id,
            "relative_path": self.files.relative_upload_path(stored_file),
            "original_filename": stored_file.original_filename,
        }

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(f"{self.settings.tool_runner_url}/analyze/manifest", json=payload)
                response.raise_for_status()
        except httpx.HTTPError as exc:
            self.jobs.update(job_id, status="failed", error=f"Tool runner request failed: {exc}")
            return

        self.jobs.update(job_id, status="completed", result=response.json())


class ArchiveAuditService:
    def __init__(self, settings: Settings, files: FileStore, jobs: JobStore) -> None:
        self.settings = settings
        self.files = files
        self.jobs = jobs

    async def run_archive_analysis(self, job_id: str) -> None:
        job = self.jobs.update(job_id, status="running")
        stored_file = self.files.get(job.file_id)
        payload = {
            "file_id": stored_file.id,
            "relative_path": self.files.relative_upload_path(stored_file),
            "original_filename": stored_file.original_filename,
        }

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(f"{self.settings.tool_runner_url}/analyze/archive", json=payload)
                response.raise_for_status()
        except httpx.HTTPError as exc:
            self.jobs.update(job_id, status="failed", error=f"Tool runner request failed: {exc}")
            return

        self.jobs.update(job_id, status="completed", result=response.json())


class ProjectArchiveAuditService:
    def __init__(self, settings: Settings, files: FileStore, jobs: JobStore) -> None:
        self.settings = settings
        self.files = files
        self.jobs = jobs

    async def run_project_archive_analysis(self, job_id: str) -> None:
        job = self.jobs.update(job_id, status="running")
        stored_file = self.files.get(job.file_id)
        payload = {
            "file_id": stored_file.id,
            "relative_path": self.files.relative_upload_path(stored_file),
            "original_filename": stored_file.original_filename,
        }

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(f"{self.settings.tool_runner_url}/analyze/project-archive", json=payload)
                response.raise_for_status()
        except httpx.HTTPError as exc:
            self.jobs.update(job_id, status="failed", error=f"Tool runner request failed: {exc}")
            return

        self.jobs.update(job_id, status="completed", result=categorize_project_archive_result(response.json()))


class DjangoConfigAuditService:
    def __init__(self, settings: Settings, files: FileStore, jobs: JobStore) -> None:
        self.settings = settings
        self.files = files
        self.jobs = jobs

    async def run_django_config_analysis(self, job_id: str) -> None:
        job = self.jobs.update(job_id, status="running")
        stored_file = self.files.get(job.file_id)
        payload = {
            "file_id": stored_file.id,
            "relative_path": self.files.relative_upload_path(stored_file),
            "original_filename": stored_file.original_filename,
            "max_files": self.settings.django_config_max_files,
            "max_file_bytes": self.settings.django_config_max_file_bytes,
            "max_total_bytes": self.settings.django_config_max_total_bytes,
        }

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(f"{self.settings.tool_runner_url}/analyze/django-config", json=payload)
                response.raise_for_status()
        except httpx.HTTPError as exc:
            self.jobs.update(job_id, status="failed", error=f"Tool runner request failed: {exc}")
            return

        self.jobs.update(job_id, status="completed", result=response.json())


class DockerConfigAuditService:
    def __init__(self, settings: Settings, files: FileStore, jobs: JobStore) -> None:
        self.settings = settings
        self.files = files
        self.jobs = jobs

    async def run_docker_config_analysis(self, job_id: str) -> None:
        job = self.jobs.update(job_id, status="running")
        stored_file = self.files.get(job.file_id)
        payload = {
            "file_id": stored_file.id,
            "relative_path": self.files.relative_upload_path(stored_file),
            "original_filename": stored_file.original_filename,
            "max_files": self.settings.docker_config_max_files,
            "max_file_bytes": self.settings.docker_config_max_file_bytes,
            "max_total_bytes": self.settings.docker_config_max_total_bytes,
        }

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(f"{self.settings.tool_runner_url}/analyze/docker-config", json=payload)
                response.raise_for_status()
        except httpx.HTTPError as exc:
            self.jobs.update(job_id, status="failed", error=f"Tool runner request failed: {exc}")
            return

        self.jobs.update(job_id, status="completed", result=response.json())


class SecretsReviewAuditService:
    def __init__(self, settings: Settings, files: FileStore, jobs: JobStore) -> None:
        self.settings = settings
        self.files = files
        self.jobs = jobs

    async def run_secrets_review_analysis(self, job_id: str) -> None:
        job = self.jobs.update(job_id, status="running")
        stored_file = self.files.get(job.file_id)
        payload = {
            "file_id": stored_file.id,
            "relative_path": self.files.relative_upload_path(stored_file),
            "original_filename": stored_file.original_filename,
            "max_files": self.settings.secrets_review_max_files,
            "max_file_bytes": self.settings.secrets_review_max_file_bytes,
            "max_total_bytes": self.settings.secrets_review_max_total_bytes,
        }

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(f"{self.settings.tool_runner_url}/analyze/secrets-review", json=payload)
                response.raise_for_status()
        except httpx.HTTPError as exc:
            self.jobs.update(job_id, status="failed", error=f"Tool runner request failed: {exc}")
            return

        self.jobs.update(job_id, status="completed", result=response.json())


class NodePackageConfigAuditService:
    def __init__(self, settings: Settings, files: FileStore, jobs: JobStore) -> None:
        self.settings = settings
        self.files = files
        self.jobs = jobs

    async def run_node_package_config_analysis(self, job_id: str) -> None:
        job = self.jobs.update(job_id, status="running")
        stored_file = self.files.get(job.file_id)
        payload = {
            "file_id": stored_file.id,
            "relative_path": self.files.relative_upload_path(stored_file),
            "original_filename": stored_file.original_filename,
            "max_files": self.settings.node_package_config_max_files,
            "max_file_bytes": self.settings.node_package_config_max_file_bytes,
            "max_total_bytes": self.settings.node_package_config_max_total_bytes,
        }

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(f"{self.settings.tool_runner_url}/analyze/node-package-config", json=payload)
                response.raise_for_status()
        except httpx.HTTPError as exc:
            self.jobs.update(job_id, status="failed", error=f"Tool runner request failed: {exc}")
            return

        self.jobs.update(job_id, status="completed", result=response.json())


class CiCdConfigAuditService:
    def __init__(self, settings: Settings, files: FileStore, jobs: JobStore) -> None:
        self.settings = settings
        self.files = files
        self.jobs = jobs

    async def run_ci_cd_config_analysis(self, job_id: str) -> None:
        job = self.jobs.update(job_id, status="running")
        stored_file = self.files.get(job.file_id)
        payload = {
            "file_id": stored_file.id,
            "relative_path": self.files.relative_upload_path(stored_file),
            "original_filename": stored_file.original_filename,
            "max_files": self.settings.ci_cd_config_max_files,
            "max_file_bytes": self.settings.ci_cd_config_max_file_bytes,
            "max_total_bytes": self.settings.ci_cd_config_max_total_bytes,
        }

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(f"{self.settings.tool_runner_url}/analyze/ci-cd-config", json=payload)
                response.raise_for_status()
        except httpx.HTTPError as exc:
            self.jobs.update(job_id, status="failed", error=redact_ci_cd_secret_text(f"Tool runner request failed: {exc}"))
            return

        result = redact_ci_cd_config_value(response.json())
        self.jobs.update(job_id, status="completed", result=result if isinstance(result, dict) else {"result": result})


class K8sConfigAuditService:
    def __init__(self, settings: Settings, files: FileStore, jobs: JobStore) -> None:
        self.settings = settings
        self.files = files
        self.jobs = jobs

    async def run_k8s_config_analysis(self, job_id: str) -> None:
        job = self.jobs.update(job_id, status="running")
        stored_file = self.files.get(job.file_id)
        payload = {
            "file_id": stored_file.id,
            "relative_path": self.files.relative_upload_path(stored_file),
            "original_filename": stored_file.original_filename,
            "max_files": self.settings.k8s_config_max_files,
            "max_file_bytes": self.settings.k8s_config_max_file_bytes,
            "max_total_bytes": self.settings.k8s_config_max_total_bytes,
        }

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(f"{self.settings.tool_runner_url}/analyze/k8s-config", json=payload)
                response.raise_for_status()
        except httpx.HTTPError as exc:
            self.jobs.update(job_id, status="failed", error=f"Tool runner request failed: {exc}")
            return

        result = redact_k8s_config_value(response.json())
        self.jobs.update(job_id, status="completed", result=result if isinstance(result, dict) else {"result": result})


class TerraformConfigAuditService:
    def __init__(self, settings: Settings, files: FileStore, jobs: JobStore) -> None:
        self.settings = settings
        self.files = files
        self.jobs = jobs

    async def run_terraform_config_analysis(self, job_id: str) -> None:
        job = self.jobs.update(job_id, status="running")
        stored_file = self.files.get(job.file_id)
        payload = {
            "file_id": stored_file.id,
            "relative_path": self.files.relative_upload_path(stored_file),
            "original_filename": stored_file.original_filename,
            "max_files": self.settings.terraform_config_max_files,
            "max_file_bytes": self.settings.terraform_config_max_file_bytes,
            "max_total_bytes": self.settings.terraform_config_max_total_bytes,
        }

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(f"{self.settings.tool_runner_url}/analyze/terraform-config", json=payload)
                response.raise_for_status()
        except httpx.HTTPError as exc:
            self.jobs.update(job_id, status="failed", error=f"Tool runner request failed: {exc}")
            return

        result = redact_terraform_config_value(response.json())
        self.jobs.update(job_id, status="completed", result=result if isinstance(result, dict) else {"result": result})


class NginxConfigAuditService:
    def __init__(self, settings: Settings, files: FileStore, jobs: JobStore) -> None:
        self.settings = settings
        self.files = files
        self.jobs = jobs

    async def run_nginx_config_analysis(self, job_id: str) -> None:
        job = self.jobs.update(job_id, status="running")
        stored_file = self.files.get(job.file_id)
        payload = {
            "file_id": stored_file.id,
            "relative_path": self.files.relative_upload_path(stored_file),
            "original_filename": stored_file.original_filename,
            "max_files": self.settings.nginx_config_max_files,
            "max_file_bytes": self.settings.nginx_config_max_file_bytes,
            "max_total_bytes": self.settings.nginx_config_max_total_bytes,
        }

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(f"{self.settings.tool_runner_url}/analyze/nginx-config", json=payload)
                response.raise_for_status()
        except httpx.HTTPError as exc:
            self.jobs.update(job_id, status="failed", error=f"Tool runner request failed: {exc}")
            return

        result = redact_nginx_config_value(response.json())
        self.jobs.update(job_id, status="completed", result=result if isinstance(result, dict) else {"result": result})


class ComposeConfigAuditService:
    def __init__(self, settings: Settings, files: FileStore, jobs: JobStore) -> None:
        self.settings = settings
        self.files = files
        self.jobs = jobs

    async def run_compose_config_analysis(self, job_id: str) -> None:
        job = self.jobs.update(job_id, status="running")
        stored_file = self.files.get(job.file_id)
        payload = {
            "file_id": stored_file.id,
            "relative_path": self.files.relative_upload_path(stored_file),
            "original_filename": stored_file.original_filename,
            "max_files": self.settings.compose_config_max_files,
            "max_file_bytes": self.settings.compose_config_max_file_bytes,
            "max_total_bytes": self.settings.compose_config_max_total_bytes,
        }

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(f"{self.settings.tool_runner_url}/analyze/compose-config", json=payload)
                response.raise_for_status()
        except httpx.HTTPError as exc:
            self.jobs.update(job_id, status="failed", error=f"Tool runner request failed: {exc}")
            return

        result = redact_compose_config_value(response.json())
        self.jobs.update(job_id, status="completed", result=result if isinstance(result, dict) else {"result": result})


class DatabaseConfigAuditService:
    def __init__(self, settings: Settings, files: FileStore, jobs: JobStore) -> None:
        self.settings = settings
        self.files = files
        self.jobs = jobs

    async def run_database_config_analysis(self, job_id: str) -> None:
        job = self.jobs.update(job_id, status="running")
        stored_file = self.files.get(job.file_id)
        payload = {
            "file_id": stored_file.id,
            "relative_path": self.files.relative_upload_path(stored_file),
            "original_filename": stored_file.original_filename,
            "max_files": self.settings.database_config_max_files,
            "max_file_bytes": self.settings.database_config_max_file_bytes,
            "max_total_bytes": self.settings.database_config_max_total_bytes,
        }

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(f"{self.settings.tool_runner_url}/analyze/database-config", json=payload)
                response.raise_for_status()
        except httpx.HTTPError as exc:
            self.jobs.update(job_id, status="failed", error=f"Tool runner request failed: {exc}")
            return

        result = redact_database_config_value(response.json())
        self.jobs.update(job_id, status="completed", result=result if isinstance(result, dict) else {"result": result})


class SqlDatabaseConfigAuditService:
    def __init__(self, settings: Settings, files: FileStore, jobs: JobStore) -> None:
        self.settings = settings
        self.files = files
        self.jobs = jobs

    async def run_sql_database_config_analysis(self, job_id: str) -> None:
        job = self.jobs.update(job_id, status="running")
        stored_file = self.files.get(job.file_id)
        payload = {
            "file_id": stored_file.id,
            "relative_path": self.files.relative_upload_path(stored_file),
            "original_filename": stored_file.original_filename,
            "max_files": self.settings.sql_database_config_max_files,
            "max_file_bytes": self.settings.sql_database_config_max_file_bytes,
            "max_total_bytes": self.settings.sql_database_config_max_total_bytes,
        }

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(f"{self.settings.tool_runner_url}/analyze/sql-database-config", json=payload)
                response.raise_for_status()
        except httpx.HTTPError as exc:
            self.jobs.update(job_id, status="failed", error=redact_sql_database_secret_text(f"Tool runner request failed: {exc}"))
            return

        result = redact_sql_database_config_value(response.json())
        self.jobs.update(job_id, status="completed", result=result if isinstance(result, dict) else {"result": result})


class RedisConfigAuditService:
    def __init__(self, settings: Settings, files: FileStore, jobs: JobStore) -> None:
        self.settings = settings
        self.files = files
        self.jobs = jobs

    async def run_redis_config_analysis(self, job_id: str) -> None:
        job = self.jobs.update(job_id, status="running")
        stored_file = self.files.get(job.file_id)
        payload = {
            "file_id": stored_file.id,
            "relative_path": self.files.relative_upload_path(stored_file),
            "original_filename": stored_file.original_filename,
            "max_files": self.settings.redis_config_max_files,
            "max_file_bytes": self.settings.redis_config_max_file_bytes,
            "max_total_bytes": self.settings.redis_config_max_total_bytes,
        }

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(f"{self.settings.tool_runner_url}/analyze/redis-config", json=payload)
                response.raise_for_status()
        except httpx.HTTPError as exc:
            self.jobs.update(job_id, status="failed", error=redact_redis_secret_text(f"Tool runner request failed: {exc}"))
            return

        result = redact_redis_config_value(response.json())
        self.jobs.update(job_id, status="completed", result=result if isinstance(result, dict) else {"result": result})


class ActiveNetworkDryRunService:
    def __init__(self, settings: Settings, jobs: JobStore) -> None:
        self.settings = settings
        self.jobs = jobs

    async def run_active_network_dry_run_analysis(self, job_id: str, active_request: ActiveDryRunRequest) -> None:
        self.jobs.update(job_id, status="running")
        try:
            result = run_active_network_dry_run(active_request)
        except Exception as exc:  # pragma: no cover - defensive controlled failure path.
            self.jobs.update(job_id, status="failed", error=redact_active_secret_text(f"Active dry-run failed: {exc}"))
            return

        redacted_result = redact_active_config_value(result)
        self.jobs.update(job_id, status="completed", result=redacted_result if isinstance(redacted_result, dict) else {"result": redacted_result})


class ActiveHttpHeaderProbeService:
    def __init__(self, settings: Settings, jobs: JobStore) -> None:
        self.settings = settings
        self.jobs = jobs

    async def run_active_http_header_probe_analysis(self, job_id: str, active_request: ActiveHttpHeaderProbeRequest) -> None:
        self.jobs.update(job_id, status="running")
        try:
            result = run_authorized_http_header_probe(active_request)
        except Exception as exc:  # pragma: no cover - defensive controlled failure path.
            self.jobs.update(job_id, status="failed", error=redact_active_secret_text(f"Active HTTP header probe failed: {exc}"))
            return

        redacted_result = redact_active_config_value(result)
        self.jobs.update(job_id, status="completed", result=redacted_result if isinstance(redacted_result, dict) else {"result": redacted_result})


class ActiveNmapBasicService:
    def __init__(
        self,
        settings: Settings,
        jobs: JobStore,
        executor_adapter: ActiveNmapBasicExecutorAdapter | None = None,
    ) -> None:
        self.settings = settings
        self.jobs = jobs
        self.executor_adapter = executor_adapter or ActiveNmapBasicNoLiveExecutorAdapter()

    async def record_no_live_result(self, job_id: str, handoff_plan: ActiveNmapBasicHandoffPlan) -> None:
        await self.run_active_nmap_basic_analysis(job_id, handoff_plan)

    async def run_active_nmap_basic_analysis(self, job_id: str, handoff_plan: ActiveNmapBasicHandoffPlan) -> None:
        self.jobs.update(job_id, status="running")
        try:
            result = self._build_result_payload(handoff_plan)
        except Exception as exc:  # pragma: no cover - defensive controlled failure path.
            self.jobs.update(job_id, status="failed", error=redact_active_secret_text(f"active_nmap_basic adapter failed: {exc}"))
            return

        self.jobs.update(job_id, status="completed", result=result)

    def _build_result_payload(self, handoff_plan: ActiveNmapBasicHandoffPlan) -> dict[str, Any]:
        unit_payloads: list[dict[str, Any]] = []
        for unit in handoff_plan.units:
            raw_execution_result = self.executor_adapter.execute(unit)
            execution_result = _controlled_active_nmap_basic_execution_result(raw_execution_result)
            parse_result = _active_nmap_basic_parse_result(raw_execution_result, execution_result)
            unit_payloads.append(build_active_nmap_basic_result_payload(execution_result, parse_result))

        result = _aggregate_active_nmap_basic_unit_payloads(unit_payloads)
        adapter_name = _safe_active_nmap_basic_adapter_name(getattr(self.executor_adapter, "adapter_name", "mocked_executor"))
        result.update(
            {
                "execution_state": result.get("status", "failed"),
                "job_created": True,
                "adapter": adapter_name,
                "executor_adapter": adapter_name,
                "executor_adapter_invoked": bool(handoff_plan.units),
                "runner_connected": False,
                "nmap_executed": False,
                "network_requests_sent": 0,
                "dns_queries_sent": 0,
                "subprocess_invoked": False,
                "target_count": handoff_plan.target_count,
                "port_count": handoff_plan.port_count,
                "target_port_checks": handoff_plan.target_port_checks,
                "implicit_concurrency": handoff_plan.implicit_concurrency,
            }
        )
        result["limits"].update(
            {
                "max_targets": handoff_plan.target_count,
                "max_ports_per_target": handoff_plan.port_count,
                "max_total_target_port_checks": handoff_plan.target_port_checks,
            }
        )
        result["summary"].update(
            {
                "target_count": handoff_plan.target_count,
                "port_count": handoff_plan.port_count,
                "target_port_checks": handoff_plan.target_port_checks,
                "network_requests_sent": 0,
                "dns_queries_sent": 0,
                "adapter": adapter_name,
                "executor_adapter": adapter_name,
            }
        )
        return result


ActiveNmapBasicNoLiveService = ActiveNmapBasicService


def _controlled_active_nmap_basic_execution_result(raw_result: Mapping[str, Any]) -> dict[str, Any]:
    status = raw_result.get("status")
    controlled_status = status if isinstance(status, str) and status in ACTIVE_NMAP_BASIC_CONTROLLED_EXECUTION_STATUSES else "failed"
    reason = raw_result.get("reason")
    controlled_reason = (
        reason
        if isinstance(reason, str) and reason in ACTIVE_NMAP_BASIC_CONTROLLED_REASONS
        else _default_active_nmap_basic_reason(controlled_status)
    )
    return {
        "status": controlled_status,
        "execution_attempted": bool(raw_result.get("execution_attempted")),
        "output_truncated": bool(raw_result.get("output_truncated")),
        "stderr_truncated": bool(raw_result.get("stderr_truncated")),
        "timed_out": bool(raw_result.get("timed_out")) or controlled_status == "timed_out",
        "reason": controlled_reason,
        "stdout": raw_result.get("stdout"),
    }


def _active_nmap_basic_parse_result(
    raw_execution_result: Mapping[str, Any],
    execution_result: Mapping[str, Any],
) -> Mapping[str, Any] | None:
    parse_result = raw_execution_result.get("parse_result")
    if isinstance(parse_result, Mapping):
        return parse_result
    if execution_result.get("status") != "completed":
        return None
    return parse_active_nmap_basic_xml(execution_result.get("stdout"))


def _aggregate_active_nmap_basic_unit_payloads(unit_payloads: list[dict[str, Any]]) -> dict[str, Any]:
    if not unit_payloads:
        return build_active_nmap_basic_result_payload(
            {
                "status": "failed",
                "execution_attempted": False,
                "output_truncated": False,
                "stderr_truncated": False,
                "timed_out": False,
                "reason": "controlled_execution_error",
            },
            None,
        )
    if len(unit_payloads) == 1:
        return dict(unit_payloads[0])

    first = dict(unit_payloads[0])
    observations = [
        observation
        for payload in unit_payloads
        for observation in payload.get("port_observations", [])
        if isinstance(observation, dict)
    ]
    warnings = _dedupe_active_nmap_basic_strings(
        warning
        for payload in unit_payloads
        for warning in payload.get("parser_warnings", [])
        if isinstance(warning, str)
    )
    errors = _dedupe_active_nmap_basic_strings(
        error
        for payload in unit_payloads
        for error in payload.get("errors", [])
        if isinstance(error, str)
    )
    statuses = [str(payload.get("status") or "failed") for payload in unit_payloads]
    output_truncated = any(bool(payload.get("limits", {}).get("output_truncated")) for payload in unit_payloads)
    stderr_truncated = any(bool(payload.get("limits", {}).get("stderr_truncated")) for payload in unit_payloads)
    timed_out = any(bool(payload.get("limits", {}).get("timed_out")) for payload in unit_payloads)

    first["status"] = _combined_active_nmap_basic_status(statuses)
    first["execution_attempted"] = any(bool(payload.get("execution_attempted")) for payload in unit_payloads)
    first["parser_ran"] = any(bool(payload.get("parser_ran")) for payload in unit_payloads)
    first["port_observations"] = observations
    first["observation_count"] = len(observations)
    first["parser_warnings"] = warnings
    first["errors"] = errors
    first["limits"] = {
        **dict(first.get("limits") if isinstance(first.get("limits"), dict) else {}),
        "output_truncated": output_truncated,
        "stderr_truncated": stderr_truncated,
        "timed_out": timed_out,
    }
    first["summary"] = {
        **dict(first.get("summary") if isinstance(first.get("summary"), dict) else {}),
        "observation_count": len(observations),
        "open_tcp_observations_count": sum(
            1
            for observation in observations
            if observation.get("protocol") == "tcp" and observation.get("state") == "open"
        ),
    }
    return first


def _combined_active_nmap_basic_status(statuses: list[str]) -> str:
    if statuses and all(status == statuses[0] for status in statuses):
        return statuses[0]
    if "completed" in statuses:
        return "completed"
    for status in ("timed_out", "nmap_missing", "failed", "malformed", "truncated", "unsupported_shape", "no_ports", "empty", "not_executed"):
        if status in statuses:
            return status
    return "failed"


def _default_active_nmap_basic_reason(status: str) -> str:
    return {
        "completed": "raw_bounded",
        "failed": "mocked_failed",
        "timed_out": "process_timeout",
        "nmap_missing": "nmap_missing",
        "not_executed": "test_double_no_live",
    }.get(status, "controlled_execution_error")


def _safe_active_nmap_basic_adapter_name(value: object) -> str:
    if not isinstance(value, str) or not value:
        return "mocked_executor"
    if value not in {"test_double_no_live", "mocked_executor"}:
        return "mocked_executor"
    return value


def _dedupe_active_nmap_basic_strings(values) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


class WebAuditService:
    def __init__(self, settings: Settings, files: FileStore, jobs: JobStore) -> None:
        self.settings = settings
        self.files = files
        self.jobs = jobs

    async def run_web_analysis(self, job_id: str, request_url: str | None = None) -> None:
        job = self.jobs.update(job_id, status="running")
        target_url = request_url or job.target_url
        if not target_url:
            self.jobs.update(job_id, status="failed", error="Web audit job is missing a target URL.")
            return
        payload = {
            "url": target_url,
            "allow_private_targets": self.settings.web_allow_private_targets,
            "timeout_seconds": self.settings.web_timeout_seconds,
            "max_response_bytes": self.settings.web_max_response_bytes,
            "max_redirects": self.settings.web_max_redirects,
            "allowed_ports": list(self.settings.web_allowed_ports),
        }

        try:
            async with httpx.AsyncClient(timeout=self.settings.web_timeout_seconds + 10.0) as client:
                response = await client.post(f"{self.settings.tool_runner_url}/analyze/web-basic", json=payload)
                response.raise_for_status()
        except httpx.HTTPError as exc:
            self.jobs.update(job_id, status="failed", error=f"Tool runner request failed: {exc}")
            return

        self.jobs.update(job_id, status="completed", result=response.json())


DOMAIN_BASE_RECORD_QUERIES = 8
DOMAIN_DMARC_RECORD_QUERIES = 1
DOMAIN_WWW_RECORD_QUERIES = 3
DOMAIN_MAX_NAMESERVERS = 3
DOMAIN_RUNNER_TIMEOUT_MARGIN_SECONDS = 10.0


def calculate_domain_runner_timeout_seconds(dns_timeout_seconds: float, *, include_www: bool = True) -> float:
    query_count = DOMAIN_BASE_RECORD_QUERIES + DOMAIN_DMARC_RECORD_QUERIES
    if include_www:
        query_count += DOMAIN_WWW_RECORD_QUERIES
    worst_case_dns_seconds = query_count * DOMAIN_MAX_NAMESERVERS * dns_timeout_seconds
    return worst_case_dns_seconds + DOMAIN_RUNNER_TIMEOUT_MARGIN_SECONDS


def calculate_subdomain_inventory_runner_timeout_seconds(
    global_deadline_seconds: float,
    *,
    dns_timeout_seconds: float,
) -> float:
    in_flight_dns_margin_seconds = DOMAIN_MAX_NAMESERVERS * dns_timeout_seconds
    return global_deadline_seconds + in_flight_dns_margin_seconds + DOMAIN_RUNNER_TIMEOUT_MARGIN_SECONDS


class DomainAuditService:
    def __init__(self, settings: Settings, files: FileStore, jobs: JobStore) -> None:
        self.settings = settings
        self.files = files
        self.jobs = jobs

    async def run_domain_analysis(self, job_id: str) -> None:
        job = self.jobs.update(job_id, status="running")
        if not job.target_domain:
            self.jobs.update(job_id, status="failed", error="Domain audit job is missing a target domain.")
            return
        payload = {
            "domain": job.target_domain,
            "timeout_seconds": self.settings.domain_dns_timeout_seconds,
        }
        runner_timeout_seconds = calculate_domain_runner_timeout_seconds(
            self.settings.domain_dns_timeout_seconds,
            include_www=not job.target_domain.startswith("www."),
        )

        try:
            async with httpx.AsyncClient(timeout=runner_timeout_seconds) as client:
                response = await client.post(f"{self.settings.tool_runner_url}/analyze/domain-basic", json=payload)
                response.raise_for_status()
        except httpx.HTTPError as exc:
            self.jobs.update(job_id, status="failed", error=f"Tool runner request failed: {exc}")
            return

        self.jobs.update(job_id, status="completed", result=response.json())


class SubdomainInventoryAuditService:
    def __init__(self, settings: Settings, files: FileStore, jobs: JobStore) -> None:
        self.settings = settings
        self.files = files
        self.jobs = jobs

    async def run_subdomain_inventory_analysis(self, job_id: str, candidates: list[str] | None = None) -> None:
        job = self.jobs.update(job_id, status="running")
        if not job.target_domain:
            self.jobs.update(job_id, status="failed", error="Subdomain inventory job is missing a root domain.")
            return
        candidate_list = candidates or []
        payload = {
            "root_domain": job.target_domain,
            "subdomains": candidate_list,
            "timeout_seconds": self.settings.domain_dns_timeout_seconds,
            "max_candidates": self.settings.subdomain_max_candidates,
            "wildcard_checks": self.settings.subdomain_wildcard_checks,
            "global_deadline_seconds": self.settings.subdomain_global_deadline_seconds,
        }
        runner_timeout_seconds = calculate_subdomain_inventory_runner_timeout_seconds(
            self.settings.subdomain_global_deadline_seconds,
            dns_timeout_seconds=self.settings.domain_dns_timeout_seconds,
        )

        try:
            async with httpx.AsyncClient(timeout=runner_timeout_seconds) as client:
                response = await client.post(f"{self.settings.tool_runner_url}/analyze/subdomains-basic", json=payload)
                response.raise_for_status()
        except httpx.HTTPError as exc:
            self.jobs.update(job_id, status="failed", error=f"Tool runner request failed: {exc}")
            return

        self.jobs.update(job_id, status="completed", result=response.json())
