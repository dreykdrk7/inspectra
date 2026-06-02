from __future__ import annotations

import httpx

from app.config import Settings
from app.reporting import (
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

        self.jobs.update(job_id, status="completed", result=response.json())


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
            self.jobs.update(job_id, status="failed", error=f"Tool runner request failed: {exc}")
            return

        self.jobs.update(job_id, status="completed", result=response.json())


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
