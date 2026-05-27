from __future__ import annotations

import httpx

from app.config import Settings
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
