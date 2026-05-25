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
