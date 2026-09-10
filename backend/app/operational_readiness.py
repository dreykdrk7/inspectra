from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Awaitable, Callable
from uuid import uuid4

import httpx

from app.config import Settings
from app.observability import log_audit_event
from app.storage import ExecutionWorkspaceStore, JobStore, ProjectSnapshotAdmissionStore


READINESS_RESPONSE_MAX_BYTES = 4_096
RUNNER_HEALTH_SERVICE = "inspectra-audit-tools"
ReadinessStorageProbe = Callable[[], bool]
ReadinessRunnerProbe = Callable[[], Awaitable[bool]]
ReadinessPendingProbe = Callable[[], bool]


class OperationalReadinessService:
    """Produce a bounded readiness signal with no topology or project data."""

    def __init__(
        self,
        settings: Settings,
        jobs: JobStore,
        snapshot_admissions: ProjectSnapshotAdmissionStore,
        execution_workspaces: ExecutionWorkspaceStore,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        storage_probe: ReadinessStorageProbe | None = None,
        runner_probe: ReadinessRunnerProbe | None = None,
        deletion_pending_probe: ReadinessPendingProbe | None = None,
    ) -> None:
        self.settings = settings
        self.jobs = jobs
        self.snapshot_admissions = snapshot_admissions
        self.execution_workspaces = execution_workspaces
        self.transport = transport
        self.storage_probe = storage_probe or (lambda: probe_private_storage(self.settings.runtime_dir))
        self.runner_probe = runner_probe or self._probe_analysis_runners
        self.deletion_pending_probe = deletion_pending_probe or (lambda: False)

    async def check(self) -> dict[str, object]:
        storage_state = "unavailable"
        runner_state = "unavailable"
        admission_state = "unavailable"
        recovery_state = "unavailable"

        storage_result, runner_result = await asyncio.gather(
            asyncio.wait_for(asyncio.to_thread(self.storage_probe), timeout=self.settings.readiness_timeout_seconds),
            asyncio.wait_for(self.runner_probe(), timeout=self.settings.readiness_timeout_seconds),
            return_exceptions=True,
        )
        # Detailed exception text may contain hosts or paths and is never
        # returned or logged by this aggregate endpoint.
        storage_state = "ready" if storage_result is True else "unavailable"
        runner_state = "ready" if runner_result is True else "unavailable"

        try:
            admission_state = "ready" if self.jobs.has_global_admission_capacity() else "saturated"
        except Exception:
            admission_state = "unavailable"

        try:
            active_job_ids = self.jobs.active_project_job_ids()
            recovery_ok = (
                not self.snapshot_admissions.has_pending()
                and not self.deletion_pending_probe()
                and not self.execution_workspaces.has_orphans(active_job_ids=active_job_ids)
            )
            recovery_state = "ready" if recovery_ok else "unavailable"
        except Exception:
            recovery_state = "unavailable"

        checks = {
            "storage": storage_state,
            "analysis_runners": runner_state,
            "admission": admission_state,
            "recovery_cleanup": recovery_state,
        }
        ready = all(value == "ready" for value in checks.values())
        result: dict[str, object] = {
            "status": "ready" if ready else "not_ready",
            "service": "inspectra-backend",
            "checks": checks,
        }
        log_audit_event("service.readiness.checked", readiness_status=result["status"], **checks)
        return result

    async def _probe_analysis_runners(self) -> bool:
        async with httpx.AsyncClient(
            timeout=self.settings.readiness_timeout_seconds,
            follow_redirects=False,
            trust_env=False,
            transport=self.transport,
        ) as client:
            results = await asyncio.gather(
                self._probe_runner(client, f"{self.settings.tool_runner_url}/health"),
                self._probe_runner(client, f"{self.settings.network_tool_runner_url}/health"),
                return_exceptions=True,
            )
        return all(result is True for result in results)

    @staticmethod
    async def _probe_runner(client: httpx.AsyncClient, url: str) -> bool:
        async with client.stream(
            "GET",
            url,
            headers={"accept": "application/json", "accept-encoding": "identity"},
        ) as response:
            if response.status_code != 200 or response.is_redirect:
                return False
            body = bytearray()
            if response.is_stream_consumed:
                if len(response.content) > READINESS_RESPONSE_MAX_BYTES:
                    return False
                body.extend(response.content)
            else:
                async for chunk in response.aiter_raw():
                    if len(body) + len(chunk) > READINESS_RESPONSE_MAX_BYTES:
                        return False
                    body.extend(chunk)
        try:
            payload = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return False
        return payload == {"status": "ok", "service": RUNNER_HEALTH_SERVICE}


def probe_private_storage(runtime_dir: Path) -> bool:
    """Verify a small durable write and cleanup without exposing its path."""

    filename = f".readiness-{uuid4().hex}"
    probe_path = runtime_dir / filename
    descriptor: int | None = None
    try:
        descriptor = os.open(probe_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
        os.write(descriptor, b"inspectra-readiness-v1")
        os.fsync(descriptor)
        return True
    finally:
        if descriptor is not None:
            os.close(descriptor)
        probe_path.unlink(missing_ok=True)
