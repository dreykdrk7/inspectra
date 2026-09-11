"""Single-use entrypoint for an isolated passive source analysis.

The controller starts this module in a fresh process with a request-scoped
working directory and resource limits already applied. Only a bounded JSON
request is accepted on stdin; errors returned to the controller never include
tracebacks, environment values, or filesystem paths.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
import sys
from typing import Any, Awaitable, Callable

from fastapi import HTTPException, status
from pydantic import ValidationError

from runner import main


Handler = Callable[[Any], Awaitable[dict[str, Any]]]


HANDLERS: dict[str, tuple[type[main.StoredSourceRequest], Handler]] = {
    "pdf": (main.PdfAnalysisRequest, main.analyze_pdf),
    "image": (main.ImageAnalysisRequest, main.analyze_image),
    "manifest": (main.ManifestAnalysisRequest, main.analyze_manifest),
    "archive": (main.ArchiveAnalysisRequest, main.analyze_archive),
    "project-archive": (main.ArchiveAnalysisRequest, main.analyze_project_archive),
    "django-config": (main.ArchiveAnalysisRequest, main.analyze_django_config),
    "docker-config": (main.ArchiveAnalysisRequest, main.analyze_docker_config),
    "secrets-review": (main.ArchiveAnalysisRequest, main.analyze_secrets_review),
    "node-package-config": (main.ArchiveAnalysisRequest, main.analyze_node_package_config),
    "ci-cd-config": (main.ArchiveAnalysisRequest, main.analyze_ci_cd_config),
    "k8s-config": (main.ArchiveAnalysisRequest, main.analyze_k8s_config),
    "terraform-config": (main.ArchiveAnalysisRequest, main.analyze_terraform_config),
    "nginx-config": (main.ArchiveAnalysisRequest, main.analyze_nginx_config),
    "compose-config": (main.ArchiveAnalysisRequest, main.analyze_compose_config),
    "database-config": (main.ArchiveAnalysisRequest, main.analyze_database_config),
    "sql-database-config": (main.ArchiveAnalysisRequest, main.analyze_sql_database_config),
    "redis-config": (main.ArchiveAnalysisRequest, main.analyze_redis_config),
}


def emit(payload: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(payload, separators=(",", ":")))
    sys.stdout.flush()


async def execute(analyzer: str, payload: Any) -> dict[str, Any]:
    configured = HANDLERS.get(analyzer)
    if configured is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="The isolated analyzer is not supported.")
    request_model, handler = configured
    if not isinstance(payload, dict):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="The isolated analysis request is invalid.")
    request = request_model.model_validate(payload)
    return await handler(request)


def run() -> int:
    if len(sys.argv) != 2:
        emit({"status_code": 400, "detail": "The isolated analyzer is required."})
        return 2
    try:
        payload = json.loads(sys.stdin.buffer.read(main.ISOLATED_WORKER_MAX_RESULT_BYTES))
        main.DATA_DIR = Path.cwd().resolve()
        result = asyncio.run(execute(sys.argv[1], payload))
    except HTTPException as exc:
        detail = exc.detail if isinstance(exc.detail, str) and len(exc.detail) <= 500 else "The isolated analysis failed safely."
        emit({"status_code": exc.status_code, "detail": detail})
        return 1
    except (ValidationError, json.JSONDecodeError, UnicodeDecodeError):
        emit({"status_code": 400, "detail": "The isolated analysis request is invalid."})
        return 2
    except MemoryError:
        emit({"status_code": 422, "detail": "The isolated analysis stopped at its resource boundary."})
        return 1
    except BaseException:
        emit({"status_code": 500, "detail": "The isolated analysis failed safely."})
        return 1
    emit({"status_code": 200, "result": result})
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
