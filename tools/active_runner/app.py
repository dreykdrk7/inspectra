from __future__ import annotations

from collections.abc import Mapping
import os
from typing import Any

from fastapi import FastAPI, Request

from active_runner.service import (
    ACTIVE_TOOLS_HEALTH_PATH,
    ACTIVE_TOOLS_NMAP_BASIC_PATH,
    ActiveToolsFakeExecutor,
    ActiveToolsNmapRunner,
    handle_active_nmap_basic_real,
    handle_active_nmap_basic_no_scan,
    handle_active_tools_health,
    handle_active_tools_request,
)


def create_active_tools_app(
    *,
    nmap_basic_executor: ActiveToolsFakeExecutor | None = None,
    nmap_basic_runner: ActiveToolsNmapRunner | None = None,
    nmap_basic_execution_enabled: bool | None = None,
) -> FastAPI:
    app = FastAPI(
        title="Inspectra Active Tools",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    execution_enabled = (
        _active_nmap_basic_execution_enabled_from_env()
        if nmap_basic_execution_enabled is None
        else nmap_basic_execution_enabled
    )

    @app.get(ACTIVE_TOOLS_HEALTH_PATH)
    async def health(request: Request) -> dict[str, Any]:
        return handle_active_tools_health(
            await _request_payload(request),
            active_nmap_basic_execution_enabled=execution_enabled,
        )

    @app.post(ACTIVE_TOOLS_NMAP_BASIC_PATH)
    async def active_nmap_basic(request: Request) -> dict[str, Any]:
        payload = await _request_payload(request)
        if nmap_basic_executor is not None:
            return handle_active_nmap_basic_no_scan(payload, executor=nmap_basic_executor)
        if execution_enabled:
            return handle_active_nmap_basic_real(payload, runner=nmap_basic_runner)
        return handle_active_nmap_basic_no_scan(
            payload,
        )

    @app.api_route(ACTIVE_TOOLS_HEALTH_PATH, methods=["POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
    @app.api_route(ACTIVE_TOOLS_NMAP_BASIC_PATH, methods=["GET", "PUT", "PATCH", "DELETE", "OPTIONS"])
    async def known_path_wrong_method(request: Request) -> dict[str, Any]:
        return handle_active_tools_request(
            request.method,
            request.url.path,
            await _request_payload(request),
        )

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
    async def unknown_path(path: str, request: Request) -> dict[str, Any]:
        return handle_active_tools_request(
            request.method,
            f"/{path}",
            await _request_payload(request),
        )

    return app


async def _request_payload(request: Request) -> Any:
    payload: Any = None
    if _request_has_body(request):
        try:
            payload = await request.json()
        except ValueError:
            payload = "invalid_json_body"

    if not request.query_params:
        return payload

    if isinstance(payload, Mapping):
        return dict(payload) | {"query_params_present": True}
    if payload is None:
        return dict(request.query_params)
    return {"body_present": True, "query_params_present": True}


def _request_has_body(request: Request) -> bool:
    content_length = request.headers.get("content-length")
    if content_length is None:
        return False
    try:
        return int(content_length) > 0
    except ValueError:
        return True


def _active_nmap_basic_execution_enabled_from_env() -> bool:
    value = os.getenv("INSPECTRA_ACTIVE_TOOLS_NMAP_BASIC_EXECUTION_ENABLED", "")
    return value.strip().lower() in {"1", "true", "yes", "on"}


app = create_active_tools_app()
