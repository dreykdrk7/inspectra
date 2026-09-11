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
from active_runner.capabilities import (
    ACTIVE_CAPABILITY_PATHS,
    CapabilityExecutor,
    CapabilityName,
    capability_execution_enabled,
    execute_active_capability,
)
from active_runner.verification import (
    ACTIVE_VERIFICATION_CAPABILITY,
    ACTIVE_VERIFICATION_PATH,
    VerificationExecutor,
    execute_active_verification,
)


def create_active_tools_app(
    *,
    nmap_basic_executor: ActiveToolsFakeExecutor | None = None,
    nmap_basic_runner: ActiveToolsNmapRunner | None = None,
    nmap_basic_execution_enabled: bool | None = None,
    capability_executors: Mapping[str, CapabilityExecutor] | None = None,
    capability_execution_flags: Mapping[str, bool] | None = None,
    verification_executor: VerificationExecutor | None = None,
    verification_execution_enabled: bool | None = None,
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
    verification_enabled = (
        _active_verification_execution_enabled_from_env()
        if verification_execution_enabled is None
        else verification_execution_enabled
    )

    def effective_capability_flags() -> dict[str, bool]:
        flags = {
            capability: (
                bool(capability_execution_flags.get(capability, False))
                if capability_execution_flags is not None
                else capability_execution_enabled(capability)
            )
            for capability in ACTIVE_CAPABILITY_PATHS
        }
        flags[ACTIVE_VERIFICATION_CAPABILITY] = verification_enabled
        return flags

    @app.get(ACTIVE_TOOLS_HEALTH_PATH)
    async def health(request: Request) -> dict[str, Any]:
        return handle_active_tools_health(
            await _request_payload(request),
            active_nmap_basic_execution_enabled=execution_enabled,
            capability_execution_flags=effective_capability_flags(),
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

    def capability_handler(capability: CapabilityName):
        async def handler(request: Request) -> dict[str, Any]:
            enabled = (
                bool(capability_execution_flags.get(capability, False))
                if capability_execution_flags is not None
                else capability_execution_enabled(capability)
            )
            executor = capability_executors.get(capability) if capability_executors is not None else None
            return execute_active_capability(await _request_payload(request), enabled=enabled, executor=executor)

        return handler

    for capability, path in ACTIVE_CAPABILITY_PATHS.items():
        app.add_api_route(path, capability_handler(capability), methods=["POST"])

    @app.post(ACTIVE_VERIFICATION_PATH)
    async def active_asset_verification(request: Request) -> dict[str, Any]:
        return execute_active_verification(
            await _request_payload(request),
            enabled=verification_enabled,
            executor=verification_executor,
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


def _active_verification_execution_enabled_from_env() -> bool:
    value = os.getenv("INSPECTRA_ACTIVE_TOOLS_ASSET_VERIFICATION_EXECUTION_ENABLED", "")
    return value.strip().lower() in {"1", "true", "yes", "on"}


app = create_active_tools_app()
