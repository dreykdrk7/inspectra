import pytest
from httpx import ASGITransport, AsyncClient

from active_runner.app import create_active_tools_app
from active_runner.capabilities import ACTIVE_CAPABILITY_PATHS, ACTIVE_CAPABILITY_PROFILES


def _request(capability: str, **overrides):
    payload = {
        "contract_version": "2026-09-09.1",
        "capability": capability,
        "profile": ACTIVE_CAPABILITY_PROFILES[capability],
        "target": "fixture.example.test" if capability != "active_http_basic_header_review" else "https://fixture.example.test",
        "port": 443 if capability == "active_tls_basic" else None,
        "confirmations_verified_by_backend": True,
    }
    payload.update(overrides)
    return payload


@pytest.mark.anyio
async def test_isolated_active_runner_uses_only_fixed_routes_and_injected_executors():
    calls = []

    def executor(request):
        calls.append((request.capability, request.profile, request.port))
        return {"capability": request.capability, "status": "completed", "target": "[REDACTED_TARGET]"}

    flags = {capability: True for capability in ACTIVE_CAPABILITY_PATHS}
    executors = {capability: executor for capability in ACTIVE_CAPABILITY_PATHS}
    app = create_active_tools_app(capability_execution_flags=flags, capability_executors=executors)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://active-tools") as client:
        for capability, path in ACTIVE_CAPABILITY_PATHS.items():
            response = await client.post(path, json=_request(capability))
            assert response.status_code == 200
            assert response.json() == {"capability": capability, "status": "completed", "target": "[REDACTED_TARGET]"}
    assert [item[0] for item in calls] == list(ACTIVE_CAPABILITY_PATHS)


@pytest.mark.anyio
async def test_isolated_active_runner_fails_closed_without_flag_or_with_scope_drift():
    executor = lambda request: {"capability": request.capability, "status": "completed", "target": "[REDACTED_TARGET]"}
    flags = {capability: False for capability in ACTIVE_CAPABILITY_PATHS}
    flags["active_tls_basic"] = True
    app = create_active_tools_app(
        capability_execution_flags=flags,
        capability_executors={capability: executor for capability in ACTIVE_CAPABILITY_PATHS},
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://active-tools") as client:
        disabled = await client.post(ACTIVE_CAPABILITY_PATHS["active_dns_inventory"], json=_request("active_dns_inventory"))
        drift = await client.post(
            ACTIVE_CAPABILITY_PATHS["active_tls_basic"],
            json=_request("active_tls_basic", profile="arbitrary", command="do-not-run"),
        )
    assert disabled.status_code == 503
    assert drift.status_code == 422
    assert "do-not-run" not in drift.text


@pytest.mark.anyio
async def test_isolated_active_runner_rejects_target_reflection_from_executor():
    target = "sensitive.fixture.test"
    app = create_active_tools_app(
        capability_execution_flags={"active_dns_inventory": True},
        capability_executors={"active_dns_inventory": lambda request: {"capability": request.capability, "value": request.target}},
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://active-tools") as client:
        response = await client.post(
            ACTIVE_CAPABILITY_PATHS["active_dns_inventory"],
            json=_request("active_dns_inventory", target=target),
        )
    assert response.status_code == 502
    assert target not in response.text


@pytest.mark.anyio
async def test_isolated_active_runner_health_reports_every_effective_gate_without_executing():
    flags = {capability: capability in {"active_dns_inventory", "active_tls_basic"} for capability in ACTIVE_CAPABILITY_PATHS}
    app = create_active_tools_app(
        nmap_basic_execution_enabled=True,
        capability_execution_flags=flags,
        capability_executors={capability: lambda request: (_ for _ in ()).throw(AssertionError(request.capability)) for capability in ACTIVE_CAPABILITY_PATHS},
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://active-tools") as client:
        response = await client.get("/health")

    assert response.status_code == 200
    payload = response.json()
    assert set(payload["capabilities"]) == {*ACTIVE_CAPABILITY_PATHS, "active_nmap_basic", "active_asset_verification"}
    assert payload["capabilities"]["active_nmap_basic"]["execution_enabled"] is True
    assert payload["capabilities"]["active_dns_inventory"]["execution_enabled"] is True
    assert payload["capabilities"]["active_dns_osint"]["execution_enabled"] is False
    assert payload["capabilities"]["active_asset_verification"]["execution_enabled"] is False
    assert all(item["target_input_allowed"] is False for item in payload["capabilities"].values())
    assert payload["network_requests_sent"] == 0
    assert payload["nmap_executed"] is False
    assert len(response.content) <= 4_096


@pytest.mark.anyio
async def test_isolated_active_runner_health_rejects_target_input_without_echo_or_execution():
    executed = []
    app = create_active_tools_app(
        capability_execution_flags={capability: True for capability in ACTIVE_CAPABILITY_PATHS},
        capability_executors={capability: lambda request: executed.append(request) for capability in ACTIVE_CAPABILITY_PATHS},
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://active-tools") as client:
        response = await client.get("/health", params={"target": "private.fixture.test"})

    assert response.status_code == 200
    assert response.json()["status"] == "blocked_no_live_service"
    assert response.json()["errors"] == ["health_payload_not_accepted"]
    assert all(not item["execution_enabled"] for item in response.json()["capabilities"].values())
    assert "private.fixture.test" not in response.text
    assert executed == []
