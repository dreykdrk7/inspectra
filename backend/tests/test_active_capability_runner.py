import json

import httpx
import pytest

from app.active_capability_runner import ActiveCapabilityRunnerError, ActiveToolsCapabilityRunner


@pytest.mark.anyio
async def test_backend_active_runner_client_uses_fixed_internal_route_and_minimal_contract():
    captured = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append((str(request.url), json.loads(request.content)))
        return httpx.Response(200, json={"capability": "active_dns_inventory", "target": "[REDACTED_DOMAIN]", "status": "best_effort_inventory"})

    runner = ActiveToolsCapabilityRunner("http://active-tools:8080", transport=httpx.MockTransport(handler))
    result = await runner.execute(capability="active_dns_inventory", target="fixture.example.test")

    assert result["capability"] == "active_dns_inventory"
    assert captured[0][0] == "http://active-tools:8080/active/dns-inventory"
    assert captured[0][1] == {
        "contract_version": "2026-09-09.1",
        "capability": "active_dns_inventory",
        "profile": "dns_inventory_authorized",
        "target": "fixture.example.test",
        "port": None,
        "confirmations_verified_by_backend": True,
    }


@pytest.mark.anyio
@pytest.mark.parametrize(
    "base_url",
    ["", "https://public.example.com", "http://user:password@active-tools:8080", "http://active-tools:8080/path"],
)
async def test_backend_active_runner_client_rejects_unapproved_destination(base_url):
    runner = ActiveToolsCapabilityRunner(base_url)
    with pytest.raises(ActiveCapabilityRunnerError, match="active_runner_unconfigured"):
        await runner.execute(capability="active_dns_inventory", target="fixture.example.test")


@pytest.mark.anyio
@pytest.mark.parametrize("response", [
    httpx.Response(302, headers={"location": "https://elsewhere.example"}),
    httpx.Response(200, content=b"x" * 262_145),
    httpx.Response(200, json={"capability": "active_dns_inventory", "value": "fixture.example.test"}),
    httpx.Response(200, json={"capability": "active_dns_inventory", "stdout": "hidden"}),
])
async def test_backend_active_runner_client_rejects_redirect_oversize_reflection_and_raw_output(response):
    runner = ActiveToolsCapabilityRunner(
        "http://active-tools:8080",
        transport=httpx.MockTransport(lambda _request: response),
    )
    with pytest.raises(ActiveCapabilityRunnerError):
        await runner.execute(capability="active_dns_inventory", target="fixture.example.test")
