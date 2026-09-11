import json
from pathlib import Path

import httpx
import pytest

from app.active_verification_runner import ActiveToolsVerificationRunner, ActiveVerificationRunnerError


def _response(*, matched=True, reason_code="matched"):
    return {
        "contract_version": "2026-09-08.1",
        "capability": "active_asset_verification",
        "matched": matched,
        "reason_code": reason_code,
    }


@pytest.mark.anyio
async def test_verification_client_uses_fixed_internal_route_and_minimal_contract():
    canary_target = "_inspectra-verification.private.fixture.test"
    canary_token = "iv1_" + "z" * 32
    seen = []

    def handler(request: httpx.Request):
        seen.append((str(request.url), json.loads(request.content)))
        return httpx.Response(200, json=_response())

    runner = ActiveToolsVerificationRunner("http://active-tools:8080", transport=httpx.MockTransport(handler))
    result = await runner.verify(method="dns_txt", target=canary_target, challenge_token=canary_token)
    assert result.matched is True
    assert seen[0][0] == "http://active-tools:8080/active/asset-verification"
    assert seen[0][1] == {
        "contract_version": "2026-09-08.1",
        "capability": "active_asset_verification",
        "method": "dns_txt",
        "target": canary_target,
        "challenge_token": canary_token,
        "confirmations_verified_by_backend": True,
    }
    assert canary_target not in repr(result)
    assert canary_token not in repr(result)


@pytest.mark.anyio
@pytest.mark.parametrize("response", [
    httpx.Response(307, headers={"location": "http://attacker.invalid/collect"}),
    httpx.Response(200, content=b"x" * 1025),
    httpx.Response(200, json={**_response(), "target": "private.fixture.test"}),
    httpx.Response(200, json=_response(matched=False, reason_code="matched")),
])
async def test_verification_client_rejects_redirect_oversize_extra_or_inconsistent_response(response):
    runner = ActiveToolsVerificationRunner(
        "http://active-tools:8080",
        transport=httpx.MockTransport(lambda _request: response),
    )
    with pytest.raises(ActiveVerificationRunnerError):
        await runner.verify(
            method="http_well_known",
            target="https://private.fixture.test",
            challenge_token="iv1_" + "x" * 32,
        )


def test_backend_verification_module_has_no_live_dns_http_or_socket_transport():
    source = (Path(__file__).resolve().parents[1] / "app" / "active_asset_verification.py").read_text(encoding="utf-8")
    for forbidden in ("import socket", "import ssl", "import http.client", "UdpDnsInventoryResolver", "urlopen("):
        assert forbidden not in source
    client_source = (Path(__file__).resolve().parents[1] / "app" / "active_verification_runner.py").read_text(encoding="utf-8")
    assert "follow_redirects=False" in client_source
    assert "trust_env=False" in client_source
