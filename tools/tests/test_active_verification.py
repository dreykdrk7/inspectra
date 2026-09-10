import json

import pytest
from fastapi import HTTPException

from active_runner import verification
from active_runner.verification import execute_active_verification


def _payload(**overrides):
    payload = {
        "contract_version": "2026-09-08.1",
        "capability": "active_asset_verification",
        "method": "dns_txt",
        "target": "_inspectra-verification.example.test",
        "challenge_token": "iv1_" + "a" * 32,
        "confirmations_verified_by_backend": True,
    }
    payload.update(overrides)
    return payload


def test_verification_runner_is_double_gated_and_returns_only_closed_outcome():
    with pytest.raises(HTTPException) as disabled:
        execute_active_verification(_payload(), enabled=False)
    assert disabled.value.status_code == 503

    seen = []
    result = execute_active_verification(
        _payload(),
        enabled=True,
        executor=lambda request: seen.append((request.method, request.target, request.challenge_token)) or {"matched": True, "reason_code": "matched"},
    )
    assert seen == [("dns_txt", "_inspectra-verification.example.test", "iv1_" + "a" * 32)]
    assert result == {
        "contract_version": "2026-09-08.1",
        "capability": "active_asset_verification",
        "matched": True,
        "reason_code": "matched",
    }
    assert "example.test" not in json.dumps(result)
    assert "iv1_" not in json.dumps(result)


@pytest.mark.parametrize("overrides", [
    {"target": "example.test"},
    {"target": "_inspectra-verification.example.test", "redirect": "https://attacker.invalid"},
    {"method": "http_well_known", "target": "https://user:pass@example.test"},
    {"method": "http_well_known", "target": "https://example.test/private"},
    {"method": "http_well_known", "target": "https://example.test?token=secret"},
    {"challenge_token": "secret"},
])
def test_verification_runner_rejects_unbounded_or_ambiguous_contracts_without_echo(overrides):
    canary = json.dumps(overrides)
    with pytest.raises(HTTPException) as rejected:
        execute_active_verification(_payload(**overrides), enabled=True, executor=lambda _request: {"matched": True, "reason_code": "matched"})
    assert rejected.value.status_code == 422
    assert canary not in str(rejected.value.detail)


def test_verification_runner_rejects_inconsistent_or_sensitive_executor_results():
    for outcome in (
        {"matched": False, "reason_code": "matched"},
        {"matched": True, "reason_code": "token_not_observed"},
        {"matched": True, "reason_code": "matched", "target": "example.test"},
    ):
        with pytest.raises(HTTPException) as rejected:
            execute_active_verification(_payload(), enabled=True, executor=lambda _request, value=outcome: value)
        assert rejected.value.status_code == 422


def test_http_verification_pins_public_address_and_never_follows_redirect(monkeypatch):
    calls = []
    monkeypatch.setattr(verification, "_bounded_resolve", lambda _host, _port: ["93.184.216.34"])
    monkeypatch.setattr(verification, "_bounded_http_get", lambda origin, address: calls.append((origin, address)) or (302, b"https://attacker.invalid"))
    result = execute_active_verification(
        _payload(method="http_well_known", target="https://example.test"),
        enabled=True,
    )
    assert result["reason_code"] == "http_status_not_ok"
    assert calls == [("https://example.test", "93.184.216.34")]


def test_http_verification_rejects_private_resolution_and_bounded_body(monkeypatch):
    called = []
    monkeypatch.setattr(verification, "_bounded_resolve", lambda _host, _port: ["127.0.0.1"])
    monkeypatch.setattr(verification, "_bounded_http_get", lambda *_args: called.append(True) or (200, b"unused"))
    private = execute_active_verification(
        _payload(method="http_well_known", target="https://example.test"),
        enabled=True,
    )
    assert private["reason_code"] == "http_target_not_public"
    assert called == []

    monkeypatch.setattr(verification, "_bounded_resolve", lambda _host, _port: ["93.184.216.34"])
    monkeypatch.setattr(verification, "_bounded_http_get", lambda *_args: (200, b"x" * 513))
    oversized = execute_active_verification(
        _payload(method="http_well_known", target="https://example.test"),
        enabled=True,
    )
    assert oversized["reason_code"] == "http_body_limit"
