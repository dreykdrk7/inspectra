from datetime import datetime, timedelta, timezone

import pytest

from app.active_asset_verification import (
    ActiveAssetVerificationStartRequest,
    ActiveAssetVerificationStore,
)
from app.active_assets import ActiveAssetCreateRequest, ActiveAssetStore
from app.config import load_settings


def test_verification_challenges_are_rate_limited_per_asset(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_DATA_DIR", str(tmp_path))
    settings = load_settings()
    settings.ensure_directories()
    now = datetime.now(timezone.utc)
    asset = ActiveAssetStore(settings, now_func=lambda: now).create(
        ActiveAssetCreateRequest.model_validate({
            "asset_type": "domain",
            "value": "example.test",
            "responsible_user_ids": [],
            "capabilities": ["active_dns_inventory"],
            "allowed_ports": [],
            "allowed_protocols": ["dns"],
            "authorization_method": "manual_attestation",
            "authorization_reference": "ticket-42",
            "authorized_at": (now - timedelta(minutes=1)).isoformat(),
            "expires_at": (now + timedelta(days=30)).isoformat(),
            "notes": [],
        }),
        organization_id="a" * 32,
        actor_id="a" * 32,
    )
    store = ActiveAssetVerificationStore(settings, now_func=lambda: now)
    request = ActiveAssetVerificationStartRequest(method="manual_attestation", control_check_confirmed=True)
    for _ in range(5):
        store.start(asset, request, organization_id=asset.organization_id, actor_id=asset.owner_id)
    with pytest.raises(Exception, match="verification_rate_limited"):
        store.start(asset, request, organization_id=asset.organization_id, actor_id=asset.owner_id)
