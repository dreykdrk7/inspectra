from __future__ import annotations

from datetime import date
import hashlib
import json
from pathlib import Path
import socket

import pytest


FIXTURE_ROOT = Path(__file__).parent / "fixtures"
MANIFEST_PATH = FIXTURE_ROOT / "advisory-fixtures-manifest.json"
PROVIDER_DIRECTORIES = {"osv", "github", "cisa", "nvd"}
PROVIDERS = {"osv", "github_advisories", "cisa_kev", "nvd"}


def _manifest() -> dict:
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def test_every_public_advisory_fixture_has_current_bounded_attribution_metadata():
    manifest = _manifest()
    assert manifest["contract_version"] == "2026-09-09.1"
    assert manifest["network_policy"] == "no_external_network"
    entries = manifest["fixtures"]
    assert isinstance(entries, list) and entries

    actual_paths = {
        path.relative_to(FIXTURE_ROOT).as_posix()
        for directory in PROVIDER_DIRECTORIES
        for path in (FIXTURE_ROOT / directory).glob("*.json")
    }
    declared_paths = {entry["path"] for entry in entries}
    assert declared_paths == actual_paths

    for entry in entries:
        assert set(entry) == {
            "path", "provider", "origin", "schema_reference", "reviewed_on",
            "purpose", "transformation", "license_status", "sha256", "max_bytes",
        }
        assert entry["provider"] in PROVIDERS
        assert entry["origin"] == "synthetic_from_public_schema"
        assert entry["license_status"] == "synthetic_no_provider_content_copied"
        assert entry["schema_reference"].startswith("https://")
        assert 1 <= len(entry["purpose"]) <= 300
        assert 1 <= len(entry["transformation"]) <= 400
        assert date.fromisoformat(entry["reviewed_on"]) <= date(2026, 9, 9)
        fixture_path = FIXTURE_ROOT / entry["path"]
        raw = fixture_path.read_bytes()
        assert len(raw) <= entry["max_bytes"] <= 16 * 1024
        assert hashlib.sha256(raw).hexdigest() == entry["sha256"]
        json.loads(raw)
        lowered = raw.lower()
        for forbidden in (b"authorization:", b"bearer ", b"private_key", b"access_token", b"refresh_token"):
            assert forbidden not in lowered


def test_ordinary_backend_suite_blocks_external_resolution_and_connections():
    with pytest.raises(AssertionError, match="External name resolution"):
        socket.getaddrinfo("api.osv.dev", 443)
    external_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        with pytest.raises(AssertionError, match="External network access"):
            external_socket.connect(("192.0.2.1", 443))
    finally:
        external_socket.close()

    assert socket.getaddrinfo("localhost", 80)
