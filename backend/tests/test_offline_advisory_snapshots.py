from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

import httpx
import pytest

from app.models import JobRecord
from app.offline_advisory_cli import main as offline_cli_main
from app.offline_advisory_snapshots import (
    OfflineAdvisorySnapshotError,
    activate_offline_advisory_snapshot,
    get_active_offline_advisory_snapshot,
    import_offline_advisory_bundle,
)
from app.project_vulnerability_intelligence import OsvVulnerabilityIntelligenceService
from app.public_advisory_egress import (
    PublicAdvisoryEgressClient,
    PublicAdvisoryResponseCache,
    PublicComponentIdentity,
)


NOW = datetime(2026, 9, 9, 12, tzinfo=timezone.utc)
FIXTURES = Path(__file__).parent / "fixtures"


def bundle(*, fixed: str = "18.3.2", expires_at: str = "2026-09-10T12:00:00Z") -> dict:
    return {
        "contract_version": "2026-09-09.1",
        "kind": "inspectra_public_advisory_offline_bundle",
        "created_at": "2026-09-08T10:00:00Z",
        "expires_at": expires_at,
        "entries": [{
            "provider": "osv",
            "identities": [{"ecosystem": "npm", "name": "react", "version": "18.3.1"}],
            "pages": 1,
            "response": {
                "results": [{"vulns": [{
                    "id": "CVE-2025-1234",
                    "aliases": ["GHSA-AAAA-BBBB-CCCC"],
                    "affected": [{
                        "package": {"ecosystem": "npm", "name": "react"},
                        "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": fixed}]}],
                    }],
                    "references": [{"url": "https://osv.dev/vulnerability/CVE-2025-1234"}],
                }]}],
            },
        }],
    }


def write_bundle(path, value: object) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    path.write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


def disabled_client(directory, *, transport=None):
    return PublicAdvisoryEgressClient(
        enabled=False,
        timeout_seconds=1,
        max_response_bytes=2 * 1024 * 1024,
        max_concurrency=1,
        max_retries=0,
        max_batch_components=25,
        cache=PublicAdvisoryResponseCache(
            directory,
            ttl_seconds=3600,
            max_response_bytes=2 * 1024 * 1024,
            clock=lambda: NOW,
        ),
        http_transport=transport,
        clock=lambda: NOW,
    )


def analysis() -> JobRecord:
    return JobRecord(
        id="a" * 32,
        owner_id="owner",
        project_id="b" * 32,
        audit_type="project_archive_basic",
        status="completed",
        created_at=NOW,
        updated_at=NOW,
        result={"component_inventory": [{
            "id": "component-react",
            "ecosystem": "npm",
            "name": "react",
            "manifest_path": "private/project/package.json",
            "manifest_path_status": "reported",
            "dependency_group": "dependencies",
            "source_type": "registry",
            "declared_version": "18.3.1",
            "exact_version": "18.3.1",
            "package_url": "pkg:npm/react@18.3.1",
            "dependency_scope": "direct",
            "relationship_status": "reported",
            "version_status": "exact_resolved",
            "correlation_eligible": True,
            "resolution": "lockfile",
            "lockfile_match_status": "matched",
            "manifest_type": "package_json",
            "lockfile_path": "private/project/package-lock.json",
            "lockfile_path_status": "reported",
            "lockfile_type": "npm_package_lock",
        }]},
    )


def test_imported_osv_snapshot_runs_full_correlation_with_egress_disabled(tmp_path):
    source = tmp_path / "authorized-bundle.json"
    advisories = tmp_path / "advisories"
    expected = write_bundle(source, bundle())
    summary = import_offline_advisory_bundle(source, advisories, expected_sha256=expected, now=NOW)
    requests = []
    client = disabled_client(
        advisories,
        transport=httpx.MockTransport(lambda request: requests.append(request) or httpx.Response(500)),
    )

    snapshot = OsvVulnerabilityIntelligenceService(client, cache_ttl_seconds=3600).correlate(analysis(), now=NOW)

    assert requests == []
    assert snapshot["state"] == "ready"
    assert snapshot["offline_snapshot_id"] == summary["snapshot_id"]
    assert snapshot["findings"][0]["advisory_id"] == "CVE-2025-1234"
    assert snapshot["findings"][0]["fixed_versions"] == ["18.3.2"]
    assert snapshot["summary"]["queried_components"] == 1
    assert snapshot["sources"][0]["state"] == "fresh"
    rendered = json.dumps(snapshot)
    assert "private/project" not in rendered
    assert expected not in rendered


def test_all_supported_offline_providers_resolve_only_their_fixed_lookup_keys(tmp_path):
    value = bundle()
    value["entries"].extend([
        {
            "provider": "github_advisories",
            "lookup_id": "GHSA-AAAA-BBBB-CCCC",
            "response": json.loads((FIXTURES / "github" / "global-advisory-valid.json").read_text()),
        },
        {
            "provider": "nvd",
            "lookup_id": "CVE-2025-1234",
            "response": json.loads((FIXTURES / "nvd" / "cve-valid.json").read_text()),
        },
        {
            "provider": "cisa_kev",
            "response": json.loads((FIXTURES / "cisa" / "kev-valid.json").read_text()),
        },
    ])
    source = tmp_path / "bundle.json"
    advisories = tmp_path / "advisories"
    digest = write_bundle(source, value)
    imported = import_offline_advisory_bundle(source, advisories, expected_sha256=digest, now=NOW)
    client = disabled_client(advisories)

    osv = client.query_osv_batch([PublicComponentIdentity(ecosystem="npm", name="react", version="18.3.1")])
    github = client.fetch_github_advisory("GHSA-AAAA-BBBB-CCCC")
    nvd = client.fetch_nvd_cve("CVE-2025-1234")
    cisa = client.fetch_cisa_kev_feed()

    assert imported["providers"] == ["cisa_kev", "github_advisories", "nvd", "osv"]
    assert {result.status for result in (osv, github, nvd, cisa)} == {"success"}
    assert {result.offline_snapshot_id for result in (osv, github, nvd, cisa)} == {imported["snapshot_id"]}
    assert client.fetch_github_advisory("GHSA-DDDD-EEEE-FFFF").status == "disabled"
    assert client.fetch_nvd_cve("CVE-2025-9999").status == "disabled"

    service = OsvVulnerabilityIntelligenceService(client, cache_ttl_seconds=3600)
    correlated = service.correlate(analysis(), now=NOW)
    corroborated = service.corroborate_github(correlated)
    nvd_enriched = service.enrich_nvd(corroborated)
    kev_enriched = service.correlate_cisa_kev(nvd_enriched)
    assert corroborated["summary"]["github_corroborated"] == 1
    assert nvd_enriched["summary"]["nvd_enriched"] == 1
    assert kev_enriched["summary"]["cisa_kev_known_exploited"] == 1
    assert kev_enriched["offline_snapshot_id"] == imported["snapshot_id"]


def test_import_rejects_checksum_contract_and_expiry_without_replacing_active(tmp_path):
    source = tmp_path / "bundle.json"
    advisories = tmp_path / "advisories"
    first_digest = write_bundle(source, bundle())
    first = import_offline_advisory_bundle(source, advisories, expected_sha256=first_digest, now=NOW)

    with pytest.raises(OfflineAdvisorySnapshotError, match="bundle_checksum_mismatch"):
        import_offline_advisory_bundle(source, advisories, expected_sha256="0" * 64, now=NOW)
    expired_digest = write_bundle(source, bundle(expires_at="2026-09-09T11:00:00Z"))
    with pytest.raises(OfflineAdvisorySnapshotError, match="bundle_freshness_invalid"):
        import_offline_advisory_bundle(source, advisories, expected_sha256=expired_digest, now=NOW)

    assert get_active_offline_advisory_snapshot(advisories)["snapshot_id"] == first["snapshot_id"]


def test_import_rejects_ambiguous_or_private_identity_and_mismatched_provider_data(tmp_path):
    source = tmp_path / "bundle.json"
    advisories = tmp_path / "advisories"
    private = bundle()
    private["entries"][0]["identities"][0]["name"] = "@private/package"
    private_digest = write_bundle(source, private)
    with pytest.raises(OfflineAdvisorySnapshotError, match="bundle_identity_invalid"):
        import_offline_advisory_bundle(source, advisories, expected_sha256=private_digest, now=NOW)

    mismatched = bundle()
    mismatched["entries"][0]["response"]["results"][0]["vulns"][0]["affected"][0]["package"]["name"] = "other"
    mismatch_digest = write_bundle(source, mismatched)
    with pytest.raises(OfflineAdvisorySnapshotError, match="bundle_response_invalid"):
        import_offline_advisory_bundle(source, advisories, expected_sha256=mismatch_digest, now=NOW)

    assert get_active_offline_advisory_snapshot(advisories) is None


def test_import_rejects_duplicate_json_keys_and_partially_invalid_provider_feeds(tmp_path):
    source = tmp_path / "bundle.json"
    advisories = tmp_path / "advisories"
    duplicate = (
        b'{"contract_version":"2026-09-09.1","contract_version":"2026-09-09.1",'
        b'"kind":"inspectra_public_advisory_offline_bundle","created_at":"2026-09-08T10:00:00Z",'
        b'"expires_at":"2026-09-10T12:00:00Z","entries":[]}'
    )
    source.write_bytes(duplicate)
    with pytest.raises(OfflineAdvisorySnapshotError, match="bundle_duplicate_json_key"):
        import_offline_advisory_bundle(
            source, advisories, expected_sha256=hashlib.sha256(duplicate).hexdigest(), now=NOW,
        )

    partially_invalid = bundle()
    partially_invalid["entries"][0]["response"]["results"][0]["vulns"].append({"id": "not-enough-evidence"})
    digest = write_bundle(source, partially_invalid)
    with pytest.raises(OfflineAdvisorySnapshotError, match="bundle_response_invalid"):
        import_offline_advisory_bundle(source, advisories, expected_sha256=digest, now=NOW)

    assert get_active_offline_advisory_snapshot(advisories) is None


def test_atomic_activation_restores_a_prior_snapshot_and_rejects_expired_target(tmp_path):
    source = tmp_path / "bundle.json"
    advisories = tmp_path / "advisories"
    first_digest = write_bundle(source, bundle(fixed="18.3.2"))
    first = import_offline_advisory_bundle(source, advisories, expected_sha256=first_digest, now=NOW)
    second_digest = write_bundle(source, bundle(fixed="18.3.3"))
    second = import_offline_advisory_bundle(source, advisories, expected_sha256=second_digest, now=NOW)

    assert first["snapshot_id"] != second["snapshot_id"]
    restored = activate_offline_advisory_snapshot(advisories, first["snapshot_id"], now=NOW)
    assert restored["snapshot_id"] == first["snapshot_id"]
    result = disabled_client(advisories).query_osv_batch([
        PublicComponentIdentity(ecosystem="npm", name="react", version="18.3.1")
    ])
    assert result.status == "success"
    assert result.offline_snapshot_id == first["snapshot_id"]

    with pytest.raises(OfflineAdvisorySnapshotError, match="snapshot_expired"):
        activate_offline_advisory_snapshot(
            advisories,
            second["snapshot_id"],
            now=datetime(2026, 10, 20, tzinfo=timezone.utc),
        )


def test_import_rejects_a_repeated_snapshot_without_replacing_active(tmp_path):
    source = tmp_path / "bundle.json"
    advisories = tmp_path / "advisories"
    digest = write_bundle(source, bundle())
    first = import_offline_advisory_bundle(source, advisories, expected_sha256=digest, now=NOW)

    with pytest.raises(OfflineAdvisorySnapshotError, match="snapshot_already_imported"):
        import_offline_advisory_bundle(source, advisories, expected_sha256=digest, now=NOW)

    assert get_active_offline_advisory_snapshot(advisories)["snapshot_id"] == first["snapshot_id"]


def test_operator_cli_requires_confirmation_and_outputs_only_safe_summary(tmp_path, capsys):
    source = tmp_path / "private-name-must-not-be-printed.json"
    advisories = tmp_path / "advisories"
    expected = write_bundle(source, bundle())

    denied = offline_cli_main([
        "import", "--bundle", str(source), "--expected-sha256", expected,
        "--advisories-dir", str(advisories),
    ], now=NOW)
    assert denied == 2
    assert "operator_confirmation_required" in capsys.readouterr().err

    accepted = offline_cli_main([
        "import", "--bundle", str(source), "--expected-sha256", expected,
        "--advisories-dir", str(advisories), "--operator-confirmed",
    ], now=NOW)
    output = capsys.readouterr().out
    assert accepted == 0
    assert '"providers": ["osv"]' in output
    assert "private-name-must-not-be-printed" not in output
    assert "react" not in output
