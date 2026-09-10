import json
from datetime import datetime, timedelta, timezone

import pytest

import app.sbom_import as sbom_import
from app.sbom_import import SbomImportError, normalize_sbom, sbom_project_result
from app.sbom_preflight import SbomPreflightError, SbomPreflightStore


def test_cyclonedx_retains_only_exact_minimal_public_identities():
    source = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {
            "tools": [{"name": "private-tool", "url": "https://internal.example/secret"}],
            "component": {"bom-ref": "root-private-ref"},
        },
        "components": [
            {"name": "ignored", "version": "9", "purl": "pkg:npm/react@18.3.1", "hashes": [{"content": "secret-hash"}]},
            {"purl": "pkg:pypi/requests@2.32.3"},
            {"purl": "pkg:npm/private@1.0.0?repository_url=https://internal.example"},
            {"purl": "pkg:golang/example.com/private@v1.0.0"},
            {"purl": "pkg:npm/no-version"},
        ],
        "dependencies": [{"ref": "root-private-ref", "dependsOn": ["react-ref"]}],
    }
    source["components"][0]["bom-ref"] = "react-ref"
    normalized = normalize_sbom(json.dumps(source).encode(), public_identities_confirmed=True)
    serialized = json.dumps(normalized)
    assert [(item["ecosystem"], item["name"], item["exact_version"]) for item in normalized["components"]] == [
        ("npm", "react", "18.3.1"),
        ("pypi", "requests", "2.32.3"),
    ]
    assert normalized["rejected_or_ambiguous_components"] == 3
    assert normalized["components"][0]["dependency_scope"] == "direct"
    assert normalized["components"][0]["relationship_status"] == "reported"
    assert normalized["components"][1]["dependency_scope"] == "transitive"
    assert normalized["components"][1]["relationship_status"] == "not_reported"
    assert "internal.example" not in serialized
    assert "secret-hash" not in serialized
    assert sbom_project_result(normalized)["component_inventory_summary"]["exact_registry_components"] == 2


@pytest.mark.parametrize("source_format", ["cyclonedx", "spdx"])
def test_sbom_retains_safe_maven_identity_and_relationships_without_metadata(source_format):
    purl = "pkg:maven/org.example/legacy@1.0.Final"
    if source_format == "cyclonedx":
        source = {
            "bomFormat": "CycloneDX", "specVersion": "1.6",
            "metadata": {"component": {"bom-ref": "private-root"}, "properties": [{"name": "url", "value": "https://private.example"}]},
            "components": [
                {"bom-ref": "maven", "purl": purl, "hashes": [{"content": "private-hash"}]},
                {"bom-ref": "qualified", "purl": "pkg:maven/org.example/qualified@1.0.0?type=jar"},
                {"bom-ref": "vendor", "purl": "pkg:maven/org.example/vendor@1.0-vendor"},
                {"bom-ref": "mixed", "purl": "pkg:maven/Org.Example/mixed@1.0.0"},
            ],
            "dependencies": [{"ref": "private-root", "dependsOn": ["maven"]}],
        }
    else:
        source = {
            "spdxVersion": "SPDX-2.3",
            "packages": [
                {"SPDXID": "SPDXRef-Root", "externalRefs": []},
                {"SPDXID": "SPDXRef-Maven", "downloadLocation": "https://private.example", "checksums": [{"checksumValue": "private-hash"}], "externalRefs": [{"referenceType": "purl", "referenceLocator": purl}]},
                {"SPDXID": "SPDXRef-Subpath", "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:maven/org.example/subpath@1.0.0#private"}]},
            ],
            "relationships": [
                {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-Root"},
                {"spdxElementId": "SPDXRef-Root", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "SPDXRef-Maven"},
            ],
        }
    normalized = normalize_sbom(json.dumps(source).encode(), public_identities_confirmed=False)
    assert len(normalized["components"]) == 1
    component = normalized["components"][0]
    assert (component["ecosystem"], component["name"], component["exact_version"]) == ("maven", "org.example:legacy", "1.0.Final")
    assert component["package_url"] == purl
    assert component["dependency_scope"] == "direct" and component["relationship_status"] == "reported"
    assert component["correlation_eligible"] is False
    rendered = json.dumps(normalized)
    for withheld in ("private.example", "private-hash", "qualified", "vendor", "subpath", "Org.Example"):
        assert withheld not in rendered


def test_spdx_purl_without_public_attestation_remains_local_only():
    source = {
        "spdxVersion": "SPDX-2.3",
        "packages": [
            {"SPDXID": "SPDXRef-Root", "externalRefs": []},
            {
                "SPDXID": "SPDXRef-Lodash",
                "name": "private label ignored",
                "downloadLocation": "git+ssh://private.example/repo",
                "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:npm/lodash@4.17.21"}],
            },
        ],
        "relationships": [
            {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-Root"},
            {"spdxElementId": "SPDXRef-Root", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "SPDXRef-Lodash"},
        ],
    }
    normalized = normalize_sbom(json.dumps(source).encode(), public_identities_confirmed=False)
    assert normalized["format"] == "spdx"
    assert normalized["components"][0]["correlation_eligible"] is False
    assert normalized["components"][0]["dependency_scope"] == "direct"
    assert normalized["components"][0]["relationship_status"] == "reported"
    assert "private.example" not in json.dumps(normalized)


def test_sbom_rejects_unknown_or_unsupported_contracts():
    with pytest.raises(SbomImportError, match="unsupported_cyclonedx_version"):
        normalize_sbom(b'{"bomFormat":"CycloneDX","specVersion":"1.3","components":[]}', public_identities_confirmed=False)
    with pytest.raises(SbomImportError, match="unsupported_format"):
        normalize_sbom(b'{"components":[]}', public_identities_confirmed=False)


def test_cyclonedx_relationship_graph_handles_cycles_duplicates_and_missing_root():
    source = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {"component": {"bom-ref": "root"}},
        "components": [
            {"bom-ref": "direct", "purl": "pkg:npm/direct-package@1.0.0"},
            {"bom-ref": "transitive", "purl": "pkg:npm/transitive-package@2.0.0"},
            {"bom-ref": "unknown", "purl": "pkg:npm/unknown-package@3.0.0"},
            {"bom-ref": "duplicate-unknown", "purl": "pkg:npm/direct-package@1.0.0"},
        ],
        "dependencies": [
            {"ref": "root", "dependsOn": ["direct"]},
            {"ref": "direct", "dependsOn": ["transitive"]},
            {"ref": "transitive", "dependsOn": ["direct"]},
        ],
    }
    normalized = normalize_sbom(json.dumps(source).encode(), public_identities_confirmed=True)
    by_name = {component["name"]: component for component in normalized["components"]}
    assert (by_name["direct-package"]["dependency_scope"], by_name["direct-package"]["relationship_status"]) == (
        "direct",
        "reported",
    )
    assert (by_name["transitive-package"]["dependency_scope"], by_name["transitive-package"]["relationship_status"]) == (
        "transitive",
        "reported",
    )
    assert by_name["unknown-package"]["relationship_status"] == "not_reported"
    result = sbom_project_result(normalized)
    assert result["component_inventory_summary"]["relationship_reported_components"] == 2
    assert result["component_inventory_summary"]["relationship_not_reported_components"] == 1


def test_truncated_sbom_graph_makes_every_scope_inconclusive(monkeypatch):
    monkeypatch.setattr(sbom_import, "MAX_SBOM_RELATIONSHIPS", 1)
    source = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {"component": {"bom-ref": "root"}},
        "components": [
            {"bom-ref": "first", "purl": "pkg:npm/first-package@1.0.0"},
            {"bom-ref": "second", "purl": "pkg:npm/second-package@1.0.0"},
        ],
        "dependencies": [
            {"ref": "root", "dependsOn": ["first"]},
            {"ref": "first", "dependsOn": ["second"]},
        ],
    }
    normalized = normalize_sbom(json.dumps(source).encode(), public_identities_confirmed=True)
    assert normalized["relationship_graph_truncated"] is True
    assert {component["relationship_status"] for component in normalized["components"]} == {"truncated"}
    summary = sbom_project_result(normalized)["component_inventory_summary"]
    assert summary["relationship_truncated_components"] == 2
    assert summary["relationship_reported_components"] == 0


def test_preflight_store_expires_is_owner_scoped_bounded_and_retains_no_payload():
    now = datetime(2026, 9, 8, tzinfo=timezone.utc)
    store = SbomPreflightStore(ttl_seconds=10, max_entries=2)
    first = store.create("owner-a", b"private-canary-one", now=now)
    second = store.create("owner-a", b"private-canary-two", now=now + timedelta(seconds=1))
    store.create("owner-a", b"private-canary-three", now=now + timedelta(seconds=2))

    assert store.active_count(now=now + timedelta(seconds=2)) == 2
    with pytest.raises(SbomPreflightError, match="invalid_or_expired"):
        store.consume("owner-a", first.token, b"private-canary-one", now=now + timedelta(seconds=2))
    with pytest.raises(SbomPreflightError, match="invalid_or_expired"):
        store.consume("owner-b", second.token, b"private-canary-two", now=now + timedelta(seconds=2))
    assert "private-canary" not in repr(store._records)
    assert store.active_count(now=now + timedelta(seconds=12)) == 0
