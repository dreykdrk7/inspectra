import json

from app.component_inventory import COMPONENT_COVERAGE_MATRIX_VERSION, add_component_inventory, build_component_coverage_matrix
from app.models import ProjectComponentCoverage
from app.reporting import build_project_archive_sections


def fixture_result() -> dict:
    return {
        "summary": {"supported_manifests_found": 2, "lockfiles_parsed": 1},
        "supported_manifests": [
            {"path": "private/team/web/package.json", "manifest_type": "package_json", "status": "parsed"},
            {"path": "private/team/api/requirements.txt", "manifest_type": "requirements_txt", "status": "parsed"},
        ],
        "parsed_manifests": [
            {"path": "private/team/web/package.json", "manifest_type": "package_json", "parsed": {"dependencies": {}}},
            {"path": "private/team/api/requirements.txt", "manifest_type": "requirements_txt", "parsed": {"dependencies": {}}},
        ],
        "lockfiles": [
            {"path": "private/team/web/package-lock.json", "lockfile_type": "npm_package_lock", "status": "parsed"},
            {"path": "private/team/web/pnpm-lock.yaml", "lockfile_type": "unsupported_lockfile", "status": "skipped"},
        ],
        "parsed_lockfiles": [
            {
                "path": "private/team/web/package-lock.json",
                "lockfile_type": "npm_package_lock",
                "dependency_graph": {"nodes_truncated": False, "edges_truncated": True},
            }
        ],
    }


def test_component_coverage_matrix_is_fixed_aggregate_and_distinguishes_detected_from_parsed():
    matrix = build_component_coverage_matrix(
        fixture_result(),
        [{"lockfile_match_status": "matched"}],
    )
    by_id = {entry["id"]: entry for entry in matrix}

    npm = by_id["npm-package-lock"]
    assert npm == {
        "id": "npm-package-lock",
        "coverage_contract_version": COMPONENT_COVERAGE_MATRIX_VERSION,
        "ecosystem": "npm",
        "manager": "npm",
        "manifest": "package.json",
        "lockfile": "package-lock.json",
        "parser_version": "package-lock-json-v2-v3",
        "direct_coverage": "exact_same_root_when_matched",
        "transitive_coverage": "bounded_registry_graph",
        "manifest_status": "parsed",
        "lockfile_status": "parsed",
        "exclusion_reason": "graph_truncated",
    }
    assert by_id["npm-pnpm-lock"]["lockfile_status"] == "detected_not_parsed"
    assert by_id["npm-pnpm-lock"]["exclusion_reason"] == "defensive_limit_or_invalid_input"
    assert by_id["npm-yarn-lock"]["lockfile_status"] == "not_detected"
    assert by_id["pypi-requirements"]["manifest_status"] == "parsed"
    assert by_id["pypi-requirements"]["parser_version"] == "requirements-lines-v2-hash-summary"
    assert by_id["pypi-requirements"]["exclusion_reason"] == "no_lockfile_contract"
    assert "private/team" not in json.dumps(matrix)
    assert all(ProjectComponentCoverage.model_validate(entry).id == entry["id"] for entry in matrix)


def test_component_coverage_matrix_is_persisted_and_reported_without_paths_or_raw_lockfile_data():
    result = add_component_inventory("project_archive_basic", fixture_result())
    matrix = result["component_coverage_matrix"]
    assert len(matrix) == 12

    sections = build_project_archive_sections(result)
    coverage_section = next(section for section in sections if section.title == "Dependency Coverage Matrix")
    rendered = json.dumps(dict(coverage_section.items), sort_keys=True)

    assert "package-lock-json-v2-v3" in rendered
    assert "private/team" not in rendered
    assert "dependency_graph" not in rendered


def test_requirements_hash_summary_is_reported_without_digest_or_private_source_values():
    private_digest = "a" * 64
    result = fixture_result()
    result["parsed_manifests"][1]["parsed"]["integrity_summary"] = {
        "contract_version": "requirements-hash-summary-v1",
        "status": "missing",
        "exact_pins": 2,
        "exact_pins_with_hashes": 1,
        "exact_pins_missing_hashes": 1,
        "hash_entries_for_exact_pins": 2,
        "non_registry_entries_excluded": 1,
    }

    sections = build_project_archive_sections(result)
    parsed_section = next(section for section in sections if section.title == "Parsed Manifests")
    rendered = json.dumps(dict(parsed_section.items), sort_keys=True)

    assert "requirements-hash-summary-v1" in rendered
    assert "exact_pins_missing_hashes" in rendered
    assert private_digest not in rendered
    assert "private.example" not in rendered


def test_component_coverage_matrix_labels_parsed_pnpm_as_local_only_without_registry_claim():
    result = fixture_result()
    result["lockfiles"] = [
        {"path": "private/team/web/pnpm-lock.yaml", "lockfile_type": "pnpm_lock", "status": "parsed"},
    ]
    result["parsed_lockfiles"] = [
        {
            "path": "private/team/web/pnpm-lock.yaml",
            "lockfile_type": "pnpm_lock",
            "lockfile_version": "9.0",
            "packages": [{"name": "react", "version": "18.3.1", "source_type": "unverified_registry"}],
        }
    ]

    matrix = build_component_coverage_matrix(
        result,
        [{"lockfile_type": "pnpm_lock", "lockfile_match_status": "matched"}],
    )
    pnpm = next(entry for entry in matrix if entry["id"] == "npm-pnpm-lock")

    assert pnpm["parser_version"] == "pnpm-lock-yaml-v9"
    assert pnpm["direct_coverage"] == "exact_same_root_local_only"
    assert pnpm["transitive_coverage"] == "not_available"
    assert pnpm["lockfile_status"] == "parsed"
    assert pnpm["exclusion_reason"] == "none"
    assert "private/team" not in json.dumps(pnpm)


def test_component_coverage_matrix_labels_yarn_classic_as_local_only_without_selector_data():
    result = fixture_result()
    result["lockfiles"] = [
        {"path": "private/team/web/yarn.lock", "lockfile_type": "yarn_classic_lock", "status": "parsed"},
    ]
    result["parsed_lockfiles"] = [
        {
            "path": "private/team/web/yarn.lock",
            "lockfile_type": "yarn_classic_lock",
            "lockfile_version": 1,
            "packages": [{"name": "react", "selector_id": "a" * 24, "version": "18.3.1", "source_type": "unverified_registry"}],
        }
    ]

    matrix = build_component_coverage_matrix(
        result,
        [{"lockfile_type": "yarn_classic_lock", "lockfile_match_status": "matched"}],
    )
    yarn = next(entry for entry in matrix if entry["id"] == "npm-yarn-lock")

    assert yarn["parser_version"] == "yarn-classic-lock-v1"
    assert yarn["direct_coverage"] == "exact_same_root_local_only"
    assert yarn["transitive_coverage"] == "not_available"
    assert yarn["lockfile_status"] == "parsed"
    assert yarn["exclusion_reason"] == "none"
    assert "private/team" not in json.dumps(yarn)


def test_component_coverage_matrix_labels_poetry_v21_as_local_only_without_source_metadata():
    result = fixture_result()
    result["supported_manifests"] = [
        {"path": "private/team/api/pyproject.toml", "manifest_type": "pyproject_toml", "status": "parsed"},
    ]
    result["parsed_manifests"] = [
        {"path": "private/team/api/pyproject.toml", "manifest_type": "pyproject_toml", "parsed": {"dependencies": {}}},
    ]
    result["lockfiles"] = [
        {"path": "private/team/api/poetry.lock", "lockfile_type": "poetry_lock", "status": "parsed"},
    ]
    result["parsed_lockfiles"] = [
        {
            "path": "private/team/api/poetry.lock",
            "lockfile_type": "poetry_lock",
            "lockfile_version": "2.1",
            "packages": [{"name": "requests", "version": "2.32.3", "source_type": "unverified_registry"}],
        }
    ]

    matrix = build_component_coverage_matrix(
        result,
        [{"lockfile_type": "poetry_lock", "lockfile_match_status": "matched"}],
    )
    poetry = next(entry for entry in matrix if entry["id"] == "pypi-poetry-lock")

    assert poetry["parser_version"] == "poetry-lock-toml-v2.1"
    assert poetry["direct_coverage"] == "exact_same_root_local_only"
    assert poetry["transitive_coverage"] == "not_available"
    assert poetry["lockfile_status"] == "parsed"
    assert poetry["exclusion_reason"] == "none"
    assert "private/team" not in json.dumps(poetry)


def test_pipfile_v6_inventory_requires_same_root_and_keeps_groups_local_only():
    result = {
        "summary": {"supported_manifests_found": 2, "lockfiles_parsed": 2},
        "supported_manifests": [
            {"path": "services/api/Pipfile", "manifest_type": "pipfile", "status": "parsed"},
            {"path": "services/other/Pipfile", "manifest_type": "pipfile", "status": "parsed"},
        ],
        "parsed_manifests": [
            {
                "path": "services/api/Pipfile",
                "manifest_type": "pipfile",
                "parsed": {"dependencies": {
                    "packages": [{"name": "requests", "specifier": ">=2", "source_type": "registry"}],
                    "dev-packages": [{"name": "pytest", "specifier": "*", "source_type": "registry"}],
                }},
            },
            {
                "path": "services/other/Pipfile",
                "manifest_type": "pipfile",
                "parsed": {"dependencies": {
                    "packages": [{"name": "httpx", "specifier": ">=0.27", "source_type": "registry"}],
                }},
            },
        ],
        "lockfiles": [
            {"path": "services/api/Pipfile.lock", "lockfile_type": "pipfile_lock", "status": "parsed"},
            {"path": "elsewhere/Pipfile.lock", "lockfile_type": "pipfile_lock", "status": "parsed"},
        ],
        "parsed_lockfiles": [
            {
                "path": "services/api/Pipfile.lock",
                "lockfile_type": "pipfile_lock",
                "lockfile_version": 6,
                "packages": [
                    {"name": "requests", "version": "2.32.3", "dependency_group": "packages", "source_type": "unverified_registry"},
                    {"name": "pytest", "version": "8.3.2", "dependency_group": "dev-packages", "source_type": "unverified_registry"},
                ],
            },
            {
                "path": "elsewhere/Pipfile.lock",
                "lockfile_type": "pipfile_lock",
                "lockfile_version": 6,
                "packages": [{"name": "httpx", "version": "0.27.2", "dependency_group": "packages", "source_type": "unverified_registry"}],
            },
        ],
    }

    enriched = add_component_inventory("project_archive_basic", result)
    by_name = {component["name"]: component for component in enriched["component_inventory"]}
    coverage = next(item for item in enriched["component_coverage_matrix"] if item["id"] == "pypi-pipfile-lock")

    assert by_name["requests"]["exact_version"] == "2.32.3"
    assert by_name["requests"]["dependency_group"] == "packages"
    assert by_name["pytest"]["exact_version"] == "8.3.2"
    assert by_name["pytest"]["dependency_group"] == "dev-packages"
    assert by_name["requests"]["correlation_eligible"] is False
    assert by_name["requests"]["package_url"] is None
    assert by_name["httpx"]["exact_version"] is None
    assert by_name["httpx"]["lockfile_match_status"] == "not_matched"
    assert coverage["parser_version"] == "pipfile-lock-json-v6"
    assert coverage["direct_coverage"] == "exact_same_root_local_only"
    assert coverage["lockfile_status"] == "parsed"
    assert coverage["exclusion_reason"] == "none"
    assert "services/" not in json.dumps(coverage)


def test_go_inventory_requires_same_root_sum_and_keeps_replaced_modules_non_correlatable():
    result = {
        "summary": {"supported_manifests_found": 1, "lockfiles_parsed": 1},
        "supported_manifests": [{"path": "services/go/go.mod", "manifest_type": "go_mod", "status": "parsed"}],
        "parsed_manifests": [
            {
                "path": "services/go/go.mod",
                "manifest_type": "go_mod",
                "parsed": {
                    "dependencies": {
                        "require": [
                            {"name": "golang.org/x/text", "specifier": "v0.19.0", "dependency_source_type": "registry"},
                            {"name": "private.example.test/team/mod", "specifier": "", "dependency_source_type": "unknown"},
                        ],
                        "indirect": [
                            {"name": "github.com/public/module", "specifier": "v1.2.3", "dependency_source_type": "registry"}
                        ],
                    }
                },
            }
        ],
        "lockfiles": [{"path": "services/go/go.sum", "lockfile_type": "go_sum", "status": "parsed"}],
        "parsed_lockfiles": [
            {
                "path": "services/go/go.sum",
                "lockfile_type": "go_sum",
                "lockfile_version": "go-sum-v1",
                "packages": [
                    {"name": "golang.org/x/text", "version": "v0.19.0", "source_type": "unverified_registry"},
                    {"name": "github.com/public/module", "version": "v1.2.3", "source_type": "unverified_registry"},
                ],
            }
        ],
    }

    enriched = add_component_inventory("project_archive_basic", result)
    by_name = {component["name"]: component for component in enriched["component_inventory"]}
    coverage = next(item for item in enriched["component_coverage_matrix"] if item["id"] == "go-mod-sum")

    assert by_name["golang.org/x/text"]["exact_version"] == "v0.19.0"
    assert by_name["golang.org/x/text"]["lockfile_match_status"] == "matched"
    assert by_name["golang.org/x/text"]["package_url"] == "pkg:golang/golang.org/x/text@v0.19.0"
    assert by_name["github.com/public/module"]["dependency_scope"] == "transitive"
    assert by_name["private.example.test/team/mod"]["correlation_eligible"] is False
    assert coverage["lockfile_status"] == "parsed"
    assert coverage["direct_coverage"] == "exact_same_root_local_only"
    assert coverage["exclusion_reason"] == "relationship_evidence_not_provided"
    assert "h1:" not in json.dumps(enriched)


def test_cargo_inventory_uses_only_same_root_official_registry_lock_entries_and_adds_bounded_transitives():
    result = {
        "summary": {"supported_manifests_found": 1, "lockfiles_parsed": 1},
        "supported_manifests": [{"path": "services/rust/Cargo.toml", "manifest_type": "cargo_toml", "status": "parsed"}],
        "parsed_manifests": [{
            "path": "services/rust/Cargo.toml",
            "manifest_type": "cargo_toml",
            "parsed": {"dependencies": {"dependencies": [
                {"name": "serde", "specifier": "1", "dependency_source_type": "registry"},
                {"name": "private-alias", "specifier": "", "dependency_source_type": "alias"},
            ]}},
        }],
        "lockfiles": [{"path": "services/rust/Cargo.lock", "lockfile_type": "cargo_lock", "status": "parsed"}],
        "parsed_lockfiles": [{
            "path": "services/rust/Cargo.lock",
            "lockfile_type": "cargo_lock",
            "lockfile_version": 4,
            "packages": [
                {"name": "serde", "version": "1.0.210", "source_type": "registry"},
                {"name": "itoa", "version": "1.0.11", "source_type": "registry"},
                {"name": "private-crate", "version": "", "source_type": "unknown"},
            ],
        }],
    }

    enriched = add_component_inventory("project_archive_basic", result)
    by_name = {component["name"]: component for component in enriched["component_inventory"]}
    coverage = next(item for item in enriched["component_coverage_matrix"] if item["id"] == "cargo-lock")

    assert by_name["serde"]["exact_version"] == "1.0.210"
    assert by_name["serde"]["package_url"] == "pkg:cargo/serde@1.0.210"
    assert by_name["itoa"]["dependency_scope"] == "transitive"
    assert by_name["itoa"]["relationship_status"] == "not_reported"
    assert by_name["private-alias"]["correlation_eligible"] is False
    assert "private-crate" not in by_name
    assert coverage["lockfile_status"] == "parsed"
    assert coverage["direct_coverage"] == "exact_same_root_when_matched"
    assert coverage["transitive_coverage"] == "not_available"
    assert coverage["exclusion_reason"] == "relationship_evidence_not_provided"
    serialized = json.dumps(enriched)
    for withheld in ("crates.io-index", "index.crates.io", "checksum", "token@", "private.example.test"):
        assert withheld not in serialized


def test_composer_inventory_resolves_same_root_locally_and_never_infers_public_origin():
    result = {
        "summary": {"supported_manifests_found": 1, "lockfiles_parsed": 1},
        "supported_manifests": [{"path": "services/php/composer.json", "manifest_type": "composer_json", "status": "parsed"}],
        "parsed_manifests": [{
            "path": "services/php/composer.json",
            "manifest_type": "composer_json",
            "parsed": {"project": {"custom_repositories_declared": False}, "dependencies": {"require": [
                {"name": "symfony/http-foundation", "specifier": "^7.1", "dependency_source_type": "registry"},
            ]}},
        }],
        "lockfiles": [{"path": "services/php/composer.lock", "lockfile_type": "composer_lock", "status": "parsed"}],
        "parsed_lockfiles": [{
            "path": "services/php/composer.lock",
            "lockfile_type": "composer_lock",
            "lockfile_version": "composer-lock-json-v1",
            "packages": [
                {"name": "symfony/http-foundation", "version": "7.1.3", "dependency_group": "require", "source_type": "unverified_registry"},
                {"name": "psr/log", "version": "3.0.2", "dependency_group": "require", "source_type": "unverified_registry"},
            ],
        }],
    }

    enriched = add_component_inventory("project_archive_basic", result)
    by_name = {component["name"]: component for component in enriched["component_inventory"]}
    coverage = next(item for item in enriched["component_coverage_matrix"] if item["id"] == "composer-lock")

    assert by_name["symfony/http-foundation"]["exact_version"] == "7.1.3"
    assert by_name["symfony/http-foundation"]["package_url"] == "pkg:composer/symfony/http-foundation@7.1.3"
    assert by_name["psr/log"]["dependency_scope"] == "transitive"
    assert by_name["psr/log"]["relationship_status"] == "not_reported"
    assert coverage["direct_coverage"] == "exact_same_root_local_only"
    assert coverage["transitive_coverage"] == "not_available"
    assert coverage["exclusion_reason"] == "relationship_evidence_not_provided"
    assert enriched["component_inventory_summary"]["unverified_lockfile_components"] == 1
    assert "private.example.test" not in json.dumps(enriched)


def test_composer_custom_repository_manifest_never_resolves_or_becomes_correlatable():
    result = {
        "summary": {"supported_manifests_found": 1, "lockfiles_parsed": 1},
        "parsed_manifests": [{
            "path": "composer.json", "manifest_type": "composer_json",
            "parsed": {"project": {"custom_repositories_declared": True}, "dependencies": {"require": [
                {"name": "company/private", "specifier": "", "dependency_source_type": "unknown"},
            ]}},
        }],
        "parsed_lockfiles": [{
            "path": "composer.lock", "lockfile_type": "composer_lock", "lockfile_version": "composer-lock-json-v1",
            "packages": [{"name": "company/private", "version": "1.0.0", "dependency_group": "require", "source_type": "unverified_registry"}],
        }],
    }

    enriched = add_component_inventory("project_archive_basic", result)
    component = next(item for item in enriched["component_inventory"] if item["name"] == "company/private")
    assert component["source_type"] == "unknown"
    assert component["exact_version"] is None
    assert component["package_url"] is None
    assert component["correlation_eligible"] is False


def test_gradle_lock_inventory_requires_same_root_build_marker_and_keeps_relationships_unknown():
    result = {
        "summary": {"supported_manifests_found": 1, "lockfiles_parsed": 1},
        "supported_manifests": [{"path": "services/jvm/build.gradle.kts", "manifest_type": "gradle_build", "status": "parsed"}],
        "parsed_manifests": [{
            "path": "services/jvm/build.gradle.kts", "manifest_type": "gradle_build",
            "parsed": {"project": {"build_dsl_not_evaluated": True}, "dependencies": {}},
        }],
        "lockfiles": [{"path": "services/jvm/gradle.lockfile", "lockfile_type": "gradle_lock", "status": "parsed"}],
        "parsed_lockfiles": [{
            "path": "services/jvm/gradle.lockfile", "lockfile_type": "gradle_lock", "lockfile_version": "gradle-lockfile-v1",
            "packages": [{"name": "org.apache.commons:commons-lang3", "version": "3.14.0", "source_type": "unverified_registry"}],
        }],
    }

    enriched = add_component_inventory("project_archive_basic", result)
    component = enriched["component_inventory"][0]
    coverage = next(item for item in enriched["component_coverage_matrix"] if item["id"] == "gradle-lock")
    assert component["ecosystem"] == "maven"
    assert component["package_url"] == "pkg:maven/org.apache.commons/commons-lang3@3.14.0"
    assert component["dependency_scope"] == "transitive"
    assert component["relationship_status"] == "not_reported"
    assert component["manifest_path"] == "services/jvm/build.gradle.kts"
    assert coverage["direct_coverage"] == "not_available"
    assert coverage["transitive_coverage"] == "not_available"
    assert coverage["exclusion_reason"] == "relationship_evidence_not_provided"


def test_nuget_inventory_preserves_scope_but_requires_unambiguous_same_root_project_and_public_attestation_later():
    result = {
        "summary": {"supported_manifests_found": 1, "lockfiles_parsed": 1},
        "supported_manifests": [{"path": "services/dotnet/App.csproj", "manifest_type": "dotnet_project", "status": "parsed"}],
        "parsed_manifests": [{
            "path": "services/dotnet/App.csproj", "manifest_type": "dotnet_project",
            "parsed": {"project": {"msbuild_not_evaluated": True}, "dependencies": {}},
        }],
        "lockfiles": [{"path": "services/dotnet/packages.lock.json", "lockfile_type": "nuget_packages_lock", "status": "parsed"}],
        "parsed_lockfiles": [{
            "path": "services/dotnet/packages.lock.json", "lockfile_type": "nuget_packages_lock",
            "lockfile_version": "nuget-packages-lock-json-v1", "target_count": 2, "ambiguous_packages": 1,
            "packages": [
                {"name": "newtonsoft.json", "version": "013.0.03.0+private-build", "source_type": "unverified_registry", "dependency_scope": "direct"},
                {"name": "system.text.encodings.web", "version": "8.0.0", "source_type": "unverified_registry", "dependency_scope": "transitive"},
                {"name": "private.project", "version": "1.0.0", "source_type": "local", "dependency_scope": "unknown"},
                {"name": "ambiguous.package", "source_type": "unknown", "dependency_scope": "unknown"},
            ],
        }],
    }

    enriched = add_component_inventory("project_archive_basic", result)
    by_name = {component["name"]: component for component in enriched["component_inventory"]}
    coverage = next(item for item in enriched["component_coverage_matrix"] if item["id"] == "nuget-packages-lock")
    assert by_name["newtonsoft.json"]["package_url"] == "pkg:nuget/newtonsoft.json@13.0.3"
    assert by_name["newtonsoft.json"]["exact_version"] == "13.0.3"
    assert by_name["newtonsoft.json"]["dependency_scope"] == "direct"
    assert by_name["newtonsoft.json"]["relationship_status"] == "reported"
    assert by_name["system.text.encodings.web"]["dependency_scope"] == "transitive"
    assert by_name["private.project"]["correlation_eligible"] is False
    assert by_name["ambiguous.package"]["exact_version"] is None
    assert coverage["exclusion_reason"] == "none"
    assert enriched["component_inventory_summary"]["unverified_lockfile_components"] == 2
    assert enriched["component_inventory_summary"]["relationship_not_reported_components"] == 2
    assert "private-build" not in json.dumps(enriched["component_inventory"])


def test_nuget_inventory_rejects_ambiguous_multiple_project_markers_in_one_root():
    result = {
        "summary": {"supported_manifests_found": 2, "lockfiles_parsed": 1},
        "parsed_manifests": [
            {"path": "src/A.csproj", "manifest_type": "dotnet_project", "parsed": {"dependencies": {}}},
            {"path": "src/B.csproj", "manifest_type": "dotnet_project", "parsed": {"dependencies": {}}},
        ],
        "lockfiles": [{"path": "src/packages.lock.json", "lockfile_type": "nuget_packages_lock", "status": "parsed"}],
        "parsed_lockfiles": [{"path": "src/packages.lock.json", "lockfile_type": "nuget_packages_lock", "packages": [
            {"name": "public.package", "version": "1.2.3", "source_type": "unverified_registry", "dependency_scope": "direct"},
        ]}],
    }
    enriched = add_component_inventory("project_archive_basic", result)
    coverage = next(item for item in enriched["component_coverage_matrix"] if item["id"] == "nuget-packages-lock")
    assert enriched["component_inventory"] == []
    assert coverage["exclusion_reason"] == "ambiguous_root_pair"
