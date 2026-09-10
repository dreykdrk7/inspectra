import json

from app.license_review import add_project_license_review


def test_declared_license_review_is_exact_deduplicated_and_non_legal():
    result = {
        "summary": {"manifests_parsed": 4},
        "parsed_manifests": [
            {"path": "package.json", "parsed": {"project": {"license": "MIT", "license_status": "declared"}}},
            {"path": "package.json", "parsed": {"project": {"license": "MIT", "license_status": "declared"}}},
            {"path": "services/api/pyproject.toml", "parsed": {"project": {"license_status": "unrecognized_withheld"}}},
            {"path": "requirements.txt", "parsed": {"project": {}}},
        ],
        "findings": [],
    }

    reviewed = add_project_license_review(result, ["MIT"])

    assert reviewed["license_review"]["policy_mode"] == "exact_deny_identifiers"
    assert reviewed["license_review"]["summary"] == {
        "manifests_reviewed": 3,
        "declared": 0,
        "unknown": 2,
        "not_permitted": 1,
    }
    declarations = reviewed["license_review"]["declarations"]
    assert declarations[0] == {"manifest_path": "package.json", "status": "not_permitted", "expression": "MIT"}
    assert {finding["id"] for finding in reviewed["findings"]} == {
        "project_license_not_permitted",
        "project_license_unknown",
    }
    assert all("legal" in finding["description"].lower() for finding in reviewed["findings"])


def test_declared_license_review_never_recovers_withheld_manifest_text():
    canary = "private-canary-license@example.invalid"
    reviewed = add_project_license_review(
        {
            "parsed_manifests": [
                {"path": "pyproject.toml", "parsed": {"project": {"license_status": "unrecognized_withheld"}}}
            ]
        },
        [],
    )

    assert canary not in json.dumps(reviewed)
    assert reviewed["license_review"]["declarations"] == [
        {"manifest_path": "pyproject.toml", "status": "unknown_unrecognized_withheld"}
    ]
