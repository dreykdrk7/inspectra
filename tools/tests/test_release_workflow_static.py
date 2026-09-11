from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "release-candidate.yml"


def test_release_workflow_is_manual_sha_bound_and_read_only() -> None:
    content = WORKFLOW.read_text(encoding="utf-8")

    assert "workflow_dispatch:" in content
    assert "pull_request_target" not in content
    assert "expected_sha:" in content
    assert '[[ "${GITHUB_REF}" == "refs/heads/main" ]]' in content
    assert '[[ "${EXPECTED_SHA}" == "${GITHUB_SHA}" ]]' in content
    assert "permissions:\n  contents: read" in content
    assert "persist-credentials: false" in content
    assert "timeout-minutes: 20" in content


def test_release_workflow_pins_actions_and_only_uploads_verified_assets() -> None:
    content = WORKFLOW.read_text(encoding="utf-8")
    action_uses = re.findall(r"uses:\s+([^\s#]+)", content)

    assert action_uses
    assert all(re.fullmatch(r"actions/[a-z-]+@[0-9a-f]{40}", use) for use in action_uses)
    assert "cli/scripts/build_release.py --output release-dist" in content
    assert "sha256sum -c SHA256SUMS" in content
    assert "--max-archive-depth 2 /repo/release-dist" in content
    assert "path: release-dist/*" in content
    assert "if-no-files-found: error" in content
    assert "retention-days: 1" in content


def test_release_workflow_checks_the_real_cli_version_output() -> None:
    content = WORKFLOW.read_text(encoding="utf-8")

    assert (
        'test "$(/tmp/inspectra-wheel/bin/inspectra --version)" '
        '= "inspectra-cli 0.3.0-beta.1"'
    ) in content
    assert (
        'test "$(/tmp/inspectra-sdist/bin/inspectra --version)" '
        '= "inspectra-cli 0.3.0-beta.1"'
    ) in content


def test_release_workflow_cannot_publish_or_target_external_registries() -> None:
    content = WORKFLOW.read_text(encoding="utf-8").lower()

    for forbidden in (
        "contents: write",
        "id-token: write",
        "packages: write",
        "gh release",
        "pypi",
        "docker/login-action",
        "docker/build-push-action",
    ):
        assert forbidden not in content
