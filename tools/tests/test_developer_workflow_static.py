from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MAKEFILE = REPO_ROOT / "Makefile"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"
README = REPO_ROOT / "README.md"
GITIGNORE = REPO_ROOT / ".gitignore"
FRONTEND_VISUAL_REVIEW = REPO_ROOT / "docs" / "frontend-visual-review.md"
AUDIT_REQUIREMENTS = REPO_ROOT / "tools" / "requirements-audit.lock"
DEV_REQUIREMENTS = REPO_ROOT / "backend" / "requirements-dev.lock"
TEST_STRATEGY = REPO_ROOT / "docs" / "test-strategy.md"


def test_makefile_exposes_reproducible_setup_and_validation_targets() -> None:
    body = MAKEFILE.read_text(encoding="utf-8")

    for target in (
        "check-python-version:",
        "check-backlogs:",
        "setup-python: check-python-version",
        "test-python: setup-python",
        "test-cli: setup-python",
        "audit-python: setup-python",
        "setup-frontend:",
        "test-frontend: setup-frontend",
        "build-frontend: setup-frontend",
        "audit-frontend: setup-frontend",
        "validate-compose:",
        "validate-compose-private:",
        "verify-secret-scanner:",
        "validate:",
    ):
        assert target in body

    assert "backend/requirements-dev.lock -r tools/requirements.lock" in body
    assert 'PYTHONPATH=cli "$(VENV_PYTHON)" -m pytest cli/tests' in body
    assert "PYTHON_REQUIRED_MAJOR ?= 3" in body
    assert "PYTHON_REQUIRED_MINOR ?= 12" in body
    assert "Inspectra requires Python" in body
    assert "PIP_VERSION ?= 26.2.1" in body
    assert 'pip install --upgrade "pip==$(PIP_VERSION)"' in body
    assert 'PYTHONPATH=tools "$(PYTHON)" -m backlog_consistency' in body
    assert 'AUDIT_REQUIREMENTS ?= tools/requirements-audit.lock' in body
    assert 'pip install -r "$(AUDIT_REQUIREMENTS)"' in body
    assert 'pip_audit -r "$(AUDIT_REQUIREMENTS)"' in body
    assert '$(NPM) --prefix "$(FRONTEND_DIR)" ci' in body
    assert '$(NPM) --prefix "$(FRONTEND_DIR)" run test:run' in body
    assert '$(NPM) --prefix "$(FRONTEND_DIR)" run build' in body
    assert "docker compose -f docker-compose.yml -f docker-compose.private.example.yml config --quiet" in body
    assert "GITLEAKS_IMAGE ?= ghcr.io/gitleaks/gitleaks@sha256:" in body
    assert "--network none --read-only --cap-drop ALL --security-opt no-new-privileges" in body
    assert "--config /repo/.gitleaks.toml --gitleaks-ignore-path /repo/.gitleaksignore --redact=100 --exit-code 5" in body
    assert "/repo/tests/fixtures/demo/passive-alpha/sources/demo-archive-container-infra/terraform" in body
    assert 'if [ "$$status" -ne 5 ]' in body


def test_ci_and_development_docs_use_the_shared_make_targets() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    readme = README.read_text(encoding="utf-8")

    assert "make test-python audit-python PYTHON=python" in workflow
    assert "make check-backlogs PYTHON=python" in workflow
    assert "make test-frontend build-frontend audit-frontend" in workflow
    assert "make validate-compose" in workflow
    assert "make validate-compose-private" in workflow
    assert "make verify-secret-scanner" in workflow
    assert "make validate" in readme
    assert "make check-backlogs" in readme
    assert "make test-python" in readme
    assert "make test-cli" in readme
    assert "make check-python-version" in readme
    assert "make verify-secret-scanner" in readme


def test_frontend_visual_review_uses_synthetic_data_and_a_fixed_viewport_matrix() -> None:
    guide = FRONTEND_VISUAL_REVIEW.read_text(encoding="utf-8")
    gitignore = GITIGNORE.read_text(encoding="utf-8")

    assert "tests/fixtures/demo/passive-alpha/" in guide
    assert "demo-archive-app-config.zip" in guide
    assert all(viewport in guide for viewport in ("1440 px", "768 px", "320 px"))
    assert "make test-frontend build-frontend" in guide
    assert "visual-review/" in gitignore


def test_python_audit_tool_has_a_dedicated_pinned_and_audited_lockfile() -> None:
    lockfile = AUDIT_REQUIREMENTS.read_text(encoding="utf-8")

    assert "pip-audit==2.10.1" in lockfile
    assert "requests==2.34.2" in lockfile
    assert "urllib3==2.7.0" in lockfile


def test_cli_gate_declares_schema_validation_dependencies_and_safety_contract() -> None:
    lockfile = DEV_REQUIREMENTS.read_text(encoding="utf-8")
    strategy = TEST_STRATEGY.read_text(encoding="utf-8")

    for requirement in (
        "attrs==25.3.0",
        "jsonschema==4.25.1",
        "jsonschema-specifications==2025.9.1",
        "referencing==0.36.2",
        "rpds-py==0.27.1",
    ):
        assert requirement in lockfile
    assert "make test-cli" in strategy
    assert "backend/tests/conftest.py" in strategy
    assert "backend/tests/test_test_safety_contract.py" in strategy
