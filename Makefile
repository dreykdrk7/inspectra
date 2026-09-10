PYTHON ?= python3
PYTHON_REQUIRED_MAJOR ?= 3
PYTHON_REQUIRED_MINOR ?= 12
PIP_VERSION ?= 26.2.1
VENV ?= .venv
VENV_PYTHON := $(VENV)/bin/python
NPM ?= npm
FRONTEND_DIR ?= frontend
AUDIT_REQUIREMENTS ?= tools/requirements-audit.lock
GITLEAKS_IMAGE ?= ghcr.io/gitleaks/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f

INSPECTRA_PUBLIC_HOST ?= inspectra.example.test
INSPECTRA_TLS_EMAIL ?= security@example.test
INSPECTRA_ADMIN_PASSWORD_HASH ?= placeholder

.PHONY: \
	setup-python \
	check-python-version \
	check-backlogs \
	check-release \
	test-python \
	test-cli \
	audit-python \
	setup-frontend \
	test-frontend \
	build-frontend \
	audit-frontend \
	validate-compose \
	validate-compose-private \
	verify-secret-scanner \
	validate

check-python-version:
	@"$(PYTHON)" -c 'import sys; expected = ($(PYTHON_REQUIRED_MAJOR), $(PYTHON_REQUIRED_MINOR)); actual = sys.version_info[:2]; actual == expected or (print(f"Inspectra requires Python {expected[0]}.{expected[1]}; received {sys.version.split()[0]}. Re-run with PYTHON=/path/to/python{expected[0]}.{expected[1]}.", file=sys.stderr), sys.exit(2))'

check-backlogs:
	@PYTHONPATH=tools "$(PYTHON)" -m backlog_consistency

check-release:
	@PYTHONPATH=tools "$(PYTHON)" -m release_consistency

setup-python: check-python-version
	$(PYTHON) -m venv "$(VENV)"
	"$(VENV_PYTHON)" -m pip install --upgrade "pip==$(PIP_VERSION)"
	"$(VENV_PYTHON)" -m pip install -r backend/requirements-dev.lock -r tools/requirements.lock

test-python: setup-python
	"$(VENV_PYTHON)" -m pytest
	PYTHONPATH=cli "$(VENV_PYTHON)" -m pytest cli/tests

test-cli: setup-python
	PYTHONPATH=cli "$(VENV_PYTHON)" -m pytest cli/tests

audit-python: setup-python
	"$(VENV_PYTHON)" -m pip install -r "$(AUDIT_REQUIREMENTS)"
	"$(VENV_PYTHON)" -m pip_audit -r backend/requirements.lock
	"$(VENV_PYTHON)" -m pip_audit -r backend/requirements-dev.lock
	"$(VENV_PYTHON)" -m pip_audit -r tools/requirements.lock
	"$(VENV_PYTHON)" -m pip_audit -r docker/active-tools/requirements.lock
	"$(VENV_PYTHON)" -m pip_audit -r "$(AUDIT_REQUIREMENTS)"

setup-frontend:
	$(NPM) --prefix "$(FRONTEND_DIR)" ci

test-frontend: setup-frontend
	$(NPM) --prefix "$(FRONTEND_DIR)" run test:run

build-frontend: setup-frontend
	$(NPM) --prefix "$(FRONTEND_DIR)" run build

audit-frontend: setup-frontend
	$(NPM) --prefix "$(FRONTEND_DIR)" audit --package-lock-only --audit-level=high

validate-compose:
	docker compose config --quiet

validate-compose-private:
	INSPECTRA_PUBLIC_HOST='$(INSPECTRA_PUBLIC_HOST)' INSPECTRA_TLS_EMAIL='$(INSPECTRA_TLS_EMAIL)' INSPECTRA_ADMIN_PASSWORD_HASH='$(INSPECTRA_ADMIN_PASSWORD_HASH)' docker compose -f docker-compose.yml -f docker-compose.private.example.yml config --quiet

verify-secret-scanner:
	@status=0; \
	docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
		--volume "$(CURDIR):/repo:ro" \
		--workdir /repo \
		"$(GITLEAKS_IMAGE)" \
		dir --config /repo/.gitleaks.toml --gitleaks-ignore-path /repo/.gitleaksignore --redact=100 --exit-code 5 \
		/repo/tests/fixtures/demo/passive-alpha/sources/demo-archive-container-infra/terraform || status=$$?; \
	if [ "$$status" -ne 5 ]; then \
		echo "Gitleaks policy canary failed: expected synthetic leaks (exit 5), received exit $$status." >&2; \
		exit 1; \
	fi

validate: check-backlogs check-release test-python audit-python test-frontend build-frontend audit-frontend validate-compose validate-compose-private verify-secret-scanner
