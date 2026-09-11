from pathlib import Path
import re


REPO_ROOT = Path(__file__).resolve().parents[2]
COMPOSE_FILE = REPO_ROOT / "docker-compose.yml"
PRIVATE_COMPOSE_FILE = REPO_ROOT / "docker-compose.private.example.yml"
ACCEPTANCE_COMPOSE_FILE = REPO_ROOT / "docker-compose.acceptance.yml"
ACCEPTANCE_EGRESS_COMPOSE_FILE = REPO_ROOT / "docker-compose.acceptance-egress.yml"
CADDYFILE = REPO_ROOT / "deploy" / "private" / "Caddyfile"
ACCEPTANCE_CADDYFILE = REPO_ROOT / "deploy" / "acceptance" / "Caddyfile"
README = REPO_ROOT / "README.md"
DEPLOYMENT_ACCEPTANCE = REPO_ROOT / "DEPLOYMENT_ACCEPTANCE.md"
BACKEND_DOCKERFILE = REPO_ROOT / "backend" / "Dockerfile"
TOOLS_DOCKERFILE = REPO_ROOT / "tools" / "Dockerfile"
FRONTEND_DOCKERFILE = REPO_ROOT / "frontend" / "Dockerfile"
ACTIVE_TOOLS_DOCKERFILE = REPO_ROOT / "docker" / "active-tools" / "Dockerfile"
SYSTEM_PACKAGE_SNAPSHOTS = REPO_ROOT / "docs" / "system-package-snapshots.md"
ROOT_DOCKERIGNORE = REPO_ROOT / ".dockerignore"
BACKEND_DOCKERIGNORE = REPO_ROOT / "backend" / ".dockerignore"
TOOLS_DOCKERIGNORE = REPO_ROOT / "tools" / ".dockerignore"
FRONTEND_DOCKERIGNORE = REPO_ROOT / "frontend" / ".dockerignore"
GITLEAKS_CONFIG = REPO_ROOT / ".gitleaks.toml"
GITLEAKS_IGNORE = REPO_ROOT / ".gitleaksignore"
LOCKFILES = (
    REPO_ROOT / "backend" / "requirements.lock",
    REPO_ROOT / "backend" / "requirements-dev.lock",
    REPO_ROOT / "tools" / "requirements.lock",
    REPO_ROOT / "docker" / "active-tools" / "requirements.lock",
)


def test_public_compose_ports_bind_to_loopback_by_default() -> None:
    body = COMPOSE_FILE.read_text(encoding="utf-8")

    assert '"127.0.0.1:${INSPECTRA_BACKEND_HOST_PORT:-8000}:8000"' in body
    assert '"127.0.0.1:${INSPECTRA_FRONTEND_HOST_PORT:-5173}:5173"' in body


def test_public_compose_exposes_only_safe_cors_configuration_knobs() -> None:
    body = COMPOSE_FILE.read_text(encoding="utf-8")

    assert "INSPECTRA_CORS_ORIGINS: ${INSPECTRA_CORS_ORIGINS:-http://localhost:${INSPECTRA_FRONTEND_HOST_PORT:-5173}}" in body
    assert "INSPECTRA_CORS_ALLOWED_METHODS: ${INSPECTRA_CORS_ALLOWED_METHODS:-GET,POST,PUT,DELETE}" in body
    assert "INSPECTRA_CORS_ALLOWED_HEADERS: ${INSPECTRA_CORS_ALLOWED_HEADERS:-Content-Type,X-CSRF-Token}" in body
    assert "INSPECTRA_AUDIT_MAX_CONCURRENCY: ${INSPECTRA_AUDIT_MAX_CONCURRENCY:-4}" in body
    assert "INSPECTRA_AUDIT_MAX_INFLIGHT_JOBS: ${INSPECTRA_AUDIT_MAX_INFLIGHT_JOBS:-128}" in body
    assert "INSPECTRA_AUDIT_MAX_INFLIGHT_JOBS_PER_OWNER: ${INSPECTRA_AUDIT_MAX_INFLIGHT_JOBS_PER_OWNER:-32}" in body


def test_project_analysis_services_have_reproducible_resource_and_temporary_storage_limits() -> None:
    body = COMPOSE_FILE.read_text(encoding="utf-8")

    backend_match = re.search(r"(?ms)^  backend:\n(.*?)(?=^  audit-tools:)", body)
    runner_match = re.search(r"(?ms)^  audit-tools:\n(.*?)(?=^  network-tools:)", body)
    network_runner_match = re.search(r"(?ms)^  network-tools:\n(.*?)(?=^  frontend:)", body)
    assert backend_match is not None
    assert runner_match is not None
    assert network_runner_match is not None
    backend = backend_match.group(1)
    runner = runner_match.group(1)
    network_runner = network_runner_match.group(1)
    assert "cpus: 1.0" in backend
    assert "mem_limit: 512m" in backend
    assert "pids_limit: 256" in backend
    assert "/tmp:size=67108864,mode=1777" in backend
    assert "cpus: 1.0" in runner
    assert "mem_limit: 512m" in runner
    assert "pids_limit: 128" in runner
    assert "/var/lib/inspectra-workers:size=67108864,mode=0700,uid=1000,gid=1000" in runner
    assert "INSPECTRA_PROJECT_ARCHIVE_MAX_TOTAL_UNCOMPRESSED_BYTES: \"209715200\"" in runner
    assert "INSPECTRA_PROJECT_ARCHIVE_MAX_ARCHIVE_ENTRIES: \"5000\"" in runner
    assert "INSPECTRA_PROJECT_ARCHIVE_MAX_LOCKFILE_PACKAGES: \"2000\"" in runner
    assert "INSPECTRA_PROJECT_ARCHIVE_MAX_LOCKFILE_EDGES: \"4000\"" in runner
    assert "INSPECTRA_TOOL_WORKER_MAX_SOURCE_BYTES: \"20971520\"" in runner
    assert "INSPECTRA_TOOL_WORKER_TIMEOUT_SECONDS: \"55\"" in runner
    assert "INSPECTRA_TOOL_WORKER_CPU_SECONDS: \"45\"" in runner
    assert "INSPECTRA_TOOL_WORKER_MEMORY_BYTES: \"402653184\"" in runner
    assert "INSPECTRA_TOOL_WORKER_MAX_RESULT_BYTES: \"4194304\"" in runner
    assert "INSPECTRA_TOOL_WORKER_MAX_FILE_BYTES: \"33554432\"" in runner
    assert "INSPECTRA_TOOL_WORKER_MAX_OPEN_FILES: \"64\"" in runner
    assert "INSPECTRA_TOOL_WORKER_MAX_PROCESSES: \"32\"" in runner
    assert "INSPECTRA_TOOL_WORKER_ROOT: /var/lib/inspectra-workers" in runner
    assert 'INSPECTRA_FILE_ANALYSIS_ENABLED: "true"' in runner
    assert 'INSPECTRA_NETWORK_ANALYSIS_ENABLED: "false"' in runner
    assert "./data:/app/data" not in runner
    assert "inspectra_web_egress" not in runner
    assert 'INSPECTRA_FILE_ANALYSIS_ENABLED: "false"' in network_runner
    assert 'INSPECTRA_NETWORK_ANALYSIS_ENABLED: "true"' in network_runner
    assert "inspectra_web_egress" in network_runner
    assert "./data:/app/data" not in network_runner
    assert "INSPECTRA_NETWORK_TOOL_RUNNER_URL: http://network-tools:8081" in backend
    assert "INSPECTRA_READINESS_TIMEOUT_SECONDS: ${INSPECTRA_READINESS_TIMEOUT_SECONDS:-2}" in backend
    assert "http://127.0.0.1:8000/ready" in backend
    assert "http://127.0.0.1:8000/health" not in backend


def test_public_compose_builds_the_browser_api_url_from_the_published_backend_port() -> None:
    body = COMPOSE_FILE.read_text(encoding="utf-8")

    assert "VITE_API_BASE_URL: ${VITE_API_BASE_URL:-http://localhost:${INSPECTRA_BACKEND_HOST_PORT:-8000}}" in body
    assert "VITE_API_BASE_URL: http://localhost:8000" not in body


def test_private_compose_requires_app_auth_and_removes_direct_app_ports() -> None:
    body = PRIVATE_COMPOSE_FILE.read_text(encoding="utf-8")

    assert "ports: !reset []" in body
    assert "INSPECTRA_DEPLOYMENT_PROFILE: private_tls_proxy" in body
    assert "INSPECTRA_AUTH_MODE: self_hosted_single_admin" in body
    assert "INSPECTRA_ADMIN_PASSWORD_HASH: ${INSPECTRA_ADMIN_PASSWORD_HASH:?" in body
    assert "INSPECTRA_AUTH_STATE_STORE: sqlite" in body
    assert 'INSPECTRA_SESSION_COOKIE_SECURE: "true"' in body
    assert "VITE_API_BASE_URL: /api" in body
    assert "image: caddy:2.11.4-alpine@sha256:5f5c8640aae01df9654968d946d8f1a56c497f1dd5c5cda4cf95ab7c14d58648" in body
    assert '"${INSPECTRA_PRIVATE_HTTPS_PORT:-443}:443"' in body
    assert '"${INSPECTRA_BACKEND_HOST_PORT:-8000}:8000"' not in body
    assert '"${INSPECTRA_FRONTEND_HOST_PORT:-5173}:5173"' not in body


def test_private_proxy_has_a_bounded_runtime_envelope() -> None:
    body = PRIVATE_COMPOSE_FILE.read_text(encoding="utf-8")
    proxy_match = re.search(r"(?ms)^  proxy:\n(.*?)(?=^volumes:)", body)

    assert proxy_match is not None
    proxy = proxy_match.group(1)
    assert "read_only: true" in proxy
    assert "cap_drop:\n      - ALL" in proxy
    assert "security_opt:\n      - no-new-privileges:true" in proxy
    assert "cpus: 0.5" in proxy
    assert "mem_limit: 128m" in proxy
    assert "pids_limit: 64" in proxy


def test_private_deployment_docs_require_compose_safe_password_hash_quoting() -> None:
    readme = README.read_text(encoding="utf-8")
    acceptance = DEPLOYMENT_ACCEPTANCE.read_text(encoding="utf-8")
    quoted_shape = "INSPECTRA_ADMIN_PASSWORD_HASH='pbkdf2_sha256$<iterations>$<salt>$<digest>'"

    assert quoted_shape in readme
    assert "An unquoted verifier is a deployment error" in readme
    assert "INSPECTRA_ADMIN_PASSWORD_HASH='pbkdf2_sha256$<iteraciones>$<salt>$<digest>'" in acceptance
    assert "cualquier aviso de interpolación" in acceptance


def test_private_proxy_keeps_the_api_same_origin_and_internal() -> None:
    body = CADDYFILE.read_text(encoding="utf-8")

    assert "{$INSPECTRA_PUBLIC_HOST}" in body
    assert "handle_path /api/*" in body
    assert "reverse_proxy backend:8000" in body
    assert "reverse_proxy frontend:5173" in body


def test_private_proxy_sets_defensive_https_response_headers() -> None:
    body = CADDYFILE.read_text(encoding="utf-8")

    assert 'Strict-Transport-Security "max-age=31536000"' in body
    assert 'X-Content-Type-Options "nosniff"' in body
    assert 'X-Frame-Options "DENY"' in body
    assert 'Referrer-Policy "strict-origin-when-cross-origin"' in body
    assert 'Permissions-Policy "camera=(), geolocation=(), microphone=(), payment=(), usb=()"' in body
    assert 'Cross-Origin-Opener-Policy "same-origin"' in body
    assert 'Cross-Origin-Resource-Policy "same-origin"' in body
    assert "Content-Security-Policy \"default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; object-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-src 'none'; upgrade-insecure-requests\"" in body
    assert "unsafe-inline" not in body


def test_acceptance_overlay_is_loopback_only_synthetic_and_does_not_replace_existing_containers() -> None:
    body = ACCEPTANCE_COMPOSE_FILE.read_text(encoding="utf-8")
    caddy = ACCEPTANCE_CADDYFILE.read_text(encoding="utf-8")

    assert body.count("container_name: !reset null") == 5
    assert "INSPECTRA_ACCEPTANCE_DATA_DIR:?" in body
    assert '"127.0.0.1:${INSPECTRA_ACCEPTANCE_HTTP_PORT:-18080}:80"' in body
    assert '"127.0.0.1:${INSPECTRA_ACCEPTANCE_HTTPS_PORT:-18443}:443"' in body
    assert body.count("internal: true") == 3
    assert "inspectra_acceptance_entry" in body
    assert "https://localhost" in caddy
    assert "tls internal" in caddy
    assert "handle_path /api/*" in caddy
    assert "reverse_proxy backend:8000" in caddy
    assert "reverse_proxy frontend:5173" in caddy
    assert "{$INSPECTRA_PUBLIC_HOST}" not in caddy


def test_acceptance_egress_is_a_separate_explicit_backend_only_overlay() -> None:
    body = ACCEPTANCE_EGRESS_COMPOSE_FILE.read_text(encoding="utf-8")

    assert "INSPECTRA_ACCEPTANCE_PUBLIC_ADVISORY_EGRESS_ENABLED:?" in body
    assert "INSPECTRA_PUBLIC_ADVISORY_EGRESS_ENABLED:" in body
    assert "INSPECTRA_ACCEPTANCE_PRIVATE_PACKAGE_RULES:-" in body
    assert "INSPECTRA_ACCEPTANCE_PUBLIC_PYPI_PACKAGES:-" in body
    assert body.count("inspectra_public_advisory_egress") == 2
    assert "networks: !override" in body
    assert "audit-tools:" not in body
    assert "network-tools:" not in body
    assert "frontend:" not in body
    assert "proxy:" not in body


def test_backend_disables_unconfigured_proxy_headers() -> None:
    body = BACKEND_DOCKERFILE.read_text(encoding="utf-8")

    assert '"--no-proxy-headers"' in body


def test_runtime_images_are_pinned_to_manifest_digests() -> None:
    python_base = "python:3.12-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea"
    node_base = "node:22-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32"
    dockerfile_frontend = "docker/dockerfile:1@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32"

    for dockerfile in (BACKEND_DOCKERFILE, TOOLS_DOCKERFILE, ACTIVE_TOOLS_DOCKERFILE):
        assert python_base in dockerfile.read_text(encoding="utf-8")
    assert FRONTEND_DOCKERFILE.read_text(encoding="utf-8").count(node_base) == 2
    assert dockerfile_frontend in BACKEND_DOCKERFILE.read_text(encoding="utf-8")
    assert dockerfile_frontend in ACTIVE_TOOLS_DOCKERFILE.read_text(encoding="utf-8")


def test_system_package_installs_use_the_documented_immutable_debian_snapshot() -> None:
    snapshot = "20260824T000000Z"
    expected_snapshot_setup = (
        f"ARG INSPECTRA_DEBIAN_SNAPSHOT={snapshot}",
        'Acquire::Check-Valid-Until "false";',
        "https://snapshot.debian.org/archive/debian-security/${INSPECTRA_DEBIAN_SNAPSHOT}",
        "https://snapshot.debian.org/archive/debian/${INSPECTRA_DEBIAN_SNAPSHOT}",
    )

    for dockerfile in (TOOLS_DOCKERFILE, ACTIVE_TOOLS_DOCKERFILE):
        body = dockerfile.read_text(encoding="utf-8")
        assert all(expected in body for expected in expected_snapshot_setup)

    documentation = SYSTEM_PACKAGE_SNAPSHOTS.read_text(encoding="utf-8")
    assert snapshot in documentation
    for package_version in ("file` | `1:5.46-5", "libimage-exiftool-perl` | `13.25+dfsg-1", "poppler-utils` | `25.03.0-5+deb13u4", "qpdf` | `12.2.0-1", "nmap` | `7.95+dfsg-3"):
        assert package_version in documentation


def test_python_images_install_committed_lockfiles() -> None:
    for lockfile in LOCKFILES:
        assert lockfile.exists()

    assert "COPY requirements.lock /tmp/requirements.lock" in BACKEND_DOCKERFILE.read_text(encoding="utf-8")
    assert "COPY requirements.lock /tmp/requirements.lock" in TOOLS_DOCKERFILE.read_text(encoding="utf-8")
    assert "COPY docker/active-tools/requirements.lock" in ACTIVE_TOOLS_DOCKERFILE.read_text(encoding="utf-8")


def test_docker_build_contexts_exclude_local_data_and_secret_material() -> None:
    required_exclusions = (".env", ".env.*", "*.pem", "*.key", "*.p12", "*.pfx")

    for dockerignore in (BACKEND_DOCKERIGNORE, TOOLS_DOCKERIGNORE, FRONTEND_DOCKERIGNORE):
        body = dockerignore.read_text(encoding="utf-8")
        assert all(pattern in body for pattern in required_exclusions)

    root_body = ROOT_DOCKERIGNORE.read_text(encoding="utf-8")
    assert "# The active-tools Dockerfile builds from the repository root." in root_body
    assert "\n*\n" in root_body
    assert "!docker/active-tools/Dockerfile" in root_body
    assert "!docker/active-tools/requirements.lock" in root_body
    assert "!tools/active_runner/**" in root_body


def test_secret_scan_is_configured_with_only_synthetic_fixture_allowlists() -> None:
    workflow = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    config = GITLEAKS_CONFIG.read_text(encoding="utf-8")
    ignore = GITLEAKS_IGNORE.read_text(encoding="utf-8")

    assert "fetch-depth: 0" in workflow
    assert "ghcr.io/gitleaks/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f" in workflow
    assert 'git --config /repo/.gitleaks.toml --gitleaks-ignore-path /repo/.gitleaksignore --redact=100 --exit-code 1 --log-opts="--all" /repo' in workflow
    assert "gitleaks/gitleaks-action@" not in workflow
    assert "GITLEAKS_LICENSE" not in workflow
    assert "make verify-secret-scanner" in workflow
    assert "[extend]" in config
    assert "useDefault = true" in config
    assert "[allowlist]" in config
    assert config.count("tests/fixtures/") == 7
    assert "unsafe_counterexamples" in config
    assert "demo-archive-container-infra/terraform/main[.]tf" in config
    assert "src/" not in config
    fingerprints = [line for line in ignore.splitlines() if line and not line.startswith("#")]
    assert len(fingerprints) == 54
    assert all(line.count(":") >= 3 for line in fingerprints)
    assert all(
        ":backend/tests/" in line
        or ":tools/tests/" in line
        or ":tests/fixtures/" in line
        or ":docs/future/" in line
        or ".test.ts" in line
        for line in fingerprints
    )


def test_ci_actions_are_pinned_to_verified_commit_shas() -> None:
    workflow = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    expected_actions = {
        "actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0": 4,
        "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065 # v5.6.0": 1,
        "actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4.4.0": 1,
    }

    for action, expected_count in expected_actions.items():
        assert workflow.count(action) == expected_count
    assert re.search(r"^\s*- uses: [^\s@]+@v", workflow, flags=re.MULTILINE) is None
