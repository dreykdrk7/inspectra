from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = REPO_ROOT / "docker" / "active-tools" / "Dockerfile"
DOCKERIGNORE = REPO_ROOT / "docker" / "active-tools" / "Dockerfile.dockerignore"
REQUIREMENTS = REPO_ROOT / "docker" / "active-tools" / "requirements.txt"
COMPOSE_EXAMPLE = REPO_ROOT / "docker-compose.active-tools.example.yml"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_active_tools_scaffold_files_exist() -> None:
    assert DOCKERFILE.exists()
    assert DOCKERIGNORE.exists()
    assert REQUIREMENTS.exists()
    assert COMPOSE_EXAMPLE.exists()


def test_active_tools_dockerfile_keeps_active_boundary_separate() -> None:
    body = _read(DOCKERFILE)

    assert "FROM python:3.12-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea" in body
    assert "apt-get install" in body
    assert "nmap" in body
    assert "COPY docker/active-tools/requirements.lock /tmp/active-tools-requirements.lock" in body
    assert "pip install --no-cache-dir -r /tmp/active-tools-requirements.lock" in body
    assert "COPY tools/active_runner /app/active_runner" in body
    for module in (
        "active_dns_inventory.py",
        "active_dns_osint.py",
        "active_http_basic_header_review.py",
        "active_tls_basic.py",
    ):
        assert f"COPY backend/app/{module} /app/app/{module}" in body
    assert "tools/runner/main.py" not in body
    assert "HEALTHCHECK" not in body
    assert "EXPOSE" not in body
    assert "--script" not in body
    assert "NSE" in body
    assert "nmap -" not in body
    assert "CMD [\"nmap\"" not in body
    assert "scaffold_no_run" in body
    assert "python -m uvicorn" not in body


def test_active_tools_asgi_packaging_is_minimal_and_explicit() -> None:
    body = _read(REQUIREMENTS).splitlines()

    assert body == ["fastapi==0.141.1", "httpx==0.28.1", "uvicorn==0.52.4"]


def test_active_tools_compose_example_is_disabled_and_private() -> None:
    body = _read(COMPOSE_EXAMPLE)

    assert "profiles: [\"active\"]" in body
    assert "image: inspectra-active-tools:asgi-smoke" in body
    assert "dockerfile: docker/active-tools/Dockerfile" in body
    assert 'command: ["python", "-m", "uvicorn", "active_runner.app:app", "--host", "0.0.0.0", "--port", "8080"]' in body
    for flag in (
        "INSPECTRA_ACTIVE_TOOLS_NMAP_BASIC_EXECUTION_ENABLED",
        "INSPECTRA_ACTIVE_TOOLS_DNS_INVENTORY_EXECUTION_ENABLED",
        "INSPECTRA_ACTIVE_TOOLS_DNS_OSINT_EXECUTION_ENABLED",
        "INSPECTRA_ACTIVE_TOOLS_HTTP_HEADERS_EXECUTION_ENABLED",
        "INSPECTRA_ACTIVE_TOOLS_TLS_BASIC_EXECUTION_ENABLED",
    ):
        assert f'{flag}: "false"' in body
    assert "healthcheck:" in body
    assert "http://127.0.0.1:8080/health" in body
    assert "internal: true" in body
    assert "inspectra_active_egress:" in body
    assert "cap_drop:" in body
    assert "- ALL" in body
    assert "read_only: true" in body
    assert "tmpfs:" in body
    assert "/tmp:rw,noexec,nosuid,size=16m" in body
    assert "no-new-privileges:true" in body
    assert "ports:" not in body
    assert "network_mode: host" not in body
    assert "privileged: true" not in body
    assert "docker.sock" not in body
    assert "tools/runner/main.py" not in body


def test_active_tools_dockerignore_excludes_sensitive_and_runtime_data() -> None:
    body = _read(DOCKERIGNORE).splitlines()

    for expected in (
        ".env",
        ".env.*",
        ".envrc",
        "data",
        "data/uploads",
        "data/results",
        "frontend/node_modules",
        "frontend/dist",
        ".venv",
    ):
        assert expected in body
