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

    assert "FROM python:3.12-slim" in body
    assert "apt-get install" in body
    assert "nmap" in body
    assert "COPY docker/active-tools/requirements.txt /tmp/active-tools-requirements.txt" in body
    assert "pip install --no-cache-dir -r /tmp/active-tools-requirements.txt" in body
    assert "COPY tools/active_runner /app/active_runner" in body
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

    assert body == ["fastapi>=0.115,<1.0", "uvicorn>=0.30,<1.0"]


def test_active_tools_compose_example_is_disabled_and_private() -> None:
    body = _read(COMPOSE_EXAMPLE)

    assert "profiles: [\"active\"]" in body
    assert "dockerfile: docker/active-tools/Dockerfile" in body
    assert "internal: true" in body
    assert "cap_drop:" in body
    assert "- ALL" in body
    assert "read_only: true" in body
    assert "tmpfs:" in body
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
