import io
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import struct
import tarfile
import threading
import zipfile

import runner.main as runner
import pytest
from httpx import ASGITransport, AsyncClient


SAMPLE_PNG = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde"
PACKAGE_JSON = """{
  "name": "demo-app",
  "version": "1.0.0",
  "scripts": {
    "postinstall": "node scripts/postinstall.js",
    "test": "vitest"
  },
  "dependencies": {
    "react": "^18.3.1",
    "local-lib": "file:../local-lib",
    "floating": "latest"
  },
  "devDependencies": {
    "vite": "*"
  },
  "engines": {
    "node": ">=20"
  }
}
"""
REQUIREMENTS_TXT = """
fastapi==0.115.0
httpx>=0.27
-e git+https://example.invalid/demo.git#egg=demo
--extra-index-url https://packages.example.invalid/simple
"""
PYPROJECT_TOML = """
[project]
name = "demo-service"
version = "0.1.0"
dependencies = [
  "fastapi>=0.115",
  "httpx==0.27.0",
  "demo @ git+https://example.invalid/demo.git",
]

[project.optional-dependencies]
dev = ["pytest>=8"]

[tool.poetry.dependencies]
python = "^3.12"
requests = "^2.32"

[tool.poetry.group.docs.dependencies]
mkdocs = "*"
"""


def test_run_command_records_timeout(monkeypatch):
    monkeypatch.setattr(runner, "COMMAND_TIMEOUT_SECONDS", 0.01)

    result = runner.run_command(["python3", "-c", "import time; time.sleep(1)"])

    assert result["timed_out"] is True
    assert result["exit_code"] is None
    assert result["timeout_seconds"] == 0.01


@pytest.mark.anyio
async def test_analyze_image_returns_passive_metadata(monkeypatch, tmp_path):
    uploads_dir = tmp_path / "uploads"
    uploads_dir.mkdir()
    image_path = uploads_dir / "pixel.png"
    image_path.write_bytes(SAMPLE_PNG)
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    monkeypatch.setattr(runner, "run_command", fake_image_command)
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/image",
            json={"file_id": "f" * 32, "relative_path": "uploads/pixel.png"},
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["analyzer"] == "inspectra-image-basic"
    assert payload["identification"]["detected_format"] == "png"
    assert payload["identification"]["mime_type"] == "image/png"
    assert payload["metadata"]["exiftool"]["ImageWidth"] == 1
    assert payload["privacy_indicators"]["gps_present"] is True
    assert payload["hashes"]["sha256"]


@pytest.mark.anyio
async def test_analyze_image_rejects_path_traversal(monkeypatch, tmp_path):
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/image",
            json={"file_id": "f" * 32, "relative_path": "../outside.png"},
        )

    assert response.status_code == 400
    assert response.json()["detail"] == "Path escapes data directory."


@pytest.mark.anyio
async def test_analyze_manifest_package_json_detects_scripts_and_source_dependencies(monkeypatch, tmp_path):
    manifest_path = write_manifest(tmp_path, "package.json", PACKAGE_JSON)
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/manifest",
            json={"file_id": "f" * 32, "relative_path": str(manifest_path.relative_to(tmp_path)), "original_filename": "package.json"},
        )

    assert response.status_code == 200
    payload = response.json()
    finding_ids = {finding["id"] for finding in payload["findings"]}
    assert payload["analyzer"] == "manifest_basic"
    assert payload["manifest_type"] == "package_json"
    assert payload["parsed"]["project"]["name"] == "demo-app"
    assert payload["parsed"]["scripts"]["postinstall"] == "node scripts/postinstall.js"
    dependencies = {item["name"]: item for item in payload["parsed"]["dependencies"]["dependencies"]}
    assert dependencies["react"]["source_type"] == "registry"
    assert dependencies["local-lib"]["source_type"] == "local"
    assert dependencies["local-lib"]["declared_requirement"] == "local-lib: file:../local-lib"
    assert "package_sensitive_lifecycle_script" in finding_ids
    assert "dependency_external_or_local_source" in finding_ids
    assert "dependency_broad_range" in finding_ids
    assert payload["summary"]["total_dependencies"] == 4


@pytest.mark.anyio
async def test_analyze_manifest_requirements_detects_unpinned_and_custom_sources(monkeypatch, tmp_path):
    manifest_path = write_manifest(tmp_path, "requirements.txt", REQUIREMENTS_TXT)
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/manifest",
            json={"file_id": "f" * 32, "relative_path": str(manifest_path.relative_to(tmp_path)), "original_filename": "requirements.txt"},
        )

    assert response.status_code == 200
    payload = response.json()
    finding_ids = {finding["id"] for finding in payload["findings"]}
    assert payload["manifest_type"] == "requirements_txt"
    assert payload["summary"]["total_dependencies"] == 3
    dependencies = {item["name"]: item for item in payload["parsed"]["dependencies"]["dependencies"]}
    assert dependencies["fastapi"]["source_type"] == "registry"
    assert dependencies["demo"]["source_type"] == "editable"
    assert dependencies["demo"]["declared_requirement"].startswith("-e git+https://")
    assert "requirements_dependency_not_exactly_pinned" in finding_ids
    assert "requirements_editable_install" in finding_ids
    assert "requirements_custom_index" in finding_ids
    assert "dependency_external_or_local_source" in finding_ids


@pytest.mark.anyio
async def test_analyze_manifest_pyproject_extracts_dependencies_and_findings(monkeypatch, tmp_path):
    manifest_path = write_manifest(tmp_path, "pyproject.toml", PYPROJECT_TOML)
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/manifest",
            json={"file_id": "f" * 32, "relative_path": str(manifest_path.relative_to(tmp_path)), "original_filename": "pyproject.toml"},
        )

    assert response.status_code == 200
    payload = response.json()
    finding_ids = {finding["id"] for finding in payload["findings"]}
    assert payload["manifest_type"] == "pyproject_toml"
    assert payload["parsed"]["project"]["name"] == "demo-service"
    assert "optional:dev" in payload["parsed"]["dependencies"]
    assert "poetry:docs" in payload["parsed"]["dependencies"]
    dependencies = {item["name"]: item for item in payload["parsed"]["dependencies"]["dependencies"]}
    assert dependencies["fastapi"]["source_type"] == "registry"
    assert dependencies["demo"]["source_type"] == "vcs"
    assert dependencies["demo"]["declared_requirement"] == "demo @ git+https://example.invalid/demo.git"
    assert "dependency_not_exactly_pinned" in finding_ids
    assert "dependency_external_or_local_source" in finding_ids
    assert "dependency_broad_range" in finding_ids


@pytest.mark.anyio
async def test_analyze_manifest_rejects_path_traversal(monkeypatch, tmp_path):
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/manifest",
            json={"file_id": "f" * 32, "relative_path": "../package.json", "original_filename": "package.json"},
        )

    assert response.status_code == 400
    assert response.json()["detail"] == "Path escapes data directory."


@pytest.mark.anyio
async def test_analyze_archive_zip_reports_structure_and_indicators(monkeypatch, tmp_path):
    archive_path = write_zip_archive(
        tmp_path,
        {
            "src/app.py": b"print('hello')\n",
            "package.json": PACKAGE_JSON.encode("utf-8"),
            ".env": b"TOKEN=redacted\n",
            "nested/project.tar.gz": b"placeholder",
        },
    )
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/archive",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.zip"},
        )

    assert response.status_code == 200
    payload = response.json()
    finding_ids = {finding["id"] for finding in payload["findings"]}
    assert payload["analyzer"] == "archive_basic"
    assert payload["archive_type"] == "zip"
    assert payload["summary"]["total_entries"] == 4
    assert payload["summary"]["manifest_files_detected"] == 1
    assert payload["summary"]["sensitive_name_matches"] == 1
    assert payload["summary"]["nested_archives"] == 1
    assert payload["detected_manifests"][0]["path"] == "package.json"
    assert "archive_sensitive_name_entry" in finding_ids
    assert "archive_nested_archive_entry" in finding_ids
    assert payload["hashes"]["sha256"]


@pytest.mark.anyio
async def test_analyze_archive_zip_detects_path_traversal(monkeypatch, tmp_path):
    archive_path = write_zip_archive(tmp_path, {"../evil.txt": b"nope"})
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/archive",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.zip"},
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["summary"]["path_traversal_entries"] == 1
    assert {finding["id"] for finding in payload["findings"]} >= {"archive_path_traversal_entry"}
    assert payload["entries_sample"][0]["flags"]["path_traversal"] is True


@pytest.mark.anyio
async def test_analyze_archive_zip_preflight_truncates_entry_heavy_archive(monkeypatch, tmp_path):
    monkeypatch.setattr(runner, "ARCHIVE_MAX_ENTRIES", 3)
    monkeypatch.setattr(runner, "ARCHIVE_MAX_LISTED_ENTRIES", 2)
    archive_path = write_zip_archive(tmp_path, {f"files/{index}.txt": b"x" for index in range(5)})
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/archive",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.zip"},
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["summary"]["truncated"] is True
    assert payload["summary"]["zip_entries_declared"] == 5
    assert payload["entries_sample"] == []
    assert len(payload["entries_sample"]) <= 2
    assert "archive_zip_entry_limit_preflight" in {finding["id"] for finding in payload["findings"]}


@pytest.mark.anyio
async def test_analyze_archive_zip_preflight_blocks_large_central_directory(monkeypatch, tmp_path):
    monkeypatch.setattr(runner, "ARCHIVE_MAX_ZIP_CENTRAL_DIRECTORY_BYTES", 1)
    archive_path = write_zip_archive(tmp_path, {"README.md": b"hello\n"})
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/archive",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.zip"},
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["summary"]["truncated"] is True
    assert payload["summary"]["zip_central_directory_bytes"] > 1
    assert payload["entries_sample"] == []
    assert "archive_zip_central_directory_too_large" in {finding["id"] for finding in payload["findings"]}


@pytest.mark.anyio
async def test_analyze_archive_tar_reports_symlink(monkeypatch, tmp_path):
    archive_path = write_tar_archive(tmp_path)
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/archive",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.tar"},
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["archive_type"] == "tar"
    assert payload["summary"]["files"] == 1
    assert payload["summary"]["symlinks"] == 1
    assert "archive_symlink_entry" in {finding["id"] for finding in payload["findings"]}


@pytest.mark.anyio
async def test_analyze_archive_tar_respects_entry_limit(monkeypatch, tmp_path):
    monkeypatch.setattr(runner, "ARCHIVE_MAX_ENTRIES", 2)
    monkeypatch.setattr(runner, "ARCHIVE_MAX_LISTED_ENTRIES", 1)
    archive_path = write_tar_many_entries(tmp_path, 4)
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/archive",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.tar"},
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["archive_type"] == "tar"
    assert payload["summary"]["truncated"] is True
    assert payload["summary"]["total_entries"] == 2
    assert len(payload["entries_sample"]) == 1
    assert "archive_too_many_entries" in {finding["id"] for finding in payload["findings"]}


@pytest.mark.anyio
async def test_analyze_archive_handles_corrupt_file(monkeypatch, tmp_path):
    uploads_dir = tmp_path / "uploads"
    uploads_dir.mkdir()
    archive_path = uploads_dir / "broken.zip"
    archive_path.write_bytes(b"PK not really a zip")
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/archive",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "broken.zip"},
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["archive_type"] == "unknown"
    assert payload["errors"]
    assert payload["summary"]["total_entries"] == 0


@pytest.mark.anyio
async def test_analyze_project_archive_zip_parses_package_json(monkeypatch, tmp_path):
    archive_path = write_zip_archive(
        tmp_path,
        {
            "README.md": b"# ignored\n",
            "package.json": PACKAGE_JSON.encode("utf-8"),
            "package-lock.json": b"{}",
        },
    )
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/project-archive",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.zip"},
        )

    assert response.status_code == 200
    payload = response.json()
    finding_ids = {finding["id"] for finding in payload["findings"]}
    assert payload["analyzer"] == "project_archive_basic"
    assert payload["summary"]["supported_manifests_found"] == 1
    assert payload["summary"]["supported_manifests_parsed"] == 1
    assert payload["summary"]["unsupported_manifests_detected"] == 1
    assert payload["summary"]["total_dependencies"] == 4
    assert payload["parsed_manifests"][0]["manifest_type"] == "package_json"
    assert payload["parsed_manifests"][0]["parsed"]["project"]["name"] == "demo-app"
    assert "package_sensitive_lifecycle_script" in finding_ids
    assert "dependency_external_or_local_source" in finding_ids


@pytest.mark.anyio
async def test_analyze_project_archive_zip_preflight_respects_archive_entry_limit(monkeypatch, tmp_path):
    monkeypatch.setattr(runner, "PROJECT_ARCHIVE_MAX_ARCHIVE_ENTRIES", 2)
    archive_path = write_zip_archive(
        tmp_path,
        {
            "README.md": b"# ignored\n",
            "src/app.py": b"print('ignored')\n",
            "package.json": PACKAGE_JSON.encode("utf-8"),
        },
    )
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/project-archive",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.zip"},
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["summary"]["truncated"] is True
    assert payload["summary"]["total_entries_seen"] == 0
    assert payload["summary"]["zip_entries_declared"] == 3
    assert payload["summary"]["supported_manifests_parsed"] == 0
    assert "project_archive_zip_entry_limit_preflight" in {finding["id"] for finding in payload["findings"]}


@pytest.mark.anyio
async def test_analyze_project_archive_zip_parses_requirements(monkeypatch, tmp_path):
    archive_path = write_zip_archive(tmp_path, {"services/api/requirements.txt": REQUIREMENTS_TXT.encode("utf-8")})
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/project-archive",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.zip"},
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["parsed_manifests"][0]["manifest_type"] == "requirements_txt"
    assert payload["summary"]["total_dependencies"] == 3
    assert "requirements_custom_index" in {finding["id"] for finding in payload["findings"]}


@pytest.mark.anyio
async def test_analyze_project_archive_zip_parses_pyproject(monkeypatch, tmp_path):
    archive_path = write_zip_archive(tmp_path, {"pyproject.toml": PYPROJECT_TOML.encode("utf-8")})
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/project-archive",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.zip"},
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["parsed_manifests"][0]["manifest_type"] == "pyproject_toml"
    assert payload["parsed_manifests"][0]["parsed"]["project"]["name"] == "demo-service"
    assert "poetry:docs" in payload["parsed_manifests"][0]["parsed"]["dependencies"]


@pytest.mark.anyio
async def test_analyze_project_archive_tar_parses_manifest(monkeypatch, tmp_path):
    archive_path = write_tar_manifest_archive(tmp_path, "package.json", PACKAGE_JSON.encode("utf-8"))
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/project-archive",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.tar"},
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["archive_type"] == "tar"
    assert payload["summary"]["supported_manifests_parsed"] == 1
    assert payload["parsed_manifests"][0]["path"] == "package.json"


@pytest.mark.anyio
async def test_analyze_project_archive_skips_manifest_with_path_traversal(monkeypatch, tmp_path):
    archive_path = write_zip_archive(tmp_path, {"../package.json": PACKAGE_JSON.encode("utf-8")})
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/project-archive",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.zip"},
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["summary"]["supported_manifests_found"] == 1
    assert payload["summary"]["supported_manifests_parsed"] == 0
    assert payload["supported_manifests"][0]["reason"] == "path_traversal"
    assert "project_archive_path_traversal" in {finding["id"] for finding in payload["findings"]}


@pytest.mark.anyio
async def test_analyze_project_archive_skips_oversized_manifest(monkeypatch, tmp_path):
    monkeypatch.setattr(runner, "PROJECT_ARCHIVE_MAX_MANIFEST_BYTES", 20)
    archive_path = write_zip_archive(tmp_path, {"package.json": PACKAGE_JSON.encode("utf-8")})
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/project-archive",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.zip"},
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["summary"]["supported_manifests_parsed"] == 0
    assert payload["supported_manifests"][0]["reason"] == "manifest_too_large"
    assert "project_archive_manifest_too_large" in {finding["id"] for finding in payload["findings"]}


@pytest.mark.anyio
async def test_analyze_project_archive_handles_corrupt_file(monkeypatch, tmp_path):
    uploads_dir = tmp_path / "uploads"
    uploads_dir.mkdir()
    archive_path = uploads_dir / "broken.zip"
    archive_path.write_bytes(b"PK not really a zip")
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/project-archive",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "broken.zip"},
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["archive_type"] == "unknown"
    assert payload["errors"]
    assert payload["summary"]["supported_manifests_parsed"] == 0


@pytest.mark.anyio
async def test_analyze_django_config_zip_detects_settings_findings_and_redacts_secrets(monkeypatch, tmp_path):
    settings_text = b"""
DEBUG = True
SECRET_KEY = "supersecret-django-key"
ALLOWED_HOSTS = ["*"]
CORS_ALLOW_ALL_ORIGINS = True
CSRF_COOKIE_SECURE = False
SESSION_COOKIE_SECURE = False
DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "PASSWORD": "db-secret"}}
"""
    archive_path = write_zip_archive(tmp_path, {"project/settings.py": settings_text})
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/django-config",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.zip"},
        )

    payload = response.json()
    finding_ids = {finding["id"] for finding in payload["findings"]}
    serialized = json.dumps(payload)
    assert response.status_code == 200
    assert payload["analyzer"] == "django_config_basic"
    assert payload["summary"]["settings_files_detected"] == 1
    assert payload["summary"]["files_read"] == 1
    assert payload["summary"]["secrets_redacted_count"] >= 2
    assert "django_debug_enabled" in finding_ids
    assert "django_secret_key_hardcoded" in finding_ids
    assert "django_allowed_hosts_wildcard" in finding_ids
    assert "django_cors_allow_all" in finding_ids
    assert "django_database_password_hardcoded" in finding_ids
    assert "supersecret-django-key" not in serialized
    assert "db-secret" not in serialized
    assert "[REDACTED]" in serialized


@pytest.mark.anyio
async def test_analyze_django_config_detects_env_without_reading_and_deployment_signals(monkeypatch, tmp_path):
    archive_path = write_zip_archive(
        tmp_path,
        {
            ".env": b"SECRET_KEY=should-not-leak\n",
            ".env.example": b"DEBUG=False\n",
            "requirements.txt": b"Django==5.0.0\n",
            "Dockerfile": b'CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]\n',
            "docker-compose.yml": b'services:\n  db:\n    ports:\n      - "5432:5432"\n  web:\n    env_file: .env\n',
        },
    )
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/django-config",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.zip"},
        )

    payload = response.json()
    finding_ids = {finding["id"] for finding in payload["findings"]}
    env_record = next(item for item in payload["detected_files"] if item["path"] == ".env")
    assert response.status_code == 200
    assert env_record["read"] is False
    assert env_record["skip_reason"] == "sensitive_env_not_read"
    assert "should-not-leak" not in json.dumps(payload)
    assert "django_config_env_file_present" in finding_ids
    assert "django_deployment_runserver_detected" in finding_ids
    assert "django_compose_exposes_5432" in finding_ids
    assert payload["django_signals"]["deployment"]["django_dependency_detected"] == "true"


@pytest.mark.anyio
async def test_analyze_django_config_detects_env_variants_without_reading(monkeypatch, tmp_path):
    archive_path = write_zip_archive(
        tmp_path,
        {
            ".env.production": b"SECRET_KEY=prod-secret\n",
            ".env.prod": b"TOKEN=prod-token\n",
            ".env.local": b"DATABASE_URL=postgres://user:pass@db/app\n",
            ".envrc": b"export PASSWORD=envrc-secret\n",
            ".env.example": b"DEBUG=False\n",
            ".env.template": b"SECRET_KEY=template-secret\n",
            ".env.sample": b"TOKEN=sample-token\n",
            "env.example": b"PASSWORD=example-password\n",
        },
    )
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/django-config",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.zip"},
        )

    payload = response.json()
    records = {item["path"]: item for item in payload["detected_files"]}
    serialized = json.dumps(payload)
    assert response.status_code == 200
    for path in (".env.production", ".env.prod", ".env.local", ".envrc"):
        assert records[path]["category"] == "env_sensitive"
        assert records[path]["read"] is False
        assert records[path]["skip_reason"] == "sensitive_env_not_read"
    for path in (".env.example", ".env.template", ".env.sample", "env.example"):
        assert records[path]["category"] == "env_template"
        assert records[path]["read"] is True
    assert payload["summary"]["env_files_detected"] == 8
    for secret in ("prod-secret", "prod-token", "pass@db", "envrc-secret"):
        assert secret not in serialized


@pytest.mark.anyio
async def test_analyze_django_config_contextualizes_debug_and_ignores_comment_only(monkeypatch, tmp_path):
    archive_path = write_zip_archive(
        tmp_path,
        {
            "project/settings/production.py": b"DEBUG = True\n",
            "project/settings/dev.py": b"DEBUG = True\n",
            "project/settings/commented.py": b"# DEBUG=True\nDEBUG = False\n",
        },
    )
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/django-config",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.zip"},
        )

    payload = response.json()
    debug_findings = [finding for finding in payload["findings"] if finding["id"] == "django_debug_enabled"]
    production_finding = next(finding for finding in debug_findings if finding.get("file_path") == "project/settings/production.py")
    dev_finding = next(finding for finding in debug_findings if finding.get("file_path") == "project/settings/dev.py")

    assert response.status_code == 200
    assert production_finding["level"] == "medium"
    assert production_finding["context"] == "production"
    assert dev_finding["level"] == "info"
    assert dev_finding["context"] == "development"
    assert not any(finding.get("file_path") == "project/settings/commented.py" for finding in debug_findings)


@pytest.mark.anyio
async def test_analyze_django_config_groups_repeated_missing_setting_findings(monkeypatch, tmp_path):
    archive_path = write_zip_archive(
        tmp_path,
        {
            "project/settings/base.py": b"DEBUG = False\n",
            "project/settings/dev.py": b"DEBUG = False\n",
            "project/settings/test.py": b"DEBUG = False\n",
        },
    )
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/django-config",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.zip"},
        )

    payload = response.json()
    csrf_findings = [finding for finding in payload["findings"] if finding["id"] == "django_csrf_cookie_secure_not_true"]
    hsts_findings = [finding for finding in payload["findings"] if finding["id"] == "django_hsts_missing_or_zero"]

    assert response.status_code == 200
    assert len(csrf_findings) == 1
    assert len(hsts_findings) == 1
    assert csrf_findings[0]["context"] == "grouped"
    assert "project/settings/base.py" in csrf_findings[0]["evidence"]
    assert "project/settings/dev.py" in csrf_findings[0]["evidence"]
    assert "grouped across 3 inspected settings files" in csrf_findings[0]["description"]


@pytest.mark.anyio
async def test_analyze_django_config_skips_path_traversal(monkeypatch, tmp_path):
    archive_path = write_zip_archive(tmp_path, {"../settings.py": b"DEBUG=True\n"})
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/django-config",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.zip"},
        )

    payload = response.json()
    assert response.status_code == 200
    assert payload["detected_files"][0]["read"] is False
    assert payload["detected_files"][0]["skip_reason"] == "path_traversal"
    assert "django_config_path_traversal" in {finding["id"] for finding in payload["findings"]}


@pytest.mark.anyio
async def test_analyze_django_config_tar_skips_symlink_and_hardlink(monkeypatch, tmp_path):
    uploads_dir = tmp_path / "uploads"
    uploads_dir.mkdir(exist_ok=True)
    archive_path = uploads_dir / "project.tar"
    with tarfile.open(archive_path, "w") as archive:
        link_info = tarfile.TarInfo("settings.py")
        link_info.type = tarfile.SYMTYPE
        link_info.linkname = "real_settings.py"
        archive.addfile(link_info)

        hardlink_info = tarfile.TarInfo("config/settings/prod.py")
        hardlink_info.type = tarfile.LNKTYPE
        hardlink_info.linkname = "real_settings.py"
        archive.addfile(hardlink_info)

    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/django-config",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.tar"},
        )

    payload = response.json()
    assert response.status_code == 200
    assert {item["skip_reason"] for item in payload["detected_files"]} == {"not_regular_file:symlink", "not_regular_file:hardlink"}
    assert "django_config_not_regular_file" in {finding["id"] for finding in payload["findings"]}


@pytest.mark.anyio
async def test_analyze_django_config_respects_file_and_byte_limits(monkeypatch, tmp_path):
    monkeypatch.setattr(runner, "DJANGO_CONFIG_MAX_FILES", 1)
    monkeypatch.setattr(runner, "DJANGO_CONFIG_MAX_FILE_BYTES", 30)
    monkeypatch.setattr(runner, "DJANGO_CONFIG_MAX_TOTAL_BYTES", 40)
    archive_path = write_zip_archive(
        tmp_path,
        {
            "settings.py": b"DEBUG=False\n",
            "project/settings/prod.py": b"DEBUG=True\n",
            "project/settings/large.py": b"X = '" + b"a" * 80 + b"'\n",
        },
    )
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/django-config",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.zip"},
        )

    payload = response.json()
    reasons = {item.get("skip_reason") for item in payload["detected_files"]}
    assert response.status_code == 200
    assert payload["summary"]["files_read"] == 1
    assert payload["summary"]["truncated"] is True
    assert "too_many_files" in reasons
    assert "file_too_large" in reasons


@pytest.mark.anyio
async def test_analyze_django_config_treats_python_as_text_without_importing(monkeypatch, tmp_path):
    archive_path = write_zip_archive(
        tmp_path,
        {
            "project/settings.py": b"raise RuntimeError('would execute if imported')\nDEBUG = True\n",
        },
    )
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/django-config",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.zip"},
        )

    payload = response.json()
    assert response.status_code == 200
    assert payload["summary"]["files_read"] == 1
    assert "django_debug_enabled" in {finding["id"] for finding in payload["findings"]}
    assert payload["errors"] == []


@pytest.mark.anyio
async def test_analyze_docker_config_dockerfile_findings_ignore_comments(monkeypatch, tmp_path):
    archive_path = write_zip_archive(
        tmp_path,
        {
            "Dockerfile": b"""
# USER root
FROM python:latest
RUN curl -fsSL https://example.invalid/install.sh | sh
""",
        },
    )
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/docker-config",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.zip"},
        )

    payload = response.json()
    finding_ids = {finding["id"] for finding in payload["findings"]}
    assert response.status_code == 200
    assert payload["analyzer"] == "docker_config_basic"
    assert payload["summary"]["dockerfiles_detected"] == 1
    assert payload["summary"]["files_reviewed"] == 1
    assert "docker_missing_user_directive" in finding_ids
    assert "docker_latest_tag" in finding_ids
    assert "docker_suspicious_curl_pipe_shell" in finding_ids
    assert "docker_runs_as_root" not in finding_ids


@pytest.mark.anyio
async def test_analyze_docker_config_user_app_avoids_missing_user(monkeypatch, tmp_path):
    archive_path = write_zip_archive(tmp_path, {"Dockerfile": b"FROM python:3.12-slim\nUSER app\n"})
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/docker-config",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.zip"},
        )

    payload = response.json()
    assert response.status_code == 200
    assert "docker_missing_user_directive" not in {finding["id"] for finding in payload["findings"]}


@pytest.mark.anyio
async def test_analyze_docker_config_root_user_unpinned_and_context(monkeypatch, tmp_path):
    archive_path = write_zip_archive(tmp_path, {"deploy/prod/Dockerfile.prod": b"FROM python\nUSER root\n"})
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/docker-config",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.zip"},
        )

    payload = response.json()
    findings = {finding["id"]: finding for finding in payload["findings"]}
    assert response.status_code == 200
    assert findings["docker_runs_as_root"]["level"] == "medium"
    assert findings["docker_runs_as_root"]["context"] == "production"
    assert "docker_unpinned_base_image" in findings


@pytest.mark.anyio
async def test_analyze_docker_config_compose_findings_and_secret_redaction(monkeypatch, tmp_path):
    compose_text = b"""
services:
  web:
    privileged: true
    network_mode: host
    pid: host
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    env_file:
      - .env.production
    environment:
      SECRET_KEY: supersecret-value
      DATABASE_URL: postgres://user:rawpass@db/app
  db:
    ports:
      - "5432:5432"
"""
    archive_path = write_zip_archive(
        tmp_path,
        {
            "docker-compose.yml": compose_text,
            ".env.production": b"SECRET_KEY=should-not-be-read\n",
        },
    )
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/docker-config",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.zip"},
        )

    payload = response.json()
    finding_ids = {finding["id"] for finding in payload["findings"]}
    serialized = json.dumps(payload)
    assert response.status_code == 200
    assert payload["summary"]["compose_files_detected"] == 1
    assert payload["summary"]["services_detected"] == 2
    assert "docker_privileged_container" in finding_ids
    assert "docker_host_network" in finding_ids
    assert "docker_host_pid_or_ipc" in finding_ids
    assert "docker_socket_mount" in finding_ids
    assert "docker_published_database_port" in finding_ids
    assert "docker_env_file_real_reference" in finding_ids
    assert "docker_sensitive_env_name" in finding_ids
    assert "supersecret-value" not in serialized
    assert "rawpass" not in serialized
    assert "should-not-be-read" not in serialized
    assert "[REDACTED]" in serialized


@pytest.mark.anyio
async def test_analyze_docker_config_lower_confidence_context_degrades_severity(monkeypatch, tmp_path):
    archive_path = write_zip_archive(tmp_path, {"examples/Dockerfile": b"FROM python\nUSER root\n"})
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/docker-config",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.zip"},
        )

    payload = response.json()
    runs_as_root = next(finding for finding in payload["findings"] if finding["id"] == "docker_runs_as_root")
    unpinned = next(finding for finding in payload["findings"] if finding["id"] == "docker_unpinned_base_image")
    assert response.status_code == 200
    assert runs_as_root["context"] == "example"
    assert runs_as_root["level"] == "low"
    assert unpinned["level"] == "info"


@pytest.mark.anyio
async def test_analyze_docker_config_skips_path_traversal(monkeypatch, tmp_path):
    archive_path = write_zip_archive(tmp_path, {"../Dockerfile": b"FROM python:latest\n"})
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/docker-config",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.zip"},
        )

    payload = response.json()
    assert response.status_code == 200
    assert payload["files_detected"][0]["read"] is False
    assert payload["files_detected"][0]["skip_reason"] == "path_traversal"
    assert "docker_config_path_traversal" in {finding["id"] for finding in payload["findings"]}


@pytest.mark.anyio
async def test_analyze_docker_config_tar_skips_symlink_and_hardlink(monkeypatch, tmp_path):
    uploads_dir = tmp_path / "uploads"
    uploads_dir.mkdir(exist_ok=True)
    archive_path = uploads_dir / "project.tar"
    with tarfile.open(archive_path, "w") as archive:
        link_info = tarfile.TarInfo("Dockerfile")
        link_info.type = tarfile.SYMTYPE
        link_info.linkname = "real.Dockerfile"
        archive.addfile(link_info)

        hardlink_info = tarfile.TarInfo("compose.prod.yml")
        hardlink_info.type = tarfile.LNKTYPE
        hardlink_info.linkname = "real-compose.yml"
        archive.addfile(hardlink_info)

    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/docker-config",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.tar"},
        )

    payload = response.json()
    assert response.status_code == 200
    assert {item["skip_reason"] for item in payload["files_detected"]} == {"not_regular_file:symlink", "not_regular_file:hardlink"}
    assert "docker_config_not_regular_file" in {finding["id"] for finding in payload["findings"]}


@pytest.mark.anyio
async def test_analyze_docker_config_respects_file_and_byte_limits(monkeypatch, tmp_path):
    monkeypatch.setattr(runner, "DOCKER_CONFIG_MAX_FILES", 1)
    monkeypatch.setattr(runner, "DOCKER_CONFIG_MAX_FILE_BYTES", 40)
    monkeypatch.setattr(runner, "DOCKER_CONFIG_MAX_TOTAL_BYTES", 80)
    archive_path = write_zip_archive(
        tmp_path,
        {
            "Dockerfile": b"FROM python:3.12\n",
            "Dockerfile.large": b"FROM python:3.12\nRUN " + b"x" * 80 + b"\n",
            "docker-compose.yml": b"services:\n  web:\n    image: app\n",
        },
    )
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/docker-config",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.zip"},
        )

    payload = response.json()
    reasons = {item.get("skip_reason") for item in payload["files_detected"]}
    assert response.status_code == 200
    assert payload["summary"]["files_reviewed"] == 1
    assert payload["summary"]["truncated"] is True
    assert "file_too_large" in reasons
    assert "too_many_files" in reasons


@pytest.mark.anyio
async def test_analyze_web_basic_reports_http_headers_cookies_and_well_known_files():
    server = start_test_http_server()
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/web-basic",
            json={
                "url": f"http://127.0.0.1:{server.server_port}/",
                "allow_private_targets": True,
                "timeout_seconds": 2,
                "max_response_bytes": 4096,
                "max_redirects": 3,
                "allowed_ports": [80, 443, server.server_port],
            },
        )

    server.shutdown()
    payload = response.json()
    finding_ids = {finding["id"] for finding in payload["findings"]}
    assert response.status_code == 200
    assert payload["analyzer"] == "web_basic"
    assert payload["http"]["status_code"] == 200
    assert payload["http"]["server"]
    assert payload["cookies"][0]["name"] == "sid"
    assert payload["cookies"][0]["value_redacted"] is True
    assert payload["cookies"][0]["httponly"] is True
    assert payload["http"]["response_headers"]["Set-Cookie"] == "[redacted]"
    assert "supersecret" not in json.dumps(payload)
    assert payload["security_headers"]["Content-Security-Policy"]["present"] is False
    assert payload["robots_txt"]["present"] is True
    assert payload["security_txt"]["present"] is True
    assert payload["summary"]["cookies_count"] == 1
    assert "web_http_without_https" in finding_ids
    assert "web_csp_missing" in finding_ids


def test_web_query_redaction_helpers_preserve_safe_params_and_redact_sensitive_values():
    redacted = runner.redact_url_query("https://example.test/path?utm_source=news&api_key=secret%201&flag")

    assert "utm_source=news" in redacted
    assert "api_key=REDACTED" in redacted
    assert "secret" not in redacted


@pytest.mark.anyio
async def test_analyze_web_basic_redacts_sensitive_query_params_in_result():
    server = start_test_http_server()
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/web-basic",
            json={
                "url": f"http://127.0.0.1:{server.server_port}/?token=supersecret&page=1&Token=second",
                "allow_private_targets": True,
                "timeout_seconds": 2,
                "max_response_bytes": 4096,
                "max_redirects": 3,
                "allowed_ports": [80, 443, server.server_port],
            },
        )

    server.shutdown()
    payload = response.json()
    serialized = json.dumps(payload)
    assert response.status_code == 200
    assert "supersecret" not in serialized
    assert "second" not in serialized
    assert payload["target"]["original_url"].endswith("/?token=REDACTED&page=1&Token=REDACTED")
    assert payload["target"]["final_url"].endswith("/?token=REDACTED&page=1&Token=REDACTED")
    assert payload["target"]["query_string_present"] is True
    assert payload["target"]["query_params_redacted"] is True
    assert set(payload["target"]["redacted_query_params"]) == {"Token", "token"}
    assert payload["robots_txt"]["url"].endswith("/robots.txt")
    assert payload["security_txt"]["url"].endswith("/.well-known/security.txt")


@pytest.mark.anyio
async def test_analyze_web_basic_follows_redirects_and_stops_at_limit():
    server = start_test_http_server()
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        followed = await client.post(
            "/analyze/web-basic",
            json={
                "url": f"http://127.0.0.1:{server.server_port}/redirect",
                "allow_private_targets": True,
                "timeout_seconds": 2,
                "max_response_bytes": 4096,
                "max_redirects": 3,
                "allowed_ports": [80, 443, server.server_port],
            },
        )
        limited = await client.post(
            "/analyze/web-basic",
            json={
                "url": f"http://127.0.0.1:{server.server_port}/loop",
                "allow_private_targets": True,
                "timeout_seconds": 2,
                "max_response_bytes": 4096,
                "max_redirects": 1,
                "allowed_ports": [80, 443, server.server_port],
            },
        )

    server.shutdown()
    followed_payload = followed.json()
    limited_payload = limited.json()
    assert followed.status_code == 200
    assert followed_payload["target"]["final_url"].endswith("/final")
    assert followed_payload["summary"]["redirects_count"] == 1
    assert limited.status_code == 200
    assert limited_payload["summary"]["redirects_count"] == 1
    assert "web_redirect_limit_reached" in {finding["id"] for finding in limited_payload["findings"]}
    assert limited_payload["errors"]


@pytest.mark.anyio
async def test_analyze_web_basic_redacts_sensitive_query_params_in_redirects():
    server = start_test_http_server()
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/web-basic",
            json={
                "url": f"http://127.0.0.1:{server.server_port}/redirect-query",
                "allow_private_targets": True,
                "timeout_seconds": 2,
                "max_response_bytes": 4096,
                "max_redirects": 3,
                "allowed_ports": [80, 443, server.server_port],
            },
        )

    server.shutdown()
    payload = response.json()
    serialized = json.dumps(payload)
    assert response.status_code == 200
    assert "supersecret" not in serialized
    assert payload["http"]["redirects"][0]["to_url"].endswith("/final?token=REDACTED&page=1")
    assert payload["target"]["final_url"].endswith("/final?token=REDACTED&page=1")
    assert payload["target"]["query_params_redacted"] is True


@pytest.mark.anyio
async def test_analyze_web_basic_detects_redirect_loop():
    server = start_test_http_server()
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/web-basic",
            json={
                "url": f"http://127.0.0.1:{server.server_port}/loop",
                "allow_private_targets": True,
                "timeout_seconds": 2,
                "max_response_bytes": 4096,
                "max_redirects": 3,
                "allowed_ports": [80, 443, server.server_port],
            },
        )

    server.shutdown()
    payload = response.json()
    assert response.status_code == 200
    assert "web_redirect_loop_detected" in {finding["id"] for finding in payload["findings"]}
    assert payload["errors"]


@pytest.mark.anyio
async def test_analyze_web_basic_blocks_private_targets_by_default():
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/web-basic",
            json={"url": "http://127.0.0.1/", "allow_private_targets": False},
        )

    assert response.status_code == 400
    assert "blocked address range" in response.json()["detail"]


@pytest.mark.anyio
async def test_analyze_web_basic_enforces_allowed_ports(monkeypatch):
    public_ip = runner.ipaddress.ip_address("93.184.216.34")
    monkeypatch.setattr(runner, "resolve_web_host", lambda host, port: {public_ip})

    runner.validate_web_url_allowed("https://example.test", allow_private_targets=False, allowed_ports=(80, 443))
    runner.validate_web_url_allowed("http://example.test", allow_private_targets=False, allowed_ports=(80, 443))
    runner.validate_web_url_allowed("https://example.test:443", allow_private_targets=False, allowed_ports=(80, 443))
    runner.validate_web_url_allowed("http://example.test:80", allow_private_targets=False, allowed_ports=(80, 443))

    with pytest.raises(runner.HTTPException) as rejected:
        runner.validate_web_url_allowed("https://example.test:8443", allow_private_targets=False, allowed_ports=(80, 443))
    assert "port 8443 is not allowed" in rejected.value.detail

    runner.validate_web_url_allowed("https://example.test:8443", allow_private_targets=False, allowed_ports=(80, 443, 8443))


@pytest.mark.anyio
async def test_analyze_web_basic_blocks_localhost_metadata_and_private_targets(monkeypatch):
    with pytest.raises(runner.HTTPException) as localhost_rejected:
        runner.validate_web_url_allowed("http://localhost/", allow_private_targets=False, allowed_ports=(80, 443))
    with pytest.raises(runner.HTTPException) as loopback_rejected:
        runner.validate_web_url_allowed("http://[::1]/", allow_private_targets=False, allowed_ports=(80, 443))
    with pytest.raises(runner.HTTPException) as metadata_rejected:
        runner.validate_web_url_allowed("http://169.254.169.254/", allow_private_targets=True, allowed_ports=(80, 443))
    with pytest.raises(runner.HTTPException) as private_rejected:
        runner.validate_web_url_allowed("http://192.168.1.20/", allow_private_targets=False, allowed_ports=(80, 443))

    runner.validate_web_url_allowed("http://192.168.1.20/", allow_private_targets=True, allowed_ports=(80, 443))
    monkeypatch.setattr(runner, "resolve_web_host", lambda host, port: {runner.ipaddress.ip_address("192.168.1.20")})
    with pytest.raises(runner.HTTPException) as host_rejected:
        runner.validate_web_url_allowed("http://example.test/", allow_private_targets=False, allowed_ports=(80, 443))

    assert "loopback" in localhost_rejected.value.detail
    assert "loopback" in loopback_rejected.value.detail
    assert "cloud metadata" in metadata_rejected.value.detail
    assert "private address" in private_rejected.value.detail
    assert "private address" in host_rejected.value.detail


@pytest.mark.anyio
async def test_analyze_web_basic_blocks_private_redirect_target():
    server = start_test_http_server()
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/web-basic",
            json={
                "url": f"http://127.0.0.1:{server.server_port}/redirect-private",
                "allow_private_targets": True,
                "timeout_seconds": 2,
                "max_response_bytes": 4096,
                "max_redirects": 3,
                "allowed_ports": [80, 443, server.server_port],
            },
        )

    server.shutdown()
    assert response.status_code == 400
    assert "cloud metadata" in response.json()["detail"]


@pytest.mark.anyio
async def test_analyze_web_basic_blocks_unsafe_redirect_targets():
    server = start_test_http_server()
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        file_redirect = await client.post(
            "/analyze/web-basic",
            json={
                "url": f"http://127.0.0.1:{server.server_port}/redirect-file",
                "allow_private_targets": True,
                "timeout_seconds": 2,
                "max_response_bytes": 4096,
                "max_redirects": 3,
                "allowed_ports": [80, 443, server.server_port],
            },
        )
        port_redirect = await client.post(
            "/analyze/web-basic",
            json={
                "url": f"http://127.0.0.1:{server.server_port}/redirect-port",
                "allow_private_targets": True,
                "timeout_seconds": 2,
                "max_response_bytes": 4096,
                "max_redirects": 3,
                "allowed_ports": [80, 443, server.server_port],
            },
        )

    server.shutdown()
    assert file_redirect.status_code == 400
    assert "Only http and https" in file_redirect.json()["detail"]
    assert port_redirect.status_code == 400
    assert "port 8443 is not allowed" in port_redirect.json()["detail"]


@pytest.mark.anyio
async def test_analyze_web_basic_limits_response_bytes():
    server = start_test_http_server()
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/web-basic",
            json={
                "url": f"http://127.0.0.1:{server.server_port}/large",
                "allow_private_targets": True,
                "timeout_seconds": 2,
                "max_response_bytes": 32,
                "max_redirects": 1,
                "allowed_ports": [80, 443, server.server_port],
            },
        )

    server.shutdown()
    payload = response.json()
    assert response.status_code == 200
    assert payload["http"]["bytes_read"] == 32
    assert payload["http"]["response_truncated"] is True


@pytest.mark.anyio
async def test_analyze_domain_basic_reports_dns_and_email_security(monkeypatch):
    records = {
        ("example.com", "A"): (["93.184.216.34"], []),
        ("example.com", "AAAA"): (["2606:2800:220:1:248:1893:25c8:1946"], []),
        ("example.com", "CNAME"): ([], []),
        ("example.com", "MX"): ([{"preference": 10, "exchange": "mail.example.com"}], []),
        ("example.com", "NS"): (["ns1.example.com", "ns2.example.com"], []),
        ("example.com", "TXT"): (["v=spf1 include:_spf.example.com -all"], []),
        ("example.com", "CAA"): ([{"flags": 0, "tag": "issue", "value": "letsencrypt.org"}], []),
        ("example.com", "SOA"): ([{"mname": "ns1.example.com", "rname": "hostmaster.example.com", "serial": 1}], []),
        ("_dmarc.example.com", "TXT"): (["v=DMARC1; p=reject; rua=mailto:dmarc@example.com; pct=100"], []),
        ("www.example.com", "A"): (["93.184.216.34"], []),
        ("www.example.com", "AAAA"): ([], []),
        ("www.example.com", "CNAME"): ([], []),
    }
    monkeypatch.setattr(runner, "query_dns_record", lambda domain, record_type, timeout: records.get((domain, record_type), ([], [])))
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post("/analyze/domain-basic", json={"domain": "Example.COM", "timeout_seconds": 1})

    payload = response.json()
    assert response.status_code == 200
    assert payload["analyzer"] == "domain_basic"
    assert payload["target"]["normalized_domain"] == "example.com"
    assert payload["dns"]["A"] == ["93.184.216.34"]
    assert payload["email_security"]["spf"]["present"] is True
    assert payload["email_security"]["spf"]["all_mechanism"] == "-all"
    assert payload["email_security"]["dmarc"]["policy"] == "reject"
    assert payload["summary"]["mx_present"] is True
    assert payload["summary"]["www_resolves"] is True


@pytest.mark.anyio
async def test_analyze_domain_basic_generates_informational_findings(monkeypatch):
    records = {
        ("example.com", "A"): (["93.184.216.34"], []),
        ("example.com", "AAAA"): ([], []),
        ("example.com", "CNAME"): ([], []),
        ("example.com", "MX"): ([], []),
        ("example.com", "NS"): (["ns1.example-dns.com"], []),
        ("example.com", "TXT"): (["v=spf1 +all", "v=spf1 include:mail.example.com ?all", "api_key=[redacted]"], []),
        ("example.com", "CAA"): ([], []),
        ("example.com", "SOA"): ([], []),
        ("_dmarc.example.com", "TXT"): (["v=DMARC1; p=none; pct=50"], []),
        ("www.example.com", "A"): ([], []),
        ("www.example.com", "AAAA"): ([], []),
        ("www.example.com", "CNAME"): ([], []),
    }
    monkeypatch.setattr(runner, "query_dns_record", lambda domain, record_type, timeout: records.get((domain, record_type), ([], [])))
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post("/analyze/domain-basic", json={"domain": "example.com", "timeout_seconds": 1})

    payload = response.json()
    finding_ids = {finding["id"] for finding in payload["findings"]}
    assert response.status_code == 200
    assert "domain_single_nameserver" in finding_ids
    assert "domain_mx_absent" in finding_ids
    assert "domain_multiple_spf_records" in finding_ids
    assert "domain_spf_plus_all" in finding_ids
    assert "domain_dmarc_policy_none" in finding_ids
    assert "domain_dmarc_pct_partial" in finding_ids
    assert "domain_caa_absent" in finding_ids
    assert "domain_www_not_resolving" in finding_ids
    assert "domain_txt_sensitive_indicator" in finding_ids


@pytest.mark.anyio
async def test_analyze_domain_basic_reports_dmarc_absent_and_dns_errors(monkeypatch):
    def fake_query(domain: str, record_type: str, timeout: float):
        if domain == "_dmarc.example.com":
            return [], []
        if record_type == "A":
            return [], ["A query via 127.0.0.53 failed safely: TimeoutError."]
        return [], []

    monkeypatch.setattr(runner, "query_dns_record", fake_query)
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post("/analyze/domain-basic", json={"domain": "example.com", "timeout_seconds": 1})

    payload = response.json()
    assert response.status_code == 200
    assert "domain_dmarc_absent" in {finding["id"] for finding in payload["findings"]}
    assert payload["errors"]


def test_analyze_domain_basic_queries_www_baseline_without_duplication(monkeypatch):
    calls: list[tuple[str, str]] = []

    def fake_query(domain: str, record_type: str, timeout: float):
        calls.append((domain, record_type))
        if domain == "www.example.com" and record_type == "CNAME":
            return ["example.com"], []
        return [], []

    monkeypatch.setattr(runner, "query_dns_record", fake_query)

    payload = runner.analyze_domain_basic_target("example.com", timeout_seconds=1)

    assert payload["dns"]["www"]["checked"] is True
    assert payload["dns"]["www"]["domain"] == "www.example.com"
    assert ("www.example.com", "A") in calls
    assert ("www.example.com", "AAAA") in calls
    assert ("www.example.com", "CNAME") in calls


def test_analyze_domain_basic_skips_www_baseline_when_target_already_www(monkeypatch):
    calls: list[tuple[str, str]] = []

    def fake_query(domain: str, record_type: str, timeout: float):
        calls.append((domain, record_type))
        return [], []

    monkeypatch.setattr(runner, "query_dns_record", fake_query)

    payload = runner.analyze_domain_basic_target("www.example.com", timeout_seconds=1)

    assert payload["dns"]["www"] == {"checked": False, "reason": "Target domain already starts with www."}
    assert all(not domain.startswith("www.www.") for domain, _ in calls)
    assert ("_dmarc.www.example.com", "TXT") in calls


@pytest.mark.anyio
async def test_analyze_domain_basic_rejects_invalid_domain():
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        url_response = await client.post("/analyze/domain-basic", json={"domain": "https://example.com"})
        ip_response = await client.post("/analyze/domain-basic", json={"domain": "127.0.0.1"})
        local_response = await client.post("/analyze/domain-basic", json={"domain": "test.local"})

    assert url_response.status_code == 400
    assert ip_response.status_code == 400
    assert local_response.status_code == 400


@pytest.mark.anyio
async def test_analyze_subdomains_basic_normalizes_deduplicates_and_resolves(monkeypatch):
    calls: list[tuple[str, str]] = []
    records = {
        ("www.example.com", "A"): (["93.184.216.34"], []),
        ("www.example.com", "AAAA"): ([], []),
        ("www.example.com", "CNAME"): (["example.net"], []),
        ("api.example.com", "A"): ([], []),
        ("api.example.com", "AAAA"): ([], []),
        ("api.example.com", "CNAME"): ([], []),
    }

    def fake_query(domain: str, record_type: str, timeout: float):
        calls.append((domain, record_type))
        return records.get((domain, record_type), ([], []))

    monkeypatch.setattr(runner, "query_dns_record", fake_query)
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/subdomains-basic",
            json={
                "root_domain": "Example.COM",
                "subdomains": ["www", "WWW.example.com", "api.example.com"],
                "timeout_seconds": 1,
                "wildcard_checks": 0,
            },
        )

    payload = response.json()
    assert response.status_code == 200
    assert payload["analyzer"] == "subdomain_inventory_basic"
    assert payload["target"]["normalized_root_domain"] == "example.com"
    assert payload["summary"]["candidates_submitted"] == 3
    assert payload["summary"]["candidates_accepted"] == 2
    assert payload["summary"]["candidates_rejected"] == 1
    assert payload["summary"]["resolved_count"] == 1
    assert payload["summary"]["cname_count"] == 1
    assert payload["summary"]["truncated"] is False
    assert payload["summary"]["deadline_reached"] is False
    assert payload["limits"]["global_deadline_seconds"] == runner.SUBDOMAIN_GLOBAL_DEADLINE_SECONDS
    assert payload["wildcard_dns"]["checked"] is False
    assert {candidate["status"] for candidate in payload["candidates"]} == {"accepted", "rejected"}
    assert {result["fqdn"] for result in payload["results"]} == {"www.example.com", "api.example.com"}
    assert "subdomain_duplicate_candidate" in {finding["id"] for finding in payload["findings"]}
    assert "subdomain_external_cname" in {finding["id"] for finding in payload["findings"]}
    assert all(not domain.startswith("inspectra-wildcard-") for domain, _ in calls)


@pytest.mark.anyio
async def test_analyze_subdomains_basic_rejects_out_of_scope_candidates(monkeypatch):
    calls: list[tuple[str, str]] = []

    def fake_query(domain: str, record_type: str, timeout: float):
        calls.append((domain, record_type))
        return [], []

    monkeypatch.setattr(runner, "query_dns_record", fake_query)
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/subdomains-basic",
            json={
                "root_domain": "example.com",
                "subdomains": ["api.evil.com", "*.example.com", "https://api.example.com", "api.example.com.", "example.com", "127.0.0.1"],
                "timeout_seconds": 1,
                "wildcard_checks": 0,
            },
        )

    payload = response.json()
    assert response.status_code == 200
    assert payload["summary"]["candidates_accepted"] == 0
    assert payload["summary"]["candidates_rejected"] == 6
    assert all(candidate["status"] == "rejected" for candidate in payload["candidates"])
    assert "subdomain_candidate_rejected" in {finding["id"] for finding in payload["findings"]}
    assert calls == []


@pytest.mark.anyio
async def test_analyze_subdomains_basic_detects_private_ips_and_dns_errors(monkeypatch):
    def fake_query(domain: str, record_type: str, timeout: float):
        if record_type == "A":
            return ["192.168.1.10"], []
        if record_type == "AAAA":
            return [], ["AAAA query via 127.0.0.53 failed safely: TimeoutError."]
        return [], []

    monkeypatch.setattr(runner, "query_dns_record", fake_query)
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/subdomains-basic",
            json={"root_domain": "example.com", "subdomains": ["admin"], "timeout_seconds": 1, "wildcard_checks": 0},
        )

    payload = response.json()
    assert response.status_code == 200
    assert payload["summary"]["private_ip_count"] == 1
    assert payload["results"][0]["private_or_reserved_ip_detected"] is True
    assert payload["errors"]
    assert "subdomain_private_or_reserved_ip" in {finding["id"] for finding in payload["findings"]}


@pytest.mark.anyio
@pytest.mark.parametrize("ipv6_address", ["::1", "fc00::1", "fe80::1", "ff02::1", "::", "2001:db8::1"])
async def test_analyze_subdomains_basic_detects_private_or_reserved_ipv6(monkeypatch, ipv6_address):
    def fake_query(domain: str, record_type: str, timeout: float):
        if record_type == "AAAA":
            return [ipv6_address], []
        return [], []

    monkeypatch.setattr(runner, "query_dns_record", fake_query)
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/subdomains-basic",
            json={"root_domain": "example.com", "subdomains": ["admin"], "timeout_seconds": 1, "wildcard_checks": 0},
        )

    payload = response.json()
    finding = next(finding for finding in payload["findings"] if finding["id"] == "subdomain_private_or_reserved_ip")
    assert response.status_code == 200
    assert payload["results"][0]["private_or_reserved_ip_detected"] is True
    assert finding["level"] == "low"
    assert "vulnerability" not in json.dumps(payload).lower()


@pytest.mark.anyio
async def test_analyze_subdomains_basic_external_cname_handles_trailing_dot_and_case(monkeypatch):
    def fake_query(domain: str, record_type: str, timeout: float):
        if domain == "internal.example.com" and record_type == "CNAME":
            return ["Target.Example.COM."], []
        if domain == "external.example.com" and record_type == "CNAME":
            return ["app.External-Provider.COM."], []
        return [], []

    monkeypatch.setattr(runner, "query_dns_record", fake_query)
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/subdomains-basic",
            json={
                "root_domain": "example.com",
                "subdomains": ["internal", "external"],
                "timeout_seconds": 1,
                "wildcard_checks": 0,
            },
        )

    payload = response.json()
    findings = [finding for finding in payload["findings"] if finding["id"] == "subdomain_external_cname"]
    results = {result["fqdn"]: result for result in payload["results"]}
    assert response.status_code == 200
    assert "external_cname_detected" not in results["internal.example.com"]
    assert results["external.example.com"]["external_cname_detected"] is True
    assert len(findings) == 1
    assert "app.External-Provider.COM." in findings[0]["evidence"]


@pytest.mark.anyio
async def test_analyze_subdomains_basic_global_deadline_returns_partial_result(monkeypatch):
    class FakeClock:
        def __init__(self) -> None:
            self.value = 0.0

        def monotonic(self) -> float:
            return self.value

        def advance(self, seconds: float) -> None:
            self.value += seconds

    clock = FakeClock()
    calls: list[tuple[str, str]] = []

    def fake_query(domain: str, record_type: str, timeout: float):
        calls.append((domain, record_type))
        if domain == "www.example.com" and record_type == "A":
            clock.advance(2.0)
            return ["93.184.216.34"], []
        return [], []

    monkeypatch.setattr(runner.time, "monotonic", clock.monotonic)
    monkeypatch.setattr(runner, "query_dns_record", fake_query)
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/subdomains-basic",
            json={
                "root_domain": "example.com",
                "subdomains": ["www", "api", "cdn"],
                "timeout_seconds": 1,
                "wildcard_checks": 2,
                "global_deadline_seconds": 1,
            },
        )

    payload = response.json()
    assert response.status_code == 200
    assert payload["summary"]["truncated"] is True
    assert payload["summary"]["deadline_reached"] is True
    assert payload["summary"]["candidates_processed"] == 1
    assert payload["summary"]["candidates_pending"] == 2
    assert payload["limits"]["global_deadline_seconds"] == 1
    assert payload["wildcard_dns"]["checked"] is False
    assert payload["wildcard_dns"]["skipped_reason"] == "global_deadline_reached"
    assert {result["fqdn"]: result["status"] for result in payload["results"]} == {
        "www.example.com": "partial",
        "api.example.com": "skipped",
        "cdn.example.com": "skipped",
    }
    assert "subdomain_global_deadline_reached" in {finding["id"] for finding in payload["findings"]}
    assert calls == [("www.example.com", "A")]


@pytest.mark.anyio
async def test_analyze_subdomains_basic_global_deadline_cuts_wildcard_probe(monkeypatch):
    class FakeClock:
        def __init__(self) -> None:
            self.value = 0.0

        def monotonic(self) -> float:
            return self.value

        def advance(self, seconds: float) -> None:
            self.value += seconds

    clock = FakeClock()
    calls: list[tuple[str, str]] = []

    def fake_query(domain: str, record_type: str, timeout: float):
        calls.append((domain, record_type))
        if domain.startswith("inspectra-wildcard-") and record_type == "A":
            clock.advance(2.0)
            return ["93.184.216.34"], []
        return [], []

    monkeypatch.setattr(runner.time, "monotonic", clock.monotonic)
    monkeypatch.setattr(runner, "query_dns_record", fake_query)
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/subdomains-basic",
            json={
                "root_domain": "example.com",
                "subdomains": ["www"],
                "timeout_seconds": 1,
                "wildcard_checks": 2,
                "global_deadline_seconds": 1,
            },
        )

    payload = response.json()
    wildcard_calls = [call for call in calls if call[0].startswith("inspectra-wildcard-")]
    assert response.status_code == 200
    assert payload["summary"]["truncated"] is True
    assert payload["summary"]["deadline_reached"] is True
    assert payload["wildcard_dns"]["checked"] is True
    assert payload["wildcard_dns"]["partial"] is True
    assert payload["wildcard_dns"]["deadline_reached"] is True
    assert len(wildcard_calls) == 1


@pytest.mark.anyio
async def test_analyze_subdomains_basic_reports_wildcard_dns_possible(monkeypatch):
    def fake_query(domain: str, record_type: str, timeout: float):
        if domain.startswith("inspectra-wildcard-") and record_type == "A":
            return ["93.184.216.34"], []
        return [], []

    monkeypatch.setattr(runner, "query_dns_record", fake_query)
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/subdomains-basic",
            json={"root_domain": "example.com", "subdomains": ["www"], "timeout_seconds": 1, "wildcard_checks": 2},
        )

    payload = response.json()
    assert response.status_code == 200
    assert payload["wildcard_dns"]["checked"] is True
    assert payload["wildcard_dns"]["possible"] is True
    assert payload["wildcard_dns"]["probes_count"] == 2
    assert "subdomain_wildcard_dns_possible" in {finding["id"] for finding in payload["findings"]}


@pytest.mark.anyio
async def test_analyze_subdomains_basic_reports_wildcard_dns_not_possible(monkeypatch):
    monkeypatch.setattr(runner, "query_dns_record", lambda domain, record_type, timeout: ([], []))
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/subdomains-basic",
            json={"root_domain": "example.com", "subdomains": ["www"], "timeout_seconds": 1, "wildcard_checks": 2},
        )

    payload = response.json()
    assert response.status_code == 200
    assert payload["wildcard_dns"]["checked"] is True
    assert payload["wildcard_dns"]["possible"] is False
    assert payload["summary"]["wildcard_dns_possible"] is False


@pytest.mark.anyio
async def test_analyze_subdomains_basic_respects_max_candidates():
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/subdomains-basic",
            json={"root_domain": "example.com", "subdomains": ["www", "api"], "max_candidates": 1, "wildcard_checks": 0},
        )
        deadline_response = await client.post(
            "/analyze/subdomains-basic",
            json={"root_domain": "example.com", "subdomains": ["www"], "global_deadline_seconds": 0},
        )

    assert response.status_code == 400
    assert "Too many subdomain candidates" in response.json()["detail"]
    assert deadline_response.status_code == 400
    assert "global deadline" in deadline_response.json()["detail"]


def test_parse_dns_nameserver_lines_is_ipv4_only_and_bounded():
    lines = [
        "# comment",
        "search example.test",
        "nameserver 192.0.2.1",
        "nameserver 2001:db8::1",
        "nameserver not-an-ip",
        "nameserver 198.51.100.2",
        "nameserver 203.0.113.3",
        "nameserver 203.0.113.4",
    ]

    assert runner.parse_dns_nameserver_lines(lines) == ["192.0.2.1", "198.51.100.2", "203.0.113.3"]
    assert runner.parse_dns_nameserver_lines([]) == []
    assert runner.parse_dns_nameserver_lines(["nameserver 2001:db8::1"]) == []


def test_query_dns_record_reports_no_nameservers(monkeypatch):
    monkeypatch.setattr(runner, "dns_nameservers", lambda: [])

    records, errors = runner.query_dns_record("example.com", "A", 1)

    assert records == []
    assert errors == ["No DNS nameservers were configured for the runner."]


def test_runner_normalize_domain_validation_edges():
    assert runner.normalize_domain("WWW.Example.COM") == "www.example.com"
    assert runner.normalize_domain("täst.example") == "xn--tst-qla.example"

    invalid_domains = [
        "http://example.com",
        "example.com/path",
        "example.com?x=1",
        "example.com#fragment",
        "user:pass@example.com",
        "exa mple.com",
        "::1",
        "localhost",
        "test.internal",
        "example..com",
        f"{'a' * 64}.example",
    ]
    for raw_domain in invalid_domains:
        with pytest.raises(Exception):
            runner.normalize_domain(raw_domain)


def test_parse_dns_response_decodes_core_record_types():
    a_records, a_truncated = runner.parse_dns_response(
        make_dns_response(runner.DNS_RECORD_TYPES["A"], bytes([93, 184, 216, 34])),
        DNS_TEST_QUERY_ID,
        runner.DNS_RECORD_TYPES["A"],
    )
    aaaa_records, _ = runner.parse_dns_response(
        make_dns_response(runner.DNS_RECORD_TYPES["AAAA"], bytes.fromhex("20010db8000000000000000000000001")),
        DNS_TEST_QUERY_ID,
        runner.DNS_RECORD_TYPES["AAAA"],
    )
    mx_records, _ = runner.parse_dns_response(
        make_dns_response(runner.DNS_RECORD_TYPES["MX"], struct.pack("!H", 10) + dns_name("mail.example.com")),
        DNS_TEST_QUERY_ID,
        runner.DNS_RECORD_TYPES["MX"],
    )
    caa_records, _ = runner.parse_dns_response(
        make_dns_response(runner.DNS_RECORD_TYPES["CAA"], b"\x00\x05issueletsencrypt.org"),
        DNS_TEST_QUERY_ID,
        runner.DNS_RECORD_TYPES["CAA"],
    )
    soa_records, _ = runner.parse_dns_response(
        make_dns_response(
            runner.DNS_RECORD_TYPES["SOA"],
            dns_name("ns1.example.com") + dns_name("hostmaster.example.com") + struct.pack("!IIIII", 1, 3600, 600, 86400, 300),
        ),
        DNS_TEST_QUERY_ID,
        runner.DNS_RECORD_TYPES["SOA"],
    )

    assert a_records == ["93.184.216.34"]
    assert a_truncated is False
    assert aaaa_records == ["2001:db8::1"]
    assert mx_records == [{"preference": 10, "exchange": "mail.example.com"}]
    assert caa_records == [{"flags": 0, "tag": "issue", "value": "letsencrypt.org"}]
    assert soa_records == [
        {
            "mname": "ns1.example.com",
            "rname": "hostmaster.example.com",
            "serial": 1,
            "refresh": 3600,
            "retry": 600,
            "expire": 86400,
            "minimum": 300,
        }
    ]


def test_parse_dns_response_handles_txt_chunks_redaction_and_truncation():
    txt_records, _ = runner.parse_dns_response(
        make_dns_response(runner.DNS_RECORD_TYPES["TXT"], dns_txt_chunks(["hello ", "token=supersecret", " end"])),
        DNS_TEST_QUERY_ID,
        runner.DNS_RECORD_TYPES["TXT"],
    )
    long_txt_records, _ = runner.parse_dns_response(
        make_dns_response(runner.DNS_RECORD_TYPES["TXT"], dns_txt_chunks(["a" * 255, "b" * 255, "c" * 255])),
        DNS_TEST_QUERY_ID,
        runner.DNS_RECORD_TYPES["TXT"],
    )

    assert txt_records == ["hello token=[redacted] end"]
    assert "supersecret" not in txt_records[0]
    assert len(long_txt_records[0]) <= runner.DNS_MAX_STRING_LENGTH
    assert long_txt_records[0].endswith("...[truncated]")


def test_parse_dns_response_handles_compression_truncation_and_rcodes():
    cname_records, _ = runner.parse_dns_response(
        make_dns_response(runner.DNS_RECORD_TYPES["CNAME"], b"\xc0\x0c"),
        DNS_TEST_QUERY_ID,
        runner.DNS_RECORD_TYPES["CNAME"],
    )
    nx_records, nx_truncated = runner.parse_dns_response(
        make_dns_response(runner.DNS_RECORD_TYPES["A"], None, flags=0x8183),
        DNS_TEST_QUERY_ID,
        runner.DNS_RECORD_TYPES["A"],
    )
    _, truncated = runner.parse_dns_response(
        make_dns_response(runner.DNS_RECORD_TYPES["A"], bytes([93, 184, 216, 34]), flags=0x8380),
        DNS_TEST_QUERY_ID,
        runner.DNS_RECORD_TYPES["A"],
    )

    assert cname_records == ["example.com"]
    assert nx_records == []
    assert nx_truncated is False
    assert truncated is True
    with pytest.raises(ValueError, match="DNS response code 2"):
        runner.parse_dns_response(make_dns_response(runner.DNS_RECORD_TYPES["A"], None, flags=0x8182), DNS_TEST_QUERY_ID, runner.DNS_RECORD_TYPES["A"])


def test_parse_dns_response_rejects_malformed_packets():
    question = dns_name("example.com") + struct.pack("!HH", runner.DNS_RECORD_TYPES["A"], 1)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", runner.DNS_RECORD_TYPES["A"], 1, 60, 4) + b"\x01\x02"
    malformed = struct.pack("!HHHHHH", DNS_TEST_QUERY_ID, 0x8180, 1, 1, 0, 0) + question + answer

    with pytest.raises(ValueError, match="too short"):
        runner.parse_dns_response(b"\x00", DNS_TEST_QUERY_ID, runner.DNS_RECORD_TYPES["A"])
    with pytest.raises(ValueError, match="rdata exceeds"):
        runner.parse_dns_response(malformed, DNS_TEST_QUERY_ID, runner.DNS_RECORD_TYPES["A"])


DNS_TEST_QUERY_ID = 0xBEEF


def dns_name(name: str) -> bytes:
    return b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.rstrip(".").split(".")) + b"\x00"


def dns_txt_chunks(chunks: list[str]) -> bytes:
    return b"".join(bytes([len(chunk.encode("utf-8"))]) + chunk.encode("utf-8") for chunk in chunks)


def make_dns_response(qtype: int, rdata: bytes | None, *, flags: int = 0x8180) -> bytes:
    question = dns_name("example.com") + struct.pack("!HH", qtype, 1)
    answer = b""
    if rdata is not None:
        answer = b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, 60, len(rdata)) + rdata
    return struct.pack("!HHHHHH", DNS_TEST_QUERY_ID, flags, 1, 1 if rdata is not None else 0, 0, 0) + question + answer


def test_web_tls_certificate_summary_parses_dates():
    cert = {
        "subject": ((("commonName", "example.test"),),),
        "issuer": ((("organizationName", "Inspectra Test CA"),),),
        "notBefore": "May  1 00:00:00 2026 GMT",
        "notAfter": "Jun  1 00:00:00 2026 GMT",
        "subjectAltName": (("DNS", "example.test"),),
    }

    summary = runner.summarize_certificate(cert)

    assert summary["subject"]["commonName"] == "example.test"
    assert summary["issuer"]["organizationName"] == "Inspectra Test CA"
    assert summary["not_before"].startswith("2026-05-01")
    assert summary["not_after"].startswith("2026-06-01")
    assert summary["subject_alt_names"] == ["example.test"]


def write_manifest(tmp_path, filename: str, content: str):
    uploads_dir = tmp_path / "uploads"
    uploads_dir.mkdir(exist_ok=True)
    manifest_path = uploads_dir / filename
    manifest_path.write_text(content, encoding="utf-8")
    return manifest_path


class LocalWebHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/final")
            self.end_headers()
            return
        if self.path == "/redirect-query":
            self.send_response(302)
            self.send_header("Location", "/final?token=supersecret&page=1")
            self.end_headers()
            return
        if self.path == "/loop":
            self.send_response(302)
            self.send_header("Location", "/loop2")
            self.end_headers()
            return
        if self.path == "/loop2":
            self.send_response(302)
            self.send_header("Location", "/loop")
            self.end_headers()
            return
        if self.path == "/redirect-private":
            self.send_response(302)
            self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
            self.end_headers()
            return
        if self.path == "/redirect-localhost":
            self.send_response(302)
            self.send_header("Location", "http://localhost/")
            self.end_headers()
            return
        if self.path == "/redirect-file":
            self.send_response(302)
            self.send_header("Location", "file:///etc/passwd")
            self.end_headers()
            return
        if self.path == "/redirect-port":
            self.send_response(302)
            self.send_header("Location", "https://example.test:8443/")
            self.end_headers()
            return
        if self.path == "/robots.txt":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"User-agent: *\nDisallow: /admin\nSitemap: /sitemap.xml\n")
            return
        if self.path == "/.well-known/security.txt":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Contact: mailto:security@example.test\nExpires: 2027-01-01T00:00:00Z\n")
            return
        if self.path == "/security.txt":
            self.send_response(404)
            self.end_headers()
            return
        if self.path == "/large":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"x" * 128)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Server", "InspectraTest")
        self.send_header("Set-Cookie", "sid=supersecret; HttpOnly; SameSite=Lax; Path=/")
        self.end_headers()
        self.wfile.write(b"<html><title>Inspectra</title></html>")

    def log_message(self, format, *args):
        return


def start_test_http_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), LocalWebHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def write_zip_archive(tmp_path, entries: dict[str, bytes]):
    uploads_dir = tmp_path / "uploads"
    uploads_dir.mkdir(exist_ok=True)
    archive_path = uploads_dir / "project.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return archive_path


def write_tar_archive(tmp_path):
    uploads_dir = tmp_path / "uploads"
    uploads_dir.mkdir(exist_ok=True)
    archive_path = uploads_dir / "project.tar"
    with tarfile.open(archive_path, "w") as archive:
        content = b"hello\n"
        file_info = tarfile.TarInfo("README.md")
        file_info.size = len(content)
        file_info.mode = 0o644
        archive.addfile(file_info, io.BytesIO(content))

        link_info = tarfile.TarInfo("latest-readme")
        link_info.type = tarfile.SYMTYPE
        link_info.linkname = "README.md"
        link_info.mode = 0o777
        archive.addfile(link_info)
    return archive_path


def write_tar_many_entries(tmp_path, count: int):
    uploads_dir = tmp_path / "uploads"
    uploads_dir.mkdir(exist_ok=True)
    archive_path = uploads_dir / "project.tar"
    with tarfile.open(archive_path, "w") as archive:
        for index in range(count):
            content = b"x\n"
            file_info = tarfile.TarInfo(f"files/{index}.txt")
            file_info.size = len(content)
            file_info.mode = 0o644
            archive.addfile(file_info, io.BytesIO(content))
    return archive_path


def write_tar_manifest_archive(tmp_path, filename: str, content: bytes):
    uploads_dir = tmp_path / "uploads"
    uploads_dir.mkdir(exist_ok=True)
    archive_path = uploads_dir / "project.tar"
    with tarfile.open(archive_path, "w") as archive:
        file_info = tarfile.TarInfo(filename)
        file_info.size = len(content)
        file_info.mode = 0o644
        archive.addfile(file_info, io.BytesIO(content))
    return archive_path


def fake_image_command(args: list[str]) -> dict:
    stdout = ""
    if args[0] == "file" and "--mime-type" in args:
        stdout = "image/png\n"
    elif args[0] == "file":
        stdout = "PNG image data, 1 x 1, 8-bit/color RGB\n"
    elif args[0] == "exiftool":
        stdout = '[{"ImageWidth":1,"ImageHeight":1,"MIMEType":"image/png","GPSLatitude":40.0,"Software":"unit-test"}]'

    return {
        "command": args[0],
        "args": args[1:-1],
        "exit_code": 0,
        "duration_ms": 1.0,
        "stdout": stdout,
        "stderr": "",
        "timed_out": False,
        "timeout_seconds": runner.COMMAND_TIMEOUT_SECONDS,
    }
