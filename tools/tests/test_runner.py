import io
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
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
    assert payload["cookies"][0]["httponly"] is True
    assert payload["security_headers"]["Content-Security-Policy"]["present"] is False
    assert payload["robots_txt"]["present"] is True
    assert payload["security_txt"]["present"] is True
    assert payload["summary"]["cookies_count"] == 1
    assert "web_http_without_https" in finding_ids
    assert "web_csp_missing" in finding_ids


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
async def test_analyze_web_basic_blocks_private_targets_by_default():
    transport = ASGITransport(app=runner.app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/analyze/web-basic",
            json={"url": "http://127.0.0.1:8080/", "allow_private_targets": False},
        )

    assert response.status_code == 400
    assert "blocked address range" in response.json()["detail"]


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
            },
        )

    server.shutdown()
    assert response.status_code == 400
    assert "cloud metadata" in response.json()["detail"]


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
            },
        )

    server.shutdown()
    payload = response.json()
    assert response.status_code == 200
    assert payload["http"]["bytes_read"] == 32
    assert payload["http"]["response_truncated"] is True


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
        self.send_header("Set-Cookie", "sid=abc; HttpOnly; SameSite=Lax; Path=/")
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
