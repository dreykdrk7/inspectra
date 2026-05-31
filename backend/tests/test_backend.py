from datetime import datetime, timedelta, timezone
import io
import json
import tarfile
import threading
from xml.etree import ElementTree
import zipfile

import pytest
from fastapi import HTTPException
from httpx import ASGITransport, AsyncClient

from app.config import load_settings
from app.domain_security import normalize_domain, normalize_subdomain_candidate
from app.main import app
from app.models import JobRecord
from app.reporting import markdown_block_value, markdown_inline_value
from app.sbom import extract_components_from_job, generate_cyclonedx_json, generate_spdx_json
from app.services import (
    ArchiveAuditService,
    DjangoConfigAuditService,
    DomainAuditService,
    ImageAuditService,
    ManifestAuditService,
    PdfAuditService,
    ProjectArchiveAuditService,
    SubdomainInventoryAuditService,
    WebAuditService,
    calculate_domain_runner_timeout_seconds,
    calculate_subdomain_inventory_runner_timeout_seconds,
)
from app.storage import FileStore, JobStore
from app import web_security


SAMPLE_PNG = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde"
SAMPLE_PACKAGE_JSON = b'{"name":"demo","version":"1.0.0","dependencies":{"react":"^18.3.1"}}'
SAMPLE_REQUIREMENTS = b"fastapi==0.115.0\nhttpx>=0.27\n"
SAMPLE_PYPROJECT = b'[project]\nname = "demo"\nversion = "1.0.0"\ndependencies = ["fastapi>=0.115"]\n'


class NoopAuditService:
    async def run_pdf_analysis(self, job_id: str) -> None:
        return None

    async def run_image_analysis(self, job_id: str) -> None:
        return None

    async def run_manifest_analysis(self, job_id: str) -> None:
        return None

    async def run_archive_analysis(self, job_id: str) -> None:
        return None

    async def run_project_archive_analysis(self, job_id: str) -> None:
        return None

    async def run_django_config_analysis(self, job_id: str) -> None:
        return None

    async def run_web_analysis(self, job_id: str, request_url: str | None = None) -> None:
        return None

    async def run_domain_analysis(self, job_id: str) -> None:
        return None

    async def run_subdomain_inventory_analysis(self, job_id: str, candidates: list[str] | None = None) -> None:
        return None


class CapturingWebAuditService:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str | None]] = []

    async def run_web_analysis(self, job_id: str, request_url: str | None = None) -> None:
        self.calls.append((job_id, request_url))


class CapturingSubdomainInventoryAuditService:
    def __init__(self) -> None:
        self.calls: list[tuple[str, list[str] | None]] = []

    async def run_subdomain_inventory_analysis(self, job_id: str, candidates: list[str] | None = None) -> None:
        self.calls.append((job_id, candidates))


def configure_test_state(monkeypatch, tmp_path, max_upload_bytes=None):
    monkeypatch.setenv("INSPECTRA_DATA_DIR", str(tmp_path))
    if max_upload_bytes is not None:
        monkeypatch.setenv("INSPECTRA_MAX_UPLOAD_BYTES", str(max_upload_bytes))
    settings = load_settings()
    settings.ensure_directories()
    file_store = FileStore(settings)
    job_store = JobStore(settings)
    app.state.settings = settings
    app.state.files = file_store
    app.state.jobs = job_store
    app.state.pdf_audits = PdfAuditService(settings, file_store, job_store)
    app.state.image_audits = ImageAuditService(settings, file_store, job_store)
    app.state.manifest_audits = ManifestAuditService(settings, file_store, job_store)
    app.state.archive_audits = ArchiveAuditService(settings, file_store, job_store)
    app.state.project_archive_audits = ProjectArchiveAuditService(settings, file_store, job_store)
    app.state.django_config_audits = DjangoConfigAuditService(settings, file_store, job_store)
    app.state.web_audits = WebAuditService(settings, file_store, job_store)
    app.state.domain_audits = DomainAuditService(settings, file_store, job_store)
    app.state.subdomain_inventory_audits = SubdomainInventoryAuditService(settings, file_store, job_store)


@pytest.mark.anyio
async def test_health(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "inspectra-backend"}


@pytest.mark.anyio
async def test_pdf_upload_creates_record(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    sample_pdf = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\n%%EOF\n"
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/files/pdf",
            files={"file": ("sample.pdf", sample_pdf, "application/pdf")},
        )

    assert response.status_code == 201
    payload = response.json()
    assert payload["original_filename"] == "sample.pdf"
    assert payload["kind"] == "pdf"
    assert payload["stored_filename"].endswith(".pdf")
    assert (tmp_path / "uploads" / payload["stored_filename"]).exists()


@pytest.mark.anyio
async def test_image_upload_creates_record(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/files/image",
            files={"file": ("pixel.png", SAMPLE_PNG, "image/png")},
        )

    assert response.status_code == 201
    payload = response.json()
    assert payload["kind"] == "image"
    assert payload["content_type"] == "image/png"
    assert payload["stored_filename"].endswith(".png")
    assert (tmp_path / "uploads" / payload["stored_filename"]).exists()


@pytest.mark.anyio
async def test_image_upload_rejects_unsupported_format(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/files/image",
            files={"file": ("note.txt", b"not an image", "text/plain")},
        )

    assert response.status_code == 400
    assert "JPEG, PNG, and WebP" in response.json()["detail"]


@pytest.mark.anyio
async def test_manifest_upload_accepts_package_json(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/files/manifest",
            files={"file": ("package.json", SAMPLE_PACKAGE_JSON, "application/json")},
        )

    assert response.status_code == 201
    payload = response.json()
    assert payload["kind"] == "manifest"
    assert payload["content_type"] == "application/json"
    assert payload["stored_filename"].endswith("-package.json")
    assert (tmp_path / "uploads" / payload["stored_filename"]).exists()


@pytest.mark.anyio
async def test_manifest_upload_accepts_requirements_txt(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/files/manifest",
            files={"file": ("requirements.txt", SAMPLE_REQUIREMENTS, "text/plain")},
        )

    assert response.status_code == 201
    payload = response.json()
    assert payload["kind"] == "manifest"
    assert payload["content_type"] == "text/plain"
    assert payload["stored_filename"].endswith("-requirements.txt")


@pytest.mark.anyio
async def test_manifest_upload_accepts_pyproject_toml(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/files/manifest",
            files={"file": ("pyproject.toml", SAMPLE_PYPROJECT, "application/toml")},
        )

    assert response.status_code == 201
    payload = response.json()
    assert payload["kind"] == "manifest"
    assert payload["content_type"] == "application/toml"
    assert payload["stored_filename"].endswith("-pyproject.toml")


@pytest.mark.anyio
async def test_manifest_upload_rejects_unsupported_file(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/files/manifest",
            files={"file": ("setup.py", b"print('nope')\n", "text/x-python")},
        )

    assert response.status_code == 400
    assert "package.json, requirements.txt, and pyproject.toml" in response.json()["detail"]


@pytest.mark.anyio
async def test_archive_upload_accepts_zip(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    sample_zip = make_zip_bytes({"src/app.py": b"print('hello')\n", "package.json": SAMPLE_PACKAGE_JSON})
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/files/archive",
            files={"file": ("project.zip", sample_zip, "application/zip")},
        )
        list_response = await client.get("/files")

    assert response.status_code == 201
    payload = response.json()
    assert payload["kind"] == "archive"
    assert payload["content_type"] == "application/zip"
    assert payload["stored_filename"].endswith(".zip")
    assert (tmp_path / "uploads" / payload["stored_filename"]).exists()
    assert list_response.json()[0]["kind"] == "archive"


@pytest.mark.anyio
async def test_archive_upload_accepts_tar_gz(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    sample_tar_gz = make_tar_bytes({"README.md": b"# demo\n"}, gzipped=True)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/files/archive",
            files={"file": ("project.tar.gz", sample_tar_gz, "application/gzip")},
        )

    assert response.status_code == 201
    payload = response.json()
    assert payload["kind"] == "archive"
    assert payload["content_type"] == "application/gzip"
    assert payload["stored_filename"].endswith(".tar.gz")


@pytest.mark.anyio
async def test_archive_upload_rejects_unsupported_file(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/files/archive",
            files={"file": ("project.rar", b"not supported", "application/octet-stream")},
        )

    assert response.status_code == 400
    assert ".zip, .tar, .tar.gz, and .tgz" in response.json()["detail"]


@pytest.mark.anyio
async def test_manifest_upload_size_limit_returns_clear_error(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path, max_upload_bytes=10)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/files/manifest",
            files={"file": ("requirements.txt", SAMPLE_REQUIREMENTS, "text/plain")},
        )

    assert response.status_code == 413
    assert "Maximum allowed size is 10 bytes" in response.json()["detail"]


@pytest.mark.anyio
async def test_list_files_does_not_expose_absolute_paths(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        await client.post("/files/pdf", files={"file": ("a.pdf", b"%PDF-1.4\n%%EOF\n", "application/pdf")})
        await client.post("/files/pdf", files={"file": ("b.pdf", b"%PDF-1.4\n%%EOF\n", "application/pdf")})
        response = await client.get("/files")

    assert response.status_code == 200
    payload = response.json()
    assert len(payload) == 2
    assert "path" not in payload[0]
    assert all(not value.startswith("/") for item in payload for value in item.values() if isinstance(value, str))


@pytest.mark.anyio
async def test_legacy_file_metadata_without_kind_defaults_to_pdf(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    file_id = "c" * 32
    legacy_payload = {
        "id": file_id,
        "original_filename": "legacy.pdf",
        "stored_filename": f"{file_id}.pdf",
        "content_type": "application/pdf",
        "size_bytes": 10,
        "sha256": "abc",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    (tmp_path / "uploads" / f"{file_id}.json").write_text(json.dumps(legacy_payload), encoding="utf-8")
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get(f"/files/{file_id}")

    assert response.status_code == 200
    assert response.json()["kind"] == "pdf"


@pytest.mark.anyio
async def test_upload_size_limit_returns_clear_error(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path, max_upload_bytes=10)
    transport = ASGITransport(app=app)
    oversized_pdf = b"%PDF-1.4\n" + b"x" * 20

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/files/pdf",
            files={"file": ("large.pdf", oversized_pdf, "application/pdf")},
        )

    assert response.status_code == 413
    assert "Maximum allowed size is 10 bytes" in response.json()["detail"]


@pytest.mark.anyio
async def test_image_upload_size_limit_returns_clear_error(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path, max_upload_bytes=10)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/files/image",
            files={"file": ("large.png", SAMPLE_PNG + b"x" * 20, "image/png")},
        )

    assert response.status_code == 413
    assert "Maximum allowed size is 10 bytes" in response.json()["detail"]


@pytest.mark.anyio
async def test_image_audit_job_creation_and_cross_type_rejections(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    noop = NoopAuditService()
    app.state.pdf_audits = noop
    app.state.image_audits = noop
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        pdf_response = await client.post("/files/pdf", files={"file": ("sample.pdf", b"%PDF-1.4\n%%EOF\n", "application/pdf")})
        image_response = await client.post("/files/image", files={"file": ("pixel.png", SAMPLE_PNG, "image/png")})
        pdf_file = pdf_response.json()
        image_file = image_response.json()

        image_job_response = await client.post(f"/audits/image/{image_file['id']}")
        image_as_pdf_response = await client.post(f"/audits/pdf/{image_file['id']}")
        pdf_as_image_response = await client.post(f"/audits/image/{pdf_file['id']}")

    assert image_job_response.status_code == 202
    assert image_job_response.json()["audit_type"] == "image_basic"
    assert image_as_pdf_response.status_code == 400
    assert image_as_pdf_response.json()["detail"] == "File is not a PDF."
    assert pdf_as_image_response.status_code == 400
    assert pdf_as_image_response.json()["detail"] == "File is not an image."


@pytest.mark.anyio
async def test_manifest_audit_job_creation_and_cross_type_rejections(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    noop = NoopAuditService()
    app.state.pdf_audits = noop
    app.state.image_audits = noop
    app.state.manifest_audits = noop
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        pdf_response = await client.post("/files/pdf", files={"file": ("sample.pdf", b"%PDF-1.4\n%%EOF\n", "application/pdf")})
        image_response = await client.post("/files/image", files={"file": ("pixel.png", SAMPLE_PNG, "image/png")})
        manifest_response = await client.post(
            "/files/manifest",
            files={"file": ("package.json", SAMPLE_PACKAGE_JSON, "application/json")},
        )
        pdf_file = pdf_response.json()
        image_file = image_response.json()
        manifest_file = manifest_response.json()

        manifest_job_response = await client.post(f"/audits/manifest/{manifest_file['id']}")
        manifest_as_pdf_response = await client.post(f"/audits/pdf/{manifest_file['id']}")
        manifest_as_image_response = await client.post(f"/audits/image/{manifest_file['id']}")
        pdf_as_manifest_response = await client.post(f"/audits/manifest/{pdf_file['id']}")
        image_as_manifest_response = await client.post(f"/audits/manifest/{image_file['id']}")

    assert manifest_job_response.status_code == 202
    assert manifest_job_response.json()["audit_type"] == "manifest_basic"
    assert manifest_as_pdf_response.status_code == 400
    assert manifest_as_pdf_response.json()["detail"] == "File is not a PDF."
    assert manifest_as_image_response.status_code == 400
    assert manifest_as_image_response.json()["detail"] == "File is not an image."
    assert pdf_as_manifest_response.status_code == 400
    assert pdf_as_manifest_response.json()["detail"] == "File is not a manifest."
    assert image_as_manifest_response.status_code == 400
    assert image_as_manifest_response.json()["detail"] == "File is not a manifest."


@pytest.mark.anyio
async def test_archive_audit_job_creation_and_cross_type_rejections(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    noop = NoopAuditService()
    app.state.pdf_audits = noop
    app.state.image_audits = noop
    app.state.manifest_audits = noop
    app.state.archive_audits = noop
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        pdf_response = await client.post("/files/pdf", files={"file": ("sample.pdf", b"%PDF-1.4\n%%EOF\n", "application/pdf")})
        image_response = await client.post("/files/image", files={"file": ("pixel.png", SAMPLE_PNG, "image/png")})
        manifest_response = await client.post(
            "/files/manifest",
            files={"file": ("package.json", SAMPLE_PACKAGE_JSON, "application/json")},
        )
        archive_response = await client.post(
            "/files/archive",
            files={"file": ("project.zip", make_zip_bytes({"package.json": SAMPLE_PACKAGE_JSON}), "application/zip")},
        )
        pdf_file = pdf_response.json()
        image_file = image_response.json()
        manifest_file = manifest_response.json()
        archive_file = archive_response.json()

        archive_job_response = await client.post(f"/audits/archive/{archive_file['id']}")
        archive_as_pdf_response = await client.post(f"/audits/pdf/{archive_file['id']}")
        archive_as_image_response = await client.post(f"/audits/image/{archive_file['id']}")
        archive_as_manifest_response = await client.post(f"/audits/manifest/{archive_file['id']}")
        pdf_as_archive_response = await client.post(f"/audits/archive/{pdf_file['id']}")
        image_as_archive_response = await client.post(f"/audits/archive/{image_file['id']}")
        manifest_as_archive_response = await client.post(f"/audits/archive/{manifest_file['id']}")

    assert archive_job_response.status_code == 202
    assert archive_job_response.json()["audit_type"] == "archive_basic"
    assert archive_as_pdf_response.status_code == 400
    assert archive_as_pdf_response.json()["detail"] == "File is not a PDF."
    assert archive_as_image_response.status_code == 400
    assert archive_as_image_response.json()["detail"] == "File is not an image."
    assert archive_as_manifest_response.status_code == 400
    assert archive_as_manifest_response.json()["detail"] == "File is not a manifest."
    assert pdf_as_archive_response.status_code == 400
    assert pdf_as_archive_response.json()["detail"] == "File is not an archive."
    assert image_as_archive_response.status_code == 400
    assert image_as_archive_response.json()["detail"] == "File is not an archive."
    assert manifest_as_archive_response.status_code == 400
    assert manifest_as_archive_response.json()["detail"] == "File is not an archive."


@pytest.mark.anyio
async def test_project_archive_audit_job_creation_and_rejections(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    noop = NoopAuditService()
    app.state.project_archive_audits = noop
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        pdf_response = await client.post("/files/pdf", files={"file": ("sample.pdf", b"%PDF-1.4\n%%EOF\n", "application/pdf")})
        archive_response = await client.post(
            "/files/archive",
            files={"file": ("project.zip", make_zip_bytes({"package.json": SAMPLE_PACKAGE_JSON}), "application/zip")},
        )
        pdf_file = pdf_response.json()
        archive_file = archive_response.json()

        project_archive_response = await client.post(f"/audits/project-archive/{archive_file['id']}")
        pdf_as_project_archive_response = await client.post(f"/audits/project-archive/{pdf_file['id']}")
        invalid_response = await client.post("/audits/project-archive/not-a-file-id")

    assert project_archive_response.status_code == 202
    assert project_archive_response.json()["audit_type"] == "project_archive_basic"
    assert pdf_as_project_archive_response.status_code == 400
    assert pdf_as_project_archive_response.json()["detail"] == "File is not an archive."
    assert invalid_response.status_code == 400


@pytest.mark.anyio
async def test_django_config_audit_job_creation_and_rejections(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    noop = NoopAuditService()
    app.state.django_config_audits = noop
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        pdf_response = await client.post("/files/pdf", files={"file": ("sample.pdf", b"%PDF-1.4\n%%EOF\n", "application/pdf")})
        archive_response = await client.post(
            "/files/archive",
            files={"file": ("django.zip", make_zip_bytes({"project/settings.py": b"DEBUG=True\n"}), "application/zip")},
        )
        pdf_file = pdf_response.json()
        archive_file = archive_response.json()

        django_response = await client.post(f"/audits/django-config/{archive_file['id']}")
        pdf_as_django_response = await client.post(f"/audits/django-config/{pdf_file['id']}")
        invalid_response = await client.post("/audits/django-config/not-a-file-id")

    assert django_response.status_code == 202
    assert django_response.json()["audit_type"] == "django_config_basic"
    assert pdf_as_django_response.status_code == 400
    assert pdf_as_django_response.json()["detail"] == "File is not an archive."
    assert invalid_response.status_code == 400


@pytest.mark.anyio
async def test_web_basic_audit_requires_authorization(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    app.state.web_audits = NoopAuditService()
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/audits/web/basic",
            json={"url": "https://example.com", "authorization_confirmed": False},
        )

    assert response.status_code == 400
    assert response.json()["detail"] == "Authorization confirmation is required."


@pytest.mark.anyio
async def test_web_basic_audit_rejects_invalid_url_and_scheme(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    app.state.web_audits = NoopAuditService()
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        invalid_response = await client.post(
            "/audits/web/basic",
            json={"url": "not-a-url", "authorization_confirmed": True},
        )
        scheme_response = await client.post(
            "/audits/web/basic",
            json={"url": "ftp://example.com", "authorization_confirmed": True},
        )
        userinfo_response = await client.post(
            "/audits/web/basic",
            json={"url": "https://user:pass@example.com", "authorization_confirmed": True},
        )

    assert invalid_response.status_code == 400
    assert scheme_response.status_code == 400
    assert scheme_response.json()["detail"] == "Only http and https URLs are accepted."
    assert userinfo_response.status_code == 400
    assert userinfo_response.json()["detail"] == "URL credentials are not accepted."


def test_web_query_redaction_helpers_preserve_safe_params_and_redact_sensitive_values():
    redacted = web_security.redact_url_query(
        "https://example.com/callback?code=abc123&state=xyz&page=1&Token=second&flag"
    )

    assert "code=REDACTED" in redacted
    assert "state=REDACTED" in redacted
    assert "Token=REDACTED" in redacted
    assert "page=1" in redacted
    assert "abc123" not in redacted
    assert "second" not in redacted
    assert web_security.query_redaction_summary(redacted)["redacted_query_params"] == ["code", "state", "Token"]


@pytest.mark.anyio
async def test_web_basic_audit_redacts_sensitive_query_params_in_stored_job(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    web_service = CapturingWebAuditService()
    app.state.web_audits = web_service
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/audits/web/basic",
            json={
                "url": "https://example.test/callback?token=supersecret&page=1&token=second",
                "authorization_confirmed": True,
            },
        )
        list_response = await client.get("/jobs")

    assert response.status_code == 202
    payload = response.json()
    assert "supersecret" not in json.dumps(payload)
    assert "second" not in json.dumps(payload)
    assert payload["target_url"] == "https://example.test/callback?token=REDACTED&page=1&token=REDACTED"
    assert list_response.json()[0]["target_url"] == payload["target_url"]
    assert web_service.calls
    assert web_service.calls[0][1] == "https://example.test/callback?token=supersecret&page=1&token=second"


@pytest.mark.anyio
async def test_web_basic_audit_leaves_url_without_query_unchanged(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    app.state.web_audits = NoopAuditService()
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/audits/web/basic",
            json={"url": "https://example.test/status", "authorization_confirmed": True},
        )

    assert response.status_code == 202
    assert response.json()["target_url"] == "https://example.test/status"


@pytest.mark.anyio
async def test_web_basic_audit_blocks_private_targets_by_default(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    app.state.web_audits = NoopAuditService()
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/audits/web/basic",
            json={"url": "http://127.0.0.1", "authorization_confirmed": True},
        )

    assert response.status_code == 400
    assert "blocked address range" in response.json()["detail"]


@pytest.mark.anyio
async def test_web_basic_audit_allows_private_targets_when_configured(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_WEB_ALLOW_PRIVATE_TARGETS", "true")
    monkeypatch.setenv("INSPECTRA_WEB_ALLOWED_PORTS", "80,443,8080")
    configure_test_state(monkeypatch, tmp_path)
    app.state.web_audits = NoopAuditService()
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/audits/web/basic",
            json={"url": "http://127.0.0.1:8080/status", "authorization_confirmed": True},
        )
        list_response = await client.get("/jobs")

    assert response.status_code == 202
    payload = response.json()
    assert payload["audit_type"] == "web_basic"
    assert payload["file_id"] is None
    assert payload["target_url"] == "http://127.0.0.1:8080/status"
    assert list_response.json()[0]["target_url"] == payload["target_url"]


@pytest.mark.anyio
async def test_web_basic_audit_enforces_allowed_ports(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    app.state.web_audits = NoopAuditService()
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        rejected = await client.post(
            "/audits/web/basic",
            json={"url": "https://example.com:8443", "authorization_confirmed": True},
        )

    monkeypatch.setenv("INSPECTRA_WEB_ALLOWED_PORTS", "80,443,8443")
    configure_test_state(monkeypatch, tmp_path)
    app.state.web_audits = NoopAuditService()
    monkeypatch.setattr(
        web_security,
        "resolve_host_addresses",
        lambda host, port: {web_security.ipaddress.ip_address("93.184.216.34")},
    )
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        accepted = await client.post(
            "/audits/web/basic",
            json={"url": "https://example.com:8443/status", "authorization_confirmed": True},
        )

    assert rejected.status_code == 400
    assert "port 8443 is not allowed" in rejected.json()["detail"]
    assert accepted.status_code == 202
    assert accepted.json()["target_url"] == "https://example.com:8443/status"


@pytest.mark.anyio
async def test_web_basic_audit_still_blocks_metadata_target_when_private_allowed(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_WEB_ALLOW_PRIVATE_TARGETS", "true")
    configure_test_state(monkeypatch, tmp_path)
    app.state.web_audits = NoopAuditService()
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/audits/web/basic",
            json={"url": "http://169.254.169.254/latest/meta-data/", "authorization_confirmed": True},
        )

    assert response.status_code == 400
    assert "cloud metadata" in response.json()["detail"]


@pytest.mark.anyio
async def test_web_basic_audit_blocks_hostname_resolving_to_private_ip(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    app.state.web_audits = NoopAuditService()
    monkeypatch.setattr(
        web_security,
        "resolve_host_addresses",
        lambda host, port: {web_security.ipaddress.ip_address("192.168.1.20")},
    )
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/audits/web/basic",
            json={"url": "https://example.test", "authorization_confirmed": True},
        )

    assert response.status_code == 400
    assert "private address" in response.json()["detail"]


@pytest.mark.anyio
async def test_domain_basic_audit_job_creation_and_list(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    app.state.domain_audits = NoopAuditService()
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/audits/domain/basic",
            json={"domain": "Example.COM", "authorization_confirmed": True},
        )
        list_response = await client.get("/jobs")

    assert response.status_code == 202
    payload = response.json()
    assert payload["audit_type"] == "domain_basic"
    assert payload["file_id"] is None
    assert payload["target_domain"] == "example.com"
    assert list_response.json()[0]["target_domain"] == "example.com"


@pytest.mark.anyio
async def test_domain_basic_audit_requires_authorization(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    app.state.domain_audits = NoopAuditService()
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/audits/domain/basic",
            json={"domain": "example.com", "authorization_confirmed": False},
        )

    assert response.status_code == 400
    assert response.json()["detail"] == "Authorization confirmation is required."


@pytest.mark.anyio
async def test_domain_basic_audit_rejects_invalid_domains(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    app.state.domain_audits = NoopAuditService()
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        url_response = await client.post(
            "/audits/domain/basic",
            json={"domain": "https://example.com", "authorization_confirmed": True},
        )
        path_response = await client.post(
            "/audits/domain/basic",
            json={"domain": "example.com/path", "authorization_confirmed": True},
        )
        ip_response = await client.post(
            "/audits/domain/basic",
            json={"domain": "127.0.0.1", "authorization_confirmed": True},
        )
        localhost_response = await client.post(
            "/audits/domain/basic",
            json={"domain": "localhost", "authorization_confirmed": True},
        )
        local_response = await client.post(
            "/audits/domain/basic",
            json={"domain": "test.local", "authorization_confirmed": True},
        )

    assert url_response.status_code == 400
    assert path_response.status_code == 400
    assert ip_response.status_code == 400
    assert localhost_response.status_code == 400
    assert local_response.status_code == 400


@pytest.mark.anyio
async def test_subdomain_inventory_audit_job_creation_and_list(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    service = CapturingSubdomainInventoryAuditService()
    app.state.subdomain_inventory_audits = service
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/audits/subdomains/basic",
            json={
                "root_domain": "Example.COM",
                "subdomains": ["www", "API.Example.COM"],
                "authorization_confirmed": True,
            },
        )
        list_response = await client.get("/jobs")

    assert response.status_code == 202
    payload = response.json()
    assert payload["audit_type"] == "subdomain_inventory_basic"
    assert payload["file_id"] is None
    assert payload["target_domain"] == "example.com"
    assert list_response.json()[0]["target_domain"] == "example.com"
    assert service.calls == [(payload["id"], ["www", "API.Example.COM"])]


@pytest.mark.anyio
async def test_subdomain_inventory_audit_requires_authorization(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    app.state.subdomain_inventory_audits = NoopAuditService()
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            "/audits/subdomains/basic",
            json={"root_domain": "example.com", "subdomains": ["www"], "authorization_confirmed": False},
        )

    assert response.status_code == 400
    assert response.json()["detail"] == "Authorization confirmation is required."


@pytest.mark.anyio
async def test_subdomain_inventory_audit_rejects_bad_root_and_candidate_lists(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_SUBDOMAIN_MAX_CANDIDATES", "2")
    configure_test_state(monkeypatch, tmp_path)
    app.state.subdomain_inventory_audits = NoopAuditService()
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        bad_root = await client.post(
            "/audits/subdomains/basic",
            json={"root_domain": "https://example.com", "subdomains": ["www"], "authorization_confirmed": True},
        )
        empty_list = await client.post(
            "/audits/subdomains/basic",
            json={"root_domain": "example.com", "subdomains": [], "authorization_confirmed": True},
        )
        too_many = await client.post(
            "/audits/subdomains/basic",
            json={"root_domain": "example.com", "subdomains": ["www", "api", "cdn"], "authorization_confirmed": True},
        )

    assert bad_root.status_code == 400
    assert empty_list.status_code == 422
    assert too_many.status_code == 400


@pytest.mark.anyio
async def test_subdomain_inventory_audit_rejects_invalid_candidates(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    service = CapturingSubdomainInventoryAuditService()
    app.state.subdomain_inventory_audits = service
    bad_candidates = [
        "example.com",
        "api.evil.com",
        "*.example.com",
        "https://api.example.com",
        "api.example.com/path",
        "api.example.com?x=1",
        "api.example.com#fragment",
        "api.example.com.",
        "api.",
        "127.0.0.1",
        "::1",
        "host.local",
        "bad candidate",
        f"{'a' * 64}.example.com",
    ]
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        responses = [
            await client.post(
                "/audits/subdomains/basic",
                json={"root_domain": "example.com", "subdomains": [candidate], "authorization_confirmed": True},
            )
            for candidate in bad_candidates
        ]
        mixed_response = await client.post(
            "/audits/subdomains/basic",
            json={"root_domain": "example.com", "subdomains": ["www", "api.evil.com"], "authorization_confirmed": True},
        )

    assert all(response.status_code == 400 for response in responses)
    assert mixed_response.status_code == 400
    assert service.calls == []


@pytest.mark.anyio
async def test_subdomain_inventory_audit_rejects_oversized_strings(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    service = CapturingSubdomainInventoryAuditService()
    app.state.subdomain_inventory_audits = service
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        long_root = await client.post(
            "/audits/subdomains/basic",
            json={"root_domain": f"{'a' * 250}.com", "subdomains": ["www"], "authorization_confirmed": True},
        )
        long_candidate = await client.post(
            "/audits/subdomains/basic",
            json={"root_domain": "example.com", "subdomains": [f"{'a' * 254}"], "authorization_confirmed": True},
        )

    assert long_root.status_code == 422
    assert long_candidate.status_code == 422
    assert service.calls == []


@pytest.mark.parametrize(
    ("root_domain", "candidate", "expected"),
    [
        ("example.com", "www", "www.example.com"),
        ("example.com", "API.Example.COM", "api.example.com"),
        ("example.com", "täst", "xn--tst-qla.example.com"),
    ],
)
def test_normalize_subdomain_candidate_accepts_labels_and_fqdns(root_domain, candidate, expected):
    assert normalize_subdomain_candidate(root_domain, candidate) == expected


@pytest.mark.parametrize(
    "candidate",
    [
        "example.com",
        "api.evil.com",
        "api.",
        "api.example.com.",
        "::1",
        "host.local",
        f"{'a' * 64}.example.com",
    ],
)
def test_normalize_subdomain_candidate_rejects_contract_edges(candidate):
    with pytest.raises(HTTPException):
        normalize_subdomain_candidate("example.com", candidate)


def test_domain_runner_timeout_budget_scales_with_dns_timeout():
    assert calculate_domain_runner_timeout_seconds(5.0) == 190.0
    assert calculate_domain_runner_timeout_seconds(5.0, include_www=False) == 145.0
    assert calculate_domain_runner_timeout_seconds(2.0) > calculate_domain_runner_timeout_seconds(1.0)
    assert calculate_domain_runner_timeout_seconds(0.25) > 10.0


def test_subdomain_inventory_runner_timeout_uses_global_deadline():
    assert calculate_subdomain_inventory_runner_timeout_seconds(30.0, dns_timeout_seconds=5.0) == 55.0
    assert calculate_subdomain_inventory_runner_timeout_seconds(30.0, dns_timeout_seconds=1.0) == 43.0
    assert calculate_subdomain_inventory_runner_timeout_seconds(120.0, dns_timeout_seconds=5.0) == 145.0


def test_subdomain_inventory_global_deadline_config(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("INSPECTRA_SUBDOMAIN_GLOBAL_DEADLINE_SECONDS", "12.5")

    settings = load_settings()

    assert settings.subdomain_global_deadline_seconds == 12.5


def test_django_config_limits_config(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("INSPECTRA_DJANGO_CONFIG_MAX_FILES", "12")
    monkeypatch.setenv("INSPECTRA_DJANGO_CONFIG_MAX_FILE_BYTES", "1024")
    monkeypatch.setenv("INSPECTRA_DJANGO_CONFIG_MAX_TOTAL_BYTES", "4096")

    settings = load_settings()

    assert settings.django_config_max_files == 12
    assert settings.django_config_max_file_bytes == 1024
    assert settings.django_config_max_total_bytes == 4096


@pytest.mark.parametrize(
    ("raw_domain", "expected"),
    [
        ("example.com", "example.com"),
        ("www.example.com", "www.example.com"),
        ("Sub.Example.CO.UK", "sub.example.co.uk"),
        ("täst.example", "xn--tst-qla.example"),
        ("example.com.", "example.com"),
    ],
)
def test_normalize_domain_accepts_valid_domains(raw_domain, expected):
    assert normalize_domain(raw_domain) == expected


@pytest.mark.parametrize(
    "raw_domain",
    [
        "",
        "https://example.com",
        "http://example.com",
        "example.com/path",
        "example.com?x=1",
        "example.com#fragment",
        "user:pass@example.com",
        "exa mple.com",
        "127.0.0.1",
        "::1",
        "localhost",
        "test.local",
        "test.localhost",
        "test.internal",
        "test.test",
        "test.invalid",
        "example..com",
        f"{'a' * 64}.example",
        "-bad.example",
        "bad-.example",
        ".".join(["a" * 63] * 5),
        "\ud800.example",
    ],
)
def test_normalize_domain_rejects_invalid_domains(raw_domain):
    with pytest.raises(HTTPException):
        normalize_domain(raw_domain)


@pytest.mark.anyio
async def test_list_jobs_returns_recent_first_with_summary(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    older = datetime(2026, 1, 1, tzinfo=timezone.utc)
    newer = older + timedelta(days=1)
    app.state.jobs.save(
        JobRecord(
            id="a" * 32,
            audit_type="pdf_basic",
            file_id="1" * 32,
            status="completed",
            created_at=older,
            updated_at=older,
            result={"analyzer": "old", "hashes": {"sha256": "abc"}, "validation": {"qpdf_ok": True, "warnings": []}},
        )
    )
    app.state.jobs.save(
        JobRecord(
            id="b" * 32,
            audit_type="pdf_basic",
            file_id="2" * 32,
            status="failed",
            created_at=newer,
            updated_at=newer,
            error="runner unavailable",
        )
    )
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/jobs")

    assert response.status_code == 200
    payload = response.json()
    assert [item["id"] for item in payload] == ["b" * 32, "a" * 32]
    assert payload[0]["summary"] == {"error": "runner unavailable"}
    assert payload[1]["summary"]["sha256"] == "abc"


@pytest.mark.anyio
async def test_delete_file_removes_source_and_marks_jobs(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        upload_response = await client.post(
            "/files/pdf",
            files={"file": ("sample.pdf", b"%PDF-1.4\n%%EOF\n", "application/pdf")},
        )
        file_payload = upload_response.json()
        job = app.state.jobs.create_pdf_job(file_payload["id"])
        app.state.jobs.update(
            job.id,
            status="completed",
            result={"analyzer": "inspectra-pdf-basic", "hashes": {"sha256": file_payload["sha256"]}, "validation": {"qpdf_ok": True}},
        )

        delete_response = await client.delete(f"/files/{file_payload['id']}")
        deleted_file_response = await client.get(f"/files/{file_payload['id']}")
        job_response = await client.get(f"/jobs/{job.id}")

    assert delete_response.status_code == 200
    assert delete_response.json()["associated_jobs_marked"] == 1
    assert deleted_file_response.status_code == 404
    assert not (tmp_path / "uploads" / file_payload["stored_filename"]).exists()
    assert not (tmp_path / "uploads" / f"{file_payload['id']}.json").exists()
    assert job_response.status_code == 200
    assert job_response.json()["source_file_deleted_at"] is not None
    assert job_response.json()["result"]["hashes"]["sha256"] == file_payload["sha256"]


def test_storage_lockfile_is_created_inside_data(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)

    app.state.jobs.create_pdf_job("1" * 32)

    lock_path = tmp_path / ".locks" / "storage.lock"
    assert lock_path.exists()
    assert lock_path.resolve().is_relative_to(tmp_path.resolve())


def test_job_save_preserves_existing_source_deleted_marker(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    job = app.state.jobs.create_pdf_job("2" * 32)
    stale_record = app.state.jobs.get(job.id)

    assert app.state.jobs.mark_file_deleted(job.file_id) == 1
    stale_completed = stale_record.model_copy(
        update={
            "status": "completed",
            "updated_at": datetime(2026, 5, 26, tzinfo=timezone.utc),
            "result": {"analyzer": "race-fixture"},
        }
    )
    app.state.jobs.save(stale_completed)

    final = app.state.jobs.get(job.id)
    assert final.status == "completed"
    assert final.result == {"analyzer": "race-fixture"}
    assert final.source_file_deleted_at is not None


def test_concurrent_job_completion_and_delete_marker_preserve_fields(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    job = app.state.jobs.create_pdf_job("3" * 32)
    barrier = threading.Barrier(2)

    def mark_deleted() -> None:
        barrier.wait(timeout=2)
        app.state.jobs.mark_file_deleted(job.file_id)

    def complete_job() -> None:
        barrier.wait(timeout=2)
        app.state.jobs.update(job.id, status="completed", result={"analyzer": "concurrent"})

    threads = [threading.Thread(target=mark_deleted), threading.Thread(target=complete_job)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=2)

    assert all(not thread.is_alive() for thread in threads)
    final = app.state.jobs.get(job.id)
    assert final.status == "completed"
    assert final.result == {"analyzer": "concurrent"}
    assert final.source_file_deleted_at is not None


def test_concurrent_updates_for_different_jobs_do_not_corrupt_json(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    jobs = [app.state.jobs.create_pdf_job(f"{index:032x}") for index in range(10, 16)]
    barrier = threading.Barrier(len(jobs))

    def complete_job(job: JobRecord, index: int) -> None:
        barrier.wait(timeout=2)
        app.state.jobs.update(job.id, status="completed", result={"index": index})

    threads = [threading.Thread(target=complete_job, args=(job, index)) for index, job in enumerate(jobs)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=2)

    assert all(not thread.is_alive() for thread in threads)
    for index, job in enumerate(jobs):
        payload = json.loads((tmp_path / "results" / "jobs" / f"{job.id}.json").read_text(encoding="utf-8"))
        final = app.state.jobs.get(job.id)
        assert payload["status"] == "completed"
        assert final.result == {"index": index}


@pytest.mark.anyio
async def test_export_markdown_for_existing_job(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    job = save_export_fixture_job()
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get(f"/jobs/{job.id}/export/markdown")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/markdown")
    assert response.headers["content-disposition"] == f'attachment; filename="inspectra-job-{job.id}.md"'
    assert "# Inspectra Audit Report" in response.text
    assert "manifest_basic" in response.text
    assert "`<script>alert('x')</script>`" in response.text


@pytest.mark.anyio
async def test_export_markdown_neutralizes_dynamic_markdown_content(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    job = save_malicious_markdown_fixture_job()
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get(f"/jobs/{job.id}/export/markdown")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/markdown")
    assert response.headers["content-disposition"] == f'attachment; filename="inspectra-job-{job.id}.md"'
    markdown = response.text
    assert "`[click me](https://evil.example)`" in markdown
    assert "`![x](https://evil.example/pixel.png)`" in markdown
    assert '`<img src="https://evil.example/pixel.png">`' in markdown
    assert "`# Fake Heading`" in markdown
    assert "`- fake item`" in markdown
    assert "`> fake quote`" in markdown
    assert "`value | injected | column`" in markdown
    assert "`demo @ git+https://evil.example/demo.git`" in markdown
    assert "`<script>alert(1)</script>`" in markdown
    assert "````text\nfirst line\n> fake quote\n```inside fenced content\nhttps://evil.example/log\n````" in markdown


def test_markdown_helpers_use_safe_code_delimiters():
    assert markdown_inline_value("[click](https://evil.example)") == "`[click](https://evil.example)`"
    assert markdown_inline_value("`inline`") == "`` `inline` ``"

    block = markdown_block_value("before\n```text\ninside\n```\nafter")

    assert block.startswith("````text\n")
    assert block.endswith("\n````")
    assert "```text\ninside\n```" in block


@pytest.mark.anyio
async def test_export_html_escapes_dynamic_content(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    job = save_export_fixture_job()
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get(f"/jobs/{job.id}/export/html")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert response.headers["content-disposition"] == f'attachment; filename="inspectra-job-{job.id}.html"'
    assert "<script>alert('x')</script>" not in response.text
    assert "&lt;script&gt;alert(&#x27;x&#x27;)&lt;/script&gt;" in response.text


@pytest.mark.anyio
async def test_export_xml_escapes_dynamic_content_and_is_valid(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    job = save_export_fixture_job()
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get(f"/jobs/{job.id}/export/xml")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/xml")
    assert response.headers["content-disposition"] == f'attachment; filename="inspectra-job-{job.id}.xml"'
    assert "<script>alert('x')</script>" not in response.text
    assert "&lt;script&gt;alert('x')&lt;/script&gt;" in response.text
    root = ElementTree.fromstring(response.text)
    assert root.tag == "inspectraAuditReport"
    assert root.findtext("./job/id") == job.id


@pytest.mark.anyio
async def test_export_pdf_for_existing_job(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    job = save_export_fixture_job()
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get(f"/jobs/{job.id}/export/pdf")

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert response.headers["content-disposition"] == f'attachment; filename="inspectra-job-{job.id}.pdf"'
    assert response.content.startswith(b"%PDF")
    assert len(response.content) > 200


@pytest.mark.anyio
async def test_export_archive_job_all_formats(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    job = save_archive_export_fixture_job()
    expected = {
        "markdown": ("text/markdown", "md"),
        "html": ("text/html", "html"),
        "xml": ("application/xml", "xml"),
        "pdf": ("application/pdf", "pdf"),
    }
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        responses = {
            report_format: await client.get(f"/jobs/{job.id}/export/{report_format}")
            for report_format in expected
        }

    for report_format, response in responses.items():
        content_type, extension = expected[report_format]
        assert response.status_code == 200
        assert response.headers["content-type"].startswith(content_type)
        assert response.headers["content-disposition"] == f'attachment; filename="inspectra-job-{job.id}.{extension}"'
    assert "archive_basic" in responses["markdown"].text
    assert "Archive Metrics" in responses["html"].text
    assert ElementTree.fromstring(responses["xml"].text).findtext("./job/auditType") == "archive_basic"
    assert responses["pdf"].content.startswith(b"%PDF")


@pytest.mark.anyio
async def test_export_project_archive_job_all_formats(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    job = save_project_archive_export_fixture_job()
    expected = {
        "markdown": ("text/markdown", "md"),
        "html": ("text/html", "html"),
        "xml": ("application/xml", "xml"),
        "pdf": ("application/pdf", "pdf"),
    }
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        responses = {
            report_format: await client.get(f"/jobs/{job.id}/export/{report_format}")
            for report_format in expected
        }

    for report_format, response in responses.items():
        content_type, extension = expected[report_format]
        assert response.status_code == 200
        assert response.headers["content-type"].startswith(content_type)
        assert response.headers["content-disposition"] == f'attachment; filename="inspectra-job-{job.id}.{extension}"'
    assert "project_archive_basic" in responses["markdown"].text
    assert "Project Archive Metrics" in responses["html"].text
    assert ElementTree.fromstring(responses["xml"].text).findtext("./job/auditType") == "project_archive_basic"
    assert responses["pdf"].content.startswith(b"%PDF")


@pytest.mark.anyio
async def test_export_web_job_all_formats(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    job = save_web_export_fixture_job()
    expected = {
        "markdown": ("text/markdown", "md"),
        "html": ("text/html", "html"),
        "xml": ("application/xml", "xml"),
        "pdf": ("application/pdf", "pdf"),
    }
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        responses = {
            report_format: await client.get(f"/jobs/{job.id}/export/{report_format}")
            for report_format in expected
        }

    for report_format, response in responses.items():
        content_type, extension = expected[report_format]
        assert response.status_code == 200
        assert response.headers["content-type"].startswith(content_type)
        assert response.headers["content-disposition"] == f'attachment; filename="inspectra-job-{job.id}.{extension}"'
    assert "web_basic" in responses["markdown"].text
    assert "Security Headers" in responses["html"].text
    assert ElementTree.fromstring(responses["xml"].text).findtext("./job/targetUrl") == "https://example.com/callback?token=REDACTED&page=1"
    assert responses["pdf"].content.startswith(b"%PDF")
    for response in responses.values():
        content = response.text if response.headers["content-type"].startswith(("text/", "application/xml")) else response.content.decode("latin1")
        assert "supersecret" not in content
        assert "[redacted]" in content
        if response.headers["content-type"].startswith(("text/", "application/xml")):
            assert "token=REDACTED" in content


@pytest.mark.anyio
async def test_export_domain_job_all_formats(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    job = save_domain_export_fixture_job()
    expected = {
        "markdown": ("text/markdown", "md"),
        "html": ("text/html", "html"),
        "xml": ("application/xml", "xml"),
        "pdf": ("application/pdf", "pdf"),
    }
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        responses = {
            report_format: await client.get(f"/jobs/{job.id}/export/{report_format}")
            for report_format in expected
        }

    for report_format, response in responses.items():
        content_type, extension = expected[report_format]
        assert response.status_code == 200
        assert response.headers["content-type"].startswith(content_type)
        assert response.headers["content-disposition"] == f'attachment; filename="inspectra-job-{job.id}.{extension}"'
    assert "domain_basic" in responses["markdown"].text
    assert "DNS Records" in responses["html"].text
    assert ElementTree.fromstring(responses["xml"].text).findtext("./job/targetDomain") == "example.com"
    assert responses["pdf"].content.startswith(b"%PDF")


@pytest.mark.anyio
async def test_export_subdomain_inventory_job_all_formats(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    job = save_subdomain_inventory_export_fixture_job()
    expected = {
        "markdown": ("text/markdown", "md"),
        "html": ("text/html", "html"),
        "xml": ("application/xml", "xml"),
        "pdf": ("application/pdf", "pdf"),
    }
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        responses = {
            report_format: await client.get(f"/jobs/{job.id}/export/{report_format}")
            for report_format in expected
        }

    for report_format, response in responses.items():
        content_type, extension = expected[report_format]
        assert response.status_code == 200
        assert response.headers["content-type"].startswith(content_type)
        assert response.headers["content-disposition"] == f'attachment; filename="inspectra-job-{job.id}.{extension}"'
    assert "subdomain_inventory_basic" in responses["markdown"].text
    assert "Subdomain Inventory Limits" in responses["markdown"].text
    assert "global_deadline_reached" in responses["markdown"].text
    assert "Subdomain Inventory Metrics" in responses["html"].text
    assert ElementTree.fromstring(responses["xml"].text).findtext("./job/targetDomain") == "example.com"
    assert responses["pdf"].content.startswith(b"%PDF")


@pytest.mark.anyio
async def test_export_django_config_job_all_formats(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    job = save_django_config_export_fixture_job()
    expected = {
        "markdown": ("text/markdown", "md"),
        "html": ("text/html", "html"),
        "xml": ("application/xml", "xml"),
        "pdf": ("application/pdf", "pdf"),
    }
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        responses = {
            report_format: await client.get(f"/jobs/{job.id}/export/{report_format}")
            for report_format in expected
        }

    for report_format, response in responses.items():
        content_type, extension = expected[report_format]
        assert response.status_code == 200
        assert response.headers["content-type"].startswith(content_type)
        assert response.headers["content-disposition"] == f'attachment; filename="inspectra-job-{job.id}.{extension}"'
    assert "django_config_basic" in responses["markdown"].text
    assert "Finding 1 Context" in responses["markdown"].text
    assert "production" in responses["markdown"].text
    assert "Finding 2 Context" in responses["markdown"].text
    assert "grouped" in responses["markdown"].text
    assert "Django Config Metrics" in responses["html"].text
    assert "Finding 1 Context" in responses["html"].text
    assert "production" in responses["html"].text
    assert "Finding 2 Context" in responses["html"].text
    assert "grouped" in responses["html"].text
    assert ElementTree.fromstring(responses["xml"].text).findtext("./job/auditType") == "django_config_basic"
    assert responses["pdf"].content.startswith(b"%PDF")
    assert "supersecret" not in responses["markdown"].text
    assert "[REDACTED]" in responses["markdown"].text


@pytest.mark.anyio
async def test_export_django_config_redacts_legacy_secret_values(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    now = datetime(2026, 5, 29, tzinfo=timezone.utc)
    job = JobRecord(
        id="e" * 32,
        audit_type="django_config_basic",
        file_id="4" * 32,
        status="completed",
        created_at=now,
        updated_at=now,
        error="TOKEN=super-secret-value-123",
        result={
            "analyzer": "django_config_basic",
            "archive_type": "zip",
            "summary": {"files_read": 1, "findings_count": 1, "secrets_redacted_count": 0},
            "detected_files": [
                {
                    "path": "project/settings.py",
                    "category": "django_config",
                    "read": False,
                    "skip_reason": "DATABASE_URL=postgres://user:rawpass@db/app",
                }
            ],
            "django_signals": {
                "secret_key": {"status": "SECRET_KEY = 'django-insecure-test-secret'", "files": ["project/settings.py"]},
            },
            "findings": [
                {
                    "id": "legacy_secret",
                    "title": "Legacy raw secret",
                    "level": "medium",
                    "description": "DATABASE_URL=postgres://user:rawpass@db/app",
                    "evidence": "SECRET_KEY = 'super-secret-value-123'",
                    "recommendation": "-----BEGIN PRIVATE KEY-----\nabc123\n-----END PRIVATE KEY-----",
                    "file_path": "project/settings.py",
                    "context": "production<script>TOKEN=super-secret-value-123</script>",
                }
            ],
            "errors": ["PASSWORD=super-secret-value-123"],
        },
    )
    app.state.jobs.save(job)
    expected = {
        "markdown": "text/markdown",
        "html": "text/html",
        "xml": "application/xml",
        "pdf": "application/pdf",
    }
    forbidden = (
        b"super-secret-value-123",
        b"django-insecure-test-secret",
        b"rawpass",
        b"abc123",
        b"BEGIN PRIVATE KEY",
    )
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        responses = {
            report_format: await client.get(f"/jobs/{job.id}/export/{report_format}")
            for report_format in expected
        }

    for report_format, response in responses.items():
        assert response.status_code == 200
        assert response.headers["content-type"].startswith(expected[report_format])
        assert b"REDACTED" in response.content
        for secret in forbidden:
            assert secret not in response.content
    assert "&lt;script&gt;" in responses["html"].text
    assert "<script>" not in responses["html"].text


@pytest.mark.anyio
async def test_export_django_config_jobs_with_sparse_and_incomplete_results(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    now = datetime(2026, 5, 29, tzinfo=timezone.utc)
    jobs = [
        JobRecord(id="1" * 32, audit_type="django_config_basic", file_id="4" * 32, status="queued", created_at=now, updated_at=now),
        JobRecord(id="2" * 32, audit_type="django_config_basic", file_id="4" * 32, status="running", created_at=now, updated_at=now),
        JobRecord(
            id="3" * 32,
            audit_type="django_config_basic",
            file_id="4" * 32,
            status="failed",
            created_at=now,
            updated_at=now,
            error="Django config runner failed safely.",
        ),
        JobRecord(
            id="4" * 32,
            audit_type="django_config_basic",
            file_id="4" * 32,
            status="completed",
            created_at=now,
            updated_at=now,
            result={"analyzer": "django_config_basic", "summary": {}, "findings": [], "errors": []},
        ),
    ]
    for job in jobs:
        app.state.jobs.save(job)
    expected = {
        "markdown": "text/markdown",
        "html": "text/html",
        "xml": "application/xml",
        "pdf": "application/pdf",
    }
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        for job in jobs:
            for report_format, content_type in expected.items():
                response = await client.get(f"/jobs/{job.id}/export/{report_format}")

                assert response.status_code == 200
                assert response.headers["content-type"].startswith(content_type)
                if report_format == "xml":
                    root = ElementTree.fromstring(response.text)
                    assert root.findtext("./job/status") == job.status
                    assert root.findtext("./job/auditType") == "django_config_basic"
                elif report_format == "pdf":
                    assert response.content.startswith(b"%PDF")
                else:
                    assert job.status in response.text
                    assert "django_config_basic" in response.text


@pytest.mark.anyio
async def test_export_domain_jobs_with_sparse_and_incomplete_results(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    now = datetime(2026, 5, 27, tzinfo=timezone.utc)
    jobs = [
        JobRecord(
            id="a" * 32,
            audit_type="domain_basic",
            file_id=None,
            target_domain="queued.example",
            status="queued",
            created_at=now,
            updated_at=now,
        ),
        JobRecord(
            id="b" * 32,
            audit_type="domain_basic",
            file_id=None,
            target_domain="running.example",
            status="running",
            created_at=now,
            updated_at=now,
        ),
        JobRecord(
            id="c" * 32,
            audit_type="domain_basic",
            file_id=None,
            target_domain="failed.example",
            status="failed",
            created_at=now,
            updated_at=now,
            error="DNS runner failed safely.",
        ),
        JobRecord(
            id="d" * 32,
            audit_type="domain_basic",
            file_id=None,
            target_domain="sparse.example",
            status="completed",
            created_at=now,
            updated_at=now,
            result={"analyzer": "domain_basic", "target": {"normalized_domain": "sparse.example"}, "summary": {}},
        ),
    ]
    for job in jobs:
        app.state.jobs.save(job)
    expected = {
        "markdown": "text/markdown",
        "html": "text/html",
        "xml": "application/xml",
        "pdf": "application/pdf",
    }
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        for job in jobs:
            for report_format, content_type in expected.items():
                response = await client.get(f"/jobs/{job.id}/export/{report_format}")

                assert response.status_code == 200
                assert response.headers["content-type"].startswith(content_type)
                if report_format == "xml":
                    root = ElementTree.fromstring(response.text)
                    assert root.findtext("./job/status") == job.status
                    assert root.findtext("./job/targetDomain") == job.target_domain
                elif report_format == "pdf":
                    assert response.content.startswith(b"%PDF")
                else:
                    assert job.status in response.text
                    assert job.target_domain in response.text


@pytest.mark.anyio
async def test_export_subdomain_inventory_jobs_with_sparse_and_incomplete_results(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    now = datetime(2026, 5, 27, tzinfo=timezone.utc)
    jobs = [
        JobRecord(
            id="9" * 32,
            audit_type="subdomain_inventory_basic",
            file_id=None,
            target_domain="queued.example",
            status="queued",
            created_at=now,
            updated_at=now,
        ),
        JobRecord(
            id="a1" * 16,
            audit_type="subdomain_inventory_basic",
            file_id=None,
            target_domain="running.example",
            status="running",
            created_at=now,
            updated_at=now,
        ),
        JobRecord(
            id="b2" * 16,
            audit_type="subdomain_inventory_basic",
            file_id=None,
            target_domain="failed.example",
            status="failed",
            created_at=now,
            updated_at=now,
            error="Subdomain inventory runner failed safely.",
        ),
        JobRecord(
            id="c3" * 16,
            audit_type="subdomain_inventory_basic",
            file_id=None,
            target_domain="sparse.example",
            status="completed",
            created_at=now,
            updated_at=now,
            result={
                "analyzer": "subdomain_inventory_basic",
                "target": {"normalized_root_domain": "sparse.example"},
                "summary": {"truncated": False, "deadline_reached": False},
            },
        ),
    ]
    for job in jobs:
        app.state.jobs.save(job)
    expected = {
        "markdown": "text/markdown",
        "html": "text/html",
        "xml": "application/xml",
        "pdf": "application/pdf",
    }
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        for job in jobs:
            for report_format, content_type in expected.items():
                response = await client.get(f"/jobs/{job.id}/export/{report_format}")

                assert response.status_code == 200
                assert response.headers["content-type"].startswith(content_type)
                if report_format == "xml":
                    root = ElementTree.fromstring(response.text)
                    assert root.findtext("./job/status") == job.status
                    assert root.findtext("./job/auditType") == "subdomain_inventory_basic"
                    assert root.findtext("./job/targetDomain") == job.target_domain
                elif report_format == "pdf":
                    assert response.content.startswith(b"%PDF")
                else:
                    assert job.status in response.text
                    assert job.target_domain in response.text


@pytest.mark.anyio
async def test_export_returns_404_for_missing_job(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get(f"/jobs/{'f' * 32}/export/html")

    assert response.status_code == 404


@pytest.mark.anyio
async def test_export_rejects_invalid_job_id(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get("/jobs/../../etc/passwd/export/html")
        invalid_response = await client.get("/jobs/not-a-job/export/html")

    assert response.status_code in {400, 404}
    assert invalid_response.status_code == 400


@pytest.mark.anyio
async def test_export_cyclonedx_sbom_for_manifest_job(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    job = save_export_fixture_job()
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get(f"/jobs/{job.id}/sbom/cyclonedx-json")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/vnd.cyclonedx+json")
    assert response.headers["content-disposition"] == f'attachment; filename="inspectra-job-{job.id}-cyclonedx.json"'
    payload = response.json()
    assert payload["bomFormat"] == "CycloneDX"
    assert payload["metadata"]["component"]["name"] == "<script>alert('x')</script>"
    assert payload["components"][0]["name"] == "react"
    assert payload["components"][0]["purl"] == "pkg:npm/react"
    assert "vulnerabilities" not in json.dumps(payload).lower()


@pytest.mark.anyio
async def test_export_spdx_sbom_for_manifest_job(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    job = save_export_fixture_job()
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get(f"/jobs/{job.id}/sbom/spdx-json")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/spdx+json")
    assert response.headers["content-disposition"] == f'attachment; filename="inspectra-job-{job.id}-spdx.json"'
    payload = response.json()
    assert payload["spdxVersion"] == "SPDX-2.3"
    assert payload["packages"][0]["name"] == "react"
    assert payload["packages"][0]["downloadLocation"] == "NOASSERTION"
    assert payload["packages"][0]["externalRefs"][0]["referenceLocator"] == "pkg:npm/react"
    assert "vulnerabilities" not in json.dumps(payload).lower()


@pytest.mark.anyio
async def test_export_sbom_for_project_archive_job(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    job = save_project_archive_export_fixture_job()
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        cyclonedx_response = await client.get(f"/jobs/{job.id}/sbom/cyclonedx-json")
        spdx_response = await client.get(f"/jobs/{job.id}/sbom/spdx-json")

    assert cyclonedx_response.status_code == 200
    cyclonedx = cyclonedx_response.json()
    assert cyclonedx["components"][0]["name"] == "react"
    assert find_cyclonedx_property(cyclonedx["components"][0], "inspectra:source_manifest") == "package.json"

    assert spdx_response.status_code == 200
    spdx = spdx_response.json()
    assert spdx["packages"][0]["name"] == "react"
    assert "source manifest: package.json" in spdx["packages"][0]["comment"]


@pytest.mark.anyio
async def test_sbom_export_rejects_incompatible_jobs(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    now = datetime(2026, 5, 26, tzinfo=timezone.utc)
    audit_types = ("pdf_basic", "image_basic", "archive_basic", "web_basic", "domain_basic", "subdomain_inventory_basic", "django_config_basic")
    job_ids: list[str] = []
    for index, audit_type in enumerate(audit_types, start=1):
        job_id = f"{index:x}" * 32
        job_ids.append(job_id)
        app.state.jobs.save(
            JobRecord(
                id=job_id,
                audit_type=audit_type,
                file_id=None if audit_type in {"web_basic", "domain_basic", "subdomain_inventory_basic"} else f"{index + 3:x}" * 32,
                target_url="https://example.com/" if audit_type == "web_basic" else None,
                target_domain="example.com" if audit_type in {"domain_basic", "subdomain_inventory_basic"} else None,
                status="completed",
                created_at=now,
                updated_at=now,
                result={"analyzer": audit_type, "hashes": {"sha256": "abc123"}},
            )
        )
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        responses = [await client.get(f"/jobs/{job_id}/sbom/cyclonedx-json") for job_id in job_ids]

    for response in responses:
        assert response.status_code == 400
        assert response.json()["detail"] == "SBOM export is only available for dependency manifest jobs"


@pytest.mark.anyio
async def test_sbom_export_requires_completed_manifest_job(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    now = datetime(2026, 5, 26, tzinfo=timezone.utc)
    job = JobRecord(
        id="9" * 32,
        audit_type="manifest_basic",
        file_id="8" * 32,
        status="running",
        created_at=now,
        updated_at=now,
        result={"analyzer": "manifest_basic"},
    )
    app.state.jobs.save(job)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get(f"/jobs/{job.id}/sbom/spdx-json")

    assert response.status_code == 409
    assert response.json()["detail"] == "SBOM export requires a completed manifest analysis job"


@pytest.mark.anyio
async def test_sbom_export_rejects_missing_and_invalid_job_ids(monkeypatch, tmp_path):
    configure_test_state(monkeypatch, tmp_path)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        missing_response = await client.get(f"/jobs/{'f' * 32}/sbom/cyclonedx-json")
        traversal_response = await client.get("/jobs/../../etc/passwd/sbom/cyclonedx-json")
        invalid_response = await client.get("/jobs/not-a-job/sbom/cyclonedx-json")

    assert missing_response.status_code == 404
    assert traversal_response.status_code in {400, 404}
    assert invalid_response.status_code == 400


def test_sbom_helpers_normalize_npm_dependencies():
    job = save_standalone_job(
        manifest_type="package_json",
        dependencies={
            "dependencies": [
                {"name": "react", "specifier": "^18.3.1"},
                {"name": "@scope/pkg", "specifier": "1.2.3"},
            ]
        },
        original_filename="package.json",
    )

    components = extract_components_from_job(job)
    cyclonedx = json.loads(generate_cyclonedx_json(job))

    assert components[0].ecosystem == "npm"
    assert components[0].declared_requirement == "react: ^18.3.1"
    assert components[0].dependency_source_type == "registry"
    assert components[0].package_url == "pkg:npm/react"
    assert components[1].package_url == "pkg:npm/%40scope/pkg@1.2.3"
    react_component = cyclonedx_component_by_name(cyclonedx, "react")
    assert react_component["name"] == "react"
    assert "version" not in react_component
    assert find_cyclonedx_property(react_component, "inspectra:dependency_source_type") == "registry"


def test_sbom_helpers_omit_purl_for_ambiguous_npm_sources():
    job = save_standalone_job(
        manifest_type="package_json",
        dependencies={
            "dependencies": [
                {"name": "local-lib", "specifier": "file:../local-lib"},
                {"name": "workspace-lib", "specifier": "workspace:*"},
                {"name": "git-lib", "specifier": "git+https://example.invalid/git-lib.git"},
                {"name": "tarball-lib", "specifier": "https://example.invalid/tarball-lib.tgz"},
                {"name": "repo-lib", "specifier": "github:user/repo"},
                {"name": "alias-lib", "specifier": "npm:real-package@1.2.3"},
            ]
        },
        original_filename="package.json",
    )

    components = {component.name: component for component in extract_components_from_job(job)}
    cyclonedx = json.loads(generate_cyclonedx_json(job))

    expected_sources = {
        "local-lib": "local",
        "workspace-lib": "workspace",
        "git-lib": "vcs",
        "tarball-lib": "url",
        "repo-lib": "vcs",
        "alias-lib": "alias",
    }
    for name, source_type in expected_sources.items():
        component = components[name]
        cyclonedx_component = cyclonedx_component_by_name(cyclonedx, name)
        assert component.package_url is None
        assert component.dependency_source_type == source_type
        assert "purl" not in cyclonedx_component
        assert find_cyclonedx_property(cyclonedx_component, "inspectra:dependency_source_type") == source_type
        assert find_cyclonedx_property(cyclonedx_component, "inspectra:purl_omitted_reason")


def test_sbom_helpers_normalize_python_requirements():
    job = save_standalone_job(
        manifest_type="requirements_txt",
        dependencies={
            "dependencies": [
                {"name": "fastapi", "specifier": "==0.115.0", "source": "line 1"},
                {"name": "httpx", "specifier": ">=0.27", "source": "line 2"},
            ]
        },
        original_filename="requirements.txt",
    )

    components = extract_components_from_job(job)

    assert components[0].ecosystem == "pypi"
    assert components[0].declared_requirement == "fastapi==0.115.0"
    assert components[0].package_url == "pkg:pypi/fastapi@0.115.0"
    assert components[1].declared_requirement == "httpx>=0.27"
    assert components[1].package_url == "pkg:pypi/httpx"


def test_sbom_helpers_omit_purl_for_ambiguous_python_requirements():
    job = save_standalone_job(
        manifest_type="requirements_txt",
        dependencies={
            "dependencies": [
                {"name": "editable-reference", "specifier": "-e .", "declared_requirement": "-e .", "source_type": "editable"},
                {
                    "name": "demo",
                    "specifier": "@ git+https://example.invalid/demo.git",
                    "declared_requirement": "demo @ git+https://example.invalid/demo.git",
                },
                {
                    "name": "localpkg",
                    "specifier": "@ file:///tmp/localpkg.whl",
                    "declared_requirement": "localpkg @ file:///tmp/localpkg.whl",
                },
                {
                    "name": "wheelpkg",
                    "specifier": "@ https://example.invalid/wheelpkg.whl",
                    "declared_requirement": "wheelpkg @ https://example.invalid/wheelpkg.whl",
                },
                {"name": "./local-package", "specifier": "./local-package", "declared_requirement": "./local-package"},
            ]
        },
        original_filename="requirements.txt",
    )

    components = {component.name: component for component in extract_components_from_job(job)}
    spdx = json.loads(generate_spdx_json(job))

    expected_sources = {
        "editable-reference": "editable",
        "demo": "vcs",
        "localpkg": "local",
        "wheelpkg": "url",
        "./local-package": "local",
    }
    for name, source_type in expected_sources.items():
        component = components[name]
        spdx_package_payload = spdx_package_by_name(spdx, name)
        assert component.package_url is None
        assert component.dependency_source_type == source_type
        assert "externalRefs" not in spdx_package_payload
        assert f"dependency source type: {source_type}" in spdx_package_payload["comment"]
        assert "Package URL omitted:" in spdx_package_payload["comment"]


def test_sbom_helpers_omit_purl_for_ambiguous_pyproject_sources():
    job = save_standalone_job(
        manifest_type="pyproject_toml",
        dependencies={
            "dependencies": [
                {"name": "fastapi", "specifier": ">=0.115", "declared_requirement": "fastapi>=0.115"},
                {
                    "name": "demo",
                    "specifier": "@ https://example.invalid/demo.whl",
                    "declared_requirement": "demo @ https://example.invalid/demo.whl",
                },
                {
                    "name": "localpkg",
                    "specifier": "path = ../localpkg",
                    "declared_requirement": "localpkg: path = ../localpkg",
                },
            ]
        },
        original_filename="pyproject.toml",
    )

    components = {component.name: component for component in extract_components_from_job(job)}
    cyclonedx = json.loads(generate_cyclonedx_json(job))

    assert components["fastapi"].package_url == "pkg:pypi/fastapi"
    for name, source_type in {"demo": "url", "localpkg": "local"}.items():
        component = components[name]
        cyclonedx_component = cyclonedx_component_by_name(cyclonedx, name)
        assert component.package_url is None
        assert component.dependency_source_type == source_type
        assert "purl" not in cyclonedx_component
        assert find_cyclonedx_property(cyclonedx_component, "inspectra:purl_omitted_reason")


def test_sbom_helpers_normalize_pyproject_from_project_archive():
    now = datetime(2026, 5, 26, tzinfo=timezone.utc)
    job = JobRecord(
        id="b" * 32,
        audit_type="project_archive_basic",
        file_id="7" * 32,
        status="completed",
        created_at=now,
        updated_at=now,
        result={
            "analyzer": "project_archive_basic",
            "parsed_manifests": [
                {
                    "path": "services/api/pyproject.toml",
                    "manifest_type": "pyproject_toml",
                    "parsed": {
                        "project": {"name": "api"},
                        "dependencies": {"dependencies": [{"name": "requests", "specifier": ">=2.31"}]},
                    },
                }
            ],
        },
    )

    components = extract_components_from_job(job)

    assert components[0].ecosystem == "pypi"
    assert components[0].source_manifest_path == "services/api/pyproject.toml"
    assert components[0].declared_requirement == "requests>=2.31"


def test_sbom_helpers_apply_conservative_purl_policy_to_project_archives():
    now = datetime(2026, 5, 26, tzinfo=timezone.utc)
    job = JobRecord(
        id="b" * 32,
        audit_type="project_archive_basic",
        file_id="7" * 32,
        status="completed",
        created_at=now,
        updated_at=now,
        result={
            "analyzer": "project_archive_basic",
            "parsed_manifests": [
                {
                    "path": "web/package.json",
                    "manifest_type": "package_json",
                    "parsed": {
                        "project": {"name": "web"},
                        "dependencies": {
                            "dependencies": [
                                {"name": "react", "specifier": "^18.3.1"},
                                {"name": "local-lib", "specifier": "file:../local-lib"},
                            ]
                        },
                    },
                },
                {
                    "path": "api/requirements.txt",
                    "manifest_type": "requirements_txt",
                    "parsed": {
                        "project": {},
                        "dependencies": {
                            "dependencies": [
                                {
                                    "name": "demo",
                                    "specifier": "@ git+https://example.invalid/demo.git",
                                    "declared_requirement": "demo @ git+https://example.invalid/demo.git",
                                }
                            ]
                        },
                    },
                },
            ],
        },
    )

    components = {component.name: component for component in extract_components_from_job(job)}

    assert components["react"].package_url == "pkg:npm/react"
    assert components["react"].source_manifest_path == "web/package.json"
    assert components["local-lib"].package_url is None
    assert components["local-lib"].source_manifest_path == "web/package.json"
    assert components["demo"].package_url is None
    assert components["demo"].dependency_source_type == "vcs"
    assert components["demo"].source_manifest_path == "api/requirements.txt"


def find_cyclonedx_property(component: dict, name: str) -> str | None:
    for prop in component.get("properties", []):
        if prop.get("name") == name:
            return prop.get("value")
    return None


def cyclonedx_component_by_name(payload: dict, name: str) -> dict:
    for component in payload["components"]:
        if component.get("name") == name:
            return component
    raise AssertionError(f"CycloneDX component not found: {name}")


def spdx_package_by_name(payload: dict, name: str) -> dict:
    for package in payload["packages"]:
        if package.get("name") == name:
            return package
    raise AssertionError(f"SPDX package not found: {name}")


def save_standalone_job(manifest_type: str, dependencies: dict, original_filename: str) -> JobRecord:
    now = datetime(2026, 5, 26, tzinfo=timezone.utc)
    return JobRecord(
        id="a" * 32,
        audit_type="manifest_basic",
        file_id="6" * 32,
        status="completed",
        created_at=now,
        updated_at=now,
        result={
            "analyzer": "manifest_basic",
            "manifest_type": manifest_type,
            "file_identification": {"original_filename": original_filename},
            "parsed": {"project": {"name": "demo"}, "dependencies": dependencies, "scripts": {}, "engines": {}},
            "summary": {"total_dependencies": sum(len(items) for items in dependencies.values())},
            "findings": [],
            "errors": [],
        },
    )


def save_export_fixture_job() -> JobRecord:
    now = datetime(2026, 5, 26, tzinfo=timezone.utc)
    job = JobRecord(
        id="e" * 32,
        audit_type="manifest_basic",
        file_id="1" * 32,
        status="completed",
        created_at=now,
        updated_at=now,
        result={
            "analyzer": "manifest_basic",
            "completed_at": now.isoformat(),
            "manifest_type": "package_json",
            "hashes": {"sha256": "abc123"},
            "file_identification": {"size_bytes": 128, "original_filename": "package.json"},
            "parsed": {
                "project": {"name": "<script>alert('x')</script>", "version": "1.0.0"},
                "dependencies": {"dependencies": [{"name": "react", "specifier": "^18.3.1"}]},
                "scripts": {"postinstall": "node setup.js"},
            },
            "summary": {"total_dependencies": 1, "dependency_groups": ["dependencies"], "informational_findings_count": 1},
            "findings": [
                {
                    "id": "package_sensitive_lifecycle_script",
                    "title": "Lifecycle script should be reviewed",
                    "level": "medium",
                    "description": "Review before running package manager commands.",
                    "evidence": "postinstall: node setup.js",
                    "recommendation": "Confirm the script is expected.",
                }
            ],
            "errors": [],
        },
    )
    app.state.jobs.save(job)
    return job


def save_malicious_markdown_fixture_job() -> JobRecord:
    now = datetime(2026, 5, 26, tzinfo=timezone.utc)
    job = JobRecord(
        id="5" * 32,
        audit_type="manifest_basic",
        file_id="4" * 32,
        status="completed",
        created_at=now,
        updated_at=now,
        error="![x](https://evil.example/pixel.png)",
        result={
            "analyzer": "manifest_basic",
            "completed_at": now.isoformat(),
            "manifest_type": "requirements_txt",
            "hashes": {"sha256": "abc123"},
            "file_identification": {
                "size_bytes": 256,
                "original_filename": "[click me](https://evil.example)",
                "path_hint": "value | injected | column",
            },
            "parsed": {
                "project": {"name": '<img src="https://evil.example/pixel.png">'},
                "dependencies": {
                    "dependencies": [
                        {
                            "name": "# Fake Heading",
                            "specifier": "- fake item",
                            "declared_requirement": "demo @ git+https://evil.example/demo.git",
                        },
                        {"name": "> fake quote", "specifier": "value | injected | column"},
                    ]
                },
                "scripts": {"postinstall": "`inline`"},
            },
            "summary": {"total_dependencies": 2, "dependency_groups": ["dependencies"], "informational_findings_count": 1},
            "findings": [
                {
                    "id": "markdown_fixture",
                    "title": "[click me](https://evil.example)",
                    "level": "medium",
                    "description": "- fake item",
                    "evidence": "> fake quote",
                    "recommendation": "# Fake Heading",
                }
            ],
            "tool_outputs": {
                "fake_tool": {
                    "exit_code": 1,
                    "timed_out": False,
                    "stderr": "first line\n> fake quote\n```inside fenced content\nhttps://evil.example/log",
                }
            },
            "errors": ["<script>alert(1)</script>"],
        },
    )
    app.state.jobs.save(job)
    return job


def save_archive_export_fixture_job() -> JobRecord:
    now = datetime(2026, 5, 26, tzinfo=timezone.utc)
    job = JobRecord(
        id="d" * 32,
        audit_type="archive_basic",
        file_id="2" * 32,
        status="completed",
        created_at=now,
        updated_at=now,
        result={
            "analyzer": "archive_basic",
            "archive_type": "zip",
            "completed_at": now.isoformat(),
            "hashes": {"sha256": "abc123"},
            "file_identification": {"size_bytes": 512, "original_filename": "project.zip"},
            "summary": {
                "total_entries": 3,
                "total_uncompressed_bytes": 128,
                "total_compressed_bytes": 96,
                "directories": 1,
                "files": 2,
                "symlinks": 0,
                "hardlinks": 0,
                "executables": 0,
                "nested_archives": 1,
                "sensitive_name_matches": 1,
                "path_traversal_entries": 0,
                "absolute_path_entries": 0,
                "manifest_files_detected": 1,
                "findings_count": 2,
                "truncated": False,
            },
            "detected_manifests": [{"path": "package.json", "manifest_type": "package.json"}],
            "entries_sample": [
                {
                    "path": "package.json",
                    "type": "file",
                    "size": 64,
                    "compressed_size": 48,
                    "mode": "0o644",
                    "depth": 1,
                    "flags": {"manifest_file": True},
                }
            ],
            "findings": [
                {
                    "id": "archive_sensitive_name_entry",
                    "title": "Potentially sensitive filename detected",
                    "level": "medium",
                    "description": "Review this indicator manually.",
                    "evidence": ".env",
                    "recommendation": "Confirm the file should be present.",
                }
            ],
            "errors": [],
        },
    )
    app.state.jobs.save(job)
    return job


def save_project_archive_export_fixture_job() -> JobRecord:
    now = datetime(2026, 5, 26, tzinfo=timezone.utc)
    job = JobRecord(
        id="c" * 32,
        audit_type="project_archive_basic",
        file_id="3" * 32,
        status="completed",
        created_at=now,
        updated_at=now,
        result={
            "analyzer": "project_archive_basic",
            "archive_type": "zip",
            "completed_at": now.isoformat(),
            "hashes": {"sha256": "abc123"},
            "file_identification": {"size_bytes": 1024, "original_filename": "project.zip"},
            "summary": {
                "total_entries_seen": 4,
                "supported_manifests_found": 1,
                "supported_manifests_parsed": 1,
                "unsupported_manifests_detected": 1,
                "total_dependencies": 1,
                "dependency_groups": ["dependencies"],
                "findings_count": 1,
                "truncated": False,
            },
            "supported_manifests": [{"path": "package.json", "manifest_type": "package_json", "status": "parsed"}],
            "unsupported_manifests": [{"path": "package-lock.json", "manifest_type": "package-lock.json"}],
            "parsed_manifests": [
                {
                    "path": "package.json",
                    "manifest_type": "package_json",
                    "size_bytes": 128,
                    "parsed": {
                        "project": {"name": "demo"},
                        "dependencies": {"dependencies": [{"name": "react", "specifier": "^18.3.1"}]},
                        "scripts": {"postinstall": "node setup.js"},
                    },
                    "summary": {"total_dependencies": 1, "dependency_groups": ["dependencies"], "informational_findings_count": 1},
                    "findings": [],
                    "errors": [],
                }
            ],
            "findings": [
                {
                    "id": "package_sensitive_lifecycle_script",
                    "title": "Lifecycle script should be reviewed",
                    "level": "medium",
                    "description": "Review before running package manager commands.",
                    "evidence": "package.json: postinstall: node setup.js",
                    "recommendation": "Confirm the script is expected.",
                }
            ],
            "errors": [],
        },
    )
    app.state.jobs.save(job)
    return job


def save_web_export_fixture_job() -> JobRecord:
    now = datetime(2026, 5, 26, tzinfo=timezone.utc)
    job = JobRecord(
        id="8" * 32,
        audit_type="web_basic",
        file_id=None,
        target_url="https://example.com/callback?token=supersecret&page=1",
        status="completed",
        created_at=now,
        updated_at=now,
        result={
            "analyzer": "web_basic",
            "completed_at": now.isoformat(),
            "target": {
                "original_url": "https://example.com/callback?token=supersecret&page=1",
                "normalized_url": "https://example.com/callback?token=supersecret&page=1",
                "final_url": "https://example.com/callback?token=supersecret&page=1",
                "scheme": "https",
                "host": "example.com",
            },
            "http": {
                "status_code": 200,
                "redirects": [
                    {
                        "from_url": "https://example.com/start?token=supersecret",
                        "to_url": "https://example.com/callback?token=supersecret&page=1",
                        "status_code": 302,
                    }
                ],
                "response_headers": {
                    "Content-Type": "text/html",
                    "Server": "unit-test",
                    "Set-Cookie": "sid=supersecret; HttpOnly",
                    "Location": "https://example.com/callback?token=supersecret&page=1",
                },
                "content_type": "text/html",
                "bytes_read": 128,
            },
            "security_headers": {
                "Content-Security-Policy": {"present": False, "value": None},
                "X-Content-Type-Options": {"present": True, "value": "nosniff"},
            },
            "cookies": [{"name": "sid", "value_redacted": True, "value_length": 11, "secure": True, "httponly": True, "samesite": "Lax"}],
            "tls": {"present": True, "certificate": {"days_until_expiration": 90}, "errors": []},
            "robots_txt": {"checked": True, "present": True, "status_code": 200, "has_disallow": False},
            "security_txt": {"checked": True, "present": False, "status_code": 404, "fields": {}},
            "findings": [
                {
                    "id": "web_csp_missing",
                    "title": "Content-Security-Policy header is absent",
                    "level": "info",
                    "description": "Review hardening options.",
                    "evidence": "https://example.com/callback?token=supersecret&page=1",
                    "recommendation": "Consider adding CSP where appropriate.",
                }
            ],
            "summary": {
                "findings_count": 1,
                "missing_security_headers_count": 1,
                "cookies_count": 1,
                "redirects_count": 0,
                "tls_present": True,
                "security_txt_present": False,
                "robots_txt_present": True,
            },
            "errors": [],
        },
    )
    app.state.jobs.save(job)
    return job


def save_domain_export_fixture_job() -> JobRecord:
    now = datetime(2026, 5, 26, tzinfo=timezone.utc)
    job = JobRecord(
        id="9" * 32,
        audit_type="domain_basic",
        file_id=None,
        target_domain="example.com",
        status="completed",
        created_at=now,
        updated_at=now,
        result={
            "analyzer": "domain_basic",
            "target": {
                "domain": "example.com",
                "normalized_domain": "example.com",
                "checked_at": now.isoformat(),
            },
            "dns": {
                "A": ["93.184.216.34"],
                "AAAA": [],
                "CNAME": [],
                "MX": [{"preference": 10, "exchange": "mail.example.com"}],
                "NS": ["ns1.example.com", "ns2.example.com"],
                "TXT": ["v=spf1 -all"],
                "CAA": [{"flags": 0, "tag": "issue", "value": "letsencrypt.org"}],
                "SOA": [{"mname": "ns1.example.com", "rname": "hostmaster.example.com", "serial": 1}],
                "www": {"checked": True, "domain": "www.example.com", "CNAME": ["example.com"], "errors": []},
            },
            "email_security": {
                "spf": {"present": True, "record_count": 1, "all_mechanism": "-all", "records": ["v=spf1 -all"]},
                "dmarc": {"present": True, "record_count": 1, "policy": "reject", "records": ["v=DMARC1; p=reject"]},
                "dkim": {"checked": False, "status": "not_checked"},
            },
            "findings": [{"id": "domain_caa_absent", "title": "CAA records were not observed", "level": "info"}],
            "summary": {
                "records_found_count": 7,
                "findings_count": 1,
                "spf_present": True,
                "dmarc_present": True,
                "dmarc_policy": "reject",
                "caa_present": True,
                "mx_present": True,
                "www_resolves": True,
            },
            "errors": [],
        },
    )
    app.state.jobs.save(job)
    return job


def save_subdomain_inventory_export_fixture_job() -> JobRecord:
    now = datetime(2026, 5, 26, tzinfo=timezone.utc)
    job = JobRecord(
        id="8" * 32,
        audit_type="subdomain_inventory_basic",
        file_id=None,
        target_domain="example.com",
        status="completed",
        created_at=now,
        updated_at=now,
        result={
            "analyzer": "subdomain_inventory_basic",
            "target": {
                "root_domain": "example.com",
                "normalized_root_domain": "example.com",
                "checked_at": now.isoformat(),
            },
            "summary": {
                "candidates_submitted": 4,
                "candidates_accepted": 3,
                "candidates_rejected": 1,
                "candidates_processed": 2,
                "candidates_pending": 1,
                "resolved_count": 1,
                "unresolved_count": 1,
                "cname_count": 1,
                "private_ip_count": 1,
                "findings_count": 3,
                "wildcard_dns_possible": False,
                "truncated": True,
                "deadline_reached": True,
            },
            "limits": {
                "global_deadline_seconds": 30,
                "dns_timeout_seconds": 5,
                "max_candidates": 100,
                "wildcard_checks": 2,
            },
            "candidates": [
                {"input": "www", "fqdn": "www.example.com", "status": "accepted"},
                {"input": "api.example.com", "fqdn": "api.example.com", "status": "accepted"},
                {"input": "cdn", "fqdn": "cdn.example.com", "status": "accepted"},
                {"input": "api.evil.com", "fqdn": None, "status": "rejected", "rejection_reason": "outside root"},
            ],
            "results": [
                {
                    "fqdn": "www.example.com",
                    "resolves": True,
                    "status": "processed",
                    "A": ["192.168.1.10"],
                    "AAAA": [],
                    "CNAME": ["example.net"],
                    "private_or_reserved_ip_detected": True,
                    "errors": [],
                },
                {
                    "fqdn": "api.example.com",
                    "resolves": False,
                    "status": "processed",
                    "A": [],
                    "AAAA": [],
                    "CNAME": [],
                    "private_or_reserved_ip_detected": False,
                    "errors": ["A query failed safely."],
                },
                {
                    "fqdn": "cdn.example.com",
                    "resolves": False,
                    "status": "skipped",
                    "skip_reason": "global_deadline_reached",
                    "deadline_reached": True,
                    "A": [],
                    "AAAA": [],
                    "CNAME": [],
                    "private_or_reserved_ip_detected": False,
                    "errors": ["Skipped because the global subdomain inventory deadline was reached."],
                },
            ],
            "wildcard_dns": {"checked": True, "possible": False, "probes_count": 2, "notes": "heuristic", "errors": []},
            "findings": [
                {"id": "subdomain_private_or_reserved_ip", "title": "Private IP", "level": "low"},
                {"id": "subdomain_external_cname", "title": "External CNAME", "level": "info"},
                {"id": "subdomain_global_deadline_reached", "title": "Deadline reached", "level": "low"},
            ],
            "truncation_reason": "global_deadline_reached",
            "errors": [],
        },
    )
    app.state.jobs.save(job)
    return job


def save_django_config_export_fixture_job() -> JobRecord:
    now = datetime(2026, 5, 26, tzinfo=timezone.utc)
    job = JobRecord(
        id="d" * 32,
        audit_type="django_config_basic",
        file_id="4" * 32,
        status="completed",
        created_at=now,
        updated_at=now,
        result={
            "analyzer": "django_config_basic",
            "archive_type": "zip",
            "completed_at": now.isoformat(),
            "hashes": {"sha256": "abc123"},
            "file_identification": {"size_bytes": 2048, "original_filename": "django.zip"},
            "limits": {"max_files": 100, "max_file_bytes": 524288, "max_total_bytes": 2097152},
            "summary": {
                "files_considered": 2,
                "files_read": 1,
                "settings_files_detected": 1,
                "deployment_files_detected": 0,
                "env_files_detected": 1,
                "findings_count": 2,
                "secrets_redacted_count": 1,
                "truncated": False,
            },
            "detected_files": [
                {"path": "project/settings.py", "category": "django_config", "read": True, "size_bytes": 128, "context": "production"},
                {"path": ".env", "category": "env_sensitive", "read": False, "skip_reason": "sensitive_env_not_read"},
            ],
            "django_signals": {
                "debug": {"status": "enabled_or_default_true", "files": ["project/settings.py"]},
                "secret_key": {"status": "hardcoded", "files": ["project/settings.py"]},
            },
            "findings": [
                {
                    "id": "django_debug_enabled",
                    "title": "Django DEBUG appears enabled or defaults to true",
                    "level": "medium",
                    "description": "Review production settings.",
                    "evidence": "DEBUG = True",
                    "recommendation": "Set DEBUG=False in production.",
                    "file_path": "project/settings.py",
                    "context": "production",
                },
                {
                    "id": "django_secret_key_hardcoded",
                    "title": "Django SECRET_KEY appears hardcoded",
                    "level": "medium",
                    "description": "Review production secrets.",
                    "evidence": "SECRET_KEY = [REDACTED]",
                    "recommendation": "Load SECRET_KEY from a protected environment secret.",
                    "context": "grouped",
                },
            ],
            "errors": [],
        },
    )
    app.state.jobs.save(job)
    return job


def make_zip_bytes(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return buffer.getvalue()


def make_tar_bytes(entries: dict[str, bytes], *, gzipped: bool = False) -> bytes:
    buffer = io.BytesIO()
    mode = "w:gz" if gzipped else "w"
    with tarfile.open(fileobj=buffer, mode=mode) as archive:
        for name, content in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
    return buffer.getvalue()
