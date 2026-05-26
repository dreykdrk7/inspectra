from datetime import datetime, timedelta, timezone
import io
import json
import tarfile
from xml.etree import ElementTree
import zipfile

import pytest
from httpx import ASGITransport, AsyncClient

from app.config import load_settings
from app.main import app
from app.models import JobRecord
from app.services import ArchiveAuditService, ImageAuditService, ManifestAuditService, PdfAuditService, ProjectArchiveAuditService
from app.storage import FileStore, JobStore


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
    assert "&lt;script&gt;alert('x')&lt;/script&gt;" in response.text


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
