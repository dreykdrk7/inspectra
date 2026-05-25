from datetime import datetime, timedelta, timezone

import pytest
from httpx import ASGITransport, AsyncClient

from app.config import load_settings
from app.main import app
from app.models import JobRecord
from app.services import PdfAuditService
from app.storage import FileStore, JobStore


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
    assert payload["stored_filename"].endswith(".pdf")
    assert (tmp_path / "uploads" / payload["stored_filename"]).exists()


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
