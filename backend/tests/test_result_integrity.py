import json

import pytest
from fastapi import HTTPException

from app.config import load_settings
from app.storage import JobStore, RESULT_INTEGRITY_CONTRACT_VERSION


def store(monkeypatch, tmp_path):
    monkeypatch.setenv("INSPECTRA_DATA_DIR", str(tmp_path))
    settings = load_settings()
    settings.ensure_directories()
    return settings, JobStore(settings)


def completed_job(jobs: JobStore):
    job = jobs.create_project_archive_job(
        "a" * 32,
        owner_id="owner-a",
        project_id="b" * 32,
        source_sha256="c" * 64,
    )
    return jobs.update(
        job.id,
        status="completed",
        result={
            "summary": {"supported_manifests_found": 0},
            "normalized_findings": [],
            "diagnostic": "Authorization: Bearer result-integrity-secret",
        },
    )


def test_result_is_redacted_before_canonical_integrity_seal_and_survives_json_reordering(monkeypatch, tmp_path):
    settings, jobs = store(monkeypatch, tmp_path)
    job = completed_job(jobs)
    path = settings.jobs_dir / f"{job.id}.json"
    payload = json.loads(path.read_text(encoding="utf-8"))

    assert payload["_result_integrity"]["contract_version"] == RESULT_INTEGRITY_CONTRACT_VERSION
    assert len(payload["_result_integrity"]["sha256"]) == 64
    assert "result-integrity-secret" not in json.dumps(payload)
    assert payload["result"]["diagnostic"] == "Authorization: [REDACTED]"
    assert jobs.get(job.id).result_integrity_status == "valid"
    assert jobs.get_list_item(job.id).result_integrity_status == "valid"

    path.write_text(json.dumps(payload, indent=3, sort_keys=False), encoding="utf-8")
    assert JobStore(settings).get(job.id).result_integrity_status == "valid"


@pytest.mark.parametrize("field,value", [("owner_id", "owner-b"), ("result", {"normalized_findings": []})])
def test_integrity_mismatch_fails_closed_with_a_generic_error(monkeypatch, tmp_path, field, value):
    settings, jobs = store(monkeypatch, tmp_path)
    job = completed_job(jobs)
    path = settings.jobs_dir / f"{job.id}.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload[field] = value
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(HTTPException) as raised:
        JobStore(settings).get(job.id)

    assert raised.value.status_code == 409
    assert raised.value.detail == "Stored result integrity check failed."
    assert str(tmp_path) not in raised.value.detail
    assert "owner" not in raised.value.detail.lower()


def test_legacy_result_without_an_envelope_is_readable_but_explicitly_unknown(monkeypatch, tmp_path):
    settings, jobs = store(monkeypatch, tmp_path)
    job = completed_job(jobs)
    path = settings.jobs_dir / f"{job.id}.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload.pop("_result_integrity")
    payload.pop("result_integrity_status")
    path.write_text(json.dumps(payload), encoding="utf-8")

    legacy = JobStore(settings).get(job.id)

    assert legacy.result is not None
    assert legacy.result_integrity_status == "unknown"


def test_invalid_stored_metadata_does_not_disclose_the_artifact_path(monkeypatch, tmp_path):
    settings, jobs = store(monkeypatch, tmp_path)
    job = completed_job(jobs)
    path = settings.jobs_dir / f"{job.id}.json"
    path.write_text("{not-valid-json", encoding="utf-8")

    with pytest.raises(HTTPException) as raised:
        JobStore(settings).get(job.id)

    assert raised.value.status_code == 500
    assert raised.value.detail == "Stored job metadata is invalid."
    assert str(path) not in raised.value.detail
    assert job.id not in raised.value.detail
