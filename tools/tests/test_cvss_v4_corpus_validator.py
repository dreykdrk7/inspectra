from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

import validate_cvss_v4_corpus as validator


VECTOR = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"


def _write_tiny_corpus(root: Path) -> dict[str, str]:
    vector_root = root / "vectorFiles"
    vector_root.mkdir()
    record = repr({"vector": VECTOR, "score": 9.3, "severity": "Critical"}) + "\n"
    contents = {
        "macro-scores": record,
        "base-threat-scores": record,
        "reference-scores": f"{record}Invalid vector string\n",
        "reference-vectors": f"{VECTOR}\ninvalid\n",
    }
    for name, content in contents.items():
        (vector_root / name).write_text(content, encoding="utf-8")
    return {name: hashlib.sha256(content.encode()).hexdigest() for name, content in contents.items()}


def test_validator_checks_pinned_files_and_expected_outcomes(tmp_path, monkeypatch):
    digests = _write_tiny_corpus(tmp_path)
    monkeypatch.setattr(validator, "EXPECTED_FILES", digests)
    monkeypatch.setattr(
        validator,
        "EXPECTED_RESULTS",
        {
            "macro": validator.CorpusResult(supported=1),
            "base-threat": validator.CorpusResult(supported=1),
            "reference": validator.CorpusResult(supported=1, invalid_markers=1),
        },
    )

    assert validator.validate(tmp_path) == validator.EXPECTED_RESULTS


def test_validator_fails_closed_when_a_pinned_file_changes(tmp_path, monkeypatch):
    digests = _write_tiny_corpus(tmp_path)
    monkeypatch.setattr(validator, "EXPECTED_FILES", digests)
    with (tmp_path / "vectorFiles" / "macro-scores").open("a", encoding="utf-8") as output:
        output.write("unexpected\n")

    with pytest.raises(ValueError, match="digest mismatch: macro-scores"):
        validator.validate(tmp_path)
