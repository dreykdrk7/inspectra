#!/usr/bin/env python3
"""Validate Inspectra's CVSS v4 evaluator against a pinned FIRST corpus.

This command performs no network access. The operator must supply a checkout of
FIRST's ``cvss-resources`` repository at the documented commit; exact file
digests prevent a different corpus from being accepted accidentally.
"""

from __future__ import annotations

import argparse
import ast
from dataclasses import dataclass
import hashlib
from pathlib import Path
import sys
from typing import Iterable


REPOSITORY_COMMIT = "fe21348d442bb91281f991f181f829c95de4af7b"
EXPECTED_FILES = {
    "macro-scores": "b55926940d4fbb073a0d30a98d6983de93f4542209eee936a671713387f92213",
    "base-threat-scores": "2695a9b8664608dbf589d48cc8f5cb3f136c7a20d180fa8a54787810c2566ba3",
    "reference-scores": "3b60f12899249bf8b48e01ff0aba451f052a836b22c6a3ffd880b7a5cc2fea4f",
    "reference-vectors": "fdcb3de3485354ff36577b41b2fcf7f8056785fb6d6bf6c6eed97e7d3bc934bf",
}
MAX_FILE_BYTES = 96 * 1024 * 1024
MAX_LINE_BYTES = 2_048


@dataclass(frozen=True)
class CorpusResult:
    supported: int = 0
    unknown: int = 0
    invalid_markers: int = 0
    mismatches: int = 0

    def add(self, other: "CorpusResult") -> "CorpusResult":
        return CorpusResult(
            supported=self.supported + other.supported,
            unknown=self.unknown + other.unknown,
            invalid_markers=self.invalid_markers + other.invalid_markers,
            mismatches=self.mismatches + other.mismatches,
        )


EXPECTED_RESULTS = {
    "macro": CorpusResult(supported=270),
    "base-threat": CorpusResult(supported=419_904),
    "reference": CorpusResult(supported=41_270, unknown=25_028, invalid_markers=33),
}


def _sha256(path: Path) -> str:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError(f"unsafe corpus file: {path.name}")
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _checked_lines(path: Path) -> Iterable[str]:
    size = path.stat().st_size
    if not path.is_file() or path.is_symlink() or size > MAX_FILE_BYTES:
        raise ValueError(f"unsafe corpus file: {path.name}")
    with path.open("r", encoding="utf-8", newline="") as source:
        for line_number, line in enumerate(source, start=1):
            if len(line.encode("utf-8")) > MAX_LINE_BYTES:
                raise ValueError(f"oversized corpus line: {path.name}:{line_number}")
            yield line.rstrip("\r\n")


def _load_score_records(path: Path) -> Iterable[tuple[str, float]]:
    for line_number, line in enumerate(_checked_lines(path), start=1):
        try:
            record = ast.literal_eval(line)
        except (SyntaxError, ValueError) as exc:
            raise ValueError(f"invalid score record: {path.name}:{line_number}") from exc
        if (
            not isinstance(record, dict)
            or set(record) != {"vector", "score", "severity"}
            or not isinstance(record["vector"], str)
            or not isinstance(record["score"], (int, float))
            or isinstance(record["score"], bool)
            or not isinstance(record["severity"], str)
        ):
            raise ValueError(f"unexpected score record: {path.name}:{line_number}")
        yield record["vector"], float(record["score"])


def _score_records(records: Iterable[tuple[str, float]]) -> CorpusResult:
    from app.cvss import assess_cvss_v4_vector

    result = CorpusResult()
    for vector, expected in records:
        assessment = assess_cvss_v4_vector(vector)
        if assessment.base_score is None:
            result = result.add(CorpusResult(unknown=1))
        elif assessment.base_score != expected:
            result = result.add(CorpusResult(mismatches=1))
        else:
            result = result.add(CorpusResult(supported=1))
    return result


def _score_rejected_vectors(vectors: Iterable[str]) -> CorpusResult:
    from app.cvss import assess_cvss_v4_vector

    result = CorpusResult()
    for vector in vectors:
        assessment = assess_cvss_v4_vector(vector)
        result = result.add(
            CorpusResult(unknown=1)
            if assessment.base_score is None
            else CorpusResult(mismatches=1)
        )
    return result


def _score_reference(vector_path: Path, score_path: Path) -> CorpusResult:
    vectors = list(_checked_lines(vector_path))
    scores = list(_checked_lines(score_path))
    if len(vectors) != len(scores):
        raise ValueError("reference vector and score counts differ")
    records: list[tuple[str, float]] = []
    rejected_vectors: list[str] = []
    invalid_markers = 0
    for line_number, (_, score) in enumerate(zip(vectors, scores), start=1):
        if score == "Invalid vector string":
            invalid_markers += 1
            continue
        try:
            record = ast.literal_eval(score)
        except (SyntaxError, ValueError) as exc:
            raise ValueError(f"invalid reference score:{line_number}") from exc
        if (
            isinstance(record, dict)
            and set(record) == {"vector", "score", "severity", "error"}
            and isinstance(record["vector"], str)
            and record["score"] == "error"
            and record["severity"] == "error"
            and isinstance(record["error"], str)
        ):
            rejected_vectors.append(record["vector"])
            continue
        if (
            not isinstance(record, dict)
            or set(record) != {"vector", "score", "severity"}
            or not isinstance(record["vector"], str)
            or not isinstance(record["score"], (int, float))
            or isinstance(record["score"], bool)
            or not isinstance(record["severity"], str)
        ):
            raise ValueError(f"unexpected reference score:{line_number}")
        records.append((record["vector"], float(record["score"])))
    return (
        _score_records(records)
        .add(_score_rejected_vectors(rejected_vectors))
        .add(CorpusResult(invalid_markers=invalid_markers))
    )


def validate(corpus_root: Path) -> dict[str, CorpusResult]:
    vector_root = corpus_root.resolve() / "vectorFiles"
    for filename, expected_digest in EXPECTED_FILES.items():
        path = vector_root / filename
        if _sha256(path) != expected_digest:
            raise ValueError(f"digest mismatch: {filename}")
    results = {
        "macro": _score_records(_load_score_records(vector_root / "macro-scores")),
        "base-threat": _score_records(_load_score_records(vector_root / "base-threat-scores")),
        "reference": _score_reference(
            vector_root / "reference-vectors", vector_root / "reference-scores"
        ),
    }
    for name, expected in EXPECTED_RESULTS.items():
        if results[name] != expected:
            raise ValueError(f"unexpected validation result for {name}: {results[name]}")
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus_root", type=Path)
    args = parser.parse_args()
    backend_root = Path(__file__).resolve().parents[1] / "backend"
    sys.path.insert(0, str(backend_root))
    try:
        results = validate(args.corpus_root)
    except (OSError, ValueError) as exc:
        print(f"CVSS_V4_CORPUS_INVALID: {exc}", file=sys.stderr)
        return 2
    total = CorpusResult()
    for name, result in results.items():
        total = total.add(result)
        print(
            f"{name}: supported={result.supported} unknown={result.unknown} "
            f"invalid_markers={result.invalid_markers} mismatches={result.mismatches}"
        )
    print(
        f"total: supported={total.supported} unknown={total.unknown} "
        f"invalid_markers={total.invalid_markers} mismatches={total.mismatches}"
    )
    return 1 if total.mismatches else 0


if __name__ == "__main__":
    raise SystemExit(main())
