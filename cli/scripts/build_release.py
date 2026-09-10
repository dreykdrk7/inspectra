#!/usr/bin/env python3
"""Build and compare two local CLI distributions without publishing them."""

from __future__ import annotations

import argparse
from io import BytesIO
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import tarfile
from pathlib import PurePosixPath


SOURCE_DATE_EPOCH = "315532800"
MAX_SDIST_BYTES = 20 * 1024 * 1024


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _build(python: str, source: Path, destination: Path) -> None:
    work_source = destination.parent / "source"
    shutil.copytree(
        source,
        work_source,
        ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache", "*.egg-info", "build", "dist"),
    )
    destination.mkdir()
    environment = dict(os.environ)
    environment.update({"PYTHONHASHSEED": "0", "SOURCE_DATE_EPOCH": SOURCE_DATE_EPOCH, "TZ": "UTC"})
    completed = subprocess.run(
        [python, "-m", "build", "--no-isolation", "--outdir", str(destination), str(work_source)],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        timeout=180.0,
        env=environment,
    )
    if completed.returncode != 0:
        raise RuntimeError("The local distribution build failed; no artifact was released.")
    for archive in destination.glob("*.tar.gz"):
        _normalize_sdist(archive)


def _normalize_sdist(archive: Path) -> None:
    """Remove build-clock and host ownership metadata from a bounded sdist."""
    if archive.stat().st_size > MAX_SDIST_BYTES:
        raise RuntimeError("The source distribution exceeds its normalization boundary.")
    members: list[tuple[tarfile.TarInfo, bytes | None]] = []
    with tarfile.open(archive, "r:gz") as source:
        for original in source.getmembers():
            path = PurePosixPath(original.name)
            if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
                raise RuntimeError("The source distribution contains an unsafe path.")
            if not (original.isfile() or original.isdir()):
                raise RuntimeError("The source distribution contains an unsupported entry type.")
            content = None
            if original.isfile():
                extracted = source.extractfile(original)
                if extracted is None:
                    raise RuntimeError("The source distribution contains an unreadable file.")
                content = extracted.read(MAX_SDIST_BYTES + 1)
                if len(content) > MAX_SDIST_BYTES:
                    raise RuntimeError("A source distribution member exceeds its boundary.")
            member = tarfile.TarInfo(path.as_posix())
            member.type = tarfile.DIRTYPE if original.isdir() else tarfile.REGTYPE
            member.mode = 0o755 if original.isdir() or (original.mode & 0o111) else 0o644
            member.mtime = int(SOURCE_DATE_EPOCH)
            member.uid = member.gid = 0
            member.uname = member.gname = ""
            member.size = len(content) if content is not None else 0
            members.append((member, content))
    raw_tar = BytesIO()
    with tarfile.open(fileobj=raw_tar, mode="w", format=tarfile.PAX_FORMAT) as destination:
        for member, content in sorted(members, key=lambda item: item[0].name.encode("utf-8")):
            destination.addfile(member, BytesIO(content) if content is not None else None)
    compressed = BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=compressed, mtime=int(SOURCE_DATE_EPOCH), compresslevel=9) as output:
        output.write(raw_tar.getvalue())
    archive.write_bytes(compressed.getvalue())


def _sbom(version: str) -> bytes:
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:00000000-0000-4000-8000-000000000000",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "inspectra-cli",
                "version": version,
                "purl": f"pkg:pypi/inspectra-cli@{version}",
                "properties": [
                    {"name": "inspectra:python-requires", "value": ">=3.12"},
                    {"name": "inspectra:external-runtime-requirements", "value": "Git; Gitleaks 8.x"},
                ],
            }
        },
        "components": [],
        "dependencies": [{"ref": f"pkg:pypi/inspectra-cli@{version}", "dependsOn": []}],
    }
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--python", default=sys.executable)
    args = parser.parse_args()
    source = Path(__file__).resolve().parents[1]
    output = args.output.resolve()
    if output.exists() and any(output.iterdir()):
        raise SystemExit("Output directory must be absent or empty.")
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="inspectra-build-a-") as first_name, tempfile.TemporaryDirectory(
        prefix="inspectra-build-b-"
    ) as second_name:
        first = Path(first_name) / "dist"
        second = Path(second_name) / "dist"
        _build(args.python, source, first)
        _build(args.python, source, second)
        first_files = sorted(path.name for path in first.iterdir())
        second_files = sorted(path.name for path in second.iterdir())
        if first_files != second_files or not first_files:
            raise SystemExit("Reproducibility check failed: build file sets differ.")
        for name in first_files:
            if _sha256(first / name) != _sha256(second / name):
                raise SystemExit(f"Reproducibility check failed for {name}.")
            shutil.copyfile(first / name, output / name)

    wheel = next(output.glob("inspectra_cli-*.whl"))
    version = wheel.name.removeprefix("inspectra_cli-").split("-", 1)[0]
    sbom_path = output / f"inspectra-cli-{version}.sbom.cdx.json"
    sbom_path.write_bytes(_sbom(version))
    artifacts = sorted(path for path in output.iterdir() if path.name != "SHA256SUMS")
    checksum_lines = [f"{_sha256(path)}  {path.name}" for path in artifacts]
    (output / "SHA256SUMS").write_text("\n".join(checksum_lines) + "\n", encoding="ascii")
    print(json.dumps({"source_date_epoch": SOURCE_DATE_EPOCH, "artifacts": checksum_lines}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
