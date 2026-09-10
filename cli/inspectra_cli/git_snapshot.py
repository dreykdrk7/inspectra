"""Build bounded, reproducible archives from immutable Git objects only."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
from io import BytesIO
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import tempfile


DEFAULT_MAX_FILES = 5_000
DEFAULT_MAX_SOURCE_BYTES = 200 * 1024 * 1024
MAX_BLOB_BYTES = 20 * 1024 * 1024
GIT_OBJECT_ID = re.compile(r"^[0-9a-f]{40,64}$")

_GENERATED_DIRECTORIES = frozenset(
    {
        ".cache",
        ".gradle",
        ".idea",
        ".mypy_cache",
        ".next",
        ".nuget",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".venv",
        ".vscode",
        "__pycache__",
        "build",
        "coverage",
        "dist",
        "node_modules",
        "out",
        "target",
        "vendor",
    }
)
_CREDENTIAL_FILENAMES = frozenset(
    {
        ".npmrc",
        ".pypirc",
        ".netrc",
        "credentials",
        "credentials.json",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "id_rsa",
    }
)
_GENERATED_SUFFIXES = (
    ".class",
    ".dll",
    ".dylib",
    ".exe",
    ".min.css",
    ".min.js",
    ".o",
    ".obj",
    ".pyc",
    ".pyo",
    ".so",
    ".wasm",
)
_CREDENTIAL_SUFFIXES = (".key", ".p12", ".pfx", ".pem")


class SnapshotError(RuntimeError):
    """A safe preflight failure that must stop before upload."""


@dataclass(frozen=True)
class SnapshotMetadata:
    contract_version: str
    commit: str
    tree: str
    tracked_entries: int
    included_files: int
    excluded_files: int
    skipped_special_entries: int
    source_bytes: int
    archive_bytes: int
    archive_sha256: str
    exclusions: dict[str, int]

    def public_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class _GitBlob:
    mode: int
    object_id: str
    size: int
    path: str


class SnapshotBundle:
    """Own the private temporary material used by preflight and upload."""

    def __init__(
        self,
        temporary_directory: tempfile.TemporaryDirectory[str],
        archive_path: Path,
        scan_root: Path,
        metadata: SnapshotMetadata,
    ) -> None:
        self._temporary_directory = temporary_directory
        self.archive_path = archive_path
        self.scan_root = scan_root
        self.metadata = metadata

    def cleanup(self) -> None:
        self._temporary_directory.cleanup()

    def __enter__(self) -> "SnapshotBundle":
        return self

    def __exit__(self, *_: object) -> None:
        self.cleanup()


def _git_environment() -> dict[str, str]:
    allowed = {
        key: value
        for key, value in os.environ.items()
        if key not in {"GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY"}
        and not key.startswith("GIT_CONFIG_")
    }
    allowed.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_NO_LAZY_FETCH": "1",
            "LC_ALL": "C",
        }
    )
    return allowed


def _run_git(
    repository: Path,
    arguments: list[str],
    *,
    timeout: float = 20.0,
    failure_message: str = "The requested Git repository or commit could not be verified.",
) -> bytes:
    git = shutil.which("git")
    if git is None:
        raise SnapshotError("Git is required but was not found on PATH.")
    try:
        completed = subprocess.run(
            [git, "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-C", str(repository), *arguments],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            env=_git_environment(),
        )
    except subprocess.TimeoutExpired as exc:
        raise SnapshotError("Git metadata inspection exceeded its time limit.") from exc
    if completed.returncode != 0:
        raise SnapshotError(failure_message)
    return completed.stdout


def _git_probe(repository: Path, arguments: list[str]) -> tuple[int, bytes]:
    git = shutil.which("git")
    if git is None:
        raise SnapshotError("Git is required but was not found on PATH.")
    try:
        completed = subprocess.run(
            [git, "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-C", str(repository), *arguments],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=10.0,
            env=_git_environment(),
        )
    except subprocess.TimeoutExpired as exc:
        raise SnapshotError("Git metadata inspection exceeded its time limit.") from exc
    return completed.returncode, completed.stdout


def _repository_is_shallow(repository: Path) -> bool:
    returncode, output = _git_probe(repository, ["rev-parse", "--is-shallow-repository"])
    return returncode == 0 and output.strip() == b"true"


def _repository_uses_promisor_objects(repository: Path) -> bool:
    returncode, _ = _git_probe(repository, ["config", "--local", "--get-regexp", r"^remote\..*\.promisor$"])
    return returncode == 0


def resolve_repository(path: Path) -> Path:
    try:
        candidate = path.expanduser().resolve(strict=True)
    except OSError as exc:
        raise SnapshotError("The repository path does not exist or cannot be read.") from exc
    if not candidate.is_dir():
        candidate = candidate.parent
    root_bytes = _run_git(candidate, ["rev-parse", "--path-format=absolute", "--show-toplevel"])
    try:
        root = Path(root_bytes.decode("utf-8").strip()).resolve(strict=True)
    except (UnicodeDecodeError, OSError) as exc:
        raise SnapshotError("Git returned an invalid repository root.") from exc
    if not root.is_dir() or not (root / ".git").exists():
        raise SnapshotError("Only non-bare Git working repositories are supported.")
    return root


def resolve_commit(repository: Path, revision: str) -> tuple[str, str]:
    requested = revision.strip()
    if not requested or len(requested) > 200 or requested.startswith("-") or any(ord(char) < 32 for char in requested):
        raise SnapshotError("The Git revision is invalid.")
    returncode, commit = _git_probe(repository, ["rev-parse", "--verify", "--end-of-options", f"{requested}^{{commit}}"])
    if returncode != 0:
        if _repository_is_shallow(repository):
            raise SnapshotError(
                "The requested commit is not available in this shallow clone. Provide the exact commit locally and retry; Inspectra did not fetch it."
            )
        if _repository_uses_promisor_objects(repository):
            raise SnapshotError(
                "The requested promised Git object is unavailable locally. Materialize the authorized commit outside Inspectra and retry."
            )
        raise SnapshotError("The Git revision does not resolve to a local commit.")
    tree = _run_git(
        repository,
        ["rev-parse", "--verify", "--end-of-options", f"{commit.decode().strip()}^{{tree}}"],
        failure_message="The local commit object is incomplete or corrupt.",
    )
    commit_id = commit.decode("ascii").strip().lower()
    tree_id = tree.decode("ascii").strip().lower()
    if not GIT_OBJECT_ID.fullmatch(commit_id) or not GIT_OBJECT_ID.fullmatch(tree_id):
        raise SnapshotError("Git returned an unsupported object identifier.")
    return commit_id, tree_id


def _exclusion_reason(path: str) -> str | None:
    pure_path = PurePosixPath(path)
    lower_parts = tuple(part.lower() for part in pure_path.parts)
    basename = lower_parts[-1]
    if basename == ".env" or basename.startswith(".env."):
        return "environment_file"
    if basename in _CREDENTIAL_FILENAMES or basename.endswith(_CREDENTIAL_SUFFIXES):
        return "credential_file"
    if any(part == ".git" for part in lower_parts):
        return "git_metadata"
    if any(part in _GENERATED_DIRECTORIES for part in lower_parts[:-1]):
        return "generated_directory"
    if basename.endswith(_GENERATED_SUFFIXES):
        return "generated_file"
    return None


def _validate_git_path(raw_path: bytes) -> str:
    try:
        path = raw_path.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SnapshotError("A tracked filename is not valid UTF-8.") from exc
    pure_path = PurePosixPath(path)
    if (
        not path
        or pure_path.is_absolute()
        or any(part in {"", ".", ".."} for part in pure_path.parts)
        or "\\" in path
        or any(ord(character) < 32 or ord(character) == 127 for character in path)
    ):
        raise SnapshotError("A tracked filename cannot be represented safely.")
    return path


def _list_blobs(repository: Path, commit: str) -> tuple[list[_GitBlob], int, int]:
    listing = _run_git(
        repository,
        ["ls-tree", "-r", "-z", "--full-tree", "--long", commit],
        timeout=60.0,
        failure_message="The local commit tree is incomplete or unavailable.",
    )
    blobs: list[_GitBlob] = []
    tracked_entries = 0
    skipped_special = 0
    for entry in listing.split(b"\0"):
        if not entry:
            continue
        tracked_entries += 1
        try:
            metadata, raw_path = entry.split(b"\t", 1)
            mode_raw, object_type, object_id_raw, size_raw = metadata.split()
        except ValueError as exc:
            raise SnapshotError("Git returned an invalid tree entry.") from exc
        if size_raw in {b"-", b"BAD"}:
            raise SnapshotError("A required Git blob is missing or corrupt; restore the authorized commit locally.")
        path = _validate_git_path(raw_path)
        if object_type != b"blob" or mode_raw not in {b"100644", b"100755"}:
            skipped_special += 1
            continue
        try:
            size = int(size_raw)
            mode = int(mode_raw, 8)
            object_id = object_id_raw.decode("ascii").lower()
        except (ValueError, UnicodeDecodeError) as exc:
            raise SnapshotError("Git returned invalid blob metadata.") from exc
        if size < 0 or not GIT_OBJECT_ID.fullmatch(object_id):
            raise SnapshotError("Git returned invalid blob metadata.")
        blobs.append(_GitBlob(mode=mode, object_id=object_id, size=size, path=path))
    return blobs, tracked_entries, skipped_special


def _read_blob(repository: Path, blob: _GitBlob) -> bytes:
    if blob.size > MAX_BLOB_BYTES:
        raise SnapshotError("A retained source file exceeds the 20 MiB per-file limit.")
    payload = _run_git(
        repository,
        ["cat-file", "blob", blob.object_id],
        timeout=30.0,
        failure_message="A required Git blob is missing or corrupt; restore the authorized commit locally.",
    )
    if len(payload) != blob.size:
        raise SnapshotError("A Git blob changed or could not be read completely.")
    return payload


def _write_private_file(root: Path, path: str, payload: bytes) -> None:
    target = root.joinpath(*PurePosixPath(path).parts)
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    target.write_bytes(payload)
    target.chmod(0o600)


def _add_tar_file(archive: tarfile.TarFile, blob: _GitBlob, payload: bytes) -> None:
    info = tarfile.TarInfo(name=blob.path)
    info.size = len(payload)
    info.mode = 0o755 if blob.mode & 0o111 else 0o644
    info.mtime = 0
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.pax_headers = {}
    archive.addfile(info, BytesIO(payload))


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def build_snapshot(
    path: Path,
    revision: str = "HEAD",
    *,
    max_files: int = DEFAULT_MAX_FILES,
    max_source_bytes: int = DEFAULT_MAX_SOURCE_BYTES,
) -> SnapshotBundle:
    if not 1 <= max_files <= DEFAULT_MAX_FILES:
        raise SnapshotError(f"max_files must be between 1 and {DEFAULT_MAX_FILES}.")
    if not 1 <= max_source_bytes <= DEFAULT_MAX_SOURCE_BYTES:
        raise SnapshotError(f"max_source_bytes must be between 1 and {DEFAULT_MAX_SOURCE_BYTES}.")

    repository = resolve_repository(path)
    commit, tree = resolve_commit(repository, revision)
    blobs, tracked_entries, skipped_special = _list_blobs(repository, commit)
    exclusions: dict[str, int] = {}
    retained: list[_GitBlob] = []
    total_source_bytes = 0
    for blob in sorted(blobs, key=lambda item: item.path.encode("utf-8")):
        reason = _exclusion_reason(blob.path)
        if reason is not None:
            exclusions[reason] = exclusions.get(reason, 0) + 1
            continue
        if len(retained) >= max_files:
            raise SnapshotError("The retained snapshot exceeds the configured file limit.")
        total_source_bytes += blob.size
        if total_source_bytes > max_source_bytes:
            raise SnapshotError("The retained snapshot exceeds the configured source byte limit.")
        retained.append(blob)
    if not retained:
        raise SnapshotError("The selected commit has no admissible source files.")

    temporary_directory = tempfile.TemporaryDirectory(prefix="inspectra-cli-")
    temporary_root = Path(temporary_directory.name)
    temporary_root.chmod(0o700)
    scan_root = temporary_root / "source"
    scan_root.mkdir(mode=0o700)
    archive_path = temporary_root / "snapshot.tar"
    try:
        with tarfile.open(archive_path, "w", format=tarfile.PAX_FORMAT) as archive:
            for blob in retained:
                payload = _read_blob(repository, blob)
                _write_private_file(scan_root, blob.path, payload)
                _add_tar_file(archive, blob, payload)
        archive_path.chmod(0o600)
        metadata = SnapshotMetadata(
            contract_version="2026-09-07.1",
            commit=commit,
            tree=tree,
            tracked_entries=tracked_entries,
            included_files=len(retained),
            excluded_files=sum(exclusions.values()),
            skipped_special_entries=skipped_special,
            source_bytes=total_source_bytes,
            archive_bytes=archive_path.stat().st_size,
            archive_sha256=_sha256_file(archive_path),
            exclusions=dict(sorted(exclusions.items())),
        )
        return SnapshotBundle(temporary_directory, archive_path, scan_root, metadata)
    except Exception:
        temporary_directory.cleanup()
        raise
