from __future__ import annotations

import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO
import json
from pathlib import Path
import subprocess
import tarfile
import threading
import sys
import inspectra_cli.git_snapshot as git_snapshot_module
import inspectra_cli.commands as commands_module

import pytest

from inspectra_cli.client import AnalysisTimeoutError, ApiClientError, InspectraApiClient
from inspectra_cli.client import ClientCompatibilityError
from inspectra_cli.commands import EXIT_OK, execute_scan
from inspectra_cli.git_snapshot import SnapshotError, build_snapshot
from inspectra_cli.security import SecretDetectedError, SecretScanResult, run_secret_preflight
from inspectra_cli import __version__
from inspectra_cli.doctor import run_doctor


def _git(repository: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return completed.stdout.strip()


def _repository(tmp_path: Path) -> tuple[Path, str]:
    repository = tmp_path / "owned-repository"
    repository.mkdir()
    _git(repository, "init", "-q")
    _git(repository, "config", "user.email", "fixture@example.test")
    _git(repository, "config", "user.name", "Fixture")
    (repository / "src").mkdir()
    (repository / "src" / "app.py").write_text("print('tracked')\n", encoding="utf-8")
    (repository / ".env.example").write_text("TOKEN=example\n", encoding="utf-8")
    (repository / "dist").mkdir()
    (repository / "dist" / "bundle.js").write_text("generated\n", encoding="utf-8")
    (repository / "package-lock.json").write_text('{"lockfileVersion":3,"packages":{}}\n', encoding="utf-8")
    _git(repository, "add", ".")
    _git(repository, "commit", "-qm", "fixture")
    commit = _git(repository, "rev-parse", "HEAD")
    (repository / "src" / "app.py").write_text("print('local change')\n", encoding="utf-8")
    (repository / "untracked.txt").write_text("private worktree data\n", encoding="utf-8")
    return repository, commit


def _tar_files(path: Path) -> dict[str, bytes]:
    with tarfile.open(path, "r") as archive:
        files: dict[str, bytes] = {}
        for member in archive.getmembers():
            if not member.isfile():
                continue
            source = archive.extractfile(member)
            assert source is not None
            files[member.name] = source.read()
        return files


def test_snapshot_uses_only_commit_blobs_and_is_reproducible(tmp_path: Path) -> None:
    repository, commit = _repository(tmp_path)

    with build_snapshot(repository, commit) as first:
        first_bytes = first.archive_path.read_bytes()
        first_metadata = first.metadata
        files = _tar_files(first.archive_path)
    with build_snapshot(repository / "src", "HEAD") as second:
        second_bytes = second.archive_path.read_bytes()
        second_metadata = second.metadata

    assert first_bytes == second_bytes
    assert first_metadata.archive_sha256 == second_metadata.archive_sha256
    assert first_metadata.commit == commit
    assert first_metadata.tree == _git(repository, "rev-parse", f"{commit}^{{tree}}")
    assert files == {
        "package-lock.json": b'{"lockfileVersion":3,"packages":{}}\n',
        "src/app.py": b"print('tracked')\n",
    }
    assert first_metadata.included_files == 2
    assert first_metadata.exclusions == {"environment_file": 1, "generated_directory": 1}
    assert b"local change" not in first_bytes
    assert b"private worktree data" not in first_bytes


def test_snapshot_rejects_revision_options_and_limits(tmp_path: Path) -> None:
    repository, _ = _repository(tmp_path)

    with pytest.raises(SnapshotError, match="revision"):
        build_snapshot(repository, "--all")
    with pytest.raises(SnapshotError, match="file limit"):
        build_snapshot(repository, max_files=1)


def test_snapshot_preserves_unicode_spaces_and_crlf_as_git_blob_bytes(tmp_path: Path) -> None:
    repository = tmp_path / "repo with spaces"
    repository.mkdir()
    _git(repository, "init", "-q")
    _git(repository, "config", "user.email", "fixture@example.test")
    _git(repository, "config", "user.name", "Fixture")
    relative = Path("carpeta con espacio") / "café.txt"
    (repository / relative.parent).mkdir()
    expected = "línea uno\r\nlínea dos\r\n".encode("utf-8")
    (repository / relative).write_bytes(expected)
    _git(repository, "add", ".")
    _git(repository, "commit", "-qm", "unicode fixture")

    with build_snapshot(repository) as first, build_snapshot(repository) as second:
        files = _tar_files(first.archive_path)
        assert first.archive_path.read_bytes() == second.archive_path.read_bytes()

    assert files == {relative.as_posix(): expected}


def test_shallow_clone_missing_commit_fails_without_fetch(monkeypatch, tmp_path: Path) -> None:
    origin = tmp_path / "origin"
    origin.mkdir()
    _git(origin, "init", "-q")
    _git(origin, "config", "user.email", "fixture@example.test")
    _git(origin, "config", "user.name", "Fixture")
    (origin / "file.txt").write_text("first\n", encoding="utf-8")
    _git(origin, "add", ".")
    _git(origin, "commit", "-qm", "first")
    missing_commit = _git(origin, "rev-parse", "HEAD")
    (origin / "file.txt").write_text("second\n", encoding="utf-8")
    _git(origin, "commit", "-qam", "second")
    shallow = tmp_path / "shallow"
    subprocess.run(
        ["git", "clone", "-q", "--depth", "1", origin.as_uri(), str(shallow)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    calls: list[tuple[list[str], dict[str, str] | None]] = []
    real_run = subprocess.run

    def record_run(command, *args, **kwargs):
        calls.append((list(command), kwargs.get("env")))
        return real_run(command, *args, **kwargs)

    monkeypatch.setattr(git_snapshot_module.subprocess, "run", record_run)
    with pytest.raises(SnapshotError, match="shallow clone") as error:
        build_snapshot(shallow, missing_commit)

    assert "token" not in str(error.value).lower()
    assert all("fetch" not in command for command, _ in calls)
    assert all(environment and environment.get("GIT_NO_LAZY_FETCH") == "1" for _, environment in calls)


def test_unknown_revision_and_missing_blob_have_distinct_safe_errors(tmp_path: Path) -> None:
    repository, _ = _repository(tmp_path)
    with pytest.raises(SnapshotError, match="does not resolve to a local commit"):
        build_snapshot(repository, "f" * 40)

    blob = _git(repository, "rev-parse", "HEAD:src/app.py")
    loose_object = repository / ".git" / "objects" / blob[:2] / blob[2:]
    assert loose_object.is_file()
    loose_object.unlink()
    with pytest.raises(SnapshotError, match="missing or corrupt") as error:
        build_snapshot(repository)
    assert blob not in str(error.value)
    assert str(repository) not in str(error.value)


def _fake_gitleaks(path: Path) -> Path:
    executable = path / "gitleaks"
    executable.write_text(
        """#!/usr/bin/env python3
import json
from pathlib import Path
import sys
report = next(Path(arg.split('=', 1)[1]) for arg in sys.argv if arg.startswith('--report-path='))
source = Path(sys.argv[-1])
found = (source / 'canary.txt').exists() or (source / 'leak.txt').exists()
report.write_text(json.dumps([{'RuleID': 'redacted'}] if found else []), encoding='utf-8')
raise SystemExit(17 if found else 0)
""",
        encoding="utf-8",
    )
    executable.chmod(0o700)
    return executable


def test_secret_preflight_requires_canary_and_blocks_source_findings(tmp_path: Path) -> None:
    gitleaks = _fake_gitleaks(tmp_path)
    clean = tmp_path / "clean"
    clean.mkdir()
    (clean / "safe.txt").write_text("safe\n", encoding="utf-8")

    result = run_secret_preflight(clean, gitleaks_command=str(gitleaks))

    assert result.canary_detected is True
    assert result.findings == 0
    (clean / "leak.txt").write_text("not exposed by the test scanner\n", encoding="utf-8")
    with pytest.raises(SecretDetectedError) as error:
        run_secret_preflight(clean, gitleaks_command=str(gitleaks))
    assert error.value.finding_count == 1
    assert "leak.txt" not in str(error.value)


class _InspectraHandler(BaseHTTPRequestHandler):
    uploaded_archive = b""
    request_bodies: list[bytes] = []
    authorization_headers: list[str | None] = []
    capability_authorization_headers: list[str | None] = []
    capabilities_status = 200
    capabilities_payload: dict[str, object] = {
        "contract_version": "2026-09-10.6",
        "status": "available",
        "server_version": "0.3.0-beta.1",
        "supported_cli_protocols": ["2026-09-10.6"],
        "contracts": {
            "git_snapshot": ["2026-09-07.1"],
            "ci_admission": ["2026-09-06.1"],
            "policy_result": ["2026-09-07.1"],
            "cli_result": ["2026-09-07.1"],
            "go_dependency_graph": ["2026-09-10.1"],
            "cargo_dependency_graph": ["2026-09-10.2"],
            "composer_dependency_graph": ["2026-09-10.3"],
            "gradle_dependency_graph": ["2026-09-10.4"],
            "nuget_dependency_graph": ["2026-09-10.5"],
            "ci_graph_envelope": ["2026-09-10.1"],
        },
    }

    def log_message(self, *_: object) -> None:
        return

    def _json(self, status: int, payload: dict[str, object]) -> None:
        encoded = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_POST(self) -> None:
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.__class__.request_bodies.append(body)
        self.__class__.authorization_headers.append(self.headers.get("Authorization"))
        if self.path == "/files/archive":
            payload_start = body.index(b"\r\n\r\n") + 4
            payload_end = body.rindex(b"\r\n--")
            self.__class__.uploaded_archive = body[payload_start:payload_end]
            self._json(201, {"id": "f" * 32})
            return
        if self.path == "/projects":
            self._json(201, {"project": {"id": "a" * 32}, "job": {"id": "b" * 32}})
            return
        if self.path == f"/projects/{'a' * 32}/ci/snapshots":
            self._json(202, {"job": {"id": "b" * 32}, "replayed": True})
            return
        if self.path == f"/projects/{'a' * 32}/analyses/{'b' * 32}/cancel":
            self._json(202, {"id": "b" * 32, "status": "cancelling"})
            return
        if self.path == f"/projects/{'a' * 32}/analyses/{'b' * 32}/dependency-graphs/go":
            marker = b'Content-Disposition: form-data; name="artifact_sha256"\r\n\r\n'
            digest = body.split(marker, 1)[1].split(b"\r\n", 1)[0].decode("ascii")
            self._json(200, {"ecosystem": "go", "state": "accepted", "artifact_sha256": digest})
            return
        if self.path == f"/projects/{'a' * 32}/analyses/{'b' * 32}/dependency-graphs/cargo":
            marker = b'Content-Disposition: form-data; name="artifact_sha256"\r\n\r\n'
            digest = body.split(marker, 1)[1].split(b"\r\n", 1)[0].decode("ascii")
            self._json(200, {"ecosystem": "cargo", "state": "accepted", "artifact_sha256": digest})
            return
        if self.path == f"/projects/{'a' * 32}/analyses/{'b' * 32}/dependency-graphs/composer":
            marker = b'Content-Disposition: form-data; name="artifact_sha256"\r\n\r\n'
            digest = body.split(marker, 1)[1].split(b"\r\n", 1)[0].decode("ascii")
            self._json(200, {"ecosystem": "composer", "state": "accepted", "artifact_sha256": digest})
            return
        if self.path == f"/projects/{'a' * 32}/analyses/{'b' * 32}/dependency-graphs/gradle":
            marker = b'Content-Disposition: form-data; name="artifact_sha256"\r\n\r\n'
            digest = body.split(marker, 1)[1].split(b"\r\n", 1)[0].decode("ascii")
            self._json(200, {"ecosystem": "maven", "producer": "gradle", "state": "accepted", "artifact_sha256": digest})
            return
        if self.path == f"/projects/{'a' * 32}/analyses/{'b' * 32}/dependency-graphs/nuget":
            marker = b'Content-Disposition: form-data; name="artifact_sha256"\r\n\r\n'
            digest = body.split(marker, 1)[1].split(b"\r\n", 1)[0].decode("ascii")
            self._json(200, {"ecosystem": "nuget", "producer": "nuget", "state": "accepted", "artifact_sha256": digest})
            return
        self._json(404, {"detail": "not found"})

    def do_GET(self) -> None:
        if self.path == "/client-capabilities":
            self.__class__.capability_authorization_headers.append(self.headers.get("Authorization"))
            self._json(self.__class__.capabilities_status, self.__class__.capabilities_payload)
            return
        if self.path == f"/jobs/{'b' * 32}":
            self._json(200, {"id": "b" * 32, "status": "completed"})
            return
        if self.path.startswith(f"/projects/{'a' * 32}/findings?"):
            self._json(
                200,
                {
                    "state": "ready",
                    "result_truncated": False,
                    "summary": {"total": 1, "by_severity": {"high": 1}, "by_category": {}},
                    "coverage": {"coverage_status": "complete"},
                },
            )
            return
        if self.path == f"/projects/{'a' * 32}":
            self._json(200, {"project": {"id": "a" * 32, "baseline_analysis_id": None}})
            return
        if self.path == f"/projects/{'a' * 32}/analyses/{'b' * 32}/vulnerability-intelligence":
            self._json(200, {"state": "disabled", "summary": {"finding_count": 0}})
            return
        self._json(404, {"detail": "not found"})


def _arguments(repository: Path, port: int) -> argparse.Namespace:
    return argparse.Namespace(
        command="scan",
        path=repository,
        commit="HEAD",
        api_url=f"http://127.0.0.1:{port}",
        web_url=f"http://127.0.0.1:{port}",
        name=None,
        project_id=None,
        go_graph=None,
        cargo_graph=None,
        composer_graph=None,
        gradle_graph=None,
        branch=None,
        policy="observe",
        dry_run=False,
        json=True,
        yes=True,
        confirm_authorized=True,
        timeout=5.0,
        cancel_on_interrupt=False,
        http_timeout=5.0,
        max_files=5_000,
        max_bytes=200 * 1024 * 1024,
    )


def test_scan_end_to_end_uploads_snapshot_and_returns_project_result(tmp_path: Path) -> None:
    repository, commit = _repository(tmp_path)
    _InspectraHandler.uploaded_archive = b""
    _InspectraHandler.request_bodies = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _InspectraHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        exit_code, result = execute_scan(
            _arguments(repository, server.server_port),
            secret_preflight=lambda _: SecretScanResult("gitleaks", "fixture", True, 0),
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert exit_code == EXIT_OK
    assert result["status"] == "completed"
    assert result["snapshot"]["commit"] == commit
    assert result["findings"]["total"] == 1
    assert result["public_intelligence"]["state"] == "disabled"
    assert result["result_url"].endswith(f"#project={'a' * 32}&job={'b' * 32}")
    with tarfile.open(fileobj=BytesIO(_InspectraHandler.uploaded_archive), mode="r") as archive:
        names = archive.getnames()
        assert names == ["package-lock.json", "src/app.py"]
        assert archive.extractfile("src/app.py").read() == b"print('tracked')\n"
    combined_requests = b"".join(_InspectraHandler.request_bodies)
    assert str(repository).encode() not in combined_requests
    assert b"local change" not in combined_requests
    assert b"private worktree data" not in combined_requests


def test_scan_ci_submits_commit_bound_snapshot_with_environment_token(monkeypatch, tmp_path: Path) -> None:
    repository, commit = _repository(tmp_path)
    _InspectraHandler.request_bodies = []
    _InspectraHandler.authorization_headers = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _InspectraHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    arguments = _arguments(repository, server.server_port)
    arguments.project_id = "a" * 32
    arguments.branch = "feature/ci"
    monkeypatch.setenv("INSPECTRA_TOKEN", "one-time-test-token")
    try:
        exit_code, result = execute_scan(
            arguments,
            secret_preflight=lambda _: SecretScanResult("gitleaks", "fixture", True, 0),
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert exit_code == EXIT_OK
    assert result["ci_replayed"] is True
    assert result["snapshot"]["commit"] == commit
    request = _InspectraHandler.request_bodies[0]
    assert commit.encode() in request
    assert result["snapshot"]["archive_sha256"].encode() in request
    assert str(repository).encode() not in request
    assert _InspectraHandler.authorization_headers == ["Bearer one-time-test-token"]


class _WaitExitClient:
    replayed = False
    wait_error: BaseException = AnalysisTimeoutError("fixture timeout")
    cancel_error: ApiClientError | None = None
    cancel_calls: list[tuple[str, str]] = []

    def __init__(self, *_: object, **__: object) -> None:
        pass

    def ensure_compatible(self) -> None:
        return None

    def upload_archive(self, _archive_path: Path) -> str:
        return "f" * 32

    def create_project(self, _file_id: str, *, name: str | None = None) -> tuple[str, str]:
        assert name is None
        return "a" * 32, "b" * 32

    def submit_ci_snapshot(self, *_: object, **__: object) -> tuple[str, bool]:
        return "b" * 32, self.replayed

    def result_url(self, *_: object) -> str:
        return f"http://127.0.0.1/#project={'a' * 32}&job={'b' * 32}"

    def wait_for_analysis(self, *_: object, **__: object) -> None:
        raise self.wait_error

    def cancel_analysis(self, project_id: str, job_id: str) -> str:
        self.cancel_calls.append((project_id, job_id))
        if self.cancel_error is not None:
            raise self.cancel_error
        return "cancelling"


def _execute_wait_exit(repository: Path, *, cancel: bool, client_factory=_WaitExitClient):
    arguments = _arguments(repository, 1)
    arguments.cancel_on_interrupt = cancel
    return execute_scan(
        arguments,
        secret_preflight=lambda _: SecretScanResult("gitleaks", "fixture", True, 0),
        client_factory=client_factory,
    )


def test_timeout_leaves_remote_analysis_running_by_default(tmp_path: Path) -> None:
    repository, _ = _repository(tmp_path)
    _WaitExitClient.wait_error = AnalysisTimeoutError("fixture timeout")
    _WaitExitClient.cancel_error = None
    _WaitExitClient.cancel_calls = []

    with pytest.raises(AnalysisTimeoutError) as error:
        _execute_wait_exit(repository, cancel=False)

    assert error.value.remote_cancellation == "not_requested"
    assert error.value.result_url.endswith(f"job={'b' * 32}")
    assert _WaitExitClient.cancel_calls == []


def test_timeout_requests_one_remote_cancellation_when_opted_in(tmp_path: Path) -> None:
    repository, _ = _repository(tmp_path)
    _WaitExitClient.wait_error = AnalysisTimeoutError("fixture timeout")
    _WaitExitClient.cancel_error = None
    _WaitExitClient.cancel_calls = []

    with pytest.raises(AnalysisTimeoutError) as error:
        _execute_wait_exit(repository, cancel=True)

    assert error.value.remote_cancellation == "confirmed_cancelling"
    assert _WaitExitClient.cancel_calls == [("a" * 32, "b" * 32)]


@pytest.mark.parametrize("status_code", [401, 409])
def test_timeout_preserves_original_failure_when_cancellation_is_not_confirmed(
    tmp_path: Path, status_code: int
) -> None:
    repository, _ = _repository(tmp_path)
    _WaitExitClient.wait_error = AnalysisTimeoutError("fixture timeout")
    _WaitExitClient.cancel_error = ApiClientError("private upstream detail", status_code=status_code)
    _WaitExitClient.cancel_calls = []

    with pytest.raises(AnalysisTimeoutError) as error:
        _execute_wait_exit(repository, cancel=True)

    assert str(error.value) == "fixture timeout"
    assert error.value.remote_cancellation == "not_confirmed"
    assert _WaitExitClient.cancel_calls == [("a" * 32, "b" * 32)]


def test_keyboard_interrupt_requests_one_remote_cancellation(tmp_path: Path) -> None:
    repository, _ = _repository(tmp_path)
    _WaitExitClient.wait_error = KeyboardInterrupt()
    _WaitExitClient.cancel_error = None
    _WaitExitClient.cancel_calls = []

    with pytest.raises(KeyboardInterrupt) as error:
        _execute_wait_exit(repository, cancel=True)

    assert error.value.remote_cancellation == "confirmed_cancelling"
    assert _WaitExitClient.cancel_calls == [("a" * 32, "b" * 32)]


def test_replayed_ci_analysis_is_never_cancelled_on_timeout(monkeypatch, tmp_path: Path) -> None:
    repository, _ = _repository(tmp_path)
    _WaitExitClient.wait_error = AnalysisTimeoutError("fixture timeout")
    _WaitExitClient.cancel_error = None
    _WaitExitClient.cancel_calls = []
    _WaitExitClient.replayed = True
    arguments = _arguments(repository, 1)
    arguments.project_id = "a" * 32
    arguments.cancel_on_interrupt = True
    monkeypatch.setenv("INSPECTRA_TOKEN", "fixture-token")
    try:
        with pytest.raises(AnalysisTimeoutError) as error:
            execute_scan(
                arguments,
                secret_preflight=lambda _: SecretScanResult("gitleaks", "fixture", True, 0),
                client_factory=_WaitExitClient,
            )
    finally:
        _WaitExitClient.replayed = False

    assert error.value.remote_cancellation == "skipped_replayed"
    assert _WaitExitClient.cancel_calls == []


def test_client_cancellation_uses_exact_scoped_route_and_credential() -> None:
    _InspectraHandler.request_bodies = []
    _InspectraHandler.authorization_headers = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _InspectraHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        client = InspectraApiClient(
            f"http://127.0.0.1:{server.server_port}",
            token="cancel-test-token",
            timeout_seconds=5,
        )
        state = client.cancel_analysis("a" * 32, "b" * 32)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert state == "cancelling"
    assert _InspectraHandler.request_bodies == [b""]
    assert _InspectraHandler.authorization_headers == ["Bearer cancel-test-token"]


def test_main_returns_timeout_code_and_machine_readable_cancellation_state(
    monkeypatch, tmp_path: Path, capsys
) -> None:
    error = AnalysisTimeoutError("fixture timeout")
    error.project_id = "a" * 32
    error.job_id = "b" * 32
    error.result_url = "http://127.0.0.1/#project=fixture"
    error.remote_cancellation = "not_confirmed"
    monkeypatch.setattr(commands_module, "execute_scan", lambda _arguments: (_ for _ in ()).throw(error))

    exit_code = commands_module.main([
        "scan", str(tmp_path), "--yes", "--confirm-authorized", "--json", "--cancel-on-interrupt"
    ])
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 6
    assert payload["code"] == "analysis_timeout"
    assert payload["remote_cancellation"] == "not_confirmed"
    assert payload["job_id"] == "b" * 32
    assert "private upstream detail" not in json.dumps(payload)


def test_main_returns_130_with_link_after_keyboard_interrupt(monkeypatch, tmp_path: Path, capsys) -> None:
    error = KeyboardInterrupt()
    error.project_id = "a" * 32
    error.job_id = "b" * 32
    error.result_url = "http://127.0.0.1/#project=fixture"
    error.remote_cancellation = "confirmed_cancelling"
    monkeypatch.setattr(commands_module, "execute_scan", lambda _arguments: (_ for _ in ()).throw(error))

    exit_code = commands_module.main([
        "scan", str(tmp_path), "--yes", "--confirm-authorized", "--json", "--cancel-on-interrupt"
    ])
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 130
    assert payload["code"] == "interrupted"
    assert payload["remote_cancellation"] == "confirmed_cancelling"
    assert payload["result_url"].startswith("http://127.0.0.1/")


def test_scan_ci_validates_and_attaches_source_bound_go_graph(monkeypatch, tmp_path: Path) -> None:
    repository, commit = _repository(tmp_path)
    with build_snapshot(repository, commit) as snapshot:
        source_sha256 = snapshot.metadata.archive_sha256
    graph = tmp_path / "go-graph.json"
    graph.write_text(json.dumps({
        "contract_version": "2026-09-10.1",
        "ecosystem": "go",
        "producer": "go-mod-graph",
        "source_commit_sha": commit,
        "source_sha256": source_sha256,
        "complete": True,
        "truncation_reason": None,
        "nodes": [{"id": "n1", "name": "golang.org/x/text", "version": "v0.19.0"}],
        "roots": ["n1"],
        "edges": [],
    }, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    graph.chmod(0o600)
    _InspectraHandler.request_bodies = []
    _InspectraHandler.authorization_headers = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _InspectraHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    arguments = _arguments(repository, server.server_port)
    arguments.project_id = "a" * 32
    arguments.go_graph = graph
    monkeypatch.setenv("INSPECTRA_TOKEN", "graph-test-token")
    try:
        exit_code, result = execute_scan(
            arguments,
            secret_preflight=lambda _: SecretScanResult("gitleaks", "fixture", True, 0),
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert exit_code == EXIT_OK
    assert result["dependency_graph"]["state"] == "accepted"
    assert result["dependency_graph"]["artifact_sha256"] == hashlib.sha256(graph.read_bytes()).hexdigest()
    assert len(_InspectraHandler.request_bodies) == 2
    assert b"golang.org/x/text" in _InspectraHandler.request_bodies[1]
    assert str(repository).encode() not in b"".join(_InspectraHandler.request_bodies)
    assert _InspectraHandler.authorization_headers == ["Bearer graph-test-token", "Bearer graph-test-token"]


def test_scan_ci_validates_and_attaches_source_bound_cargo_graph(monkeypatch, tmp_path: Path) -> None:
    repository, commit = _repository(tmp_path)
    with build_snapshot(repository, commit) as snapshot:
        source_sha256 = snapshot.metadata.archive_sha256
    graph = tmp_path / "cargo-graph.json"
    graph.write_text(json.dumps({
        "contract_version": "2026-09-10.2", "ecosystem": "cargo", "producer": "cargo-metadata-graph",
        "source_commit_sha": commit, "source_sha256": source_sha256,
        "target_coverage": "all_locked_targets", "complete": True, "truncation_reason": None,
        "targets": ["linux_x86_64"],
        "nodes": [{"id": "n1", "name": "serde", "version": "1.0.210", "features": ["derive"], "targets": ["linux_x86_64"]}],
        "roots": ["n1"], "edges": [],
    }, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    graph.chmod(0o600)
    _InspectraHandler.request_bodies = []
    _InspectraHandler.authorization_headers = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _InspectraHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    arguments = _arguments(repository, server.server_port)
    arguments.project_id = "a" * 32
    arguments.cargo_graph = graph
    monkeypatch.setenv("INSPECTRA_TOKEN", "cargo-graph-test-token")
    try:
        exit_code, result = execute_scan(
            arguments,
            secret_preflight=lambda _: SecretScanResult("gitleaks", "fixture", True, 0),
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert exit_code == EXIT_OK
    assert result["cargo_dependency_graph"]["state"] == "accepted"
    assert result["cargo_dependency_graph"]["artifact_sha256"] == hashlib.sha256(graph.read_bytes()).hexdigest()
    assert len(_InspectraHandler.request_bodies) == 2
    assert b"serde" in _InspectraHandler.request_bodies[1]
    assert b"linux_x86_64" in _InspectraHandler.request_bodies[1]
    assert str(repository).encode() not in b"".join(_InspectraHandler.request_bodies)
    assert _InspectraHandler.authorization_headers == ["Bearer cargo-graph-test-token", "Bearer cargo-graph-test-token"]


def test_scan_ci_validates_and_attaches_source_bound_composer_graph(monkeypatch, tmp_path: Path) -> None:
    repository, commit = _repository(tmp_path)
    with build_snapshot(repository, commit) as snapshot:
        source_sha256 = snapshot.metadata.archive_sha256
    graph = tmp_path / "composer-graph.json"
    graph.write_text(json.dumps({
        "contract_version": "2026-09-10.3", "ecosystem": "composer", "producer": "composer-locked-graph",
        "source_commit_sha": commit, "source_sha256": source_sha256,
        "complete": True, "truncation_reason": None,
        "nodes": [{"id": "n1", "name": "vendor/package", "version": "1.2.3"}],
        "roots": ["n1"], "edges": [],
    }, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    graph.chmod(0o600)
    _InspectraHandler.request_bodies = []
    _InspectraHandler.authorization_headers = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _InspectraHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    arguments = _arguments(repository, server.server_port)
    arguments.project_id = "a" * 32
    arguments.composer_graph = graph
    monkeypatch.setenv("INSPECTRA_TOKEN", "composer-graph-test-token")
    try:
        exit_code, result = execute_scan(
            arguments,
            secret_preflight=lambda _: SecretScanResult("gitleaks", "fixture", True, 0),
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert exit_code == EXIT_OK
    assert result["composer_dependency_graph"]["state"] == "accepted"
    assert result["composer_dependency_graph"]["artifact_sha256"] == hashlib.sha256(graph.read_bytes()).hexdigest()
    assert len(_InspectraHandler.request_bodies) == 2
    assert b"vendor/package" in _InspectraHandler.request_bodies[1]
    assert str(repository).encode() not in b"".join(_InspectraHandler.request_bodies)
    assert _InspectraHandler.authorization_headers == ["Bearer composer-graph-test-token", "Bearer composer-graph-test-token"]


def test_scan_ci_validates_and_attaches_source_bound_gradle_graph(monkeypatch, tmp_path: Path) -> None:
    repository, commit = _repository(tmp_path)
    with build_snapshot(repository, commit) as snapshot:
        source_sha256 = snapshot.metadata.archive_sha256
    graph = tmp_path / "gradle-graph.json"
    graph.write_text(json.dumps({
        "contract_version": "2026-09-10.4", "ecosystem": "maven", "producer": "gradle-dependency-graph",
        "source_commit_sha": commit, "source_sha256": source_sha256,
        "scope_coverage": ["compile", "runtime"], "complete": True, "truncation_reason": None,
        "nodes": [{"id": "n1", "name": "org.example:package", "version": "1.2.3", "scopes": ["compile", "runtime"]}],
        "roots": ["n1"], "edges": [],
    }, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    graph.chmod(0o600)
    _InspectraHandler.request_bodies = []
    _InspectraHandler.authorization_headers = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _InspectraHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    arguments = _arguments(repository, server.server_port)
    arguments.project_id = "a" * 32
    arguments.gradle_graph = graph
    monkeypatch.setenv("INSPECTRA_TOKEN", "gradle-graph-test-token")
    try:
        exit_code, result = execute_scan(arguments, secret_preflight=lambda _: SecretScanResult("gitleaks", "fixture", True, 0))
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=2)
    assert exit_code == EXIT_OK
    assert result["gradle_dependency_graph"]["state"] == "accepted"
    assert result["gradle_dependency_graph"]["artifact_sha256"] == hashlib.sha256(graph.read_bytes()).hexdigest()
    assert len(_InspectraHandler.request_bodies) == 2
    assert b"org.example:package" in _InspectraHandler.request_bodies[1]
    assert str(repository).encode() not in b"".join(_InspectraHandler.request_bodies)
    assert _InspectraHandler.authorization_headers == ["Bearer gradle-graph-test-token", "Bearer gradle-graph-test-token"]


def test_scan_ci_validates_and_attaches_source_bound_nuget_graph(monkeypatch, tmp_path: Path) -> None:
    repository, commit = _repository(tmp_path)
    with build_snapshot(repository, commit) as snapshot:
        source_sha256 = snapshot.metadata.archive_sha256
    graph = tmp_path / "nuget-graph.json"
    graph.write_text(json.dumps({
        "contract_version": "2026-09-10.5", "ecosystem": "nuget", "producer": "nuget-dependency-graph",
        "source_commit_sha": commit, "source_sha256": source_sha256,
        "target_coverage": "all_locked_targets", "complete": True, "truncation_reason": None,
        "targets": ["t0", "t1"],
        "nodes": [
            {"id": "n1", "name": "newtonsoft.json", "version": "13.0.3", "targets": ["t0", "t1"]},
            {"id": "n2", "name": "system.text.json", "version": "8.0.0", "targets": ["t1"]},
        ],
        "roots": [{"node": "n1", "targets": ["t0", "t1"]}],
        "edges": [{"source": "n1", "target": "n2", "targets": ["t1"]}],
    }, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    graph.chmod(0o600)
    _InspectraHandler.request_bodies = []
    _InspectraHandler.authorization_headers = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _InspectraHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    arguments = _arguments(repository, server.server_port)
    arguments.project_id = "a" * 32
    arguments.nuget_graph = graph
    monkeypatch.setenv("INSPECTRA_TOKEN", "nuget-graph-test-token")
    try:
        exit_code, result = execute_scan(arguments, secret_preflight=lambda _: SecretScanResult("gitleaks", "fixture", True, 0))
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=2)
    assert exit_code == EXIT_OK
    assert result["nuget_dependency_graph"]["state"] == "accepted"
    assert result["nuget_dependency_graph"]["artifact_sha256"] == hashlib.sha256(graph.read_bytes()).hexdigest()
    assert len(_InspectraHandler.request_bodies) == 2
    assert b"newtonsoft.json" in _InspectraHandler.request_bodies[1]
    assert b"net8.0" not in _InspectraHandler.request_bodies[1]
    assert str(repository).encode() not in b"".join(_InspectraHandler.request_bodies)
    assert _InspectraHandler.authorization_headers == ["Bearer nuget-graph-test-token", "Bearer nuget-graph-test-token"]


def test_go_graph_rejects_duplicate_keys_before_upload(tmp_path: Path) -> None:
    from inspectra_cli.dependency_graph import validate_go_dependency_graph

    graph = tmp_path / "ambiguous.json"
    graph.write_text(
        '{"contract_version":"2026-09-10.1","ecosystem":"go","ecosystem":"go",'
        '"producer":"go-mod-graph","source_commit_sha":"' + "c" * 40 + '",'
        '"source_sha256":"' + "a" * 64 + '","complete":true,"truncation_reason":null,'
        '"nodes":[],"roots":[],"edges":[]}',
        encoding="utf-8",
    )
    with pytest.raises(SnapshotError, match="unambiguous"):
        validate_go_dependency_graph(graph, expected_commit_sha="c" * 40, expected_source_sha256="a" * 64)


@pytest.mark.parametrize("link_kind", ["symbolic", "hard"])
def test_go_graph_rejects_linked_artifacts(tmp_path: Path, link_kind: str) -> None:
    from inspectra_cli.dependency_graph import validate_go_dependency_graph

    original = tmp_path / "original.json"
    original.write_text(
        '{"complete":true,"contract_version":"2026-09-10.1","ecosystem":"go",'
        '"edges":[],"nodes":[],"producer":"go-mod-graph","roots":[],'
        '"source_commit_sha":"' + "c" * 40 + '","source_sha256":"' + "a" * 64 + '",'
        '"truncation_reason":null}',
        encoding="utf-8",
    )
    linked = tmp_path / "linked.json"
    if link_kind == "symbolic":
        linked.symlink_to(original.name)
    else:
        linked.hardlink_to(original)

    with pytest.raises(SnapshotError, match="bounded regular file"):
        validate_go_dependency_graph(linked, expected_commit_sha="c" * 40, expected_source_sha256="a" * 64)


def test_cargo_graph_rejects_duplicate_keys_before_upload(tmp_path: Path) -> None:
    from inspectra_cli.cargo_dependency_graph import validate_cargo_dependency_graph

    graph = tmp_path / "ambiguous-cargo.json"
    graph.write_text(
        '{"complete":true,"contract_version":"2026-09-10.2","ecosystem":"cargo","ecosystem":"cargo",'
        '"edges":[],"nodes":[],"producer":"cargo-metadata-graph","roots":[],"source_commit_sha":"'
        + "c" * 40 + '","source_sha256":"' + "a" * 64
        + '","target_coverage":"all_locked_targets","targets":["linux"],"truncation_reason":null}',
        encoding="utf-8",
    )
    with pytest.raises(SnapshotError, match="unambiguous"):
        validate_cargo_dependency_graph(
            graph, expected_commit_sha="c" * 40, expected_source_sha256="a" * 64
        )


@pytest.mark.parametrize("link_kind", ["symbolic", "hard"])
def test_cargo_graph_rejects_linked_artifacts(tmp_path: Path, link_kind: str) -> None:
    from inspectra_cli.cargo_dependency_graph import validate_cargo_dependency_graph

    original = tmp_path / "cargo-original.json"
    original.write_text(
        '{"complete":true,"contract_version":"2026-09-10.2","ecosystem":"cargo",'
        '"edges":[],"nodes":[],"producer":"cargo-metadata-graph","roots":[],"source_commit_sha":"'
        + "c" * 40 + '","source_sha256":"' + "a" * 64
        + '","target_coverage":"all_locked_targets","targets":["linux"],"truncation_reason":null}',
        encoding="utf-8",
    )
    linked = tmp_path / "cargo-linked.json"
    linked.symlink_to(original.name) if link_kind == "symbolic" else linked.hardlink_to(original)
    with pytest.raises(SnapshotError, match="bounded regular file"):
        validate_cargo_dependency_graph(
            linked, expected_commit_sha="c" * 40, expected_source_sha256="a" * 64
        )


def test_composer_graph_rejects_duplicate_keys_before_upload(tmp_path: Path) -> None:
    from inspectra_cli.composer_dependency_graph import validate_composer_dependency_graph

    graph = tmp_path / "ambiguous-composer.json"
    graph.write_text(
        '{"complete":true,"contract_version":"2026-09-10.3","ecosystem":"composer","ecosystem":"composer",'
        '"edges":[],"nodes":[],"producer":"composer-locked-graph","roots":[],"source_commit_sha":"'
        + "c" * 40 + '","source_sha256":"' + "a" * 64 + '","truncation_reason":null}',
        encoding="utf-8",
    )
    with pytest.raises(SnapshotError, match="unambiguous"):
        validate_composer_dependency_graph(graph, expected_commit_sha="c" * 40, expected_source_sha256="a" * 64)


@pytest.mark.parametrize("link_kind", ["symbolic", "hard"])
def test_composer_graph_rejects_linked_artifacts(tmp_path: Path, link_kind: str) -> None:
    from inspectra_cli.composer_dependency_graph import validate_composer_dependency_graph

    original = tmp_path / "composer-original.json"
    original.write_text(
        '{"complete":true,"contract_version":"2026-09-10.3","ecosystem":"composer",'
        '"edges":[],"nodes":[],"producer":"composer-locked-graph","roots":[],"source_commit_sha":"'
        + "c" * 40 + '","source_sha256":"' + "a" * 64 + '","truncation_reason":null}',
        encoding="utf-8",
    )
    linked = tmp_path / "composer-linked.json"
    linked.symlink_to(original.name) if link_kind == "symbolic" else linked.hardlink_to(original)
    with pytest.raises(SnapshotError, match="bounded regular file"):
        validate_composer_dependency_graph(linked, expected_commit_sha="c" * 40, expected_source_sha256="a" * 64)


@pytest.mark.parametrize(
    "url",
    [
        "http://example.test:8000",
        "https://user:password@example.test",
        "ftp://localhost",
        "https://example.test/api?token=secret",
    ],
)
def test_api_url_rejects_unsafe_shapes(url: str) -> None:
    with pytest.raises(ApiClientError):
        InspectraApiClient(url)


def test_version_has_one_runtime_source() -> None:
    from inspectra_cli.commands import _parser
    from inspectra_cli.integration_output import render_sarif

    with pytest.raises(SystemExit) as exit_info:
        _parser().parse_args(["--version"])
    assert exit_info.value.code == 0
    sarif = json.loads(render_sarif({"finding_results": []}))
    assert sarif["runs"][0]["tool"]["driver"]["semanticVersion"] == __version__


def test_doctor_checks_external_tools_and_packaged_policy(monkeypatch, tmp_path: Path) -> None:
    git = tmp_path / "git"
    git.write_text("#!/bin/sh\necho 'git version fixture'\n", encoding="utf-8")
    git.chmod(0o700)
    gitleaks = tmp_path / "gitleaks"
    gitleaks.write_text("#!/bin/sh\necho '8.30.1-fixture'\n", encoding="utf-8")
    gitleaks.chmod(0o700)
    monkeypatch.setenv("PATH", str(tmp_path))

    healthy, payload = run_doctor(
        secret_preflight=lambda _: SecretScanResult("gitleaks", "fixture", True, 0),
    )

    assert healthy is (sys.version_info[:2] == (3, 12))
    assert payload["cli_version"] == __version__
    assert {item["name"]: item["status"] for item in payload["checks"]} == {
        "python": "pass",
        "git": "pass",
        "gitleaks": "pass",
        "packaged_policy": "pass",
    }


def test_doctor_fails_closed_when_requirements_are_missing() -> None:
    healthy, payload = run_doctor(which=lambda _: None)

    assert healthy is False
    statuses = {item["name"]: item["status"] for item in payload["checks"]}
    assert statuses["git"] == "fail"
    assert statuses["gitleaks"] == "fail"


def test_scan_rejects_incompatible_server_before_git_gitleaks_or_upload(tmp_path: Path) -> None:
    repository, _ = _repository(tmp_path)
    events: list[str] = []

    class IncompatibleClient:
        def __init__(self, *_: object, **__: object) -> None:
            events.append("client_created")

        def ensure_compatible(self) -> None:
            events.append("handshake")
            raise ClientCompatibilityError("fixture incompatible")

    with pytest.raises(ClientCompatibilityError, match="incompatible"):
        execute_scan(
            _arguments(repository, 1),
            secret_preflight=lambda _: events.append("gitleaks"),
            client_factory=IncompatibleClient,
        )

    assert events == ["client_created", "handshake"]


def test_capabilities_request_omits_automation_credential() -> None:
    _InspectraHandler.capability_authorization_headers = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _InspectraHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        client = InspectraApiClient(
            f"http://127.0.0.1:{server.server_port}", token="must-not-be-sent", timeout_seconds=5
        )
        capabilities = client.ensure_compatible()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert capabilities["status"] == "available"
    assert _InspectraHandler.capability_authorization_headers == [None]


@pytest.mark.parametrize(
    ("status", "payload", "message"),
    [
        (404, {"detail": "not found"}, "does not advertise"),
        (200, {"status": "available"}, "malformed"),
        (
            200,
            {
                **_InspectraHandler.capabilities_payload,
                "supported_cli_protocols": ["obsolete"],
            },
            "incompatible",
        ),
    ],
)
def test_capabilities_rejects_old_malformed_or_incompatible_servers(
    status: int, payload: dict[str, object], message: str
) -> None:
    previous_status = _InspectraHandler.capabilities_status
    previous_payload = _InspectraHandler.capabilities_payload
    _InspectraHandler.capabilities_status = status
    _InspectraHandler.capabilities_payload = payload
    server = ThreadingHTTPServer(("127.0.0.1", 0), _InspectraHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        client = InspectraApiClient(f"http://127.0.0.1:{server.server_port}", timeout_seconds=5)
        with pytest.raises(ClientCompatibilityError, match=message):
            client.ensure_compatible()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        _InspectraHandler.capabilities_status = previous_status
        _InspectraHandler.capabilities_payload = previous_payload
