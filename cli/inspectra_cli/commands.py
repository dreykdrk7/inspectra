"""Command-line entry point for safe local Inspectra project analysis."""

from __future__ import annotations

import argparse
from collections.abc import Callable, Sequence
import json
import os
from pathlib import Path
import sys
from typing import Any

from inspectra_cli import __version__

from inspectra_cli.client import (
    AnalysisFailedError,
    AnalysisTimeoutError,
    ApiClientError,
    ClientCompatibilityError,
    InspectraApiClient,
)
from inspectra_cli.git_snapshot import (
    DEFAULT_MAX_FILES,
    DEFAULT_MAX_SOURCE_BYTES,
    SnapshotError,
    build_snapshot,
)
from inspectra_cli.security import SecretDetectedError, SecretScanError, SecretScanResult, run_secret_preflight
from inspectra_cli.policy import evaluate_policy
from inspectra_cli.integration_output import render_json, render_markdown, render_sarif
from inspectra_cli.doctor import run_doctor
from inspectra_cli.config import ConfigError, resolve_scan_configuration, show_profile
from inspectra_cli.dependency_graph import validate_go_dependency_graph
from inspectra_cli.cargo_dependency_graph import validate_cargo_dependency_graph
from inspectra_cli.composer_dependency_graph import validate_composer_dependency_graph
from inspectra_cli.gradle_dependency_graph import validate_gradle_dependency_graph
from inspectra_cli.nuget_dependency_graph import validate_nuget_dependency_graph
from inspectra_cli.graph_producer import produce_ci_graph


EXIT_OK = 0
EXIT_INPUT = 2
EXIT_SECRET_BLOCKED = 3
EXIT_API = 4
EXIT_ANALYSIS = 5
EXIT_TIMEOUT = 6
EXIT_INTERNAL = 7
EXIT_POLICY_FAILED = 8
EXIT_POLICY_INCONCLUSIVE = 9


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="inspectra",
        description="Create a safe snapshot from an authorized Git commit and analyze it with Inspectra.",
    )
    parser.add_argument("--version", action="version", version=f"inspectra-cli {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)
    doctor = subparsers.add_parser("doctor", help="Verify local runtime requirements without reading a repository.")
    doctor.add_argument("--json", action="store_true", help="Emit one machine-readable JSON document.")
    config = subparsers.add_parser("config", help="Validate and inspect secret-free local profiles.")
    config_subparsers = config.add_subparsers(dest="config_command", required=True)
    config_show = config_subparsers.add_parser("show", help="Resolve a profile without exposing credentials.")
    config_show.add_argument("--profile", default=os.environ.get("INSPECTRA_PROFILE", "default"))
    config_show.add_argument("--config", type=Path)
    config_show.add_argument("--json", action="store_true")
    graph = subparsers.add_parser("graph", help="Prepare a closed source-bound graph from sanitized CI observations.")
    graph.add_argument("--ecosystem", required=True, choices=("go", "cargo", "composer", "gradle", "nuget"))
    graph.add_argument("--input", required=True, type=Path)
    graph.add_argument("--output", required=True, type=Path)
    graph.add_argument("--commit", required=True)
    graph.add_argument("--source-sha256", required=True)
    graph.add_argument("--json", action="store_true")
    scan = subparsers.add_parser("scan", help="Analyze a tracked Git commit without reading local changes.")
    scan.add_argument("path", type=Path, help="A path inside the authorized Git repository.")
    scan.add_argument("--commit", default="HEAD", help="Commit or revision to snapshot (default: HEAD).")
    scan.add_argument("--api-url")
    scan.add_argument("--web-url")
    scan.add_argument("--name", help="Optional project display name sent to your Inspectra server.")
    scan.add_argument("--project-id", help="Existing project for idempotent CI admission (requires INSPECTRA_TOKEN).")
    scan.add_argument(
        "--go-graph",
        type=Path,
        help="Closed Go dependency graph JSON produced by authorized CI; requires --project-id for upload.",
    )
    scan.add_argument(
        "--cargo-graph",
        type=Path,
        help="Closed Cargo graph JSON produced by authorized CI; requires --project-id for upload.",
    )
    scan.add_argument(
        "--composer-graph",
        type=Path,
        help="Closed Composer graph JSON produced by authorized CI; requires --project-id for upload.",
    )
    scan.add_argument(
        "--gradle-graph", type=Path,
        help="Closed Gradle graph JSON produced by authorized CI; requires --project-id for upload.",
    )
    scan.add_argument(
        "--nuget-graph", type=Path,
        help="Closed NuGet multi-target graph JSON produced by authorized CI; requires --project-id for upload.",
    )
    scan.add_argument("--profile", default=os.environ.get("INSPECTRA_PROFILE"), help="Secret-free local profile name.")
    scan.add_argument("--config", type=Path, help="Explicit profile file; mode 0600 and not a symlink.")
    scan.add_argument("--branch", help="Optional informational Git branch/ref for CI metadata.")
    scan.add_argument(
        "--policy",
        choices=("observe", "standard", "strict"),
        default=None,
        help="Deterministic result gate. Standard/strict require current public intelligence.",
    )
    scan.add_argument("--dry-run", action="store_true", help="Run the complete local preflight without uploading.")
    scan.add_argument("--json", action="store_true", help="Emit one machine-readable JSON document.")
    scan.add_argument("--format", choices=("human", "json", "markdown", "sarif"), default="human")
    scan.add_argument("--output", type=Path, help="Write JSON, Markdown or SARIF to a new artifact file.")
    scan.add_argument("--yes", action="store_true", help="Do not prompt before upload.")
    scan.add_argument(
        "--confirm-authorized",
        action="store_true",
        help="Confirm you are authorized to analyze this repository; required with --yes.",
    )
    scan.add_argument("--timeout", type=float, help="Maximum analysis wait in seconds (1-900).")
    scan.add_argument(
        "--cancel-on-interrupt",
        action="store_true",
        help="Request cancellation of a newly admitted analysis after timeout or local interruption.",
    )
    scan.add_argument("--http-timeout", type=float, help="Per-request timeout in seconds (1-60).")
    scan.add_argument("--max-files", type=int, default=DEFAULT_MAX_FILES, help="Local retained-file limit (max 5000).")
    scan.add_argument(
        "--max-bytes",
        type=int,
        default=DEFAULT_MAX_SOURCE_BYTES,
        help="Local source byte limit (max 209715200).",
    )
    return parser


def _write_json(payload: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")


def _human_preflight(metadata: dict[str, Any], secret_scan: dict[str, Any]) -> None:
    print("Preflight local completado", file=sys.stderr)
    print(f"  Commit: {metadata['commit']}", file=sys.stderr)
    print(f"  Árbol: {metadata['tree']}", file=sys.stderr)
    print(f"  Archivos incluidos: {metadata['included_files']}", file=sys.stderr)
    print(f"  Archivos excluidos: {metadata['excluded_files']}", file=sys.stderr)
    print(f"  Bytes fuente: {metadata['source_bytes']}", file=sys.stderr)
    print(f"  Bytes TAR: {metadata['archive_bytes']}", file=sys.stderr)
    print(f"  SHA-256: {metadata['archive_sha256']}", file=sys.stderr)
    print(
        f"  Secretos: {secret_scan['findings']} hallazgos; canario detectado={str(secret_scan['canary_detected']).lower()}",
        file=sys.stderr,
    )


def _confirm_upload(commit: str, *, assume_yes: bool, authorization_confirmed: bool) -> bool:
    if assume_yes:
        if not authorization_confirmed:
            raise SnapshotError("--yes requires --confirm-authorized; no upload was attempted.")
        return True
    expected = f"ANALIZAR {commit[:12]}"
    print("Confirma que eres propietario o tienes autorización explícita para analizar este commit.", file=sys.stderr)
    try:
        response = input(f"Escribe {expected} para crear el proyecto y subir la instantánea: ")
    except EOFError:
        return False
    return response.strip() == expected


def _remote_cancellation_after_wait_exit(
    client: InspectraApiClient,
    *,
    enabled: bool,
    replayed: bool,
    project_id: str,
    job_id: str,
) -> str:
    if not enabled:
        return "not_requested"
    if replayed:
        return "skipped_replayed"
    try:
        state = client.cancel_analysis(project_id, job_id)
    except ApiClientError:
        return "not_confirmed"
    return "confirmed_cancelled" if state == "cancelled" else "confirmed_cancelling"


def _annotate_wait_exit(
    exc: BaseException,
    *,
    project_id: str,
    job_id: str,
    result_url: str,
    remote_cancellation: str,
) -> None:
    setattr(exc, "project_id", project_id)
    setattr(exc, "job_id", job_id)
    setattr(exc, "result_url", result_url)
    setattr(exc, "remote_cancellation", remote_cancellation)


def execute_scan(
    arguments: argparse.Namespace,
    *,
    secret_preflight: Callable[[Path], SecretScanResult] = run_secret_preflight,
    client_factory: Callable[..., InspectraApiClient] = InspectraApiClient,
) -> tuple[int, dict[str, Any]]:
    if arguments.json and not arguments.dry_run and not arguments.yes:
        raise SnapshotError("--json requires --yes for uploads so stdout remains one JSON document.")
    go_graph_path = getattr(arguments, "go_graph", None)
    cargo_graph_path = getattr(arguments, "cargo_graph", None)
    composer_graph_path = getattr(arguments, "composer_graph", None)
    gradle_graph_path = getattr(arguments, "gradle_graph", None)
    nuget_graph_path = getattr(arguments, "nuget_graph", None)
    if any(path is not None for path in (go_graph_path, cargo_graph_path, composer_graph_path, gradle_graph_path, nuget_graph_path)) and not arguments.dry_run and not arguments.project_id:
        raise SnapshotError("Dependency graph uploads require an existing --project-id so evidence remains source-bound.")

    token = os.environ.get("INSPECTRA_TOKEN")
    client = None
    if not arguments.dry_run:
        client = client_factory(arguments.api_url, token=token, timeout_seconds=arguments.http_timeout)
        client.ensure_compatible()

    with build_snapshot(
        arguments.path,
        arguments.commit,
        max_files=arguments.max_files,
        max_source_bytes=arguments.max_bytes,
    ) as snapshot:
        go_graph = (
            validate_go_dependency_graph(
                go_graph_path,
                expected_commit_sha=snapshot.metadata.commit,
                expected_source_sha256=snapshot.metadata.archive_sha256,
            )
            if go_graph_path is not None
            else None
        )
        cargo_graph = (
            validate_cargo_dependency_graph(
                cargo_graph_path,
                expected_commit_sha=snapshot.metadata.commit,
                expected_source_sha256=snapshot.metadata.archive_sha256,
            )
            if cargo_graph_path is not None
            else None
        )
        composer_graph = (
            validate_composer_dependency_graph(
                composer_graph_path,
                expected_commit_sha=snapshot.metadata.commit,
                expected_source_sha256=snapshot.metadata.archive_sha256,
            )
            if composer_graph_path is not None
            else None
        )
        gradle_graph = (
            validate_gradle_dependency_graph(
                gradle_graph_path,
                expected_commit_sha=snapshot.metadata.commit,
                expected_source_sha256=snapshot.metadata.archive_sha256,
            )
            if gradle_graph_path is not None
            else None
        )
        nuget_graph = (
            validate_nuget_dependency_graph(
                nuget_graph_path,
                expected_commit_sha=snapshot.metadata.commit,
                expected_source_sha256=snapshot.metadata.archive_sha256,
            )
            if nuget_graph_path is not None
            else None
        )
        secret_scan = secret_preflight(snapshot.scan_root)
        metadata = snapshot.metadata.public_dict()
        security = secret_scan.public_dict()
        if not arguments.json:
            _human_preflight(metadata, security)
        if arguments.dry_run:
            return EXIT_OK, {
                "contract_version": "2026-09-07.1",
                "status": "dry_run_complete",
                "upload_performed": False,
                "authorization_required_before_upload": True,
                "snapshot": metadata,
                "secret_preflight": security,
                "dependency_graph": go_graph.public_dict() if go_graph is not None else None,
                "cargo_dependency_graph": cargo_graph.public_dict() if cargo_graph is not None else None,
                "composer_dependency_graph": composer_graph.public_dict() if composer_graph is not None else None,
                "gradle_dependency_graph": gradle_graph.public_dict() if gradle_graph is not None else None,
                "nuget_dependency_graph": nuget_graph.public_dict() if nuget_graph is not None else None,
            }
        if not _confirm_upload(
            snapshot.metadata.commit,
            assume_yes=arguments.yes,
            authorization_confirmed=arguments.confirm_authorized,
        ):
            raise SnapshotError("Confirmation did not match; no upload was attempted.")

        assert client is not None
        replayed = False
        if arguments.project_id:
            if not token:
                raise ApiClientError("--project-id requires INSPECTRA_TOKEN from the CI secret store.")
            if arguments.name:
                raise SnapshotError("--name cannot be combined with --project-id.")
            project_id = arguments.project_id
            job_id, replayed = client.submit_ci_snapshot(
                snapshot.archive_path,
                project_id=project_id,
                commit_sha=snapshot.metadata.commit,
                source_sha256=snapshot.metadata.archive_sha256,
                branch=arguments.branch,
            )
        else:
            file_id = client.upload_archive(snapshot.archive_path)
            try:
                project_id, job_id = client.create_project(file_id, name=arguments.name)
            except Exception:
                client.delete_file(file_id)
                raise
        result_url = client.result_url(arguments.web_url, project_id, job_id)
        try:
            client.wait_for_analysis(job_id, timeout_seconds=arguments.timeout)
        except AnalysisTimeoutError as exc:
            cancellation = _remote_cancellation_after_wait_exit(
                client,
                enabled=getattr(arguments, "cancel_on_interrupt", False),
                replayed=replayed,
                project_id=project_id,
                job_id=job_id,
            )
            _annotate_wait_exit(
                exc,
                project_id=project_id,
                job_id=job_id,
                result_url=result_url,
                remote_cancellation=cancellation,
            )
            raise
        except AnalysisFailedError as exc:
            _annotate_wait_exit(
                exc,
                project_id=project_id,
                job_id=job_id,
                result_url=result_url,
                remote_cancellation="not_applicable",
            )
            raise
        except KeyboardInterrupt as exc:
            cancellation = _remote_cancellation_after_wait_exit(
                client,
                enabled=getattr(arguments, "cancel_on_interrupt", False),
                replayed=replayed,
                project_id=project_id,
                job_id=job_id,
            )
            _annotate_wait_exit(
                exc,
                project_id=project_id,
                job_id=job_id,
                result_url=result_url,
                remote_cancellation=cancellation,
            )
            raise
        graph_receipt = None
        if go_graph is not None:
            graph_receipt = client.attach_go_dependency_graph(
                project_id,
                job_id,
                payload=go_graph.payload,
                artifact_sha256=go_graph.sha256,
            )
        cargo_graph_receipt = None
        if cargo_graph is not None:
            cargo_graph_receipt = client.attach_cargo_dependency_graph(
                project_id,
                job_id,
                payload=cargo_graph.payload,
                artifact_sha256=cargo_graph.sha256,
            )
        composer_graph_receipt = None
        if composer_graph is not None:
            composer_graph_receipt = client.attach_composer_dependency_graph(
                project_id,
                job_id,
                payload=composer_graph.payload,
                artifact_sha256=composer_graph.sha256,
            )
        gradle_graph_receipt = None
        if gradle_graph is not None:
            gradle_graph_receipt = client.attach_gradle_dependency_graph(
                project_id, job_id, payload=gradle_graph.payload,
                artifact_sha256=gradle_graph.sha256,
            )
        nuget_graph_receipt = None
        if nuget_graph is not None:
            nuget_graph_receipt = client.attach_nuget_dependency_graph(
                project_id, job_id, payload=nuget_graph.payload,
                artifact_sha256=nuget_graph.sha256,
            )
        summary = client.project_summary(project_id, job_id)
        policy_context = client.project_policy_context(project_id, job_id)
        policy = evaluate_policy(arguments.policy, policy_context)
        local_findings = policy_context.get("findings", {}).get("findings", [])
        public_findings = policy_context.get("public_intelligence", {}).get("findings", [])
        exit_code = (
            EXIT_POLICY_INCONCLUSIVE if policy["verdict"] == "inconclusive"
            else EXIT_POLICY_FAILED if policy["verdict"] == "fail"
            else EXIT_OK
        )
        return exit_code, {
            "contract_version": "2026-09-07.1",
            "status": "completed",
            "upload_performed": True,
            "snapshot": metadata,
            "secret_preflight": security,
            "project_id": project_id,
            "analysis_id": job_id,
            "ci_replayed": replayed,
            "dependency_graph": graph_receipt,
            "cargo_dependency_graph": cargo_graph_receipt,
            "composer_dependency_graph": composer_graph_receipt,
            "gradle_dependency_graph": gradle_graph_receipt,
            "nuget_dependency_graph": nuget_graph_receipt,
            "result_url": result_url,
            "policy": policy,
            "finding_results": [
                *([item for item in local_findings if isinstance(item, dict)] if isinstance(local_findings, list) else []),
                *([item for item in public_findings if isinstance(item, dict)] if isinstance(public_findings, list) else []),
            ],
            **summary,
        }


def _safe_error_payload(code: str, message: str, exc: BaseException | None = None) -> dict[str, Any]:
    payload: dict[str, Any] = {"contract_version": "2026-09-07.1", "status": "error", "code": code, "message": message}
    if exc is not None:
        for field in ("project_id", "job_id", "result_url"):
            value = getattr(exc, field, None)
            if isinstance(value, str):
                payload[field] = value
        remote_cancellation = getattr(exc, "remote_cancellation", None)
        if remote_cancellation in {
            "not_requested",
            "skipped_replayed",
            "not_confirmed",
            "confirmed_cancelling",
            "confirmed_cancelled",
            "not_applicable",
        }:
            payload["remote_cancellation"] = remote_cancellation
    return payload


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    if arguments.command == "doctor":
        healthy, payload = run_doctor()
        if arguments.json:
            _write_json(payload)
        else:
            print(f"Inspectra CLI {payload['cli_version']}: {payload['status']}")
            for check in payload["checks"]:
                version = f" ({check['version']})" if check["version"] else ""
                print(f"  [{check['status']}] {check['name']}{version}: {check['detail']}")
        return EXIT_OK if healthy else EXIT_INPUT
    if arguments.command == "config":
        try:
            payload = show_profile(arguments.profile, arguments.config)
        except ConfigError as exc:
            if arguments.json:
                _write_json(_safe_error_payload("config_invalid", str(exc)))
            else:
                print(f"Error [config_invalid]: {exc}", file=sys.stderr)
            return EXIT_INPUT
        if arguments.json:
            _write_json(payload)
        else:
            print(f"Perfil {payload['profile']}: {payload['status']}")
            for field, value in payload["values"].items():
                print(f"  {field}: {value!s} [{payload['sources'][field]}]")
            print(f"  automation_token: {payload['automation_token']}")
        return EXIT_OK
    if arguments.command == "graph":
        try:
            payload = produce_ci_graph(
                arguments.ecosystem, arguments.input, arguments.output,
                commit_sha=arguments.commit, source_sha256=arguments.source_sha256,
            )
        except SnapshotError as exc:
            if arguments.json:
                _write_json(_safe_error_payload("graph_preflight_failed", str(exc)))
            else:
                print(f"Error [graph_preflight_failed]: {exc}", file=sys.stderr)
            return EXIT_INPUT
        if arguments.json:
            _write_json(payload)
        else:
            print(f"Graph artifact created: {payload['ecosystem']} · {payload['artifact_sha256']}")
        return EXIT_OK
    try:
        resolve_scan_configuration(arguments)
    except ConfigError as exc:
        if getattr(arguments, "json", False):
            _write_json(_safe_error_payload("config_invalid", str(exc)))
        else:
            print(f"Error [config_invalid]: {exc}", file=sys.stderr)
        return EXIT_INPUT
    if arguments.json:
        arguments.format = "json"
    try:
        exit_code, payload = execute_scan(arguments)
    except SecretDetectedError as exc:
        exit_code = EXIT_SECRET_BLOCKED
        payload = _safe_error_payload("secret_detected", str(exc))
    except SecretScanError as exc:
        exit_code = EXIT_SECRET_BLOCKED
        payload = _safe_error_payload("secret_scan_failed", str(exc))
    except SnapshotError as exc:
        exit_code = EXIT_INPUT
        payload = _safe_error_payload("preflight_failed", str(exc))
    except AnalysisTimeoutError as exc:
        exit_code = EXIT_TIMEOUT
        cancellation = getattr(exc, "remote_cancellation", "not_requested")
        messages = {
            "confirmed_cancelling": "Analysis wait timed out; Inspectra accepted one remote cancellation request.",
            "confirmed_cancelled": "Analysis wait timed out; Inspectra confirmed the remote analysis is cancelled.",
            "skipped_replayed": "Analysis wait timed out; remote cancellation was skipped because the analysis was an existing replay.",
            "not_confirmed": "Analysis wait timed out; remote cancellation could not be confirmed. Inspect the linked analysis.",
            "not_requested": str(exc),
        }
        payload = _safe_error_payload(
            "analysis_timeout", messages.get(cancellation, str(exc)), exc
        )
    except AnalysisFailedError as exc:
        exit_code = EXIT_ANALYSIS
        payload = _safe_error_payload("analysis_failed", str(exc), exc)
    except ApiClientError as exc:
        exit_code = EXIT_API
        payload = _safe_error_payload("api_error", str(exc))
    except KeyboardInterrupt as exc:
        exit_code = 130
        cancellation = getattr(exc, "remote_cancellation", "not_requested")
        messages = {
            "confirmed_cancelling": "Interrupted locally; Inspectra accepted one remote cancellation request.",
            "confirmed_cancelled": "Interrupted locally; Inspectra confirmed the remote analysis is cancelled.",
            "skipped_replayed": "Interrupted locally; remote cancellation was skipped because the analysis was an existing replay.",
            "not_confirmed": "Interrupted locally; remote cancellation could not be confirmed. Inspect the linked analysis.",
            "not_requested": "Interrupted locally; the remote analysis was left running by default.",
        }
        payload = _safe_error_payload(
            "interrupted",
            messages.get(cancellation, "Interrupted locally; no additional operation was started."),
            exc,
        )
    except Exception:
        exit_code = EXIT_INTERNAL
        payload = _safe_error_payload("internal_error", "Inspectra CLI stopped on an unexpected local error.")

    if arguments.format in {"json", "markdown", "sarif"}:
        rendered = (
            render_json(payload) if arguments.format == "json"
            else render_markdown(payload) if arguments.format == "markdown"
            else render_sarif(payload)
        )
        if arguments.output:
            try:
                with arguments.output.open("x", encoding="utf-8") as destination:
                    destination.write(rendered)
            except (OSError, ValueError):
                print("Error [output_failed]: output artifact could not be created safely.", file=sys.stderr)
                return EXIT_INTERNAL
        else:
            sys.stdout.write(rendered)
    elif exit_code == EXIT_OK:
        if payload["status"] == "dry_run_complete":
            print("Dry-run completo; no se subió ningún archivo.")
        else:
            print(f"Análisis completado: {payload['result_url']}")
            findings = payload.get("findings") or {}
            print(f"Hallazgos locales: {findings.get('total', 0)}")
            intelligence = payload.get("public_intelligence") or {}
            print(f"Inteligencia pública: {intelligence.get('state', 'unavailable')}")
    elif exit_code in {EXIT_POLICY_FAILED, EXIT_POLICY_INCONCLUSIVE}:
        print(f"Policy {payload['policy']['policy']}: {payload['policy']['verdict']}", file=sys.stderr)
        print(f"Seguimiento: {payload['result_url']}", file=sys.stderr)
    else:
        print(f"Error [{payload['code']}]: {payload['message']}", file=sys.stderr)
        if payload.get("result_url"):
            print(f"Seguimiento: {payload['result_url']}", file=sys.stderr)
    return exit_code
