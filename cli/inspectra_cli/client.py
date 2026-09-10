"""Small bounded HTTP client for the existing Inspectra project API."""

from __future__ import annotations

import http.client
import hashlib
import json
from pathlib import Path
import secrets
import ssl
import time
from typing import Any
import re
from urllib.parse import quote, urlencode, urlsplit, urlunsplit

from inspectra_cli import __version__
from inspectra_cli.contracts import CLI_PROTOCOL_VERSION, REQUIRED_SERVER_CONTRACTS


MAX_RESPONSE_BYTES = 2 * 1024 * 1024
TERMINAL_JOB_STATES = frozenset({"completed", "failed", "cancelled"})


class ApiClientError(RuntimeError):
    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        self.status_code = status_code
        super().__init__(message)


class ClientCompatibilityError(ApiClientError):
    pass


class AnalysisTimeoutError(ApiClientError):
    pass


class AnalysisFailedError(ApiClientError):
    def __init__(self, state: str, termination_reason: str | None = None) -> None:
        self.state = state
        self.termination_reason = termination_reason
        message = f"Inspectra analysis ended as {state}."
        if termination_reason:
            message += f" Reason: {termination_reason}."
        super().__init__(message)


def _validate_base_url(value: str) -> tuple[str, str, int, str]:
    parsed = urlsplit(value.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ApiClientError("The Inspectra URL must use HTTPS, or HTTP on loopback.")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ApiClientError("The Inspectra URL cannot contain credentials, a query or a fragment.")
    host = parsed.hostname.lower().rstrip(".")
    if parsed.scheme == "http" and host not in {"localhost", "127.0.0.1", "::1"}:
        raise ApiClientError("Plain HTTP is allowed only for a loopback Inspectra server.")
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise ApiClientError("The Inspectra URL contains an invalid port.") from exc
    path = parsed.path.rstrip("/")
    if ".." in path.split("/") or any(ord(character) < 32 for character in path):
        raise ApiClientError("The Inspectra URL path is invalid.")
    return parsed.scheme, host, port, path


class InspectraApiClient:
    def __init__(self, base_url: str, *, token: str | None = None, timeout_seconds: float = 15.0) -> None:
        self.scheme, self.host, self.port, self.base_path = _validate_base_url(base_url)
        if not 1 <= timeout_seconds <= 60:
            raise ApiClientError("HTTP timeout must be between 1 and 60 seconds.")
        self.timeout_seconds = timeout_seconds
        self.token = token.strip() if token else None
        if self.token and (len(self.token) > 512 or any(ord(character) < 33 for character in self.token)):
            raise ApiClientError("The automation token has an invalid shape.")

    def _connection(self) -> http.client.HTTPConnection:
        if self.scheme == "https":
            return http.client.HTTPSConnection(
                self.host,
                self.port,
                timeout=self.timeout_seconds,
                context=ssl.create_default_context(),
            )
        return http.client.HTTPConnection(self.host, self.port, timeout=self.timeout_seconds)

    def _headers(self, *, include_authorization: bool = True) -> dict[str, str]:
        headers = {"Accept": "application/json", "User-Agent": f"inspectra-cli/{__version__}"}
        if include_authorization and self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _path(self, path: str) -> str:
        if not path.startswith("/"):
            raise ApiClientError("Internal API path is invalid.")
        return f"{self.base_path}{path}" or "/"

    @staticmethod
    def _read_json_response(response: http.client.HTTPResponse) -> dict[str, Any] | list[Any]:
        content_length = response.getheader("Content-Length")
        if content_length:
            try:
                if int(content_length) > MAX_RESPONSE_BYTES:
                    raise ApiClientError("Inspectra returned an oversized response.", status_code=response.status)
            except ValueError as exc:
                raise ApiClientError("Inspectra returned an invalid response length.") from exc
        payload = response.read(MAX_RESPONSE_BYTES + 1)
        if len(payload) > MAX_RESPONSE_BYTES:
            raise ApiClientError("Inspectra returned an oversized response.")
        if not 200 <= response.status < 300:
            raise ApiClientError(f"Inspectra API request failed with HTTP {response.status}.", status_code=response.status)
        try:
            parsed = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ApiClientError("Inspectra returned an invalid JSON response.") from exc
        if not isinstance(parsed, (dict, list)):
            raise ApiClientError("Inspectra returned an unsupported JSON response.")
        return parsed

    def request_json(self, method: str, path: str, body: dict[str, Any] | None = None) -> dict[str, Any] | list[Any]:
        payload = json.dumps(body, separators=(",", ":")).encode("utf-8") if body is not None else None
        headers = self._headers()
        if payload is not None:
            headers["Content-Type"] = "application/json"
        connection = self._connection()
        try:
            connection.request(method, self._path(path), body=payload, headers=headers)
            return self._read_json_response(connection.getresponse())
        except (OSError, http.client.HTTPException) as exc:
            raise ApiClientError("Inspectra could not be reached within the HTTP boundary.") from exc
        finally:
            connection.close()

    def ensure_compatible(self) -> dict[str, Any]:
        """Negotiate a source-free contract before Git or Gitleaks access."""

        connection = self._connection()
        try:
            connection.request(
                "GET",
                self._path("/client-capabilities"),
                headers=self._headers(include_authorization=False),
            )
            payload = self._read_json_response(connection.getresponse())
        except ApiClientError as exc:
            if exc.status_code == 404:
                raise ClientCompatibilityError(
                    "This Inspectra server does not advertise CLI compatibility; upgrade the server before scanning."
                ) from exc
            raise ClientCompatibilityError(
                "Inspectra CLI compatibility could not be established; no repository data was processed."
            ) from exc
        except (OSError, http.client.HTTPException) as exc:
            raise ClientCompatibilityError(
                "The Inspectra server is unavailable; no repository data was processed."
            ) from exc
        finally:
            connection.close()
        expected_fields = {"contract_version", "status", "server_version", "supported_cli_protocols", "contracts"}
        if not isinstance(payload, dict) or set(payload) != expected_fields:
            raise ClientCompatibilityError("Inspectra returned a malformed CLI capabilities contract.")
        protocols = payload.get("supported_cli_protocols")
        contracts = payload.get("contracts")
        if (
            payload.get("contract_version") != CLI_PROTOCOL_VERSION
            or payload.get("status") != "available"
            or not isinstance(payload.get("server_version"), str)
            or not isinstance(protocols, list)
            or not all(isinstance(item, str) for item in protocols)
            or not isinstance(contracts, dict)
            or set(contracts) != set(REQUIRED_SERVER_CONTRACTS)
            or not all(
                isinstance(versions, list) and all(isinstance(version, str) for version in versions)
                for versions in contracts.values()
            )
        ):
            raise ClientCompatibilityError("Inspectra returned a malformed CLI capabilities contract.")
        incompatible = [
            name
            for name, required in REQUIRED_SERVER_CONTRACTS.items()
            if required not in contracts[name]
        ]
        if CLI_PROTOCOL_VERSION not in protocols or incompatible:
            detail = ", ".join(incompatible) if incompatible else "cli_protocol"
            raise ClientCompatibilityError(
                f"CLI/server contracts are incompatible ({detail}); install a compatible CLI or upgrade the server."
            )
        return payload

    def upload_archive(self, archive_path: Path) -> str:
        boundary = f"inspectra-{secrets.token_hex(16)}"
        prefix = (
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="file"; filename="snapshot.tar"\r\n'
            "Content-Type: application/x-tar\r\n\r\n"
        ).encode("ascii")
        suffix = f"\r\n--{boundary}--\r\n".encode("ascii")
        content_length = len(prefix) + archive_path.stat().st_size + len(suffix)
        connection = self._connection()
        try:
            connection.putrequest("POST", self._path("/files/archive"))
            for name, value in self._headers().items():
                connection.putheader(name, value)
            connection.putheader("Content-Type", f"multipart/form-data; boundary={boundary}")
            connection.putheader("Content-Length", str(content_length))
            connection.endheaders()
            connection.send(prefix)
            with archive_path.open("rb") as source:
                while chunk := source.read(1024 * 1024):
                    connection.send(chunk)
            connection.send(suffix)
            payload = self._read_json_response(connection.getresponse())
        except (OSError, http.client.HTTPException) as exc:
            raise ApiClientError("The snapshot upload did not complete safely.") from exc
        finally:
            connection.close()
        if not isinstance(payload, dict) or not isinstance(payload.get("id"), str):
            raise ApiClientError("Inspectra did not return a valid uploaded source identifier.")
        return payload["id"]

    def submit_ci_snapshot(
        self,
        archive_path: Path,
        *,
        project_id: str,
        commit_sha: str,
        source_sha256: str,
        branch: str | None = None,
    ) -> tuple[str, bool]:
        if not re.fullmatch(r"[a-f0-9]{32}", project_id):
            raise ApiClientError("The CI project identifier is invalid.")
        if not re.fullmatch(r"[a-f0-9]{40,64}", commit_sha):
            raise ApiClientError("The CI commit identifier is invalid.")
        if not re.fullmatch(r"[a-f0-9]{64}", source_sha256):
            raise ApiClientError("The CI source digest is invalid.")
        fields = {
            "commit_sha": commit_sha,
            "source_sha256": source_sha256,
            "authorization_confirmed": "true",
            **({"branch": branch} if branch else {}),
        }
        boundary = f"inspectra-{secrets.token_hex(16)}"
        field_bytes = b"".join(
            (
                f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
            ).encode("utf-8")
            for name, value in fields.items()
        )
        file_prefix = (
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="file"; filename="snapshot.tar"\r\n'
            "Content-Type: application/x-tar\r\n\r\n"
        ).encode("ascii")
        suffix = f"\r\n--{boundary}--\r\n".encode("ascii")
        content_length = len(field_bytes) + len(file_prefix) + archive_path.stat().st_size + len(suffix)
        connection = self._connection()
        try:
            connection.putrequest("POST", self._path(f"/projects/{project_id}/ci/snapshots"))
            for name, value in self._headers().items():
                connection.putheader(name, value)
            connection.putheader("Content-Type", f"multipart/form-data; boundary={boundary}")
            connection.putheader("Content-Length", str(content_length))
            connection.endheaders()
            connection.send(field_bytes)
            connection.send(file_prefix)
            with archive_path.open("rb") as source:
                while chunk := source.read(1024 * 1024):
                    connection.send(chunk)
            connection.send(suffix)
            payload = self._read_json_response(connection.getresponse())
        except (OSError, http.client.HTTPException) as exc:
            raise ApiClientError("The CI snapshot admission did not complete safely.") from exc
        finally:
            connection.close()
        if not isinstance(payload, dict) or not isinstance(payload.get("job"), dict):
            raise ApiClientError("Inspectra did not return a valid CI admission response.")
        job_id = payload["job"].get("id")
        if not isinstance(job_id, str) or not re.fullmatch(r"[a-f0-9]{32}", job_id):
            raise ApiClientError("Inspectra did not return a valid CI analysis identifier.")
        return job_id, payload.get("replayed") is True

    def attach_go_dependency_graph(
        self,
        project_id: str,
        analysis_id: str,
        *,
        payload: bytes,
        artifact_sha256: str,
    ) -> dict[str, Any]:
        """Attach one already-validated bounded artifact without logging identities."""
        return self._attach_dependency_graph(project_id, analysis_id, ecosystem="go", payload=payload, artifact_sha256=artifact_sha256)

    def attach_cargo_dependency_graph(
        self,
        project_id: str,
        analysis_id: str,
        *,
        payload: bytes,
        artifact_sha256: str,
    ) -> dict[str, Any]:
        """Attach one locally validated Cargo artifact without logging identities."""
        return self._attach_dependency_graph(project_id, analysis_id, ecosystem="cargo", payload=payload, artifact_sha256=artifact_sha256)

    def attach_composer_dependency_graph(
        self,
        project_id: str,
        analysis_id: str,
        *,
        payload: bytes,
        artifact_sha256: str,
    ) -> dict[str, Any]:
        """Attach one locally validated Composer artifact without free-form metadata."""
        return self._attach_dependency_graph(project_id, analysis_id, ecosystem="composer", payload=payload, artifact_sha256=artifact_sha256)

    def attach_gradle_dependency_graph(
        self, project_id: str, analysis_id: str, *, payload: bytes, artifact_sha256: str,
    ) -> dict[str, Any]:
        """Attach one locally validated Gradle artifact without source metadata."""
        return self._attach_dependency_graph(
            project_id, analysis_id, ecosystem="gradle", receipt_ecosystem="maven",
            payload=payload, artifact_sha256=artifact_sha256,
        )

    def attach_nuget_dependency_graph(
        self, project_id: str, analysis_id: str, *, payload: bytes, artifact_sha256: str,
    ) -> dict[str, Any]:
        """Attach one locally validated NuGet artifact without target names."""
        return self._attach_dependency_graph(
            project_id, analysis_id, ecosystem="nuget",
            payload=payload, artifact_sha256=artifact_sha256,
        )

    def _attach_dependency_graph(
        self, project_id: str, analysis_id: str, *, ecosystem: str,
        receipt_ecosystem: str | None = None, payload: bytes, artifact_sha256: str
    ) -> dict[str, Any]:
        if ecosystem not in {"go", "cargo", "composer", "gradle", "nuget"}:
            raise ApiClientError("The dependency evidence ecosystem is invalid.")
        if not re.fullmatch(r"[a-f0-9]{32}", project_id) or not re.fullmatch(r"[a-f0-9]{32}", analysis_id):
            raise ApiClientError("The dependency evidence destination is invalid.")
        if not payload or len(payload) > 1_048_576:
            raise ApiClientError("The dependency evidence exceeds its fixed size limit.")
        if not re.fullmatch(r"[a-f0-9]{64}", artifact_sha256) or hashlib.sha256(payload).hexdigest() != artifact_sha256:
            raise ApiClientError("The dependency evidence digest changed after local validation.")
        boundary = f"inspectra-{secrets.token_hex(16)}"
        field_bytes = (
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"artifact_sha256\"\r\n\r\n{artifact_sha256}\r\n"
        ).encode("ascii")
        file_prefix = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{ecosystem}-dependency-graph.json"\r\n'
            "Content-Type: application/json\r\n\r\n"
        ).encode("ascii")
        suffix = f"\r\n--{boundary}--\r\n".encode("ascii")
        connection = self._connection()
        try:
            connection.putrequest(
                "POST",
                self._path(f"/projects/{project_id}/analyses/{analysis_id}/dependency-graphs/{ecosystem}"),
            )
            for name, value in self._headers().items():
                connection.putheader(name, value)
            connection.putheader("Content-Type", f"multipart/form-data; boundary={boundary}")
            connection.putheader("Content-Length", str(len(field_bytes) + len(file_prefix) + len(payload) + len(suffix)))
            connection.endheaders()
            connection.send(field_bytes)
            connection.send(file_prefix)
            connection.send(payload)
            connection.send(suffix)
            response = self._read_json_response(connection.getresponse())
        except (OSError, http.client.HTTPException) as exc:
            raise ApiClientError("The dependency evidence upload did not complete safely.") from exc
        finally:
            connection.close()
        if (
            not isinstance(response, dict)
            or response.get("ecosystem") != (receipt_ecosystem or ecosystem)
            or response.get("state") not in {"accepted", "truncated", "divergent"}
            or response.get("artifact_sha256") != artifact_sha256
        ):
            raise ApiClientError("Inspectra did not return a valid dependency evidence receipt.")
        return response

    def delete_file(self, file_id: str) -> None:
        try:
            self.request_json("DELETE", f"/files/{quote(file_id, safe='')}")
        except ApiClientError:
            # This is best-effort cleanup after a failed project creation. The
            # original exception remains the public failure.
            return

    def create_project(self, file_id: str, *, name: str | None = None) -> tuple[str, str]:
        body: dict[str, Any] = {"source_file_id": file_id, "authorization_confirmed": True}
        if name:
            body["name"] = name
        payload = self.request_json("POST", "/projects", body)
        if not isinstance(payload, dict):
            raise ApiClientError("Inspectra did not return a valid project response.")
        project = payload.get("project")
        job = payload.get("job")
        if not isinstance(project, dict) or not isinstance(project.get("id"), str):
            raise ApiClientError("Inspectra did not return a valid project identifier.")
        if not isinstance(job, dict) or not isinstance(job.get("id"), str):
            raise ApiClientError("Inspectra did not return a valid analysis identifier.")
        return project["id"], job["id"]

    def wait_for_analysis(self, job_id: str, *, timeout_seconds: float, poll_seconds: float = 1.0) -> dict[str, Any]:
        if not 1 <= timeout_seconds <= 900:
            raise ApiClientError("Analysis wait timeout must be between 1 and 900 seconds.")
        deadline = time.monotonic() + timeout_seconds
        while True:
            payload = self.request_json("GET", f"/jobs/{quote(job_id, safe='')}")
            if not isinstance(payload, dict) or not isinstance(payload.get("status"), str):
                raise ApiClientError("Inspectra returned an invalid analysis state.")
            state = payload["status"]
            if state in TERMINAL_JOB_STATES:
                if state != "completed":
                    reason = payload.get("termination_reason")
                    raise AnalysisFailedError(state, reason if isinstance(reason, str) else None)
                return payload
            if state not in {"queued", "running", "cancelling"}:
                raise ApiClientError("Inspectra returned an unknown analysis state.")
            if time.monotonic() >= deadline:
                raise AnalysisTimeoutError("Timed out waiting for Inspectra analysis; the server job may still be running.")
            time.sleep(min(poll_seconds, max(0.0, deadline - time.monotonic())))

    def cancel_analysis(self, project_id: str, job_id: str) -> str:
        """Request cancellation for one exact project analysis and validate its state."""

        if not re.fullmatch(r"[a-f0-9]{32}", project_id) or not re.fullmatch(r"[a-f0-9]{32}", job_id):
            raise ApiClientError("The analysis cancellation destination is invalid.")
        payload = self.request_json(
            "POST",
            f"/projects/{quote(project_id, safe='')}/analyses/{quote(job_id, safe='')}/cancel",
        )
        if (
            not isinstance(payload, dict)
            or payload.get("id") != job_id
            or payload.get("status") not in {"cancelling", "cancelled"}
        ):
            raise ApiClientError("Inspectra did not confirm analysis cancellation.")
        return payload["status"]

    def project_summary(self, project_id: str, analysis_id: str) -> dict[str, Any]:
        findings = self.request_json(
            "GET",
            f"/projects/{quote(project_id, safe='')}/findings?{urlencode({'analysis_id': analysis_id})}",
        )
        intelligence = self.request_json(
            "GET",
            f"/projects/{quote(project_id, safe='')}/analyses/{quote(analysis_id, safe='')}/vulnerability-intelligence",
        )
        finding_summary = findings.get("summary", {}) if isinstance(findings, dict) else {}
        coverage = findings.get("coverage") if isinstance(findings, dict) else None
        public_summary = intelligence.get("summary", {}) if isinstance(intelligence, dict) else {}
        return {
            "findings": finding_summary if isinstance(finding_summary, dict) else {},
            "coverage": coverage if isinstance(coverage, dict) else None,
            "public_intelligence": {
                "state": intelligence.get("state") if isinstance(intelligence, dict) else "unavailable",
                "summary": public_summary if isinstance(public_summary, dict) else {},
            },
        }

    def project_policy_context(self, project_id: str, analysis_id: str) -> dict[str, Any]:
        project = self.request_json("GET", f"/projects/{quote(project_id, safe='')}")
        findings = self.request_json(
            "GET", f"/projects/{quote(project_id, safe='')}/findings?{urlencode({'analysis_id': analysis_id})}"
        )
        intelligence = self.request_json(
            "GET", f"/projects/{quote(project_id, safe='')}/analyses/{quote(analysis_id, safe='')}/vulnerability-intelligence"
        )
        comparison = None
        if isinstance(project, dict) and isinstance(project.get("project"), dict):
            baseline_id = project["project"].get("baseline_analysis_id")
            if isinstance(baseline_id, str) and baseline_id != analysis_id:
                comparison = self.request_json(
                    "GET",
                    f"/projects/{quote(project_id, safe='')}/comparisons?"
                    + urlencode({"base_analysis_id": baseline_id, "target_analysis_id": analysis_id}),
                )
        return {
            "findings": findings if isinstance(findings, dict) else {},
            "public_intelligence": intelligence if isinstance(intelligence, dict) else {},
            "comparison": comparison if isinstance(comparison, dict) else None,
        }

    def result_url(self, web_url: str | None, project_id: str, job_id: str) -> str:
        if web_url:
            scheme, host, port, path = _validate_base_url(web_url)
        else:
            scheme, host, port, path = self.scheme, self.host, self.port, ""
        default_port = 443 if scheme == "https" else 80
        display_host = f"[{host}]" if ":" in host else host
        netloc = display_host if port == default_port else f"{display_host}:{port}"
        fragment = urlencode({"project": project_id, "job": job_id})
        return urlunsplit((scheme, netloc, path or "/", "", fragment))
