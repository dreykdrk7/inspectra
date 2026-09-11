"""Fail-closed Gitleaks preflight for private CLI snapshots."""

from __future__ import annotations

from dataclasses import dataclass
from importlib import resources
import json
from pathlib import Path
import shutil
import subprocess
import tempfile


GITLEAKS_FINDINGS_EXIT_CODE = 17


class SecretScanError(RuntimeError):
    """The scanner could not establish a safe result."""


class SecretDetectedError(SecretScanError):
    def __init__(self, finding_count: int) -> None:
        self.finding_count = finding_count
        super().__init__(f"Secret preflight found {finding_count} potential secret(s); upload was blocked.")


@dataclass(frozen=True)
class SecretScanResult:
    scanner: str
    policy: str
    canary_detected: bool
    findings: int

    def public_dict(self) -> dict[str, object]:
        return {
            "scanner": self.scanner,
            "policy": self.policy,
            "canary_detected": self.canary_detected,
            "findings": self.findings,
        }


def _load_finding_count(report_path: Path) -> int:
    try:
        payload = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SecretScanError("Gitleaks did not produce a valid redacted report.") from exc
    if not isinstance(payload, list):
        raise SecretScanError("Gitleaks returned an unsupported report shape.")
    return len(payload)


def _run_gitleaks(gitleaks: str, source: Path, config: Path, report_path: Path) -> tuple[int, int]:
    try:
        completed = subprocess.run(
            [
                gitleaks,
                "dir",
                "--no-banner",
                "--config",
                str(config),
                "--redact=100",
                f"--exit-code={GITLEAKS_FINDINGS_EXIT_CODE}",
                "--report-format=json",
                f"--report-path={report_path}",
                str(source),
            ],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=120.0,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SecretScanError("Gitleaks could not complete within the preflight boundary.") from exc
    if completed.returncode not in {0, GITLEAKS_FINDINGS_EXIT_CODE}:
        raise SecretScanError("Gitleaks failed; upload remains blocked.")
    finding_count = _load_finding_count(report_path) if report_path.exists() else 0
    if completed.returncode == GITLEAKS_FINDINGS_EXIT_CODE and finding_count < 1:
        raise SecretScanError("Gitleaks reported findings without a valid redacted report.")
    if completed.returncode == 0 and finding_count != 0:
        raise SecretScanError("Gitleaks exit status and report disagree.")
    return completed.returncode, finding_count


def run_secret_preflight(source: Path, *, gitleaks_command: str = "gitleaks") -> SecretScanResult:
    gitleaks = shutil.which(gitleaks_command)
    if gitleaks is None:
        raise SecretScanError(
            "Gitleaks is required for inspectra scan. Install Gitleaks and retry; the secret scan cannot be skipped."
        )

    config_resource = resources.files("inspectra_cli").joinpath("data/gitleaks.toml")
    with resources.as_file(config_resource) as config_path, tempfile.TemporaryDirectory(
        prefix="inspectra-gitleaks-"
    ) as temporary_name:
        temporary_root = Path(temporary_name)
        temporary_root.chmod(0o700)
        canary_root = temporary_root / "canary"
        canary_root.mkdir(mode=0o700)
        # Concatenation keeps the synthetic detector canary out of the repository.
        canary_value = "AKIA" + "ABCDEFGHIJKLMNOP"
        canary_file = canary_root / "canary.txt"
        canary_file.write_text(f"aws_access_key_id = {canary_value}\n", encoding="utf-8")
        canary_file.chmod(0o600)
        canary_report = temporary_root / "canary-report.json"
        canary_status, canary_findings = _run_gitleaks(gitleaks, canary_root, config_path, canary_report)
        if canary_status != GITLEAKS_FINDINGS_EXIT_CODE or canary_findings < 1:
            raise SecretScanError("The Gitleaks canary was not detected; upload remains blocked.")

        source_report = temporary_root / "source-report.json"
        source_status, source_findings = _run_gitleaks(gitleaks, source, config_path, source_report)
        if source_status == GITLEAKS_FINDINGS_EXIT_CODE:
            raise SecretDetectedError(source_findings)
        return SecretScanResult(
            scanner="gitleaks",
            policy="built-in-default-rules",
            canary_detected=True,
            findings=0,
        )
