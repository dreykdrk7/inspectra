"""Local, non-sensitive dependency diagnostics for the Inspectra CLI."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass
from importlib import resources
from pathlib import Path
import platform
import os
import shutil
import subprocess
import sys
import tempfile

from inspectra_cli import __version__
from inspectra_cli.security import SecretScanError, run_secret_preflight


@dataclass(frozen=True)
class DoctorCheck:
    name: str
    status: str
    version: str | None
    detail: str

    def public_dict(self) -> dict[str, str | None]:
        return asdict(self)


def _bounded_version(command: Sequence[str]) -> str | None:
    try:
        completed = subprocess.run(
            command,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=5.0,
            env={"PATH": os.defpath, "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    return " ".join(completed.stdout.replace("\x00", "").split())[:120] or None


def run_doctor(
    *,
    which: Callable[[str], str | None] = shutil.which,
    secret_preflight: Callable[[Path], object] = run_secret_preflight,
) -> tuple[bool, dict[str, object]]:
    checks: list[DoctorCheck] = []
    python_ok = sys.version_info[:2] == (3, 12)
    checks.append(
        DoctorCheck(
            "python",
            "pass" if python_ok else "fail",
            platform.python_version(),
            "Python 3.12 is required." if not python_ok else "Required interpreter is active.",
        )
    )

    git = which("git")
    git_version = _bounded_version([git, "--version"]) if git else None
    checks.append(
        DoctorCheck(
            "git",
            "pass" if git_version else "fail",
            git_version,
            "Git is available for immutable object reads." if git_version else "Install Git and add it to PATH.",
        )
    )

    gitleaks = which("gitleaks")
    gitleaks_version = _bounded_version([gitleaks, "version"]) if gitleaks else None
    canary_ok = False
    if gitleaks_version:
        try:
            with tempfile.TemporaryDirectory(prefix="inspectra-doctor-") as temporary_name:
                empty_source = Path(temporary_name) / "empty"
                empty_source.mkdir(mode=0o700)
                secret_preflight(empty_source)
            canary_ok = True
        except SecretScanError:
            canary_ok = False
    checks.append(
        DoctorCheck(
            "gitleaks",
            "pass" if canary_ok else "fail",
            gitleaks_version,
            (
                "Gitleaks and the packaged policy passed the detector canary."
                if canary_ok
                else "Install Gitleaks 8.x and ensure its detector canary can run."
            ),
        )
    )

    policy_resource = resources.files("inspectra_cli").joinpath("data/gitleaks.toml")
    try:
        policy_present = policy_resource.is_file() and policy_resource.read_bytes().startswith(b"title")
    except OSError:
        policy_present = False
    checks.append(
        DoctorCheck(
            "packaged_policy",
            "pass" if policy_present else "fail",
            None,
            "Built-in Gitleaks policy is readable." if policy_present else "Reinstall the verified CLI artifact.",
        )
    )
    healthy = all(check.status == "pass" for check in checks)
    return healthy, {
        "contract_version": "2026-09-08.1",
        "status": "ready" if healthy else "not_ready",
        "cli_version": __version__,
        "checks": [check.public_dict() for check in checks],
    }
