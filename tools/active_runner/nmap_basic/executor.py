from __future__ import annotations

import subprocess
from collections.abc import Callable, Mapping
from typing import Any, TypeAlias

from active_runner.contracts import (
    ACTIVE_NMAP_BASIC_CAPABILITY,
    ACTIVE_NMAP_BASIC_MAX_STDERR_BYTES,
    ACTIVE_NMAP_BASIC_MAX_STDOUT_BYTES,
    ACTIVE_NMAP_BASIC_PROCESS_TIMEOUT_SECONDS,
    ACTIVE_NMAP_BASIC_PROFILE,
    ActiveNmapBasicCommandError,
)

from .command_builder import build_active_nmap_basic_argv
from .service import (
    ActiveNmapBasicServiceError,
    ActiveNmapBasicServiceRequest,
    coerce_active_nmap_basic_service_request,
    validate_active_nmap_basic_service_contract,
)
from .target_policy import ActiveNmapBasicTargetPolicyError, validate_active_nmap_basic_execution_target


ActiveNmapBasicExecutionResult: TypeAlias = dict[str, Any]
ActiveNmapBasicSubprocessRunner = Callable[..., subprocess.CompletedProcess[bytes]]


def execute_active_nmap_basic(
    request: ActiveNmapBasicServiceRequest | Mapping[str, Any],
    *,
    runner: ActiveNmapBasicSubprocessRunner | None = None,
    timeout_seconds: int = ACTIVE_NMAP_BASIC_PROCESS_TIMEOUT_SECONDS,
    max_stdout_bytes: int = ACTIVE_NMAP_BASIC_MAX_STDOUT_BYTES,
    max_stderr_bytes: int = ACTIVE_NMAP_BASIC_MAX_STDERR_BYTES,
) -> ActiveNmapBasicExecutionResult:
    timeout_budget = _bounded_limit(timeout_seconds, ACTIVE_NMAP_BASIC_PROCESS_TIMEOUT_SECONDS)
    stdout_budget = _bounded_limit(max_stdout_bytes, ACTIVE_NMAP_BASIC_MAX_STDOUT_BYTES)
    stderr_budget = _bounded_limit(max_stderr_bytes, ACTIVE_NMAP_BASIC_MAX_STDERR_BYTES)

    try:
        normalized_request = coerce_active_nmap_basic_service_request(request)
        validate_active_nmap_basic_service_contract(normalized_request)
        target_policy = validate_active_nmap_basic_execution_target(normalized_request.target)
        argv = build_active_nmap_basic_argv(
            target=target_policy.normalized_target,
            ports=normalized_request.ports,
            profile=normalized_request.profile,
        )
    except (ActiveNmapBasicServiceError, ActiveNmapBasicTargetPolicyError, ActiveNmapBasicCommandError) as exc:
        reason_code = getattr(exc, "reason_code", "invalid_request")
        return _base_result("failed", execution_attempted=False) | {
            "reason": reason_code,
            "error_type": "validation_error",
        }

    run = runner or subprocess.run
    try:
        completed = run(
            argv,
            capture_output=True,
            check=False,
            shell=False,
            timeout=timeout_budget,
        )
    except FileNotFoundError:
        return _base_result("nmap_missing", execution_attempted=True) | {
            "reason": "nmap_missing",
            "error_type": "nmap_missing",
        }
    except subprocess.TimeoutExpired as exc:
        stdout, stdout_truncated = _bounded_text(exc.stdout, stdout_budget, target_policy.normalized_target)
        stderr, stderr_truncated = _bounded_text(exc.stderr, stderr_budget, target_policy.normalized_target)
        return _base_result("timed_out", execution_attempted=True) | {
            "reason": "process_timeout",
            "timed_out": True,
            "stdout": stdout,
            "stderr": stderr,
            "output_truncated": stdout_truncated,
            "stderr_truncated": stderr_truncated,
        }
    except Exception:
        return _base_result("failed", execution_attempted=True) | {
            "reason": "unexpected_execution_error",
            "error_type": "unexpected_execution_error",
        }

    stdout, stdout_truncated = _bounded_text(completed.stdout, stdout_budget, target_policy.normalized_target)
    stderr, stderr_truncated = _bounded_text(completed.stderr, stderr_budget, target_policy.normalized_target)
    if completed.returncode == 0:
        status = "completed"
        reason = "raw_bounded"
    else:
        status = "failed"
        reason = "nmap_nonzero_exit"

    return _base_result(status, execution_attempted=True) | {
        "reason": reason,
        "exit_code": completed.returncode,
        "stdout": stdout,
        "stderr": stderr,
        "output_truncated": stdout_truncated,
        "stderr_truncated": stderr_truncated,
    }


def _base_result(status: str, *, execution_attempted: bool) -> ActiveNmapBasicExecutionResult:
    return {
        "status": status,
        "capability": ACTIVE_NMAP_BASIC_CAPABILITY,
        "profile": ACTIVE_NMAP_BASIC_PROFILE,
        "execution_attempted": execution_attempted,
        "output_truncated": False,
        "stderr_truncated": False,
        "timed_out": False,
        "argv_preview_available": False,
        "command_returned": False,
        "target_returned": False,
        "parser_ran": False,
        "findings_created": False,
    }


def _bounded_limit(value: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return maximum
    return min(value, maximum)


def _bounded_text(value: bytes | str | None, max_bytes: int, target: str) -> tuple[str, bool]:
    if value is None:
        return "", False
    raw = value if isinstance(value, bytes) else value.encode("utf-8", errors="replace")
    truncated = len(raw) > max_bytes
    bounded = raw[:max_bytes]
    text = bounded.decode("utf-8", errors="replace")
    return _redact_target(text, target), truncated


def _redact_target(text: str, target: str) -> str:
    if not target:
        return _redact_forbidden_claims(text)
    redacted = text.replace(target, "[REDACTED_TARGET]")
    lower_target = target.lower()
    if lower_target != target:
        redacted = redacted.replace(lower_target, "[REDACTED_TARGET]")
    return _redact_forbidden_claims(redacted)


def _redact_forbidden_claims(text: str) -> str:
    redacted = text
    for phrase in ("confirmed vulnerability", "exploitable", "target is safe"):
        redacted = redacted.replace(phrase, "[REDACTED_CLAIM]")
    return redacted
