import json
import subprocess
from pathlib import Path

from active_runner.contracts import (
    ACTIVE_NMAP_BASIC_CAPABILITY,
    ACTIVE_NMAP_BASIC_PROFILE,
    ACTIVE_NMAP_BASIC_PROCESS_TIMEOUT_SECONDS,
)
from active_runner.nmap_basic.executor import execute_active_nmap_basic


def make_request(**overrides):
    payload = {
        "mode": "live_nmap_basic",
        "profile": ACTIVE_NMAP_BASIC_PROFILE,
        "target": "192.168.56.10",
        "ports": [443, 22, 80],
        "authorization_confirmed": True,
        "local_private_scope_confirmed": True,
        "live_traffic_confirmed": True,
    }
    payload.update(overrides)
    return payload


def serialized(payload) -> str:
    return json.dumps(payload, sort_keys=True)


def test_executor_calls_subprocess_with_allowlisted_argv_list_and_no_shell():
    calls = []

    def fake_runner(argv, **kwargs):
        calls.append({"argv": argv, "kwargs": kwargs})
        return subprocess.CompletedProcess(argv, 0, stdout=b"<nmaprun></nmaprun>", stderr=b"")

    result = execute_active_nmap_basic(make_request(), runner=fake_runner)

    assert result["status"] == "completed"
    assert result["reason"] == "raw_bounded"
    assert result["capability"] == ACTIVE_NMAP_BASIC_CAPABILITY
    assert result["profile"] == ACTIVE_NMAP_BASIC_PROFILE
    assert result["execution_attempted"] is True
    assert result["parser_ran"] is False
    assert result["findings_created"] is False
    assert calls == [
        {
            "argv": [
                "nmap",
                "-sT",
                "-Pn",
                "-n",
                "--max-retries",
                "1",
                "--host-timeout",
                "30s",
                "-oX",
                "-",
                "-p",
                "22,80,443",
                "--",
                "192.168.56.10",
            ],
            "kwargs": {
                "capture_output": True,
                "check": False,
                "shell": False,
                "timeout": ACTIVE_NMAP_BASIC_PROCESS_TIMEOUT_SECONDS,
            },
        }
    ]


def test_executor_rejects_raw_flags_before_subprocess():
    called = False

    def fake_runner(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("subprocess must not be called")

    result = execute_active_nmap_basic(make_request(raw_flags="-A"), runner=fake_runner)

    assert result["status"] == "failed"
    assert result["reason"] == "unsupported_request_field"
    assert result["error_type"] == "validation_error"
    assert result["execution_attempted"] is False
    assert called is False


def test_executor_applies_target_policy_before_subprocess():
    called = False

    def fake_runner(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("subprocess must not be called")

    result = execute_active_nmap_basic(make_request(target="example.com"), runner=fake_runner)

    assert result["status"] == "failed"
    assert result["reason"] == "target_not_local_private"
    assert result["error_type"] == "validation_error"
    assert result["execution_attempted"] is False
    assert called is False


def test_executor_blocks_range_target_before_subprocess():
    called = False

    def fake_runner(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("subprocess must not be called")

    result = execute_active_nmap_basic(make_request(target="192.168.56.0/24"), runner=fake_runner)

    assert result["status"] == "failed"
    assert result["reason"] == "target_unsupported_syntax"
    assert result["execution_attempted"] is False
    assert called is False


def test_executor_timeout_returns_controlled_bounded_result():
    def fake_runner(argv, **kwargs):
        raise subprocess.TimeoutExpired(
            cmd=argv,
            timeout=kwargs["timeout"],
            output=b"partial 192.168.56.10",
            stderr=b"late 192.168.56.10",
        )

    result = execute_active_nmap_basic(make_request(), runner=fake_runner)
    body = serialized(result)

    assert result["status"] == "timed_out"
    assert result["reason"] == "process_timeout"
    assert result["execution_attempted"] is True
    assert result["timed_out"] is True
    assert "[REDACTED_TARGET]" in body
    assert "192.168.56.10" not in body


def test_executor_nmap_missing_returns_controlled_error():
    def fake_runner(*args, **kwargs):
        raise FileNotFoundError("nmap")

    result = execute_active_nmap_basic(make_request(), runner=fake_runner)
    body = serialized(result)

    assert result["status"] == "nmap_missing"
    assert result["reason"] == "nmap_missing"
    assert result["error_type"] == "nmap_missing"
    assert result["execution_attempted"] is True
    assert "traceback" not in body.lower()


def test_executor_nonzero_exit_returns_controlled_error():
    def fake_runner(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 2, stdout=b"", stderr=b"failed for 192.168.56.10")

    result = execute_active_nmap_basic(make_request(), runner=fake_runner)
    body = serialized(result)

    assert result["status"] == "failed"
    assert result["reason"] == "nmap_nonzero_exit"
    assert result["exit_code"] == 2
    assert result["execution_attempted"] is True
    assert "192.168.56.10" not in body


def test_executor_limits_stdout_and_stderr():
    def fake_runner(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 0, stdout=b"a" * 20, stderr=b"b" * 15)

    result = execute_active_nmap_basic(
        make_request(),
        runner=fake_runner,
        max_stdout_bytes=8,
        max_stderr_bytes=5,
    )

    assert result["status"] == "completed"
    assert result["stdout"] == "a" * 8
    assert result["stderr"] == "b" * 5
    assert result["output_truncated"] is True
    assert result["stderr_truncated"] is True


def test_executor_clamps_unbounded_limit_overrides():
    calls = []

    def fake_runner(argv, **kwargs):
        calls.append(kwargs)
        return subprocess.CompletedProcess(argv, 0, stdout=b"a" * 20, stderr=b"b" * 20)

    result = execute_active_nmap_basic(
        make_request(),
        runner=fake_runner,
        timeout_seconds=9999,
        max_stdout_bytes=999999,
        max_stderr_bytes=999999,
    )

    assert calls[0]["timeout"] == ACTIVE_NMAP_BASIC_PROCESS_TIMEOUT_SECONDS
    assert result["status"] == "completed"
    assert result["output_truncated"] is False
    assert result["stderr_truncated"] is False


def test_executor_result_has_no_raw_command_target_or_vulnerability_claims():
    def fake_runner(argv, **kwargs):
        return subprocess.CompletedProcess(
            argv,
            0,
            stdout=b"192.168.56.10 confirmed vulnerability exploitable target is safe",
            stderr=b"nmap stderr for 192.168.56.10",
        )

    result = execute_active_nmap_basic(make_request(), runner=fake_runner)
    body = serialized(result)

    assert "argv" not in result
    assert "command" not in result
    assert result["argv_preview_available"] is False
    assert result["command_returned"] is False
    assert result["target_returned"] is False
    assert "192.168.56.10" not in body
    assert "nmap -sT" not in body
    assert "confirmed vulnerability" not in body
    assert "exploitable" not in body
    assert "target is safe" not in body


def test_executor_source_has_no_shell_or_passive_runner_integration():
    source_paths = [
        Path("tools/active_runner/nmap_basic/executor.py"),
        Path("tools/active_runner/nmap_basic/target_policy.py"),
    ]
    combined = "\n".join(path.read_text(encoding="utf-8") for path in source_paths)

    forbidden_source_terms = [
        "shell" + "=True",
        "os." + "system",
        "po" + "pen",
        "P" + "open(",
        "requests.",
        "httpx",
        "socket.",
        "dns.",
        "tools.runner",
        "runner/main.py",
    ]
    for term in forbidden_source_terms:
        assert term not in combined
