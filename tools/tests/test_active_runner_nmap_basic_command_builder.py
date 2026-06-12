import inspect
from pathlib import Path

import pytest

from active_runner import FORBIDDEN_NMAP_BASIC_FLAGS, build_active_nmap_basic_argv
from active_runner.contracts import (
    ACTIVE_NMAP_BASIC_BINARY,
    ACTIVE_NMAP_BASIC_MAX_PORTS,
    ACTIVE_NMAP_BASIC_PROFILE,
    ActiveNmapBasicCommandError,
)


def test_nmap_basic_builder_returns_argv_list_not_shell_string():
    argv = build_active_nmap_basic_argv(target="192.168.56.10", ports=[22, 80, 443])

    assert isinstance(argv, list)
    assert all(isinstance(item, str) for item in argv)
    assert not isinstance(argv, str)
    assert argv[0] == ACTIVE_NMAP_BASIC_BINARY
    assert argv == [
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
    ]


def test_nmap_basic_builder_normalizes_duplicate_ports_deterministically():
    argv = build_active_nmap_basic_argv(target="router.local", ports=[443, 22, 443, 80])

    assert argv[argv.index("-p") + 1] == "22,80,443"
    assert argv[-2:] == ["--", "router.local"]


def test_nmap_basic_builder_rejects_non_allowlisted_profile():
    with pytest.raises(ActiveNmapBasicCommandError, match="unsupported_profile"):
        build_active_nmap_basic_argv(target="192.168.56.10", ports=[22], profile="default")


@pytest.mark.parametrize(
    ("ports", "reason_code"),
    [
        ([], "ports_empty"),
        (["22"], "port_not_integer"),
        ([True], "port_not_integer"),
        ([0], "port_out_of_range"),
        ([65536], "port_out_of_range"),
        (list(range(1, ACTIVE_NMAP_BASIC_MAX_PORTS + 2)), "too_many_ports"),
        ("22,80", "ports_not_sequence"),
    ],
)
def test_nmap_basic_builder_rejects_invalid_ports(ports, reason_code):
    with pytest.raises(ActiveNmapBasicCommandError, match=reason_code):
        build_active_nmap_basic_argv(target="192.168.56.10", ports=ports)


@pytest.mark.parametrize(
    ("target", "reason_code"),
    [
        ("", "target_empty"),
        (" 192.168.56.10", "target_ambiguous"),
        ("-oX", "target_looks_like_flag"),
        ("router local", "target_contains_whitespace"),
    ],
)
def test_nmap_basic_builder_rejects_ambiguous_targets(target, reason_code):
    with pytest.raises(ActiveNmapBasicCommandError, match=reason_code):
        build_active_nmap_basic_argv(target=target, ports=[22])


def test_nmap_basic_builder_places_target_after_end_of_options_marker():
    argv = build_active_nmap_basic_argv(target="192.168.56.10", ports=[22])

    assert argv[-2] == "--"
    assert argv[-1] == "192.168.56.10"
    assert argv.count("--") == 1


def test_nmap_basic_builder_never_emits_forbidden_flags():
    argv = build_active_nmap_basic_argv(target="192.168.56.10", ports=[22, 80])

    assert FORBIDDEN_NMAP_BASIC_FLAGS.isdisjoint(argv)
    assert "-sT" in argv
    assert "-Pn" in argv
    assert "-n" in argv


def test_nmap_basic_builder_has_no_raw_or_extra_argument_parameters():
    parameters = inspect.signature(build_active_nmap_basic_argv).parameters

    assert set(parameters) == {"target", "ports", "profile"}
    assert "extra_args" not in parameters
    assert "raw_flags" not in parameters
    assert "script" not in parameters


def test_nmap_basic_builder_source_has_no_execution_or_runner_integration():
    source_paths = [
        Path("tools/active_runner/contracts.py"),
        Path("tools/active_runner/nmap_basic/__init__.py"),
        Path("tools/active_runner/nmap_basic/command_builder.py"),
    ]
    combined = "\n".join(path.read_text(encoding="utf-8") for path in source_paths)

    forbidden_source_terms = [
        "sub" + "process",
        "shell" + "=True",
        "os." + "system",
        "po" + "pen",
        "P" + "open(",
        "ru" + "n(",
        "tools.runner",
        "runner/main.py",
    ]
    for term in forbidden_source_terms:
        assert term not in combined
