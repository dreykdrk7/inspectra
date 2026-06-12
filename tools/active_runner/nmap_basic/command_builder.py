from __future__ import annotations

from collections.abc import Sequence

from active_runner.contracts import (
    ACTIVE_NMAP_BASIC_BINARY,
    ACTIVE_NMAP_BASIC_HOST_TIMEOUT_SECONDS,
    ACTIVE_NMAP_BASIC_MAX_PORTS,
    ACTIVE_NMAP_BASIC_MAX_RETRIES,
    ACTIVE_NMAP_BASIC_MAX_TARGET_LENGTH,
    ACTIVE_NMAP_BASIC_PROFILE,
    ActiveNmapBasicCommandError,
)


FORBIDDEN_NMAP_BASIC_FLAGS = frozenset(
    {
        "-A",
        "-O",
        "-sV",
        "-sC",
        "-sS",
        "-sU",
        "-sN",
        "-sF",
        "-sX",
        "-sA",
        "-sW",
        "-sM",
        "-sI",
        "-sY",
        "-sZ",
        "-sO",
        "-sn",
        "--script",
        "--script-args",
        "--script-updatedb",
        "--traceroute",
        "--packet-trace",
        "-iL",
        "--exclude-file",
        "--randomize-hosts",
        "-D",
        "-S",
        "--spoof-mac",
        "-f",
        "--mtu",
        "--data-length",
        "--source-port",
    }
)


def build_active_nmap_basic_argv(
    *,
    target: str,
    ports: Sequence[int],
    profile: str = ACTIVE_NMAP_BASIC_PROFILE,
) -> list[str]:
    if profile != ACTIVE_NMAP_BASIC_PROFILE:
        raise ActiveNmapBasicCommandError("unsupported_profile")

    normalized_target = _normalize_target(target)
    normalized_ports = _normalize_ports(ports)
    port_argument = ",".join(str(port) for port in normalized_ports)

    return [
        ACTIVE_NMAP_BASIC_BINARY,
        "-sT",
        "-Pn",
        "-n",
        "--max-retries",
        str(ACTIVE_NMAP_BASIC_MAX_RETRIES),
        "--host-timeout",
        f"{ACTIVE_NMAP_BASIC_HOST_TIMEOUT_SECONDS}s",
        "-oX",
        "-",
        "-p",
        port_argument,
        "--",
        normalized_target,
    ]


def _normalize_target(target: str) -> str:
    if not isinstance(target, str):
        raise ActiveNmapBasicCommandError("target_not_string")
    normalized = target.strip()
    if not normalized:
        raise ActiveNmapBasicCommandError("target_empty")
    if normalized != target:
        raise ActiveNmapBasicCommandError("target_ambiguous")
    if len(normalized) > ACTIVE_NMAP_BASIC_MAX_TARGET_LENGTH:
        raise ActiveNmapBasicCommandError("target_too_long")
    if normalized.startswith("-"):
        raise ActiveNmapBasicCommandError("target_looks_like_flag")
    if any(character.isspace() for character in normalized):
        raise ActiveNmapBasicCommandError("target_contains_whitespace")
    return normalized


def _normalize_ports(ports: Sequence[int]) -> tuple[int, ...]:
    if isinstance(ports, (str, bytes)) or not isinstance(ports, Sequence):
        raise ActiveNmapBasicCommandError("ports_not_sequence")
    if not ports:
        raise ActiveNmapBasicCommandError("ports_empty")
    if len(ports) > ACTIVE_NMAP_BASIC_MAX_PORTS:
        raise ActiveNmapBasicCommandError("too_many_ports")

    normalized: set[int] = set()
    for port in ports:
        if isinstance(port, bool) or not isinstance(port, int):
            raise ActiveNmapBasicCommandError("port_not_integer")
        if port < 1 or port > 65535:
            raise ActiveNmapBasicCommandError("port_out_of_range")
        normalized.add(port)

    if not normalized:
        raise ActiveNmapBasicCommandError("ports_empty")
    if len(normalized) > ACTIVE_NMAP_BASIC_MAX_PORTS:
        raise ActiveNmapBasicCommandError("too_many_ports")
    return tuple(sorted(normalized))
