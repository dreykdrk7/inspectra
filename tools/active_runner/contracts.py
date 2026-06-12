from __future__ import annotations


ACTIVE_NMAP_BASIC_CAPABILITY = "active_nmap_basic"
ACTIVE_NMAP_BASIC_MODE = "live_nmap_basic"
ACTIVE_NMAP_BASIC_PROFILE = "tcp_connect_small"
ACTIVE_NMAP_BASIC_BINARY = "nmap"
ACTIVE_NMAP_BASIC_MAX_PORTS = 32
ACTIVE_NMAP_BASIC_MAX_TARGET_LENGTH = 253
ACTIVE_NMAP_BASIC_HOST_TIMEOUT_SECONDS = 30
ACTIVE_NMAP_BASIC_MAX_RETRIES = 1
ACTIVE_NMAP_BASIC_NOT_EXECUTED_REASON = "runner_skeleton_no_real_nmap"


class ActiveNmapBasicCommandError(ValueError):
    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)
