"""Regression tests for the ordinary suite's no-external-network boundary."""

from __future__ import annotations

import socket

import pytest


def test_ordinary_suite_blocks_external_dns_and_ip_connections() -> None:
    with pytest.raises(AssertionError, match="External name resolution is forbidden"):
        socket.getaddrinfo("network-guard-canary.invalid", 443)

    candidate = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        with pytest.raises(AssertionError, match="External network access is forbidden"):
            candidate.connect(("192.0.2.1", 443))
        with pytest.raises(AssertionError, match="External network access is forbidden"):
            candidate.connect_ex(("198.51.100.1", 443))
    finally:
        candidate.close()
