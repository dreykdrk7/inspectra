"""Global test safety boundaries.

Ordinary backend tests may use ASGI transports, simulated provider transports,
Unix sockets, or loopback servers. They must never contact an external host.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import Any

import pytest


def _loopback_or_local_address(address: Any, family: int | None = None) -> bool:
    if family == socket.AF_UNIX or isinstance(address, str):
        return family == socket.AF_UNIX
    if not isinstance(address, tuple) or not address:
        return False
    host = address[0]
    if isinstance(host, bytes):
        try:
            host = host.decode("ascii")
        except UnicodeDecodeError:
            return False
    if not isinstance(host, str):
        return False
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.split("%", 1)[0]).is_loopback
    except ValueError:
        return False


@pytest.fixture(autouse=True)
def _block_external_network(monkeypatch: pytest.MonkeyPatch):
    real_connect = socket.socket.connect
    real_connect_ex = socket.socket.connect_ex
    real_getaddrinfo = socket.getaddrinfo

    def guarded_connect(instance: socket.socket, address: Any):
        if not _loopback_or_local_address(address, instance.family):
            raise AssertionError("External network access is forbidden in the ordinary test suite.")
        return real_connect(instance, address)

    def guarded_connect_ex(instance: socket.socket, address: Any):
        if not _loopback_or_local_address(address, instance.family):
            raise AssertionError("External network access is forbidden in the ordinary test suite.")
        return real_connect_ex(instance, address)

    def guarded_getaddrinfo(host: Any, *args: Any, **kwargs: Any):
        if host is not None and not _loopback_or_local_address((host, 0)):
            raise AssertionError("External name resolution is forbidden in the ordinary test suite.")
        return real_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", guarded_connect_ex)
    monkeypatch.setattr(socket, "getaddrinfo", guarded_getaddrinfo)
