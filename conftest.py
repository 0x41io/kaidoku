"""Shared test setup: no test may reach the network.

Kaidoku talks to the NVD, FIRST, CISA and Claude. Tests must stub those. A
blocked call raises inside the code (which may catch it and carry on), so the
attempt is also recorded and the test fails at the end, naming where it tried
to go."""

import socket

import pytest


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    tried = []

    def blocked(self, address, *rest):
        tried.append(str(address))
        raise OSError(f"test tried to reach the network: {address}")

    def blocked_sendto(self, data, *rest):
        return blocked(self, rest[-1] if rest else "?")

    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket.socket, "connect_ex", blocked)
    monkeypatch.setattr(socket.socket, "sendto", blocked_sendto)
    yield
    assert not tried, f"test tried to reach the network: {sorted(set(tried))}"
