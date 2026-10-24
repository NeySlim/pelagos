# SPDX-License-Identifier: Apache-2.0
"""Kea commands whose outcome is unknown (timeout, truncated answer) are restored, never left half done."""

from __future__ import annotations

import socket
import threading

import pytest

from pelagos.connectors.base import ConnectorTimeout, ConnectorUnavailable
from pelagos.connectors.kea.control_socket import KeaControlSocket
from tests.unit.connectors.kea.test_backend import backend_with

pytestmark = pytest.mark.unit


def test_config_set_timeout_is_restored(tmp_root):
    """Kea finishes a config-set the client gave up on: the running config goes back to before."""
    backend, fake = backend_with(tmp_root, "kea26-dhcp4-config-get", "2.6.3")
    original = backend.config_get()
    real = fake._config_set
    calls = []

    def slow(args):
        calls.append(1)
        answer = real(args)
        if len(calls) == 1:
            raise ConnectorTimeout("config-set: Kea did not answer within 120.0s")
        return answer

    fake.overrides["config-set"] = slow
    new = backend.config_get()
    new["valid-lifetime"] = 4321
    result = backend.apply(backend.plan_config_replace(new))
    assert not result.ok and result.rolled_back and "did not answer" in result.message
    assert fake.cfg == original and len(calls) == 2


def test_truncated_answer_is_unavailable(tmp_path):
    path = tmp_path / "s"
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(str(path))
    srv.listen(1)

    def serve():
        conn, _ = srv.accept()
        conn.recv(65536)
        conn.sendall(b'{"result": 0, "arguments": {"a": ')
        conn.close()

    threading.Thread(target=serve, daemon=True).start()
    with pytest.raises(ConnectorUnavailable, match="truncated"):
        KeaControlSocket(path, timeout=5).send("config-get")
    srv.close()
    sock = KeaControlSocket(path, timeout=5, command_timeout=90)
    assert sock.timeout_for("config-set") == 90 and sock.timeout_for("config-get") == 5


def test_rollback_guard_survives_a_restart(tmp_root):
    from pelagos.connectors.base import PreconditionFailed
    from pelagos.connectors.kea.backend import KeaBackend
    from pelagos.domain import Family
    from tests.unit.connectors.kea.fake import make_ctx

    backend, fake = backend_with(tmp_root, "kea32-dhcp4-config-get", "3.2.1")
    new = backend.config_get()
    new["valid-lifetime"] = 1111
    plan = backend.plan_config_replace(new)
    assert backend.apply(plan).ok
    fake.cfg["valid-lifetime"] = 2222  # a hand edit after the apply
    restarted = KeaBackend(make_ctx(tmp_root), Family.V4)
    restarted.socket = fake
    with pytest.raises(PreconditionFailed):
        restarted.rollback(plan)
    fake.cfg["valid-lifetime"] = 1111
    assert restarted.rollback(plan).ok and restarted._recorded(plan.id) is None
