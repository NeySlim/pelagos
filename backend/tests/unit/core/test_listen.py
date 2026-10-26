# SPDX-License-Identifier: Apache-2.0
"""check_free: a real listener blocks the port, a closed connection in TIME_WAIT does not."""

from __future__ import annotations

import socket

import pytest

from pelagos.core.listen import ListenError, check_free


def test_live_listener_is_reported():
    with socket.socket() as srv:
        srv.bind(("127.0.0.1", 0))
        srv.listen()
        port = srv.getsockname()[1]
        with pytest.raises(ListenError, match="already in use"):
            check_free("web-listen", f"127.0.0.1:{port}")


def test_time_wait_port_is_free():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen()
    port = srv.getsockname()[1]
    cli = socket.create_connection(("127.0.0.1", port))
    conn, _ = srv.accept()
    conn.close()  # server side closes first: TIME_WAIT stays on the listening port
    cli.close()
    srv.close()
    check_free("web-listen", f"127.0.0.1:{port}")
