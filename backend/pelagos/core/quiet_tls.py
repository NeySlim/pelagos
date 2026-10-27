# SPDX-License-Identifier: Apache-2.0
"""A gevent server whose refused TLS handshakes cost one info line instead of a traceback.

Probes and port scanners fail the handshake all day: that is not an error of ours.
"""

from __future__ import annotations

import logging
import ssl
from typing import Any

log = logging.getLogger("pelagos.tls")


def quiet_handshakes(base: type, logger: logging.Logger = log) -> type:
    """`base` (a gevent StreamServer subclass) with handshake failures logged on one line."""

    class QuietHandshakes(base):  # type: ignore[misc,valid-type]
        def wrap_socket_and_handle(self, client_socket: Any, address: Any) -> Any:
            try:
                ssl_socket = self.wrap_socket(client_socket, **self.ssl_args)
            except (ssl.SSLError, OSError) as exc:
                host = address[0] if address else "?"
                logger.info("TLS handshake refused from %s: %s", host, getattr(exc, "reason", None) or exc)
                return None
            try:
                return self.handle(ssl_socket, address)
            finally:
                try:
                    ssl_socket.close()
                except OSError:
                    pass

    QuietHandshakes.__name__ = base.__name__
    return QuietHandshakes
