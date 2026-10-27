# SPDX-License-Identifier: Apache-2.0
"""gunicorn worker of the web process: the gevent-websocket worker without handshake tracebacks."""

from __future__ import annotations

import logging

from geventwebsocket.gunicorn.workers import GeventWebSocketWorker as _Base
from gunicorn.workers.ggevent import PyWSGIServer

from pelagos.core.quiet_tls import quiet_handshakes


class QuietWebSocketWorker(_Base):
    server_class = quiet_handshakes(PyWSGIServer, logging.getLogger("gunicorn.error"))
