# SPDX-License-Identifier: Apache-2.0
"""gunicorn configuration for the web process: one gevent-websocket worker, HTTPS from node.toml.

Used by packaging/systemd/pelagos.service:
  gunicorn -c /opt/pelagos/gunicorn_conf.py 'pelagos.app:wsgi_app()'
The TLS certificate and key paths come from node.toml [tls] (defaults under /etc/pelagos/tls).
"""

from __future__ import annotations

import tomllib

from gevent import monkey

monkey.patch_all()

from pelagos.core.paths import Paths  # noqa: E402

_paths = Paths.from_env()
_node = tomllib.loads(_paths.node_toml.read_text()) if _paths.node_toml.exists() else {}
_tls = _node.get("tls", {})

bind = _node.get("node", {}).get("web_listen", "0.0.0.0:8443")
workers = 1  # WebSocket fan-out lives in one process; gevent gives the concurrency.
worker_class = "geventwebsocket.gunicorn.workers.GeventWebSocketWorker"
worker_connections = 1000
timeout = 120
keepalive = 5
certfile = _tls.get("cert", str(_paths.tls_dir / "server.crt"))
keyfile = _tls.get("key", str(_paths.tls_dir / "server.key"))
ssl_version = "TLSv1_2"
limit_request_line = 4094
limit_request_fields = 100
limit_request_field_size = 8190
accesslog = "-"
errorlog = "-"
loglevel = "info"
