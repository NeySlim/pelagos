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
limit_request_line = 4094
limit_request_fields = 100
limit_request_field_size = 8190
accesslog = "-"
errorlog = "-"
loglevel = "info"


def ssl_context(conf, default_ssl_context_factory):  # gunicorn hook
    """TLS 1.2 or newer (section 16); the default factory loads certfile and keyfile."""
    import ssl

    context = default_ssl_context_factory()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def on_starting(server):  # gunicorn hook, in the master before workers fork
    """Workers find their master here to ask for a restart (services.group_watch).

    A marker left by an earlier run is stale: it must not turn this run's plain stop into exit 75.
    """
    import os

    from pelagos.services.group_watch import MASTER_ENV, marker_path

    os.environ[MASTER_ENV] = str(os.getpid())
    try:
        marker_path(_paths.run).unlink()
    except OSError:
        pass


def on_exit(server):  # gunicorn hook, in the master after it stopped the workers
    """Exit 75 when a worker saw new supplementary groups: systemd (RestartForceExitStatus) restarts us."""
    import os

    from pelagos.services.group_watch import exit_status_for_restart

    status = exit_status_for_restart(_paths.run)
    if status is not None:
        os._exit(status)
