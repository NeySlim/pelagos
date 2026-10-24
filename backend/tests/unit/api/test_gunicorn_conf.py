# SPDX-License-Identifier: Apache-2.0
"""gunicorn configuration: one gevent-websocket worker, bind and TLS from node.toml (in a subprocess,
since importing it monkey-patches the interpreter)."""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

pytestmark = pytest.mark.unit

KEYS = ("bind", "workers", "worker_class", "certfile", "keyfile")
PROBE = f"import json, pelagos.gunicorn_conf as g; print(json.dumps({{k: getattr(g, k) for k in {KEYS!r}}}))"


def test_gunicorn_conf_reads_node_toml(node_paths):
    env = {**os.environ, "PELAGOS_HOME": str(node_paths.etc.parent)}
    out = subprocess.run(
        [sys.executable, "-c", PROBE], env=env, capture_output=True, text=True, timeout=60, check=True
    )
    conf = json.loads(out.stdout.strip().splitlines()[-1])
    assert conf["workers"] == 1
    assert conf["worker_class"] == "geventwebsocket.gunicorn.workers.GeventWebSocketWorker"
    assert conf["bind"] == "0.0.0.0:8443"
    assert conf["certfile"] == str(node_paths.etc / "tls" / "server.crt")
    assert conf["keyfile"] == str(node_paths.etc / "tls" / "server.key")


def test_worker_class_is_importable():
    out = subprocess.run(
        [
            sys.executable,
            "-c",
            "import geventwebsocket.gunicorn.workers as w; print(w.GeventWebSocketWorker)",
        ],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert out.returncode == 0, out.stderr
