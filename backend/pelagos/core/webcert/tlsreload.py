# SPDX-License-Identifier: Apache-2.0
"""Hot reload of the web TLS certificate inside the gunicorn worker, without a restart.

gunicorn rebuilds the TLS context only when it replaces its workers (HUP), which would drop the
sessions kept in the worker's memory and every open WebSocket. The gevent server calls
`wrap_socket` of the object the ssl_context hook returns for each new connection: this object
hands it to the current context and swaps in a new one when the certificate or key files change.
Connections already open keep their context; only new handshakes see the new certificate.
"""

from __future__ import annotations

import logging
import os
import ssl
import threading
import time
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# Files are looked at no more often than this on the connection path.
CHECK_INTERVAL = 1.0

_current: ReloadingContext | None = None


def build_context(cert: Path, key: Path) -> ssl.SSLContext:
    """TLS 1.2 or newer, server side, the certificate chain and key from the files (section 16)."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(cert), str(key))
    return context


def _signature(*paths: Path) -> tuple[Any, ...]:
    out: list[Any] = []
    for path in paths:
        try:
            st = os.stat(path)
        except OSError:
            out.append(None)
            continue
        out.append((st.st_ino, st.st_mtime_ns, st.st_size))
    return tuple(out)


class ReloadingContext:
    """Stands in for an SSLContext where only `wrap_socket` is used (gevent StreamServer)."""

    def __init__(self, cert: Path, key: Path, initial: ssl.SSLContext | None = None) -> None:
        self.cert = Path(cert)
        self.key = Path(key)
        self._lock = threading.Lock()
        self._sig = _signature(self.cert, self.key)
        self.context = initial if initial is not None else build_context(self.cert, self.key)
        self._checked = time.monotonic()
        self.reloads = 0
        self.last_error: str | None = None

    def reload(self, force: bool = False) -> bool:
        """Load the files again when they changed (or always with `force`); True when swapped.

        A failed load (the key renamed in before the certificate) keeps the old context and leaves
        the signature unseen, so the next call tries again.
        """
        with self._lock:
            sig = _signature(self.cert, self.key)
            if not force and sig == self._sig:
                return False
            try:
                fresh = build_context(self.cert, self.key)
            except (OSError, ssl.SSLError, ValueError) as exc:
                self.last_error = str(exc)
                log.warning("web TLS certificate not reloaded: %s", exc)
                return False
            self.context, self._sig = fresh, sig
            self.reloads += 1
            self.last_error = None
            log.info("web TLS certificate reloaded from %s", self.cert)
            return True

    def maybe_reload(self) -> None:
        now = time.monotonic()
        if now - self._checked < CHECK_INTERVAL:
            return
        self._checked = now
        self.reload()

    def wrap_socket(self, sock: Any, *args: Any, **kwargs: Any) -> Any:
        self.maybe_reload()
        return self.context.wrap_socket(sock, *args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        if name == "context":
            raise AttributeError(name)
        return getattr(self.context, name)


def install(cert: Path, key: Path, initial: ssl.SSLContext | None = None) -> ReloadingContext:
    """Called from the gunicorn ssl_context hook in the worker; the web process finds it here."""
    global _current
    _current = ReloadingContext(cert, key, initial)
    return _current


def current() -> ReloadingContext | None:
    return _current


def reload_now() -> bool | None:
    """Reload in this process at once; None when this process serves no reloadable context."""
    ctx = _current
    if ctx is None:
        return None
    return ctx.reload(force=True)
