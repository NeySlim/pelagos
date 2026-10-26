# SPDX-License-Identifier: Apache-2.0
"""Hot reload of the web TLS context: new handshakes see the new certificate, open connections stay."""

from __future__ import annotations

import os
import socket
import ssl
import threading
from pathlib import Path

import pytest

from pelagos.core import ca as ca_mod
from pelagos.core.webcert import pem, tlsreload

pytestmark = pytest.mark.unit


def write_pair(directory: Path, name: str) -> tuple[bytes, bytes, str]:
    key = pem.generate_key()
    cert = pem.self_signed(key, [f"{name}.example.lan"], days=2)
    return pem.cert_pem(cert), pem.key_pem(key), pem.fingerprint(cert)


def replace(path: Path, data: bytes) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)


class EchoServer:
    def __init__(self, context: tlsreload.ReloadingContext) -> None:
        self.context = context
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen()
        self.port = self.sock.getsockname()[1]
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self) -> None:
        while True:
            try:
                raw, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self.echo, args=(raw,), daemon=True).start()

    def echo(self, raw: socket.socket) -> None:
        try:
            with self.context.wrap_socket(raw, server_side=True) as tls:
                while data := tls.recv(100):
                    tls.sendall(data)
        except (OSError, ssl.SSLError):
            pass

    def close(self) -> None:
        self.sock.close()


def connect(port: int) -> tuple[ssl.SSLSocket, str]:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    tls = context.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=5))
    return tls, ca_mod.fingerprint_der(tls.getpeercert(binary_form=True))


def roundtrip(tls: ssl.SSLSocket, payload: bytes) -> bytes:
    tls.sendall(payload)
    return tls.recv(100)


def test_reload_keeps_open_connections(tmp_path, monkeypatch):
    monkeypatch.setattr(tlsreload, "CHECK_INTERVAL", 0.0)
    cert, key = tmp_path / "server.crt", tmp_path / "server.key"
    a_cert, a_key, a_fp = write_pair(tmp_path, "a")
    b_cert, b_key, b_fp = write_pair(tmp_path, "b")
    cert.write_bytes(a_cert)
    key.write_bytes(a_key)
    context = tlsreload.install(cert, key)
    server = EchoServer(context)
    try:
        old, fp = connect(server.port)
        assert fp == a_fp and roundtrip(old, b"one") == b"one"

        # The key lands first: the pair does not match yet, the old context keeps serving.
        replace(key, b_key)
        probe, fp = connect(server.port)
        probe.close()
        assert fp == a_fp and context.last_error and context.reloads == 0

        replace(cert, b_cert)
        fresh, fp = connect(server.port)
        assert fp == b_fp and context.reloads == 1
        assert roundtrip(fresh, b"two") == b"two"
        # The connection opened before the swap still talks, with its old certificate.
        assert roundtrip(old, b"three") == b"three"
        old.close()
        fresh.close()
        # Nothing changed since: no reload; a forced one (the web process after an install) does.
        assert not context.reload()
        assert tlsreload.reload_now() is True and context.reloads == 2
    finally:
        server.close()
        tlsreload._current = None


def test_reload_now_without_a_server_context():
    tlsreload._current = None
    assert tlsreload.reload_now() is None
