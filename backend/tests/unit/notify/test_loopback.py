# SPDX-License-Identifier: Apache-2.0
"""The real HTTP client and smtplib against local servers on the loopback: TLS with an extra CA,
no redirect followed, bounded body, STARTTLS and AUTH."""

import base64
import json
import socket
import socketserver
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from pelagos.notify.model import Channel
from pelagos.notify.transports import SendContext, send
from tests.unit.core.webcert_pki import key_pem_of, make_ca, make_leaf, pem_of

from .helpers import batch

pytestmark = pytest.mark.unit


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    root = make_ca("Notify Test Root")
    cert, key = make_leaf(root, ["localhost"])
    d = tmp_path_factory.mktemp("pki")
    (d / "cert.pem").write_text(pem_of(cert))
    (d / "key.pem").write_text(key_pem_of(key))
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(d / "cert.pem", d / "key.pem")
    return pem_of(root.cert), server


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self.server.seen.append((self.command, self.path, dict(self.headers), body))
        if self.path.startswith("/redirect"):
            self.send_response(302)
            self.send_header("Location", "/ok")
            self.end_headers()
            return
        payload = b"x" * 1_000_000 if self.path.startswith("/big") else b'{"id":1}'
        self.send_response(200)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        try:
            self.wfile.write(payload)
        except OSError:
            pass

    do_PUT = do_POST  # noqa: N815


@pytest.fixture
def http_server(request):
    tls = getattr(request, "param", None)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    srv.seen = []
    if tls is not None:
        srv.socket = request.getfixturevalue("pki")[1].wrap_socket(srv.socket, server_side=True)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv
    srv.shutdown()
    srv.server_close()


def ctx():
    return SendContext(timeout=5.0)


def test_plain_http_webhook_and_no_redirect(http_server):
    port = http_server.server_address[1]
    ok = send(
        Channel(id="C", type="webhook", params={"url": f"http://127.0.0.1:{port}/in"}), {}, batch(), ctx()
    )
    assert ok.ok and ok.status == 200
    method, path, headers, body = http_server.seen[0]
    assert (method, path) == ("POST", "/in")
    assert headers["X-Pelagos-Delivery"] == batch().id and headers["User-Agent"].startswith("pelagos/")
    assert json.loads(body)["schema"] == "pelagos.notification.v1"
    res = send(
        Channel(id="C", type="webhook", params={"url": f"http://127.0.0.1:{port}/redirect"}),
        {},
        batch(),
        ctx(),
    )
    assert not res.ok and res.status == 302 and not res.retry
    assert [p for _, p, _, _ in http_server.seen] == ["/in", "/redirect"]


def test_big_body_is_not_read_whole(http_server):
    port = http_server.server_address[1]
    assert send(
        Channel(id="C", type="webhook", params={"url": f"http://127.0.0.1:{port}/big"}), {}, batch(), ctx()
    ).ok


def test_connection_refused_is_transient():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    res = send(
        Channel(id="C", type="webhook", params={"url": f"http://127.0.0.1:{port}/"}), {}, batch(), ctx()
    )
    assert not res.ok and res.retry


@pytest.mark.parametrize("http_server", ["tls"], indirect=True)
def test_tls_with_extra_ca_only(http_server, pki):
    port = http_server.server_address[1]
    params = {"homeserver": f"https://localhost:{port}", "room_id": "!r:example.lan"}
    res = send(Channel(id="C", type="matrix", params=params), {"token": "tok"}, batch(), ctx())
    assert not res.ok and not res.retry and "TLS verification failed" in res.error
    res = send(
        Channel(id="C", type="matrix", params={**params, "ca_pem": pki[0]}), {"token": "tok"}, batch(), ctx()
    )
    assert res.ok, res.error
    method, path, headers, _ = http_server.seen[-1]
    assert method == "PUT" and path.startswith(
        "/_matrix/client/v3/rooms/%21r%3Aexample.lan/send/m.room.message/"
    )
    assert headers["Authorization"] == "Bearer tok"


class SmtpHandler(socketserver.StreamRequestHandler):
    """Just enough of RFC 5321, 3207 (STARTTLS) and 4954 (AUTH PLAIN) for smtplib."""

    def handle(self):
        srv = self.server
        sock, tls = self.request, False
        rfile, wfile = self.rfile, self.wfile

        def say(line):
            wfile.write(line.encode() + b"\r\n")
            wfile.flush()

        say("220 localhost test")
        while line := rfile.readline():
            cmd = line.decode().strip()
            verb = cmd.split(" ")[0].upper()
            srv.log.append(verb)
            if verb in ("EHLO", "HELO"):
                exts = ["250-localhost"] + ([] if tls else ["250-STARTTLS"]) + ["250 AUTH PLAIN"]
                for e in exts:
                    say(e)
            elif verb == "STARTTLS":
                say("220 go ahead")
                sock = srv.tls.wrap_socket(sock, server_side=True)
                rfile, wfile, tls = sock.makefile("rb"), sock.makefile("wb"), True
            elif verb == "AUTH":
                creds = base64.b64decode(cmd.split(" ")[2]).split(b"\0")
                srv.auth = (creds[1].decode(), creds[2].decode(), tls)
                say("235 ok" if creds[2] == b"good" else "535 5.7.8 bad")
            elif verb in ("MAIL", "RCPT"):
                srv.envelope.append(cmd)
                say("250 ok")
            elif verb == "DATA":
                say("354 go")
                data = []
                while (part := rfile.readline()) not in (b".\r\n", b""):
                    data.append(part)
                srv.data = b"".join(data)
                say("250 queued")
            elif verb == "QUIT":
                say("221 bye")
                return
            else:
                say("502 no")


@pytest.fixture
def smtp_server(pki):
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), SmtpHandler)
    srv.daemon_threads = True
    srv.tls, srv.log, srv.envelope, srv.auth, srv.data = pki[1], [], [], None, b""
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv
    srv.shutdown()
    srv.server_close()


def mail(port, **over):
    params = {"host": "localhost", "port": port, "security": "starttls", "username": "bot",
              "from": "pelagos@example.lan", "to": ["ops@example.lan"]}  # fmt: skip
    params.update(over)
    return Channel(id="C1", type="email", params=params)


def test_smtp_starttls_auth_and_data(smtp_server, pki):
    port = smtp_server.server_address[1]
    res = send(mail(port, ca_pem=pki[0]), {"password": "good"}, batch(), ctx())
    assert res.ok, res.error
    assert smtp_server.auth == ("bot", "good", True)
    assert smtp_server.log.index("STARTTLS") < smtp_server.log.index("AUTH")
    assert smtp_server.envelope[1].upper() == "RCPT TO:<OPS@EXAMPLE.LAN>"
    assert b"Subject: [Pelagos] 1 critical" in smtp_server.data


def test_smtp_untrusted_certificate_and_bad_password(smtp_server, pki):
    port = smtp_server.server_address[1]
    res = send(mail(port), {"password": "good"}, batch(), ctx())
    assert not res.ok and "TLS verification failed" in res.error and smtp_server.auth is None
    res = send(mail(port, ca_pem=pki[0]), {"password": "wrong-password"}, batch(), ctx())
    assert not res.ok and res.status == 535 and not res.retry and "wrong-password" not in res.error


def test_smtp_plain_toward_loopback(smtp_server):
    port = smtp_server.server_address[1]
    res = send(mail(port, security="none", host="127.0.0.1", username=None), {}, batch(), ctx())
    assert res.ok, res.error
    assert "STARTTLS" not in smtp_server.log and smtp_server.data
