# SPDX-License-Identifier: Apache-2.0
import base64
import hashlib
import hmac
import json
import smtplib
import ssl

import pytest

from pelagos.notify.http import HttpResponse
from pelagos.notify.model import Channel, SendResult
from pelagos.notify.render import verify_signature
from pelagos.notify.transports import send, validate

from .helpers import NOW, FakeHttp, batch, ctx, probe_batch, resolved_batch

pytestmark = pytest.mark.unit


def channel(kind, **params):
    return Channel(id="C1", type=kind, name="x", language="en", params=params)


def one(http: FakeHttp):
    assert len(http.requests) == 1
    return http.requests[0]


# ntfy


def test_ntfy_json_publish_on_root_with_bearer():
    http = FakeHttp()
    res = send(
        channel("ntfy", url="https://ntfy.example.lan/base", topic="ops"),
        {"token": "tk_abc"},
        batch(),
        ctx(http),
    )
    assert res.ok and res.status == 200
    req = one(http)
    assert req.method == "POST" and req.url == "https://ntfy.example.lan/base/"
    assert req.headers["Authorization"] == "Bearer tk_abc"
    body = json.loads(req.body)
    assert body["topic"] == "ops" and body["priority"] == 5
    assert body["title"].startswith("[Pelagos] 1 critical")
    assert body["tags"] == ["rotating_light", "pelagos"]
    assert body["click"] == "https://ns1.example.lan:8443/alerts"
    assert req.timeout == 5.0


@pytest.mark.parametrize(
    ("make", "priority"),
    [(resolved_batch, 2), (probe_batch, 3), (lambda: batch(events=batch().events[1:]), 4)],
)
def test_ntfy_priorities(make, priority):
    http = FakeHttp()
    send(channel("ntfy", url="https://n.example.lan", topic="t"), {}, make(), ctx(http))
    assert json.loads(one(http).body)["priority"] == priority
    assert "Authorization" not in one(http).headers


def test_ntfy_basic_auth_and_message_cap():
    http = FakeHttp()
    b = batch()
    b.events = b.events * 40
    params = {"url": "https://n.example.lan", "topic": "t", "username": "bob"}
    send(Channel(id="C", type="ntfy", params=params), {"password": "pw"}, b, ctx(http))
    req = one(http)
    assert req.headers["Authorization"] == "Basic " + base64.b64encode(b"bob:pw").decode()
    assert len(json.loads(req.body)["message"].encode()) <= 4096


# Gotify


def test_gotify_token_in_header_never_in_url():
    http = FakeHttp()
    res = send(channel("gotify", url="https://g.example.lan/"), {"token": "AppTok123"}, batch(), ctx(http))
    assert res.ok
    req = one(http)
    assert req.url == "https://g.example.lan/message" and "AppTok123" not in req.url
    assert req.headers["X-Gotify-Key"] == "AppTok123"
    body = json.loads(req.body)
    assert body["priority"] == 8
    assert body["extras"]["client::display"] == {"contentType": "text/plain"}
    assert body["extras"]["client::notification"]["click"]["url"].endswith("/alerts")


def test_gotify_custom_priorities():
    http = FakeHttp()
    params = {"url": "https://g.example.lan", "priorities": {"info": 1}}
    send(Channel(id="C", type="gotify", params=params), {"token": "t" * 8}, resolved_batch(), ctx(http))
    assert json.loads(one(http).body)["priority"] == 1


# Matrix


def test_matrix_put_with_txn_id_and_html():
    http = FakeHttp(HttpResponse(200, b'{"event_id":"$e"}'))
    b = batch()
    ch = channel("matrix", homeserver="https://m.example.lan", room_id="!abc:example.lan")
    assert send(ch, {"token": "syt_x"}, b, ctx(http)).ok
    req = one(http)
    assert req.method == "PUT"
    assert (
        req.url
        == f"https://m.example.lan/_matrix/client/v3/rooms/%21abc%3Aexample.lan/send/m.room.message/{b.id}.C1"
    )
    assert req.headers["Authorization"] == "Bearer syt_x"
    body = json.loads(req.body)
    assert body["msgtype"] == "m.text" and body["format"] == "org.matrix.custom.html"
    assert body["body"].startswith("[Pelagos]") and "&lt;b&gt;ntfy&lt;/b&gt;" in body["formatted_body"]


def test_matrix_resend_reuses_the_txn_id():
    http = FakeHttp()
    ch = channel("matrix", homeserver="https://m.example.lan", room_id="!abc")
    b = batch()
    send(ch, {"token": "tok"}, b, ctx(http))
    send(ch, {"token": "tok"}, b, ctx(http))
    assert http.requests[0].url == http.requests[1].url
    send(Channel(id="C2", type="matrix", params=ch.params), {"token": "tok"}, b, ctx(http))
    assert http.requests[2].url.endswith(f"/{b.id}.C2")


# Webhook and Home Assistant


def test_webhook_signed_payload():
    http = FakeHttp()
    b = batch()
    ch = channel(
        "webhook",
        url="https://hook.example.lan/in",
        headers={"X-Team": "dns", "Host": "evil", "X-Pelagos-Delivery": "x"},
    )
    assert send(ch, {"hmac_secret": "k3y-secret"}, b, ctx(http)).ok
    req = one(http)
    assert req.method == "POST" and req.url == "https://hook.example.lan/in"
    assert req.headers["X-Team"] == "dns" and "Host" not in req.headers
    assert req.headers["X-Pelagos-Delivery"] == b.id
    assert req.headers["X-Pelagos-Timestamp"] == str(NOW)
    assert verify_signature(
        "k3y-secret", req.headers["X-Pelagos-Timestamp"], req.body, req.headers["X-Pelagos-Signature"], NOW
    )
    expected = hmac.new(b"k3y-secret", f"{NOW}.".encode() + req.body, hashlib.sha256).hexdigest()
    assert req.headers["X-Pelagos-Signature"] == "sha256=" + expected
    assert json.loads(req.body)["schema"] == "pelagos.notification.v1"


def test_webhook_unsigned_without_secret():
    http = FakeHttp()
    send(channel("webhook", url="https://hook.example.lan"), {}, batch(), ctx(http))
    assert "X-Pelagos-Signature" not in one(http).headers


def test_home_assistant_preset():
    http = FakeHttp()
    b = batch()
    assert send(
        channel("home_assistant", url="http://ha.example.lan:8123/"),
        {"webhook_id": "pelagos-x1"},
        b,
        ctx(http),
    ).ok
    req = one(http)
    assert req.url == "http://ha.example.lan:8123/api/webhook/pelagos-x1"
    assert req.headers["Content-Type"] == "application/json"
    assert json.loads(req.body)["id"] == b.id


# Failures


@pytest.mark.parametrize(
    ("status", "retry"),
    [(500, True), (503, True), (429, True), (408, True), (401, False), (404, False), (302, False)],
)
def test_status_classification(status, retry):
    http = FakeHttp(HttpResponse(status, b"nope\r\nmore"))
    res = send(channel("gotify", url="https://g.example.lan"), {"token": "tok1"}, batch(), ctx(http))
    assert not res.ok and res.status == status and res.retry is retry
    assert "\n" not in res.error


def test_network_error_retries_and_cert_error_does_not():
    ch = channel("ntfy", url="https://n.example.lan", topic="t")
    res = send(ch, {}, batch(), ctx(FakeHttp(ConnectionRefusedError("refused"))))
    assert not res.ok and res.retry and "connection failed" in res.error
    res = send(ch, {}, batch(), ctx(FakeHttp(TimeoutError("timed out"))))
    assert res.retry
    err = ssl.SSLCertVerificationError("bad")
    res = send(ch, {}, batch(), ctx(FakeHttp(err)))
    assert not res.ok and not res.retry and "TLS verification failed" in res.error


def test_errors_never_carry_a_secret():
    hook = "very-secret-hook-id"
    http = FakeHttp(HttpResponse(404, f"no webhook {hook}".encode()))
    res = send(
        channel("home_assistant", url="https://ha.example.lan"), {"webhook_id": hook}, batch(), ctx(http)
    )
    assert hook not in res.error and "***" in res.error
    res = send(
        channel("ntfy", url="https://n.example.lan", topic="t"),
        {"token": "tk_leak"},
        batch(),
        ctx(FakeHttp(OSError("tk_leak"))),
    )
    assert "tk_leak" not in res.error


def test_broken_channels_never_raise():
    assert not send({"id": "C", "type": "pager"}, {}, batch(), ctx()).ok
    assert not send({"id": "C", "type": "matrix", "params": {}}, {}, batch(), ctx()).ok
    res = send(
        {"id": "C", "type": "ntfy", "params": {"url": "https://n", "topic": "t", "ca_pem": "junk"}},
        {},
        batch(),
        ctx(),
    )
    assert not res.ok and "invalid extra CA" in res.error and not res.retry


def test_result_dict():
    assert SendResult(ok=False, duration_ms=3, status=401, error="x").to_dict() == {
        "ok": False, "duration_ms": 3, "status": 401, "error": "x"
    }  # fmt: skip


# E-mail with a fake smtplib object


class FakeSMTP:
    def __init__(self, security, host, port, timeout, context, *, starttls=True, fail=None):
        self.args = (security, host, port, timeout)
        self.context = context
        self.calls = []
        self.offer_starttls = starttls
        self.fail = fail
        self.sent = None

    def ehlo(self):
        self.calls.append("ehlo")

    def has_extn(self, name):
        return self.offer_starttls and name == "starttls"

    def starttls(self, context):
        assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
        self.calls.append("starttls")

    def login(self, user, password):
        self.calls.append(("login", user, password))
        if self.fail == "auth":
            raise smtplib.SMTPAuthenticationError(535, b"5.7.8 bad credentials")

    def send_message(self, msg, to_addrs):
        if self.fail == "busy":
            raise smtplib.SMTPDataError(451, b"try later")
        if self.fail == "refused":
            raise smtplib.SMTPRecipientsRefused({a: (550, b"no") for a in to_addrs})
        self.sent = (msg, to_addrs)

    def quit(self):
        self.calls.append("quit")

    def close(self):
        pass


def smtp_factory(**kw):
    made = []

    def factory(*args):
        made.append(FakeSMTP(*args, **kw))
        return made[-1]

    return factory, made


def mail_channel(**over):
    params = {
        "host": "smtp.example.lan",
        "port": 587,
        "security": "starttls",
        "username": "pelagos",
        "from": "Pelagos <pelagos@example.lan>",
        "to": ["ops@example.lan", "b@example.lan"],
    }
    params.update(over)
    return Channel(id="C1", type="email", language="fr", params=params)


def test_email_starttls_login_and_message():
    factory, made = smtp_factory()
    b = batch()
    res = send(mail_channel(), {"password": "pw"}, b, ctx(smtp=factory))
    assert res.ok and res.status == 250
    s = made[0]
    assert s.args == ("starttls", "smtp.example.lan", 587, 5.0)
    assert s.calls[:4] == ["ehlo", "starttls", "ehlo", ("login", "pelagos", "pw")]
    msg, to = s.sent
    assert to == ["ops@example.lan", "b@example.lan"]
    assert msg["Subject"].startswith("[Pelagos] 1 critique")
    assert msg["Message-ID"] == f"<{b.id}.C1@example.lan>"
    assert msg["X-Pelagos-Delivery"] == b.id and msg["Auto-Submitted"] == "auto-generated"
    assert "Encore ouvertes" in msg.get_content()


def test_email_refuses_a_server_without_starttls():
    factory, _ = smtp_factory(starttls=False)
    res = send(mail_channel(), {}, batch(), ctx(smtp=factory))
    assert not res.ok and "STARTTLS" in res.error and not res.retry


def test_email_implicit_tls_and_plain_loopback_only():
    factory, made = smtp_factory()
    assert send(mail_channel(security="tls", port=None), {}, batch(), ctx(smtp=factory)).ok
    assert made[0].args[:3] == ("tls", "smtp.example.lan", 465) and "starttls" not in made[0].calls
    res = send(mail_channel(security="none"), {}, batch(), ctx(smtp=factory))
    assert not res.ok and "loopback" in res.error and len(made) == 1
    assert send(mail_channel(security="none", host="127.0.0.1", port=25), {}, batch(), ctx(smtp=factory)).ok


@pytest.mark.parametrize(
    ("fail", "status", "retry"), [("auth", 535, False), ("busy", 451, True), ("refused", 550, False)]
)
def test_email_failures(fail, status, retry):
    factory, _ = smtp_factory(fail=fail)
    res = send(mail_channel(), {"password": "s3cret-pw"}, batch(), ctx(smtp=factory))
    assert not res.ok and res.status == status and res.retry is retry
    assert "s3cret-pw" not in res.error


# Validation


def issues(table, secrets=()):
    return {(i.field, i.level) for i in validate(table, set(secrets))}


def test_validate_per_type():
    assert issues({"type": "ntfy", "params": {"url": "https://n.example.lan", "topic": "ops"}}) == set()
    assert ("params.topic", "error") in issues(
        {"type": "ntfy", "params": {"url": "https://n", "topic": "a b"}}
    )
    assert ("params.url", "warning") in issues(
        {"type": "ntfy", "params": {"url": "http://n", "topic": "t"}}, ["token"]
    )
    assert ("params.url", "error") in issues({"type": "gotify", "params": {"url": "ftp://g"}})
    assert ("params.url", "error") in issues({"type": "webhook", "params": {"url": "https://u:p@h/x"}})
    assert ("params.room_id", "error") in issues(
        {"type": "matrix", "params": {"homeserver": "https://m", "room_id": "#a:b"}}
    )
    assert issues({"type": "matrix", "params": {"homeserver": "https://m", "room_id": "!abc"}}) == set()
    bad_headers = {
        "type": "webhook",
        "params": {"url": "https://h", "headers": {"X-A": "a\nb", "Content-Type": "x"}},
    }
    assert {f for f, _ in issues(bad_headers)} == {"params.headers.X-A", "params.headers.Content-Type"}
    assert issues({"type": "home_assistant", "params": {"url": "https://ha"}}, ["webhook_id"]) == set()
    assert issues({"type": "pager"}) == {("type", "error")}
    assert ("params.ca_pem", "error") in issues(
        {"type": "gotify", "params": {"url": "https://g", "ca_pem": "junk"}}
    )


def test_validate_email():
    good = {
        "host": "smtp.example.lan",
        "from": "p@example.lan",
        "to": ["a@example.lan"],
        "security": "starttls",
    }
    assert issues({"type": "email", "params": good}) == set()
    assert ("params.security", "error") in issues({"type": "email", "params": {**good, "security": "none"}})
    assert ("params.security", "warning") in issues(
        {"type": "email", "params": {**good, "host": "::1", "security": "none"}}
    )
    assert ("params.to.0", "error") in issues({"type": "email", "params": {**good, "to": ["nope"]}})
    assert ("params.username", "error") in issues({"type": "email", "params": good}, ["password"])
    assert ("params.port", "error") in issues({"type": "email", "params": {**good, "port": 70000}})
