# SPDX-License-Identifier: Apache-2.0
"""pelagos enroll waits for a peer whose replication port is briefly closed, never resends a request."""

from __future__ import annotations

import ssl

import pytest

from pelagos.core import enrollment
from pelagos.core.enrollment import EnrollError, fetch_ca
from pelagos.core.repl_http import ConnectFailed, HttpResult


def _refused() -> ConnectFailed:
    try:
        raise ConnectionRefusedError(111, "Connection refused")
    except ConnectionRefusedError as cause:
        exc = ConnectFailed("cannot connect to ns1.example.lan:8444: [Errno 111] Connection refused")
        exc.__cause__ = cause
        return exc


@pytest.fixture
def clock(monkeypatch):
    now = [0.0]
    monkeypatch.setattr(enrollment.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(enrollment.time, "sleep", lambda s: now.__setitem__(0, now[0] + s))
    return now


def _send(outcomes):
    calls = []

    def send():
        calls.append(1)
        out = outcomes.pop(0)
        if isinstance(out, Exception):
            raise out
        return out

    return send, calls


def test_refused_connections_are_retried_until_the_peer_answers(clock):
    ok = HttpResult(200, {"ca_pem": "x"}, None)
    send, calls = _send([_refused(), _refused(), ok])
    notes: list[str] = []
    assert enrollment._request_with_retry(send, 60.0, notes.append) is ok
    assert len(calls) == 3 and len(notes) == 2 and "retrying in" in notes[0]
    assert clock[0] == 3.0


def test_retry_gives_up_with_a_clear_message(clock):
    send, calls = _send([_refused() for _ in range(50)])
    with pytest.raises(EnrollError) as err:
        enrollment._request_with_retry(send, 10.0, lambda _m: None)
    assert err.value.code == "unreachable"
    assert "still failing after 10 s" in str(err.value) and "collector" in str(err.value)
    assert clock[0] <= 10.0 and len(calls) > 1


def test_certificate_errors_and_no_retry_budget_fail_at_once(clock):
    bad = ConnectFailed("cannot connect: certificate verify failed")
    bad.__cause__ = ssl.SSLCertVerificationError("certificate verify failed")
    send, calls = _send([bad])
    with pytest.raises(ConnectFailed):
        enrollment._request_with_retry(send, 60.0, lambda _m: None)
    send, calls2 = _send([_refused()])
    with pytest.raises(ConnectFailed):
        enrollment._request_with_retry(send, 0.0, lambda _m: None)
    assert len(calls) == 1 and len(calls2) == 1 and clock[0] == 0.0


def test_fetch_ca_reports_a_closed_port_as_unreachable(clock, monkeypatch):
    def refuse(*_a, **_k):
        raise _refused()

    monkeypatch.setattr(enrollment, "request_json", refuse)
    with pytest.raises(EnrollError) as err:
        fetch_ca("https://ns1.example.lan:8444", "sha256:00", retry_for=5.0)
    assert err.value.code == "unreachable" and clock[0] > 0
