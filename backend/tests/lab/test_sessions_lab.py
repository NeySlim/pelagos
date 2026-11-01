# SPDX-License-Identifier: Apache-2.0
"""Sessions resumed across the reference pair (section 16, "Sessions across nodes").

lab-ns1 and lab-ns2 are rolled back to `clean`, get the deb of this checkout (no engine is imported:
sessions do not need one), ns1 is initialized and ns2 enrolled. Then: a cookie issued by ns1 works on
ns2 (read and write with its CSRF token); a logout on ns1 is refused on ns2 within seconds; a web
restart keeps live sessions and still refuses the logged-out cookie; a password change through ns2
ends the user's other session on ns1; removing ns2 replaces the signing secret (a cookie from before
is refused once its local session is gone) and ns2 enrolls again; with ns2 on the previous release
($PELAGOS_SESSIONS_OLD_DEB, the amd64 deb of 0.3.x; the step is skipped without it) each switch
between versions costs one login and never loops; finally the audit logs and the journals of both
nodes hold no sid, cookie, CSRF token or signing secret.

Cookies are sent by hand: the nodes are reached under their own addresses, and a browser would keep
one cookie per name (the supported topology puts one name in front of both).
"""

from __future__ import annotations

import base64
import json
import os
import ssl
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import pytest

from pelagos.core.secrets import SESSION_SIGNING, SecretBox
from tests.lab.labkit import (
    ADMIN_PASSWORD,
    NS1,
    NS2,
    Api,
    deb_package,
    rollback,
    scp,
    ssh,
    sudo_cat,
    wait_for,
)

pytestmark = pytest.mark.lab

A1, A2 = NS1[1], NS2[1]
COOKIE = "pelagos_session"
USER, USER_PASSWORD, NEW_PASSWORD = "vera", "Lab-Session-User-42", "Lab-Session-User-43"
STATE: dict[str, Any] = {"secrets": []}
OLD_DEB = os.environ.get("PELAGOS_SESSIONS_OLD_DEB")

_TLS = ssl.create_default_context()
_TLS.check_hostname = False
_TLS.verify_mode = ssl.CERT_NONE


class Answer:
    def __init__(self, status: int, body: Any, cookie: str | None) -> None:
        self.status, self.body, self.cookie = status, body, cookie


def call(
    address: str, method: str, path: str, cookie: str | None, csrf: str | None = None, body=None
) -> Answer:
    """One request with an explicit cookie; returns the status, the JSON body and any new cookie."""
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(f"https://{address}:8443/api/v1{path}", data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if cookie:
        req.add_header("Cookie", f"{COOKIE}={cookie}")
    if csrf:
        req.add_header("X-CSRF-Token", csrf)
    try:
        with urllib.request.urlopen(req, context=_TLS, timeout=60) as res:  # noqa: S310
            status, raw, headers = res.status, res.read(), res.headers
    except urllib.error.HTTPError as exc:
        status, raw, headers = exc.code, exc.read(), exc.headers
    new = None
    for header in headers.get_all("Set-Cookie") or []:
        if header.startswith(f"{COOKIE}="):
            new = header.split(";", 1)[0].split("=", 1)[1]
    return Answer(status, json.loads(raw) if raw else None, new)


def login(address: str, username: str = "admin", password: str = ADMIN_PASSWORD) -> tuple[str, str]:
    out = call(address, "POST", "/auth/login", None, body={"username": username, "password": password})
    assert out.status == 200, out.body
    assert out.cookie
    STATE["secrets"] += [
        out.cookie,
        out.body["csrf_token"],
        out.cookie.split(".")[1] if "." in out.cookie else "",
    ]
    return out.cookie, out.body["csrf_token"]


def status(address: str, cookie: str) -> int:
    return call(address, "GET", "/auth/session", cookie).status


def install(address: str, deb: Path, downgrade: bool = False) -> None:
    scp(address, deb, "/tmp/pelagos-under-test.deb")
    flag = "--allow-downgrades " if downgrade else ""
    ssh(
        address,
        f"sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q {flag}/tmp/pelagos-under-test.deb",
        timeout=900,
    )


def enroll_ns2() -> None:
    admin = Api(A1)
    wait_for("ns1 login", admin.login, timeout=120)
    token = admin.post("/nodes/enroll-token", {})
    ssh(
        A2,
        f"sudo pelagos enroll --url {token['url']} --token {token['token']} "
        f"--ca-fingerprint {token['ca_fingerprint']} --name ns2 "
        f"--replication-url https://{A2}:8444 --web-url https://{A2}:8443 "
        "&& sudo systemctl start pelagos pelagos-collector",
    )

    def both_online() -> bool:
        nodes = admin.get("/nodes")["items"]
        return len(nodes) == 2 and all(n["status"] == "online" for n in nodes)

    wait_for("both nodes online", both_online, timeout=180)


def signing_secret(address: str) -> str:
    """The clear signing secret of a node (to prove it never reaches a log)."""
    key = sudo_cat(address, "/etc/pelagos/master.key").strip()
    text = sudo_cat(address, "/var/lib/pelagos/cluster.toml")
    line = next(x for x in text.splitlines() if x.startswith(f'"{SESSION_SIGNING}"'))
    sealed = line.split("=", 1)[1].strip().strip('"')
    return SecretBox.from_b64(key).decrypt(SESSION_SIGNING, sealed)


class TestSessionsAcrossThePair:
    def test_00_rollback_and_provision(self):
        rollback("lab-ns1", "lab-ns2")
        deb = deb_package()
        for host in (A1, A2):
            install(host, deb)
        ssh(
            A1,
            f"sudo PELAGOS_ADMIN_PASSWORD={ADMIN_PASSWORD} pelagos init --name ns1 "
            f"--web-url https://{A1}:8443 --replication-url https://{A1}:8444 "
            "&& sudo systemctl start pelagos pelagos-collector",
        )
        enroll_ns2()
        admin = Api(A1)
        admin.login()
        admin.post("/admin/users", {"username": USER, "password": USER_PASSWORD, "roles": ["viewer"]})
        wait_for("the user on ns2", lambda: login(A2, USER, USER_PASSWORD), timeout=60)

    def test_01_cookie_of_ns1_works_on_ns2(self):
        cookie, csrf = login(A1, USER, USER_PASSWORD)
        out = call(A2, "GET", "/auth/session", cookie)
        assert out.status == 200 and out.body["user"]["username"] == USER and out.body["csrf_token"] == csrf
        assert out.body["node"]["peer"]["name"] == "ns2"
        out = call(A2, "PUT", "/account/preferences", cookie, csrf, {"theme_mode": "dark"})
        assert out.status == 200, out.body
        assert call(A2, "PUT", "/account/preferences", cookie, None, {"theme_mode": "dark"}).status == 403
        STATE["live"] = cookie

    def test_02_logout_on_ns1_refused_on_ns2(self):
        cookie, csrf = login(A1, USER, USER_PASSWORD)
        assert status(A2, cookie) == 200
        assert call(A1, "POST", "/auth/logout", cookie, csrf).status == 204
        started = time.monotonic()
        wait_for(
            "ns2 refuses the logged-out cookie", lambda: status(A2, cookie) == 401, timeout=10, interval=0.5
        )
        assert time.monotonic() - started < 5
        STATE["gone"] = cookie

    def test_03_restart_keeps_sessions_and_revocations(self):
        ssh(A2, "sudo systemctl restart pelagos")
        wait_for("ns2 web back", lambda: status(A2, STATE["live"]) in (200, 401), timeout=120)
        assert status(A2, STATE["live"]) == 200
        assert status(A2, STATE["gone"]) == 401

    def test_04_password_change_on_ns2_ends_other_sessions_on_ns1(self):
        first, csrf = login(A1, USER, USER_PASSWORD)
        second, _ = login(A1, USER, USER_PASSWORD)
        assert status(A1, second) == 200
        out = call(
            A2,
            "POST",
            "/auth/password",
            first,
            csrf,
            {"current_password": USER_PASSWORD, "new_password": NEW_PASSWORD},
        )
        assert out.status == 204 and out.cookie
        wait_for("ns1 refuses the other session", lambda: status(A1, second) == 401, timeout=10, interval=0.5)
        assert status(A1, out.cookie) == 200  # the caller, re-signed on ns2, works on ns1
        STATE["secrets"].append(out.cookie)

    def test_05_node_removal_replaces_the_secret_then_enroll_again(self):
        cookie, _ = login(A2, "admin", ADMIN_PASSWORD)  # local on ns2, resumed nowhere yet
        before = signing_secret(A1)
        STATE["secrets"].append(before)
        admin = Api(A1)
        admin.login()
        ns2 = next(n for n in admin.get("/nodes")["items"] if n["peer"]["name"] == "ns2")
        admin.call("DELETE", f"/nodes/{ns2['peer']['id']}")
        assert signing_secret(A1) != before
        assert status(A1, cookie) == 401  # signed with the replaced secret
        ssh(
            A2,
            "sudo systemctl stop pelagos pelagos-collector; "
            "sudo DEBIAN_FRONTEND=noninteractive apt-get purge -y -q pelagos; "
            "sudo rm -rf /etc/pelagos /var/lib/pelagos",
            timeout=600,
        )
        install(A2, deb_package())
        enroll_ns2()
        assert status(A2, cookie) == 401
        fresh, _ = login(A1, USER, NEW_PASSWORD)
        wait_for("ns2 resumes a new cookie", lambda: status(A2, fresh) == 200, timeout=60)
        STATE["secrets"].append(signing_secret(A1))

    def test_06_previous_release_both_ways_without_loops(self):
        if not OLD_DEB:
            pytest.skip("PELAGOS_SESSIONS_OLD_DEB (the previous release's amd64 deb) is not set")
        install(A2, Path(OLD_DEB), downgrade=True)
        ssh(A2, "sudo systemctl restart pelagos pelagos-collector")
        wait_for(
            "ns2 on the previous release", lambda: call(A2, "GET", "/health", None).status == 200, timeout=180
        )
        new_cookie, _ = login(A1, USER, NEW_PASSWORD)
        # 0.4.0 to 0.3.x: one 401, one login, then a plain 0.3.x cookie.
        assert status(A2, new_cookie) == 401
        old_cookie, _ = login(A2, USER, NEW_PASSWORD)
        assert "." not in old_cookie and status(A2, old_cookie) == 200
        # 0.3.x to 0.4.0: one 401, one login, a v1 cookie that ns2 refuses again once.
        assert status(A1, old_cookie) == 401
        back, _ = login(A1, USER, NEW_PASSWORD)
        assert back.startswith("v1.") and status(A1, back) == 200
        assert status(A2, back) == 401
        install(A2, deb_package())
        ssh(A2, "sudo systemctl restart pelagos pelagos-collector")
        wait_for("ns2 back on this checkout", lambda: status(A2, back) == 200, timeout=180)

    def test_07_no_session_secret_in_audit_or_journals(self):
        texts = []
        for host in (A1, A2):
            texts.append(sudo_cat(host, "/var/lib/pelagos/audit/audit.jsonl"))
            texts.append(ssh(host, "sudo journalctl -u pelagos -u pelagos-collector --no-pager -o cat")[1])
        blob = "\n".join(texts)
        assert '"auth.resume"' in blob and '"auth.logout"' in blob
        for value in STATE["secrets"]:
            if value:
                assert value not in blob
                raw = value.encode()
                assert base64.b64encode(raw).decode() not in blob
