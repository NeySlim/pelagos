# SPDX-License-Identifier: Apache-2.0
"""Notifications on a real pair (lab-ad1 ns1, lab-ad2 ns2: BIND, Kea 2.6 HA from Debian 13) toward real
receivers in containers on lab-docker: ntfy (token), Gotify (application token), Mailpit (SMTP
STARTTLS with a private CA and a login), Conduit (Matrix bot) and a webhook receiver checking the
HMAC signature.

The pair runs the deb of this checkout (installed over what is there; a pair is set up first when the
VMs have no Pelagos). Each channel is tested through the API, then a real outage (Kea stopped on ns2)
reaches every channel once from ns1 and its end sends the resolution. The sender VM is then powered
off: ns2 takes over after its missed peer polls (90 s with the default 30 s polls) and reports it;
when ns1 is back the resolutions leave, and no event reached the webhook more than twice. The lab
VMs are not rolled back (they have no base snapshot): the channels and containers are removed at the
end unless PELAGOS_LAB_KEEP=1.
"""

from __future__ import annotations

import base64
import json
import time
import urllib.error
import urllib.request
from typing import Any

import pytest

from pelagos import __version__
from tests.lab.labkit import (
    ADMIN_PASSWORD,
    DOCKER,
    Api,
    deb_package,
    keep,
    put,
    pve_vm,
    run_script,
    scp,
    ssh,
    wait_for,
)

pytestmark = pytest.mark.lab

AD1 = ("lab-ad1", "10.99.0.31", 9131)
AD2 = ("lab-ad2", "10.99.0.32", 9132)
A1, A2, DK = AD1[1], AD2[1], DOCKER[1]
STATE: dict[str, Any] = {}
HMAC_SECRET = "lab-hmac-secret-1"
MAIL_PASSWORD = "lab-mail-password-1"
MATRIX_REG = "lab-matrix-registration-1"
KINDS = ["daemon_down", "peer_offline", "ha_partner_down", "ha_degraded"]

RECEIVER = r"""
import hashlib, hmac, json, os, sys, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
SECRET = os.environ["HMAC_SECRET"].encode()
GOT = []
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        ts = self.headers.get("X-Pelagos-Timestamp", "")
        want = "sha256=" + hmac.new(SECRET, ts.encode() + b"." + raw, hashlib.sha256).hexdigest()
        ok = hmac.compare_digest(want, self.headers.get("X-Pelagos-Signature", ""))
        ok = ok and abs(time.time() - int(ts or 0)) < 300
        delivery = self.headers.get("X-Pelagos-Delivery")
        GOT.append({"at": time.time(), "signed": ok, "delivery": delivery, "body": json.loads(raw)})
        self.send_response(200 if ok else 401); self.send_header("Content-Length", "0"); self.end_headers()
    def do_GET(self):
        out = json.dumps(GOT).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out))); self.end_headers(); self.wfile.write(out)
    def log_message(self, *a): pass
ThreadingHTTPServer(("0.0.0.0", 8090), H).serve_forever()
"""

CERTS = f"""
set -e
d=/srv/n5/certs; sudo rm -rf $d; sudo mkdir -p $d; cd $d
ec="-newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes"
sudo openssl req -x509 $ec -days 2 -subj /CN=n5-lab-ca -keyout ca.key -out ca.pem \
  -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign 2>/dev/null
sudo openssl req $ec -subj /CN={DK} -keyout key.pem -out req.csr 2>/dev/null
printf 'subjectAltName=IP:{DK}\\nextendedKeyUsage=serverAuth\\nkeyUsage=critical,digitalSignature\\n' \
  | sudo tee ext >/dev/null
sudo openssl x509 -req -in req.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 -extfile ext \
  -out cert.pem 2>/dev/null
sudo chmod 644 key.pem
"""


def api(address: str) -> Api:
    key = f"api:{address}"
    if key not in STATE:
        client = Api(address)
        wait_for(f"{address} login", lambda: client.login(), timeout=300, interval=5)
        STATE[key] = client
    return STATE[key]  # type: ignore[return-value]


def docker(command: str, check: bool = True) -> str:
    return ssh(DK, f"sudo docker {command}", check=check)[1]


def http_json(
    url: str, headers: dict[str, str] | None = None, data: Any = None, method: str | None = None
) -> Any:
    body = None if data is None else json.dumps(data).encode()
    req = urllib.request.Request(url, data=body, headers=headers or {}, method=method)  # noqa: S310 - lab http
    if body is not None:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=20) as res:  # noqa: S310
        return json.loads(res.read() or b"null")


def basic(user: str, password: str) -> dict[str, str]:
    return {"Authorization": "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()}


# What each receiver got ------------------------------------------------------------------------


def webhook() -> list[dict[str, Any]]:
    return http_json(f"http://{DK}:8090/")


def ntfy() -> list[dict[str, Any]]:
    url = f"http://{DK}:8080/pelagos/json?poll=1&since=all"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {STATE['ntfy_token']}"})
    with urllib.request.urlopen(req, timeout=20) as res:  # noqa: S310
        return [json.loads(line) for line in res.read().decode().splitlines() if line.strip()]


def gotify() -> list[dict[str, Any]]:
    return http_json(f"http://{DK}:8081/message?limit=200", basic("admin", "lab-gotify-1"))["messages"]


def mailpit() -> list[dict[str, Any]]:
    return http_json(f"http://{DK}:8025/api/v1/messages?limit=200")["messages"]


def matrix() -> list[dict[str, Any]]:
    room = STATE["room_id"]
    url = f"http://{DK}:6167/_matrix/client/v3/rooms/{room}/messages?dir=b&limit=200"
    out = http_json(url, {"Authorization": f"Bearer {STATE['matrix_token']}"})["chunk"]
    return [e for e in out if e.get("type") == "m.room.message"]


RECEIVERS = {"webhook": webhook, "ntfy": ntfy, "gotify": gotify, "email": mailpit, "matrix": matrix}


def counts() -> dict[str, int]:
    return {name: len(fn()) for name, fn in RECEIVERS.items()}


def texts(name: str) -> list[str]:
    items = RECEIVERS[name]()
    if name == "webhook":
        return [json.dumps(i["body"]) for i in items]
    if name == "ntfy":
        return [f"{i.get('title', '')} {i.get('message', '')}" for i in items]
    if name == "gotify":
        return [f"{i.get('title', '')} {i.get('message', '')}" for i in items]
    if name == "email":
        return [f"{i.get('Subject', '')} {i.get('Snippet', '')}" for i in items]
    return [e["content"].get("body", "") for e in items]


def batches(after: int = 0) -> list[dict[str, Any]]:
    return [w for w in webhook()[after:] if w["body"]["reason"] != "test"]


def events(items: list[dict[str, Any]]) -> list[tuple[str, str, str | None]]:
    return [
        (e["event"], e["alert"]["kind"], e["alert"]["node_name"]) for w in items for e in w["body"]["events"]
    ]


def sender_of(address: str) -> str | None:
    return api(address).get("/admin/notifications")["sender"]["node_id"]


class TestNotifyLab:
    def test_00_deploy_this_checkout(self):
        deb = deb_package()
        fresh = ssh(A1, "sudo test -f /etc/pelagos/node.toml", check=False)[0] != 0
        if fresh:
            run_script("provision.sh", "pair", timeout=1800, env={
                "PROV_NS1": AD1[0], "PROV_NS2": AD2[0], "PROV_NS1_IP": A1, "PROV_NS2_IP": A2})  # fmt: skip
        for host in (A1, A2):
            scp(host, deb, "/tmp/pelagos.deb")
            ssh(
                host,
                "sudo DEBIAN_FRONTEND=noninteractive apt-get install --reinstall -y -q /tmp/pelagos.deb",
                timeout=900,
            )
            ssh(host, "sudo systemctl restart pelagos pelagos-collector")
        if fresh:
            ssh(
                A1,
                f"sudo PELAGOS_ADMIN_PASSWORD={ADMIN_PASSWORD} pelagos init --name ns1 "
                f"--web-url https://{A1}:8443 --replication-url https://{A1}:8444 "
                "&& sudo systemctl start pelagos pelagos-collector",
            )
            token = api(A1).post("/nodes/enroll-token", {})
            ssh(
                A2,
                f"sudo pelagos enroll --url {token['url']} --token {token['token']} "
                f"--ca-fingerprint {token['ca_fingerprint']} --name ns2 "
                f"--replication-url https://{A2}:8444 --web-url https://{A2}:8443 "
                "&& sudo systemctl start pelagos pelagos-collector",
            )

        def both_current() -> bool:
            nodes = api(A1).get("/nodes")["items"]
            return len(nodes) == 2 and all(
                n["status"] == "online" and n.get("version") == __version__ for n in nodes
            )

        wait_for("both nodes online on this version", both_current, timeout=300, interval=5)
        if fresh:
            for address in (A1, A2):
                api(address).apply(
                    api(address).post("/install/import/plan", {"engines": ["bind", "kea4", "d2"]})
                )
        # Production defaults for the timings under test; a fast collector poll.
        api(A1).call(
            "PUT",
            "/admin/settings",
            {
                "collector": {"poll_seconds": 10, "peer_poll_seconds": 30},
                "notifications": {"group_seconds": 60, "confirm_seconds": 60, "messages_max_per_hour": 30},
            },
        )
        for channel in api(A1).get("/admin/notifications")["channels"]:
            api(A1).call("DELETE", f"/admin/notifications/channels/{channel['id']}")
        if api(A1).get("/admin/notifications")["mute"]:
            api(A1).call("DELETE", "/admin/notifications/mute")
        order = [
            n["peer"]["id"] for n in sorted(api(A1).get("/nodes")["items"], key=lambda n: n["peer"]["name"])
        ]
        api(A1).call("PUT", "/admin/notifications/order", {"node_ids": order})
        STATE["ids"] = order
        wait_for("ns1 sender", lambda: sender_of(A1) == order[0], timeout=120)

    def test_01_receivers(self):
        docker("rm -f n5-ntfy n5-gotify n5-mailpit n5-hook n5-conduit >/dev/null 2>&1", check=False)
        ssh(DK, "sudo rm -rf /srv/n5 && sudo mkdir -p /srv/n5")
        ssh(DK, CERTS)
        put(DK, "/srv/n5/receiver.py", RECEIVER)
        docker(
            "run -d --name n5-hook -p 8090:8090 -e HMAC_SECRET=" + HMAC_SECRET
            + " -v /srv/n5/receiver.py:/r.py:ro python:3.13-slim python -u /r.py"
        )  # fmt: skip
        docker(
            "run -d --name n5-ntfy -p 8080:80 -v /srv/n5/ntfy:/var/lib/ntfy "
            "-e NTFY_AUTH_FILE=/var/lib/ntfy/auth.db "
            "-e NTFY_AUTH_DEFAULT_ACCESS=deny-all -e NTFY_BASE_URL=http://" + DK + ":8080 "
            "binwiederhier/ntfy serve"
        )
        docker("run -d --name n5-gotify -p 8081:80 -e GOTIFY_DEFAULTUSER_PASS=lab-gotify-1 gotify/server")
        docker(
            "run -d --name n5-mailpit -p 8025:8025 -p 1025:1025 -v /srv/n5/certs:/certs:ro axllent/mailpit "
            "--smtp-tls-cert /certs/cert.pem --smtp-tls-key /certs/key.pem --smtp-require-starttls "
            "--smtp-auth-accept-any"
        )
        docker(
            "run -d --name n5-conduit -p 6167:6167 -e CONDUIT_CONFIG= -e CONDUIT_SERVER_NAME=lab.example "
            "-e CONDUIT_DATABASE_BACKEND=rocksdb -e CONDUIT_DATABASE_PATH=/var/lib/matrix-conduit/ "
            "-e CONDUIT_PORT=6167 -e CONDUIT_ADDRESS=0.0.0.0 -e CONDUIT_ALLOW_REGISTRATION=true "
            f"-e CONDUIT_REGISTRATION_TOKEN={MATRIX_REG} -e CONDUIT_ALLOW_FEDERATION=false "
            "-e 'CONDUIT_TRUSTED_SERVERS=[]' matrixconduit/matrix-conduit"
        )
        wait_for("webhook receiver", lambda: webhook() == [], timeout=60)

        # ntfy: a user and its access token, topic `pelagos`.
        wait_for("ntfy", lambda: http_json(f"http://{DK}:8080/v1/health")["healthy"], timeout=60)
        docker("exec -e NTFY_PASSWORD=lab-ntfy-1 n5-ntfy ntfy user add --role=admin pelagos")
        out = docker("exec n5-ntfy ntfy token add pelagos")
        STATE["ntfy_token"] = next(w for w in out.split() if w.startswith("tk_"))

        # Gotify: an application token.
        wait_for("gotify", lambda: http_json(f"http://{DK}:8081/health")["health"] == "green", timeout=60)
        app = http_json(f"http://{DK}:8081/application", basic("admin", "lab-gotify-1"), {"name": "pelagos"})
        STATE["gotify_token"] = app["token"]

        # Matrix: a bot account registered with the token, and a room it created.
        def register() -> dict[str, Any]:
            url = f"http://{DK}:6167/_matrix/client/v3/register"
            body: dict[str, Any] = {"username": "pelagos", "password": "lab-matrix-bot-1"}
            try:
                return http_json(url, data=body)
            except urllib.error.HTTPError as exc:
                session = json.loads(exc.read())["session"]
            body["auth"] = {"type": "m.login.registration_token", "token": MATRIX_REG, "session": session}
            return http_json(url, data=body)

        bot = wait_for("matrix bot", register, timeout=60)
        STATE["matrix_token"] = bot["access_token"]
        room = http_json(
            f"http://{DK}:6167/_matrix/client/v3/createRoom",
            {"Authorization": f"Bearer {bot['access_token']}"},
            {"name": "pelagos"},
        )
        STATE["room_id"] = room["room_id"]
        STATE["ca_pem"] = ssh(DK, "cat /srv/n5/certs/ca.pem")[1]
        wait_for("mailpit", lambda: mailpit() == [], timeout=60)

    def test_02_channels_tested_through_the_api(self):
        filters = {"kinds_include": KINDS}
        specs = {
            "webhook": {"params": {"url": f"http://{DK}:8090/hook"}, "secrets": {"hmac_secret": HMAC_SECRET}},
            "ntfy": {
                "params": {"url": f"http://{DK}:8080", "topic": "pelagos"},
                "secrets": {"token": STATE["ntfy_token"]},
            },
            "gotify": {"params": {"url": f"http://{DK}:8081"}, "secrets": {"token": STATE["gotify_token"]}},
            "email": {
                "params": {
                    "host": DK,
                    "port": 1025,
                    "security": "starttls",
                    "username": "pelagos",
                    "from": "pelagos@example.lan",
                    "to": ["ops@example.lan"],
                    "ca_pem": STATE["ca_pem"],
                },
                "secrets": {"password": MAIL_PASSWORD},
            },
            "matrix": {
                "params": {"homeserver": f"http://{DK}:6167", "room_id": STATE["room_id"]},
                "secrets": {"token": STATE["matrix_token"]},
            },
        }
        STATE["channels"] = {}
        for kind, spec in specs.items():
            body = {"type": kind, "name": f"lab {kind}", "language": "fr" if kind == "email" else "en",
                    "filters": filters, **spec}  # fmt: skip
            channel = api(A1).post("/admin/notifications/channels", body)
            assert any(channel["secrets"].values()), channel
            assert MAIL_PASSWORD not in json.dumps(channel) and HMAC_SECRET not in json.dumps(channel)
            STATE["channels"][kind] = channel["id"]
            result = api(A1).post("/admin/notifications/test", {"channel_id": channel["id"]})
            assert result["ok"] is True, (kind, result)
        got = wait_for("every test message", lambda: all(v >= 1 for v in counts().values()) and counts())
        assert got == dict.fromkeys(RECEIVERS, 1), got
        [hook] = webhook()
        assert hook["signed"] and hook["body"]["reason"] == "test"
        # The email channel speaks French; the others English.
        assert any("Pelagos" in t for t in texts("email"))
        STATE["base"] = counts()

    def test_03_kea_outage_reaches_every_channel_once(self):
        start = time.time()
        ssh(A2, "sudo systemctl stop kea-dhcp4-server")
        try:
            wait_for(
                "the outage on every channel",
                lambda: all(c > STATE["base"][k] for k, c in counts().items()),
                timeout=300,
                interval=5,
            )
            STATE["outage_s"] = time.time() - start
            time.sleep(90)
            sent = batches()
            assert all(w["signed"] for w in sent)
            assert {w["body"]["sender"]["name"] for w in sent} == {"ns1"}
            assert ("opened", "daemon_down", "ns2") in events(sent), events(sent)
            assert len([e for e in events(sent) if e == ("opened", "daemon_down", "ns2")]) == 1
            # Grouped: the HA alerts of the same outage ride in the same few messages.
            assert len(sent) <= 3, [events([w]) for w in sent]
            assert any("ns2" in t for t in texts("ntfy")[-len(sent) :])
        finally:
            ssh(A2, "sudo systemctl start kea-dhcp4-server")
        wait_for(
            "the resolution",
            lambda: ("resolved", "daemon_down", "ns2") in events(batches()),
            timeout=300,
            interval=5,
        )
        STATE["mark"] = len(webhook())

    def test_04_sender_powered_off_then_back(self):
        ids = STATE["ids"]
        mark = STATE["mark"]
        off = time.time()
        pve_vm(AD1[2], "stop")
        try:
            wait_for("ns2 sender", lambda: sender_of(A2) == ids[1], timeout=240, interval=2)
            STATE["takeover_s"] = time.time() - off
            # 3 missed peer polls of 30 s, plus a dispatcher tick.
            assert STATE["takeover_s"] < 130, STATE["takeover_s"]
            wait_for(
                "ns2 reporting ns1 offline",
                lambda: ("opened", "peer_offline", "ns1") in events(batches(mark)),
                timeout=300,
                interval=5,
            )
            from_ns2 = [w for w in batches(mark) if w["body"]["sender"]["name"] == "ns2"]
            assert from_ns2 and all(w["signed"] for w in from_ns2)
            STATE["first_from_ns2_s"] = from_ns2[0]["at"] - off
        finally:
            pve_vm(AD1[2], "start")
        wait_for("ns1 back", lambda: ssh(A1, "true", check=False)[0] == 0, timeout=300, interval=5)
        STATE.pop(f"api:{A1}", None)
        wait_for("ns1 sender again", lambda: sender_of(A2) == ids[0], timeout=300, interval=5)
        wait_for(
            "the resolution of peer_offline",
            lambda: ("resolved", "peer_offline", "ns1") in events(batches(mark)),
            timeout=300,
            interval=5,
        )
        time.sleep(60)
        seen: dict[tuple[str, str, str | None], int] = {}
        for ev in events(batches(mark)):
            seen[ev] = seen.get(ev, 0) + 1
        assert all(n <= 2 for n in seen.values()), seen
        deliveries = [w["delivery"] for w in webhook()]
        assert len(deliveries) - len(set(deliveries)) <= 1, deliveries
        history = api(A1).get(f"/admin/notifications/history?channel_id={STATE['channels']['webhook']}")
        assert {r["node_id"] for r in history["items"] if r["reason"] != "test"} == set(ids)
        print(json.dumps({k: STATE[k] for k in ("outage_s", "takeover_s", "first_from_ns2_s")}))

    def test_99_cleanup(self):
        if keep():
            pytest.skip("PELAGOS_LAB_KEEP=1")
        for channel_id in STATE.get("channels", {}).values():
            api(A1).call("DELETE", f"/admin/notifications/channels/{channel_id}")
        docker("rm -f n5-ntfy n5-gotify n5-mailpit n5-hook n5-conduit", check=False)
        ssh(DK, "sudo rm -rf /srv/n5", check=False)
