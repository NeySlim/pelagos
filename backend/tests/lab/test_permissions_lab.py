# SPDX-License-Identifier: Apache-2.0
"""Permission guard under the packaged units (production item 79).

lab-r5a (snapshot `legacy`) runs named with `directory "/etc/bind/cache"` (bind:bind, not group
writable, no pelagos folder), the layout where 0.2.4 failed every RPZ subscription with EPERM:
`RestrictSUIDSGID=yes` refused `mkdir(0o2775)`. Earlier lab runs missed it because the importer
pre-creates `/var/cache/bind/pelagos` as root and named's `directory` was that folder.
With `$PELAGOS_P79_OLD_DEB` (the 0.2.4 deb) the failure is reproduced first. Then the deb of this
checkout: its postinst creates `/etc/bind/cache/pelagos` (named's folder itself untouched, a second
run changes nothing); with the folder removed the RPZ plan is refused at plan time with the
finding, `path_not_writable` opens, the `path_access` plan of the privileged helper fixes it, the
alert resolves and the subscription (a list served from lab-dev) loads. A collector drop-in without
the engine ReadWritePaths is detected in the unit's sandbox. lab-k1a (snapshot `k1-ha26`, Kea 2.6.3
from Debian) with its D2 file `_kea:root 0640` is detected as unreadable.
"""

from __future__ import annotations

import functools
import http.server
import os
import socketserver
import tempfile
import threading
from pathlib import Path

import pytest

from tests.lab.labkit import ADMIN_PASSWORD, Api, deb_package, rollback, scp, ssh, wait_for

pytestmark = pytest.mark.lab

NODE = "10.99.0.55"
K1A = "10.99.0.85"
LAB_DEV = os.environ.get("PELAGOS_LAB_DEV_ADDRESS", "10.99.0.15")
CACHE = "/etc/bind/cache"
ZONE_DIR = f"{CACHE}/pelagos"
DROPIN = "/etc/systemd/system/pelagos-collector.service.d/no-engine-paths.conf"
NO_ENGINE_PATHS = "[Service]\nReadWritePaths=\nReadWritePaths=/var/lib/pelagos /run/pelagos /etc/pelagos\n"
CHECK = "sudo pelagos permissions check --unit pelagos-collector.service"
FEED = "malware1.example.com\nmalware2.example.net\nphish.example.org\n"


def api(address: str = NODE) -> Api:
    a = Api(address)
    a.login()
    return a


def open_alerts(a: Api) -> list[dict]:
    return [
        x for x in a.get("/alerts?kind=path_not_writable&per_page=500")["items"] if x["state"] != "resolved"
    ]


def mode(path: str, host: str = NODE) -> str:
    return ssh(host, f"stat -c '%a %U:%G' {path}")[1].strip()


@pytest.fixture(scope="module")
def feed():
    """A small domain list served from lab-dev (no external feed in the lab)."""
    root = Path(tempfile.mkdtemp(prefix="pelagos-rpz-feed-"))
    (root / "tif.txt").write_text(FEED)
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(root))
    server = socketserver.TCPServer((LAB_DEV, 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://{LAB_DEV}:{server.server_address[1]}/tif.txt"
    finally:
        server.shutdown()


def install(deb: Path) -> None:
    scp(NODE, deb, "/tmp/pelagos.deb")
    ssh(NODE, "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q /tmp/pelagos.deb", timeout=900)


def subscribe(a: Api, url: str) -> dict:
    a.call("PUT", "/admin/settings", {"rpz": {"private_sources_enabled": True}})
    body = {"kind": "url", "url": url, "format": "domains", "category": "security", "name": "local TIF"}
    out = a.call("PUT", "/dns/rpz/subscriptions/localtif", body)
    return out["plan"] or a.post("/dns/rpz/plan")["plan"]


@pytest.fixture(scope="module")
def node(feed):
    if os.environ.get("PELAGOS_LAB_ROLLED_BACK") != "1":  # the caller restored `legacy` already
        rollback("lab-r5a")
    # Production's layout: named's directory outside /var/cache/bind, bind:bind, no pelagos folder.
    ssh(
        NODE,
        f"sudo install -d -o bind -g bind -m 0755 {CACHE} "
        f'&& sudo sed -i \'s#directory "/var/cache/bind";#directory "{CACHE}";#\' '
        "/etc/bind/named.conf.options "
        f"&& printf '{CACHE}/ rw,\\n{CACHE}/** rwk,\\n' | sudo tee -a /etc/apparmor.d/local/usr.sbin.named "
        "&& sudo apparmor_parser -r /etc/apparmor.d/usr.sbin.named && sudo systemctl restart named",
    )
    old = os.environ.get("PELAGOS_P79_OLD_DEB")
    install(Path(old) if old else deb_package())
    ssh(
        NODE,
        f"sudo rmdir {ZONE_DIR}/rpz {ZONE_DIR} 2>/dev/null; "
        f"sudo PELAGOS_ADMIN_PASSWORD={ADMIN_PASSWORD} pelagos init --name ns1 "
        f"--web-url https://{NODE}:8443 --replication-url https://{NODE}:8444 "
        "&& sudo pelagos import --engines bind --yes && sudo systemctl start pelagos pelagos-collector",
        timeout=600,
    )
    wait_for("web API", api, timeout=120)
    try:
        yield bool(old)
    finally:
        ssh(NODE, f"sudo rm -f {DROPIN}; sudo systemctl daemon-reload", check=False)


def test_old_release_fails_with_eperm_then_the_deb_creates_the_folder(node, feed):
    a = api()
    if node:
        plan = subscribe(a, feed)
        result = a.post(f"/plans/{plan['id']}/apply", {"confirm": True}, timeout=600)
        assert result["state"] != "applied"
        assert f"cannot create zone directory {ZONE_DIR}: [Errno 1] Operation not permitted" in str(result)
        install(deb_package())
        ssh(NODE, "sudo systemctl start pelagos pelagos-collector")
        wait_for("web API", api, timeout=120)
    else:
        ssh(NODE, "sudo dpkg-reconfigure pelagos")  # the postinst of an upgrade
    before = mode(CACHE)
    assert mode(ZONE_DIR) == "2775 bind:bind"
    log = ssh(NODE, "sudo journalctl -t pelagos-postinst --no-pager")[1]
    assert f"created {ZONE_DIR}: absent -> 2775 bind:bind" in log
    # Idempotent, and named's own folder is never widened.
    assert ssh(NODE, "sudo pelagos permissions ensure 2>/dev/null")[1].strip() == ""
    assert mode(CACHE) == before and before.split()[0] in ("755", "2755")
    assert ssh(NODE, CHECK, check=False)[0] == 0


def test_refused_at_plan_time_alert_fix_then_subscription(node, feed):
    a = api()
    ssh(NODE, f"sudo rm -rf {ZONE_DIR}")
    rc, out, _ = ssh(NODE, CHECK, check=False)
    assert rc == 1 and f"install -d -o bind -g bind -m 2775 {ZONE_DIR}" in out, out
    plan = subscribe(a, feed)
    assert plan["state"] == "failed" and plan["error_message"]["key"] == "permission.plan_refused"
    (refusal,) = [v for v in plan["validations"] if v["tool"] == "permissions"]
    assert f"install -d -o bind -g bind -m 2775 {ZONE_DIR}" in refusal["output"]
    assert "cannot be created: no write permission on the parent folder" in refusal["output"]
    assert ssh(NODE, f"test -e {ZONE_DIR}", check=False)[0] == 1  # nothing created at plan time

    ssh(NODE, "sudo systemctl restart pelagos-collector")
    alerts = wait_for("path_not_writable", lambda: open_alerts(a), timeout=120, interval=5)
    assert {x["subject"] for x in alerts} >= {f"path:{ZONE_DIR}"}
    assert all(x["severity"] == "warning" for x in alerts)

    view = a.get("/install/permissions")
    ids = sorted({c["finding_id"] for c in view["checks"] if not c["ok"] and c.get("finding_id")})
    assert ids == [f"bind:path_access:{ZONE_DIR}"]
    fix = a.post("/install/security/plan", {"selection": {view["node_id"]: ids}})
    assert "(absent -> 2775 bind:bind)" in fix["diff"]
    job = a.apply(fix)
    assert job["state"] == "done"
    assert mode(ZONE_DIR) == "2775 bind:bind"
    # The fix's audit entry wakes the collector's check: the alert resolves on its own.
    wait_for("alert resolved", lambda: not open_alerts(a), timeout=120, interval=5)

    plan = a.post("/dns/rpz/plan")["plan"]
    assert plan["state"] == "validated", plan
    result = a.post(f"/plans/{plan['id']}/apply", {"confirm": True}, timeout=600)
    assert result["state"] == "applied", result
    # The unit created rpz/ itself: setgid inherited from its parent, never asked for.
    assert mode(f"{ZONE_DIR}/rpz") == "2775 pelagos:bind"
    a.post("/dns/rpz/refresh", {})

    def loaded() -> bool:
        answer = ssh(NODE, "dig +short @127.0.0.1 malware1.example.com.localtif.rpz.invalid CNAME")[1]
        return answer.strip() == "."

    wait_for("the list loaded into its policy zone", loaded, timeout=300, interval=10)


def test_sandbox_without_the_engine_paths_is_detected(node):
    a = api()
    ssh(
        NODE,
        f"printf '{NO_ENGINE_PATHS}' | sudo install -D -m 0644 /dev/stdin {DROPIN}"
        " && sudo systemctl daemon-reload",
    )
    rc, out, _ = ssh(NODE, CHECK, check=False)
    assert rc == 1 and "outside the paths the service may write (ReadWritePaths)" in out, out
    ssh(NODE, "sudo systemctl restart pelagos-collector")

    def read_only() -> list[dict]:
        return [x for x in open_alerts(a) if x["details"]["problem"] == "read_only"]

    alerts = wait_for("read_only alerts", read_only, timeout=120, interval=5)
    assert any(x["subject"] == f"path:{ZONE_DIR}" for x in alerts)
    ssh(
        NODE,
        f"sudo rm -f {DROPIN} && sudo systemctl daemon-reload && sudo systemctl restart pelagos-collector",
    )
    wait_for("alerts resolved", lambda: not open_alerts(a), timeout=120, interval=5)


def test_kea_file_of_group_root_is_detected():
    if ssh(K1A, "true", check=False, timeout=30)[0] != 0:
        pytest.skip("lab-k1a is not running")
    scp(K1A, deb_package(), "/tmp/pelagos.deb")
    conf = "/etc/kea/kea-dhcp-ddns.conf"
    ssh(
        K1A,
        "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q /tmp/pelagos.deb "
        f"&& sudo PELAGOS_ADMIN_PASSWORD={ADMIN_PASSWORD} pelagos init --name k1a "
        f"--web-url https://{K1A}:8443 --replication-url https://{K1A}:8444 "
        f"&& sudo pelagos import --engines kea4,d2 --yes && sudo chgrp root {conf} && sudo chmod 0640 {conf}",
        timeout=900,
    )
    rc, out, _ = ssh(K1A, CHECK, check=False)
    assert rc == 1 and f"Kea file {conf}: cannot be read: no read permission" in out, out
    assert f"chgrp _kea {conf} && chmod g+r {conf}" in out
