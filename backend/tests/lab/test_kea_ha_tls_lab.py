# SPDX-License-Identifier: Apache-2.0
"""Kea HA TLS on the production setup (Kea 2.6.3 HA pair from Debian 13, Pelagos from this checkout).

As in production: TLS set by hand first (a certificate per peer signed with the cluster CA key by
openssl, files in /etc/kea/tls root:_kea with the key 0640, https URLs, require-client-certs,
standby then primary), then adopted by Pelagos (no kea_ha_listener_open finding, the certificates in
the inventory), renewed by plan while lab-client keeps taking leases and the pair stays in
hot-standby, a renewal whose check fails undone on both peers, and the plan from a plain HTTP pair.
The VMs are rolled back first; the pair is left running in TLS.
"""

from __future__ import annotations

import json
import threading
import time

import pytest

from pelagos.installer import keaconf
from tests.lab.labkit import (
    ADMIN_PASSWORD,
    CLIENT,
    NS1,
    NS2,
    Api,
    deb_package,
    rollback,
    run_script,
    scp,
    ssh,
    sudo_cat,
    wait_for,
)

pytestmark = pytest.mark.lab

A1, A2 = NS1[1], NS2[1]
CONF = "/etc/kea/kea-dhcp4.conf"
SOCKET = "/run/kea/kea4-ctrl-socket"
FID = {A1: f"kea:kea_ha_listener_open:kea4:{A1}:8001", A2: f"kea:kea_ha_listener_open:kea4:{A2}:8001"}
STATE: dict[str, object] = {}
APT = "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q"


def api(address: str) -> Api:
    key = f"api:{address}"
    if key not in STATE:
        client = Api(address)
        wait_for(f"{address} login", lambda: client.login(), timeout=120)
        STATE[key] = client
    return STATE[key]  # type: ignore[return-value]


def node_id(address: str) -> str:
    return api(address).get("/nodes/self")["peer"]["id"]


def kea(host: str, command: str) -> dict:
    out = ssh(host, f"echo '{json.dumps({'command': command})}' | sudo socat - UNIX-CONNECT:{SOCKET}")[1]
    return json.loads(out)


def ha(host: str) -> tuple[str, str | None]:
    servers = kea(host, "status-get")["arguments"]["high-availability"][0]["ha-servers"]
    return servers["local"]["state"], servers["remote"].get("last-state")


def both_hot_standby() -> bool:
    return all(ha(h) == ("hot-standby", "hot-standby") for h in (A1, A2))


def rel(host: str) -> dict:
    cfg = keaconf.loads(sudo_cat(host, CONF))
    hook = next(h for h in cfg["Dhcp4"]["hooks-libraries"] if h["library"].endswith("libdhcp_ha.so"))
    return hook["parameters"]["high-availability"][0]


def fingerprint(host: str, path: str) -> str:
    return ssh(host, f"sudo openssl x509 -in {path} -noout -fingerprint -sha256")[1].strip()


def findings(address: str) -> list[dict]:
    return api(address).get("/install/security")["findings"]


def ha_findings(address: str) -> list[dict]:
    return [f for f in findings(address) if f["kind"] == "kea_ha_listener_open"]


def edit(host: str, fn) -> None:
    cfg = keaconf.loads(sudo_cat(host, CONF))
    fn(cfg)
    ssh(host, f"sudo tee {CONF} >/dev/null", data=json.dumps(cfg, indent=2).encode())
    ssh(host, f"sudo runuser -u _kea -- kea-dhcp4 -t {CONF} >/dev/null")


def client_nic() -> str:
    awk = "awk -F': ' '$2 != \"lo\" && $2 != \"eth0\" {print $2; exit}'"
    return ssh(CLIENT[1], f"ip -o link show | {awk}")[1].strip()


class Watch:
    """Samples the HA state of both peers and a full DHCP exchange of lab-client while a plan runs."""

    def __init__(self) -> None:
        self.stop = threading.Event()
        self.states: list[tuple[float, str, tuple[str, str | None]]] = []
        self.leases: list[tuple[float, bool, str]] = []
        self.threads = [
            threading.Thread(target=self._ha, daemon=True),
            threading.Thread(target=self._dhcp, daemon=True),
        ]

    def __enter__(self) -> Watch:
        for t in self.threads:
            t.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop.set()
        for t in self.threads:
            t.join(timeout=60)

    def _ha(self) -> None:
        while not self.stop.is_set():
            for host in (A1, A2):
                try:
                    self.states.append((time.time(), host, ha(host)))
                except Exception as exc:  # recorded as a sample
                    self.states.append((time.time(), host, ("error", str(exc)[:80])))
            time.sleep(1)

    def _dhcp(self) -> None:
        nic = STATE.get("nic") or client_nic()
        while not self.stop.is_set():
            # One DORA with 3 tries 2 s apart, as a client that just booted.
            _code, out, err = ssh(
                CLIENT[1],
                f"sudo timeout 20 udhcpc -i {nic} -n -q -f -t 3 -T 2 -s /bin/true 2>&1 | tail -2",
                check=False,
            )
            self.leases.append(
                (time.time(), "obtained" in out or "lease of" in out, (out + err).strip()[-120:])
            )
            time.sleep(2)


class TestKeaHaTls:
    def test_00_rollback_and_provision(self):
        rollback("lab-ns1", "lab-ns2", "lab-client")
        out = run_script("provision.sh", "all", timeout=1800)
        assert "HA: hot-standby" in out
        nic = ssh(
            CLIENT[1], "ip -o link show | awk -F': ' '$2 != \"lo\" && $2 != \"eth0\" {print $2; exit}'"
        )[1]
        STATE["nic"] = nic.strip()
        ssh(
            CLIENT[1],
            "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q udhcpc >/dev/null",
            timeout=600,
        )
        for host in (A1, A2):
            assert ssh(host, "/usr/sbin/kea-dhcp4 -v")[1].strip() == "2.6.3"
        wait_for("HA in hot-standby", both_hot_standby, timeout=180, interval=5)

    def test_01_install_init_enroll_import(self):
        deb = deb_package()
        for host in (A1, A2):
            scp(host, deb, "/tmp/pelagos.deb")
            ssh(
                host,
                "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q /tmp/pelagos.deb",
                timeout=900,
            )
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

        def both_online() -> bool:
            nodes = api(A1).get("/nodes")["items"]
            return len(nodes) == 2 and all(n["status"] == "online" for n in nodes)

        wait_for("both nodes online", both_online, timeout=120)
        api(A1).call("PUT", "/admin/settings", {"collector": {"poll_seconds": 10, "peer_poll_seconds": 10}})
        for address in (A1, A2):
            api(address).apply(api(address).post("/install/import/plan", {"engines": ["bind", "kea4", "d2"]}))
        wait_for("HA in hot-standby", both_hot_standby, timeout=180, interval=5)
        assert ha_findings(A1) and ha_findings(A2)

    def test_02_tls_by_hand_as_in_production(self):
        """openssl on ns1 with the cluster CA key, 5 years, both certificates made there."""
        ext = (
            "subjectAltName=IP:$ip\\nextendedKeyUsage=serverAuth,clientAuth\\n"
            "keyUsage=critical,digitalSignature\\nbasicConstraints=critical,CA:FALSE\\n"
            "subjectKeyIdentifier=hash\\nauthorityKeyIdentifier=keyid\\n"
        )
        script = rf"""
set -e
umask 077
d=$(mktemp -d)
cd "$d"
for p in ns1:{A1} ns2:{A2}; do
  n=${{p%:*}}; ip=${{p#*:}}
  openssl ecparam -name prime256v1 -genkey -noout -out $n.key
  openssl req -new -key $n.key -subj "/CN=kea-ha-$n" -out $n.csr
  printf "{ext}" > $n.ext
  openssl x509 -req -in $n.csr -CA /var/lib/pelagos/pki/ca.crt -CAkey /var/lib/pelagos/pki/ca.key \
    -CAcreateserial -days 1825 -sha256 -extfile $n.ext -out $n.crt
done
cp /var/lib/pelagos/pki/ca.crt ca.crt
tar cf /tmp/ha-tls.tar ns1.key ns1.crt ns2.key ns2.crt ca.crt
chmod 0644 /tmp/ha-tls.tar
rm -rf "$d"
"""
        ssh(A1, "sudo bash -s", data=script.encode())
        raw = ssh(A1, "base64 -w0 /tmp/ha-tls.tar")[1]
        ssh(A2, "base64 -d > /tmp/ha-tls.tar", data=raw.encode())
        inst = "sudo install -o root -g _kea"
        for host, me in ((A1, "ns1"), (A2, "ns2")):
            ssh(
                host,
                f"set -e; {inst} -d -m 0750 /etc/kea/tls; cd /tmp && rm -rf hat && mkdir hat"
                f" && tar xf ha-tls.tar -C hat && {inst} -m 0644 hat/ca.crt /etc/kea/tls/ca.crt"
                f" && {inst} -m 0644 hat/{me}.crt /etc/kea/tls/{me}.crt"
                f" && {inst} -m 0640 hat/{me}.key /etc/kea/tls/{me}.key"
                " && sudo rm -rf hat /tmp/ha-tls.tar",
            )

            def tls(cfg: dict, me: str = me) -> None:
                hook = next(
                    h for h in cfg["Dhcp4"]["hooks-libraries"] if h["library"].endswith("libdhcp_ha.so")
                )
                r = hook["parameters"]["high-availability"][0]
                r.update(
                    {
                        "trust-anchor": "/etc/kea/tls/ca.crt",
                        "cert-file": f"/etc/kea/tls/{me}.crt",
                        "key-file": f"/etc/kea/tls/{me}.key",
                        "require-client-certs": True,
                    }
                )
                for p in r["peers"]:
                    p["url"] = p["url"].replace("http://", "https://")

            edit(host, tls)
        start = time.monotonic()
        assert kea(A2, "config-reload")["result"] == 0  # standby first
        time.sleep(3)
        assert kea(A1, "config-reload")["result"] == 0
        wait_for("HA back in hot-standby over TLS", both_hot_standby, timeout=180, interval=3)
        STATE["by_hand_seconds"] = round(time.monotonic() - start)
        print(f"by hand: hot-standby again after {STATE['by_hand_seconds']} s")

    def test_03_adopted_finding_closed_and_inventory(self):
        for address in (A1, A2):
            wait_for(
                f"no kea_ha_listener_open on {address}", lambda a=address: not ha_findings(a), timeout=60
            )
        nodes = {n["name"]: n for n in api(A1).get("/admin/certificates")["nodes"]}
        for name, ip in (("ns1", A1), ("ns2", A2)):
            (entry,) = nodes[name]["kea_ha"]
            assert entry["full"] and entry["engine"] == "kea4", entry
            cert = entry["cert"]
            assert cert["path"] == f"/etc/kea/tls/{name}.crt" and cert["san"] == [ip], cert
            assert cert["cluster_ca"] and cert["issuer_common_name"].startswith("Pelagos cluster"), cert
            assert cert["not_after"] > "2031-", cert
            assert entry["trust_anchor"]["is_cluster_ca"], entry
        assert not [
            a
            for a in api(A1).get("/alerts?state=open&kind=cert_expiry&per_page=200")["items"]
            if a["subject"].startswith("cert:kea_ha:")
        ]

    def test_04_renewal_without_outage(self):
        before = {h: fingerprint(h, f"/etc/kea/tls/{n}.crt") for h, n in ((A1, "ns1"), (A2, "ns2"))}
        confs = {h: sudo_cat(h, CONF) for h in (A1, A2)}
        plan = api(A1).post("/install/security/ha-tls/plan", {})
        assert "renew" in plan["summary"], plan["summary"]
        with Watch() as watch:
            time.sleep(10)
            job = api(A1).apply(plan, timeout=900)
            time.sleep(10)
        STATE["renewal_job"] = [(s["name"], s["state"]) for s in job["steps"]]
        for host, name in ((A1, "ns1"), (A2, "ns2")):
            assert fingerprint(host, f"/etc/kea/tls/{name}.crt") != before[host]
            assert sudo_cat(host, CONF) == confs[host]  # same paths, nothing rewritten
            mode = ssh(host, f"sudo stat -c '%a %U:%G' /etc/kea/tls/{name}.key")[1].strip()
            assert mode == "640 root:_kea", mode
        assert both_hot_standby()
        bad = [s for s in watch.states if s[2][0] not in ("hot-standby", "waiting", "syncing", "ready")]
        states = sorted({(h, s) for _t, h, s in watch.states})
        print("HA states seen:", states)
        print("leases:", [(round(t), ok) for t, ok, _o in watch.leases])
        assert not [s for s in watch.states if s[2][0] in ("partner-down", "terminated", "error")], bad
        assert watch.leases and all(ok for _t, ok, _o in watch.leases), watch.leases

    def test_05_failed_check_is_undone_on_both(self):
        before = {h: fingerprint(h, f"/etc/kea/tls/{n}.crt") for h, n in ((A1, "ns1"), (A2, "ns2"))}
        # ns1 stops answering ns2 on the HA port: ns2's check after its reload cannot pass.
        ssh(A1, f"{APT} nftables >/dev/null", timeout=600)
        ssh(
            A1,
            "sudo nft add table inet labcut && sudo nft add chain inet labcut input "
            "'{ type filter hook input priority -50; }' && "
            f"sudo nft add rule inet labcut input ip saddr {A2} tcp dport 8001 drop",
        )
        try:
            plan = api(A1).post("/install/security/ha-tls/plan", {})
            out = api(A1).post(f"/plans/{plan['id']}/apply", {"confirm": True})

            def finished() -> dict | None:
                job = api(A1).get(f"/jobs/{out['id']}")
                return job if job["state"] in ("done", "failed") else None

            job = wait_for("renewal job", finished, timeout=900, interval=3)
        finally:
            ssh(A1, "sudo nft delete table inet labcut", check=False)
        assert job["state"] == "failed", job
        print("undo:", [(s["name"], s["state"], (s.get("output") or "")[-160:]) for s in job["steps"]])
        names = [s["name"] for s in job["steps"]]
        assert any("ha-tls-undo" in n for n in names), names
        for host, name in ((A1, "ns1"), (A2, "ns2")):
            assert fingerprint(host, f"/etc/kea/tls/{name}.crt") == before[host]
        wait_for("HA back in hot-standby", both_hot_standby, timeout=240, interval=5)

    def test_06_plan_from_a_plain_http_pair(self):
        def plain(cfg: dict) -> None:
            hooks = cfg["Dhcp4"]["hooks-libraries"]
            r = next(h for h in hooks if h["library"].endswith("libdhcp_ha.so"))["parameters"]
            r = r["high-availability"][0]
            for key in ("trust-anchor", "cert-file", "key-file", "require-client-certs"):
                r.pop(key, None)
            for p in r["peers"]:
                p["url"] = p["url"].replace("https://", "http://")

        for host in (A1, A2):
            edit(host, plain)
        assert kea(A2, "config-reload")["result"] == 0
        assert kea(A1, "config-reload")["result"] == 0
        wait_for("HA in hot-standby over HTTP", both_hot_standby, timeout=180, interval=5)
        wait_for("finding back", lambda: ha_findings(A1) and ha_findings(A2), timeout=60)
        selection = {node_id(A1): [FID[A1]], node_id(A2): [FID[A2]]}
        plan = api(A1).post("/install/security/plan", {"selection": selection})
        assert any(c["target"].startswith("security/ha-tls/ha-tls-3-primary") for c in plan["changes"]), plan
        with Watch() as watch:
            job = api(A1).apply(plan, timeout=900)
        print("switch steps:", [(s["name"], s["state"]) for s in job["steps"]])
        print("HA states seen:", sorted({(h, s) for _t, h, s in watch.states}))
        for host in (A1, A2):
            r = rel(host)
            assert r["require-client-certs"] is True and all(
                p["url"].startswith("https://") for p in r["peers"]
            )
            assert r["cert-file"].startswith("/etc/kea/tls/") and r["trust-anchor"].startswith(
                "/etc/kea/tls/"
            )
        wait_for("HA in hot-standby over TLS", both_hot_standby, timeout=180, interval=5)
        for address in (A1, A2):
            wait_for(
                f"no kea_ha_listener_open on {address}", lambda a=address: not ha_findings(a), timeout=60
            )
