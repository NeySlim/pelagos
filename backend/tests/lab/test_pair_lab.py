# SPDX-License-Identifier: Apache-2.0
"""The reference pair end to end: lab-ns1 and lab-ns2 from a legacy BIND + Kea HA setup to a
Pelagos cluster, driven from lab-dev over ssh and HTTPS.

scripts/lab/provision.sh builds the pair without Pelagos (BIND primary/secondary, Kea 2.6 HA
hot-standby, D2 signing with hmac-md5, lab-client as DHCP client). Then: the deb on both nodes,
ns2 enrolled from ns1, both configurations imported, the security plan applied (md5 to sha256
through the dual-key switch on both D2), a record written through ns2 and read on ns1, a host
whose reservation and records join a real lease, Kea killed on ns1 (HA alert), ns2 stopped and
caught up, a static zone edited through its file then converted to dynamic, hand edits of the Kea
files adopted, ns2's D2 file adopted, an rndc change and a zone retransfer run on ns2, all from
ns1. The VMs are
rolled back first; the pair is left running with Pelagos for the demo.
"""

from __future__ import annotations

import json
import re
import time

import pytest

from pelagos.installer import keaconf
from tests.lab.labkit import (
    CLIENT,
    NS1,
    NS2,
    Api,
    ApiError,
    deb_package,
    rollback,
    run_script,
    scp,
    ssh,
    sudo_cat,
    wait_for,
)

pytestmark = pytest.mark.lab

A1, A2, AC = NS1[1], NS2[1], CLIENT[1]
DHCP_NET = "10.99.1."
STATE: dict[str, object] = {}


def api(address: str) -> Api:
    """One logged-in session per node for the whole module (logins are rate limited)."""
    key = f"api:{address}"
    if key not in STATE:
        client = Api(address)
        wait_for(f"{address} login", lambda: client.login(), timeout=120)
        STATE[key] = client
    return STATE[key]  # type: ignore[return-value]


def node_id(address: str) -> str:
    return api(address).get("/nodes/self")["peer"]["id"]


def client_nic() -> tuple[str, str]:
    out = ssh(AC, "ip -o link show | awk -F': ' '$2 != \"lo\" && $2 != \"eth0\" {print $2; exit}'")[1]
    nic = out.strip()
    return nic, ssh(AC, f"cat /sys/class/net/{nic}/address")[1].strip()


def client_address() -> str | None:
    nic, _ = client_nic()
    out = ssh(AC, f"ip -4 -o addr show dev {nic}")[1]
    for word in out.split():
        if word.startswith(DHCP_NET):
            return word.split("/")[0]
    return None


def renew_client() -> None:
    """Releases the lease and asks again: a real DISCOVER/REQUEST from lab-client."""
    # A Kea reload sends the HA pair through WAITING and SYNCING (about 12 s) with DHCP disabled:
    # a DISCOVER sent meanwhile is dropped and the client backs off for longer than the wait.
    wait_for(
        "both Kea serving",
        lambda: all(kea_command(h, "ha-heartbeat")["arguments"]["state"] == "hot-standby" for h in (A1, A2)),
        timeout=120,
        interval=2,
    )
    nic, _ = client_nic()
    ssh(AC, f"sudo networkctl down {nic}; sleep 1; sudo networkctl up {nic}")


def kea_command(host: str, command: str) -> dict:
    out = ssh(
        host,
        f"echo '{json.dumps({'command': command})}' | sudo socat - UNIX-CONNECT:/run/kea/kea4-ctrl-socket",
    )[1]
    return json.loads(out)


def open_alerts(address: str, kind: str) -> list[dict]:
    return api(address).get(f"/alerts?state=open&kind={kind}")["items"]


def dig(host: str, name: str, rtype: str = "A") -> str:
    return ssh(host, f"dig +short @127.0.0.1 {name} {rtype}")[1].strip()


STATIC_ZONE = "static.example.lan"
STATIC_FILE = f"/var/lib/bind/db.{STATIC_ZONE}"
STATIC_TEXT = f"""; {STATIC_ZONE}: written by hand, keep this comment
$TTL 3600
@\tIN SOA ns1.example.lan. hostmaster.example.lan. ( SERIAL 3600 900 604800 300 )
\tIN NS ns1.example.lan.
\tIN NS ns2.example.lan.
ns1\tIN A {A1}
"""
KEA4_CONF = "/etc/kea/kea-dhcp4.conf"
HAND_COMMENT = "// edited by hand on the lab"
# A global-only key: no subnet copy and no bounds tied to other keys.
PROBATION = "decline-probation-period"


def install_file(host: str, path: str, content: str, owner: str, mode: str = "0664") -> None:
    user, group = owner.split(":")
    ssh(host, f"sudo install -m {mode} -o {user} -g {group} /dev/stdin {path}", data=content.encode())


def hand_edit_kea(host: str, old: int, new: int) -> None:
    """Sets the probation period in the file only (tee keeps owner and mode); Kea runs the old value."""
    text = sudo_cat(host, KEA4_CONF)
    edited = re.sub(rf'"{PROBATION}"\s*:\s*{old}\b', f'"{PROBATION}": {new}', text, count=1)
    if edited == text:
        edited = re.sub(r'"Dhcp4"\s*:\s*\{', f'"Dhcp4": {{\n    "{PROBATION}": {new},', text, count=1)
    assert edited != text, "no Dhcp4 object in the Kea file"
    if not edited.startswith(HAND_COMMENT):
        edited = f"{HAND_COMMENT}\n{edited}"
    ssh(host, f"sudo tee {KEA4_CONF} >/dev/null", data=edited.encode())


def file_diverged(address: str) -> bool:
    me = node_id(address)
    items = api(address).get("/dhcp/v4/config/file")["items"]
    return any(i["node_id"] == me and i["diverged"] for i in items)


D2_CONF = "/etc/kea/kea-dhcp-ddns.conf"
D2_TIMEOUT = "dns-server-timeout"


def hand_edit_d2(host: str, value: int) -> None:
    """Sets the DNS server timeout in the D2 file only, with a comment; D2 keeps running the old one."""
    text = sudo_cat(host, D2_CONF)
    edited = re.sub(rf'"{D2_TIMEOUT}"\s*:\s*\d+', f'"{D2_TIMEOUT}": {value}', text, count=1)
    if edited == text:
        edited = re.sub(
            r'"DhcpDdns"\s*:\s*\{', f'"DhcpDdns": {{\n    "{D2_TIMEOUT}": {value},', text, count=1
        )
    assert edited != text, "no DhcpDdns object in the D2 file"
    if not edited.startswith(HAND_COMMENT):
        edited = f"{HAND_COMMENT}\n{edited}"
    ssh(host, f"sudo tee {D2_CONF} >/dev/null", data=edited.encode())


def d2_file_of(address: str, node: str) -> dict:
    items = api(address).get("/dhcp/d2/config/file")["items"]
    return next((i for i in items if i["node_id"] == node), {})


def file_alerts(address: str) -> list[dict]:
    return [a for a in open_alerts(address, "config_divergence") if a["subject"] == "kea4:config-file"]


class TestReferencePair:
    def test_00_rollback_and_provision(self):
        rollback("lab-ns1", "lab-ns2", "lab-client")
        out = run_script("provision.sh", "all", timeout=1800)
        assert "HA: hot-standby" in out

    def test_01_pair_works_without_pelagos(self):
        assert ssh(A1, "/usr/sbin/kea-dhcp4 -v")[1].startswith("2.6")
        wait_for("lab-client lease", client_address, timeout=60)
        # The first lease may predate D2 or the HA sync of provisioning (no update sent): ask again
        # until an update with the md5 key lands, three attempts at most.
        for attempt in range(3):
            renew_client()
            wait_for("lab-client lease again", client_address, timeout=90)
            addr = client_address()
            try:
                for host in (A1, A2):
                    wait_for(
                        f"DDNS record on {host}",
                        lambda h=host, a=addr: dig(h, "lab-client.example.lan") == a,
                        timeout=60,
                    )
                break
            except AssertionError:
                if attempt == 2:
                    raise
        d2 = json.loads(sudo_cat(A2, "/etc/kea/kea-dhcp-ddns.conf"))["DhcpDdns"]
        assert d2["tsig-keys"][0]["algorithm"] == "HMAC-MD5"
        assert kea_command(A1, "ha-heartbeat")["arguments"]["state"] == "hot-standby"

    def test_02_install_the_deb_on_both(self):
        deb = deb_package()
        for host in (A1, A2):
            scp(host, deb, "/tmp/pelagos.deb")
            ssh(
                host,
                "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q /tmp/pelagos.deb",
                timeout=900,
            )
            assert ssh(host, "systemctl is-active pelagos-helper.socket")[1].strip() == "active"
            assert ssh(host, "stat -c '%U:%G %a' /run/pelagos-helper.sock")[1].strip() == "root:pelagos 660"

    def test_03_init_ns1_enroll_ns2(self):
        from tests.lab.labkit import ADMIN_PASSWORD

        ssh(
            A1,
            f"sudo PELAGOS_ADMIN_PASSWORD={ADMIN_PASSWORD} pelagos init --name ns1 "
            f"--web-url https://{A1}:8443 --replication-url https://{A1}:8444 "
            "&& sudo systemctl start pelagos pelagos-collector",
        )
        token = api(A1).post("/nodes/enroll-token", {})
        assert token["url"] == f"https://{A1}:8444" and token["ca_fingerprint"].startswith("sha256:")
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
        # The same admin logs in on ns2: users come from the replicated cluster.toml.
        assert api(A2).get("/nodes/self")["peer"]["name"] == "ns2"

    def test_04_import_both_configurations(self):
        for address in (A1, A2):
            plan = api(address).post("/install/import/plan", {"engines": ["bind", "kea4", "d2"]})
            assert plan["scope"] == "import" and not plan.get("error"), plan
            job = api(address).apply(plan)
            verify = next(s for s in job["steps"] if s["name"] == "import/verify")["output"]
            assert "bind.unchanged=ok" in verify and "kea4.unchanged=ok" in verify, verify
            assert "d2.unchanged=ok" in verify
        full = {"bind": True, "kea4": True, "kea6": False, "d2": True}

        def modules_everywhere() -> bool:
            # Each import publishes its node's engines in cluster.toml; replication brings them over.
            for address in (A1, A2):
                mods = {n["peer"]["name"]: n["peer"]["modules"] for n in api(address).get("/nodes")["items"]}
                if mods.get("ns1") != full or mods.get("ns2") != full:
                    return False
            return True

        wait_for("modules replicated", modules_everywhere, timeout=90)

        # Kea 2.6 from Debian answers the reads the API needs (no host_cmds, no subnet_cmds).
        # A peer's capabilities come with its next engine snapshot, a few seconds after its import.
        def servers_known() -> list | None:
            items = api(A1).get("/dhcp/v4/servers")["items"]
            return items if len(items) == 2 and all(s.get("capabilities") for s in items) else None

        servers = wait_for("Kea capabilities of both nodes", servers_known, timeout=90)
        assert {s["capabilities"]["version"][:3] for s in servers} == {"2.6"}
        subnets = api(A1).get("/dhcp/v4/subnets")["items"]
        assert [s["subnet"] for s in subnets] == ["10.99.1.0/24"]
        leases = api(A1).get("/dhcp/v4/leases")["items"]
        assert any(lease["ip_address"].startswith(DHCP_NET) for lease in leases)

        def ha_ns1() -> dict | None:
            # The import restarted Kea for the socket drop-in: the peers resynchronize first.
            ha = {h["server_name"]: h for h in api(A1).get("/dhcp/v4/ha")["items"]}
            return ha["ns1"] if ha.get("ns1", {}).get("state") == "hot-standby" else None

        assert wait_for("HA back in hot-standby", ha_ns1, timeout=180, interval=5)["mode"] == "hot-standby"
        d2 = api(A2).get("/dhcp/d2/servers")["items"]
        assert d2 and d2[0]["capabilities"]["version"].startswith("2.6")

    def test_05_security_audit_and_dual_key_switch(self):
        ids1, ids2 = node_id(A1), node_id(A2)
        findings = api(A1).get("/install/security")["findings"]
        kinds = {f["kind"] for f in findings}
        assert {"weak_shared_kea_key", "update_without_admin_key", "transfer_without_read_key"} <= kinds
        plan = api(A1).post("/install/security/plan", {"finding_ids": [f["id"] for f in findings]})
        switch = next(c for c in plan["changes"] if c["target"].endswith("/2-d2-switch"))
        assert sorted(switch["node_ids"]) == sorted([ids1, ids2])
        since = int(time.time())
        job = api(A1).apply(plan, timeout=900)
        names = [s["name"] for s in job["steps"]]
        assert "2-d2-switch/ns2" in names and names[-1].endswith("3-bind-remove")
        assert api(A1).get("/install/security")["findings"] == []
        # ns2 holds secondary copies only: its finding opens transfers to ddi-read.
        rest = api(A2).get("/install/security")["findings"]
        assert [f["kind"] for f in rest] == ["transfer_without_read_key"]
        api(A2).apply(api(A2).post("/install/security/plan", {"finding_ids": [f["id"] for f in rest]}))
        assert api(A2).get("/install/security")["findings"] == []
        # md5 is gone everywhere; both D2 sign with the sha256 key BIND accepts.
        for host in (A1, A2):
            d2 = json.loads(sudo_cat(host, "/etc/kea/kea-dhcp-ddns.conf"))["DhcpDdns"]
            assert [(k["name"], k["algorithm"].upper()) for k in d2["tsig-keys"]] == [
                ("kea-ddns-sha256", "HMAC-SHA256")
            ]
        assert "hmac-md5" not in ssh(A1, "sudo named-checkconf -p")[1]
        # A real lease renewal updates the DNS with the new key.
        renew_client()

        def ddns_ok() -> bool:
            log = ssh(A1, f"sudo journalctl -u kea-dhcp-ddns-server --since @{since} --no-pager")[1]
            return "DHCP_DDNS_ADD_SUCCEEDED" in log or "DHCP_DDNS_REMOVE_SUCCEEDED" in log

        wait_for("DDNS update signed with the new key", ddns_ok, timeout=90)
        assert "BADKEY" not in ssh(A1, f"sudo journalctl -u named --since @{since} --no-pager")[1]

    def test_06_record_through_ns2_read_on_ns1(self):
        change = {"op": "add", "target": "www/A", "after": {"ttl": 300, "rdata": ["10.99.0.80"]}}
        plan = api(A2).post("/dns/zones/example.lan/records/plan", {"changes": [change]})
        assert plan["target_node_ids"] == [node_id(A1)]  # the primary's named takes the UPDATE
        result = api(A2).apply(plan)
        assert result["state"] == "applied", result
        records = api(A1).get("/dns/zones/example.lan/records?name=www")["items"]
        assert records == [{"name": "www.example.lan.", "rtype": "A", "ttl": 300, "rdata": ["10.99.0.80"]}]
        wait_for("the secondary has www", lambda: dig(A2, "www.example.lan") == "10.99.0.80")
        audit = api(A1).get("/audit?action=dns.rrset")["items"]
        assert any(e.get("plan_id") == plan["id"] for e in audit)

    def test_07_host_joins_a_real_lease(self):
        _, mac = client_nic()
        body = {
            "hostname": "labhost",
            "ip": "10.99.1.50",
            "mac": mac,
            "zone": "example.lan",
            "reverse_zone": "1.99.10.in-addr.arpa",
            "reservation": True,
            "subnet_id": 1,
        }
        plan = api(A1).post("/hosts/plan", body)
        assert sorted(plan["target_node_ids"]) == sorted([node_id(A1), node_id(A2)])
        result = api(A1).apply(plan)
        assert result["state"] == "applied", result
        # Both Kea of the HA pair carry the reservation (config-set and config-write on Kea 2.6).
        for address in (A1, A2):
            res = api(address).get("/dhcp/v4/reservations?subnet_id=1")["items"]
            assert any(r["identifier"] == mac and r["ip_address"] == "10.99.1.50" for r in res), address
            conf = sudo_cat(address, "/etc/kea/kea-dhcp4.conf")
            assert "10.99.1.50" in conf
        # The apply reloads Kea on each node and the HA pair resynchronizes after each reload: a
        # request landing in between is answered from the old lease. Ask again until the reload
        # settled, a reservation that is never honoured still fails after the last attempt.
        for attempt in range(4):
            renew_client()
            try:
                wait_for(
                    "lab-client gets its reserved address",
                    lambda: client_address() == "10.99.1.50",
                    timeout=40,
                )
                break
            except AssertionError:
                if attempt == 3:
                    raise

        def joined() -> dict | None:
            hosts = api(A1).get("/hosts?q=labhost")["items"]
            host = hosts[0] if hosts else None
            if host and host["lease"] and host["lease"]["ip_address"] == "10.99.1.50":
                return host
            return None

        host = wait_for("the hosts view joins the lease", joined, timeout=60)
        assert host["reservation"]["identifier"] == mac
        assert {(r["name"], r["rtype"]) for r in host["records"]} >= {
            ("labhost.example.lan.", "A"),
            ("50.1.99.10.in-addr.arpa.", "PTR"),
        }

    def test_08_kea_killed_on_ns1_raises_ha_alert(self):
        settings = {"collector": {"poll_seconds": 10, "peer_poll_seconds": 10}}
        api(A1).call("PUT", "/admin/settings", settings)
        wait_for(
            "settings replicated",
            lambda: api(A2).get("/admin/settings")["collector"]["poll_seconds"] == 10,
        )
        ssh(A1, "sudo systemctl kill -s KILL kea-dhcp4-server")
        alert = wait_for(
            "HA partner-down alert on ns2",
            lambda: open_alerts(A2, "ha_partner_down"),
            timeout=180,
            interval=5,
        )
        assert alert[0]["engine"] == "kea4" and "partner-down" in alert[0]["title"]
        wait_for("kea4 down on ns1", lambda: open_alerts(A1, "daemon_down"), timeout=120, interval=5)
        ha2 = next(h for h in api(A2).get("/dhcp/v4/ha")["items"] if h["server_name"] == "ns2")
        assert ha2["state"] == "partner-down"
        # Back to normal: the primary syncs its leases from ns2 and both return to hot-standby.
        ssh(A1, "sudo systemctl start kea-dhcp4-server")
        wait_for(
            "hot-standby again",
            lambda: kea_command(A1, "ha-heartbeat")["arguments"]["state"] == "hot-standby",
            timeout=240,
            interval=5,
        )
        wait_for("HA alert resolved", lambda: not open_alerts(A2, "ha_partner_down"), timeout=180, interval=5)

    def test_09_ns2_stopped_then_catches_up(self):
        ssh(A2, "sudo systemctl stop pelagos pelagos-collector")
        wait_for("ns2 offline on ns1", lambda: open_alerts(A1, "peer_offline"), timeout=180, interval=5)
        # Writes while ns2 is away: a setting (cluster.toml) and a record (audit log).
        api(A1).call("PUT", "/admin/settings", {"alerts_pool_warning_percent": 81})
        change = {"op": "add", "target": "away/A", "after": {"ttl": 300, "rdata": ["10.99.0.81"]}}
        plan = api(A1).post("/dns/zones/example.lan/records/plan", {"changes": [change]})
        assert api(A1).apply(plan)["state"] == "applied"
        own = next(n for n in api(A1).get("/nodes")["items"] if n["is_self"])
        ssh(A2, "sudo systemctl start pelagos pelagos-collector")

        def caught_up() -> bool:
            me = next(n for n in api(A2).get("/nodes")["items"] if n["is_self"])
            return me["config_version"] >= own["config_version"] and me["audit_count"] >= own["audit_count"]

        wait_for("ns2 catches up", caught_up, timeout=180, interval=5)
        assert api(A2).get("/admin/settings")["checks"]["pool_warning_percent"] == 81
        audit = api(A2).get("/audit?action=dns.rrset")["items"]
        assert any(e.get("plan_id") == plan["id"] for e in audit)
        wait_for("peer back online", lambda: not open_alerts(A1, "peer_offline"), timeout=180, interval=5)

    def test_10_static_zone_file_edit_on_the_pair(self):
        """A static zone added by hand on ns1 (secondary on ns2): a record written through ns2 is a
        file edit on ns1, comments kept, and the secondary transfers the new serial."""
        text = STATIC_TEXT.replace("SERIAL", time.strftime("%Y%m%d01"))
        install_file(A1, STATIC_FILE, text, "bind:bind")
        primary = (
            f'zone "{STATIC_ZONE}" {{ type primary; file "{STATIC_FILE}"; '
            f"allow-transfer {{ key ddi-read; {A2}; }}; also-notify {{ {A2}; }}; notify yes; }};\n"
        )
        secondary = (
            f'zone "{STATIC_ZONE}" {{ type secondary; primaries {{ {A1}; }}; '
            f'file "/var/cache/bind/db.{STATIC_ZONE}"; }};\n'
        )
        for host, stanza in ((A1, primary), (A2, secondary)):
            ssh(host, "sudo tee -a /etc/bind/named.conf.local >/dev/null", data=stanza.encode())
            ssh(host, "sudo named-checkconf && sudo rndc reconfig")
        wait_for("the secondary loads the static zone", lambda: dig(A2, f"ns1.{STATIC_ZONE}") == A1)
        assert api(A1).get(f"/dns/zones/{STATIC_ZONE}")["mode"] == "static"

        def plan_through_ns2() -> dict | None:
            # ns2 routes the plan to the primary's node once it has seen ns1's zones.
            change = {"op": "add", "target": "www/A", "after": {"ttl": 300, "rdata": ["10.99.0.82"]}}
            plan = api(A2).post(f"/dns/zones/{STATIC_ZONE}/records/plan", {"changes": [change]})
            return plan if plan.get("target_node_ids") == [node_id(A1)] else None

        plan = wait_for("a static zone plan routed to ns1", plan_through_ns2, timeout=120, interval=10)
        result = api(A2).apply(plan)
        assert result["state"] == "applied", json.dumps(result, indent=2)
        text = sudo_cat(A1, STATIC_FILE)
        assert text.startswith(f"; {STATIC_ZONE}: written by hand") and "10.99.0.82" in text, text
        assert ssh(A1, f"sudo test -e {STATIC_FILE}.jnl", check=False)[0] != 0
        wait_for("ns2 transfers the edit", lambda: dig(A2, f"www.{STATIC_ZONE}") == "10.99.0.82", timeout=90)

    def test_11_static_zone_converted_to_dynamic(self):
        """The security audit's static_zone remediation adds an update-policy; records then go by UPDATE."""
        findings = api(A1).get("/install/security")["findings"]
        static = [f for f in findings if f["kind"] == "static_zone"]
        assert [f["subject"] for f in static] == [f"_default/{STATIC_ZONE}."], findings
        plan = api(A1).post("/install/security/plan", {"finding_ids": [static[0]["id"]]})
        api(A1).apply(plan)
        assert api(A1).get("/install/security")["findings"] == []
        assert api(A1).get(f"/dns/zones/{STATIC_ZONE}")["mode"] == "dynamic"
        change = {"op": "add", "target": "dyn/A", "after": {"ttl": 300, "rdata": ["10.99.0.83"]}}
        plan = api(A1).post(f"/dns/zones/{STATIC_ZONE}/records/plan", {"changes": [change]})
        assert "file edit" not in json.dumps(plan), plan
        assert api(A1).apply(plan)["state"] == "applied"
        wait_for("the UPDATE reaches ns2", lambda: dig(A2, f"dyn.{STATIC_ZONE}") == "10.99.0.83", timeout=90)
        assert dig(A1, f"www.{STATIC_ZONE}") == "10.99.0.82"

    def test_12_kea_file_divergence_adopted(self):
        """A hand edit of ns1's Kea file blocks the pair's plans (409 on ns2 too) until adopted;
        ns2 then adopts its own edited file, and one options plan brings both back in line."""
        old = kea_command(A1, "config-get")["arguments"]["Dhcp4"][PROBATION]
        hand_edit_kea(A1, old, old + 3600)
        wait_for("ns1 sees its file diverge", lambda: file_diverged(A1), timeout=90, interval=5)
        after = {
            "subnet_id": 1,
            "id_type": "hw-address",
            "identifier": "02:00:00:00:12:34",
            "ip_address": "10.99.1.60",
        }
        body = {"change": {"op": "add", "target": "", "after": after}}

        def blocked_on_ns2() -> bool:
            try:
                api(A2).post("/dhcp/v4/reservations/plan", body)
            except ApiError as exc:
                return exc.status == 409 and exc.body["code"] == "config_divergence"
            return False

        wait_for("the pair's plans refused from ns2", blocked_on_ns2, timeout=120, interval=10)
        plan = api(A1).post("/dhcp/v4/config/adopt/plan", {"source": "running"})
        assert plan["requires_confirmation"], plan
        assert api(A1).apply(plan)["state"] == "applied"
        text = sudo_cat(A1, KEA4_CONF)
        assert text.startswith(HAND_COMMENT), text[:200]
        assert keaconf.loads(text)["Dhcp4"][PROBATION] == old
        assert not file_diverged(A1)
        wait_for("the file alert resolved", lambda: not file_alerts(A1), timeout=120, interval=5)

        hand_edit_kea(A2, old, old + 3600)
        wait_for("ns2 sees its file diverge", lambda: file_diverged(A2), timeout=90, interval=5)
        plan = api(A2).post("/dhcp/v4/config/adopt/plan", {"source": "file"})
        assert api(A2).apply(plan)["state"] == "applied"
        assert kea_command(A2, "config-get")["arguments"]["Dhcp4"][PROBATION] == old + 3600
        assert not file_diverged(A2)
        change = {"op": "replace", "target": PROBATION, "after": old}
        plan = api(A1).post("/dhcp/v4/options/plan", {"changes": [change]})
        assert sorted(plan["target_node_ids"]) == sorted([node_id(A1), node_id(A2)]), plan
        assert api(A1).apply(plan)["state"] == "applied"
        for host in (A1, A2):
            assert kea_command(host, "config-get")["arguments"]["Dhcp4"][PROBATION] == old
            assert keaconf.loads(sudo_cat(host, KEA4_CONF))["Dhcp4"][PROBATION] == old
        wait_for(
            "no file alert left", lambda: not file_alerts(A1) and not file_alerts(A2), timeout=120, interval=5
        )
        # config-set restarts the HA service on both peers: they resynchronize first.
        wait_for(
            "hot-standby after the options plan",
            lambda: kea_command(A1, "ha-heartbeat")["arguments"]["state"] == "hot-standby",
            timeout=180,
            interval=5,
        )

    def test_12b_d2_file_of_ns2_adopted_from_ns1(self):
        """ns2's D2 file is edited by hand; ns1 sees it diverge and adopts ns2's running configuration
        through the peer write channel: ns2 builds and applies the plan, both nodes audit it."""
        ns2 = node_id(A2)
        before = keaconf.loads(sudo_cat(A2, D2_CONF))["DhcpDdns"].get(D2_TIMEOUT)
        hand_edit_d2(A2, 4321)
        wait_for(
            "ns1 sees ns2's D2 file diverge",
            lambda: d2_file_of(A1, ns2).get("diverged"),
            timeout=120,
            interval=5,
        )
        plan = api(A1).post("/dhcp/d2/config/adopt/plan", {"source": "running", "node_id": ns2})
        assert plan["target_node_ids"] == [ns2] and plan["requires_confirmation"], plan
        assert api(A1).apply(plan)["state"] == "applied"
        text = sudo_cat(A2, D2_CONF)
        assert text.startswith(HAND_COMMENT), text[:200]
        assert keaconf.loads(text)["DhcpDdns"].get(D2_TIMEOUT) != 4321
        if before is not None:
            assert keaconf.loads(text)["DhcpDdns"][D2_TIMEOUT] == before
        wait_for(
            "ns2's D2 file agrees", lambda: not d2_file_of(A1, ns2).get("diverged"), timeout=120, interval=5
        )
        ns1 = node_id(A1)
        audited = api(A2).get("/audit?per_page=50&action=d2.config")["items"]
        assert any(e["plan_id"] == plan["id"] and e["user"] == f"node:{ns1}" for e in audited), audited
        # A runtime change on ns2 from ns1: rndc runs there, both nodes audit it.
        out = api(A1).post(
            "/dns/ops", {"op": "flushname", "params": {"name": "www.example.lan"}, "node_id": ns2}
        )
        assert out["node_id"] == ns2
        ops = api(A2).get("/audit?per_page=20&action=dns.ops")["items"]
        assert any(e["user"] == f"node:{ns1}" and e["request"].get("requested_by") for e in ops), ops
        # A zone operation on ns2's secondary from ns1: retransfer runs on ns2, audited on both.
        out = api(A1).post("/dns/zones/example.lan/retransfer", {"node_id": ns2})
        assert out["node_id"] == ns2
        there = api(A2).get("/audit?per_page=50")["items"]
        mine = [e for e in there if e["user"] == f"node:{ns1}" and "retransfer" in json.dumps(e)]
        assert mine and mine[0]["result"] == "ok", there
        here = api(A1).get("/audit?per_page=20&action=dns.zone.op")["items"]
        assert any("retransfer" in json.dumps(e) for e in here), here
        wait_for("ns2 serves the zone again", lambda: dig(A2, "www.example.lan") == "10.99.0.80", timeout=60)

    def test_13_demo_state(self):
        api(A1).call(
            "PUT",
            "/admin/settings",
            {"alerts_pool_warning_percent": 80, "collector": {"poll_seconds": 60, "peer_poll_seconds": 30}},
        )
        wait_for(
            "settings replicated",
            lambda: api(A2).get("/admin/settings")["collector"]["poll_seconds"] == 60,
        )
        # A primary listed in its own NS set needs no transfer right (the collector has no netlink).
        for alert in open_alerts(A1, "delegation_issue"):
            assert not (alert["subject"].startswith("ns-transfer:") and A1 in alert["details"]["addresses"])
        # A health check alert ignored as the admin's choice resolves at once, and comes back on revoke.
        keyed = [a for a in open_alerts(A1, "insecure_key") if a["details"].get("exception_keys")]
        if keyed:
            alert = keyed[0]
            body = {"kind": "insecure_key", "key": alert["details"]["exception_keys"][0], "comment": "lab"}
            created = api(A1).call("POST", "/alerts/exceptions", body)
            gone = lambda: alert["id"] not in {a["id"] for a in open_alerts(A1, "insecure_key")}  # noqa: E731
            wait_for("excepted alert resolved", gone, timeout=60, interval=3)
            api(A1).call("DELETE", f"/alerts/exceptions/{created['id']}")
        for address in (A1, A2):
            assert api(address).get("/nodes/replication")["state"] == "ready"
            health = Api(address).get("/health")
            assert health["status"] == "ok" and health["replication"] == "ready"
