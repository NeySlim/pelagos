# SPDX-License-Identifier: Apache-2.0
"""The production setup on the lab: a Kea 2.6.3 HA pair from the Debian 13 packages (no host_cmds,
no subnet_cmds) with BIND 9.20 from Debian, reservations written by hand in an order Kea does not
keep, a kea-dhcp6 package installed but disabled, then Pelagos from the deb of this checkout.

Checked: the import leaves kea6 out, the security audit, a reservation written through config-set
on both peers, no divergence alert while file and peers only differ in order or spelling, a
reservation that differs on one peer named in the alert, the external change audit entries, a
hook compiled by hand detected, and a real `terminated` (one clock 90 s ahead) brought back to
hot-standby by the "Repair HA" plan. The VMs are rolled back first; the pair is left running.
"""

from __future__ import annotations

import json
import os
import re
import time

import pytest

from pelagos.installer import keaconf
from tests.lab.labkit import (
    ADMIN_PASSWORD,
    NS1,
    NS2,
    Api,
    ApiError,
    deb_package,
    fixable,
    left,
    rollback,
    run_script,
    scp,
    ssh,
    sudo_cat,
    wait_for,
)

pytestmark = pytest.mark.lab

A1, A2 = NS1[1], NS2[1]
KEA4_CONF = "/etc/kea/kea-dhcp4.conf"
SOCKET = "/run/kea/kea4-ctrl-socket"
STATE: dict[str, object] = {}
# Reservations as an administrator wrote them: an order and spellings config-get does not keep
# (Kea 2.6 lists client-id reservations first, then by hw-address, and prints a client-id as
# plain hex).
SEEDED = [
    {"hostname": "printer", "hw-address": "02:00:00:00:00:30", "ip-address": "10.99.1.30"},
    {"hostname": "nas", "hw-address": "02:00:00:00:00:10", "ip-address": "10.99.1.10"},
    {"hostname": "tv", "client-id": "01:02:00:00:00:00:40", "ip-address": "10.99.1.40"},
    {"hostname": "camera", "hw-address": "02:00:00:00:00:20", "ip-address": "10.99.1.20"},
]
CUSTOM_HOOK = "libkea_sanitize_hostname.so"
# A hook built from source, as the one found in production: it loads and does nothing.
HOOK_SOURCE = r"""
#include <hooks/hooks.h>
extern "C" {
int version() { return KEA_HOOKS_VERSION; }
int load(isc::hooks::LibraryHandle&) { return 0; }
int unload() { return 0; }
int multi_threading_compatible() { return 1; }
}
"""
SKEW = 90
# BIND as in production (empty: the current Debian 13 one). Served by snapshot.debian.org, from the
# debian-security snapshot where it appeared (2026-07-22, checked on 2026-10-26).
BIND_VERSION = os.environ.get("PELAGOS_LAB_BIND_VERSION", "1:9.20.26-1~deb13u1")
BIND_SNAPSHOT = os.environ.get(
    "PELAGOS_LAB_BIND_SNAPSHOT", "https://snapshot.debian.org/archive/debian-security/20260722T215339Z"
)
BIND_PACKAGES = ("bind9", "bind9-utils", "bind9-dnsutils", "bind9-host", "bind9-libs")


def pin_bind(host: str) -> None:
    """Puts BIND_VERSION in place of the provisioned bind9 (held), configuration kept."""
    if not BIND_VERSION:
        return
    source = f"deb [check-valid-until=no] {BIND_SNAPSHOT} trixie-security main"
    wanted = " ".join(f"{p}={BIND_VERSION}" for p in BIND_PACKAGES)
    ssh(
        host,
        f"echo '{source}' | sudo tee /etc/apt/sources.list.d/bind-snapshot.list >/dev/null"
        " && sudo apt-get update -q >/dev/null"
        " && sudo DEBIAN_FRONTEND=noninteractive"
        f" apt-get install -y -q --allow-downgrades {wanted} >/dev/null"
        f" && sudo apt-mark hold {' '.join(BIND_PACKAGES)} >/dev/null"
        " && sudo systemctl restart named && sleep 2 && sudo rndc status >/dev/null",
        timeout=900,
    )


def api(address: str) -> Api:
    key = f"api:{address}"
    if key not in STATE:
        client = Api(address)
        wait_for(f"{address} login", lambda: client.login(), timeout=120)
        STATE[key] = client
    return STATE[key]  # type: ignore[return-value]


def node_id(address: str) -> str:
    key = f"id:{address}"
    if key not in STATE:
        STATE[key] = api(address).get("/nodes/self")["peer"]["id"]
    return STATE[key]  # type: ignore[return-value]


def kea(host: str, command: str) -> dict:
    out = ssh(host, f"echo '{json.dumps({'command': command})}' | sudo socat - UNIX-CONNECT:{SOCKET}")[1]
    return json.loads(out)


def ha_local(host: str) -> dict:
    entry = kea(host, "status-get")["arguments"]["high-availability"][0]["ha-servers"]
    return {"state": entry["local"]["state"], "partner": entry["remote"].get("last-state")}


def reservations(config: dict) -> list[dict]:
    return config["Dhcp4"]["subnet4"][0].get("reservations") or []


def edit_kea_file(host: str, edit, reload: bool = True) -> None:
    """Rewrites the Kea file as an administrator would (owner and mode kept), then config-reload."""
    cfg = keaconf.loads(sudo_cat(host, KEA4_CONF))
    edit(cfg)
    ssh(host, f"sudo tee {KEA4_CONF} >/dev/null", data=json.dumps(cfg, indent=2).encode())
    ssh(host, f"sudo runuser -u _kea -- kea-dhcp4 -t {KEA4_CONF} >/dev/null")
    if reload:
        assert kea(host, "config-reload")["result"] == 0


def open_alerts(address: str, kind: str) -> list[dict]:
    return api(address).get(f"/alerts?state=open&kind={kind}&per_page=200")["items"]


def peer_divergence(address: str) -> list[dict]:
    return [a for a in open_alerts(address, "config_divergence") if a["subject"] == "kea4:config-hash"]


def file_divergence(address: str) -> list[dict]:
    return [a for a in open_alerts(address, "config_divergence") if a["subject"] == "kea4:config-file"]


def difference_items(alert: dict) -> list[str]:
    return [
        item
        for rel in alert["details"].get("relationships") or []
        for diff in rel.get("differences") or []
        for item in diff.get("items") or []
    ]


def external_changes(address: str, since: str) -> list[dict]:
    items = api(address).get("/audit?per_page=50&action=external.change")["items"]
    return [e for e in items if e["ts"] >= since]


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())


def quiet_for(seconds: float, *checks) -> None:
    """Each check stays false for `seconds` (longer than the divergence grace and a few polls)."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        for check in checks:
            found = check()
            assert not found, found
        time.sleep(10)


def both_hot_standby() -> bool:
    return all(ha_local(h) == {"state": "hot-standby", "partner": "hot-standby"} for h in (A1, A2))


class TestKea26DebianPair:
    def test_00_rollback_and_provision(self):
        rollback("lab-ns1", "lab-ns2", "lab-client")
        out = run_script("provision.sh", "all", timeout=1800)
        assert "HA: hot-standby" in out
        for host in (A1, A2):
            pin_bind(host)
            # Hand-written reservations, the same on both peers.
            edit_kea_file(host, lambda cfg: cfg["Dhcp4"]["subnet4"][0].update(reservations=SEEDED))
            # Production had the kea-dhcp6 package with its default file, never started.
            ssh(
                host,
                "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q kea-dhcp6-server >/dev/null"
                " && sudo systemctl disable --now -q kea-dhcp6-server",
                timeout=900,
            )
        wait_for("HA back in hot-standby", both_hot_standby, timeout=180, interval=5)

    def test_01_production_versions(self):
        for host in (A1, A2):
            versions = ssh(host, "dpkg-query -W -f '${Package} ${Version}\\n' kea-dhcp4-server bind9")[1]
            got = dict(line.split() for line in versions.splitlines())
            assert re.fullmatch(r"2\.6\.3-\d+\+deb13u\d+", got["kea-dhcp4-server"]), got
            assert re.fullmatch(r"1:9\.20\.\d+-\d+~deb13u\d+", got["bind9"]), got
            assert not BIND_VERSION or got["bind9"] == BIND_VERSION, got
            assert ssh(host, "/usr/sbin/named -v")[1].startswith("BIND 9.20.")
            assert ssh(host, "/usr/sbin/kea-dhcp4 -v")[1].strip() == "2.6.3"
        # config-get keeps neither the order nor the spelling of the file.
        running = [r["hostname"] for r in reservations(kea(A1, "config-get")["arguments"])]
        assert running != [r["hostname"] for r in SEEDED] and sorted(running) == sorted(
            r["hostname"] for r in SEEDED
        )
        tv = next(r for r in reservations(kea(A1, "config-get")["arguments"]) if r["hostname"] == "tv")
        assert tv["client-id"] == "01020000000040"

    def test_02_install_init_enroll(self):
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

    def test_03_import_leaves_the_idle_kea6_out(self):
        for address in (A1, A2):
            engines = api(address).get("/install/detect")["engines"]
            kea6 = engines["kea6"]
            assert kea6["installed"] and kea6["config_exists"], kea6
            assert not kea6["running"] and not kea6["enabled"], kea6
            # What the import screen and `pelagos import` select: running or enabled daemons.
            chosen = [e for e, d in engines.items() if d["installed"] and (d["running"] or d["enabled"])]
            assert sorted(chosen) == ["bind", "d2", "kea4"], chosen
            job = api(address).apply(api(address).post("/install/import/plan", {"engines": chosen}))
            verify = next(s for s in job["steps"] if s["name"] == "import/verify")["output"]
            assert "kea4.unchanged=ok" in verify, verify

        def servers_known() -> list | None:
            items = api(A1).get("/dhcp/v4/servers")["items"]
            return items if len(items) == 2 and all(s.get("capabilities") for s in items) else None

        servers = wait_for("Kea capabilities of both nodes", servers_known, timeout=120)
        assert {s["capabilities"]["version"] for s in servers} == {"2.6.3"}
        wait_for("HA back in hot-standby", both_hot_standby, timeout=180, interval=5)

    def test_04_security_audit(self):
        findings = api(A1).get("/install/security")["findings"]
        kinds = {f["kind"] for f in findings}
        assert {"weak_shared_kea_key", "update_without_admin_key"} <= kinds, kinds
        api(A1).apply(api(A1).post("/install/security/plan", {"finding_ids": fixable(findings)}), 900)
        assert left(api(A1).get("/install/security")["findings"]) == []
        rest = fixable(api(A2).get("/install/security")["findings"])
        if rest:
            api(A2).apply(api(A2).post("/install/security/plan", {"finding_ids": rest}))
        assert left(api(A2).get("/install/security")["findings"]) == []
        wait_for("HA back in hot-standby", both_hot_standby, timeout=180, interval=5)

    def test_05_reordered_reservations_raise_nothing(self):
        for address in (A1, A2):
            mine = next(
                i
                for i in api(address).get("/dhcp/v4/config/file")["items"]
                if i["node_id"] == node_id(address)
            )
            assert not mine["diverged"], mine
        quiet_for(
            150,
            lambda: file_divergence(A1),
            lambda: file_divergence(A2),
            lambda: peer_divergence(A1),
            lambda: open_alerts(A1, "reservation_risk"),
        )

    def test_06_reservation_through_config_set(self):
        body = {
            "change": {
                "op": "add",
                "target": "",
                "after": {
                    "subnet_id": 1,
                    "id_type": "hw-address",
                    "identifier": "02:00:00:00:00:50",
                    "ip_address": "10.99.1.50",
                    "hostname": "kiosk",
                },
            }
        }
        plan = api(A1).post("/dhcp/v4/reservations/plan", body)
        assert sorted(plan["target_node_ids"]) == sorted([node_id(A1), node_id(A2)]), plan
        result = api(A1).apply(plan)
        assert result["state"] == "applied", result
        for host in (A1, A2):
            caps = kea(host, "list-commands")["arguments"]
            assert "reservation-add" not in caps and "config-set" in caps  # no host_cmds on Debian
            running = reservations(kea(host, "config-get")["arguments"])
            assert any(r["hw-address"] == "02:00:00:00:00:50" for r in running if "hw-address" in r)
            written = reservations(keaconf.loads(sudo_cat(host, KEA4_CONF)))
            # A file without includes is persisted by config-write: Kea's own dump, in its order.
            assert [r["hostname"] for r in written] == [r["hostname"] for r in running], written
            assert sorted(r["hostname"] for r in written) == sorted(
                [*(r["hostname"] for r in SEEDED), "kiosk"]
            )
        wait_for("HA back in hot-standby", both_hot_standby, timeout=180, interval=5)
        quiet_for(150, lambda: file_divergence(A1), lambda: file_divergence(A2), lambda: peer_divergence(A1))

    def test_07_a_reservation_that_differs_on_one_peer_is_named(self):
        since = now_iso()

        def other_mac(cfg: dict) -> None:
            for r in reservations(cfg):
                if r["hostname"] == "camera":
                    r["hw-address"] = "02:00:00:00:00:21"

        edit_kea_file(A2, other_mac)
        alert = wait_for("peer divergence on ns1", lambda: peer_divergence(A1), timeout=300, interval=10)[0]
        items = difference_items(alert)
        assert any("hw-address=02:00:00:00:00:20" in i and "camera" in i for i in items), items
        assert any("hw-address=02:00:00:00:00:21" in i and "camera" in i for i in items), items
        assert len(items) == 2, items
        entry = wait_for("external change audited", lambda: external_changes(A2, since), timeout=180)[0]
        assert entry["node_id"] == node_id(A2) and entry["target"] == "kea4:config", entry
        assert "02:00:00:00:00:21" in entry["diff"] and "camera" in entry["diff"], entry
        # The audit log replicates: ns1 shows it too.
        wait_for("external change on ns1", lambda: external_changes(A1, since), timeout=120)
        assert not file_divergence(A2)  # the file and the running configuration agree

        def back(cfg: dict) -> None:
            for r in reservations(cfg):
                if r["hostname"] == "camera":
                    r["hw-address"] = "02:00:00:00:00:20"

        edit_kea_file(A2, back)
        wait_for("peer divergence resolved", lambda: not peer_divergence(A1), timeout=180, interval=10)
        wait_for("HA back in hot-standby", both_hot_standby, timeout=180, interval=5)

    def test_08_a_hook_built_by_hand_is_detected(self):
        since = now_iso()
        ssh(
            A1,
            "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends "
            "g++ kea-dev libboost-dev >/dev/null",
            timeout=900,
        )
        hooks = ssh(A1, "/usr/sbin/kea-dhcp4 -W | sed -n 's/.*Hooks directory: *//p'")[1].strip()
        library = f"{hooks}/{CUSTOM_HOOK}"
        ssh(
            A1,
            f"cat > /tmp/sanitize.cc && sudo g++ -std=c++17 -shared -fPIC -I/usr/include/kea "
            f"-o {library} /tmp/sanitize.cc -lkea-hooks",
            data=HOOK_SOURCE.encode(),
        )
        assert ssh(A1, f"dpkg -S {library}", check=False)[0] != 0
        edit_kea_file(A1, lambda cfg: cfg["Dhcp4"]["hooks-libraries"].append({"library": library}))
        loaded = kea(A1, "config-get")["arguments"]["Dhcp4"]["hooks-libraries"]
        assert any(h["library"] == library for h in loaded)
        alert = wait_for(
            "custom_hook on ns1", lambda: open_alerts(A1, "custom_hook"), timeout=180, interval=10
        )[0]
        assert alert["node_id"] == node_id(A1) and CUSTOM_HOOK in alert["title"], alert
        assert "hostname-char" in json.dumps(alert), alert
        divergence = wait_for("hook divergence", lambda: peer_divergence(A1), timeout=300, interval=10)[0]
        assert any(CUSTOM_HOOK in i for i in difference_items(divergence)), divergence
        entry = wait_for("external change audited", lambda: external_changes(A1, since), timeout=180)[0]
        assert CUSTOM_HOOK in entry["diff"], entry

        def drop(cfg: dict) -> None:
            libs = cfg["Dhcp4"]["hooks-libraries"]
            libs[:] = [h for h in libs if CUSTOM_HOOK not in h["library"]]

        edit_kea_file(A1, drop)
        wait_for("custom_hook resolved", lambda: not open_alerts(A1, "custom_hook"), timeout=180, interval=10)
        wait_for("peer divergence resolved", lambda: not peer_divergence(A1), timeout=180, interval=10)
        wait_for("HA back in hot-standby", both_hot_standby, timeout=180, interval=5)

    def test_09_terminated_by_a_clock_skew_then_repaired(self):
        ns1, ns2 = node_id(A1), node_id(A2)
        ssh(A2, f"sudo timedatectl set-ntp false && sudo date -s @$(( $(date +%s) + {SKEW} )) >/dev/null")
        wait_for(
            "both servers terminated",
            lambda: all(ha_local(h)["state"] == "terminated" for h in (A1, A2)),
            timeout=120,
            interval=5,
        )
        log = ssh(A1, "sudo journalctl -u kea-dhcp4-server --since -5min --no-pager")[1]
        assert "HA_HIGH_CLOCK_SKEW_CAUSED_TERMINATION" in log
        # Kea 2.6.3 reports no clock-skew: the cause comes from the node clocks Pelagos measures.
        assert "clock-skew" not in json.dumps(kea(A1, "status-get"))

        def terminated(address: str, text: str) -> dict | None:
            found = [a for a in open_alerts(address, "ha_terminated") if text in a["title"]]
            return found[0] if found else None

        skewed = "clock of node ns2 is"
        alert1 = wait_for("ha_terminated on ns1", lambda: terminated(A1, skewed), timeout=180, interval=5)
        alert2 = wait_for("ha_terminated on ns2", lambda: terminated(A2, skewed), timeout=180, interval=5)
        assert alert1["details"]["cause"] == alert2["details"]["cause"] == "clock_skew"
        skew = wait_for("clock_skew on ns1", lambda: open_alerts(A1, "clock_skew"), timeout=120)[0]
        assert skew["node_id"] == ns2 and skew["severity"] == "critical", skew
        # The repair refuses while the clocks disagree: a restart would terminate again.
        with pytest.raises(ApiError) as refused:
            api(A1).post("/dhcp/v4/ha/repair/plan", {})
        assert refused.value.status == 422 and "synchronize the clocks" in json.dumps(refused.value.body)

        ssh(A2, f"sudo date -s @{int(time.time())} >/dev/null && sudo timedatectl set-ntp true")
        wait_for(
            "ns2 synchronized",
            lambda: ssh(A2, "timedatectl show -p NTPSynchronized --value")[1].strip() == "yes",
            timeout=120,
        )
        fixed = "the clocks agree now"
        wait_for("cause marked fixed on ns1", lambda: terminated(A1, fixed), timeout=180, interval=5)
        wait_for("cause marked fixed on ns2", lambda: terminated(A2, fixed), timeout=180, interval=5)
        assert all(ha_local(h)["state"] == "terminated" for h in (A1, A2))  # Kea does not recover alone

        plan = api(A1).post("/dhcp/v4/ha/repair/plan", {})
        assert plan["state"] == "validated" and plan["requires_confirmation"], plan
        assert plan["target_node_ids"] == [ns2, ns1], plan  # the standby first, the primary last
        assert all(v["ok"] for v in plan["validations"]), plan["validations"]
        result = api(A1).apply(plan)
        assert result["state"] == "applied", result
        messages = {r["node_id"]: r["message"] for r in result["results"]}
        assert "restarted (config-reload)" in messages[ns2] and "restarted (config-reload)" in messages[ns1]
        assert "hot-standby with ns2" in messages[ns1], messages
        wait_for("both in hot-standby", both_hot_standby, timeout=60, interval=5)
        for address in (A1, A2):
            wait_for(
                f"ha_terminated resolved on {address}",
                lambda a=address: not open_alerts(a, "ha_terminated"),
                timeout=180,
                interval=5,
            )
        wait_for("clock_skew resolved", lambda: not open_alerts(A1, "clock_skew"), timeout=120, interval=5)
        audit = api(A1).get("/audit?per_page=50")["items"]
        assert any(e.get("plan_id") == plan["id"] for e in audit), audit[:5]

    def test_10_demo_state(self):
        api(A1).call("PUT", "/admin/settings", {"collector": {"poll_seconds": 60, "peer_poll_seconds": 30}})
        wait_for(
            "settings replicated", lambda: api(A2).get("/admin/settings")["collector"]["poll_seconds"] == 60
        )
        assert both_hot_standby()
