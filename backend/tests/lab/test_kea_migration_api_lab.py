# SPDX-License-Identifier: Apache-2.0
"""The Kea migration analysis API on a real Kea 2.6.3 HA pair (section 26, batch K2).

lab-k1a and lab-k1b: Debian 13 with Kea 2.6.3 from Debian in hot-standby over TLS with
`require-client-certs`, D2 with a clear `secret`, kea-ctrl-agent installed (the K1 provisioning;
snapshot `k1-ha26`). Pelagos from the deb of this checkout is installed on both, k1b enrolled.
Checked: the inventory of both nodes (Debian package, series 2.6 not maintained), the
`kea_series_obsolete` alert of each node, and a report for ISC 3.2 whose dry run really ran on both
nodes (through the helper and the peer action), with no HA asymmetry and nothing changed on the
nodes. Restore the snapshot to run it again from scratch.
"""

from __future__ import annotations

import pytest

from tests.lab.labkit import ADMIN_PASSWORD, Api, deb_package, scp, ssh, wait_for

pytestmark = pytest.mark.lab

K1A, K1B = ("lab-k1a", "10.99.0.85"), ("lab-k1b", "10.99.0.86")
STATE: dict[str, object] = {}
# What the analysis must leave as it was: Kea files, packages, apt state.
UNCHANGED = (
    'sudo sh -c \'cd / && find etc/kea etc/apt var/lib/apt/lists -type f -printf "%p %s %T@\\n" | sort;'
    " dpkg-query -W | sha256sum; systemctl is-active kea-dhcp4-server kea-dhcp-ddns-server || true'"
)


def api(address: str) -> Api:
    key = f"api:{address}"
    if key not in STATE:
        client = Api(address)
        wait_for(f"{address} login", lambda: client.login(), timeout=180)
        STATE[key] = client
    return STATE[key]  # type: ignore[return-value]


class TestKeaMigrationApi:
    def test_00_install_and_enroll(self):
        if ssh(K1A[0], "dpkg-query -W -f '${Status}' pelagos 2>/dev/null", check=False)[1].startswith(
            "install ok"
        ):
            pytest.skip("Pelagos already installed: restore snapshot k1-ha26 to start over")
        deb = deb_package()
        for host, _ in (K1A, K1B):
            scp(host, deb, "/tmp/pelagos.deb")
            ssh(
                host,
                "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q /tmp/pelagos.deb",
                timeout=900,
            )
        a, b = K1A[1], K1B[1]
        ssh(
            K1A[0],
            f"sudo PELAGOS_ADMIN_PASSWORD={ADMIN_PASSWORD} pelagos init --name k1a "
            f"--web-url https://{a}:8443 --replication-url https://{a}:8444 "
            "&& sudo systemctl start pelagos pelagos-collector",
        )
        token = api(a).post("/nodes/enroll-token", {})
        ssh(
            K1B[0],
            f"sudo pelagos enroll --url {token['url']} --token {token['token']} "
            f"--ca-fingerprint {token['ca_fingerprint']} --name k1b "
            f"--replication-url https://{b}:8444 --web-url https://{b}:8443 "
            "&& sudo systemctl start pelagos pelagos-collector",
        )

        def both_online() -> bool:
            nodes = api(a).get("/nodes")["items"]
            return len(nodes) == 2 and all(n["status"] == "online" for n in nodes)

        wait_for("both nodes online", both_online, timeout=180)
        for address in (a, b):
            job = api(address).apply(api(address).post("/install/import/plan", {"engines": ["kea4", "d2"]}))
            assert job.get("state", "done") == "done", job

    def test_01_inventory_of_both_nodes(self):
        def both() -> dict | None:
            out = api(K1A[1]).get("/install/kea-migration", timeout=180)
            return out if sum(1 for n in out["nodes"] if n.get("engines")) == 2 else None

        out = wait_for("the inventory of both nodes", both, timeout=120, interval=10)
        for node in out["nodes"]:
            assert node["reachable"], node
            kea4 = node["engines"]["kea4"]
            assert kea4["version"] == "2.6.3" and kea4["series"] == "2.6", kea4
            assert kea4["source"] == "distro" and kea4["package"] == "kea-dhcp4-server", kea4
            assert kea4["maintained"] is False and kea4["eol"] == "2026-07-30", kea4
            assert node["engines"]["d2"]["series"] == "2.6"
            assert node["distro"] == {"id": "debian", "codename": "trixie"}
        by = {(t["series"], t["source"]): t for t in out["targets"]}
        assert by[("3.2", "isc")]["available"] and by[("3.2", "isc")]["recommended"]
        assert by[("3.0", "backports")]["available"]

    def test_02_series_alert_on_each_node(self):
        def alerts() -> list | None:
            items = api(K1A[1]).get("/alerts?state=open&kind=kea_series_obsolete&per_page=50")["items"]
            return items if len({a["node_id"] for a in items}) == 2 else None

        found = wait_for("kea_series_obsolete on both nodes", alerts, timeout=300, interval=10)
        for alert in found:
            assert alert["subject"] == "kea:series" and alert["severity"] == "info"
            d = alert["details"]
            assert (d["series"], d["source"], d["eol"], d["successor"]) == (
                "2.6",
                "distro",
                "2026-07-30",
                "3.2",
            )

    def test_03_analysis_for_isc_3_2(self):
        before = {h: ssh(h, UNCHANGED)[1] for h, _ in (K1A, K1B)}
        report = api(K1A[1]).post(
            "/install/kea-migration/analyze", {"series": "3.2", "source": "isc"}, timeout=1200
        )
        ids = {n["peer"]["id"] for n in api(K1A[1]).get("/nodes")["items"]}
        assert set(report["node_ids"]) == ids and report["unreachable"] == []
        assert report["target_version"].startswith("3.2."), report["target_version"]
        for node_id in ids:
            for engine in ("kea4", "d2"):
                result = report["validation"][node_id][engine]
                assert result["mode"] == "dry_run" and result["ok"], (node_id, engine, result)
            removed = {p["name"] for p in report["packages"][node_id]["remove"]}
            assert {"kea-dhcp4-server", "kea-common"} <= removed, removed
            installed = {p["name"] for p in report["packages"][node_id]["install"]}
            assert {"isc-kea-dhcp4", "isc-kea-hooks"} <= installed, installed
        codes = {(f["code"], f["node_id"]) for f in report["findings"]}
        assert not [c for c in codes if c[0] == "ha_asymmetric"], report["findings"]
        assert {("d2_secret_file", n) for n in ids} <= codes, codes
        assert {("restrict_commands", n) for n in ids} <= codes, codes
        assert all("*****" in report["diffs"][n]["d2"] for n in ids)
        assert report["outage_estimate_seconds"] > 0
        kept = api(K1A[1]).get("/install/kea-migration", timeout=180)["analysis"]
        assert kept["id"] == report["id"]
        audit = api(K1A[1]).get("/audit?action=kea.migration.analyze&per_page=5")["items"]
        assert audit and audit[0]["target"] == f"kea-migration:{report['id']}"
        for host, _ in (K1A, K1B):
            assert ssh(host, UNCHANGED)[1] == before[host], host
            assert not ssh(host, "sudo ls -d /tmp/pelagos-kea-dry-run-* 2>/dev/null", check=False)[1].strip()
