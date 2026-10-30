# SPDX-License-Identifier: Apache-2.0
"""Prepare phase of the Kea migration on a real Kea 2.6.3 HA pair (section 28, batch K3).

lab-k1a and lab-k1b from snapshot `k1-ha26` (Debian 13, Kea 2.6.3 from Debian in hot-standby over
TLS, D2 with a clear `secret`). Pelagos from the deb of this checkout is installed on both, k1b
enrolled (test_00 does it when it is not there yet). Checked: the plan from an ISC 3.2 analysis,
the record written and replicated, the archive of each node, the target packages in apt's cache,
the exact 2.6 packages kept, the 2.6 and 3.x files under the migration directory with its private
part root's, `/etc/kea`, the installed packages and the running services unchanged; a second
prepare from a new analysis replaces the first. Restore the snapshot to run it again from scratch.
"""

from __future__ import annotations

import json

import pytest

from tests.lab import test_kea_migration_api_lab as k1
from tests.lab.labkit import ADMIN_PASSWORD, ssh, wait_for
from tests.lab.test_kea_migration_api_lab import K1A, K1B, api

pytestmark = pytest.mark.lab

STATE: dict[str, object] = {}
# What the prepare must leave as it was: Kea files, installed packages, running services.
UNCHANGED = (
    'sudo sh -c \'cd / && find etc/kea -printf "%p %s %m %u %g %T@\\n" | sort;'
    " dpkg-query -W | sha256sum; systemctl is-active kea-dhcp4-server kea-dhcp-ddns-server || true'"
)


def mdir(migration_id: str) -> str:
    """Root's state of the migration, outside the tree the service user owns."""
    return f"/var/lib/pelagos-helper/kea-migration/{migration_id}"


class TestKeaMigrationPrepare:
    def test_00_install_enroll_and_archive_key(self):
        installed = ssh(K1A[0], "dpkg-query -W -f '${Status}' pelagos 2>/dev/null", check=False)[1]
        if not installed.startswith("install ok"):
            k1.TestKeaMigrationApi.test_00_install_and_enroll(k1.TestKeaMigrationApi())
        out = api(K1A[1]).get("/admin/archives")
        if not any(r.get("kind") == "cluster" for r in out.get("recipients") or []):
            api(K1A[1]).post("/admin/archives/identity", {"op": "generate", "password": ADMIN_PASSWORD})

    def test_01_prepare_isc_3_2(self):
        before = {h: ssh(h, UNCHANGED)[1] for h, _ in (K1A, K1B)}

        def analysis() -> dict | None:
            # Right after the enrollment the peer's Kea modules may not have replicated yet.
            out = api(K1A[1]).post(
                "/install/kea-migration/analyze", {"series": "3.2", "source": "isc"}, timeout=1200
            )
            return out if len(out["roles"]) == 2 else None

        report = wait_for("an analysis of both nodes", analysis, timeout=900, interval=30)
        assert not report["blocking"], [f for f in report["findings"] if f["severity"] == "blocking"]
        roles = sorted(report["roles"].values())
        assert roles == ["primary", "standby"], report["roles"]
        plan = api(K1A[1]).post(f"/install/kea-migration/{report['id']}/plan", {"phase": "prepare"})
        assert plan["scope"] == "kea.migration" and plan["requires_confirmation"]
        steps = [c["after"]["step"] for c in plan["changes"]]
        assert steps == ["kea-mig-archive"] * 2 + ["kea-mig-prepare"] * 2, steps
        job = api(K1A[1]).apply(plan, timeout=1800)
        assert job["state"] == "done", job
        STATE["id"] = report["id"]
        mig = api(K1A[1]).get(f"/install/kea-migration/{report['id']}")
        assert mig["state"] == "prepared" and mig["phase"] == "prepare", mig
        assert mig["rollback_possible"] is False  # only once the migrate phase runs
        for node in mig["nodes"]:
            assert node["status"] == "done" and node["rollback_ready"], node
            assert node["archive_id"] and node["from_version"] == "2.6.3", node
        assert [n["role"] for n in mig["nodes"]] == ["standby", "primary"]
        # Replicated: the other node shows the same record.
        other = wait_for(
            "the record on k1b",
            lambda: (
                (m := api(K1B[1]).get("/install/kea-migration", timeout=180)["current"])
                and m["state"] == "prepared"
                and m
            ),
            timeout=120,
            interval=5,
        )
        assert other["id"] == report["id"]
        for host, _ in (K1A, K1B):
            assert ssh(host, UNCHANGED)[1] == before[host], host
        audit = api(K1A[1]).get("/audit?action=kea.migration.step&per_page=50")["items"]
        audit = [a for a in audit if a["target"] == f"kea-migration:{report['id']}"]
        assert len(audit) == 4 and all(a["result"] == "ok" for a in audit), audit

    def test_02_files_and_packages_on_each_node(self):
        d = mdir(str(STATE["id"]))
        for host, _ in (K1A, K1B):
            manifest = json.loads(ssh(host, f"sudo cat {d}/manifest.json")[1])
            assert manifest["series"] == "3.2" and manifest["target_version"].startswith("3.2.")
            assert manifest["validation"] == {"kea4": "dry_run", "d2": "dry_run"}, manifest["validation"]
            perms = ssh(host, f"sudo stat -c '%a %U' {d} {d}/private {d}/packages/target")[1].split()
            assert perms == ["700", "root", "700", "root", "700", "root"], perms
            files = ssh(host, f"sudo ls {d}/private/before {d}/private/target")[1]
            assert "kea-dhcp4.conf" in files and "secret-0.tsig" in files, files
            d2 = json.loads(ssh(host, f"sudo cat {d}/private/target/kea-dhcp-ddns.conf")[1])
            assert all("secret" not in k for k in d2["DhcpDdns"]["tsig-keys"])
            # The exact 2.6 packages kept as files; the target ones in root's cache, none installed.
            names = {p["name"]: p["version"] for p in manifest["packages_before"]}
            assert names.get("kea-dhcp4-server", "").startswith("2.6.3"), names
            for p in manifest["packages_before"]:
                ssh(host, f"sudo test -s {d}/packages/previous/{p['file']}")
            for p in manifest["packages_target"]:
                ssh(host, f"sudo test -s {d}/packages/target/{p['file']}")
            assert {p["name"] for p in manifest["packages_target"]} >= {"isc-kea-dhcp4", "isc-kea-hooks"}
            installed = ssh(
                host, "dpkg-query -W -f '${Package} ${Status}\\n' 'isc-kea*' 2>/dev/null", check=False
            )[1]
            assert "install ok installed" not in installed, installed
            # The ISC repository is configured, apt can install offline from its cache.
            assert (
                ssh(host, "test -f /etc/apt/sources.list.d/isc-kea-3-2.list && echo yes")[1].strip() == "yes"
            )
            wanted = " ".join(f"{p['name']}={p['version']}" for p in manifest["packages_target"])
            cache = f"-o Dir::Cache::archives={d}/packages/target/"
            uris = ssh(host, f"sudo apt-get install {cache} --print-uris -qq {wanted}")[1]
            assert ".deb" not in uris, uris  # everything the install needs is in the cache

    def test_03_prepare_again_replaces_the_record(self):
        report = api(K1A[1]).post(
            "/install/kea-migration/analyze", {"series": "3.2", "source": "isc"}, timeout=1200
        )
        plan = api(K1A[1]).post(f"/install/kea-migration/{report['id']}/plan", {"phase": "prepare"})
        job = api(K1A[1]).apply(plan, timeout=1800)
        assert job["state"] == "done", job
        current = api(K1A[1]).get("/install/kea-migration")["current"]
        assert current["id"] == report["id"] and current["state"] == "prepared"
        # The migrate plan of the new record builds (time 1 runs in test_kea_migration_time1_lab).
        plan = api(K1A[1]).post(f"/install/kea-migration/{report['id']}/plan", {"phase": "migrate"})
        assert plan["changes"][0]["after"]["step"] == "kea-mig-ha-maintenance"
