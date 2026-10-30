# SPDX-License-Identifier: Apache-2.0
"""Time 1 of the Kea migration and its return on a real Kea 2.6.3 HA pair (section 28, batch K4).

lab-k1a (primary) and lab-k1b (standby) from snapshot `k1-ha26`, Pelagos from this checkout
(test_00 of the prepare test installs and enrolls it). Checked: a time 1 that fails after the ISC
packages went in (a converted file changed behind the prepare) returns the standby to the exact 2.6
packages and files by itself; a clean time 1 leaves the standby stopped on ISC 3.2 with its files
checked by the installed daemons, the primary serving alone, the primary's files accepted by the
standby's 3.x daemons; the manual return then puts the pair back in hot-standby with every Kea file,
package and service as before. Restore the snapshot to run it again from scratch.
"""

from __future__ import annotations

import json
import time

import pytest

from tests.lab import test_kea_migration_prepare_lab as k3
from tests.lab.labkit import deb_package, scp, ssh, wait_for
from tests.lab.test_kea_migration_api_lab import K1A, K1B, api

pytestmark = pytest.mark.lab

PRIMARY, STANDBY = K1A, K1B
# What the return must give back exactly: the Kea files (content, owner, mode), the installed
# packages and the services; mtimes change, nothing else may. The ISC packages stay known to dpkg
# as removed ("rc"): purging isc-kea-common would delete /etc/kea and /var/lib/kea.
KEA_STATE = (
    'sudo sh -c \'cd / && find etc/kea -printf "%p %y %m %u %g %l\\n" | sort;'
    " find etc/kea -type f -exec sha256sum {} + | sort;"
    ' dpkg-query -W -f "\\${db:Status-Abbrev} \\${Package} \\${Version}\\n" "kea*"'
    ' "isc-kea*" 2>/dev/null | grep ^ii; systemctl is-active kea-dhcp4-server kea-dhcp-ddns-server || true;'
    " ls /etc/apparmor.d/disable 2>/dev/null; dpkg-statoverride --list | sort'"
)
STATUS = (
    "sudo python3 -c 'import json,socket;s=socket.socket(socket.AF_UNIX);"
    's.connect("/run/kea/kea4-ctrl-socket");s.sendall(b"{\\"command\\": \\"status-get\\"}");'
    'b=b""\nwhile True:\n c=s.recv(65536)\n if not c: break\n b+=c\nprint(b.decode())\''
)


def ha_state(host: str) -> str:
    out = json.loads(ssh(host, STATUS)[1])
    return out["arguments"]["high-availability"][0]["ha-servers"]["local"]["state"]


def prepared() -> str:
    report = api(PRIMARY[1]).post(
        "/install/kea-migration/analyze", {"series": "3.2", "source": "isc"}, timeout=1200
    )
    assert not report["blocking"], report["findings"]
    plan = api(PRIMARY[1]).post(f"/install/kea-migration/{report['id']}/plan", {"phase": "prepare"})
    api(PRIMARY[1]).apply(plan, timeout=1800)
    mig = api(PRIMARY[1]).get(f"/install/kea-migration/{report['id']}")
    assert mig["state"] == "prepared", mig
    return report["id"]


def run_job(plan: dict, timeout: float = 1800) -> dict:
    out = api(PRIMARY[1]).post(f"/plans/{plan['id']}/apply", {"confirm": True}, timeout=timeout)
    job_id = out["id"]

    def done() -> dict | None:
        job = api(PRIMARY[1]).get(f"/jobs/{job_id}")
        return job if job["state"] in ("done", "failed") else None

    return wait_for(f"job {job_id}", done, timeout=timeout, interval=3)


def pair_back() -> None:
    wait_for(
        "the pair in hot-standby",
        lambda: ha_state(PRIMARY[0]) == "hot-standby" and ha_state(STANDBY[0]) == "hot-standby",
        timeout=300,
        interval=5,
    )


class TestKeaMigrationTime1:
    def test_00_install_enroll_and_archive_key(self):
        installed = ssh(PRIMARY[0], "dpkg-query -W -f '${Status}' pelagos 2>/dev/null", check=False)[1]
        if installed.startswith("install ok"):
            # Pelagos from an earlier run: this checkout's package over it.
            deb = deb_package()
            for host, _ in (PRIMARY, STANDBY):
                scp(host, deb, "/tmp/pelagos.deb")
                ssh(host, "sudo dpkg -i /tmp/pelagos.deb && sudo systemctl restart pelagos pelagos-collector")
        k3.TestKeaMigrationPrepare.test_00_install_enroll_and_archive_key(k3.TestKeaMigrationPrepare())
        pair_back()

    def test_01_failed_time_1_returns_by_itself(self):
        before = {h: ssh(h, KEA_STATE)[1] for h, _ in (PRIMARY, STANDBY)}
        mid = prepared()
        # A converted file changed behind the prepare: refused after the packages went in.
        ssh(STANDBY[0], f"sudo sh -c 'echo >> {k3.mdir(mid)}/private/target/kea-dhcp4.conf'")
        plan = api(PRIMARY[1]).post(f"/install/kea-migration/{mid}/plan", {"phase": "migrate"})
        assert [c["after"]["step"] for c in plan["changes"]][:4] == [
            "kea-mig-ha-maintenance",
            "kea-mig-stop",
            "kea-mig-install",
            "kea-mig-validate-partner",
        ]
        job = run_job(plan)
        assert job["state"] == "failed" and "automatic return" in job["error"], job["error"]
        names = [s["name"].split("/")[1] for s in job["steps"] if s["name"].startswith("kea-migration/")]
        assert names[-5:] == [
            "kea-mig-stop",
            "kea-mig-install",
            "kea-mig-start",
            "kea-mig-start",
            "kea-mig-ha-maintenance",
        ], names
        mig = api(PRIMARY[1]).get(f"/install/kea-migration/{mid}")
        assert mig["state"] == "rolled_back" and mig["error_step"] == "kea-mig-install", mig
        assert "changed since the prepare" in mig["error"]
        pair_back()
        for host, _ in (PRIMARY, STANDBY):
            assert ssh(host, KEA_STATE)[1] == before[host], host

    def test_02_time_1_then_the_return(self):
        before = {h: ssh(h, KEA_STATE)[1] for h, _ in (PRIMARY, STANDBY)}
        mid = prepared()
        plan = api(PRIMARY[1]).post(
            f"/install/kea-migration/{mid}/plan",
            {"phase": "migrate", "options": {"response_delay_milliseconds": 8000}},
        )
        job = run_job(plan)
        assert job["state"] == "done", json.dumps(job, indent=2)
        mig = api(PRIMARY[1]).get(f"/install/kea-migration/{mid}")
        assert (mig["state"], mig["stage"], mig["rollback_possible"]) == ("migrating", "standby", True), mig
        standby = next(n for n in mig["nodes"] if n["role"] == "standby")
        assert standby["to_version"].startswith("3.2.") and standby["step"] == "kea-mig-validate-partner"
        assert "the partner's file is accepted" in job["steps"][-1]["output"], job["steps"][-1]
        # The standby: ISC 3.2, Debian Kea gone, nothing running, its 3.x files with short delays.
        pkgs = ssh(STANDBY[0], "dpkg-query -W -f '${Package} ${Status}\\n' 'kea*' 'isc-kea*' 2>/dev/null")[1]
        assert "isc-kea-dhcp4 install ok installed" in pkgs, pkgs
        assert "kea-dhcp4-server install ok installed" not in pkgs, pkgs
        units = ssh(
            STANDBY[0], "systemctl is-active isc-kea-dhcp4-server isc-kea-dhcp-ddns-server", check=False
        )
        assert "active\n" not in units[1].replace("inactive", ""), units
        conf = json.loads(ssh(STANDBY[0], "sudo cat /etc/kea/kea-dhcp4.conf")[1])
        [ha] = [h for h in conf["Dhcp4"]["hooks-libraries"] if h["library"].endswith("libdhcp_ha.so")]
        rel = ha["parameters"]["high-availability"][0]
        assert rel["max-response-delay"] == 8000 and rel["max-unacked-clients"] == 0, rel
        assert rel["restrict-commands"] is True
        ssh(STANDBY[0], "sudo runuser -u _kea -- kea-dhcp4 -T /etc/kea/kea-dhcp4.conf")
        ssh(STANDBY[0], "sudo runuser -u _kea -- kea-dhcp-ddns -t /etc/kea/kea-dhcp-ddns.conf")
        # The primary serves alone, still on 2.6.
        assert ha_state(PRIMARY[0]) in ("partner-down", "partner-in-maintenance")
        assert "kea-dhcp4-server\t2.6.3" in ssh(PRIMARY[0], "dpkg-query -W kea-dhcp4-server")[1]
        # The return.
        back = api(PRIMARY[1]).post(f"/install/kea-migration/{mid}/plan", {"phase": "rollback"})
        assert [c["after"]["step"] for c in back["changes"]] == [
            "kea-mig-stop",
            "kea-mig-install",
            "kea-mig-start",
            "kea-mig-start",
            "kea-mig-ha-maintenance",
        ]
        started = time.monotonic()
        job = run_job(back)
        assert job["state"] == "done", json.dumps(job, indent=2)
        print(f"return of the standby: {time.monotonic() - started:.0f} s")
        mig = api(PRIMARY[1]).get(f"/install/kea-migration/{mid}")
        assert mig["state"] == "rolled_back" and not mig["rollback_possible"], mig
        assert next(n for n in mig["nodes"] if n["role"] == "standby")["status"] == "rolled_back"
        pair_back()
        for host, _ in (PRIMARY, STANDBY):
            assert ssh(host, KEA_STATE)[1] == before[host], host
        audit = api(PRIMARY[1]).get("/audit?action=kea.migration.rollback&per_page=5")["items"]
        assert audit and audit[0]["target"] == f"kea-migration:{mid}" and audit[0]["result"] == "ok"
