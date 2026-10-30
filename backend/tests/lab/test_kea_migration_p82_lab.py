# SPDX-License-Identifier: Apache-2.0
"""The Kea migration on a pair whose nodes name their interfaces differently (item 82 of 0.3.0).

lab-k1a (primary, `eth0`) and lab-k1b (standby, NIC renamed `lan0` by a systemd .link file and
netplan, its Kea file and subnet naming `lan0`) from snapshot `k1-ifdiff` (k1-ha26 plus the
rename). 0.3.0 refused this pair at time 1 (the standby checked the primary's file and found no
`eth0`) and its automatic return then failed (`apt-get --no-download` on local .deb files whose
version the Debian index lists: "Unable to fetch some archives"). Checked here:

- test_01: a record left by 0.3.0 after a failed return restored by hand (state failed, both nodes on
  2.6.3, removed ISC packages `rc`, migration folders): the reconcile phase reads every node back,
  marks the migration rolled_back without touching /etc/kea, purges the `rc` packages and removes
  the folders. With `PELAGOS_P82_OLD_DEB` (a 0.3.0 deb) the state is first made for real: the old
  migration fails, the pair is restored by hand as in production, then this checkout's deb goes in
  (by scripts/deploy-prod.sh when `PELAGOS_P82_RELEASE_DIR` names a release directory).
- test_02: a failure injected after each step of times 1 and 2 (`PELAGOS_KEA_MIGRATION_FAIL_AFTER`
  on the driver) and a converted file changed behind the prepare: each time the automatic return
  puts both nodes back on the exact 2.6.3 packages, with /etc/kea, the AppArmor links, the unit
  states, the stat overrides and the directory modes identical (sums), no `rc` package, the pair in
  hot-standby.
- test_03: analysis, prepare, times 1 to 3 on this pair, then the return of the migrated pair.
- test_04: the standby's install fails inside dpkg (the target isc-kea-dhcp4 postinst exits 1, the
  packages after it left half-configured): the automatic return gives the exact state back.
Restore the snapshot to run it again from scratch. About 90 minutes.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import time
from pathlib import Path

import pytest

from tests.lab import test_kea_migration_api_lab as k1
from tests.lab import test_kea_migration_time1_lab as k4
from tests.lab.labkit import REPO, deb_package, scp, ssh, wait_for
from tests.lab.test_kea_migration_api_lab import K1A, K1B, api

pytestmark = pytest.mark.lab

PRIMARY, STANDBY = K1A, K1B
NODES = (PRIMARY, STANDBY)
UNITS = "kea-dhcp4-server kea-dhcp6-server kea-dhcp-ddns-server kea-ctrl-agent"
# Everything the return must give back, compared as text: /etc/kea (tree and sums), installed Kea
# packages, unit enable and active states, AppArmor profiles and their disable links, stat
# overrides and the Kea directories' owners and modes.
STATE = (
    "sudo sh -c '"
    'cd / && find etc/kea -printf "%p %y %m %u %g %l\\n" | sort;'
    " find etc/kea -type f -exec sha256sum {} + | sort;"
    ' dpkg-query -W -f "\\${db:Status-Abbrev} \\${Package} \\${Version}\\n" "kea*" "isc-kea*" 2>/dev/null'
    " | grep ^ii;"
    f" for u in {UNITS}; do echo $u $(systemctl is-enabled $u 2>/dev/null) $(systemctl is-active $u); done;"
    ' find /etc/apparmor.d/disable -printf "%p %l\\n" | sort;'
    " sha256sum /etc/apparmor.d/usr.sbin.kea-* | sort;"
    ' dpkg-statoverride --list | sort; stat -c "%n %U %G %a" /etc/kea /var/lib/kea /var/log/kea /run/kea\''
)
# A one-shot apt hook: the target isc-kea-dhcp4 deb repacked with a failing postinst just before
# dpkg runs (its sum was already checked), then the hook removes itself so the return runs clean.
HOOK = "/etc/apt/apt.conf.d/99-p82-postinst-fails"
SABOTAGE = "/usr/local/sbin/p82-postinst-fails"
SABOTAGE_SH = r"""#!/bin/sh
rm -f HOOK
while read -r deb; do
  case "$deb" in
    */packages/target/isc-kea-dhcp4_*.deb)
      d=$(mktemp -d); dpkg-deb -R "$deb" "$d/x"
      printf '#!/bin/sh\necho p82: postinst fails >&2\nexit 1\n' > "$d/x/DEBIAN/postinst"
      chmod 755 "$d/x/DEBIAN/postinst"; dpkg-deb -b "$d/x" "$deb" >/dev/null; rm -rf "$d";;
  esac
done
exit 0
""".replace("HOOK", HOOK)
RC = "dpkg-query -W -f '${db:Status-Abbrev} ${Package}\\n' 'isc-kea*' 2>/dev/null | grep '^rc' || true"
DROPIN = "/etc/systemd/system/pelagos.service.d/p82-fault.conf"
# Each step of time 1 and time 2 of a two-node pair, by the role of the node that runs it.
STEPS = [
    ("kea-mig-validate-partner", "primary"),
    ("kea-mig-ha-maintenance", "primary"),
    ("kea-mig-stop", "standby"),
    ("kea-mig-install", "standby"),
    ("kea-mig-stop", "primary"),
    ("kea-mig-fetch-leases", "standby"),
    ("kea-mig-leases-in", "standby"),
    ("kea-mig-start", "standby"),
    ("kea-mig-wait-partner-down", "standby"),
]


def states() -> dict[str, str]:
    return {h: ssh(h, STATE)[1] for h, _ in NODES}


def interfaces_differ() -> None:
    a = json.loads(ssh(PRIMARY[0], "sudo cat /etc/kea/kea-dhcp4.conf")[1])["Dhcp4"]["interfaces-config"]
    b = json.loads(ssh(STANDBY[0], "sudo cat /etc/kea/kea-dhcp4.conf")[1])["Dhcp4"]["interfaces-config"]
    assert a["interfaces"] == ["eth0"] and b["interfaces"] == ["lan0"], (a, b)
    assert "lan0" in ssh(STANDBY[0], "ip -br link")[1]


def record(mid: str) -> dict:
    return api(PRIMARY[1]).get(f"/install/kea-migration/{mid}")


def fault(spec: str | None) -> None:
    """The lab hook of the driver: fail `spec` (`<step>@<role>`) once it really ran."""
    if spec:
        ssh(
            PRIMARY[0],
            f"sudo mkdir -p {Path(DROPIN).parent} && printf '[Service]\\nEnvironment="
            f"PELAGOS_KEA_MIGRATION_FAIL_AFTER={spec}\\n' | sudo tee {DROPIN} >/dev/null",
        )
    else:
        ssh(PRIMARY[0], f"sudo rm -f {DROPIN}")
    ssh(PRIMARY[0], "sudo systemctl daemon-reload && sudo systemctl restart pelagos")
    relogin()
    wait_for("the driver back", lambda: api(PRIMARY[1]).get("/install/kea-migration", timeout=180), 300, 5)


def no_cache() -> None:
    """apt's cache emptied, as in production: the return must use the kept files alone (with the
    2.6.3 files still in /var/cache/apt/archives, 0.3.0's return worked; without them it failed)."""
    for host, _ in NODES:
        ssh(host, "sudo apt-get clean")


def relogin() -> None:
    """A restarted service: log in again on the next call."""
    for key in [k for k in k1.STATE if str(k).startswith("api:")]:
        del k1.STATE[key]


def returned_exactly(before: dict[str, str]) -> None:
    k4.pair_back()
    for host, _ in NODES:
        assert ssh(host, RC)[1].strip() == "", (host, ssh(host, RC)[1])
        after = ssh(host, STATE)[1]
        assert after == before[host], (host, _diff(before[host], after))
    assert k4.ha_state(PRIMARY[0]) == "hot-standby" and k4.ha_state(STANDBY[0]) == "hot-standby"


def _diff(a: str, b: str) -> str:
    import difflib

    return "\n".join(difflib.unified_diff(a.splitlines(), b.splitlines(), lineterm=""))


class TestKeaMigrationP82:
    def test_00_install_enroll_and_archive_key(self):
        interfaces_differ()
        old = os.environ.get("PELAGOS_P82_OLD_DEB")
        installed = ssh(PRIMARY[0], "dpkg-query -W -f '${Status}' pelagos 2>/dev/null", check=False)[1]
        if old and not installed.startswith("install ok"):
            # The 0.3.0 deb first, enrolled: test_01 makes the production state with it.
            k1.deb_package = lambda: Path(old)
            k1.TestKeaMigrationApi.test_00_install_and_enroll(k1.TestKeaMigrationApi())
            k4.k3.TestKeaMigrationPrepare.test_00_install_enroll_and_archive_key(
                k4.k3.TestKeaMigrationPrepare()
            )
            k4.pair_back()
            return
        k4.TestKeaMigrationTime1.test_00_install_enroll_and_archive_key(k4.TestKeaMigrationTime1())

    def test_01_reconcile_a_pair_restored_by_hand(self):
        current = api(PRIMARY[1]).get("/install/kea-migration")["current"]
        if os.environ.get("PELAGOS_P82_OLD_DEB") and (current is None or current["state"] != "failed"):
            current = self._production_state()
        if current is None or current["state"] != "failed":
            pytest.skip("no record left by a failed return: set PELAGOS_P82_OLD_DEB to make one")
        mid = current["id"]
        files = {
            h: ssh(h, "sudo sh -c 'cd / && find etc/kea -type f -exec sha256sum {} + | sort'")[1]
            for h, _ in NODES
        }
        assert any(ssh(h, RC)[1].strip() for h, _ in NODES)  # what production had
        plan = api(PRIMARY[1]).post(f"/install/kea-migration/{mid}/plan", {"phase": "reconcile"})
        assert plan["requires_confirmation"] and plan["scope"] == "kea.migration"
        job = k4.run_job(plan)
        assert job["state"] == "done", json.dumps(job, indent=2)
        assert all(isinstance(s["output"], str) for s in job["steps"])
        mig = record(mid)
        assert (mig["state"], mig["phase"], mig["error"]) == ("rolled_back", "reconcile", None), mig
        assert all(n["status"] == "rolled_back" for n in mig["nodes"]), mig["nodes"]
        for host, _ in NODES:
            # Kea files untouched, removed ISC packages purged, migration folders gone.
            assert (
                ssh(host, "sudo sh -c 'cd / && find etc/kea -type f -exec sha256sum {} + | sort'")[1]
                == files[host]
            )
            assert ssh(host, RC)[1].strip() == "", host
            listed = (
                "sudo ls /var/lib/pelagos-helper/kea-migration /var/lib/pelagos/kea-migration 2>/dev/null"
            )
            assert not re.findall(r"^[0-9A-Z]{26}$", ssh(host, listed, check=False)[1], re.M), host
            assert (
                ssh(host, "systemctl is-active kea-dhcp4-server kea-dhcp-ddns-server")[1].split()
                == ["active"] * 2
            )
        k4.pair_back()
        audit = api(PRIMARY[1]).get("/audit?action=kea.migration.reconcile&per_page=5")["items"]
        assert audit and audit[0]["result"] == "ok" and audit[0]["target"] == f"kea-migration:{mid}"
        # The other node shows the same record.
        other = api(STANDBY[1]).get("/install/kea-migration", timeout=180)["current"]
        assert other["state"] == "rolled_back"

    def _production_state(self) -> dict:
        """0.3.0 refuses this pair at time 1 and fails its return; the pair is then restored by
        hand as it was in production, and this checkout's deb installed over 0.3.0."""
        no_cache()  # production had no Kea package left in apt's cache
        mid = k4.prepared()
        plan = api(PRIMARY[1]).post(f"/install/kea-migration/{mid}/plan", {"phase": "migrate"})
        job = k4.run_job(plan)
        assert job["state"] == "failed" and "Unable to fetch some archives" in job["error"], job["error"]
        restore = (
            f"set -e; M={k4.k3.mdir(mid)};"
            " if dpkg-query -W -f '${Status}' isc-kea-common 2>/dev/null | grep -q 'ok installed'; then"
            " X=$(dpkg-query -W -f '${Package} ${Status}\\n' 'isc-kea*'"
            " | awk '/ok installed/{print $1\"-\"}' | tr '\\n' ' ');"
            ' sudo sh -c "cd $M/packages/previous && DEBIAN_FRONTEND=noninteractive apt-get install -y -q'
            ' -o Dpkg::Options::=--force-confold --allow-downgrades ./*.deb $X" || true;'
            " sudo DEBIAN_FRONTEND=noninteractive dpkg --force-confold --configure -a || true; fi;"
            " sudo systemctl stop kea-dhcp4-server kea-dhcp-ddns-server || true;"
            " sudo cp -a $M/private/before/. /etc/kea/;"
            " sudo rm -f /etc/apparmor.d/disable/usr.sbin.kea-*;"
            " for p in kea-dhcp4 kea-dhcp-ddns kea-lfc; do"
            " sudo apparmor_parser -r /etc/apparmor.d/usr.sbin.$p || true; done;"
            " for d in /etc/kea /run/kea /var/lib/kea /var/log/kea; do"
            " sudo chown _kea:_kea $d; sudo chmod 750 $d; done;"
            " sudo systemctl reset-failed; sudo systemctl enable --now kea-dhcp4-server kea-dhcp-ddns-server"
        )
        ssh(STANDBY[0], restore, timeout=900)
        k4.pair_back()
        release = os.environ.get("PELAGOS_P82_RELEASE_DIR")
        if release:
            # The production path: deploy-prod.sh with a release directory, standby first.
            res = subprocess.run(
                [str(REPO / "scripts" / "deploy-prod.sh"), "--settle", "10", release, STANDBY[0], PRIMARY[0]],
                capture_output=True,
                text=True,
                timeout=1800,
                check=False,
            )
            assert res.returncode == 0 and "all nodes on" in res.stdout, res.stdout + res.stderr
        else:
            deb = deb_package()
            for host, _ in NODES:
                scp(host, deb, "/tmp/pelagos.deb")
                ssh(
                    host,
                    "sudo dpkg -i /tmp/pelagos.deb && sudo systemctl restart pelagos pelagos-collector",
                    timeout=900,
                )
        relogin()
        return wait_for(
            "the record",
            lambda: api(PRIMARY[1]).get("/install/kea-migration", timeout=180)["current"],
            300,
            5,
        )

    @pytest.mark.parametrize("spec", [*(f"{s}@{r}" for s, r in STEPS), "changed-file"])
    def test_02_failure_at_each_step_returns_the_pair_exactly(self, spec):
        no_cache()
        before = states()
        fault(None if spec == "changed-file" else spec)
        try:
            mid = k4.prepared()
            if spec == "changed-file":
                # A converted file changed behind the prepare: refused once the ISC packages are in.
                ssh(
                    STANDBY[0],
                    f"sudo sh -c 'echo >> {k4.k3.mdir(mid)}/private/target/kea-dhcp4.conf'",
                )
            job = k4.run_job(api(PRIMARY[1]).post(f"/install/kea-migration/{mid}/plan", {"phase": "migrate"}))
        finally:
            fault(None)
        assert job["state"] == "failed" and "automatic return" in job["error"], job["error"]
        assert "the automatic return failed" not in job["error"], job["error"]
        assert all(isinstance(s["output"], str) for s in job["steps"])
        names = [s["name"].split("/")[1] for s in job["steps"] if s["name"].startswith("kea-migration/")]
        assert names[-2:] == ["kea-mig-wait-ha", "kea-mig-wait-ha"], names
        assert not [s for s in job["steps"] if s["state"] == "skipped"], job["steps"]
        mig = record(mid)
        step = spec.split("@")[0] if spec != "changed-file" else "kea-mig-install"
        assert (mig["state"], mig["error_step"]) == ("rolled_back", step), mig
        returned_exactly(before)
        print(f"{spec}: returned, {len(names)} steps")

    def test_03_the_pair_migrates_and_returns(self):
        no_cache()
        before = states()
        mid = k4.prepared()
        plan = api(PRIMARY[1]).post(
            f"/install/kea-migration/{mid}/plan",
            {"phase": "migrate", "options": {"response_delay_milliseconds": 8000}},
        )
        # The launch answers at once with the job; the screen then reads the record and the
        # overview while the steps run (0.3.0 showed "unreachable" until a reload).
        t0 = time.monotonic()
        started = api(PRIMARY[1]).post(f"/plans/{plan['id']}/apply", {"confirm": True}, timeout=30)
        launch = time.monotonic() - t0
        assert launch < 5 and started["state"] in ("queued", "running"), (launch, started)
        reads: list[tuple[float, str]] = []

        def done() -> dict | None:
            for path in ("/install/kea-migration", f"/install/kea-migration/{mid}"):
                t = time.monotonic()
                try:
                    body = api(PRIMARY[1]).get(path, timeout=60)
                    unreachable = [n["name"] for n in body.get("nodes", []) if n.get("reachable") is False]
                    reads.append(
                        (time.monotonic() - t, ",".join(unreachable) if path.endswith("migration") else "")
                    )
                except Exception as exc:  # recorded: the assertion below says how many
                    reads.append((time.monotonic() - t, f"error {exc}"))
            job = api(PRIMARY[1]).get(f"/jobs/{started['id']}")
            return job if job["state"] in ("done", "failed") else None

        job = wait_for(f"job {started['id']}", done, timeout=3600, interval=3)
        slowest = max(r[0] for r in reads)
        bad = [r for r in reads if r[1]]
        print(
            f"launch {launch:.2f} s, {len(reads)} reads during the job,"
            f" slowest {slowest:.1f} s, bad {bad[:5]}",
        )
        assert not [r for r in bad if r[1].startswith("error")], bad
        assert job["state"] == "done", json.dumps(job, indent=2)
        mig = record(mid)
        assert (mig["state"], mig["stage"]) == ("migrated", "done"), mig
        assert mig["outage_seconds"] is not None and mig["outage_seconds"] < 60, mig
        for host, _ in NODES:
            assert (
                "isc-kea-dhcp4 install ok installed"
                in ssh(host, "dpkg-query -W -f '${Package} ${Status}\\n' isc-kea-dhcp4")[1]
            )
        k4.pair_back()
        print(f"migrated: outage {mig['outage_seconds']} s")
        job = k4.run_job(
            api(PRIMARY[1]).post(f"/install/kea-migration/{mid}/plan", {"phase": "rollback"}), 3600
        )
        assert job["state"] == "done", json.dumps(job, indent=2)
        assert record(mid)["state"] == "rolled_back"
        returned_exactly(before)

    def test_04_a_failure_inside_dpkg_returns_the_pair_exactly(self):
        no_cache()
        before = states()
        mid = k4.prepared()
        with tempfile.NamedTemporaryFile("w", suffix=".sh") as f:
            f.write(SABOTAGE_SH)
            f.flush()
            scp(STANDBY[0], Path(f.name), "/tmp/p82-postinst-fails")
        ssh(
            STANDBY[0],
            f"sudo install -m 755 /tmp/p82-postinst-fails {SABOTAGE}"
            f" && echo 'DPkg::Pre-Install-Pkgs {{\"{SABOTAGE}\";}};' | sudo tee {HOOK} >/dev/null",
        )
        try:
            job = k4.run_job(api(PRIMARY[1]).post(f"/install/kea-migration/{mid}/plan", {"phase": "migrate"}))
        finally:
            fired = ssh(STANDBY[0], f"test -e {HOOK} && echo armed || echo fired", check=False)[1].strip()
            ssh(STANDBY[0], f"sudo rm -f {HOOK} {SABOTAGE}")
        assert fired == "fired", "the dpkg fault never ran"
        assert job["state"] == "failed" and "automatic return" in job["error"], job["error"]
        assert "the automatic return failed" not in job["error"], job["error"]
        assert "postinst" in job["error"] or "p82: postinst fails" in json.dumps(job), job["error"]
        mig = record(mid)
        assert (mig["state"], mig["error_step"]) == ("rolled_back", "kea-mig-install"), mig
        returned_exactly(before)


# The amd64 + arm64 pair of production --------------------------------------------------------------
# lab-up1 (amd64, primary, `eth0`) and lab-up3 (arm64 under qemu on lab-up2, standby, its NIC renamed
# `lan0`), the legacy pair of `provision.sh pair` (Kea 2.6.3 HA over the dedicated listener, D2 with
# an hmac-md5 `secret`). Needs PELAGOS_P82_ARM64_DEB (the arm64 deb of this checkout); skipped
# otherwise. About 60 minutes: the arm64 node is emulated.
UP1, UP3 = ("lab-up1", "10.99.0.24"), ("lab-up3", "10.99.0.26")
ARM = (UP1, UP3)
APIS: dict[str, object] = {}


def arm_api(address: str):
    from tests.lab.labkit import Api

    if address not in APIS:
        client = Api(address)
        wait_for(f"{address} login", lambda: client.login(), timeout=300)
        APIS[address] = client
    return APIS[address]


def arm_ha(host: str) -> str:
    return k4.ha_state(host)


def arm_states() -> dict[str, str]:
    return {h: ssh(h, STATE)[1] for h, _ in ARM}


def arm_job(plan: dict, timeout: float = 5400) -> dict:
    out = arm_api(UP1[1]).post(f"/plans/{plan['id']}/apply", {"confirm": True}, timeout=timeout)

    def done() -> dict | None:
        job = arm_api(UP1[1]).get(f"/jobs/{out['id']}")
        return job if job["state"] in ("done", "failed") else None

    return wait_for(f"job {out['id']}", done, timeout=timeout, interval=5)


def arm_prepared() -> str:
    def analysis() -> dict | None:
        out = arm_api(UP1[1]).post(
            "/install/kea-migration/analyze", {"series": "3.2", "source": "isc"}, timeout=3600
        )
        return out if len(out["roles"]) == 2 else None

    report = wait_for("an analysis of both nodes", analysis, timeout=3600, interval=30)
    assert not report["blocking"], [f for f in report["findings"] if f["severity"] == "blocking"]
    plan = arm_api(UP1[1]).post(f"/install/kea-migration/{report['id']}/plan", {"phase": "prepare"})
    job = arm_job(plan)
    assert job["state"] == "done", json.dumps(job, indent=2)
    return report["id"]


def arm_pair_back() -> None:
    wait_for(
        "the arm64 pair in hot-standby",
        lambda: arm_ha(UP1[0]) == "hot-standby" and arm_ha(UP3[0]) == "hot-standby",
        timeout=600,
        interval=10,
    )


@pytest.mark.skipif(not os.environ.get("PELAGOS_P82_ARM64_DEB"), reason="needs PELAGOS_P82_ARM64_DEB")
class TestKeaMigrationArm64:
    def test_00_install_enroll(self):
        from tests.lab.labkit import ADMIN_PASSWORD

        assert "aarch64" in ssh(UP3[0], "uname -m")[1]
        if not ssh(UP3[0], "ip -br link | grep -c lan0", check=False)[1].strip() == "1":
            rename = (
                "set -e; M=$(cat /sys/class/net/eth0/address);"
                ' printf "[Match]\\nMACAddress=$M\\n\\n[Link]\\nName=lan0\\n"'
                " | sudo tee /etc/systemd/network/10-pelagos-lan0.link >/dev/null;"
                " sudo sed -i 's/\\beth0\\b/lan0/g' /etc/netplan/*.yaml;"
                ' echo "network: {config: disabled}"'
                " | sudo tee /etc/cloud/cloud.cfg.d/99-pelagos-lab-network.cfg;"
                ' sudo sed -i "s/\\"eth0\\"/\\"lan0\\"/g" /etc/kea/kea-dhcp4.conf;'
                " sudo update-initramfs -u >/dev/null 2>&1 || true; (sleep 2; sudo reboot) &"
            )
            ssh(UP3[0], rename, check=False)
            wait_for("lab-up3 back with lan0", lambda: "lan0" in ssh(UP3[0], "ip -br link")[1], 900, 15)
        amd64 = os.environ.get("PELAGOS_P82_AMD64_DEB")
        debs = {
            UP1[0]: Path(amd64) if amd64 else deb_package(),
            UP3[0]: Path(os.environ["PELAGOS_P82_ARM64_DEB"]),
        }
        for host, _ in ARM:
            if ssh(host, "dpkg-query -W -f '${Status}' pelagos 2>/dev/null", check=False)[1].startswith(
                "install ok"
            ):
                continue
            scp(host, debs[host], "/tmp/pelagos.deb")
            ssh(
                host,
                "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q /tmp/pelagos.deb",
                timeout=3600,
            )
        a, b = UP1[1], UP3[1]
        if not ssh(UP1[0], "sudo test -e /var/lib/pelagos/node.toml && echo y", check=False)[1].strip():
            ssh(
                UP1[0],
                f"sudo PELAGOS_ADMIN_PASSWORD={ADMIN_PASSWORD} pelagos init --name up1 "
                f"--web-url https://{a}:8443 --replication-url https://{a}:8444 "
                "&& sudo systemctl start pelagos pelagos-collector",
            )
            token = arm_api(a).post("/nodes/enroll-token", {})
            ssh(
                UP3[0],
                f"sudo pelagos enroll --url {token['url']} --token {token['token']} "
                f"--ca-fingerprint {token['ca_fingerprint']} --name up3 "
                f"--replication-url https://{b}:8444 --web-url https://{b}:8443 "
                "&& sudo systemctl start pelagos pelagos-collector",
                timeout=900,
            )
        wait_for(
            "both nodes online",
            lambda: [n["status"] for n in arm_api(a).get("/nodes")["items"]] == ["online"] * 2,
            timeout=600,
            interval=10,
        )
        for address in (a, b):
            job = arm_api(address).apply(
                arm_api(address).post("/install/import/plan", {"engines": ["kea4", "d2"]}), timeout=1800
            )
            assert job.get("state", "done") == "done", job
        out = arm_api(a).get("/admin/archives")
        if not any(r.get("kind") == "cluster" for r in out.get("recipients") or []):
            arm_api(a).post("/admin/archives/identity", {"op": "generate", "password": ADMIN_PASSWORD})
        arm_pair_back()

    def test_01_failure_in_the_window_returns_the_arm64_standby(self):
        before = arm_states()
        ssh(
            UP1[0],
            f"sudo mkdir -p {Path(DROPIN).parent} && printf '[Service]\\nEnvironment="
            f"PELAGOS_KEA_MIGRATION_FAIL_AFTER=kea-mig-start@standby\\n' | sudo tee {DROPIN} >/dev/null"
            " && sudo systemctl daemon-reload && sudo systemctl restart pelagos",
        )
        APIS.clear()
        try:
            mid = arm_prepared()
            job = arm_job(arm_api(UP1[1]).post(f"/install/kea-migration/{mid}/plan", {"phase": "migrate"}))
        finally:
            ssh(
                UP1[0],
                f"sudo rm -f {DROPIN} && sudo systemctl daemon-reload && sudo systemctl restart pelagos",
            )
            APIS.clear()
        assert job["state"] == "failed" and "automatic return" in job["error"], job["error"]
        assert "the automatic return failed" not in job["error"], job["error"]
        arm_pair_back()
        for host, _ in ARM:
            assert ssh(host, RC)[1].strip() == "", host
            after = ssh(host, STATE)[1]
            assert after == before[host], (host, _diff(before[host], after))

    def test_02_the_mixed_pair_migrates_and_returns(self):
        before = arm_states()
        mid = arm_prepared()
        job = arm_job(arm_api(UP1[1]).post(f"/install/kea-migration/{mid}/plan", {"phase": "migrate"}))
        assert job["state"] == "done", json.dumps(job, indent=2)
        mig = arm_api(UP1[1]).get(f"/install/kea-migration/{mid}")
        assert (mig["state"], mig["stage"]) == ("migrated", "done"), mig
        arm_pair_back()
        print(f"arm64 pair migrated: outage {mig['outage_seconds']} s")
        job = arm_job(arm_api(UP1[1]).post(f"/install/kea-migration/{mid}/plan", {"phase": "rollback"}))
        assert job["state"] == "done", json.dumps(job, indent=2)
        arm_pair_back()
        for host, _ in ARM:
            assert ssh(host, RC)[1].strip() == "", host
            after = ssh(host, STATE)[1]
            assert after == before[host], (host, _diff(before[host], after))
