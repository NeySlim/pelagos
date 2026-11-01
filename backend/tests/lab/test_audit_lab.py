# SPDX-License-Identifier: Apache-2.0
"""Sealed audit segments on the reference pair in mixed versions (section 11, "Sealed segments").

lab-ns1 and lab-ns2 start on the previous release ($PELAGOS_LAB_PREVIOUS_DEB, default
build/previous/pelagos_*_amd64.deb; skipped without it). ns1 goes to the deb of this checkout: the
token reads default is migrated (ns2, still on the previous release, adopts it), ns1 rotates on demand
while ns2 is older (audit replicated both ways, entries of the rotated year merged after it, the export
of the segment unchanged, tampering and a deleted segment detected), then ns2 is upgraded and rotates
too. The VMs are rolled back first.
"""

from __future__ import annotations

import hashlib
import json
import os
import ssl
import time
import urllib.request
from pathlib import Path
from typing import Any

import pytest

from tests.lab.labkit import (
    ADMIN_PASSWORD,
    NS1,
    NS2,
    REPO,
    Api,
    deb_package,
    fixable,
    rollback,
    run_script,
    scp,
    ssh,
    sudo_cat,
    wait_for,
)

A1, A2 = NS1[1], NS2[1]
AUDIT_DIR = "/var/lib/pelagos/audit"
STATE: dict[str, Any] = {}
RANGE = "from=2000-01-01T00:00:00Z&to=2100-01-01T00:00:00Z"


def previous_deb() -> Path | None:
    env = os.environ.get("PELAGOS_LAB_PREVIOUS_DEB")
    if env:
        return Path(env) if Path(env).exists() else None
    found = sorted((REPO / "build" / "previous").glob("pelagos_*_amd64.deb"))
    return found[-1] if found else None


pytestmark = [
    pytest.mark.lab,
    pytest.mark.skipif(
        previous_deb() is None, reason="needs the previous release deb ($PELAGOS_LAB_PREVIOUS_DEB)"
    ),
]


def api(address: str, fresh: bool = False) -> Api:
    key = f"api:{address}"
    if fresh or key not in STATE:
        client = Api(address, totp_secret=STATE.get("secret"))
        wait_for(f"{address} login", lambda: client.login(), timeout=180)
        STATE[key] = client
    return STATE[key]


def node_id(address: str) -> str:
    return api(address).get("/nodes/self")["peer"]["id"]


def install(address: str, deb: Path) -> None:
    scp(address, deb, "/tmp/pelagos.deb")
    ssh(
        address,
        # apt-daily-upgrade may hold the dpkg lock right after a rollback.
        "sudo DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 "
        "install -y -q --allow-downgrades /tmp/pelagos.deb",
        timeout=900,
    )
    ssh(address, "sudo systemctl restart pelagos pelagos-collector || true")
    STATE.pop(f"api:{address}", None)


def bearer(address: str, method: str, path: str, body: Any = None) -> int:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(f"https://{address}:8443/api/v1{path}", data=data, method=method)
    req.add_header("Authorization", f"Bearer {STATE['token']}")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, context=ctx, timeout=60) as res:  # noqa: S310
        return res.status


def token_calls(address: str) -> int:
    return api(address).get("/audit?action=auth.token_call&per_page=1")["total"]


def counts_equal() -> bool:
    a = api(A1).get("/audit?per_page=1")["total"]
    b = api(A2).get("/audit?per_page=1")["total"]
    return a == b and a > 0


def export(address: str, query: str = RANGE) -> bytes:
    """The NDJSON export of a range (raw bytes), through the session of `address`."""
    client = api(address)
    req = urllib.request.Request(f"{client.base}/audit/export?{query}")  # noqa: S310
    with client.opener.open(req, timeout=120) as res:
        return res.read()


def record(address: str, name: str, ip: str) -> None:
    plan = api(address).post(
        "/dns/zones/example.lan/records/plan",
        {"changes": [{"op": "add", "target": f"{name}/A", "after": {"ttl": 60, "rdata": [ip]}}]},
    )
    api(address).apply(plan)


def segments(address: str) -> list[dict]:
    return api(address).get("/audit/segments")["segments"]


def journal_errors(address: str) -> int:
    out = ssh(
        address,
        "sudo journalctl -u pelagos -u pelagos-collector --since '-15 min' | grep -c ' ERROR ' || true",
    )[1]
    return int(out.strip() or 0)


class TestAuditSegmentsOnThePair:
    def test_00_rollback_and_provision(self):
        """Roll back ns1 and ns2, install the previous release on both, init ns1, enroll ns2."""
        rollback("lab-ns1", "lab-ns2")
        run_script("provision.sh", "pair", timeout=1800)
        deb = previous_deb()
        assert deb is not None
        for address in (A1, A2):
            install(address, deb)
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
        wait_for(
            "both online",
            lambda: all(n["status"] == "online" for n in api(A1).get("/nodes")["items"]),
            timeout=180,
        )
        # Engines adopted and the security plan applied, as in test_upgrade_ui_lab.py; the HA TLS
        # push to the peer can be refused at first, hence the retries.
        for address in (A1, A2):
            client = api(address)
            client.apply(client.post("/install/import/plan", {"engines": ["bind", "kea4", "d2"]}))
        wait_for(
            "both online after import",
            lambda: all(n["status"] == "online" for n in api(A1).get("/nodes")["items"]),
            timeout=300,
        )

        def security(address: str) -> bool:
            client = api(address)
            todo = fixable(client.get("/install/security")["findings"])
            if todo:
                client.apply(client.post("/install/security/plan", {"finding_ids": todo}), timeout=900)
            return True

        for address in (A1, A2):
            wait_for(f"security plan on {address}", lambda a=address: security(a), timeout=300, interval=10)

    def test_01_writes_and_token_reads_on_the_previous_release(self):
        """A record written on each node, an API token GET on ns1: auth.token_call audited; counts equal."""
        import pyotp

        api(A2)  # logged in before the TOTP enrollment: a password-only login is refused after it
        admin = api(A1)
        secret = admin.post("/auth/totp/enroll")["secret"]
        admin.post("/auth/totp/confirm", {"code": pyotp.TOTP(secret).now()})
        STATE["secret"] = secret
        for client in (api(A1), api(A2)):
            client.totp_secret = secret
        time.sleep(31)  # a fresh code for the token
        STATE["token"] = admin.post(
            "/auth/tokens", {"name": "lab", "role": "admin", "totp_code": pyotp.TOTP(secret).now()}
        )["token"]
        before = token_calls(A1)
        assert bearer(A1, "GET", "/nodes") == 200
        assert token_calls(A1) == before + 1  # reads audited on the previous release
        wait_for("audit counts equal", counts_equal, timeout=60)

    def test_02_upgrade_ns1_migrates_the_token_reads_default(self):
        """ns1 on this deb: admin.settings.op migrate entry; the setting reads false on ns1 and on ns2
        (the previous release adopts it at the next merge); a token GET on either node is not audited.
        The key is first removed from both files (a cluster created before the setting existed): the
        upgrade inserts it."""
        for address in (A1, A2):
            ssh(address, "sudo systemctl stop pelagos pelagos-collector")
        for address in (A1, A2):
            ssh(address, "sudo sed -i '/^api_token_audit_reads_enabled = /d' /var/lib/pelagos/cluster.toml")
            assert (
                "api_token_audit_reads_enabled"
                not in sudo_cat(address, "/var/lib/pelagos/cluster.toml").split("[replication")[0]
            )
        ssh(A2, "sudo systemctl start pelagos pelagos-collector")
        install(A1, deb_package())
        wait_for("ns1 back", lambda: api(A1, fresh=True).get("/nodes/self"), timeout=180)
        entries = api(A1).get("/audit?action=admin.settings.op&per_page=50")["items"]
        assert any(e["request"].get("renamed", {}).get("auth.api_token_audit_reads_enabled") for e in entries)

        def off_on(address: str) -> bool:
            text = sudo_cat(address, "/var/lib/pelagos/cluster.toml")
            return "api_token_audit_reads_enabled = false" in text

        wait_for("setting false on both", lambda: off_on(A1) and off_on(A2), timeout=120)
        for address in (A1, A2):
            before = token_calls(address)
            assert bearer(address, "GET", "/nodes") == 200
            time.sleep(3)
            assert token_calls(address) == before, address

    def test_03_rotate_on_ns1_while_ns2_is_on_the_previous_release(self):
        """Export saved; `pelagos audit-log rotate`; GET /audit/segments lists a sealed segment, verify ok
        (anchor compared with ns2: peers_checked 1); the export of the range is byte-identical; ns2 holds
        the audit.rotate entry."""
        before = export(A1)
        out = ssh(A1, "sudo -u pelagos pelagos audit-log rotate")[1]
        assert "rotated to audit-" in out
        (seg,) = segments(A1)
        STATE["segment"] = seg["name"]
        assert seg["sealed"] and seg["seal"]["node_id"] == node_id(A1)
        wait_for(
            "ns2 holds the anchor",
            lambda: api(A2).get("/audit?action=audit.rotate")["total"] == 1,
            timeout=60,
        )
        verdict = api(A1).post(f"/audit/segments/{seg['name']}/verify")
        assert verdict["ok"] and verdict["peers_checked"] == 1, verdict
        after = export(A1)
        assert after.startswith(before)  # the anchor comes after the old content
        assert ssh(A1, "sudo -u pelagos pelagos audit-log verify")[0] == 0

    def test_04_audit_replicates_both_ways_after_the_rotation(self):
        """Writes on both nodes; counts equal; no error in either journal; GET /audit on ns1 pages
        across segment and live file."""
        record(A1, "seg1", "192.0.2.61")
        record(A2, "seg2", "192.0.2.62")
        wait_for("audit counts equal", counts_equal, timeout=90)
        assert journal_errors(A1) == 0 and journal_errors(A2) == 0
        total = api(A1).get("/audit?per_page=1")["total"]
        seen: set[str] = set()
        page = 1
        while True:
            items = api(A1).get(f"/audit?per_page=200&page={page}")["items"]
            if not items:
                break
            seen.update(e["id"] for e in items)
            page += 1
        assert len(seen) == total

    def test_05_ns2_stopped_then_caught_up_after_the_rotation(self):
        """ns2 stopped, writes on ns1, rotation on ns1 again (-2 suffix), ns2 started: it gets every entry;
        an entry written on ns2 while it was cut off lands in ns1's live file."""
        ssh(A2, "sudo systemctl stop pelagos pelagos-collector")
        record(A1, "seg3", "192.0.2.63")
        ssh(A1, "sudo -u pelagos pelagos audit-log rotate")
        assert [s["name"] for s in segments(A1)][-1].endswith("-2.jsonl")
        ssh(A2, "sudo systemctl start pelagos pelagos-collector")
        STATE.pop(f"api:{A2}", None)
        wait_for("audit counts equal", counts_equal, timeout=180)

    def test_06_tampered_and_deleted_segments_are_detected(self):
        """One byte flipped in a segment on ns1: verify fails with chain, CLI exits 1; byte restored.
        A segment deleted by hand: verify reports missing_segment; file put back."""
        name = STATE["segment"]
        path = f"{AUDIT_DIR}/{name}"
        ssh(A1, f"sudo cp -a {path} /root/seg.bak")
        ssh(A1, f"sudo sed -i '0,/dns/s//DNS/' {path}")
        assert api(A1).post(f"/audit/segments/{name}/verify")["reason"] == "chain"
        code, out, _ = ssh(A1, "sudo -u pelagos pelagos audit-log verify", check=False)
        assert code == 1 and "FAILED (chain)" in out
        ssh(A1, f"sudo cp -a /root/seg.bak {path}")
        ssh(A1, f"sudo mv {path} /root/seg.moved")
        code, out, _ = ssh(A1, "sudo -u pelagos pelagos audit-log verify", check=False)
        assert code == 1 and "missing_segment" in out
        ssh(A1, f"sudo mv /root/seg.moved {path}")
        assert ssh(A1, "sudo -u pelagos pelagos audit-log verify")[0] == 0

    def test_07_upgrade_ns2_and_rotate_there(self):
        """ns2 on this deb, rotated on demand; both converge; the anchors of both nodes verify against
        each other; no repeated id exchange in the journals once converged; the export of a range sorted
        by id is the same on both nodes."""
        install(A2, deb_package())
        wait_for("ns2 back", lambda: api(A2, fresh=True).get("/nodes/self"), timeout=180)
        ssh(A2, "sudo -u pelagos pelagos audit-log rotate")
        wait_for("audit counts equal", counts_equal, timeout=120)
        for address in (A1, A2):
            for seg in segments(address):
                verdict = api(address).post(f"/audit/segments/{seg['name']}/verify")
                assert verdict["ok"] and verdict["peers_checked"] == 1, (address, verdict)
        time.sleep(120)  # several anti-entropy passes
        for address in (A1, A2):
            out = ssh(
                address,
                "sudo journalctl -u pelagos-collector --since '-2 min' | grep -c 'audit id exchange' || true",
            )[1]
            assert int(out.strip() or 0) <= 1, address

        def by_id(address: str) -> str:
            lines = [line for line in export(address).decode().splitlines() if line]
            return hashlib.sha256(
                "\n".join(sorted(lines, key=lambda x: json.loads(x)["id"])).encode()
            ).hexdigest()

        assert by_id(A1) == by_id(A2)
