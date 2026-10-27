# SPDX-License-Identifier: Apache-2.0
"""Item 42 against a real named: the 0.1.x grant refuses NS edits, the audit widens it, then the zone
editor and nsupdate remove a retired name server, and the "primary not in NS" check fires and clears."""

from __future__ import annotations

import dataclasses
import subprocess
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from pelagos.collector.checks import delegation, distro
from pelagos.collector.checks.runner import HealthChecks
from pelagos.domain import Change, ChangeOp, JobState, PlanState, zone_updates
from pelagos.installer.jobs import apply_plan
from pelagos.installer.security_audit import build_security_plan, run_audit
from tests.daemon import bind_custom
from tests.daemon.test_bind_backend import make_backend
from tests.fixtures.ports import find_binary
from tests.unit.installer.fakes import make_env

pytestmark = pytest.mark.daemon

LEGACY = " ".join(zone_updates.LEGACY_ADMIN_UPDATE_TYPES)
BODY = f"""
zone "example.lan" {{ type primary; file "example.lan.db";
\tupdate-policy {{ grant ddi-admin zonesub {LEGACY}; grant "kea-ddns" zonesub A AAAA PTR DHCID; }}; }};
zone "1.0.10.in-addr.arpa" {{ type primary; file "reverse.db";
\tupdate-policy {{ grant ddi-admin zonesub {LEGACY}; }}; }};
"""
# ns-old is retired (TEST-NET, nothing answers); ns1 is this primary. The reverse zone lists only
# ns-old, as both reverse zones did in production.
FORWARD = (
    "$TTL 3600\n@ IN SOA ns1 hostmaster ( 1 3600 900 1209600 3600 )\n@ IN NS ns1\n@ IN NS ns-old\n"
    "ns1 IN A 127.0.0.1\nns-old IN A 192.0.2.2\n"
)
REVERSE = (
    "$TTL 3600\n@ IN SOA ns1.example.lan. hostmaster.example.lan. ( 1 3600 900 1209600 3600 )\n"
    "@ IN NS ns-old.example.lan.\n10 IN PTR www.example.lan.\n"
)
REV = "1.0.10.in-addr.arpa."
IDS = [f"bind:update_types_narrow:_default/{z}" for z in ("example.lan.", REV)]


@pytest.fixture(autouse=True)
def _no_package_reads(monkeypatch):
    monkeypatch.setattr(distro, "read_package", lambda engine, run=None: None)
    monkeypatch.setattr(distro, "fetch_debian_tracker", lambda url, var_dir, timeout=60.0: False)


@pytest.fixture
def server(tmp_root: Path):
    srv = bind_custom.start(
        tmp_root / "update-types",
        BODY,
        files={"example.lan.db": FORWARD, "reverse.db": REVERSE},
        options="\tallow-transfer { key ddi-read; };\n",
    )
    try:
        yield srv
    finally:
        srv.stop()


def _nsupdate(server, commands: str) -> subprocess.CompletedProcess[str]:
    nsupdate = find_binary("nsupdate")
    if not nsupdate:
        pytest.skip("nsupdate not found")
    script = f"server 127.0.0.1 {server.dns_port}\n{commands}\nsend\n"
    key = f"hmac-sha256:ddi-admin:{server.keys['ddi-admin']}"
    return subprocess.run([nsupdate, "-y", key], input=script, capture_output=True, text=True, check=False)


def _delegation(backend) -> dict[str, object]:
    ctx = SimpleNamespace(
        node=SimpleNamespace(id="n1"),
        settings=lambda: {"checks": {"delegation_confirm_passes": 1, "delegation_timeout_seconds": 1}},
    )
    checks = HealthChecks(ctx, None, SimpleNamespace(dns=backend), threading.Lock())
    checks.net_factory = lambda b: delegation.DnsNet(b.dns.server, b.dns.port, 1.0, probe_port=b.dns.port)
    return {a.subject: a for a in checks._delegation().alerts}


def test_ns_removal_after_the_audit_widens_the_grant(server, tmp_root):
    settings = {
        "plans": {"ttl_seconds": 600},
        "dns": {"read_key": "ddi-read", "update_types_admin": list(zone_updates.ADMIN_UPDATE_TYPES)},
    }
    backend = make_backend(server, tmp_root, settings)
    found = _delegation(backend)
    assert "ns-primary:1.0.10.in-addr.arpa" in found
    assert found["ns-primary:1.0.10.in-addr.arpa"].details["ns"] == ["ns-old.example.lan."]
    assert "ns-silent:1.0.10.in-addr.arpa:ns-old.example.lan." in found
    assert "ns-primary:example.lan" not in found  # ns1 is this server

    # The 0.1.x grant: the zone editor's NS change and nsupdate are both REFUSED.
    fix = [Change(ChangeOp.REPLACE, f"{REV}/@/NS", after={"rdata": ["ns1.example.lan."]})]
    plan = backend.plan_rrset_changes(REV, fix)
    assert plan.state is PlanState.VALIDATED, plan.validations
    refused = backend.apply(plan)
    assert not refused.ok and "REFUSED" in refused.message and "update-policy" in refused.message
    res = _nsupdate(server, "update delete example.lan. NS ns-old.example.lan.")
    assert "REFUSED" in res.stdout + res.stderr

    # The audit sees the narrow grants and widens them through a security plan.
    env = make_env(tmp_root / "installer")
    env.paths = dataclasses.replace(env.paths, named_conf=server.named_conf)
    assert set(IDS) <= {f.id for f in run_audit(env)}
    job = apply_plan(build_security_plan(env, IDS, created_by="admin"), env)
    assert job.state is JobState.DONE, job.error
    conf = server.named_conf.read_text()
    assert conf.count(f"grant ddi-admin zonesub {LEGACY} NS CAA;") == 2  # missing types appended
    assert 'grant "kea-ddns" zonesub A AAAA PTR DHCID;' in conf
    assert not set(IDS) & {f.id for f in run_audit(env)}
    server.rndc("reconfig")

    res = _nsupdate(server, "update delete example.lan. NS ns-old.example.lan.")
    assert res.returncode == 0, res.stdout + res.stderr
    plan = backend.plan_rrset_changes(REV, fix)
    applied = backend.apply(plan)
    assert applied.ok, applied.message
    ns = {(r.name, r.rtype): r.rdata for r in backend.read_zone(REV)}[(REV, "NS")]
    assert ns == ["ns1.example.lan."]
    assert ["ns1.example.lan."] == {(r.name, r.rtype): r.rdata for r in backend.read_zone("example.lan")}[
        ("example.lan.", "NS")
    ]

    found = _delegation(backend)
    assert not [s for s in found if s.startswith(("ns-primary:", "ns-silent:"))], sorted(found)
