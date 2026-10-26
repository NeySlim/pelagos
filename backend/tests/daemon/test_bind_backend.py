# SPDX-License-Identifier: Apache-2.0
"""BindBackend against a real named: reads, record plans, zone and key plans, rollback, notify."""

from __future__ import annotations

import hashlib
import time
from pathlib import Path

import pytest

from pelagos.connectors.base import ConnectorContext, ConnectorDenied
from pelagos.connectors.bind import BindBackend
from pelagos.connectors.bind.dns_client import DnsClient, TsigKey
from pelagos.connectors.bind.rndc import RndcNotFound
from pelagos.domain.dns import ZoneKind, ZoneSource
from pelagos.domain.plan import Change, ChangeOp, PlanScope, PlanState
from tests.fixtures import named as named_fx
from tests.fixtures.ports import wait_for

pytestmark = pytest.mark.daemon

SETTINGS = {
    "plans": {"ttl_seconds": 600},
    "dns": {
        "read_key": "ddi-read",
        "admin_key": "ddi-admin",
        "update_types_admin": ["A", "AAAA", "PTR", "CNAME", "TXT", "SRV", "MX", "DHCID"],
    },
}


def make_backend(server: named_fx.NamedServer, tmp_root: Path, settings: dict | None = None) -> BindBackend:
    secrets = {f"tsig/{n}": s for n, s in server.keys.items()}
    ctx = ConnectorContext(
        node_id="n1",
        engine_config={
            "named_conf": str(server.named_conf),
            "include_dir": str(server.root / "pelagos"),
            "zone_dir": str(server.root / "pelagos-zones"),
            "rndc_conf": str(server.rndc_conf),
            "rndc_port": server.rndc_port,
            "statistics_url": server.stats_url,
            "query_port": server.dns_port,
        },
        backup_root=tmp_root / "backups" / server.role,
        get_secret=secrets.get,
        settings=settings or SETTINGS,
    )
    return BindBackend(ctx)


def setup_includes(backend: BindBackend) -> None:
    plan = backend.plan_include_setup("test")
    assert plan.state is PlanState.VALIDATED, plan.validations
    result = backend.apply(plan)
    assert result.ok, result.message
    tree = backend.read_config()
    assert tree.pelagos["include_line_present"] and tree.pelagos["checkconf"]["ok"]


def rrsets(backend: BindBackend, zone: str = "example.lan") -> dict[tuple[str, str], list[str]]:
    return {(r.name, r.rtype): r.rdata for r in backend.read_zone(zone)}


def test_observation(named_server, tmp_root):
    backend = make_backend(named_server, tmp_root)
    caps = backend.capabilities()
    assert caps.running and caps.rndc and caps.statistics_channel
    assert caps.version and caps.version.startswith("9.")
    assert caps.tsig_read_key == "ddi-read" and caps.tsig_admin_key == "ddi-admin"
    assert caps.views == [] and caps.dnssec is False

    zones = {z.name: z for z in backend.list_zones()}
    assert set(zones) == {"example.lan.", "2.0.192.in-addr.arpa.", "8.b.d.0.1.0.0.2.ip6.arpa."}
    assert zones["example.lan."].dynamic and zones["example.lan."].config_path == str(named_server.named_conf)
    assert zones["example.lan."].allow_transfer == ["key ddi-read", "key secondary-xfr"]

    st = backend.zone_status("example.lan")
    assert st.kind is ZoneKind.PRIMARY and st.serial == st.config_serial == 2026102401
    assert st.dynamic is True and st.signed is False and st.files == ["example.lan.db"]
    assert st.last_loaded is not None and st.error is None
    missing = backend.zone_status("nope.example.lan")
    assert missing.error and "no matching zone" in missing.error

    data = rrsets(backend)
    assert data[("www.example.lan.", "A")] == ["192.0.2.10"]
    assert ("example.lan.", "SOA") in data and data[("example.lan.", "NS")] == [
        "ns1.example.lan.",
        "ns2.example.lan.",
    ]

    stats = backend.instance_stats()
    assert stats.zones["_default/example.lan"]["serial"] == 2026102401 and stats.memory.get("InUse")

    assert backend.dnssec_status("example.lan")["signed"] is False
    status = backend.server_status()
    assert "last configured" in status and backend.reconfig() == ""


def test_record_add_replace_delete_with_prerequisite_failure(named_server, tmp_root):
    backend = make_backend(named_server, tmp_root)
    add = backend.plan_rrset_changes(
        "example.lan",
        [Change(ChangeOp.ADD, "example.lan/pc1/A", after={"rdata": ["192.0.2.42"], "ttl": 300})],
        created_by="alice",
    )
    assert add.state is PlanState.VALIDATED and add.scope is PlanScope.DNS_RRSET
    assert add.diff == "+pc1.example.lan. 300 IN A 192.0.2.42"
    assert add.target_node_ids == ["n1"] and add.created_by == "alice"
    result = backend.apply(add)
    assert result.ok, result.message
    assert rrsets(backend)[("pc1.example.lan.", "A")] == ["192.0.2.42"]
    sent = backend.details[add.id]["apply"]
    assert "prereq nxrrset pc1.example.lan. IN A" in sent["request"]["update"]
    assert sent["response"] == {"rcode": "NOERROR"}

    # Applying the same add again fails on its nxrrset prerequisite and changes nothing.
    again = backend.apply(add)
    assert not again.ok and "YXRRSET" in again.message

    replace = backend.plan_rrset_changes(
        "example.lan", [Change(ChangeOp.REPLACE, "example.lan/pc1/A", after={"rdata": ["192.0.2.43"]})]
    )
    assert replace.state is PlanState.VALIDATED
    # Someone else (Kea through D2, say) changes the RRset between plan and apply.
    client = DnsClient(port=named_server.dns_port)
    admin = TsigKey("ddi-admin", named_server.keys["ddi-admin"])
    client.update("example.lan", admin, lambda m: m.add("pc1.example.lan.", 300, "A", "192.0.2.44"))
    failed = backend.apply(replace)
    assert not failed.ok and "NXRRSET" in failed.message
    assert rrsets(backend)[("pc1.example.lan.", "A")] == ["192.0.2.42", "192.0.2.44"]

    replace = backend.plan_rrset_changes(
        "example.lan",
        [Change(ChangeOp.REPLACE, "example.lan/pc1/A", after={"rdata": ["192.0.2.43"], "ttl": 60})],
    )
    assert replace.diff.splitlines() == [
        "-pc1.example.lan. 300 IN A 192.0.2.42",
        "-pc1.example.lan. 300 IN A 192.0.2.44",
        "+pc1.example.lan. 60 IN A 192.0.2.43",
    ]
    assert backend.apply(replace).ok
    assert rrsets(backend)[("pc1.example.lan.", "A")] == ["192.0.2.43"]

    delete = backend.plan_rrset_changes("example.lan", [Change(ChangeOp.DELETE, "example.lan/pc1/A")])
    assert backend.apply(delete).ok
    assert ("pc1.example.lan.", "A") not in rrsets(backend)
    # Rollback sends the inverse UPDATE: the deleted RRset comes back with its TTL.
    undo = backend.rollback(delete)
    assert undo.ok and undo.rolled_back
    back = {r.name: r for r in backend.read_zone("example.lan")}["pc1.example.lan."]
    assert back.rdata == ["192.0.2.43"] and back.ttl == 60


def test_record_plan_validation_errors(named_server, tmp_root):
    backend = make_backend(named_server, tmp_root)
    plan = backend.plan_rrset_changes(
        "example.lan",
        [
            Change(ChangeOp.ADD, "example.lan/www/A", after={"rdata": ["192.0.2.1"]}),
            Change(ChangeOp.ADD, "example.lan/@/SOA", after={"rdata": ["a. b. 1 1 1 1 1"]}),
        ],
    )
    assert plan.state is PlanState.FAILED
    assert "already exists" in plan.error and "SOA" in plan.error
    no_key = make_backend(
        named_server, tmp_root, settings={"dns": {"read_key": "missing", "admin_key": "missing"}}
    )
    with pytest.raises(ConnectorDenied):
        no_key.read_zone("example.lan")


def test_zone_add_through_zones_conf_and_delete(named_server, tmp_root):
    backend = make_backend(named_server, tmp_root)
    setup_includes(backend)
    zones_conf = named_server.root / "pelagos" / "zones.conf"
    after = {
        "name": "lab.example.lan",
        "kind": "primary",
        "update_policy": ["grant ddi-admin zonesub A AAAA TXT"],
        "allow_transfer": ["key ddi-read"],
        "notes": "lab zone",
        "ns": ["ns1.example.lan."],
        "records": [{"name": "host.lab.example.lan.", "rtype": "A", "ttl": 300, "rdata": ["192.0.2.50"]}],
    }
    plan = backend.plan_zone_change(Change(ChangeOp.ADD, "_default/lab.example.lan", after=after), "alice")
    assert plan.state is PlanState.VALIDATED, plan.validations
    assert [v.tool for v in plan.validations] == ["named-checkconf", "named-checkzone"]
    assert f"+++ {zones_conf}" in plan.diff and '+zone "lab.example.lan" {' in plan.diff
    assert not plan.requires_confirmation
    result = backend.apply(plan)
    assert result.ok, result.message
    st = backend.zone_status("lab.example.lan")
    assert st.kind is ZoneKind.PRIMARY and st.dynamic and st.serial
    assert named_server.rndc("zonestatus", "lab.example.lan").startswith("name: lab.example.lan")
    assert rrsets(backend, "lab.example.lan")[("host.lab.example.lan.", "A")] == ["192.0.2.50"]
    text = zones_conf.read_text()
    assert text.startswith("# pelagos:managed v1\n") and '# pelagos:note {"notes": "lab zone"}' in text
    managed = {z.name: z for z in backend.list_zones()}["lab.example.lan."]
    assert managed.source is ZoneSource.PELAGOS and managed.notes == "lab zone"

    # A record plan on the new zone works through the same admin key.
    rec = backend.plan_rrset_changes(
        "lab.example.lan", [Change(ChangeOp.ADD, "lab.example.lan/txt/TXT", after={"rdata": ['"hello"']})]
    )
    assert backend.apply(rec).ok

    # User zones are never edited through zones.conf.
    refused = backend.plan_zone_change(Change(ChangeOp.DELETE, "_default/example.lan"))
    assert refused.state is PlanState.FAILED and "user file" in refused.error

    delete = backend.plan_zone_change(Change(ChangeOp.DELETE, "_default/lab.example.lan"))
    assert delete.state is PlanState.VALIDATED and delete.requires_confirmation
    assert backend.apply(delete).ok
    with pytest.raises(RndcNotFound):
        backend.rndc.zonestatus("lab.example.lan")
    # Rollback of the delete restores zones.conf and the zone is served again.
    assert backend.rollback(delete).ok
    assert backend.zone_status("lab.example.lan").kind is ZoneKind.PRIMARY


def test_key_rotation_in_keys_conf(named_server, tmp_root):
    backend = make_backend(named_server, tmp_root)
    setup_includes(backend)
    add_key = backend.plan_config_change(
        [Change(ChangeOp.ADD, "keys/rot-key", after={"algorithm": "hmac-sha256"})]
    )
    assert add_key.state is PlanState.VALIDATED and add_key.scope is PlanScope.DNS_KEY
    first = add_key.changes[0].after["secret"]
    assert first not in add_key.diff and 'secret "****"' in add_key.diff
    assert backend.apply(add_key).ok
    zone = backend.plan_zone_change(
        Change(
            ChangeOp.ADD,
            "_default/rot.example.lan",
            after={"kind": "primary", "allow_transfer": ["key rot-key"], "ns": ["ns1.example.net."]},
        )
    )
    assert backend.apply(zone).ok, zone.validations

    client = DnsClient(port=named_server.dns_port)
    assert client.axfr("rot.example.lan", TsigKey("rot-key", first))

    rotate = backend.plan_config_change([Change(ChangeOp.REPLACE, "keys/rot-key", after={})])
    assert rotate.requires_confirmation and rotate.changes[0].before["secret"] == "****"
    second = rotate.changes[0].after["secret"]
    assert second != first
    assert backend.apply(rotate).ok
    assert second in (named_server.root / "pelagos" / "keys.conf").read_text()
    assert client.axfr("rot.example.lan", TsigKey("rot-key", second))
    with pytest.raises(ConnectorDenied):
        client.axfr("rot.example.lan", TsigKey("rot-key", first))
    # The connector reads the rotated managed key, not a stale cluster secret.
    reader = make_backend(named_server, tmp_root, settings={"dns": {"read_key": "rot-key"}})
    reader.ctx.get_secret = {"tsig/rot-key": first}.get
    assert any(r.rtype == "SOA" for r in reader.read_zone("rot.example.lan"))

    # A key defined by the user stays out of reach.
    refused = backend.plan_config_change([Change(ChangeOp.REPLACE, "keys/ddi-admin", after={})])
    assert refused.state is PlanState.FAILED and "user file" in refused.error


def test_options_and_acls(named_server, tmp_root):
    backend = make_backend(named_server, tmp_root)
    setup_includes(backend)
    plan = backend.plan_config_change(
        [
            Change(ChangeOp.ADD, "acls/lan", after={"elements": ["192.0.2.0/24", "2001:db8::/64"]}),
            Change(ChangeOp.ADD, "options/notify-rate", after="50"),
        ]
    )
    assert plan.state is PlanState.VALIDATED and plan.scope is PlanScope.DNS_CONFIG, plan.validations
    assert backend.apply(plan).ok
    tree = backend.read_config()
    rate = next(e for e in tree.options if e.name == "notify-rate")
    assert rate.value == "50" and rate.managed
    assert next(a for a in tree.acls if a.name == "lan").managed

    dup = backend.plan_config_change([Change(ChangeOp.ADD, "options/recursion", after="yes")])
    assert dup.state is PlanState.FAILED and "user file" in dup.error
    bad = backend.plan_config_change([Change(ChangeOp.ADD, "options/serial-query-rate", after="fast")])
    assert bad.state is PlanState.FAILED and bad.validations[0].tool == "named-checkconf"

    raw = backend.plan_config_change(
        [
            Change(
                ChangeOp.ADD,
                "raw:zones.conf",
                after='zone "raw.example.lan" { type forward; forwarders { 192.0.2.53; }; };',
            )
        ]
    )
    assert raw.state is PlanState.VALIDATED, raw.validations
    assert backend.apply(raw).ok
    # Forward zones live outside the zone table (no zonestatus): check the resolved configuration.
    fwd = next(z for z in backend.list_zones() if z.name == "raw.example.lan.")
    assert (
        fwd.kind is ZoneKind.FORWARD and fwd.forwarders == ["192.0.2.53"] and fwd.source is ZoneSource.PELAGOS
    )
    assert backend.read_config().pelagos["checkconf"]["ok"]


def config_fingerprint(server: named_fx.NamedServer) -> dict[str, str]:
    files = [server.named_conf, server.root / "keys.conf", server.root / "rndc.key"]
    files += sorted((server.root / "pelagos").rglob("*.conf"))
    return {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in files}


def test_rollback_after_injected_checkconf_failure(named_server, tmp_root):
    backend = make_backend(named_server, tmp_root)
    setup_includes(backend)
    plan = backend.plan_zone_change(
        Change(
            ChangeOp.ADD, "_default/fail.example.lan", after={"kind": "primary", "ns": ["ns1.example.net."]}
        )
    )
    assert plan.state is PlanState.VALIDATED
    before = config_fingerprint(named_server)
    configured = backend.server_status()["last configured"]
    time.sleep(1.2)  # config time has a one second resolution
    fake = tmp_root / "fake-checkconf"
    fake.write_text("#!/bin/sh\necho 'named.conf:1: injected failure' >&2\nexit 1\n")
    fake.chmod(0o755)
    backend.checkconf = str(fake)

    result = backend.apply(plan)
    assert not result.ok and result.rolled_back and "injected failure" in result.message
    assert config_fingerprint(named_server) == before
    assert not (named_server.root / "pelagos-zones" / "fail.example.lan.db").exists()
    assert backend.server_status()["last configured"] == configured
    with pytest.raises(RndcNotFound):
        backend.rndc.zonestatus("fail.example.lan")
    steps = [s["name"] for s in backend.details[plan.id]["response"]["steps"]]
    assert steps[:3] == ["backup", "write", "validate"] and "rollback" in steps


def test_file_precondition_blocks_apply(named_server, tmp_root):
    backend = make_backend(named_server, tmp_root)
    setup_includes(backend)
    plan = backend.plan_config_change([Change(ChangeOp.ADD, "acls/a1", after={"elements": ["192.0.2.1"]})])
    acls = named_server.root / "pelagos" / "acls.conf"
    acls.write_text(acls.read_text() + "# hand edit\n")
    result = backend.apply(plan)
    assert not result.ok and "file_sha256" in result.message
    assert "a1" not in acls.read_text()


def test_secondary_follows_after_notify(named_server, named_secondary, tmp_root):
    # The fixture primary does not notify; give it also-notify towards the secondary, as a real pair has.
    ports = {"dns": named_server.dns_port, "rndc": named_server.rndc_port, "stats": named_server.stats_port}
    named_fx.write_primary_conf(
        named_server.root, ports, named_server.keys, secondary_port=named_secondary.dns_port
    )
    named_server.rndc("reconfig")
    primary = make_backend(named_server, tmp_root)
    secondary = DnsClient(port=named_secondary.dns_port)
    wait_for(lambda: secondary.soa_serial("example.lan") == 2026102401, timeout=20, what="initial transfer")

    plan = primary.plan_rrset_changes(
        "example.lan", [Change(ChangeOp.ADD, "example.lan/pc9/A", after={"rdata": ["192.0.2.99"]})]
    )
    assert primary.apply(plan).ok
    serial = primary.soa_serial("example.lan")
    assert isinstance(primary.notify("example.lan"), str)
    wait_for(
        lambda: secondary.soa_serial("example.lan") == serial, timeout=20, what="secondary follows notify"
    )
    # Refresh is one hour: only the NOTIFY can have triggered this transfer.
    assert named_secondary.rndc("zonestatus", "example.lan").count(str(serial)) == 1
