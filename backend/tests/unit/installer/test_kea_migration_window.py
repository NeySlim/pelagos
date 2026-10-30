# SPDX-License-Identifier: Apache-2.0
"""The window and time 3 of the Kea migration on a node (section 28, batch K5): the plans of the
whole migration and of the returns, the lease files exported by the stopped node and taken by its
partner, the shortened detection delays put back exactly, and what the finish step keeps."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from pelagos.core import kea_migration as kmc
from pelagos.installer import kea_migration_steps as steps
from pelagos.installer import kea_migration_switch as sw
from pelagos.platform import CommandResult
from tests.unit.installer.test_kea_migration_prepare import MID, details, host, not_really_root  # noqa: F401
from tests.unit.installer.test_kea_migration_switch import (
    PRIMARY,
    STANDBY,
    Kea,
    Packages,
    request,
    status,
    switch_details,
)

pytestmark = pytest.mark.unit

BACKUP = {"node_id": "node-c", "name": "ns3", "role": "backup", "order": 0, "engines": ["kea4"]}
HEADER = (
    "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,"
    "user_context,pool_id\n"
)


def lease(ip: str, expire: int) -> str:
    return f"{ip},aa:bb:cc:dd:ee:{ip.split('.')[-1]:0>2},,3600,{expire},1,0,0,,0,,0\n"


def rows(plan) -> list[tuple[str, str]]:
    return [(c.after["step"], c.node_ids[0]) for c in plan.changes]


# Plans -------------------------------------------------------------------------------------------


def test_migrate_plan_runs_the_window_then_time_3(host):  # noqa: F811
    plan = steps.build_plan(host.env, request("migrate"), "admin")
    a, b = "node-a", "node-b"
    assert rows(plan)[4:] == [
        (kmc.H_STOP, a),
        (kmc.D_FETCH_LEASES, b),
        (kmc.H_LEASES_IN, b),
        (kmc.H_START, b),
        (kmc.D_WAIT_PARTNER_DOWN, b),
        (kmc.H_INSTALL, a),
        (kmc.H_START, a),
        (kmc.D_WAIT_HA, a),
        (kmc.D_WAIT_HA, b),
        (kmc.H_DELAYS, b),
        (kmc.H_DELAYS, a),
        (kmc.H_FINISH, b),
        (kmc.H_FINISH, a),
    ]
    d = [c.after["details"] for c in plan.changes]
    assert d[4]["export_leases"] and d[4]["outage_start"] and d[4]["stage"] == "window"
    assert d[5]["from_node"] == a and d[5]["families"] == ["4"]  # node-a's d2 has no lease file
    assert d[8]["outage_end"] and d[9]["stage"] == "primary" and d[9]["direction"] == "target"
    # A time 3 that failed is resumed from the primary; a failed window is not resumed.
    resumed = steps.build_plan(host.env, request("migrate", stage="primary"), "admin")
    assert rows(resumed)[:3] == [(kmc.H_STOP, a), (kmc.H_INSTALL, a), (kmc.H_START, a)]
    with pytest.raises(ValueError, match="rolled back, not resumed"):
        steps.build_plan(host.env, request("migrate", stage="window"))


def test_backups_take_the_leases_and_start_after_the_standby(host):  # noqa: F811
    plan = steps.build_plan(host.env, request("migrate", nodes=[PRIMARY, STANDBY, BACKUP]), "admin")
    steps_c = [s for s, n in rows(plan) if n == "node-c"]
    assert steps_c == [
        kmc.H_STOP,
        kmc.H_INSTALL,
        kmc.D_FETCH_LEASES,
        kmc.H_LEASES_IN,
        kmc.H_START,
        kmc.H_DELAYS,
        kmc.H_FINISH,
    ]
    order = rows(plan)
    assert order.index((kmc.D_WAIT_PARTNER_DOWN, "node-b")) < order.index((kmc.H_START, "node-c"))
    with pytest.raises(ValueError, match="one HA pair"):
        steps.build_plan(host.env, request("migrate", nodes=[PRIMARY, BACKUP]))


def test_return_of_a_migrated_pair_mirrors_the_migration(host):  # noqa: F811
    plan = steps.build_plan(host.env, request("rollback", stage="done"), "admin")
    a, b = "node-a", "node-b"
    assert rows(plan) == [
        (kmc.H_MAINTENANCE, a),
        (kmc.H_STOP, b),
        (kmc.H_INSTALL, b),
        (kmc.H_STOP, a),
        (kmc.D_FETCH_LEASES, b),
        (kmc.H_LEASES_IN, b),
        (kmc.H_START, b),
        (kmc.D_WAIT_PARTNER_DOWN, b),
        (kmc.H_INSTALL, a),
        (kmc.H_START, a),
        (kmc.D_WAIT_HA, a),
        (kmc.D_WAIT_HA, b),
        (kmc.H_DELAYS, b),
        (kmc.H_DELAYS, a),
    ]
    d = [c.after["details"] for c in plan.changes]
    assert d[2]["direction"] == "previous" and d[2]["short_delays"] is True
    assert d[6]["restore"] is True and d[8]["direction"] == "previous" and "short_delays" not in d[8]


def test_return_after_a_failed_time_3_starts_with_the_primary(host):  # noqa: F811
    plan = steps.build_plan(host.env, request("rollback", stage="primary"), "admin")
    a, b = "node-a", "node-b"
    assert rows(plan)[:8] == [
        (kmc.H_STOP, a),
        (kmc.H_INSTALL, a),
        (kmc.H_STOP, b),
        (kmc.D_FETCH_LEASES, a),
        (kmc.H_LEASES_IN, a),
        (kmc.H_START, a),
        (kmc.D_WAIT_PARTNER_DOWN, a),
        (kmc.H_INSTALL, b),
    ]
    assert plan.changes[1].after["details"]["short_delays"] is True
    assert plan.changes[2].after["details"]["export_leases"] is True


def test_nodes_without_ha_restart_alone(host):  # noqa: F811
    single = {**PRIMARY, "role": "single"}
    plan = steps.build_plan(host.env, request("migrate", nodes=[single]), "admin")
    assert [s for s, _n in rows(plan)] == [
        kmc.H_STOP,
        kmc.H_INSTALL,
        kmc.H_START,
        kmc.D_WAIT_PARTNER_DOWN,
        kmc.H_FINISH,
    ]
    assert plan.changes[0].after["details"]["outage_start"] and plan.changes[3].after["details"]["single"]
    back = steps.build_plan(host.env, request("rollback", nodes=[single], touched=["node-a"]), "admin")
    assert [c.after["details"].get("direction") for c in back.changes][1] == "previous"
    with pytest.raises(ValueError, match="not both"):
        steps.build_plan(host.env, request("migrate", nodes=[single, STANDBY]))


# Lease files -------------------------------------------------------------------------------------


@pytest.fixture
def node(host):  # noqa: F811
    env = host.env
    env.paths.root.joinpath("usr/sbin").mkdir(parents=True)
    pk = Packages(host)
    steps.prepare(env, details(node=STANDBY))
    env.binaries["kea-lfc"] = None
    return env, pk


def lease_path(env) -> Path:
    path = sw.lease_file(env, "kea4")
    assert path is not None
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def test_export_merges_the_leftovers_in_kea_order(node):
    env, _pk = node
    path = lease_path(env)
    Path(f"{path}.2").write_text(HEADER + lease("192.0.2.10", 100))
    Path(f"{path}.1").write_text(HEADER + lease("192.0.2.10", 200))
    path.write_text(HEADER + lease("192.0.2.11", 300))
    out = sw.stop(env, switch_details(export_leases=True, engines=["kea4", "d2"]))
    copy = kmc.lease_copy_path(env.node_paths.var, MID, "4")
    assert copy.read_text() == HEADER + lease("192.0.2.10", 100) + lease("192.0.2.10", 200) + lease(
        "192.0.2.11", 300
    )
    assert out["leases"]["4"]["sha256"] == hashlib.sha256(copy.read_bytes()).hexdigest()
    assert oct(copy.stat().st_mode & 0o777) == "0o600"
    assert path.read_text() == HEADER + lease("192.0.2.11", 300)  # the node's own files are untouched


def test_export_uses_kea_lfc_when_it_is_there(node):
    env, _pk = node
    path = lease_path(env)
    path.write_text(HEADER + lease("192.0.2.10", 100) + lease("192.0.2.10", 200))
    env.binaries["kea-lfc"] = "/usr/sbin/kea-lfc"

    def lfc(argv):
        prev = Path(argv[argv.index("-x") + 1])
        prev.write_text(HEADER + lease("192.0.2.10", 200))
        return CommandResult(argv, 0, "", "")

    env.runner.responses["/usr/sbin/kea-lfc"] = lfc
    out = sw.stop(env, switch_details(export_leases=True, engines=["kea4"]))
    copy = kmc.lease_copy_path(env.node_paths.var, MID, "4")
    assert copy.read_text() == HEADER + lease("192.0.2.10", 200) and out["leases"]["4"]["size"] > 0
    lease_path(env).unlink()
    assert sw.stop(env, switch_details(export_leases=True, engines=["kea4"]))["leases"]["4"]["skipped"]


def received(env, data: str, source: str = "node-a", sha: str | None = None) -> None:
    mdir = kmc.migration_dir(env.node_paths.var, MID)
    (mdir / kmc.received_name("4")).write_text(data)
    meta = {
        "from_node": source,
        "sha256": sha or hashlib.sha256(data.encode()).hexdigest(),
        "size": len(data),
    }
    (mdir / kmc.received_meta_name("4")).write_text(json.dumps(meta))


def test_leases_in_replaces_the_file_and_keeps_the_old_one(node):
    env, _pk = node
    path = lease_path(env)
    path.write_text(HEADER + lease("192.0.2.50", 1))
    Path(f"{path}.2").write_text(HEADER + lease("192.0.2.51", 1))
    data = HEADER + lease("192.0.2.10", 500)
    received(env, data)
    d = switch_details(from_node="node-a", families=["4"])
    out = sw.leases_in(env, d)
    assert path.read_text() == data and not Path(f"{path}.2").exists()
    assert out["leases"]["4"]["path"] == str(path)
    keep = kmc.state_dir(env.node_paths, MID) / "private/leases4-before"
    assert (keep / path.name).read_text() == HEADER + lease("192.0.2.50", 1)
    assert (keep / f"{path.name}.2").exists()
    # A copy changed after its fetch, from another node, or Kea running: refused.
    received(env, data, sha="0" * 64)
    with pytest.raises(sw.SwitchError, match="changed since it was fetched"):
        sw.leases_in(env, d)
    received(env, data, source="node-c")
    with pytest.raises(sw.SwitchError, match="does not come from"):
        sw.leases_in(env, d)
    received(env, "not,a,lease,file\n")
    with pytest.raises(sw.SwitchError, match="not a Kea lease file"):
        sw.leases_in(env, d)
    env.service_manager.units.add("isc-kea-dhcp4-server.service")
    env.service_manager.active.add("isc-kea-dhcp4-server.service")
    with pytest.raises(sw.SwitchError, match="stop step comes first"):
        sw.leases_in(env, d)
    # A copy the service user turned into a link to a root file is never read.
    env.service_manager.active.clear()
    received(env, data)
    mdir = kmc.migration_dir(env.node_paths.var, MID)
    secret = env.paths.root / "secret"
    secret.write_text(data)
    (mdir / kmc.received_name("4")).unlink()
    (mdir / kmc.received_name("4")).symlink_to(secret)
    with pytest.raises(sw.SwitchError, match="cannot be read safely"):
        sw.leases_in(env, d)


# Delays and finish -------------------------------------------------------------------------------


def test_delays_put_the_file_back_exactly_and_wait_for_the_pair(node, monkeypatch):
    env, _pk = node
    monkeypatch.setattr(sw, "_sleep", lambda _s: None)
    sw.install(env, switch_details(direction="target"))
    conf = env.paths.kea_conf("kea-dhcp4")
    mdir = kmc.state_dir(env.node_paths, MID)
    converted = (mdir / "private/target/kea-dhcp4.conf").read_text()
    [rel] = sw.mig.ha_relationships(json.loads(conf.read_text()), "kea4")
    assert rel["max-response-delay"] == 8000
    server = rel["this-server-name"]
    st = status("hot-standby")
    st["arguments"]["high-availability"][0]["ha-servers"]["local"]["server-name"] = server
    kea = Kea(env, [st])
    out = sw.delays(env, switch_details(engines=["kea4", "d2"]))
    assert conf.read_text() == converted
    assert kea.sent[0] == "config-reload" and "normal state" in out["delays"]["kea4"]
    assert "delays" not in sw._state(mdir) or not sw._state(mdir)["delays"]
    assert sw.delays(env, switch_details(engines=["kea4"]))["note"]


def test_return_with_short_delays_then_delays_gives_the_2_6_file_back(node, monkeypatch):
    env, _pk = node
    monkeypatch.setattr(sw, "_sleep", lambda _s: None)
    conf = env.paths.kea_conf("kea-dhcp4")
    original = conf.read_bytes()
    sw.install(env, switch_details(direction="target"))
    sw.install(env, switch_details(direction="previous", short_delays=True))
    [rel] = sw.mig.ha_relationships(sw._load(conf), "kea4")
    assert rel["max-response-delay"] == 8000 and rel["max-unacked-clients"] == 0
    st = status("hot-standby")
    st["arguments"]["high-availability"][0]["ha-servers"]["local"]["server-name"] = rel["this-server-name"]
    Kea(env, [st])
    sw.delays(env, switch_details(engines=["kea4"]))
    assert conf.read_bytes() == original


def test_finish_keeps_what_the_return_needs(node):
    env, _pk = node
    mdir = kmc.state_dir(env.node_paths, MID)
    out = sw.finish(env, switch_details())
    assert "private/target" in out["removed"] and not (mdir / "private/target").exists()
    assert (mdir / "private/before").is_dir() and any((mdir / "packages/previous").iterdir())
    assert (mdir / "manifest.json").is_file()
