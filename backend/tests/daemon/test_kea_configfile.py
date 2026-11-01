# SPDX-License-Identifier: Apache-2.0
"""Real kea-dhcp4 running from a commented file tree with <?include?>: plans write back into the file
that defines the element, a hand edit blocks writes until "adopt file" or "adopt running", both with
rollback, and the API answers 409 config_divergence meanwhile. A commented file is split into an
include tree, or its comments ride into user-context before config-write, on one server and an HA pair."""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import pytest

from pelagos.connectors.base import ConnectorContext
from pelagos.connectors.kea.backend import KeaBackend
from pelagos.connectors.kea.configfile import FileDiverged
from pelagos.core.keadoc import KeaDocument
from pelagos.core.keafile import kea_config_differences
from pelagos.domain import Change, ChangeOp, Family, PlanState, Pool, Reservation, ReservationIdType, Subnet
from tests.daemon.api_node import V1, apply, login, make_app, make_node, planned
from tests.fixtures import kea as kea_fx

pytestmark = pytest.mark.daemon


def split_into_includes(daemon: kea_fx.KeaDaemon) -> tuple[Path, Path]:
    """Rewrites the fixture's config as a commented main file whose subnets live in an included file,
    then has Kea reload it, so the daemon runs from the tree."""
    cfg = json.loads(daemon.config_path.read_text())
    body = cfg["Dhcp4"]
    subnets = body.pop("subnet4")
    part = daemon.root / "subnets4.json"
    part.write_text(
        "// subnets of the lab, one per object\n"
        + ",\n".join(json.dumps(s, indent=2) for s in subnets)
        + "\n"
    )
    lines = [f"    {json.dumps(k)}: {json.dumps(v)}," for k, v in body.items()]
    main = (
        "// Lab DHCPv4 server: hand-written, with comments\n"
        '{\n  "Dhcp4": {\n'
        + "\n".join(lines)
        + "\n    # the subnets are kept apart\n"
        + f'    "subnet4": [\n      <?include "{part}"?>\n    ]\n'
        + "  }\n}\n"
    )
    daemon.config_path.write_text(main)
    binary = kea_fx.find_binary("kea-dhcp4")
    check = subprocess.run(
        [binary, "-t", str(daemon.config_path)],
        capture_output=True,
        text=True,
        env=kea_fx.kea_env(daemon.root),
        check=False,
    )
    assert check.returncode == 0, check.stdout + check.stderr
    daemon.ok("config-reload")
    return daemon.config_path, part


def backend_for(daemon: kea_fx.KeaDaemon, tmp_root: Path) -> KeaBackend:
    ctx = ConnectorContext(
        node_id="n1",
        engine_config={
            "socket_dir": str(daemon.socket_path.parent),
            "dhcp4_socket": daemon.socket_path.name,
            "dhcp4_conf": str(daemon.config_path),
        },
        backup_root=tmp_root / "backups",
        get_secret=lambda name: None,
        settings={},
    )
    return KeaBackend(ctx, Family.V4)


def reads_as_running(backend: KeaBackend) -> list[str]:
    return kea_config_differences(KeaDocument(backend.conf_path).value, {"Dhcp4": backend.config_get()})


def test_plans_write_into_the_included_file(kea_dhcp4, tmp_root):
    main, part = split_into_includes(kea_dhcp4)
    backend = backend_for(kea_dhcp4, tmp_root)
    main_before = main.read_text()
    subnet = Subnet(
        id=7, subnet="198.51.100.0/24", family=Family.V4, pools=[Pool(pool="198.51.100.10 - 198.51.100.20")]
    )
    plan = backend.plan_subnet_change(Change(ChangeOp.ADD, "subnet4/7", after=subnet.to_dict()))
    assert plan.state is PlanState.VALIDATED, plan.error
    result = backend.apply(plan)
    assert result.ok, result.message
    assert "patched subnets4.json" in result.message and "config-write" not in result.message
    # The new subnet went into the file that holds the subnets; the main file did not move.
    assert main.read_text() == main_before
    text = part.read_text()
    assert text.startswith("// subnets of the lab") and "198.51.100.0/24" in text
    assert reads_as_running(backend) == []
    # A global value lives in the main file: the edit lands there, comments and include kept.
    plan = backend.plan_global_change([Change(ChangeOp.REPLACE, "valid-lifetime", after=1800)])
    assert backend.apply(plan).ok
    text = main.read_text()
    assert '"valid-lifetime": 1800' in text and "# the subnets are kept apart" in text and "<?include" in text
    # Kea itself still loads the tree and runs what the files say.
    kea_dhcp4.ok("config-reload")
    assert reads_as_running(backend) == []
    assert backend.config_get()["valid-lifetime"] == 1800
    assert any(s["id"] == 7 for s in backend.config_get()["subnet4"])
    # Rollback of the global change writes the files back too.
    assert backend.rollback(plan).ok
    assert '"valid-lifetime": 3600' in main.read_text() and reads_as_running(backend) == []


def test_a_subnet_value_written_in_the_file_survives_a_global_change(kea_dhcp4, tmp_root):
    main, part = split_into_includes(kea_dhcp4)
    text = part.read_text()
    assert text.count('"id": 1,') == 1
    part.write_text(text.replace('"id": 1,', '"id": 1,\n  "valid-lifetime": 3600, // its own value'))
    kea_dhcp4.ok("config-reload")
    backend = backend_for(kea_dhcp4, tmp_root)
    plan = backend.plan_global_change([Change(ChangeOp.REPLACE, "valid-lifetime", after=1800)])
    result = backend.apply(plan)
    assert result.ok, result.message
    assert '"valid-lifetime": 1800' in main.read_text()
    assert '"valid-lifetime": 3600, // its own value' in part.read_text()
    assert reads_as_running(backend) == []
    kea_dhcp4.ok("config-reload")
    cfg = backend.config_get()
    assert cfg["valid-lifetime"] == 1800
    assert next(s for s in cfg["subnet4"] if s["id"] == 1)["valid-lifetime"] == 3600


def test_hand_edit_blocks_until_adopt_running(kea_dhcp4, tmp_root):
    main, _part = split_into_includes(kea_dhcp4)
    backend = backend_for(kea_dhcp4, tmp_root)
    main.write_text(
        main.read_text().replace('"valid-lifetime": 3600', '"valid-lifetime": 7200 /* by hand */')
    )
    with pytest.raises(FileDiverged, match="valid-lifetime"):
        backend.plan_global_change([Change(ChangeOp.REPLACE, "renew-timer", after=900)])
    plan = backend.plan_adopt("running")
    assert plan.requires_confirmation and plan.state is PlanState.VALIDATED
    assert '-    "valid-lifetime": 7200' in plan.diff and '+    "valid-lifetime": 3600' in plan.diff
    result = backend.apply(plan)
    assert result.ok, result.message
    text = main.read_text()
    assert '"valid-lifetime": 3600' in text and "/* by hand */" in text and "<?include" in text
    assert reads_as_running(backend) == []
    # Writes work again; the rollback of the adopt puts the hand edit back.
    assert (
        backend.plan_global_change([Change(ChangeOp.REPLACE, "renew-timer", after=900)]).state
        is PlanState.VALIDATED
    )
    assert backend.rollback(plan).ok
    assert '"valid-lifetime": 7200' in main.read_text()


def test_adopt_file_runs_the_file_and_rolls_back(kea_dhcp4, tmp_root):
    _main, part = split_into_includes(kea_dhcp4)
    backend = backend_for(kea_dhcp4, tmp_root)
    part.write_text(part.read_text().replace("192.0.2.100 - 192.0.2.199", "192.0.2.120 - 192.0.2.150"))
    plan = backend.plan_adopt("file")
    assert plan.validations[0].tool == "config-test" and plan.validations[0].ok
    assert "pool" in plan.diff
    result = backend.apply(plan)
    assert result.ok, result.message
    pool = backend.config_get()["subnet4"][0]["pools"][0]["pool"]
    assert pool.replace(" ", "") == "192.0.2.120-192.0.2.150"
    assert reads_as_running(backend) == []
    assert backend.rollback(plan).ok
    assert (
        backend.config_get()["subnet4"][0]["pools"][0]["pool"].replace(" ", "") == "192.0.2.100-192.0.2.199"
    )


def test_rollback_refused_after_a_later_change(kea_dhcp4, tmp_root):
    backend = backend_for(kea_dhcp4, tmp_root)
    first = backend.plan_global_change([Change(ChangeOp.REPLACE, "valid-lifetime", after=1200)])
    assert backend.apply(first).ok
    second = backend.plan_global_change([Change(ChangeOp.REPLACE, "renew-timer", after=600)])
    assert backend.apply(second).ok
    from pelagos.connectors.base import PreconditionFailed

    with pytest.raises(PreconditionFailed):
        backend.rollback(first)
    assert backend.rollback(second).ok and backend.rollback(first).ok


def test_api_blocks_with_409_then_adopt_unblocks(tmp_root, kea_dhcp4):
    ctx = make_node(tmp_root / "node", dhcp4=kea_dhcp4)
    client = login(make_app(ctx))
    try:
        path = kea_dhcp4.config_path
        cfg = json.loads(path.read_text())
        cfg["Dhcp4"]["valid-lifetime"] = 4800
        path.write_text("// edited by hand\n" + json.dumps(cfg, indent=2))
        status = client.get(f"{V1}/dhcp/v4/config/file").get_json()["items"][0]
        assert status["diverged"] is True and status["node_id"] == ctx.node.id
        body = {"changes": [{"op": "replace", "target": "valid-lifetime", "after": 900}]}
        r = client.post(f"{V1}/dhcp/v4/options/plan", json=body)
        assert r.status_code == 409 and r.get_json()["code"] == "config_divergence", r.get_json()
        plan = planned(client.post(f"{V1}/dhcp/v4/config/adopt/plan", json={"source": "running"}))
        assert plan["requires_confirmation"] and "4800" in plan["diff"]
        result = apply(client, plan, confirm=True)
        assert result["state"] == "applied", result
        assert path.read_text().startswith("// edited by hand")
        assert client.get(f"{V1}/dhcp/v4/config/file").get_json()["items"][0]["diverged"] is False
        plan = planned(client.post(f"{V1}/dhcp/v4/options/plan", json=body))
        assert apply(client, plan)["state"] == "applied"
    finally:
        from pelagos.services.container import Services

        Services.of(ctx).close()


# B1-KEACOMMENTS: a commented file without includes -------------------------------------------------


def commented(daemon: kea_fx.KeaDaemon) -> Path:
    """The fixture's config rewritten by hand: a header, a comment above the subnet and one closing
    the reservation's line; Kea reloads it."""
    path = daemon.config_path
    text = path.read_text()
    text = "// Lab DHCPv4 server, written by hand\n" + text
    text = text.replace('"subnet4": [\n', '"subnet4": [\n      // office LAN\n', 1)
    text = re.sub(r'("hostname": "printer"\n\s*})', r"\1 // the printer", text, count=1)
    assert "// the printer" in text and "// office LAN" in text
    path.write_text(text)
    daemon.ok("config-reload")
    return path


def reservation(mac: str, ip: str) -> Change:
    res = Reservation(subnet_id=1, id_type=ReservationIdType.HW_ADDRESS, identifier=mac, ip_address=ip)
    return Change(ChangeOp.ADD, f"subnet4/1/reservations/hw-address={mac}", after=res.to_dict())


def kea_check(daemon: kea_fx.KeaDaemon) -> None:
    binary = kea_fx.find_binary(daemon.name)
    check = subprocess.run(
        [binary, "-t", str(daemon.config_path)],
        capture_output=True,
        text=True,
        env=kea_fx.kea_env(daemon.root),
        check=False,
    )
    assert check.returncode == 0, check.stdout + check.stderr


def split(daemon: kea_fx.KeaDaemon) -> dict[Path, str]:
    """What import/kea4/include-tree writes, then a reload: the daemon runs from the tree."""
    tree = KeaDocument(daemon.config_path).include_tree("Dhcp4", daemon.root / "kea4.d")
    for p, text in tree.items():
        p.parent.mkdir(exist_ok=True)
        p.write_text(text)
    kea_check(daemon)
    daemon.ok("config-reload")
    return tree


def comments_of(path: Path) -> list[str]:
    return [c.text for c in KeaDocument(path).comments]


def test_include_tree_keeps_comments_across_a_reservation(kea_dhcp4, tmp_root):
    main = commented(kea_dhcp4)
    before = kea_dhcp4.ok("config-get")
    tree = split(kea_dhcp4)
    assert len(tree) > 1 and "<?include" in main.read_text()
    # The running configuration did not move.
    assert kea_dhcp4.ok("config-get") == before
    backend = backend_for(kea_dhcp4, tmp_root)
    plan = backend.plan_reservation_change(reservation("aa:bb:cc:dd:ee:42", "192.0.2.42"))
    assert plan.state is PlanState.VALIDATED, plan.validations
    result = backend.apply(plan)
    assert result.ok, result.message
    assert "patched subnet4.json" in result.message and "config-write" not in result.message
    assert {"Lab DHCPv4 server, written by hand", "office LAN", "the printer"} <= set(comments_of(main))
    assert "aa:bb:cc:dd:ee:42" in (kea_dhcp4.root / "kea4.d/subnet4.json").read_text()
    kea_check(kea_dhcp4)
    kea_dhcp4.ok("config-reload")
    assert reads_as_running(backend) == []
    subnet = backend.config_get()["subnet4"][0]
    assert any(r["hw-address"] == "aa:bb:cc:dd:ee:42" for r in subnet["reservations"])
    assert "comment" not in subnet["user-context"]["pelagos"]


def test_config_write_carries_comments_into_user_context(kea_dhcp4, tmp_root):
    main = commented(kea_dhcp4)
    backend = backend_for(kea_dhcp4, tmp_root)
    plan = backend.plan_reservation_change(reservation("aa:bb:cc:dd:ee:43", "192.0.2.43"))
    result = backend.apply(plan)
    assert result.ok, result.message
    assert "config-write" in result.message
    body = backend.config_get()
    assert body["user-context"]["pelagos"]["comment"] == "Lab DHCPv4 server, written by hand"
    subnet = body["subnet4"][0]
    # Pelagos metadata already there stays next to the comment.
    assert subnet["user-context"]["pelagos"]["notes"] == "fixture subnet"
    assert subnet["user-context"]["pelagos"]["comment"] == "office LAN"
    printer = next(r for r in subnet["reservations"] if r["hw-address"] == "aa:bb:cc:dd:ee:01")
    assert printer["user-context"]["pelagos"]["comment"] == "the printer"
    # Kea's own file now holds them, reads back as what runs and reloads.
    assert comments_of(main) == [] and '"comment": "office LAN"' in main.read_text()
    assert reads_as_running(backend) == []
    kea_dhcp4.ok("config-reload")
    # Copying again changes nothing: the next write is a plain config-write.
    again = backend.apply(backend.plan_reservation_change(reservation("aa:bb:cc:dd:ee:44", "192.0.2.44")))
    assert again.ok and "comments copied" not in again.message
    assert backend.config_get()["subnet4"][0]["user-context"]["pelagos"]["comment"] == "office LAN"
    assert backend.rollback(again).ok and backend.rollback(plan).ok
    assert "// office LAN" in main.read_text()


def test_ha_pair_copies_the_same_comments_and_never_config_writes_a_tree(tmp_root):
    from pelagos.collector import kea_shared
    from tests.daemon.test_kea_ha import ha_config, local_state
    from tests.fixtures.ports import free_port, wait_for

    hooks = kea_fx.kea_hooks_dir()
    assert hooks is not None
    ports = [free_port(), free_port()]
    daemons: list[kea_fx.KeaDaemon] = []
    try:
        for i in (1, 2):
            root = tmp_root / f"ha{i}"
            daemons.append(kea_fx.start_kea("kea-dhcp4", root, ha_config(root, hooks, i, ports)))

        def serving() -> bool:
            return all(local_state(d) == "hot-standby" for d in daemons)

        wait_for(serving, timeout=30, what="HA hot-standby")
        for d in daemons:
            commented(d)
        backends = [backend_for(d, tmp_root / f"n{i}") for i, d in enumerate(daemons, 1)]

        def same_on_both() -> None:
            bodies = [b.config_get() for b in backends]
            assert (
                kea_shared.shared_hashes({"Dhcp4": bodies[0]})["relationships"][0]["hash"]
                == (kea_shared.shared_hashes({"Dhcp4": bodies[1]})["relationships"][0]["hash"])
            )
            notes = [[s.get("user-context") for s in b["subnet4"]] + [b.get("user-context")] for b in bodies]
            assert notes[0] == notes[1]

        # Without includes: config-set then config-write on each partner, comments in user-context.
        change = reservation("aa:bb:cc:dd:ee:45", "192.0.2.45")
        for b in backends:
            result = b.apply(b.plan_reservation_change(change))
            assert result.ok, result.message
            assert "config-write" in result.message
        wait_for(serving, timeout=60, what="HA back to hot-standby")
        same_on_both()
        assert backends[0].config_get()["subnet4"][0]["user-context"]["pelagos"]["comment"] == "office LAN"

        # With includes: the files are patched, config-write never runs on the tree.
        for d in daemons:
            d.config_path.write_text("// pair member\n" + d.config_path.read_text())
            d.ok("config-reload")
            split(d)
        change = reservation("aa:bb:cc:dd:ee:46", "192.0.2.46")
        for d, b in zip(daemons, backends, strict=True):
            result = b.apply(b.plan_reservation_change(change))
            assert result.ok, result.message
            assert "config-write" not in result.message
            assert "<?include" in d.config_path.read_text() and "pair member" in comments_of(d.config_path)
            assert reads_as_running(b) == []
        wait_for(serving, timeout=60, what="HA back to hot-standby")
        same_on_both()
    finally:
        for d in daemons:
            d.stop()


def test_a_whole_configuration_replace_carries_the_comments_in_one_config_set(kea_dhcp4, tmp_root):
    """The reconciliation of a partial apply replaces the configuration with what another server
    shares (no user-context of this one): the comments of this server's file ride on that config-set."""
    commented(kea_dhcp4)
    backend = backend_for(kea_dhcp4, tmp_root)
    overlay = backend.config_get()
    overlay["valid-lifetime"] = 2400
    for subnet in overlay["subnet4"]:
        subnet.pop("user-context", None)
    result = backend.apply(backend.plan_config_replace(overlay))
    assert result.ok, result.message
    assert "config-set" in result.message and "comments copied" not in result.message
    body = backend.config_get()
    assert body["valid-lifetime"] == 2400
    assert body["subnet4"][0]["user-context"] == {"pelagos": {"comment": "office LAN"}}
    assert reads_as_running(backend) == []
