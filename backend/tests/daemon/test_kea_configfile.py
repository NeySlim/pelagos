# SPDX-License-Identifier: Apache-2.0
"""Real kea-dhcp4 running from a commented file tree with <?include?>: plans write back into the file
that defines the element, a hand edit blocks writes until "adopt file" or "adopt running", both with
rollback, and the API answers 409 config_divergence meanwhile."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from pelagos.connectors.base import ConnectorContext
from pelagos.connectors.kea.backend import KeaBackend
from pelagos.connectors.kea.configfile import FileDiverged
from pelagos.core.keadoc import KeaDocument
from pelagos.core.keafile import kea_config_differences
from pelagos.domain import Change, ChangeOp, Family, PlanState, Pool, Subnet
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
