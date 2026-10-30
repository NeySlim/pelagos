# SPDX-License-Identifier: Apache-2.0
"""Time 1 of the Kea migration on a node and its return (section 28, batch K4): the plans the helper
builds, Kea stopped, the prepared packages and converted files installed and checked, the partner's
files checked here, HA maintenance on the serving peer, and the exact 2.6 side given back (fake
package tools, daemons and sockets)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pelagos.core import kea_migration as kmc
from pelagos.core.secrets import SecretBox, SecretError, generate_master_key
from pelagos.installer import kea_migration_steps as steps
from pelagos.installer import kea_migration_switch as sw
from pelagos.platform import CommandResult
from tests.unit.installer.test_kea_migration import ISC
from tests.unit.installer.test_kea_migration_prepare import MID, details, host, not_really_root  # noqa: F401

pytestmark = pytest.mark.unit

PRIMARY = {"node_id": "node-a", "name": "ns1", "role": "primary", "order": 2, "engines": ["kea4", "d2"]}
STANDBY = {"node_id": "node-b", "name": "ns2", "role": "standby", "order": 1, "engines": ["kea4"]}


def request(phase: str, **over) -> dict:
    return {
        "phase": phase,
        "migration_id": MID,
        "series": "3.2",
        "source": "isc",
        "target_version": "3.2.1",
        "from_series": "2.6",
        "nodes": [PRIMARY, STANDBY],
        "options": {"response_delay_milliseconds": 8000, "auto_rollback": True},
        **over,
    }


def test_migrate_plan_is_time_1_on_the_standby(host):  # noqa: F811
    plan = steps.build_plan(host.env, request("migrate"), "admin")
    assert [c.target for c in plan.changes[:4]] == [
        kmc.target(kmc.H_MAINTENANCE, "node-a"),
        kmc.target(kmc.H_STOP, "node-b"),
        kmc.target(kmc.H_INSTALL, "node-b"),
        kmc.target(kmc.H_VALIDATE_PARTNER, "node-b"),
    ]
    d = [c.after["details"] for c in plan.changes[:4]]
    assert d[0]["action"] == "start" and d[2]["direction"] == "target" and d[3]["partner"] == "node-a"
    assert all(x["stage"] == "standby" and x["options"]["response_delay_milliseconds"] == 8000 for x in d)
    assert plan.requires_confirmation and plan.summary_message["key"] == "plan.kea_migration.migrate"
    with pytest.raises(ValueError, match="one HA pair"):
        steps.build_plan(host.env, request("migrate", nodes=[PRIMARY]))
    with pytest.raises(ValueError, match="1000 to 60000"):
        steps.build_plan(host.env, request("migrate", options={"response_delay_milliseconds": 10}))


def test_rollback_plan_returns_the_touched_standby_then_resumes_the_pair(host):  # noqa: F811
    plan = steps.build_plan(host.env, request("rollback", touched=["node-b"]), "admin")
    assert [c.after["step"] for c in plan.changes] == [
        kmc.H_STOP,
        kmc.H_INSTALL,
        kmc.H_START,
        kmc.H_START,
        kmc.H_MAINTENANCE,
    ]
    assert plan.changes[1].after["details"]["direction"] == "previous"
    assert plan.changes[2].after["details"]["restore"] is True
    assert plan.changes[4].after["details"]["action"] == "cancel"
    untouched = steps.build_plan(host.env, request("rollback", touched=[]), "admin")
    assert [c.after["step"] for c in untouched.changes] == [kmc.H_START, kmc.H_MAINTENANCE]


# A node prepared for real (fake package tools), then switched ---------------------------------


class Packages:
    """dpkg-query and apt-get over a mutable set of installed packages."""

    def __init__(self, host) -> None:  # noqa: F811
        self.installed = {
            "kea-common": "2.6.3-1+deb13u1",
            "kea-dhcp4-server": "2.6.3-1+deb13u1",
            "kea-dhcp-ddns-server": "2.6.3-1+deb13u1",
            "kea-ctrl-agent": "2.6.3-1+deb13u1",
            "python3-kea-connector": "2.6.3-1+deb13u1",
        }
        self.apt: list[list[str]] = []
        self.policy_seen: list[bool] = []
        self.fail = False
        self.host = host
        r = host.env.runner.responses
        r["dpkg-query -W"] = lambda argv: CommandResult(argv, 0, self.query(argv), "")
        previous = r["apt-get"]
        r["apt-get"] = lambda argv: self.apt_get(argv) if "--no-download" in argv else previous(argv)
        r["dpkg-statoverride --list"] = lambda argv: CommandResult(argv, 0, self.overrides(), "")
        self.statoverrides = ["root root 0755 /usr/sbin/kea-lfc"]

    def query(self, argv: list[str]) -> str:
        if any("Conffiles" in a for a in argv):
            return " /etc/kea/radius/dictionary 6485e4ee\n /etc/kea/kea-dhcp4.conf 621da868 obsolete\n"
        return "".join(f"{n}\t{v}\tii \n" for n, v in self.installed.items())

    def overrides(self) -> str:
        return "".join(line + "\n" for line in self.statoverrides)

    def apt_get(self, argv: list[str]) -> CommandResult:
        self.apt.append(argv)
        self.policy_seen.append((self.host.env.paths.root / sw.POLICY_RC).exists())
        if self.fail:
            return CommandResult(argv, 100, "", "E: broken")
        for arg in argv[argv.index("install") + 1 :]:
            if arg.endswith("-"):
                self.installed.pop(arg[:-1], None)
            elif "=" in arg:
                name, version = arg.split("=", 1)
                self.installed[name] = version
            elif arg.endswith(".deb"):
                name, version = Path(arg).name.split("_")[:2]
                self.installed[name] = version
        if any(a.startswith("isc-kea-common=") for a in argv):
            self.statoverrides.append("_kea _kea 0750 /etc/kea")
        return CommandResult(argv, 0, "", "")


@pytest.fixture
def node(host):  # noqa: F811
    env = host.env
    env.paths.root.joinpath("usr/sbin").mkdir(parents=True)
    pk = Packages(host)
    steps.prepare(env, details(node=STANDBY))
    return env, pk


def switch_details(**over) -> dict:
    return {
        "migration_id": MID,
        "phase": "migrate",
        "stage": "standby",
        "node": STANDBY,
        "engines": ["kea4"],
        "options": {"response_delay_milliseconds": 8000},
        **over,
    }


def kea_files(env) -> dict[str, bytes]:
    d = env.paths.kea_conf_dir
    return {str(p.relative_to(d)): p.read_bytes() for p in sorted(d.rglob("*")) if p.is_file()}


def test_stop_notes_the_units_once(node):
    env, _pk = node
    services = env.service_manager
    services.units |= {"kea-dhcp4-server.service", "kea-ctrl-agent.service"}
    services.active |= {"kea-dhcp4-server.service", "kea-ctrl-agent.service"}
    out = sw.stop(env, switch_details())
    assert sorted(out["stopped"]) == ["kea-ctrl-agent.service", "kea-dhcp4-server.service"]
    assert not services.active
    sw.stop(env, switch_details())  # again (the return): the first notes stay
    state = sw._state(kmc.migration_dir(env.node_paths.var, MID))
    assert state["units_before"]["kea-dhcp4-server.service"] == {"active": True, "enabled": True}


def test_install_target_then_previous_gives_the_2_6_side_back(node):
    env, pk = node
    before = kea_files(env)
    apparmor = env.paths.root / "etc/apparmor.d"
    apparmor.mkdir(parents=True)
    (apparmor / "usr.sbin.kea-dhcp4").write_text("profile")
    out = sw.install(env, switch_details(direction="target"))
    [apt] = pk.apt
    assert "--no-download" in apt and f"isc-kea-dhcp4={ISC}" in apt and "kea-dhcp4-server-" in apt
    assert pk.policy_seen == [True] and not (env.paths.root / sw.POLICY_RC).exists()
    assert pk.installed["isc-kea-dhcp4"] == ISC and "kea-dhcp4-server" not in pk.installed
    assert out["version"] == "3.2.1"
    conf = json.loads(env.paths.kea_conf("kea-dhcp4").read_text())
    [rel] = sw.mig.ha_relationships(conf, "kea4")
    assert rel["max-response-delay"] == 8000 and rel["max-unacked-clients"] == 0
    assert (apparmor / "disable/usr.sbin.kea-dhcp4").is_symlink()
    checked = env.runner.commands("runuser")
    assert any("kea-dhcp4 -T" in c and str(env.paths.kea_conf("kea-dhcp4")) in c for c in checked)
    # The return; files the target packages and dpkg left in /etc/kea go too.
    conf = env.paths.kea_conf_dir
    (conf / "radius").mkdir()
    (conf / "radius/dictionary").write_text("isc")
    (conf / "kea-dhcp4.conf.dpkg-dist").write_text("debian")
    out = sw.install(env, switch_details(direction="previous"))
    back = pk.apt[-1]
    assert "--allow-downgrades" in back and "isc-kea-dhcp4-" in back
    assert any(a.endswith(".deb") and "kea-dhcp4-server_2.6.3" in a for a in back)
    assert pk.installed["kea-dhcp4-server"] == "2.6.3-1+deb13u1" and "isc-kea-dhcp4" not in pk.installed
    assert kea_files(env) == before
    assert not (apparmor / "disable/usr.sbin.kea-dhcp4").exists()
    assert env.runner.commands("dpkg-statoverride --remove /etc/kea")
    assert not (env.paths.root / "etc/apt/sources.list.d/isc-kea-3-2.list").exists()


def test_install_refuses_while_kea_runs_and_a_changed_file(node):
    env, pk = node
    env.service_manager.units.add("kea-dhcp4-server.service")
    env.service_manager.active.add("kea-dhcp4-server.service")
    with pytest.raises(sw.SwitchError, match="stop step comes first"):
        sw.install(env, switch_details(direction="target"))
    env.service_manager.active.clear()
    target = kmc.migration_dir(env.node_paths.var, MID) / "private/target/kea-dhcp4.conf"
    target.write_text(target.read_text() + " ")
    with pytest.raises(sw.SwitchError, match="changed since the prepare"):
        sw.install(env, switch_details(direction="target"))
    pk.fail = True
    with pytest.raises(sw.SwitchError, match="previous packages not installed"):
        sw.install(env, switch_details(direction="previous"))


# HA maintenance on the serving peer ------------------------------------------------------------


def ha_conf(env) -> None:
    cfg = {
        "Dhcp4": {
            "control-socket": {"socket-type": "unix", "socket-name": str(env.paths.kea_socket_dir / "s4")},
            "hooks-libraries": [
                {
                    "library": "libdhcp_ha.so",
                    "parameters": {
                        "high-availability": [
                            {
                                "this-server-name": "ns1",
                                "mode": "hot-standby",
                                "heartbeat-delay": 1000,
                                "max-response-delay": 2000,
                                "peers": [
                                    {"name": "ns1", "role": "primary", "url": "https://192.0.2.1:8001/"},
                                    {"name": "ns2", "role": "standby", "url": "https://192.0.2.2:8001/"},
                                ],
                            }
                        ]
                    },
                }
            ],
        }
    }
    env.paths.kea_conf_dir.mkdir(parents=True, exist_ok=True)
    env.paths.kea_conf("kea-dhcp4").write_text(json.dumps(cfg))


def status(state: str, remote: str = "hot-standby", in_touch: bool = True) -> dict:
    servers = {
        "local": {"server-name": "ns1", "state": state},
        "remote": {"server-name": "ns2", "last-state": remote, "in-touch": in_touch},
    }
    return {"result": 0, "arguments": {"high-availability": [{"ha-servers": servers}]}}


class Kea:
    def __init__(self, env, states: list[dict]) -> None:
        self.states = states
        self.sent: list[str] = []
        env.tools.kea_command = self.command

    def command(self, sock, command, arguments=None):
        self.sent.append(command)
        if command == "status-get":
            return self.states.pop(0) if len(self.states) > 1 else self.states[0]
        return {"result": 0, "text": f"{command} done"}


@pytest.fixture
def primary(host, monkeypatch):  # noqa: F811
    monkeypatch.setattr(sw, "_sleep", lambda _s: None)
    ha_conf(host.env)
    return host.env


def test_maintenance_start_needs_the_pair_normal(primary):
    kea = Kea(primary, [status("hot-standby")])
    out = sw.maintenance(primary, {"action": "start", "engines": ["kea4", "d2"]}, "plan-1")
    assert kea.sent == ["status-get", "ha-maintenance-start"] and out["engines"] == ["kea4"]
    assert sw.ha_maintenance.active(primary.node_paths, "kea4")
    Kea(primary, [status("partner-down", "unavailable", False)])
    assert (
        "already serving alone"
        in sw.maintenance(primary, {"action": "start", "engines": ["kea4"]})["ha"]["kea4"]
    )
    Kea(primary, [status("waiting")])
    with pytest.raises(sw.SwitchError, match="not in its normal state"):
        sw.maintenance(primary, {"action": "start", "engines": ["kea4"]})


def test_maintenance_cancel_waits_for_the_pair(primary):
    kea = Kea(primary, [status("partner-in-maintenance", "in-maintenance"), status("hot-standby")])
    out = sw.maintenance(primary, {"action": "cancel", "engines": ["kea4"]})
    assert "ha-maintenance-cancel" in kea.sent and "normal state" in out["ha"]["kea4"]
    assert not sw.ha_maintenance.active(primary.node_paths, "kea4")
    # A partner that restarted: nothing to cancel, the pair negotiates; a pair that never comes back fails.
    kea = Kea(primary, [status("partner-down", "unavailable", False), status("hot-standby")])
    sw.maintenance(primary, {"action": "cancel", "engines": ["kea4"]})
    assert "ha-maintenance-cancel" not in kea.sent
    Kea(primary, [status("partner-down", "unavailable", False)])
    clock = iter(range(0, 10_000, 100))
    sw_time = sw.time.monotonic
    try:
        sw.time.monotonic = lambda: float(next(clock))
        with pytest.raises(sw.SwitchError, match="not back in its normal state"):
            sw.maintenance(primary, {"action": "cancel", "engines": ["kea4"]})
    finally:
        sw.time.monotonic = sw_time


# The partner's files --------------------------------------------------------------------------


def test_sealed_files_open_only_for_their_migration_and_node():
    box = SecretBox.from_b64(generate_master_key())
    bundle = {"configs": {"kea4": {"Dhcp4": {}}}, "secrets": {"/etc/kea/k.tsig": "c2VjcmV0"}}
    token = kmc.seal_files(box, MID, "node-a", bundle)
    assert "c2VjcmV0" not in token
    assert kmc.open_files(box, MID, "node-a", token) == bundle
    with pytest.raises(SecretError):
        kmc.open_files(box, MID, "node-b", token)


def test_partner_file_checked_here_with_local_tls_and_secret_copies(primary, tmp_path, monkeypatch):
    env = primary
    own = env.paths.kea_conf_dir / "tls"
    own.mkdir()
    (own / "ns2.pem").write_text("cert")
    cfg = json.loads(env.paths.kea_conf("kea-dhcp4").read_text())
    rel = cfg["Dhcp4"]["hooks-libraries"][0]["parameters"]["high-availability"][0]
    rel["cert-file"] = str(own / "ns2.pem")
    env.paths.kea_conf("kea-dhcp4").write_text(json.dumps(cfg))
    partner = json.loads(json.dumps(cfg))
    partner["Dhcp4"]["hooks-libraries"][0]["library"] = "/usr/lib/aarch64-linux-gnu/kea/hooks/libdhcp_ha.so"
    prel = partner["Dhcp4"]["hooks-libraries"][0]["parameters"]["high-availability"][0]
    prel["cert-file"] = "/etc/kea/tls/ns1.pem"
    d2 = {
        "DhcpDdns": {
            "tsig-keys": [{"name": "k", "algorithm": "hmac-sha256", "secret-file": "/etc/kea/k.tsig"}]
        }
    }
    bundle = {"configs": {"kea4": partner, "d2": d2}, "secrets": {"/etc/kea/k.tsig": "c2VjcmV0"}}
    monkeypatch.setattr(sw, "_partner_bundle", lambda env, d: bundle)
    seen: dict[str, dict] = {}

    def check(env, daemon, conf, flag):
        seen[daemon] = json.loads(Path(conf).read_text())
        if daemon == "kea-dhcp-ddns":
            assert Path(seen[daemon]["DhcpDdns"]["tsig-keys"][0]["secret-file"]).read_text() == "c2VjcmV0"
        return True, ""

    monkeypatch.setattr(sw, "_kea_check", check)
    out = sw.validate_partner(env, {"migration_id": MID, "partner": "node-a"})
    assert len(out["checked"]) == 2
    hook = seen["kea-dhcp4"]["Dhcp4"]["hooks-libraries"][0]
    assert hook["library"] == "libdhcp_ha.so"
    assert hook["parameters"]["high-availability"][0]["cert-file"] == str(own / "ns2.pem")
    monkeypatch.setattr(sw, "_kea_check", lambda *a: (False, "ERROR [x] DHCP4_CONFIG_LOAD_FAIL bad"))
    with pytest.raises(sw.SwitchError, match="refuses the partner's file"):
        sw.validate_partner(env, {"migration_id": MID, "partner": "node-a"})
