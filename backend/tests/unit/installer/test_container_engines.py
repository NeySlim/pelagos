# SPDX-License-Identifier: Apache-2.0
"""Engines the installer cannot drive through systemd or a local binary: Kea answering only on its
shared control socket (compose) and units run by supervisord (all-in-one image)."""

from __future__ import annotations

import json

import pytest

from pelagos.installer.env import Tools
from pelagos.platform import CommandResult, ExternalServices, FakeRunner, ServiceManager, SupervisorServices
from pelagos.platform import services as services_mod
from tests.unit.installer.fakes import make_env

pytestmark = pytest.mark.unit


def _socket_kea(tmp_path, answers):
    env = make_env(tmp_path)
    env.binaries["kea-dhcp4"] = None
    conf = env.paths.kea_conf("kea-dhcp4")
    conf.parent.mkdir(parents=True, exist_ok=True)
    sock = env.paths.kea_socket_dir / "kea4-ctrl-socket"
    conf.write_text(
        json.dumps({"Dhcp4": {"control-socket": {"socket-type": "unix", "socket-name": str(sock)}}})
    )
    tools = Tools(env)
    sent: list[tuple[str, str]] = []

    def command(path, name, arguments=None):
        sent.append((str(path), name))
        return answers[name]

    tools.kea_command = command  # type: ignore[method-assign]
    tools.socket_alive = lambda path: str(path) == str(sock)  # type: ignore[method-assign]
    return tools, conf, sock, sent


def test_kea_without_binary_is_checked_by_its_running_daemon(tmp_path):
    answers = {
        "config-test": {"result": 0, "text": "Configuration seems sane."},
        "version-get": {"result": 0, "text": "3.2.1"},
    }
    tools, conf, sock, sent = _socket_kea(tmp_path, answers)
    ok, output = tools.kea_test("kea-dhcp4", conf)
    assert ok and "config-test" in output
    assert tools.kea_version("kea-dhcp4") == "3.2.1"
    assert sent == [(str(sock), "config-test"), (str(sock), "version-get")]


def test_kea_without_binary_reports_a_refused_config(tmp_path):
    tools, conf, _sock, _sent = _socket_kea(tmp_path, {"config-test": {"result": 1, "text": "bad subnet"}})
    ok, output = tools.kea_test("kea-dhcp4", conf)
    assert not ok and "bad subnet" in output


def test_kea_without_binary_nor_socket_is_not_installed(tmp_path):
    tools, conf, _sock, _sent = _socket_kea(tmp_path, {})
    tools.socket_alive = lambda path: False  # type: ignore[method-assign]
    assert tools.kea_version("kea-dhcp4") is None
    with pytest.raises(FileNotFoundError):
        tools.kea_test("kea-dhcp4", conf)


@pytest.mark.parametrize(
    ("unit", "program"),
    [
        ("named.service", "named"),
        ("bind9.service", "named"),
        ("isc-kea-dhcp4-server.service", "kea-dhcp4"),
        ("kea-dhcp-ddns-server.service", "kea-dhcp-ddns"),
        ("kea-dhcp6", "kea-dhcp6"),
    ],
)
def test_supervisor_program_names(unit, program):
    assert services_mod.supervisor_program(unit) == program


def test_supervisor_services_map_the_verbs():
    def status(argv):
        prog = argv[-1]
        if prog == "named":
            return CommandResult(
                argv, 0, "named                            RUNNING   pid 12, uptime 0:01:02\n", ""
            )
        if prog == "kea-dhcp6":
            return CommandResult(argv, 3, "kea-dhcp6                        STOPPED   Not started\n", "")
        return CommandResult(argv, 4, f"{prog}: ERROR (no such process)\n", "")

    runner = FakeRunner(responses={"supervisorctl status": status})
    sm = SupervisorServices(runner)
    assert sm.is_active("named.service") and sm.exists("named.service")
    assert not sm.is_active("kea-dhcp6-server.service") and sm.exists("kea-dhcp6-server.service")
    assert not sm.exists("kea-ctrl-agent.service")
    assert "already running" in sm.start("named.service")
    sm.restart("isc-kea-dhcp4-server.service")
    sm.start("kea-dhcp6-server.service")
    assert ["supervisorctl", "restart", "kea-dhcp4"] in runner.log
    assert ["supervisorctl", "start", "kea-dhcp6"] in runner.log
    assert not any(argv[0] == "systemctl" for argv in runner.log)


def test_service_manager_follows_the_init_system(tmp_path, monkeypatch):
    sock = tmp_path / "supervisor.sock"
    monkeypatch.setattr(services_mod, "SUPERVISOR_SOCK", str(sock))
    monkeypatch.setattr(services_mod, "SYSTEMD_DIR", str(tmp_path / "systemd"))
    monkeypatch.setattr(services_mod.shutil, "which", lambda name: f"/usr/bin/{name}")
    assert type(services_mod.service_manager_for(FakeRunner())) is ServiceManager
    sock.write_text("")
    assert isinstance(services_mod.service_manager_for(FakeRunner()), SupervisorServices)
    (tmp_path / "systemd").mkdir()
    assert type(services_mod.service_manager_for(FakeRunner())) is ServiceManager


def test_external_engines_only_in_their_containers(tmp_path, monkeypatch):
    monkeypatch.setattr(services_mod, "SUPERVISOR_SOCK", str(tmp_path / "none.sock"))
    monkeypatch.setattr(services_mod, "SYSTEMD_DIR", str(tmp_path / "systemd"))
    monkeypatch.setenv(services_mod.EXTERNAL_ENV, "1")
    runner = FakeRunner()
    sm = services_mod.service_manager_for(runner)
    assert isinstance(sm, ExternalServices)
    assert sm.is_active("named.service") and sm.exists("kea-dhcp4-server.service")
    assert "own container" in sm.start("named.service")
    with pytest.raises(RuntimeError):
        sm.restart("named.service")
    assert runner.log == []
    (tmp_path / "systemd").mkdir()
    assert type(services_mod.service_manager_for(runner)) is ServiceManager


def _node_engines(env, engines):
    from pelagos.core.config_store import ConfigStore, NodeConfig

    env.node_paths.ensure()
    ConfigStore(env.node_paths.node_toml, env.node_paths.cluster_toml).save_node(
        NodeConfig(id=env.node_id, name=env.node_id, engines=engines)
    )


def test_remote_named_is_reached_through_the_node_settings(tmp_path):
    env = make_env(tmp_path)
    assert env.remote_bind() is None and env.rndc_conf() is None
    assert env.bind_stats_url(8053) == "http://127.0.0.1:8053/json/v1"
    remote = {
        "rndc_address": "bind",
        "statistics_url": "http://bind:8053/json/v1",
        "query_address": "192.0.2.53",
    }
    # Parked while BIND is off (pelagos init leaves it so), as the image entrypoint writes it.
    _node_engines(env, {"bind": False, "disabled": {"bind": remote}})
    assert env.remote_bind() == remote
    assert env.bind_stats_url(8053) == "http://bind:8053/json/v1"
    assert env.rndc_conf() is None  # no rndc configuration for that server yet
    env.paths.rndc_conf_pelagos.parent.mkdir(parents=True, exist_ok=True)
    env.paths.rndc_conf_pelagos.write_text("options { default-server bind; };\n")
    assert env.rndc_conf() == env.paths.rndc_conf_pelagos


def test_local_named_keeps_the_default_rndc(tmp_path):
    env = make_env(tmp_path)
    local = {"rndc_address": "127.0.0.1", "statistics_url": "http://127.0.0.1:8953/json/v1"}
    _node_engines(env, {"bind": local})
    env.paths.rndc_conf_pelagos.parent.mkdir(parents=True, exist_ok=True)
    env.paths.rndc_conf_pelagos.write_text("")
    assert env.remote_bind() is None and env.rndc_conf() is None
    assert env.bind_stats_url(8053) == "http://127.0.0.1:8053/json/v1"
