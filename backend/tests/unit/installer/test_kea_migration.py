# SPDX-License-Identifier: Apache-2.0
"""Kea migration analysis on a node: targets, packages per source, the dry run (fake package tools)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pelagos.installer import helper
from pelagos.installer import kea_migration as km
from pelagos.platform import CommandResult, FakeRunner, distro_from_fields
from pelagos.platform.distro import debian_multiarch
from tests.unit.installer.fakes import make_env, os_release

pytestmark = pytest.mark.unit

KEA_DATA = Path(__file__).parents[1] / "connectors" / "kea" / "data"
ISC = "3.2.1-isc20260928103142"
BPO = "3.0.3-1~bpo13+1"
DEBIAN = distro_from_fields(os_release("debian13"))
ROCKY = distro_from_fields(os_release("rocky10"))
DPKG_LIST = (
    "kea-common\t2.6.3-1+deb13u1\tii \n"
    "kea-dhcp4-server\t2.6.3-1+deb13u1\tii \n"
    "kea-dhcp-ddns-server\t2.6.3-1+deb13u1\tii \n"
    "kea-ctrl-agent\t2.6.3-1+deb13u1\tii \n"
    "kea-doc\t2.6.3-1+deb13u1\trc \n"
    "python3-kea-connector\t2.6.3-1+deb13u1\tii \n"
)


def configs() -> dict:
    return {
        "kea4": json.loads((KEA_DATA / "kea26-migration-dhcp4.json").read_text()),
        "d2": json.loads((KEA_DATA / "kea26-migration-d2.json").read_text()),
    }


class FakeApt:
    """apt-get, apt-cache, dpkg-deb and the extracted daemons, writing the files they would."""

    def __init__(
        self, runner: FakeRunner, version: str = ISC, verdicts: dict[str, tuple[int, str]] | None = None
    ):
        self.version = version
        self.verdicts = verdicts or {}
        self.checked: dict[str, dict] = {}
        self.missing: set[str] = set()
        self.sources: str | None = None
        r = runner.responses
        r["apt-get"] = lambda argv: CommandResult(argv, 0, "Reading package lists...", "")
        r["apt-cache"] = self.madison
        r["sh -c"] = self.download
        r["dpkg-deb -x"] = self.extract
        r["dpkg-query -W"] = DPKG_LIST
        r["dpkg-query -S"] = "kea-dhcp4-server: /usr/sbin/kea-dhcp4\n"
        r["env"] = lambda argv: CommandResult(argv, 0, self.version.split("-")[0] + "\n", "")
        r["runuser"] = self.check

    def madison(self, argv: list[str]) -> CommandResult:
        name = argv[-1]
        if name in self.missing:
            return CommandResult(argv, 0, "", "")
        return CommandResult(argv, 0, f"{name} | {self.version} | https://example.invalid main\n", "")

    def download(self, argv: list[str]) -> CommandResult:
        dl = Path(argv[4])
        self.sources = (dl.parent / "apt/sources.list").read_text()
        for spec in argv:
            if "=" in spec and not spec.startswith(("Dir::", "Debug::", "APT::")) and "::" not in spec:
                name, version = spec.split("=", 1)
                (dl / f"{name}_{version}_amd64.deb").write_text(name)
        return CommandResult(argv, 0, "", "")

    def extract(self, argv: list[str]) -> CommandResult:
        name, tree = Path(argv[2]).read_text(), Path(argv[3])
        hooks = tree / f"usr/lib/{debian_multiarch()}/kea/hooks"
        hooks.mkdir(parents=True, exist_ok=True)
        (tree / "usr/sbin").mkdir(parents=True, exist_ok=True)
        if name.endswith(("dhcp4", "dhcp4-server")):
            (tree / "usr/sbin/kea-dhcp4").write_text("")
        if name.endswith(("ddns", "ddns-server")):
            (tree / "usr/sbin/kea-dhcp-ddns").write_text("")
        if name in ("isc-kea-hooks", "kea-common"):
            for lib in ("lease_cmds", "stat_cmds", "ha", "host_cmds"):
                (hooks / f"libdhcp_{lib}.so").write_text("")
        if name == "isc-kea-mysql":
            (hooks / "libdhcp_mysql.so").write_text("")
        return CommandResult(argv, 0, "", "")

    def check(self, argv: list[str]) -> CommandResult:
        conf = Path(argv[-1])
        cfg = json.loads(conf.read_text())
        engine = {"Dhcp4": "kea4", "Dhcp6": "kea6", "DhcpDdns": "d2"}[next(iter(cfg))]
        self.checked[engine] = {
            "argv": argv,
            "config": cfg,
            "secrets": {
                k["secret-file"]: Path(k["secret-file"]).read_text()
                for k in cfg.get("DhcpDdns", {}).get("tsig-keys", [])
            },
        }
        code, out = self.verdicts.get(engine, (0, ""))
        return CommandResult(argv, code, out.replace("@CONF@", str(conf)), "")


@pytest.fixture
def env(tmp_path):
    e = make_env(tmp_path / "root")
    e.paths.root.mkdir(parents=True)
    e.runner = FakeRunner()
    return e


def test_targets():
    assert [(t["series"], t["source"], t["recommended"]) for t in km.targets(DEBIAN)] == [
        ("3.2", "isc", True),
        ("3.0", "isc", False),
        ("3.0", "backports", False),
    ]
    assert "security" in km.targets(DEBIAN)[2]["note"]
    assert [t["source"] for t in km.targets(ROCKY)] == ["isc", "isc"]
    with pytest.raises(ValueError):
        km.check_target(ROCKY, "3.0", "backports")


def test_sources_and_installed():
    assert km.classify_source("isc-kea-dhcp4", ISC) == "isc"
    assert km.classify_source("kea-dhcp4-server", BPO) == "backports"
    assert km.classify_source("kea-dhcp4-server", "2.6.3-1+deb13u1") == "distro"
    runner = FakeRunner(
        responses={"dpkg-query -W": DPKG_LIST, "dpkg-query -S": "kea-dhcp4-server: /usr/sbin/kea-dhcp4"}
    )
    installed = km.installed_packages(runner, DEBIAN)
    assert "kea-doc" not in installed and installed["kea-ctrl-agent"] == "2.6.3-1+deb13u1"
    assert km.engine_package(runner, DEBIAN, "kea4") == {
        "package": "kea-dhcp4-server",
        "version": "2.6.3-1+deb13u1",
        "source": "distro",
    }
    rpm = FakeRunner(responses={"rpm -qa": "kea\t3.0.1-1.el10\tii\nbind\t9.18\tii\n", "rpm -qf": "kea"})
    assert km.installed_packages(rpm, ROCKY) == {"kea": "3.0.1-1.el10"}
    assert km.engine_package(rpm, ROCKY, "kea4")["source"] == "distro"
    assert (
        km.engine_package(
            FakeRunner(responses={"dpkg-query -S": CommandResult([], 1, "", "")}), DEBIAN, "kea6"
        )
        is None
    )


def test_package_changes_isc_replaces_debian():
    installed = {
        "kea-common": "2.6.3",
        "kea-dhcp4-server": "2.6.3",
        "kea-ctrl-agent": "2.6.3",
        "python3-kea-connector": "2.6.3",
    }
    wanted = km.wanted_packages(DEBIAN, "isc", ["kea4", "d2"], ["isc-kea-mysql"])
    assert wanted == [
        "isc-kea-common",
        "isc-kea-dhcp4",
        "isc-kea-dhcp-ddns",
        "isc-kea-hooks",
        "isc-kea-mysql",
    ]
    out = km.package_changes("isc", installed, dict.fromkeys(wanted, ISC), "3.2")
    assert [p["name"] for p in out["remove"]] == sorted(installed)
    assert [p["name"] for p in out["install"]] == wanted and out["install"][0]["version"] == ISC
    # The Debian tools the ISC packages conflict with come back under their ISC names.
    tools = {**installed, "kea-admin": "2.6.3", "kea-doc": "2.6.3", "kea": "2.6.3"}
    wanted = km.wanted_packages(DEBIAN, "isc", ["kea4"], installed=tools)
    assert wanted[-2:] == ["isc-kea-admin", "isc-kea-doc"] and "isc-kea" not in wanted
    assert "isc-kea-admin" not in km.wanted_packages(DEBIAN, "backports", ["kea4"], installed=tools)


def test_package_changes_isc_upgrade_and_backports():
    installed = {"isc-kea-common": "2.6.1", "isc-kea-dhcp4": "2.6.1", "isc-kea-ctrl-agent": "2.6.1"}
    out = km.package_changes("isc", installed, {"isc-kea-common": ISC, "isc-kea-dhcp4": ISC}, "3.2")
    assert out["remove"] == [{"name": "isc-kea-ctrl-agent", "version": "2.6.1"}]
    # The 3.0 control agent is still a real daemon: it stays installed (stopped, disabled).
    assert km.package_changes("isc", installed, {"isc-kea-common": ISC}, "3.0")["remove"] == []
    deb = {"kea-common": "2.6.3", "kea-dhcp4-server": "2.6.3", "kea-ctrl-agent": "2.6.3"}
    out = km.package_changes("backports", deb, {"kea-common": BPO, "kea-dhcp4-server": BPO}, "3.0")
    assert out["remove"] == []
    assert {p["name"]: p["version"] for p in out["install"]} == {
        "kea-common": BPO,
        "kea-dhcp4-server": BPO,
        "kea-ctrl-agent": BPO,
    }


def test_analyze_isc_dry_run(env):
    apt = FakeApt(env.runner)
    report = km.analyze(
        env,
        "3.2",
        "isc",
        configs(),
        node_id="n1",
        ctrl_agent={"present": True, "active": False, "clients": [], "signs": []},
        workdir=env.paths.root,
    )
    assert report["target_version"] == "3.2.1"
    assert report["validation"]["kea4"] == {"ok": True, "mode": "dry_run", "output": "", "version": "3.2.1"}
    assert report["validation"]["d2"]["ok"] is True
    # Hooks load by name from the extracted tree; flags -T for DHCP, -t for D2; run as the Kea user.
    argv = apt.checked["kea4"]["argv"]
    assert argv[:4] == ["runuser", "-u", "_kea", "--"] and argv[-2] == "-T"
    assert any(a.startswith("KEA_HOOKS_PATH=") and a.endswith("/kea/hooks") for a in argv)
    assert apt.checked["d2"]["argv"][-2] == "-t"
    libs = [h["library"] for h in apt.checked["kea4"]["config"]["Dhcp4"]["hooks-libraries"]]
    assert libs == ["libdhcp_lease_cmds.so", "libdhcp_stat_cmds.so", "libdhcp_ha.so"]
    # The D2 secret is a temporary copy; the report only names the file the migration writes.
    assert list(apt.checked["d2"]["secrets"].values()) == ["c2VjcmV0LWZvci10ZXN0cw=="]
    assert report["files"] == [str(env.paths.kea_conf_dir / "kea-ddns.tsig")]
    assert "c2VjcmV0" not in json.dumps({k: v for k, v in report.items() if k != "configs"})
    assert report["configs"]["d2"]["DhcpDdns"]["tsig-keys"][0]["secret-file"].endswith("kea-ddns.tsig")
    codes = {f["code"] for f in report["findings"]}
    assert {"control_socket", "restrict_commands", "d2_secret_file", "ctrl_agent_stop", "path_moved"} <= codes
    assert not any(f["severity"] == "blocking" for f in report["findings"])
    assert all(f["node_id"] == "n1" for f in report["findings"])
    assert set(report["diffs"]) == {"kea4", "d2"} and report["diffs"]["kea4"].startswith("--- a")
    assert [p["name"] for p in report["packages"]["install"]] == [
        "isc-kea-common",
        "isc-kea-dhcp4",
        "isc-kea-dhcp-ddns",
        "isc-kea-hooks",
    ]
    assert "kea-ctrl-agent" in [p["name"] for p in report["packages"]["remove"]]
    # Private apt state, signed by the ISC key fetched over HTTPS; the temporary tree is gone.
    update = next(c for c in env.runner.commands("apt-get"))
    assert "Dir::Etc::SourceList=" in update and "Dir::State::Lists=" in update
    assert ("fetch", "https://dl.cloudsmith.io/public/isc/kea-3-2/gpg.key") in env.tools.calls
    assert not list(env.paths.root.glob("pelagos-kea-dry-run-*"))


def test_analyze_validation_failed(env):
    out = (
        "2026-10-29 07:25:19.102 ERROR [kea-dhcp4.ha-hooks/1.2] HA_CONFIGURATION_FAILED bad TLS config\n"
        "Error encountered: One or more hook libraries failed to load\n"
    )
    FakeApt(env.runner, verdicts={"kea4": (1, out)})
    report = km.analyze(env, "3.2", "isc", configs(), workdir=env.paths.root)
    (failed,) = [f for f in report["findings"] if f["code"] == "validation_failed"]
    assert failed["severity"] == "blocking" and failed["engine"] == "kea4"
    assert failed["message"]["params"]["error"] == (
        "HA_CONFIGURATION_FAILED bad TLS config: One or more hook libraries failed to load"
    )
    assert report["validation"]["kea4"]["ok"] is False and report["validation"]["d2"]["ok"] is True


def test_analyze_skipped_without_network(env):
    FakeApt(env.runner)

    def offline(url: str, timeout: float = 30.0) -> bytes:
        raise OSError("network unreachable")

    env.tools.fetch = offline  # type: ignore[method-assign]
    report = km.analyze(env, "3.2", "isc", configs(), workdir=env.paths.root)
    assert {e: v["mode"] for e, v in report["validation"].items()} == {"kea4": "skipped", "d2": "skipped"}
    skipped = [f for f in report["findings"] if f["code"] == "validation_skipped"]
    assert len(skipped) == 2 and all(f["severity"] == "info" for f in skipped)
    assert "network unreachable" in skipped[0]["message"]["params"]["reason"]
    # The rules still run, with the hooks list unknown (nothing is reported missing).
    assert "restrict_commands" in {f["code"] for f in report["findings"]}
    assert not env.runner.commands("runuser")


def test_analyze_backports_and_missing_package(env):
    apt = FakeApt(env.runner, version=BPO)
    report = km.analyze(env, "3.0", "backports", {"kea4": configs()["kea4"]}, workdir=env.paths.root)
    assert report["validation"]["kea4"]["ok"] is True
    assert "trixie-backports main" in (apt.sources or "")
    assert report["packages"]["remove"] == []
    assert {p["name"] for p in report["packages"]["install"]} >= {
        "kea-common",
        "kea-dhcp4-server",
        "kea-ctrl-agent",
    }
    apt.missing.add("isc-kea-dhcp4")
    report = km.analyze(env, "3.2", "isc", {"kea4": configs()["kea4"]}, workdir=env.paths.root)
    assert report["validation"]["kea4"]["mode"] == "skipped"
    assert "isc-kea-dhcp4 is not offered" in report["validation"]["kea4"]["output"]


def test_analyze_fetches_the_sql_hook_package(env):
    apt = FakeApt(env.runner)
    cfg = configs()["kea4"]
    cfg["Dhcp4"]["lease-database"] = {"type": "mysql", "name": "kea"}
    report = km.analyze(env, "3.2", "isc", {"kea4": cfg}, workdir=env.paths.root)
    assert "isc-kea-mysql" in [p["name"] for p in report["packages"]["install"]]
    libs = [h["library"] for h in apt.checked["kea4"]["config"]["Dhcp4"]["hooks-libraries"]]
    assert libs[0] == "libdhcp_mysql.so"


def test_rhel_workspace_uses_dnf(env, tmp_path):
    runner = FakeRunner(responses={"dnf": CommandResult([], 1, "", "Curl error (6)")})
    ws = km.Workspace(runner, ROCKY, "3.2", "isc", tmp_path / "ws", machine="x86_64")
    with pytest.raises(km.DryRunError, match="dnf download"):
        ws.fetch(["isc-kea-dhcp4"])
    (argv,) = runner.commands("dnf")
    assert "--repofrompath=pelagos-kea,https://dl.cloudsmith.io/public/isc/kea-3-2/rpm/el/10/x86_64" in argv
    assert "--setopt=pelagos-kea.gpgcheck=1" in argv
    assert "--disableplugin=*" in argv and "--enableplugin=download" in argv
    assert ws.hooks_dir() == "/usr/lib64/kea/hooks"


def test_error_line():
    assert km.error_line("Syntax check failed with: f.conf:9.3-7: got unexpected keyword") == (
        "f.conf:9.3-7: got unexpected keyword"
    )
    assert km.error_line("") == "?"
    assert km.error_line("some text\nlast words\n") == "last words"


def test_ctrl_agent_state(env):
    conf = env.paths.kea_conf("kea-ctrl-agent")
    none = {"present": False, "active": False, "clients": [], "signs": []}
    assert km.ctrl_agent_state(env) == none
    conf.parent.mkdir(parents=True, exist_ok=True)
    conf.write_text('{"Control-agent": {"http-host": "127.0.0.1", "http-port": 8080} // comment\n}')
    assert km.ctrl_agent_state(env) == {**none, "present": True}
    env.service_manager.active |= {"kea-ctrl-agent.service"}
    # Running with nobody connected right now: no client, and no stop either (mig.ctrl_agent).
    assert km.ctrl_agent_state(env) == {**none, "present": True, "active": True}
    env.service_manager.active |= {"isc-stork-agent.service"}
    env.runner.responses["ss"] = "ESTAB 0 0 127.0.0.1:8080 192.0.2.50:41000\n"
    assert km.ctrl_agent_state(env)["clients"] == ["192.0.2.50", "isc-stork-agent"]
    assert "( sport = :8080 )" in env.runner.commands("ss")[0]


def test_ctrl_agent_state_reads_signs_and_logs(env, tmp_path):
    log = tmp_path / "ca.log"
    log.write_text(
        "2026-10-28 03:00:01.120 INFO  [kea-ctrl-agent.ctrl-agent/9] CTRL_AGENT_COMMAND_RECEIVED"
        " command lease4-get-all received from remote address 192.0.2.60\n"
    )
    conf = env.paths.kea_conf("kea-ctrl-agent")
    conf.parent.mkdir(parents=True, exist_ok=True)
    ca = {
        "http-host": "192.0.2.11",
        "http-port": 8000,
        "authentication": {"type": "basic", "clients": [{"user": "a", "password": "p"}]},
        "cert-file": "/etc/kea/ca.crt",
        "loggers": [{"name": "kea-ctrl-agent", "output-options": [{"output": str(log)}]}],
    }
    conf.write_text(json.dumps({"Control-agent": ca}))
    env.service_manager.active |= {"isc-kea-ctrl-agent.service"}
    env.runner.responses["journalctl"] = (
        "CTRL_AGENT_COMMAND_RECEIVED command config-get received from remote address [2001:db8::5]\n"
    )
    state = km.ctrl_agent_state(env)
    assert state["signs"] == ["http-host 192.0.2.11", "authentication", "tls"]
    assert state["clients"] == ["192.0.2.60", "2001:db8::5"]
    (argv,) = env.runner.commands("journalctl")
    assert "-g" in argv and "isc-kea-ctrl-agent.service" in argv


def test_missing_kea_user_skips_the_dry_run(env):
    FakeApt(env.runner)
    env.runner.responses["id -u"] = CommandResult([], 1, "", "id: '_kea': no such user")
    report = km.analyze(env, "3.2", "isc", {"kea4": configs()["kea4"]}, workdir=env.paths.root)
    assert report["validation"]["kea4"]["mode"] == "skipped"
    assert "_kea does not exist" in report["validation"]["kea4"]["output"]
    assert not env.runner.commands("runuser")


def test_analyze_masks_passwords_in_diffs_and_configs(env):
    cfg = configs()["kea4"]
    cfg["Dhcp4"]["lease-database"] = {"type": "mysql", "name": "kea", "password": "S3CRET-DB"}
    rel = cfg["Dhcp4"]["hooks-libraries"][2]["parameters"]["high-availability"][0]
    rel["basic-auth-password"] = "S3CRET-HA"
    apt = FakeApt(env.runner)
    report = km.analyze(env, "3.2", "isc", {"kea4": cfg}, workdir=env.paths.root)
    assert "S3CRET" not in json.dumps(report)
    # The daemon still checks the real values.
    assert apt.checked["kea4"]["config"]["Dhcp4"]["lease-database"]["password"] == "S3CRET-DB"


def test_helper_operation(env):
    FakeApt(env.runner)
    env.paths.kea_conf_dir.mkdir(parents=True, exist_ok=True)
    for engine, cfg in configs().items():
        env.paths.kea_conf(km.DAEMONS[engine]).write_text(json.dumps(cfg))
    assert "kea_dry_run" in helper.OPERATIONS
    out = helper.handle({"op": "kea_dry_run", "series": "3.2", "source": "isc"}, lambda: env, lambda _m: None)
    assert out["node_id"] == "node-a" and set(out["validation"]) == {"kea4", "d2"}
    for bad in (
        {"series": "9.9", "source": "isc"},
        {"series": "3.2", "source": "isc", "configs": {"bind": {}}},
        {"series": "3.2", "source": "isc", "configs": {"kea4": {"Dhcp6": {}}}},
    ):
        with pytest.raises(helper.HelperError) as exc:
            helper.handle({"op": "kea_dry_run", **bad}, lambda: env, lambda _m: None)
        assert exc.value.kind == "value"


def test_daemon_that_cannot_run_skips_the_dry_run(env):
    FakeApt(env.runner)
    env.runner.responses["env"] = CommandResult(
        [], 127, "", "kea-dhcp4: error while loading shared libraries: liblog4cplus-2.1.so.9: cannot open"
    )
    report = km.analyze(env, "3.2", "isc", {"kea4": configs()["kea4"]}, workdir=env.paths.root)
    assert report["validation"]["kea4"]["mode"] == "skipped"
    (f,) = [f for f in report["findings"] if f["code"].startswith("validation")]
    assert f["code"] == "validation_skipped" and "liblog4cplus" in f["message"]["params"]["reason"]
    assert not env.runner.commands("runuser")
