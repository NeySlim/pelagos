# SPDX-License-Identifier: Apache-2.0
"""Test doubles for the installer: a temp filesystem tree, engine tools, services and packages."""

from __future__ import annotations

import dataclasses
import os
import pwd
import shutil
from pathlib import Path
from typing import Any

from pelagos.core.paths import Paths
from pelagos.installer import bindconf, keaconf
from pelagos.installer.env import InstallerEnv
from pelagos.platform import FakeRunner, distro_from_fields, parse_os_release, platform_paths
from tests.fixtures.ports import find_binary

DATA = Path(__file__).parent / "data"


def foreign_user() -> str:
    """A user other than the one running the tests (the suite also runs as root in CI)."""
    me = os.getuid()
    for name in ("root", "nobody", "daemon"):
        try:
            if pwd.getpwnam(name).pw_uid != me:
                return name
        except KeyError:
            continue
    return next(p.pw_name for p in pwd.getpwall() if p.pw_uid != me)


def os_release(name: str) -> dict[str, str]:
    return parse_os_release((DATA / "os-release" / name).read_text())


def _flatten(
    stmts: list[bindconf.Statement], files: bindconf.ConfigFiles, text_of: dict[str, str]
) -> list[str]:
    out = []
    for s in stmts:
        if s.name == "include" and s.words:
            target = str(bindconf.resolve_include(files.root, s.words[0]))
            if target in files.statements:
                out += _flatten(files.statements[target], files, text_of)
            continue
        text = text_of[str(s.path)][s.start : s.end]
        if s.block is not None and any(x.name == "include" for x in s.block.statements):
            inner = _flatten(s.block.statements, files, text_of)
            head = text_of[str(s.path)][s.start : s.block.start]
            text = head + "{\n" + "\n".join(inner) + "\n};"
        out.append(text)
    return out


def checkconf_print(named_conf: Path) -> str:
    """named-checkconf -p stand-in: every statement with includes expanded, comments dropped."""
    files = bindconf.load_files(named_conf)
    stripped = {p: _strip_comments(t) for p, t in files.texts.items()}
    files = bindconf.ConfigFiles(root=named_conf)
    for p, t in stripped.items():
        files.texts[p] = t
        files.statements[p] = bindconf.parse(t, p)
        files.order.append(p)
    return "\n".join(_flatten(files.statements[str(named_conf)], files, files.texts)) + "\n"


def _strip_comments(text: str) -> str:
    out, i, n = [], 0, len(text)
    while i < n:
        if text[i] == '"':
            j = text.find('"', i + 1)
            out.append(text[i : j + 1])
            i = j + 1
        elif text[i] == "#" or text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


class FakeTools:
    def __init__(self, env: InstallerEnv, kea_version: str = "3.2.1") -> None:
        self.env = env
        self.version = kea_version
        self.calls: list[tuple[str, ...]] = []
        self.checkconf_ok = True
        self.socket_ok = True
        self.http_status = 200
        self.addresses: list[str] = []
        # (address, zone) pairs a fake named refuses; everything else answers.
        self.refused: set[tuple[str, str]] = set()
        self.silent: set[tuple[str, str]] = set()  # probes that time out (None)
        self.real_checkconf = find_binary("named-checkconf")

    def checkconf(self, named_conf: Path) -> tuple[bool, str]:
        self.calls.append(("checkconf", str(named_conf)))
        if not self.checkconf_ok:
            return False, "injected failure"
        if not named_conf.is_file():
            return False, f"open: {named_conf}: file not found"
        try:
            checkconf_print(named_conf)
        except (OSError, bindconf.ParseError) as exc:
            return False, str(exc)
        return True, ""

    def checkconf_print(self, named_conf: Path) -> str:
        return checkconf_print(named_conf)

    def kea_test(self, daemon: str, conf: Path) -> tuple[bool, str]:
        self.calls.append(("kea_test", daemon, str(conf)))
        try:
            keaconf.loads(conf.read_text(), str(conf))
        except keaconf.KeaConfigError as exc:
            return False, str(exc)
        return True, "Configuration check successful"

    def kea_version(self, daemon: str) -> str | None:
        return self.version

    def kea_hooks_dir(self, daemon: str = "kea-dhcp4") -> Path | None:
        return None

    def named_version(self) -> str | None:
        return "9.20.30"

    def rndc(self, conf: Path | None, *args: str) -> tuple[bool, str]:
        self.calls.append(("rndc", *args))
        return True, ""

    def soa_answered(self, address: str, port: int, zone: str) -> bool | None:
        self.calls.append(("soa", address, zone))
        if (address, zone) in self.silent:
            return None
        return (address, zone) not in self.refused

    def local_addresses(self) -> list[str]:
        return list(self.addresses)

    def http_get(self, url: str, timeout: float = 5.0) -> tuple[int, str]:
        self.calls.append(("http_get", url))
        return self.http_status, "{}"

    def fetch(self, url: str, timeout: float = 30.0) -> bytes:
        self.calls.append(("fetch", url))
        return b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n"

    def kea_command(
        self, sock: Path, command: str, arguments: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        return {"result": 0}

    def socket_alive(self, sock: Path) -> bool:
        self.calls.append(("socket_alive", str(sock)))
        return self.socket_ok


@dataclasses.dataclass
class FakeServices:
    active: set[str] = dataclasses.field(default_factory=set)
    units: set[str] = dataclasses.field(default_factory=set)
    calls: list[tuple[str, str]] = dataclasses.field(default_factory=list)

    def is_active(self, unit: str) -> bool:
        return unit in self.active

    def is_enabled(self, unit: str) -> bool:
        return unit in self.active

    def exists(self, unit: str) -> bool:
        return unit in self.units

    def _do(self, verb: str, unit: str) -> str:
        self.calls.append((verb, unit))
        return ""

    def enable_now(self, unit: str) -> str:
        self.active.add(unit)
        return self._do("enable_now", unit)

    def disable_now(self, unit: str) -> str:
        self.active.discard(unit)
        return self._do("disable_now", unit)

    def restart(self, unit: str) -> str:
        return self._do("restart", unit)

    def start(self, unit: str) -> str:
        self.active.add(unit)
        return self._do("start", unit)

    def stop(self, unit: str) -> str:
        self.active.discard(unit)
        return self._do("stop", unit)

    def daemon_reload(self) -> str:
        return self._do("daemon_reload", "")


@dataclasses.dataclass
class FakePackages:
    installed: set[str] = dataclasses.field(default_factory=set)
    calls: list[tuple[str, ...]] = dataclasses.field(default_factory=list)

    def is_installed(self, p: str) -> bool:
        return p in self.installed

    def available(self, p: str) -> bool:
        return True

    def install(self, pkgs: list[str], replace: bool = False) -> str:
        self.calls.append(("install-replace" if replace else "install", *pkgs))
        self.installed.update(pkgs)
        return "installed"

    def refresh(self) -> str:
        self.calls.append(("refresh",))
        return "refreshed"


def make_env(tmp: Path, distro: str = "debian13", kea_version: str = "3.2.1") -> InstallerEnv:
    """An InstallerEnv whose engine paths all live under `tmp` (etc/bind, etc/kea, run/kea, ...)."""
    d = distro_from_fields(os_release(distro))
    base = platform_paths(d, selinux=False)
    etc_bind = tmp / ("etc/bind" if d.is_debian else "etc")
    paths = dataclasses.replace(
        base,
        named_conf=etc_bind / ("named.conf"),
        rndc_key=etc_bind / "rndc.key",
        bind_include_dir=tmp / ("etc/bind/pelagos" if d.is_debian else "etc/named/pelagos"),
        bind_zone_dir_pelagos=tmp / "var/cache/bind/pelagos",
        zone_dir=tmp / "var/cache/bind",
        kea_conf_dir=tmp / "etc/kea",
        kea_socket_dir=tmp / "run/kea",
        kea_lease_dir=tmp / "var/lib/kea",
        kea_log_dir=tmp / "var/log/kea",
        systemd_dir=tmp / "etc/systemd/system",
        root=tmp,
    )
    node = Paths(
        etc=tmp / "pelagos/etc", var=tmp / "pelagos/var", run=tmp / "pelagos/run", opt=tmp / "pelagos/opt"
    )
    env = InstallerEnv(
        distro=d,
        paths=paths,
        runner=FakeRunner(),
        node_paths=node,
        node_id="node-a",
        service_manager=FakeServices(),
        package_manager=FakePackages(),
        binaries={
            "named": "/usr/sbin/named",
            "kea-dhcp4": "/usr/sbin/kea-dhcp4",
            "kea-dhcp6": None,
            "kea-dhcp-ddns": "/usr/sbin/kea-dhcp-ddns",
        },
    )
    env.tools = FakeTools(env, kea_version)  # type: ignore[assignment]
    return env


def _in_tree(text: str, tmp: Path) -> str:
    """Host BIND paths moved under tmp: named-checkconf changes into `directory`, which must exist."""
    return text.replace("/etc/bind", str(tmp / "etc/bind")).replace(
        "/var/cache/bind", str(tmp / "var/cache/bind")
    )


def debian_tree(tmp: Path, name: str = "debian") -> InstallerEnv:
    """Debian default BIND config (named.conf + three includes) and an rndc.key, under tmp."""
    env = make_env(tmp)
    etc = tmp / "etc/bind"
    etc.mkdir(parents=True)
    (tmp / "var/cache/bind").mkdir(parents=True, exist_ok=True)
    for f in ("named.conf", "named.conf.local", "named.conf.options"):
        (etc / f).write_text(_in_tree((DATA / "bind" / f"{name}-{f}").read_text(), tmp))
    (etc / "named.conf.root-hints").write_text(
        'zone "." {\n\ttype hint;\n\tfile "/usr/share/dns/root.hints";\n};\n'
    )
    (etc / "rndc.key").write_text('key "rndc-key" {\n\talgorithm hmac-sha256;\n\tsecret "c2VjcmV0";\n};\n')
    _package_modes(tmp)
    return env


def legacy_tree(tmp: Path) -> InstallerEnv:
    env = make_env(tmp)
    etc = tmp / "etc/bind"
    etc.mkdir(parents=True, exist_ok=True)
    (tmp / "var/cache/bind").mkdir(parents=True, exist_ok=True)
    for f in (DATA / "bind" / "legacy").iterdir():
        if f.is_file():
            (etc / f.name).write_text(_in_tree(f.read_text(), tmp))
    _package_modes(tmp)
    return env


def _package_modes(tmp: Path) -> None:
    """Modes a package install leaves whatever the umask: files with secrets 0640, nothing else
    writable by group or others (the security audit checks them)."""
    for p in [tmp / "etc", *(tmp / "etc").rglob("*"), *(tmp / "var").rglob("*")]:
        if p.is_dir():
            p.chmod(0o755)
        elif p.is_file():
            p.chmod(0o640 if "secret" in p.read_text(errors="replace") else 0o644)


def copy_kea(tmp: Path, mapping: dict[str, str]) -> None:
    """mapping: target file name in etc/kea -> data file in data/kea."""
    d = tmp / "etc/kea"
    d.mkdir(parents=True, exist_ok=True)
    for target, src in mapping.items():
        shutil.copy(DATA / "kea" / src, d / target)


def join_cluster(*envs: InstallerEnv) -> Any:
    """One cluster for these envs' nodes: same master key, every node a member. Returns its SecretBox."""
    from pelagos.core.config_store import ClusterConfig, ConfigStore, NodeConfig
    from pelagos.core.secrets import SecretBox, generate_master_key, write_master_key
    from pelagos.domain import Peer

    key = generate_master_key()
    cluster = ClusterConfig.new(f"node:{envs[0].node_id}")
    for env in envs:
        cluster.nodes.append(
            Peer(
                id=env.node_id,
                name=env.node_id,
                url="https://ns.example.lan:8444",
                cert_fingerprint=f"fp-{env.node_id}",
            )
        )
    text = ""
    for env in envs:
        env.node_paths.ensure()
        write_master_key(env.node_paths.master_key, key)
        store = ConfigStore(env.node_paths.node_toml, env.node_paths.cluster_toml)
        store.save_node(NodeConfig(id=env.node_id, name=env.node_id))
        if not text:
            store.init_cluster(cluster)
            text = env.node_paths.cluster_toml.read_text()
        else:
            env.node_paths.cluster_toml.write_text(text)
    return SecretBox.from_b64(key)
