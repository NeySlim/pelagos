# SPDX-License-Identifier: Apache-2.0
"""What every installer operation needs to know about the host it runs on, and the tools it drives."""

from __future__ import annotations

import grp
import os
import tomllib
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pelagos.connectors.bind.rndc import strip_rndc_noise
from pelagos.core.paths import Paths
from pelagos.installer import keaconf
from pelagos.platform import (
    PELAGOS_USER,
    CommandRunner,
    Distro,
    PackageManager,
    PlatformPaths,
    ServiceManager,
    detect_distro,
    find_binary,
    platform_paths,
    service_manager_for,
    user_exists,
)

# node.toml [engines.bind] keys that say where named listens; an import never overrides them.
BIND_CONNECTION_KEYS = ("rndc_address", "rndc_port", "statistics_url", "query_address", "query_port")
LOCAL_ADDRESSES = frozenset({"", "127.0.0.1", "::1", "localhost"})
KEA_ENGINES = {"kea-dhcp4": "kea4", "kea-dhcp6": "kea6", "kea-dhcp-ddns": "d2"}


class Tools:
    """Engine tools behind one object so tests can replace them without a daemon."""

    def __init__(self, env: InstallerEnv) -> None:
        self.env = env

    def _bin(self, name: str) -> str:
        found = self.env.binary(name)
        if not found:
            raise FileNotFoundError(f"{name} not found; is the package installed?")
        return found

    def checkconf(self, named_conf: Path) -> tuple[bool, str]:
        res = self.env.runner.run(
            [self._bin("named-checkconf"), str(named_conf)],
            privileged=True,
            check=False,
            mutates=False,
            timeout=30,
        )
        return res.ok, res.output

    def checkconf_print(self, named_conf: Path) -> str:
        res = self.env.runner.run(
            [self._bin("named-checkconf"), "-p", str(named_conf)],
            privileged=True,
            check=True,
            mutates=False,
            timeout=30,
        )
        return res.stdout

    def _remote_socket(self, daemon: str, conf: Path | None = None) -> Path | None:
        """The control socket of a Kea daemon whose binary is not on this host (a Kea container
        sharing its socket directory, as in docker/compose.yaml), when it answers."""
        engine = KEA_ENGINES.get(daemon)
        if engine is None:
            return None
        sock = None
        conf = conf or self.env.paths.kea_conf(daemon)
        try:
            config = keaconf.loads(conf.read_text(), str(conf))
            sock = keaconf.control_socket_path(config, self.env.paths.kea_socket_dir)
        except (OSError, ValueError, KeyError):
            sock = None
        sock = sock or self.env.paths.kea_socket(engine)
        return sock if self.socket_alive(sock) else None

    def kea_test(self, daemon: str, conf: Path) -> tuple[bool, str]:
        """Checked as the Kea user, like the service runs: AppArmor denies root DAC override to Kea.
        Without the binary, the running daemon checks the file with config-test over its socket."""
        if not self.env.binary(daemon):
            sock = self._remote_socket(daemon, conf)
            if sock is None:
                raise FileNotFoundError(f"{daemon} not found and no control socket answers; is it installed?")
            try:
                config = keaconf.loads(conf.read_text(), str(conf))
                answer = self.kea_command(sock, "config-test", config)
            except (OSError, ValueError) as exc:
                return False, f"config-test over {sock}: {exc}"
            return answer.get("result") == 0, f"config-test over {sock}: {answer.get('text', '')}"
        argv = [self._bin(daemon), "-t", str(conf)]
        runuser = self.env.binary("runuser")
        if runuser and user_exists(self.env.paths.kea_user):
            argv = [runuser, "-u", self.env.paths.kea_user, "--", *argv]
        res = self.env.runner.run(argv, privileged=True, check=False, mutates=False, timeout=60)
        return res.ok, res.output

    def kea_version(self, daemon: str) -> str | None:
        binary = self.env.binary(daemon)
        if not binary:
            sock = self._remote_socket(daemon)
            if sock is None:
                return None
            try:
                answer = self.kea_command(sock, "version-get")
            except (OSError, ValueError):
                return None
            return keaconf.daemon_version_from_text(str(answer.get("text", "")))
        res = self.env.runner.run([binary, "-v"], privileged=True, check=False, mutates=False, timeout=10)
        return keaconf.daemon_version_from_text(res.output)

    def kea_hooks_dir(self, daemon: str = "kea-dhcp4") -> Path | None:
        """Compiled-in hooks directory (`-W`), else the distro default when it exists."""
        binary = self.env.binary(daemon)
        if binary:
            res = self.env.runner.run([binary, "-W"], privileged=True, check=False, mutates=False, timeout=10)
            for line in res.stdout.splitlines():
                if "Hooks directory:" in line:
                    return Path(line.split(":", 1)[1].strip())
        default = self.env.paths.kea_hooks_dir
        return default if default.is_dir() else None

    def named_version(self) -> str | None:
        binary = self.env.binary("named")
        if not binary:
            return None
        res = self.env.runner.run([binary, "-v"], privileged=True, check=False, mutates=False, timeout=10)
        return keaconf.daemon_version_from_text(res.output)

    def rndc(self, conf: Path | None, *args: str) -> tuple[bool, str]:
        argv = [self._bin("rndc")]
        if conf is not None:
            argv += ["-c", str(conf)]
        res = self.env.runner.run([*argv, *args], privileged=True, check=False, mutates=False, timeout=30)
        return res.ok, strip_rndc_noise(res.output)

    def soa_answered(self, address: str, port: int, zone: str) -> bool | None:
        """Whether named answers a SOA query for `zone` at address:port; False when it refuses
        (allow-query), None when the answer says nothing about access (timeout, SERVFAIL)."""
        import dns.exception
        import dns.message
        import dns.query
        import dns.rcode

        try:
            res = dns.query.udp(dns.message.make_query(zone, "SOA"), address, port=port, timeout=3)
        except (OSError, dns.exception.DNSException):
            return None
        if res.rcode() in (dns.rcode.REFUSED, dns.rcode.NOTAUTH):
            return False
        return True if res.rcode() in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN) else None

    def local_addresses(self) -> list[str]:
        """Global IPv4 addresses of this host: a query sent to one of them arrives from it."""
        res = self.env.runner.run(
            [self.env.binary("ip") or "ip", "-o", "-4", "addr", "show", "scope", "global"],
            check=False,
            mutates=False,
            timeout=10,
        )
        out: list[str] = []
        for line in res.stdout.splitlines():
            words = line.split()
            if "inet" in words and words.index("inet") + 1 < len(words):
                out.append(words[words.index("inet") + 1].split("/")[0])
        return out

    def http_get(self, url: str, timeout: float = 5.0) -> tuple[int, str]:
        try:
            with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310 - local http only
                return resp.status, resp.read(65536).decode(errors="replace")
        except urllib.error.HTTPError as exc:
            return exc.code, ""
        except (urllib.error.URLError, OSError, ValueError) as exc:
            return 0, str(exc)

    def fetch(self, url: str, timeout: float = 30.0) -> bytes:
        """Downloads a repository key or file over HTTPS."""
        if not url.startswith("https://"):
            raise ValueError(f"refusing non-HTTPS download {url}")
        with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310 - https only
            return resp.read(1 << 20)

    def kea_command(
        self, sock: Path, command: str, arguments: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """The installer runs as root or in the Kea group, so the socket is reached directly."""
        return keaconf.send_command(sock, command, arguments)

    def socket_alive(self, sock: Path) -> bool:
        try:
            return self.kea_command(sock, "status-get").get("result") == 0
        except (OSError, ValueError):
            return False


@dataclass(slots=True)
class InstallerEnv:
    distro: Distro
    paths: PlatformPaths
    runner: Any  # CommandRunner or a test double with the same `run`
    node_paths: Paths
    node_id: str = "local"
    dry_run: bool = False
    binaries: dict[str, str | None] = field(default_factory=dict)  # test overrides
    tools: Tools | None = None
    service_manager: Any = None  # ServiceManager or a test double
    package_manager: Any = None  # PackageManager or a test double
    # Secrets verified for this run (new TSIG key name -> secret), from sealed peer steps.
    plan_secrets: dict[str, str] = field(default_factory=dict)
    # Kea units an install plan expects (engine -> unit) until the packages bring them.
    planned_units: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.tools is None:
            self.tools = Tools(self)
        if self.service_manager is None:
            self.service_manager = service_manager_for(self.runner)
        if self.package_manager is None:
            self.package_manager = PackageManager(self.distro, self.runner)

    @classmethod
    def detect(
        cls,
        node_paths: Paths | None = None,
        dry_run: bool = False,
        os_release: Path = Path("/etc/os-release"),
        node_id: str | None = None,
    ) -> InstallerEnv:
        distro = detect_distro(os_release)
        env = cls(
            distro=distro,
            paths=platform_paths(distro),
            runner=CommandRunner(dry_run=dry_run),
            node_paths=node_paths or Paths.from_env(),
            dry_run=dry_run,
        )
        env.node_id = node_id or env.local_node_id()
        return env

    @property
    def services(self) -> ServiceManager:
        return self.service_manager

    @property
    def packages(self) -> PackageManager:
        return self.package_manager

    @property
    def t(self) -> Tools:
        assert self.tools is not None
        return self.tools

    @property
    def is_root(self) -> bool:
        return bool(getattr(self.runner, "is_root", os.geteuid() == 0))

    def binary(self, name: str) -> str | None:
        if name in self.binaries:
            return self.binaries[name]
        return find_binary(name)

    def file_group(self, name: str) -> str | None:
        """The group to give a written file: only when we are root and the group exists."""
        if os.geteuid() != 0:
            return None
        try:
            grp.getgrnam(name)
        except KeyError:
            return None
        return name

    def node_initialized(self) -> bool:
        return self.node_paths.node_toml.exists() and self.node_paths.cluster_toml.exists()

    def local_node_id(self) -> str:
        """The node id from node.toml when the node is initialized, else "local"."""
        try:
            with self.node_paths.node_toml.open("rb") as fh:
                return str(tomllib.load(fh)["node"]["id"])
        except (OSError, KeyError, ValueError):
            return "local"

    @property
    def backup_root(self) -> Path:
        return self.node_paths.backups_dir

    def kea_unit(self, engine: str, fallback: str | None = None) -> str:
        """The unit that runs a Kea daemon here: the first candidate systemd knows, else `fallback`
        (the unit of the packages being installed), else the distro name."""
        for unit in self.paths.kea_service_candidates(engine):
            if self.services.exists(unit):
                return unit
        return fallback or self.planned_units.get(engine) or self.paths.kea_services_distro[engine]

    def bind_unit(self) -> str:
        return self.paths.bind_service

    def _bind_tables(self) -> list[dict[str, Any]]:
        """node.toml [engines.bind] then the parked [engines.disabled.bind], those that are tables."""
        try:
            if not self.node_paths.node_toml.exists():
                return []
            from pelagos.core.config_store import ConfigStore

            engines = ConfigStore(self.node_paths.node_toml, self.node_paths.cluster_toml).load_node().engines
        except (OSError, ValueError):
            return []
        disabled = engines.get("disabled")
        tables = (engines.get("bind"), disabled.get("bind") if isinstance(disabled, dict) else None)
        return [t for t in tables if isinstance(t, dict)]

    def bind_table(self) -> dict[str, Any] | None:
        """Where Pelagos reaches named, local or not: the table the collector reads its query address from."""
        tables = self._bind_tables()
        return tables[0] if tables else None

    def remote_bind(self) -> dict[str, Any] | None:
        """node.toml [engines.bind] (or the parked table) of a named on another host, such as the
        BIND container of docker/compose.yaml: rndc and the statistics channel go there."""
        for table in self._bind_tables():
            if str(table.get("rndc_address") or "") not in LOCAL_ADDRESSES:
                return table
        return None

    def rndc_conf(self) -> Path | None:
        """rndc reaches a remote named only through the node's rndc configuration."""
        if self.remote_bind() is not None and self.paths.rndc_conf_pelagos.exists():
            return self.paths.rndc_conf_pelagos
        return None

    def bind_stats_url(self, port: int) -> str:
        remote = self.remote_bind()
        if remote is not None and remote.get("statistics_url"):
            return str(remote["statistics_url"])
        return f"http://127.0.0.1:{port}/json/v1"

    def update_node_engines(self, engines: dict[str, Any]) -> str:
        """Merges what this node drives into node.toml [engines]; no-op before `pelagos init`."""
        if not self.node_paths.node_toml.exists():
            return "node not initialized; node.toml not updated"
        from pelagos.core.config_store import ConfigStore, deep_merge

        store = ConfigStore(self.node_paths.node_toml, self.node_paths.cluster_toml)
        node = store.load_node()
        current = node.engines.get("bind")
        disabled = node.engines.get("disabled")
        if (
            not isinstance(current, dict)
            and isinstance(disabled, dict)
            and isinstance(engines.get("bind"), dict)
        ):
            # Importing turns BIND on: the table parked when it was turned off comes back first.
            current = disabled.pop("bind", None)
        kept: dict[str, Any] = {}
        if (
            isinstance(current, dict)
            and isinstance(engines.get("bind"), dict)
            and str(current.get("rndc_address") or "") not in LOCAL_ADDRESSES
        ):
            # A remote named (a BIND container, set by the image entrypoint) is reached as found;
            # a local one takes what this import detected (a new statistics port, say).
            kept = {k: current[k] for k in BIND_CONNECTION_KEYS if current.get(k)}
            engines = {**engines, "bind": {**engines["bind"], **kept}}
        node.engines = deep_merge(node.engines, engines)
        store.save_node(node)
        line = f"node.toml engines: {', '.join(sorted(k for k, v in node.engines.items() if v))}"
        line += self._publish_modules(node)
        return f"{line} (kept: {', '.join(sorted(kept))})" if kept else line

    def _publish_modules(self, node: Any) -> str:
        """[[nodes]].modules in cluster.toml mirrors node.toml [engines], so peers know what we run."""
        if not self.node_paths.cluster_toml.exists():
            return ""
        from pelagos.core.config_store import ConfigStore

        store = ConfigStore(
            self.node_paths.node_toml,
            self.node_paths.cluster_toml,
            self.node_paths.locks_dir / "cluster.lock",
        )
        peer = store.load_cluster().peer(node.id)
        if peer is None or peer.modules == node.modules:
            return ""

        def mutate(cfg: Any) -> None:
            own = cfg.peer(node.id)
            if own is not None:
                own.modules = node.modules

        store.update_cluster(mutate, updated_by=f"node:{node.id}")
        return "; cluster.toml modules updated"

    def stored_secret(self, name: str) -> str | None:
        """The clear value of a cluster.toml secret, None when absent or before `pelagos init`."""
        if not (self.node_initialized() and self.node_paths.master_key.exists()):
            return None
        from pelagos.core.config_store import ConfigStore
        from pelagos.core.secrets import SecretBox

        cluster = ConfigStore(self.node_paths.node_toml, self.node_paths.cluster_toml).load_cluster()
        token = cluster.secrets.get(name)
        if not token:
            return None
        return SecretBox.from_file(self.node_paths.master_key).decrypt(name, token)

    def relabel(self, paths: list[Path]) -> None:
        """SELinux: a file written through a temp file gets its directory's default type; restore it."""
        if not self.paths.selinux or self.dry_run:
            return
        existing = [str(p) for p in paths if p.exists()]
        if existing:
            self.runner.run(["restorecon", *existing], privileged=True, check=False, timeout=60)

    def stored_secret_names(self) -> set[str]:
        """Names in cluster.toml [secrets]; empty before `pelagos init` (nothing can be stored yet)."""
        if not (self.node_initialized() and self.node_paths.master_key.exists()):
            return set()
        from pelagos.core.config_store import ConfigStore

        cluster = ConfigStore(self.node_paths.node_toml, self.node_paths.cluster_toml).load_cluster()
        return set(cluster.secrets)

    def store_secrets(self, secrets: dict[str, str]) -> str:
        """Encrypts secrets into cluster.toml [secrets] when the node is initialized."""
        if not secrets:
            return "no secret to store"
        if self.dry_run:
            return f"dry run: would store {', '.join(sorted(secrets))}"
        if not (self.node_initialized() and self.node_paths.master_key.exists()):
            return "node not initialized; secrets kept only in the engine files"
        from pelagos.core.config_store import ConfigStore
        from pelagos.core.secrets import SecretBox

        box = SecretBox.from_file(self.node_paths.master_key)
        store = ConfigStore(
            self.node_paths.node_toml,
            self.node_paths.cluster_toml,
            self.node_paths.locks_dir / "cluster.lock",
        )

        def mutate(cfg: Any) -> None:
            for name, value in secrets.items():
                cfg.secrets[name] = box.encrypt(name, value)

        store.update_cluster(mutate, updated_by=f"node:{self.node_id}")
        return f"stored {', '.join(sorted(secrets))} in cluster.toml"


__all__ = ["PELAGOS_USER", "InstallerEnv", "Tools"]
