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
    user_exists,
)

# node.toml [engines.bind] keys that say where named listens; an import never overrides them.
BIND_CONNECTION_KEYS = ("rndc_address", "rndc_port", "statistics_url", "query_address", "query_port")


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

    def kea_test(self, daemon: str, conf: Path) -> tuple[bool, str]:
        """Checked as the Kea user, like the service runs: AppArmor denies root DAC override to Kea."""
        argv = [self._bin(daemon), "-t", str(conf)]
        runuser = self.env.binary("runuser")
        if runuser and user_exists(self.env.paths.kea_user):
            argv = [runuser, "-u", self.env.paths.kea_user, "--", *argv]
        res = self.env.runner.run(argv, privileged=True, check=False, mutates=False, timeout=60)
        return res.ok, res.output

    def kea_version(self, daemon: str) -> str | None:
        binary = self.env.binary(daemon)
        if not binary:
            return None
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
        return res.ok, res.output

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

    def __post_init__(self) -> None:
        if self.tools is None:
            self.tools = Tools(self)
        if self.service_manager is None:
            self.service_manager = ServiceManager(self.runner)
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

    def kea_unit(self, engine: str) -> str:
        """The unit that runs a Kea daemon here: the first candidate systemd knows, else the distro name."""
        for unit in self.paths.kea_service_candidates(engine):
            if self.services.exists(unit):
                return unit
        return self.paths.kea_services_distro[engine]

    def bind_unit(self) -> str:
        return self.paths.bind_service

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
        if isinstance(current, dict) and isinstance(engines.get("bind"), dict):
            # How to reach named (a BIND container, set by the image entrypoint) is kept as found.
            kept = {k: current[k] for k in BIND_CONNECTION_KEYS if current.get(k)}
            engines = {**engines, "bind": {**engines["bind"], **kept}}
        node.engines = deep_merge(node.engines, engines)
        store.save_node(node)
        return f"node.toml engines: {', '.join(sorted(k for k, v in node.engines.items() if v))}"

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
