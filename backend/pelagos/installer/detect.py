# SPDX-License-Identifier: Apache-2.0
"""Detect installed engines, versions, services and configuration files (GET /install/detect)."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from pelagos.installer import bindconf, bindsetup, keaconf, keasetup, managed
from pelagos.platform import Distro, platform_paths


@dataclass(slots=True)
class EngineDetection:
    installed: bool = False
    binary: str | None = None
    version: str | None = None
    service: str | None = None
    running: bool | None = None
    enabled: bool | None = None
    config: str | None = None
    config_exists: bool = False
    source: str | None = None  # "distro" | "isc" for Kea
    paths: dict[str, str] = field(default_factory=dict)


def detect_bind(env: Any) -> EngineDetection:
    paths = env.paths
    binary = env.binary("named")
    unit = env.bind_unit()
    det = EngineDetection(installed=binary is not None, binary=binary, service=unit, source="distro")
    if binary:
        det.version = env.t.named_version()
        det.running = env.services.is_active(unit)
        det.enabled = env.services.is_enabled(unit)
    det.config = str(paths.named_conf)
    det.config_exists = paths.named_conf.exists()
    det.paths = {
        "zone_dir": str(paths.zone_dir),
        "rndc_key": str(paths.rndc_key),
        "include_dir": str(paths.bind_include_dir),
        "user": paths.bind_user,
        "group": paths.bind_group,
    }
    return det


def detect_kea(env: Any, engine: str) -> EngineDetection:
    paths = env.paths
    daemon = keasetup.DAEMONS[engine]
    binary = env.binary(daemon)
    conf = paths.kea_conf(daemon)
    det = EngineDetection(installed=binary is not None, binary=binary)
    if binary:
        det.service = env.kea_unit(engine)
        # The ISC rpm units share the distro unit names: the package tells the source.
        isc_pkg = paths.kea_packages_for([engine], isc=True)[0]
        det.source = "isc" if env.packages.is_installed(isc_pkg) else "distro"
        det.version = env.t.kea_version(daemon)
        det.running = env.services.is_active(det.service)
        det.enabled = env.services.is_enabled(det.service)
    det.config = str(conf)
    det.config_exists = conf.exists()
    det.paths = {
        "socket": str(keasetup.socket_path(env, engine, conf)),
        "hooks_dir": str(paths.kea_hooks_dir),
        "lease_dir": str(paths.kea_lease_dir),
        "user": paths.kea_user,
        "group": paths.kea_group,
    }
    return det


def pelagos_state(env: Any, engines: dict[str, EngineDetection]) -> dict[str, Any]:
    """Whether the node's prerequisites are in place: include lines, Kea sockets, Pelagos keys."""
    paths = env.paths
    include_present: bool | None = None
    keys_present: bool | None = None
    if engines["bind"].config_exists:
        try:
            files = bindconf.load_files(paths.named_conf)
            stmts = [s for p in files.order for s in files.statements[p]]
            include_present = bindconf.has_include(stmts, str(paths.pelagos_conf))
            defined = bindsetup.all_keys(files)
            keys_present = managed.READ_KEY in defined and managed.ADMIN_KEY in defined
        except (OSError, bindconf.ParseError):
            include_present = None
    sockets: dict[str, bool] = {}
    for engine in keasetup.DAEMONS:
        det = engines[engine]
        # Only daemons that run: an installed but stopped kea-dhcp6 is not a broken socket.
        if det.installed and det.config_exists and det.running:
            try:
                sockets[engine] = env.t.socket_alive(
                    keasetup.socket_path(env, engine, paths.kea_conf(keasetup.DAEMONS[engine]))
                )
            except (OSError, keaconf.KeaConfigError):
                sockets[engine] = False
    return {
        "include_present": include_present,
        "sockets_ok": all(sockets.values()) if sockets else None,
        "sockets": sockets,
        "keys_present": keys_present,
        "node_initialized": env.node_initialized(),
    }


def detect_env(env: Any) -> dict[str, Any]:
    engines = {"bind": detect_bind(env)}
    for engine in keasetup.DAEMONS:
        engines[engine] = detect_kea(env, engine)
    return {
        "distro": {**asdict(env.distro), "package_manager": env.distro.package_manager},
        "engines": {k: asdict(v) for k, v in engines.items()},
        "pelagos": pelagos_state(env, engines),
    }


def detect_all(distro: Distro | None = None) -> dict[str, Any]:
    """GET /install/detect on this host."""
    from pelagos.installer.env import InstallerEnv

    env = InstallerEnv.detect()
    if distro is not None:
        env.distro, env.paths = distro, platform_paths(distro)
    return detect_env(env)
