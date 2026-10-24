# SPDX-License-Identifier: Apache-2.0
"""Install BIND and/or Kea from the distro or the ISC Cloudsmith repositories (POST /install/plan).

The plan lists one Change per step (targets `install/...`, contracts-changes.md); applying it runs a
Job whose steps follow the changes in order. BIND always comes from the distro; `source` selects
where Kea comes from. Once the packages are in, the default BIND configuration is adopted exactly
like an existing one (bindsetup), and fresh Kea daemons get a minimal configuration.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from pelagos.domain import Change, ChangeOp, Engine, Job, Plan, PlanScope, PlanState, ValidationResult
from pelagos.installer import bindsetup, keaconf, keasetup, managed
from pelagos.installer.jobs import Step
from pelagos.platform import (
    ENGINES,
    ISC_SERIES_DEFAULT,
    KEA_DAEMONS,
    PELAGOS_USER,
    Distro,
    PlatformPaths,
    ensure_supplementary_groups,
    ensure_system_user,
    isc_repo_files,
    isc_repo_name,
)

SOURCES = ("distro", "isc")
KEA_DDNS_KEY = "kea-ddns"


def _norm_engines(engines: list[str]) -> list[str]:
    unknown = [e for e in engines if e not in ENGINES]
    if unknown:
        raise ValueError(f"unknown engine(s) {', '.join(unknown)}; expected {', '.join(ENGINES)}")
    return [e for e in ENGINES if e in engines]


def _change(target: str, env: Any, after: Any, before: Any = None, op: ChangeOp = ChangeOp.ADD) -> Change:
    return Change(op=op, target=target, before=before, after=after, node_ids=[env.node_id])


def bind_installed(env: Any) -> bool:
    return env.binary("named") is not None and env.paths.named_conf.exists()


def kea_installed(env: Any, engine: str) -> bool:
    return env.binary(KEA_DAEMONS[engine]) is not None


def build_install_plan(
    env: Any,
    engines: list[str],
    source: str = "distro",
    isc_series: str | None = None,
    created_by: str = "",
) -> Plan:
    """Scope INSTALL: repositories, packages, user, include layout, Kea configs, services, verification."""
    engines = _norm_engines(engines)
    if not engines:
        raise ValueError("no engine selected")
    if source not in SOURCES:
        raise ValueError(f"source must be one of {', '.join(SOURCES)}")
    paths: PlatformPaths = env.paths
    distro: Distro = env.distro
    if not (distro.is_debian or distro.is_rhel):
        raise ValueError(
            f"{distro.pretty_name} is not a supported install target (Debian, Ubuntu, RHEL family)"
        )
    kea = [e for e in engines if e in KEA_DAEMONS]
    isc = source == "isc" and bool(kea)
    series = isc_series or ISC_SERIES_DEFAULT
    changes: list[Change] = []
    validations: list[ValidationResult] = [
        ValidationResult(ok=True, tool="detect", output=f"{distro.pretty_name}", node_id=env.node_id)
    ]

    if isc:
        files = isc_repo_files(distro, series)
        changes.append(
            _change(
                f"install/repo/isc-{isc_repo_name(series)}",
                env,
                {"series": series, "files": [str(f.path) for f in files], "manager": distro.package_manager},
            )
        )

    wanted: list[str] = []
    if "bind" in engines:
        wanted += list(paths.bind_packages)
    wanted += paths.kea_packages_for(kea, isc)
    missing = [p for p in wanted if not env.packages.is_installed(p)]
    if missing:
        after_pkgs: dict[str, Any] = {"install": missing, "present": sorted(set(wanted) - set(missing))}
        if isc:
            # The ISC packages conflict with the distro ones, which the package manager removes.
            distro_kea = paths.kea_packages_for(kea, isc=False)
            after_pkgs["replaces"] = [p for p in distro_kea if env.packages.is_installed(p)]
        changes.append(_change("install/packages", env, after_pkgs))

    groups = ([paths.bind_group] if "bind" in engines else []) + ([paths.kea_group] if kea else [])
    changes.append(_change(f"install/user/{PELAGOS_USER}", env, {"groups": groups}))

    if "bind" in engines:
        changes.append(_change("install/service/bind", env, {"unit": paths.bind_service, "enable": True}))
        keys = [managed.READ_KEY, managed.ADMIN_KEY] + ([KEA_DDNS_KEY] if "d2" in engines else [])
        changes.append(
            _change(
                "install/bind/adopt",
                env,
                {
                    "named_conf": str(paths.named_conf),
                    "include_dir": str(paths.bind_include_dir),
                    "include_lines": [
                        managed.include_line(paths.pelagos_conf),
                        managed.include_line(paths.options_conf),
                    ],
                    "statistics_port": paths.bind_stats_port,
                    "keys": keys,
                },
            )
        )

    for engine in kea:
        conf = paths.kea_conf(KEA_DAEMONS[engine])
        mode = "keep" if kea_installed(env, engine) and conf.exists() else "minimal"
        after: dict[str, Any] = {"conf": str(conf), "mode": mode, "socket": str(paths.kea_socket(engine))}
        if engine == "d2" and "bind" in engines:
            after["tsig_key"] = KEA_DDNS_KEY
            after["secret_file"] = str(keasetup.secret_file_path(paths.kea_conf_dir, KEA_DDNS_KEY))
        changes.append(_change(f"install/{engine}/config", env, after))
        changes.append(
            _change(f"install/service/{engine}", env, {"unit": "resolved at apply", "enable": True})
        )

    node_engines: dict[str, Any] = {e: True for e in engines}
    changes.append(_change("install/node", env, {"engines": node_engines}))
    changes.append(_change("install/verify", env, {"engines": engines}))

    summary = f"install {', '.join(engines)} ({'ISC Kea ' + series if isc else 'distro packages'})"
    return Plan(
        scope=PlanScope.INSTALL,
        node_id=env.node_id,
        summary=summary,
        created_by=created_by,
        engine=Engine.BIND if engines == ["bind"] else None,
        changes=changes,
        diff=render_diff(changes),
        validations=validations,
        target_node_ids=[env.node_id],
        requires_confirmation=True,
        state=PlanState.VALIDATED,
    )


def render_diff(changes: list[Change]) -> str:
    lines = []
    for c in changes:
        detail = (
            c.after if not isinstance(c.after, dict) else ", ".join(f"{k}={v}" for k, v in c.after.items())
        )
        lines.append(f"+ {c.target}: {detail}")
    return "\n".join(lines)


# Steps -----------------------------------------------------------------------------------------


class InstallContext:
    """State shared by the steps of one apply (generated secrets, versions, node.toml engines)."""

    def __init__(self, env: Any) -> None:
        self.env = env
        self.secrets: dict[str, str] = {}
        self.engine_config: dict[str, Any] = {}

    def secret(self, name: str) -> str:
        if name not in self.secrets:
            self.secrets[name] = existing_secret(self.env, name) or managed.new_secret()
        return self.secrets[name]


def existing_secret(env: Any, key_name: str) -> str | None:
    """A D2 secret file written earlier, so re-running the install keeps both sides in step."""
    path = keasetup.secret_file_path(env.paths.kea_conf_dir, key_name)
    try:
        value = path.read_text().strip()
    except OSError:
        return None
    return value or None


def step_repo(env: Any, change: Change) -> str:
    series = change.after["series"]
    out = []
    for f in isc_repo_files(env.distro, series):
        if env.dry_run:
            out.append(f"dry run: would write {f.path}")
            continue
        data = f.content.encode() if f.content is not None else env.t.fetch(str(f.url))
        target = env.paths.root / f.path.relative_to("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() and target.read_bytes() == data:
            out.append(f"{target} present")
            continue
        target.write_bytes(data)
        os.chmod(target, f.mode)
        out.append(f"{target} written")
    out.append(env.packages.refresh() or "package index refreshed")
    return "\n".join(o for o in out if o)


def step_packages(env: Any, change: Change) -> str:
    pkgs = list(change.after["install"])
    if env.distro.is_rhel and env.distro.id != "fedora":
        missing = [p for p in pkgs if p.startswith("kea") and not env.packages.available(p)]
        if missing:
            # Older RHEL releases ship Kea in EPEL only.
            env.packages.install(["epel-release"])
    if not change.after.get("replaces"):
        return env.packages.install(pkgs)
    return env.packages.install(pkgs, replace=True)


def disable_stale_apparmor(env: Any) -> list[str]:
    """Debian keeps the AppArmor profiles of removed Kea packages (conffiles) and they confine the ISC
    binaries at the same paths, denying their lock files: unload and disable those profiles."""
    apparmor = env.paths.root / "etc/apparmor.d"
    out: list[str] = []
    for profile in sorted(apparmor.glob("usr.sbin.kea-*")) if apparmor.is_dir() else []:
        if env.dry_run:
            out.append(f"dry run: would disable AppArmor profile {profile.name}")
            continue
        disabled = apparmor / "disable" / profile.name
        disabled.parent.mkdir(parents=True, exist_ok=True)
        if not disabled.exists():
            disabled.symlink_to(profile)
        env.runner.run(["apparmor_parser", "-R", str(profile)], privileged=True, check=False, timeout=60)
        out.append(f"AppArmor profile {profile.name} of the replaced distro package disabled")
    return out


def step_user(env: Any, change: Change) -> str:
    if env.dry_run:
        return f"dry run: would ensure user {PELAGOS_USER} in {', '.join(change.after['groups'])}"
    out = [ensure_system_user(env.runner)]
    out.append(ensure_supplementary_groups(env.runner, PELAGOS_USER, list(change.after["groups"])))
    return "; ".join(out)


def step_service(env: Any, engine: str) -> str:
    unit = env.bind_unit() if engine == "bind" else env.kea_unit(engine)
    notes: list[str] = []
    if engine != "bind" and env.packages.is_installed(env.paths.kea_packages_for([engine], isc=True)[0]):
        notes = disable_stale_apparmor(env)
    # A unit that hit its start limit (a failed earlier start) refuses to start until reset.
    env.runner.run(["systemctl", "reset-failed", unit], privileged=True, check=False, timeout=30)
    out = "\n".join([*notes, env.services.enable_now(unit)]).strip()
    if not env.dry_run and engine == "bind":
        # First start of named on RHEL generates rndc.key (named-setup-rndc).
        keasetup._wait(lambda: env.services.is_active(unit), seconds=20)
    return out or f"{unit} enabled and started"


def step_bind_adopt(env: Any, change: Change, ctx: InstallContext) -> str:
    keys = list(change.after["keys"])
    extra = {KEA_DDNS_KEY: ctx.secret(KEA_DDNS_KEY)} if KEA_DDNS_KEY in keys else {}
    if not env.dry_run:
        keasetup._wait(lambda: env.paths.rndc_key.exists(), seconds=20)
    result = bindsetup.adopt(
        env,
        Path(change.after["named_conf"]),
        bindsetup.AdoptOptions(
            stats_port=int(change.after["statistics_port"]), create_keys=keys, extra_secrets=extra
        ),
    )
    ctx.engine_config["bind"] = result.engine_config
    stored = env.store_secrets({k: v for k, v in result.secrets.items() if k != f"tsig/{KEA_DDNS_KEY}"})
    return "\n".join([*result.output, stored])


def step_kea_config(env: Any, engine: str, change: Change, ctx: InstallContext) -> str:
    daemon = KEA_DAEMONS[engine]
    conf = Path(change.after["conf"])
    version = env.t.kea_version(daemon)
    out = [f"{daemon} {version or 'version unknown'}"]
    if change.after.get("mode") == "keep":
        text = conf.read_text()
        if engine == "d2" and keaconf.supports_secret_file(version):
            # Kea 3.x refuses clear D2 secrets: move them to secret files before the new daemon starts.
            migrated, secret_files = keasetup.migrate_inline_secrets(
                keaconf.loads(text), env.paths.kea_conf_dir
            )
            for path, secret in secret_files.items():
                out.append(keasetup.write_secret_file(env, path, secret))
            if secret_files:
                text = keaconf.dumps(migrated)
                out.append(
                    keasetup.write_config(env, engine, conf, text, f"install-{engine}-secrets", restart=False)
                )
        new_text, changed = keasetup.ensure_unix_socket(text, engine, version)
        if changed:
            out.append(keasetup.write_config(env, engine, conf, new_text, f"install-{engine}", restart=False))
        else:
            out.append("existing configuration kept; control socket present")
    else:
        tsig: list[dict[str, Any]] = []
        key_name = change.after.get("tsig_key")
        if engine == "d2" and key_name:
            secret_file = Path(change.after["secret_file"])
            secret = ctx.secret(key_name)
            out.append(keasetup.write_secret_file(env, secret_file, secret))
            tsig.append(keasetup.tsig_key_entry(key_name, "hmac-sha256", secret, secret_file, version))
            out.append(env.store_secrets({f"tsig/{key_name}": secret}))
        hooks_dir = env.t.kea_hooks_dir(daemon)
        available = keaconf.hooks_available(hooks_dir) if hooks_dir else []
        config = keasetup.minimal_config(engine, version, hooks_dir, available, tsig)
        out.append(
            keasetup.write_config(env, engine, conf, keaconf.dumps(config), f"install-{engine}", restart=True)
        )
    out.append(keasetup.ensure_socket_access(env, engine, version))
    if keasetup.needs_socket_dropin(version) and not env.dry_run:
        out.append(env.services.restart(env.kea_unit(engine)) or "restarted for the socket drop-in")
    sock = keasetup.socket_path(env, engine, conf)
    ctx.engine_config.setdefault("kea", {"socket_dir": str(env.paths.kea_socket_dir)})
    short = {"kea4": "dhcp4", "kea6": "dhcp6", "d2": "d2"}[engine]
    ctx.engine_config["kea"][f"{short}_socket"] = sock.name
    ctx.engine_config["kea"][f"{short}_conf"] = str(conf)
    return "\n".join(o for o in out if o)


def step_node(env: Any, change: Change, ctx: InstallContext) -> str:
    engines: dict[str, Any] = dict(change.after["engines"])
    if "bind" in ctx.engine_config:
        engines["bind"] = ctx.engine_config["bind"]
    if "kea" in ctx.engine_config:
        engines["kea"] = ctx.engine_config["kea"]
    if env.dry_run:
        return "dry run: node.toml not updated"
    return env.update_node_engines(engines)


def step_verify(env: Any, engines: list[str]) -> str:
    if env.dry_run:
        return "dry run: nothing to verify"
    from pelagos.installer.importer import check_engines

    checks = check_engines(env, engines)
    failed = [k for k, v in checks.items() if not v]
    report = ", ".join(f"{k}={'ok' if v else 'FAILED'}" for k, v in checks.items())
    if failed:
        raise RuntimeError(f"verification failed: {report}")
    return report


def install_steps(plan: Plan, env: Any) -> list[Step]:
    ctx = InstallContext(env)
    steps: list[Step] = []
    for change in plan.changes:
        if change.node_ids and env.node_id not in change.node_ids:
            continue
        t = change.target
        c = change
        if t.startswith("install/repo/"):
            steps.append(Step(t, lambda c=c: step_repo(env, c), weight=2))
        elif t == "install/packages":
            steps.append(Step(t, lambda c=c: step_packages(env, c), weight=5))
        elif t.startswith("install/user/"):
            steps.append(Step(t, lambda c=c: step_user(env, c)))
        elif t.startswith("install/service/"):
            engine = t.rsplit("/", 1)[1]
            steps.append(Step(t, lambda e=engine: step_service(env, e)))
        elif t == "install/bind/adopt":
            steps.append(Step(t, lambda c=c: step_bind_adopt(env, c, ctx), weight=2))
        elif t.endswith("/config") and t.split("/")[1] in KEA_DAEMONS:
            engine = t.split("/")[1]
            steps.append(Step(t, lambda e=engine, c=c: step_kea_config(env, e, c, ctx), weight=2))
        elif t == "install/node":
            steps.append(Step(t, lambda c=c: step_node(env, c, ctx)))
        elif t == "install/verify":
            steps.append(Step(t, lambda c=c: step_verify(env, list(c.after["engines"]))))
        else:
            raise ValueError(f"unknown install change {t}")
    return steps


# Compatibility entry points named in the package skeleton ---------------------------------------


def plan_install(
    distro: Distro,
    paths: PlatformPaths,
    engines: list[str],
    source: str,
    isc_series: str | None,
    created_by: str,
    node_id: str,
) -> Plan:
    from pelagos.installer.env import InstallerEnv

    env = InstallerEnv.detect(node_id=node_id)
    env.distro, env.paths = distro, paths
    return build_install_plan(env, engines, source, isc_series, created_by)


def run_install(plan: Plan, job: Job, progress: Any) -> Job:
    """Long-running apply; reports steps through `progress(job)` for the jobs WebSocket topic."""
    from pelagos.installer.env import InstallerEnv
    from pelagos.installer.jobs import apply_plan

    return apply_plan(plan, InstallerEnv.detect(node_id=plan.node_id), job, progress)
