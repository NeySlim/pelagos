# SPDX-License-Identifier: Apache-2.0
"""Kea 3.x migration analysis on this node: targets, packages per source, dry-run validation.

The target's packages are downloaded into a temporary directory with a private package manager
state (the node's sources, keys and caches are never touched), extracted (`dpkg-deb -x`,
`rpm2cpio`), and the converted files are checked by the extracted daemons as the Kea user with
LD_LIBRARY_PATH and KEA_HOOKS_PATH on the extracted tree. Proven in the lab on 2026-10-29 on
Debian 13 with Kea 2.6.3 installed, for ISC 3.2.1 and Debian backports 3.0.3, and on Rocky 10
(architecture 26, tests/lab/test_kea_migration_lab.py).
"""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pelagos.connectors.kea import migration as mig
from pelagos.core import keafile
from pelagos.platform.distro import Distro, debian_multiarch
from pelagos.platform.packages import CLOUDSMITH, isc_repo_name

SOURCES = ("isc", "backports")
DEBIAN_MIRROR = "http://deb.debian.org/debian"
DEBIAN_KEYRING = "/usr/share/keyrings/debian-archive-keyring.gpg"
BACKPORTS_NOTE = "Debian backports come with no security support commitment (backports.debian.org)"
DAEMONS = {"kea4": "kea-dhcp4", "kea6": "kea-dhcp6", "d2": "kea-dhcp-ddns"}
# -T also loads the hooks and reads their files (HA TLS keys); D2 has only -t (Kea 3.2.1 usage).
TEST_FLAG = {"kea4": "-T", "kea6": "-T", "d2": "-t"}
OUTPUT_LIMIT = 4000
_ISC = {"kea4": "isc-kea-dhcp4", "kea6": "isc-kea-dhcp6", "d2": "isc-kea-dhcp-ddns"}
_DEB = {"kea4": "kea-dhcp4-server", "kea6": "kea-dhcp6-server", "d2": "kea-dhcp-ddns-server"}
# Debian's kea-common carries every hook, the SQL ones included; ISC splits them out.
_DB_PACKAGES = {
    "isc": {"mysql": "isc-kea-mysql", "postgresql": "isc-kea-pgsql"},
    "backports": {"mysql": "kea-common", "postgresql": "kea-common"},
}
# Debian packages with an ISC counterpart of the same role, from the Cloudsmith kea-3-0 and kea-3-2
# trixie indexes (dl.cloudsmith.io/public/isc/kea-3-2/deb/debian/dists/trixie/main/binary-amd64/
# Packages.gz, read on 2026-10-29): `isc-kea` pulls dhcp4, dhcp6, dhcp-ddns, admin, hooks and doc.
_ISC_COUNTERPART = {
    "kea": "isc-kea",
    "kea-admin": "isc-kea-admin",
    "kea-doc": "isc-kea-doc",
    "kea-dev": "isc-kea-dev",
}
_KEA_PACKAGE = re.compile(r"^(isc-kea|kea|python3-kea|python3-isc-kea)(-|$)")


class DryRunError(Exception):
    """The dry run could not run (download, extraction, missing binary): validation is skipped."""


# Targets and packages ------------------------------------------------------------------------


def targets(distro: Distro) -> list[dict[str, Any]]:
    """Migration targets this distribution can take, recommended first (design 13.4 decision 1)."""
    out: list[dict[str, Any]] = []
    if distro.is_debian or distro.is_rhel:
        out.append({"series": "3.2", "source": "isc", "recommended": True})
        out.append({"series": "3.0", "source": "isc", "recommended": False})
    if distro.is_debian and distro.id == "debian" and distro.codename:
        out.append({"series": "3.0", "source": "backports", "recommended": False, "note": BACKPORTS_NOTE})
    return out


def check_target(distro: Distro, series: str, source: str) -> None:
    if not any(t["series"] == series and t["source"] == source for t in targets(distro)):
        raise ValueError(f"no Kea {series} from {source} for {distro.pretty_name}")


def classify_source(package: str, version: str) -> str:
    if package.startswith("isc-"):
        return "isc"
    if "~bpo" in version:
        return "backports"
    return "distro"


def installed_packages(runner: Any, distro: Distro) -> dict[str, str]:
    """Installed Kea packages and their exact versions."""
    if distro.is_debian:
        argv = [
            "dpkg-query",
            "-W",
            "-f=${Package}\t${Version}\t${db:Status-Abbrev}\n",
            "kea*",
            "isc-kea*",
            "python3-kea*",
            "python3-isc-kea*",
        ]
    elif distro.is_rhel:
        argv = ["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\tii\n"]
    else:
        return {}
    res = runner.run(argv, check=False, mutates=False, timeout=60)
    out = {}
    for line in res.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) == 3 and parts[2].strip().startswith("ii") and _KEA_PACKAGE.match(parts[0]):
            out[parts[0]] = parts[1]
    return out


def engine_package(runner: Any, distro: Distro, engine: str) -> dict[str, str] | None:
    """{"package","version","source"} owning the engine's binary, None when not installed."""
    binary = f"/usr/sbin/{DAEMONS[engine]}"
    if distro.is_debian:
        res = runner.run(["dpkg-query", "-S", binary], check=False, mutates=False, timeout=30)
        name = res.stdout.split(":", 1)[0].strip() if res.ok else ""
    elif distro.is_rhel:
        res = runner.run(["rpm", "-qf", "--qf", "%{NAME}", binary], check=False, mutates=False, timeout=30)
        name = res.stdout.strip() if res.ok else ""
    else:
        return None
    if not name:
        return None
    version = installed_packages(runner, distro).get(name, "")
    return {"package": name, "version": version, "source": classify_source(name, version)}


def wanted_packages(
    distro: Distro,
    source: str,
    engines: list[str],
    extra: list[str] = (),
    installed: dict[str, str] | None = None,
) -> list[str]:
    """The target's packages for these engines (dependencies listed: they are downloaded too), plus
    the ISC counterparts of the installed Debian tools the ISC packages replace."""
    if source == "isc":
        names = ["isc-kea-common", *(_ISC[e] for e in engines if e in _ISC), "isc-kea-hooks"]
        if distro.is_debian:
            names += [_ISC_COUNTERPART[n] for n in sorted(installed or {}) if n in _ISC_COUNTERPART]
    else:
        names = ["kea-common", *(_DEB[e] for e in engines if e in _DEB)]
    return list(dict.fromkeys([*names, *extra]))


def package_changes(
    source: str, installed: dict[str, str], install: dict[str, str], series: str
) -> dict[str, list[dict[str, str]]]:
    """{"remove","install"} for the node: ISC packages conflict with every Debian or Fedora Kea
    package (`isc-kea-common` Conflicts `kea-common`), so those go; backports upgrade in place."""
    remove = []
    for name, version in sorted(installed.items()):
        if name in install:
            continue
        isc = name.startswith(("isc-", "python3-isc-"))
        transitional = name == "isc-kea-ctrl-agent" and tuple(map(int, series.split("."))) >= (3, 2)
        if (source == "isc" and (not isc or transitional)) or (source == "backports" and isc):
            remove.append({"name": name, "version": version})
    upgrade = dict(install)
    if source == "backports":
        # The other installed Debian Kea packages follow kea-common (strict version dependencies).
        for name in installed:
            if not name.startswith(("isc-", "python3-isc-")) and name not in upgrade:
                upgrade[name] = install.get("kea-common", "")
    return {
        "remove": remove,
        "install": [{"name": n, "version": v} for n, v in upgrade.items()],
    }


# Workspace -----------------------------------------------------------------------------------


@dataclass
class Workspace:
    """A temporary directory holding the private package state, the packages and their tree."""

    runner: Any
    distro: Distro
    series: str
    source: str
    root: Path
    fetch_url: Any = None  # url -> bytes, for the ISC signing key
    kea_user: str = "_kea"
    machine: str = field(default_factory=platform.machine)
    versions: dict[str, str] = field(default_factory=dict)
    files: list[Path] = field(default_factory=list)

    @property
    def tree(self) -> Path:
        return self.root / "tree"

    def _run(self, argv: list[str], timeout: float = 600, **kw: Any) -> Any:
        return self.runner.run(argv, check=False, mutates=False, timeout=timeout, **kw)

    # apt

    def _apt_options(self) -> list[str]:
        r = self.root
        opts = {
            "Dir::Etc::SourceList": r / "apt/sources.list",
            "Dir::Etc::SourceParts": r / "apt/sources.list.d",
            "Dir::Etc::Preferences": r / "apt/preferences",
            "Dir::Etc::PreferencesParts": r / "apt/preferences.d",
            "Dir::State::Lists": r / "apt/lists",
            "Dir::Cache": r / "apt/cache",
            "Debug::NoLocking": "1",
            "APT::Sandbox::User": "root",
        }
        return [x for k, v in opts.items() for x in ("-o", f"{k}={v}")]

    def _apt_setup(self) -> None:
        r = self.root / "apt"
        for d in ("sources.list.d", "preferences.d", "lists/partial", "cache/archives/partial"):
            (r / d).mkdir(parents=True, exist_ok=True)
        (r / "preferences").write_text("")
        codename = self.distro.cloudsmith_distro[1] or self.distro.codename
        if self.source == "isc":
            if self.fetch_url is None:
                raise DryRunError("no way to fetch the ISC signing key")
            repo = isc_repo_name(self.series)
            key = r / "isc.asc"
            try:
                key.write_bytes(self.fetch_url(f"{CLOUDSMITH}/{repo}/gpg.key"))
            except Exception as exc:  # any network failure skips the dry run
                raise DryRunError(f"ISC signing key: {exc}") from None
            name = self.distro.cloudsmith_distro[0]
            line = f"deb [signed-by={key}] {CLOUDSMITH}/{repo}/deb/{name} {codename} main\n"
        else:
            line = f"deb [signed-by={DEBIAN_KEYRING}] {DEBIAN_MIRROR} {codename}-backports main\n"
        (r / "sources.list").write_text(line)
        res = self._run(["apt-get", *self._apt_options(), "-q", "update"])
        if not res.ok or re.search(r"^(E:|W: (GPG|The repository))", res.output, re.M):
            raise DryRunError(f"apt-get update: {res.output.strip()[-500:]}")

    def _apt_fetch(self, packages: list[str]) -> None:
        dl = self.root / "dl"
        dl.mkdir(parents=True, exist_ok=True)
        want = []
        for name in packages:
            res = self._run(["apt-cache", *self._apt_options(), "madison", name], timeout=120)
            version = next(
                (p.split("|")[1].strip() for p in res.stdout.splitlines() if p.count("|") >= 2), ""
            )
            if not version:
                raise DryRunError(f"{name} is not offered by Kea {self.series} from {self.source}")
            self.versions[name] = version
            want.append(f"{name}={version}")
        before = set(dl.glob("*.deb"))
        res = self._run(
            [
                "sh",
                "-c",
                'cd "$1" && shift && exec apt-get "$@"',
                "sh",
                str(dl),
                *self._apt_options(),
                "-q",
                "download",
                *want,
            ]
        )
        new = sorted(set(dl.glob("*.deb")) - before)
        if not res.ok or len(new) < len(want):
            raise DryRunError(f"apt-get download: {res.output.strip()[-500:]}")
        for deb in new:
            got = self._run(["dpkg-deb", "-x", str(deb), str(self.tree)], timeout=300)
            if not got.ok:
                raise DryRunError(f"dpkg-deb -x {deb.name}: {got.output.strip()[-300:]}")
            self.files.append(deb)

    # dnf

    def _dnf_fetch(self, packages: list[str]) -> None:
        dl = self.root / "dl"
        dl.mkdir(parents=True, exist_ok=True)
        repo = isc_repo_name(self.series)
        name, release = self.distro.cloudsmith_distro
        base = f"{CLOUDSMITH}/{repo}/rpm/{name}/{release}"
        argv = [
            "dnf",
            "-q",
            "download",
            f"--destdir={dl}",
            "--disablerepo=*",
            f"--setopt=cachedir={self.root / 'dnf'}",
        ]
        if os.path.basename(os.path.realpath(shutil.which("dnf") or "dnf")) != "dnf5":
            # dnf 4 plugins write node state (generate_completion_cache fills /var/cache/dnf/packages.db).
            argv += ["--disableplugin=*", "--enableplugin=download"]
        for rid, arch in (("pelagos-kea", self.machine), ("pelagos-kea-noarch", "noarch")):
            argv += [
                f"--repofrompath={rid},{base}/{arch}",
                f"--setopt={rid}.gpgcheck=1",
                f"--setopt={rid}.repo_gpgcheck=1",
                f"--setopt={rid}.gpgkey={CLOUDSMITH}/{repo}/gpg.key",
            ]
        before = set(dl.glob("*.rpm"))
        res = self._run([*argv, "-y", *packages])
        new = sorted(set(dl.glob("*.rpm")) - before)
        if not res.ok or len(new) < len(packages):
            raise DryRunError(f"dnf download: {res.output.strip()[-500:]}")
        self.tree.mkdir(parents=True, exist_ok=True)
        for rpm in new:
            meta = self._run(["rpm", "-qp", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}", str(rpm)], timeout=60)
            if meta.ok and "\t" in meta.stdout:
                n, v = meta.stdout.strip().split("\t", 1)
                self.versions[n] = v
            got = self._run(
                ["sh", "-c", 'rpm2cpio "$1" | cpio -idm --quiet -D "$2"', "sh", str(rpm), str(self.tree)],
                timeout=300,
            )
            if not got.ok:
                raise DryRunError(f"rpm2cpio {rpm.name}: {got.output.strip()[-300:]}")
            self.files.append(rpm)

    def extract(self, files: list[Path]) -> None:
        """Package files already on this node (a prepared `packages/target`) extracted into the tree,
        exactly as `fetch` extracts what it downloads; their versions noted."""
        self.tree.mkdir(parents=True, exist_ok=True)
        for path in files:
            if path.suffix == ".deb":
                meta = self._run(["dpkg-deb", "-f", str(path), "Package", "Version"], timeout=60)
                fields = dict(line.split(": ", 1) for line in meta.stdout.splitlines() if ": " in line)
                got = self._run(["dpkg-deb", "-x", str(path), str(self.tree)], timeout=300)
            elif path.suffix == ".rpm":
                meta = self._run(
                    ["rpm", "-qp", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}", str(path)], timeout=60
                )
                n, _, v = meta.stdout.strip().partition("\t")
                fields = {"Package": n, "Version": v}
                got = self._run(
                    [
                        "sh",
                        "-c",
                        'rpm2cpio "$1" | cpio -idm --quiet -D "$2"',
                        "sh",
                        str(path),
                        str(self.tree),
                    ],
                    timeout=300,
                )
            else:
                continue
            if not got.ok:
                raise DryRunError(f"cannot extract {path.name}: {got.output.strip()[-300:]}")
            if fields.get("Package") and fields.get("Version"):
                self.versions[fields["Package"]] = fields["Version"]
            self.files.append(path)

    def fetch(self, packages: list[str]) -> None:
        packages = [p for p in packages if p not in self.versions]
        if not packages:
            return
        if self.distro.is_debian:
            if not (self.root / "apt/sources.list").exists():
                self._apt_setup()
            self._apt_fetch(packages)
        elif self.distro.is_rhel:
            self._dnf_fetch(packages)
        else:
            raise DryRunError(f"no package manager for {self.distro.id}")

    # Extracted tree

    def hooks_dir(self) -> str:
        """The target's compiled-in hooks directory (the same path as the distribution's)."""
        if self.distro.is_rhel:
            return "/usr/lib64/kea/hooks"
        return f"/usr/lib/{debian_multiarch(self.machine)}/kea/hooks"

    def hooks(self) -> frozenset[str]:
        d = self.tree / self.hooks_dir().lstrip("/")
        return frozenset(p.name for p in d.glob("*.so")) if d.is_dir() else frozenset()

    def library_path(self) -> str:
        dirs = [
            self.tree / Path(self.hooks_dir()).parent.parent.relative_to("/"),
            self.tree / "usr/lib",
            self.tree / "usr/lib64",
        ]
        return ":".join(str(d) for d in dict.fromkeys(dirs) if d.is_dir())

    def binary(self, engine: str) -> Path:
        path = self.tree / "usr/sbin" / DAEMONS[engine]
        if not path.is_file():
            raise DryRunError(f"{DAEMONS[engine]} is not in the downloaded packages")
        return path

    def env(self) -> list[str]:
        return [
            f"LD_LIBRARY_PATH={self.library_path()}",
            f"KEA_HOOKS_PATH={self.tree / self.hooks_dir().lstrip('/')}",
        ]

    def version(self, engine: str) -> str:
        """The daemon's version; a daemon that cannot start (a shared library the node lacks)
        makes the dry run unreliable, not the configuration wrong."""
        res = self._run(["env", *self.env(), str(self.binary(engine)), "-v"], timeout=30)
        text = res.output.replace(str(self.tree), "").strip()
        if not res.ok or not res.stdout.strip():
            raise DryRunError(f"{DAEMONS[engine]} {self.series} does not run here: {text[-300:]}")
        return res.stdout.strip().splitlines()[0]

    def layout(self, conf_dir: Path) -> mig.TargetLayout:
        return mig.TargetLayout(
            series=self.series,
            source=self.source,
            hooks_dir=self.hooks_dir(),
            hooks=self.hooks(),
            db_packages=_DB_PACKAGES.get(self.source, {}),
            conf_dir=conf_dir.as_posix(),
        )

    def validate(
        self, engine: str, config: dict[str, Any], secrets: dict[str, str], display: str = ""
    ) -> dict[str, Any]:
        """`config` checked by the target daemon as the Kea user; hooks load by name from the extracted
        tree, and the secret files the conversion will write are temporary copies here."""
        cfg = json.loads(json.dumps(config))
        root = cfg[mig.ROOTS[engine]]
        for hook in root.get("hooks-libraries") or []:
            if isinstance(hook, dict) and isinstance(hook.get("library"), str):
                hook["library"] = os.path.basename(hook["library"])
        work = self.root / "check" / engine
        work.mkdir(parents=True, exist_ok=True)
        for i, key in enumerate(root.get("tsig-keys") or []):
            if isinstance(key, dict) and key.get("secret-file") in secrets:
                copy = work / f"secret-{i}.tsig"
                copy.write_text(secrets[key["secret-file"]])
                copy.chmod(0o640)
                key["secret-file"] = str(copy)
        conf = work / f"{DAEMONS[engine]}.conf"
        conf.write_text(json.dumps(cfg, indent=2) + "\n")
        conf.chmod(0o640)
        self._share(work)
        version = self.version(engine)
        argv = ["env", *self.env(), str(self.binary(engine)), TEST_FLAG[engine], str(conf)]
        if self.runner.is_root:
            argv = ["runuser", "-u", self.kea_user, "--", *argv]
        res = self._run(argv, timeout=120)
        output = res.output.replace(str(conf), display or conf.name).replace(str(self.tree), "")
        return {
            "ok": res.ok,
            "mode": "dry_run",
            "output": _summary(output),
            "version": version,
        }

    def _share(self, work: Path) -> None:
        """The Kea user reads the check directory through its group, nothing more."""
        if not self.runner.is_root:
            return
        if not self._run(["id", "-u", self.kea_user], timeout=30).ok:
            raise DryRunError(f"the Kea user {self.kea_user} does not exist")
        for path in (self.root, self.root / "check", work, *work.iterdir()):
            try:
                shutil.chown(path, "root", self.kea_user)
            except (LookupError, OSError) as exc:
                if os.geteuid() == 0:
                    raise DryRunError(f"cannot share {path.name} with {self.kea_user}: {exc}") from None
                return  # a test runner posing as root
            path.chmod(0o750 if path.is_dir() else 0o640)
        # Packages keep their own modes (ISC 3.2 daemons are 0750, owned by root once extracted).
        for top, _dirs, names in os.walk(self.tree):
            for path in (Path(top), *(Path(top) / n for n in names)):
                if path.is_symlink():
                    continue
                try:
                    mode = path.stat().st_mode
                    path.chmod(mode | (0o055 if path.is_dir() or mode & 0o100 else 0o044))
                except OSError as exc:
                    raise DryRunError(f"cannot share {path.name} with {self.kea_user}: {exc}") from None


def with_standby_delays(cfg: dict[str, Any], engine: str, delay_ms: int) -> dict[str, Any]:
    """The standby's 3.x file during the migration: a short failure detection so that it serves alone
    soon after the primary stops (time 2); kea-mig-delays puts the original values back."""
    out = json.loads(json.dumps(cfg))
    for rel in mig.ha_relationships(out, engine):
        rel["max-response-delay"] = int(delay_ms)
        rel["max-unacked-clients"] = 0
    return out


def _summary(output: str) -> str:
    """Warnings and errors only; INFO lines are noise next to the answer."""
    keep = [line for line in output.splitlines() if " INFO " not in line and line.strip()]
    text = "\n".join(keep)
    return text[-OUTPUT_LIMIT:]


_LOG_PREFIX = re.compile(r"^\S+ \S+ ERROR +\[[^\]]*\] ")


def error_line(output: str) -> str:
    """Why Kea refused the file: its first ERROR (the cause) and its final verdict."""
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    first = next((_LOG_PREFIX.sub("", line) for line in lines if " ERROR " in line), "")
    final = ""
    for line in reversed(lines):
        for mark in ("Error encountered:", "Syntax check failed with:"):
            if mark in line:
                final = line.split(mark, 1)[1].strip()
                break
        if final:
            break
    parts = [first] if first else []
    if final and final not in first:
        parts.append(final)
    text = ": ".join(parts) or (lines[-1] if lines else "?")
    return text[-400:]


# This node's files and kea-ctrl-agent ---------------------------------------------------------

CA_UNITS = ("kea-ctrl-agent.service", "isc-kea-ctrl-agent.service")
STORK_UNITS = ("isc-stork-agent.service",)


def read_configs(env: Any, engines: list[str] | None = None) -> dict[str, dict[str, Any]]:
    """The Kea files of this node (comments and includes as Kea reads them), by engine."""
    out = {}
    for engine in engines or list(DAEMONS):
        path = env.paths.kea_conf(DAEMONS[engine])
        if path.is_file():
            out[engine] = keafile.load(path)
    return out


# A daemon runs when its unit is active now or enabled for the next boot; only explicit answers
# make it unused, so an unknown state keeps its findings at their severity.
_IDLE = ("inactive", "failed")
_OFF = ("disabled", "masked", "masked-runtime", "not-found")


def engine_units(env: Any, engines: list[str]) -> dict[str, dict[str, Any]]:
    """{engine: {"unit","active","enabled","used"}} from systemctl (`is-active`, `is-enabled`)."""
    sm = env.service_manager
    out = {}
    for engine in engines:
        unit = env.kea_unit(engine)
        if sm.exists(unit):
            active, enabled = sm.unit_state(unit)
        else:
            active, enabled = "inactive", "not-found"
        used = not (active in _IDLE and enabled in _OFF)
        out[engine] = {
            "unit": unit,
            "active": active or "unknown",
            "enabled": enabled or "unknown",
            "used": used,
        }
    return out


_LOOPBACK = ("127.0.0.1", "::1", "localhost")
_COMMAND_FROM = re.compile(r"CTRL_AGENT_COMMAND_RECEIVED .* received from remote address (\S+)")
LOG_DAYS = 30
LOG_TAIL = 1 << 20


def _ca_config(conf: Path) -> dict[str, Any]:
    try:
        cfg = keafile.load(conf).get("Control-agent")
    except (OSError, ValueError, keafile.KeaConfigError):
        return {}
    return cfg if isinstance(cfg, dict) else {}


def _ca_signs(ca: dict[str, Any]) -> list[str]:
    """What suggests an external client: reachable off loopback, authentication or TLS set up."""
    signs = []
    host = str(ca.get("http-host", "127.0.0.1"))
    if host not in _LOOPBACK:
        signs.append(f"http-host {host}")
    if ca.get("authentication"):
        signs.append("authentication")
    if ca.get("trust-anchor") or ca.get("cert-file"):
        signs.append("tls")
    return signs


def _ca_log_clients(env: Any, ca: dict[str, Any]) -> list[str]:
    """Remote addresses of the commands the agent logged (CTRL_AGENT_COMMAND_RECEIVED, INFO), from
    the journal of its units and the files its loggers write."""
    argv = ["journalctl", "--no-pager", "-o", "cat", f"--since=-{LOG_DAYS}d"]
    argv += [x for u in CA_UNITS for x in ("-u", u)]
    res = env.runner.run([*argv, "-g", "CTRL_AGENT_COMMAND_RECEIVED"], check=False, mutates=False, timeout=60)
    text = res.stdout
    for logger in ca.get("loggers") or []:
        options = logger.get("output-options") if isinstance(logger, dict) else None
        for opt in options or []:
            out = opt.get("output") if isinstance(opt, dict) else None
            if isinstance(out, str) and os.path.isabs(out):
                try:
                    with open(out, "rb") as f:
                        f.seek(max(0, os.fstat(f.fileno()).st_size - LOG_TAIL))
                        text += f.read().decode("utf-8", "replace")
                except OSError:
                    continue
    return [m.group(1).strip("[]") for m in _COMMAND_FROM.finditer(text)]


def ctrl_agent_state(env: Any) -> dict[str, Any]:
    """{"present","active","clients","signs"}: Pelagos never uses kea-ctrl-agent, so an established
    connection to its port, a command in its logs or a Stork agent is an external client; `signs`
    hint at one when none is seen (a periodic client is usually not connected)."""
    conf = env.paths.kea_conf("kea-ctrl-agent")
    sm = env.service_manager
    active = any(sm.is_active(u) for u in CA_UNITS)
    present = conf.is_file() or active
    clients: list[str] = []
    signs: list[str] = []
    if active:
        ca = _ca_config(conf)
        try:
            port = int(ca.get("http-port", 8000))
        except (TypeError, ValueError):
            port = 8000
        signs = _ca_signs(ca)
        clients += _ca_log_clients(env, ca)
        res = env.runner.run(
            ["ss", "-Htn", "state", "established", f"( sport = :{port} )"],
            check=False,
            mutates=False,
            timeout=30,
        )
        for line in res.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 4:
                clients.append(parts[-1].rsplit(":", 1)[0].strip("[]"))
    if any(sm.is_active(u) for u in STORK_UNITS):
        clients.append("isc-stork-agent")
    return {"present": present, "active": active, "clients": sorted(set(clients)), "signs": signs}


# Analysis of this node -----------------------------------------------------------------------


def analyze(
    env: Any,
    series: str,
    source: str,
    configs: dict[str, dict[str, Any]],
    node_id: str = "",
    ctrl_agent: dict[str, Any] | None = None,
    workdir: Path | None = None,
    units: dict[str, dict[str, Any]] | None = None,
    keep: dict[str, Any] | None = None,
    standby_delay_ms: int | None = None,
) -> dict[str, Any]:
    """Converts and dry-runs this node's Kea files (`configs`: engine -> 2.6 file) for one target.

    Returns {"node_id","series","source","target_version","findings","diffs","files","packages",
    "validation","configs","units"}; `units` is the state of each daemon's unit (engine_units),
    `files` lists the secret files the conversion adds (paths only) and `configs` the converted
    files with passwords and secrets masked. Nothing outside a temporary directory changes.
    `keep` (the prepare step) receives the unmasked `conversions` and `fetch_error`, the download
    failure that skipped the validation ("" when the packages came). `standby_delay_ms` (the prepare
    of a standby): each HA file is also checked as time 1 installs it, with the short delays.
    """
    check_target(env.distro, series, source)
    engines = [e for e in ("kea4", "kea6", "d2") if e in configs]
    tmp = Path(tempfile.mkdtemp(prefix="pelagos-kea-dry-run-", dir=workdir))
    ws = Workspace(
        env.runner, env.distro, series, source, tmp, fetch_url=env.t.fetch, kea_user=env.paths.kea_user
    )
    findings: list[mig.Finding] = []
    out: dict[str, Any] = {
        "node_id": node_id,
        "series": series,
        "source": source,
        "target_version": "",
        "findings": [],
        "diffs": {},
        "files": [],
        "packages": {},
        "validation": {},
        "configs": {},
        "units": units or {},
    }
    try:
        skipped = ""
        installed = installed_packages(env.runner, env.distro)
        try:
            ws.fetch(wanted_packages(env.distro, source, engines, installed=installed))
            layout = ws.layout(env.paths.kea_conf_dir)
        except DryRunError as exc:
            skipped = str(exc)
            layout = mig.TargetLayout(
                series,
                source,
                env.paths.kea_hooks_dir.as_posix(),
                None,
                _DB_PACKAGES.get(source, {}),
                conf_dir=env.paths.kea_conf_dir.as_posix(),
            )
        conversions = {}
        for engine in engines:
            conv = mig.convert(engine, configs[engine], layout, node_id)
            conversions[engine] = conv
            findings += conv.findings
            out["diffs"][engine] = conv.diff(str(env.paths.kea_conf(DAEMONS[engine])))
            out["files"] += sorted(conv.files)
            out["configs"][engine] = mig.mask_secrets(conv.after)
        extra = [p for c in conversions.values() for p in c.packages]
        if not skipped and extra:
            try:
                ws.fetch(extra)
            except DryRunError as exc:
                skipped = str(exc)
        for engine, conv in conversions.items():
            if skipped:
                result = {"ok": False, "mode": "skipped", "output": skipped, "version": ""}
            else:
                try:
                    display = str(env.paths.kea_conf(DAEMONS[engine]))
                    result = ws.validate(engine, conv.after, conv.files, display)
                    if result["ok"] and standby_delay_ms and mig.ha_relationships(conv.after, engine):
                        # Time 1 installs the standby's file with the short delays: check that one too.
                        short = with_standby_delays(conv.after, engine, standby_delay_ms)
                        result = ws.validate(engine, short, conv.files, display)
                except DryRunError as exc:
                    result = {"ok": False, "mode": "skipped", "output": str(exc), "version": ""}
            out["validation"][engine] = result
            if result["mode"] == "skipped":
                findings.append(
                    mig.Finding(
                        "info",
                        "validation_skipped",
                        engine,
                        "",
                        {"reason": result["output"][-300:]},
                        "none",
                        None,
                        node_id,
                    )
                )
            elif not result["ok"]:
                findings.append(
                    mig.Finding(
                        "blocking",
                        "validation_failed",
                        engine,
                        "",
                        {"version": result["version"] or series, "error": error_line(result["output"])},
                        "manual",
                        mig.REF_KB30,
                        node_id,
                    )
                )
            out["target_version"] = out["target_version"] or result.get("version", "")
        if ctrl_agent is not None:
            findings += mig.ctrl_agent(
                bool(ctrl_agent.get("present")),
                bool(ctrl_agent.get("active")),
                list(ctrl_agent.get("clients") or []),
                node_id,
                list(ctrl_agent.get("signs") or []),
            )
        wanted = wanted_packages(env.distro, source, engines, extra, installed)
        out["packages"] = package_changes(
            source, installed, {n: ws.versions.get(n, "") for n in wanted}, series
        )
        out["target_version"] = out["target_version"] or ws.versions.get(wanted[0], "")
        if keep is not None:
            keep.update(conversions=conversions, fetch_error=skipped)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    out["findings"] = [f.to_dict() for f in findings]
    return out


def dry_run_request(env: Any, request: dict[str, Any]) -> dict[str, Any]:
    """The `kea_dry_run` helper operation: `configs` (engine -> file) default to this node's files;
    read-only, everything happens in a temporary directory removed afterwards."""
    series, source = str(request.get("series") or ""), str(request.get("source") or "")
    configs = request.get("configs")
    if configs is None:
        configs = read_configs(env)
    if not isinstance(configs, dict) or not configs:
        raise ValueError("no Kea configuration to analyze")
    for engine, cfg in configs.items():
        if (
            engine not in DAEMONS
            or not isinstance(cfg, dict)
            or not isinstance(cfg.get(mig.ROOTS[engine]), dict)
        ):
            raise ValueError(f"invalid configuration for {engine!r}")
    return analyze(
        env,
        series,
        source,
        configs,
        str(request.get("node_id") or env.node_id),
        ctrl_agent_state(env),
        units=engine_units(env, list(configs)),
    )
