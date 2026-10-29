# SPDX-License-Identifier: Apache-2.0
"""`pelagos permissions`: the permission guard from the command line (deploy script, postinst).

`check` probes every standing path of this node's engines. With `--unit` (root) it runs itself in a
transient unit that copies the named unit's identity and sandbox from `systemctl show`, so the probe
meets the same ReadWritePaths, RestrictSUIDSGID and groups as the service. `ensure` (root, postinst)
creates the missing folders; it never changes an existing one.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from typing import Any

EXIT_OK, EXIT_FAILED, EXIT_USAGE = 0, 1, 2
# What the probe needs from the unit: identity, environment, file system view, system call filters.
UNIT_PROPERTIES = (
    "User",
    "Group",
    "SupplementaryGroups",
    "UMask",
    "WorkingDirectory",
    "NoNewPrivileges",
    "ProtectSystem",
    "ProtectHome",
    "ReadWritePaths",
    "ReadOnlyPaths",
    "InaccessiblePaths",
    "PrivateTmp",
    "PrivateDevices",
    "ProtectKernelTunables",
    "ProtectKernelModules",
    "ProtectControlGroups",
    "RestrictSUIDSGID",
    "RestrictNamespaces",
    "RestrictRealtime",
    "LockPersonality",
    "SystemCallArchitectures",
    "SystemCallFilter",
    "SystemCallErrorNumber",
    "CapabilityBoundingSet",
    "AmbientCapabilities",
)


def _print(checks: list[dict[str, Any]], as_json: bool) -> None:
    if as_json:
        print(json.dumps({"checks": checks}, indent=1))
        return
    for c in checks:
        mark = "ok" if c["ok"] else "NOT WRITABLE"
        print(f"{mark:13} {c['kind']:4} {c['path']} ({c['purpose']}, {c.get('route') or c.get('problem')})")
        if not c["ok"]:
            print(f"              {c.get('text')}")


def unit_properties(unit: str) -> list[str]:
    """`-p Name=value` arguments for systemd-run, read from the live unit (drop-ins included)."""
    out = subprocess.run(
        ["systemctl", "show", unit, "--no-pager", *[f"--property={p}" for p in UNIT_PROPERTIES]],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    ).stdout
    props: list[str] = []
    for line in out.splitlines():
        name, _, value = line.partition("=")
        if name not in UNIT_PROPERTIES or value == "":
            continue
        if name == "CapabilityBoundingSet" and value.strip() == "":
            continue
        props += ["-p", f"{name}={value}"]
    env = subprocess.run(
        ["systemctl", "show", unit, "--no-pager", "--property=EnvironmentFiles", "--value"],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    ).stdout
    for line in env.splitlines():
        path = line.split(" ", 1)[0].strip()
        if path:
            props += ["-p", f"EnvironmentFile=-{path}"]
    return props


def check_in_unit(unit: str) -> tuple[int, list[dict[str, Any]]]:
    """Run `pelagos permissions check --json` in a transient copy of `unit`; (exit code, checks)."""
    if os.geteuid() != 0:
        raise PermissionError("--unit needs root (systemd-run of a transient unit)")
    runner = shutil.which("systemd-run")
    if runner is None:
        raise FileNotFoundError("systemd-run not found")
    cmd = [
        runner,
        "--wait",
        "--pipe",
        "--quiet",
        "--collect",
        f"--description=Pelagos permission check as {unit}",
        *unit_properties(unit),
        sys.executable,
        "-m",
        "pelagos.cli",
        "permissions",
        "check",
        "--json",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=300)
    try:
        checks = json.loads(proc.stdout).get("checks") or []
    except ValueError:
        raise RuntimeError(
            f"the check in {unit} failed: {(proc.stderr or proc.stdout).strip()[:500]}"
        ) from None
    return proc.returncode, checks


def local_checks() -> list[dict[str, Any]]:
    """This process's checks of every engine of this node (node.toml), or of a default BIND."""
    from pelagos.core import permguard
    from pelagos.installer import path_access
    from pelagos.installer.env import InstallerEnv

    env = InstallerEnv.detect()
    return [c.to_dict() for c in permguard.run(path_access.targets(env))]


def cmd_permissions(args: argparse.Namespace) -> int:
    if args.action == "check":
        try:
            if args.unit:
                code, checks = check_in_unit(args.unit)
            else:
                checks = local_checks()
                code = EXIT_OK
        except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
            print(f"pelagos permissions: {exc}", file=sys.stderr)
            return EXIT_USAGE
        _print(checks, args.json)
        bad = [c for c in checks if not c["ok"]]
        if bad and not args.json:
            print(f"\n{len(bad)} path(s) not writable by the service", file=sys.stderr)
        return EXIT_FAILED if bad or code == EXIT_FAILED else EXIT_OK
    if args.action == "ensure":
        from pelagos.installer import path_access
        from pelagos.installer.env import InstallerEnv

        if os.geteuid() != 0 and not args.dry_run:
            print("pelagos permissions ensure: run as root", file=sys.stderr)
            return EXIT_USAGE
        try:
            lines = path_access.ensure(InstallerEnv.detect(dry_run=args.dry_run))
        except Exception as exc:
            print(f"pelagos permissions ensure: {exc}", file=sys.stderr)
            return EXIT_FAILED
        for line in lines:
            print(f"pelagos: {line}")
        return EXIT_OK
    return EXIT_USAGE


def add_parser(sub: Any) -> None:
    p = sub.add_parser("permissions", help="check or set up the folders the pelagos services write")
    p.add_argument("action", choices=("check", "ensure"))
    p.add_argument("--json", action="store_true", help="check: machine-readable output")
    p.add_argument(
        "--unit", help="check: run in a transient copy of this unit's sandbox (root), e.g. pelagos-collector"
    )
    p.add_argument("--dry-run", action="store_true", help="ensure: print what would be created")
    p.set_defaults(func=cmd_permissions)
