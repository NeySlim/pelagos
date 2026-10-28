# SPDX-License-Identifier: Apache-2.0
"""`pelagos install`, `pelagos import` and `pelagos audit`: plan, show, confirm, run as a Job.

`pelagos backup` and `pelagos restore` live in `archive_cli`."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from collections.abc import Callable
from typing import Any

from pelagos.domain import Job, JobState, Plan
from pelagos.platform import CommandError

EXIT_OK, EXIT_FAILED, EXIT_USAGE, EXIT_NOT_CONFIRMED = 0, 1, 2, 3


def _env(args: argparse.Namespace) -> Any:
    from pelagos.core.paths import Paths
    from pelagos.installer.env import InstallerEnv

    if getattr(args, "home", None):
        os.environ["PELAGOS_HOME"] = os.path.abspath(args.home)
    return InstallerEnv.detect(node_paths=Paths.from_env(), dry_run=bool(getattr(args, "dry_run", False)))


def _engines(value: str | None) -> list[str] | None:
    if not value:
        return None
    return [e.strip() for e in value.split(",") if e.strip()]


def _print_plan(plan: Plan, as_json: bool) -> None:
    if as_json:
        print(json.dumps(plan.to_dict(), indent=2))
        return
    print(f"plan {plan.id}: {plan.summary}")
    for c in plan.changes:
        if not c.node_ids:
            nodes = " (manual)"
        elif c.node_ids == [plan.node_id]:
            nodes = ""
        else:
            nodes = f" (nodes: {', '.join(c.node_ids)})"
        print(f"  - {c.target}{nodes}")
    if plan.diff:
        print("\n" + plan.diff)
    for v in plan.validations:
        if not v.ok:
            print(f"\nvalidation failed ({v.tool}):\n{v.output}", file=sys.stderr)


def _confirm(args: argparse.Namespace, plan: Plan) -> bool:
    if args.yes or args.dry_run:
        return True
    if not sys.stdin.isatty():
        print("not applied: pass --yes to apply without a terminal", file=sys.stderr)
        return False
    answer = input(f"apply {plan.summary}? [y/N] ")
    return answer.strip().lower() in ("y", "yes")


def _progress(as_json: bool) -> Any:
    shown: set[tuple[int, str]] = set()

    def report(job: Job) -> None:
        if as_json:
            return
        for i, step in enumerate(job.steps):
            key = (i, step["state"])
            if step["state"] in ("done", "failed") and key not in shown:
                shown.add(key)
                mark = "ok" if step["state"] == "done" else "FAILED"
                print(f"[{job.progress:3d}%] {step['name']}: {mark}")
                for line in (step.get("output") or "").splitlines():
                    print(f"        {line}")

    return report


def _give_node_tree(env: Any) -> None:
    """Root wrote node.toml, keys and state: the service user gets them back (pelagos.env stays root's)."""
    from pelagos.platform import PELAGOS_USER, give_tree_to

    paths = env.node_paths
    if not paths.node_toml.exists():
        return
    try:
        give_tree_to(PELAGOS_USER, [paths.etc, paths.var], skip=[paths.etc / "pelagos.env"])
    except OSError as exc:
        print(
            f"warning: could not give {paths.etc} and {paths.var} to {PELAGOS_USER}: {exc}", file=sys.stderr
        )


def _run(
    args: argparse.Namespace, env: Any, plan: Plan, before_apply: Callable[[], str | None] | None = None
) -> int:
    from pelagos.installer.jobs import apply_plan

    _print_plan(plan, args.json)
    if plan.error:
        return EXIT_FAILED
    if not args.dry_run and os.geteuid() != 0:
        print("applying needs root: run with sudo, or use --dry-run", file=sys.stderr)
        return EXIT_USAGE
    if not _confirm(args, plan):
        return EXIT_NOT_CONFIRMED
    if before_apply is not None and not args.dry_run:
        try:
            error = before_apply()
        except (OSError, ValueError) as exc:
            error = str(exc)
        if error:
            print(f"error: {error}", file=sys.stderr)
            return EXIT_FAILED
    if not args.dry_run and not env.node_initialized():
        print(
            "note: this node is not initialized; run `pelagos init`, then `pelagos import` "
            "to record the engines and their keys",
            file=sys.stderr,
        )
    job = apply_plan(plan, env, progress=_progress(args.json))
    if not args.dry_run:
        _give_node_tree(env)
    if args.json:
        print(json.dumps(job.to_dict(), indent=2))
    elif job.state is JobState.DONE:
        print(f"done: {plan.summary}")
    else:
        print(f"failed: {job.error}", file=sys.stderr)
    return EXIT_OK if job.state is JobState.DONE else EXIT_FAILED


def _admin_password(args: argparse.Namespace) -> str | None:
    password = args.admin_password or os.environ.get("PELAGOS_ADMIN_PASSWORD")
    if not password and sys.stdin.isatty():
        try:
            password = getpass.getpass("first admin password: ")
        except (EOFError, KeyboardInterrupt):
            return None
    return password or None


def _init_node(
    args: argparse.Namespace, env: Any, plan: Plan, engines: list[str]
) -> Callable[[], str | None]:
    """Initializes the node once the plan is confirmed, then moves the plan onto the new node id."""

    def run() -> str | None:
        from pelagos.auth.passwords import WeakPassword, check_strength
        from pelagos.core.bootstrap import bootstrap_first_node

        password = _admin_password(args)
        if not password:
            return "--init needs PELAGOS_ADMIN_PASSWORD, a terminal to ask for it, or --admin-password"
        try:
            check_strength(password)
        except WeakPassword as exc:
            return f"admin password refused: {exc}"
        result = bootstrap_first_node(
            env.node_paths, name=args.name, admin_password=password, engines={e: True for e in engines}
        )
        old, env.node_id = env.node_id, result.node.id
        plan.node_id = env.node_id
        plan.target_node_ids = [env.node_id if n == old else n for n in plan.target_node_ids]
        for c in plan.changes:
            c.node_ids = [env.node_id if n == old else n for n in c.node_ids]
        for p in plan.preconditions:
            if p.node_id == old:
                p.node_id = env.node_id
        print(f"node {result.node.name} ({result.node.id}) initialized")
        return None

    return run


def cmd_install(args: argparse.Namespace) -> int:
    from pelagos.installer.detect import detect_env
    from pelagos.installer.install import build_install_plan

    env = _env(args)
    if args.detect:
        print(json.dumps(detect_env(env), indent=2, default=str))
        return EXIT_OK
    engines = _engines(args.engines) or ["bind", "kea4", "d2"]
    try:
        plan = build_install_plan(env, engines, args.source, args.isc_series, created_by="cli")
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except (CommandError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_FAILED
    init = _init_node(args, env, plan, engines) if args.init and not env.node_initialized() else None
    return _run(args, env, plan, before_apply=init)


def cmd_import(args: argparse.Namespace) -> int:
    from pelagos.installer.detect import detect_env, import_defaults
    from pelagos.installer.importer import build_import_plan

    env = _env(args)
    engines = _engines(args.engines)
    if engines is None:
        try:
            found = detect_env(env)["engines"]
        except (CommandError, OSError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_FAILED
        engines, skipped = import_defaults(found)
        for name, why in skipped.items():
            print(f"skipped {name}: {why} (name it in --engines to adopt it anyway)", file=sys.stderr)
        if not engines:
            print("no installed engine with a configuration found", file=sys.stderr)
            return EXIT_USAGE
    try:
        plan = build_import_plan(env, engines, created_by="cli")
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except CommandError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_FAILED
    return _run(args, env, plan)


def cmd_audit(args: argparse.Namespace) -> int:
    from pelagos.installer.security_audit import build_security_plan, run_audit

    env = _env(args)
    try:
        findings = run_audit(env)
    except (CommandError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_FAILED
    if not args.fix and not args.fix_all:
        if args.json:
            print(json.dumps({"findings": [f.to_dict() for f in findings]}, indent=2))
        elif not findings:
            print("no finding")
        else:
            for f in findings:
                print(
                    f"[{f.severity}] {f.id}\n    {f.description}\n"
                    f"    proposal: {f.proposal}\n    risk: {f.risk}"
                )
        return EXIT_OK
    ids = [f.id for f in findings if f.to_dict()["remediable"]] if args.fix_all else list(args.fix)
    shared = [i for i in ids if ":weak_shared_kea_key:" in i]
    peers = _d2_peers(env) if shared else []
    if peers:
        note = (
            f"{', '.join(shared)}: D2 also runs on {', '.join(peers)}; switch the shared key from "
            "Administration, Security audit (or POST /api/v1/install/security/plan), which reaches every node"
        )
        if not args.fix_all:
            print(f"error: {note}", file=sys.stderr)
            return EXIT_USAGE
        print(f"skipped {note}", file=sys.stderr)
        ids = [i for i in ids if i not in shared]
    if not ids:
        print("nothing to remediate")
        return EXIT_OK
    try:
        plan = build_security_plan(env, ids, created_by="cli")
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except (CommandError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_FAILED
    return _run(args, env, plan)


def _d2_peers(env: Any) -> list[str]:
    """Names of the other cluster nodes running D2: this command only runs steps on this node, and
    removing the old shared key here would break their DDNS updates."""
    if not env.node_initialized():
        return []
    from pelagos.core.config_store import ConfigStore

    cluster = ConfigStore(env.node_paths.node_toml, env.node_paths.cluster_toml).load_cluster()
    return [n.name for n in cluster.nodes if n.modules.d2 and n.id != env.node_id]


def _common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--dry-run", action="store_true", help="show and walk the plan without changing anything")
    p.add_argument("--yes", "-y", action="store_true", help="apply without asking")
    p.add_argument("--json", action="store_true", help="machine-readable output")


def add_parsers(sub: Any) -> None:
    i = sub.add_parser("install", help="install BIND and/or Kea, then adopt their configuration")
    i.add_argument("--engines", help="comma list of bind,kea4,kea6,d2 (default bind,kea4,d2)")
    i.add_argument("--source", choices=("distro", "isc"), default="distro", help="where Kea comes from")
    i.add_argument("--isc-series", help="ISC Kea series for --source isc (default 3.2)")
    i.add_argument("--detect", action="store_true", help="print what is installed and exit")
    i.add_argument(
        "--init",
        action="store_true",
        help="also initialize this node when it is not yet; the first admin password comes from "
        "PELAGOS_ADMIN_PASSWORD or is asked on the terminal",
    )
    i.add_argument("--name", help="node name for --init (default: short hostname)")
    i.add_argument(
        "--admin-password", help="first admin password for --init (visible in ps: prefer the variable)"
    )
    _common(i)
    i.set_defaults(func=cmd_install)

    m = sub.add_parser("import", help="adopt an existing BIND/Kea configuration without rewriting it")
    m.add_argument(
        "--engines",
        help="comma list (default: installed engines with a configuration that run or are enabled)",
    )
    _common(m)
    m.set_defaults(func=cmd_import)

    a = sub.add_parser("audit", help="security audit of the configuration, and its remediation")
    a.add_argument("--fix", action="append", default=[], metavar="FINDING_ID", help="remediate this finding")
    a.add_argument("--fix-all", action="store_true", help="remediate every finding that has a remediation")
    _common(a)
    a.set_defaults(func=cmd_audit)

    from pelagos.installer.archive_cli import add_parsers as add_archive_parsers

    add_archive_parsers(sub)
