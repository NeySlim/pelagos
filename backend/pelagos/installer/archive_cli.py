# SPDX-License-Identifier: Apache-2.0
"""`pelagos backup` and `pelagos restore` (design 13.2, architecture section 23, batch B5)."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

from pelagos.installer import cli as icli
from pelagos.installer.cli import EXIT_FAILED, EXIT_NOT_CONFIRMED, EXIT_OK, EXIT_USAGE

WAIT_STEP = 1.0


# backup -------------------------------------------------------------------------------------


def _context(args: argparse.Namespace) -> Any:
    from pelagos.core.context import NodeContext
    from pelagos.core.paths import Paths

    if getattr(args, "home", None):
        os.environ["PELAGOS_HOME"] = os.path.abspath(args.home)
    paths = Paths.from_env()
    if not (paths.node_toml.exists() and paths.cluster_toml.exists()):
        raise FileNotFoundError(f"{paths.node_toml}: this node is not initialized")
    return NodeContext.build(paths)


def _meta_line(meta: Any, where: str) -> str:
    state = "complete" if meta.complete else "INCOMPLETE"
    stamp = meta.created_at.isoformat()
    return f"{stamp}  {meta.size:>10}  {state:<10}  {where}  {meta.filename}  ({meta.id})"


def _list(ctx: Any, as_json: bool) -> int:
    from pelagos.archives.inbox import ArchiveInbox
    from pelagos.archives.store import ArchiveStore

    store = ArchiveStore(ctx.paths.archives_dir)
    own = [(store.path(m), m) for m in store.list()]
    held = ArchiveInbox(ctx.paths.archives_dir, ctx.node.id, ctx.settings).held(None)
    held = [(p, m) for p, m in held if m.node_id != ctx.node.id]
    names = {n.id: n.name for n in ctx.cluster().nodes}
    if as_json:
        items = [{"path": str(p), "held_for": None, **m.to_dict()} for p, m in own]
        items += [{"path": str(p), "held_for": m.node_id, **m.to_dict()} for p, m in held]
        print(json.dumps({"items": items}, indent=2))
        return EXIT_OK
    if not own and not held:
        print("no archive on this node")
    for p, m in own:
        print(_meta_line(m, "local") + f"\n    {p}")
    for p, m in held:
        print(_meta_line(m, f"held for {names.get(m.node_id, m.node_id)}") + f"\n    {p}")
    return EXIT_OK


def _give_back(ctx: Any, folder: Path) -> None:
    if os.geteuid() == 0:
        from pelagos.platform import PELAGOS_USER, give_tree_to

        give_tree_to(PELAGOS_USER, [folder])


def _one_off(ctx: Any, args: argparse.Namespace) -> int:
    """An archive written to --output only: no store, no destination, no schedule state."""
    from pelagos.archives import age, keys
    from pelagos.collector.archive_collect import Builder
    from pelagos.collector.archives import _helper
    from pelagos.collector.main import build_backends
    from pelagos.core import settings_registry as reg

    settings = ctx.settings()
    recipients = keys.encryption_recipients(settings)
    for r in args.recipient:
        if not age.is_recipient(r):
            print(f"error: {r} is not an age recipient (age1...)", file=sys.stderr)
            return EXIT_USAGE
        if r not in recipients:
            recipients.append(r)
    if not recipients:
        print("error: no recipient: generate the cluster archive key or give --recipient", file=sys.stderr)
        return EXIT_USAGE
    out = Path(args.output)
    helper = None if os.geteuid() == 0 else _helper()
    builder = Builder(ctx, build_backends(ctx), None, helper, ctx.paths.locks_dir)
    include_leases = bool(reg.get(settings, "archives.include_leases_enabled")) and not args.no_leases
    collected = builder.build(out, recipients, include_leases)
    meta = collected.meta
    path = out / meta.filename
    if args.json:
        print(json.dumps({"path": str(path), "archive": meta.to_dict(), "notes": collected.notes}, indent=2))
    else:
        print(f"written {path} ({meta.size} bytes, sha256 {meta.sha256})")
        for note in collected.notes:
            print(f"note: {note}", file=sys.stderr)
        if not meta.complete:
            print("incomplete, not archived: " + ", ".join(collected.manifest.unreadable), file=sys.stderr)
    return EXIT_OK if meta.complete or not args.strict else EXIT_FAILED


def _report(state: Any, as_json: bool) -> int:
    ok = state.last_error is None and state.last_archive_id is not None
    if as_json:
        print(json.dumps({"ok": ok, "state": state.to_dict()}, indent=2))
    elif ok:
        print(f"archive {state.last_archive_id} written ({'complete' if state.complete else 'incomplete'})")
        for dest, err in sorted(state.errors.items()):
            print(f"destination {dest}: {err}", file=sys.stderr)
    else:
        print(f"archive failed: {state.last_error}", file=sys.stderr)
    return EXIT_OK if ok else EXIT_FAILED


def _run_now(ctx: Any, args: argparse.Namespace) -> int:
    """Asks the running collector for a run and waits for it; runs here when no collector listens."""
    from pelagos.archives.store import ArchiveStore
    from pelagos.collector.archives import EVENT_ARCHIVE, ArchiveRunner
    from pelagos.core.signals import signal_collector

    store = ArchiveStore(ctx.paths.archives_dir)
    before = store.load_state().last_attempt
    if signal_collector(ctx.paths.collector_sock, EVENT_ARCHIVE):
        if not args.json:
            print("asked the collector for an archive, waiting")
        deadline = time.monotonic() + args.timeout
        while time.monotonic() < deadline:
            state = store.load_state()
            if state.last_attempt != before and not state.running:
                return _report(state, args.json)
            time.sleep(WAIT_STEP)
        print(f"no archive finished within {args.timeout} s: see `pelagos backup --list`", file=sys.stderr)
        return EXIT_FAILED
    from pelagos.collector.archives import _helper
    from pelagos.collector.main import build_backends

    helper = (lambda: None) if os.geteuid() == 0 else _helper
    runner = ArchiveRunner(ctx, build_backends(ctx), helper=helper)
    runner.run("cli")
    _give_back(ctx, ctx.paths.archives_dir)
    return _report(store.load_state(), args.json)


def cmd_backup(args: argparse.Namespace) -> int:
    try:
        ctx = _context(args)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    try:
        if args.list:
            return _list(ctx, args.json)
        if args.output:
            return _one_off(ctx, args)
        return _run_now(ctx, args)
    except PermissionError as exc:
        print(f"error: {exc} (run as root or as the pelagos user)", file=sys.stderr)
        return EXIT_FAILED
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_FAILED


# restore ------------------------------------------------------------------------------------


def _identities(args: argparse.Namespace, env: Any) -> list[str]:
    from pelagos.installer.restore import read_identities

    if args.identity:
        return read_identities(args.identity, sys.stdin)
    # Rebuilding a node that still has its master key: the cluster identities it keeps.
    if not (env.node_initialized() and env.node_paths.master_key.exists()):
        return []
    from pelagos.archives import keys
    from pelagos.core.config_store import ConfigStore
    from pelagos.core.secrets import SecretBox

    cluster = ConfigStore(env.node_paths.node_toml, env.node_paths.cluster_toml).load_cluster()
    return keys.cluster_identities(cluster, SecretBox.from_file(env.node_paths.master_key))


def _print_plan(plan: Any) -> None:
    m = plan.manifest
    print(
        f"archive {m.archive_id} of {m.node_name} ({m.node_id}), {m.created_at.isoformat()}, "
        f"Pelagos {m.versions.get('pelagos', '?')}"
    )
    print(f"restores: {', '.join(plan.groups) or 'nothing'}")
    for part, count in plan.parts().items():
        print(f"  {part}: {count} file(s)")
    for z in plan.zones:
        print(f"  zone {z['zone']} ({z['view']}) serial {z['serial']} -> {z['path']}")
    for p in plan.removes:
        print(f"  remove {p}")
    if plan.units:
        print(f"services stopped, then started: {', '.join(plan.units)}")
    for w in plan.warnings:
        print(f"warning: {w}", file=sys.stderr)
    for e in plan.errors:
        print(f"error: {e}", file=sys.stderr)


def _confirm(args: argparse.Namespace, summary: str) -> bool:
    if args.yes:
        return True
    if not sys.stdin.isatty() or (args.identity and "-" in args.identity):
        print("not applied: pass --yes to apply without a terminal", file=sys.stderr)
        return False
    return input(f"{summary}? [y/N] ").strip().lower() in ("y", "yes")


def cmd_restore(args: argparse.Namespace) -> int:
    from pelagos.installer.restore import OfflineRestore, RestoreError

    if not args.dry_run and os.geteuid() != 0:
        print("restoring needs root: run with sudo, or use --dry-run", file=sys.stderr)
        return EXIT_USAGE
    env = icli._env(args)
    only = [g.strip() for g in args.only.split(",") if g.strip()] if args.only else None
    try:
        identities = _identities(args, env)
        restore = OfflineRestore(
            env,
            Path(args.archive),
            identities,
            only=only,
            workdir=Path(args.workdir) if args.workdir else None,
            backup_root=Path(args.backup_dir),
            force=args.force,
            log=(lambda _l: None) if args.json else print,
        )
    except RestoreError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    with restore:
        try:
            plan = restore.prepare()
        except RestoreError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_FAILED
        if not args.json:
            _print_plan(plan)
        if plan.errors:
            if args.json:
                print(json.dumps({"plan": plan.to_dict()}, indent=2))
            return EXIT_FAILED
        if args.dry_run:
            checks = restore.check_copy(plan)
            if args.json:
                print(json.dumps({"plan": plan.to_dict(), "checks": checks}, indent=2))
            else:
                for c in checks:
                    mark = {True: "ok", False: "FAILED", None: "not checked"}[c.get("ok")]
                    print(f"check {c['what']}: {mark}")
                    if c.get("ok") is False:
                        print(f"    {c.get('output', '')[-600:]}")
            return EXIT_OK if all(c.get("ok") is not False for c in checks) else EXIT_FAILED
        if not _confirm(args, f"restore {', '.join(plan.groups)} of {plan.manifest.node_name} on this host"):
            return EXIT_NOT_CONFIRMED
        result = restore.apply(plan, start=not args.no_start)
    if args.json:
        print(json.dumps({"plan": plan.to_dict(), "result": result.to_dict()}, indent=2))
    else:
        for c in result.checks:
            mark = {True: "ok", False: "FAILED", None: "not checked"}[c.get("ok")]
            print(f"check {c['what']}: {mark}")
        for e in result.errors:
            print(f"error: {e}", file=sys.stderr)
        if result.rolled_back:
            print(f"rolled back: previous files put back (copies in {result.backup_dir})", file=sys.stderr)
        elif result.ok:
            print(f"done: {result.written} files restored; replaced files saved in {result.backup_dir}")
            if args.no_start:
                print(f"services left stopped: {', '.join(plan.units)}")
    return EXIT_OK if result.ok else EXIT_FAILED


def add_parsers(sub: Any) -> None:
    b = sub.add_parser("backup", help="archive this node now, or list the archives it holds")
    b.add_argument("--list", action="store_true", help="list the archives on this node, own and held")
    b.add_argument("--output", metavar="DIR", help="write one archive to DIR only (no store, no destination)")
    b.add_argument(
        "--recipient", action="append", default=[], metavar="AGE1", help="also encrypt to this key (--output)"
    )
    b.add_argument("--no-leases", action="store_true", help="leave the Kea lease files out (--output)")
    b.add_argument("--strict", action="store_true", help="exit 1 when the archive is incomplete (--output)")
    b.add_argument("--timeout", type=int, default=900, help="seconds to wait for the collector (default 900)")
    b.add_argument("--json", action="store_true", help="machine-readable output")
    b.set_defaults(func=cmd_backup)

    r = sub.add_parser("restore", help="rebuild this node from an archive (root, services stopped)")
    r.add_argument("--archive", required=True, help="the .tar.gz.age file (its .sha256 beside it is checked)")
    r.add_argument(
        "--identity",
        action="append",
        default=[],
        metavar="FILE",
        help="age identity file (cluster or operator key), - for stdin; repeatable "
        "(default: the cluster identities of this node, when it still has them)",
    )
    r.add_argument("--only", help="comma list among bind,kea,pelagos (default: all)")
    r.add_argument("--dry-run", action="store_true", help="show the plan and check a copy, change nothing")
    r.add_argument("--no-start", action="store_true", help="leave the services stopped afterwards")
    r.add_argument("--force", action="store_true", help="replace the identity of another node on this host")
    r.add_argument("--workdir", help="where the archive is opened (default /run when it has room)")
    r.add_argument(
        "--backup-dir", default="/var/backups", help="where replaced files are saved (default /var/backups)"
    )
    r.add_argument("--yes", "-y", action="store_true", help="apply without asking")
    r.add_argument("--json", action="store_true", help="machine-readable output")
    r.set_defaults(func=cmd_restore)
