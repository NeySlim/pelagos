# SPDX-License-Identifier: Apache-2.0
"""The `pelagos` command: serve, collector, version, init, install, import, audit, enroll, helper, user."""

from __future__ import annotations

import argparse
import getpass
import logging
import os
import sys
from pathlib import Path

from pelagos import __version__
from pelagos.core.paths import Paths


def _paths(args: argparse.Namespace) -> Paths:
    if args.home:
        os.environ["PELAGOS_HOME"] = str(Path(args.home).resolve())
    return Paths.from_env()


def cmd_version(_: argparse.Namespace) -> int:
    print(f"pelagos {__version__}")
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    """Development server with Flask; production uses gunicorn via packaging/systemd."""
    paths = _paths(args)
    from pelagos.app import create_app

    app = create_app(paths)
    host, _, port = (args.bind or "127.0.0.1:8480").rpartition(":")
    app.run(host=host or "127.0.0.1", port=int(port), debug=args.debug, use_reloader=False)
    return 0


def cmd_collector(args: argparse.Namespace) -> int:
    paths = _paths(args)
    from pelagos.collector.main import run

    return run(paths, once=args.once, rebuild=args.rebuild)


class InitError(Exception):
    def __init__(self, message: str, code: int) -> None:
        super().__init__(message)
        self.code = code


def _init_password(args: argparse.Namespace) -> str:
    """Option, then PELAGOS_ADMIN_PASSWORD, then a confirmed prompt on a terminal; InitError otherwise."""
    if args.admin_password:
        print(
            "warning: --admin-password is visible in the process list and shell history; "
            "prefer PELAGOS_ADMIN_PASSWORD or the prompt",
            file=sys.stderr,
        )
    password = args.admin_password or os.environ.get("PELAGOS_ADMIN_PASSWORD")
    if not password:
        if not sys.stdin.isatty():
            raise InitError("no terminal to ask for the admin password: set PELAGOS_ADMIN_PASSWORD", 2)
        try:
            password = getpass.getpass("admin password: ")
            if getpass.getpass("again: ") != password:
                raise InitError("the two passwords differ", 2)
        except (EOFError, KeyboardInterrupt):
            raise InitError("no admin password given", 2) from None
    from pelagos.auth.passwords import WeakPassword, check_strength

    try:
        check_strength(password)
    except WeakPassword as exc:
        raise InitError(f"admin password refused: {exc}", 2) from None
    return password


def cmd_init(args: argparse.Namespace) -> int:
    """Exit 0 initialized, 1 already initialized or failed, 2 no usable admin password."""
    paths = _paths(args)
    from pelagos.core.bootstrap import bootstrap_first_node

    try:
        if paths.cluster_toml.exists():
            raise InitError(f"{paths.cluster_toml} exists: this node is already initialized", 1)
        password = _init_password(args)
        result = bootstrap_first_node(
            paths,
            name=args.name,
            admin_username=args.admin_user,
            admin_password=password,
            web_url=args.web_url,
            replication_url=args.replication_url,
        )
    except InitError as exc:
        print(f"pelagos init: {exc}", file=sys.stderr)
        return exc.code
    except FileExistsError as exc:
        print(f"pelagos init: {exc}", file=sys.stderr)
        return 1
    except PermissionError as exc:
        print(f"pelagos init: {exc} (run as root or as the pelagos user)", file=sys.stderr)
        return 1
    print(f"node {result.node.name} ({result.node.id}) initialized in {paths.etc} and {paths.var}")
    return 0


def cmd_enroll(args: argparse.Namespace) -> int:
    paths = _paths(args)
    from pelagos.core.enrollment import enroll_cli

    return enroll_cli(paths, args)


def cmd_helper(args: argparse.Namespace) -> int:
    paths = _paths(args)
    from pelagos.installer.helper import serve_stdio

    return serve_stdio(paths)


def cmd_user(args: argparse.Namespace) -> int:
    from pelagos.auth.recovery import cmd_user as run

    return run(args, _paths(args))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pelagos", description="DNS and DHCP management for BIND 9 and Kea")
    p.add_argument("--home", help="development tree holding etc/, var/, run/ (sets PELAGOS_HOME)")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("version", help="print the version").set_defaults(func=cmd_version)

    s = sub.add_parser("serve", help="run the web process (development server)")
    s.add_argument("--bind", default="127.0.0.1:8480", help="host:port (default 127.0.0.1:8480)")
    s.add_argument("--debug", action="store_true")
    s.set_defaults(func=cmd_serve)

    c = sub.add_parser("collector", help="run the collector process")
    c.add_argument("--once", action="store_true", help="run one cycle and exit")
    c.add_argument("--rebuild", action="store_true", help="drop and recreate the series cache")
    c.set_defaults(func=cmd_collector)

    i = sub.add_parser("init", help="initialize the first node (CA, master key, admin user)")
    i.add_argument("--name")
    i.add_argument("--admin-user", default="admin")
    i.add_argument(
        "--admin-password",
        help="deprecated: visible in ps and shell history; use PELAGOS_ADMIN_PASSWORD or the prompt",
    )
    i.add_argument("--web-url")
    i.add_argument("--replication-url")
    i.set_defaults(func=cmd_init)

    from pelagos.installer.cli import add_parsers as add_installer_parsers

    add_installer_parsers(sub)
    h = sub.add_parser(
        "helper", help="privileged installer helper on stdin/stdout (run by pelagos-helper.socket)"
    )
    h.set_defaults(func=cmd_helper)

    e = sub.add_parser("enroll", help="join an existing cluster with a one-time token")
    e.add_argument("--url", help="replication URL of an enrolled node, https://ns1.example.lan:8444")
    e.add_argument("--token", help="one-time token from POST /api/v1/nodes/enroll-token")
    e.add_argument("--ca-fingerprint", help="sha256:... of the cluster CA, shown with the token")
    e.add_argument("--name", help="this node's name (default: short hostname)")
    e.add_argument("--replication-url", help="how peers reach this node (default https://<name>:8444)")
    e.add_argument("--web-url", help="UI URL of this node (default https://<name>:8443)")
    e.add_argument("--engines", help="comma list among bind,kea4,kea6,d2 that this node drives")
    e.set_defaults(func=cmd_enroll)

    from pelagos.auth.recovery import add_parser as add_user_parser

    add_user_parser(sub).set_defaults(func=cmd_user)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
