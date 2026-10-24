# SPDX-License-Identifier: Apache-2.0
"""The `pelagos` command: serve, collector, version, init, install, import, audit, enroll."""

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


def cmd_init(args: argparse.Namespace) -> int:
    paths = _paths(args)
    from pelagos.core.bootstrap import bootstrap_first_node

    password = (
        args.admin_password or os.environ.get("PELAGOS_ADMIN_PASSWORD") or getpass.getpass("admin password: ")
    )
    result = bootstrap_first_node(
        paths,
        name=args.name,
        admin_username=args.admin_user,
        admin_password=password,
        web_url=args.web_url,
        replication_url=args.replication_url,
    )
    print(f"node {result.node.name} ({result.node.id}) initialized in {paths.etc} and {paths.var}")
    return 0


def _placeholder(package: str):
    def run(_: argparse.Namespace) -> int:
        print(f"not implemented yet (owner: {package})", file=sys.stderr)
        return 2

    return run


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
    i.add_argument("--admin-password")
    i.add_argument("--web-url")
    i.add_argument("--replication-url")
    i.set_defaults(func=cmd_init)

    sub.add_parser("install", help="install BIND and/or Kea (WP-INSTALLER)").set_defaults(
        func=_placeholder("WP-INSTALLER")
    )
    sub.add_parser("import", help="adopt an existing configuration (WP-INSTALLER)").set_defaults(
        func=_placeholder("WP-INSTALLER")
    )
    sub.add_parser("audit", help="security audit of the configuration (WP-INSTALLER)").set_defaults(
        func=_placeholder("WP-INSTALLER")
    )
    e = sub.add_parser("enroll", help="join an existing cluster (WP-CORE)")
    e.add_argument("--url")
    e.add_argument("--token")
    e.add_argument("--ca-fingerprint")
    e.add_argument("--name")
    e.set_defaults(func=_placeholder("WP-CORE"))
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
