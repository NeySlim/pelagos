# SPDX-License-Identifier: Apache-2.0
"""Local account recovery (`pelagos user ...`): runs on the node, as root, through the normal
cluster.toml write and audit path so the change replicates like an API write."""

from __future__ import annotations

import argparse
import getpass
import os
import sys

from pelagos.core.paths import Paths

ACTOR = "local-recovery"
PASSWORD_ENV = "PELAGOS_NEW_PASSWORD"  # noqa: S105 (an environment variable name)


class RecoveryError(Exception):
    pass


def drop_to_owner(paths: Paths) -> None:
    """Only root (or the account that already owns the node files) may recover an account; root
    switches to that owner first so every file it writes keeps the service's ownership."""
    try:
        st = paths.cluster_toml.stat()
    except FileNotFoundError:
        raise RecoveryError(f"{paths.cluster_toml} not found: this node is not initialized") from None
    euid = os.geteuid()
    if euid == st.st_uid:
        return
    if euid != 0:
        raise RecoveryError("run this command as root")
    os.setgroups([])
    os.setgid(st.st_gid)
    os.setuid(st.st_uid)


def _service(paths: Paths):  # type: ignore[no-untyped-def]
    from pelagos.core.context import NodeContext
    from pelagos.services.admin_service import AdminService

    return AdminService(NodeContext.build(paths))


def _user_id(admin, username: str) -> str:  # type: ignore[no-untyped-def]
    user = admin.ctx.cluster().user(username.strip().lower())
    if user is None:
        raise RecoveryError(f"no user named {username}")
    return user.id


def reset_password(paths: Paths, username: str, password: str) -> None:
    """New password, must be changed at next login; the account is enabled again."""
    admin = _service(paths)
    user_id = _user_id(admin, username)
    admin.reset_password(user_id, password, ACTOR, None)
    if not admin.user(user_id).enabled:
        admin.update_user(user_id, {"enabled": True}, ACTOR, None)


def disable_totp(paths: Paths, username: str) -> None:
    admin = _service(paths)
    admin.clear_totp(_user_id(admin, username), ACTOR, None)


def remove_keys(paths: Paths, username: str) -> int:
    """Every security key of the user; returns how many were removed."""
    from pelagos.services.webauthn_service import WebAuthnService

    admin = _service(paths)
    user_id = _user_id(admin, username)
    count = len(admin.user(user_id).webauthn)
    WebAuthnService(admin.ctx).remove(user_id, None, ACTOR, None)
    return count


def _read_password() -> str:
    env = os.environ.get(PASSWORD_ENV)
    if env:
        return env
    first = getpass.getpass("new password: ")
    if getpass.getpass("again: ") != first:
        raise RecoveryError("the two passwords differ")
    return first


def cmd_user(args: argparse.Namespace, paths: Paths) -> int:
    from pelagos.services.errors import ServiceError

    try:
        drop_to_owner(paths)
        if args.user_command == "reset-password":
            reset_password(paths, args.username, _read_password())
            print(f"password of {args.username} reset; it must be changed at the next login")
        elif args.user_command == "remove-keys":
            count = remove_keys(paths, args.username)
            print(f"{count} security key(s) removed from {args.username}")
        else:
            disable_totp(paths, args.username)
            print(f"one-time codes disabled for {args.username}")
        print("sessions already open on running nodes stay valid until they expire or pelagos restarts")
        return 0
    except (RecoveryError, ServiceError) as exc:
        print(f"pelagos user: {exc}", file=sys.stderr)
        return 1


def add_parser(sub: argparse._SubParsersAction) -> argparse.ArgumentParser:  # type: ignore[type-arg]
    u = sub.add_parser(
        "user", help="local account recovery (root): reset a password, disable TOTP, remove keys"
    )
    usub = u.add_subparsers(dest="user_command", required=True)
    r = usub.add_parser(
        "reset-password", help=f"set a new password (prompted, or ${PASSWORD_ENV}) and re-enable the user"
    )
    r.add_argument("username")
    d = usub.add_parser("disable-totp", help="remove the user's one-time code enrollment")
    d.add_argument("username")
    k = usub.add_parser("remove-keys", help="remove every security key (WebAuthn) of the user")
    k.add_argument("username")
    return u
