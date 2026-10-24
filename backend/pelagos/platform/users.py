# SPDX-License-Identifier: Apache-2.0
"""System users and groups: the `pelagos` service account and its engine group memberships."""

from __future__ import annotations

import grp
import pwd

from pelagos.platform.services import Runner

PELAGOS_USER = "pelagos"
PELAGOS_HOME = "/var/lib/pelagos"


def user_exists(name: str) -> bool:
    try:
        pwd.getpwnam(name)
        return True
    except KeyError:
        return False


def group_exists(name: str) -> bool:
    try:
        grp.getgrnam(name)
        return True
    except KeyError:
        return False


def user_groups(name: str) -> set[str]:
    if not user_exists(name):
        return set()
    primary = grp.getgrgid(pwd.getpwnam(name).pw_gid).gr_name
    return {primary, *(g.gr_name for g in grp.getgrall() if name in g.gr_mem)}


def ensure_system_user(runner: Runner, name: str = PELAGOS_USER, home: str = PELAGOS_HOME) -> str:
    """Idempotent: creates a locked system account with its own group."""
    if user_exists(name):
        return f"user {name} exists"
    runner.run(
        ["useradd", "--system", "--user-group", "--home-dir", home, "--shell", "/usr/sbin/nologin", name],
        privileged=True,
    )
    return f"created user {name}"


def ensure_supplementary_groups(runner: Runner, name: str, groups: list[str]) -> str:
    """Adds the user to every listed group that exists; missing groups are reported, not created."""
    wanted = [g for g in groups if group_exists(g)]
    missing = [g for g in groups if not group_exists(g)]
    have = user_groups(name)
    to_add = [g for g in wanted if g not in have]
    if to_add:
        runner.run(["usermod", "-a", "-G", ",".join(to_add), name], privileged=True)
    parts = []
    if to_add:
        parts.append(f"added {name} to {', '.join(to_add)}")
    if missing:
        parts.append(f"groups not present yet: {', '.join(missing)}")
    return "; ".join(parts) or f"{name} already in {', '.join(wanted) or 'no engine group'}"
