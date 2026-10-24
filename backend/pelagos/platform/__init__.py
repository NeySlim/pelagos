# SPDX-License-Identifier: Apache-2.0
"""Distro abstraction (WP-INSTALLER): paths, users, services and package names per distro family."""

from pelagos.platform.distro import (
    ENGINES,
    KEA_DAEMONS,
    Distro,
    PlatformPaths,
    detect_distro,
    distro_from_fields,
    find_binary,
    find_kea_hooks_dir,
    parse_os_release,
    platform_paths,
    selinux_enforcing,
)
from pelagos.platform.packages import (
    ISC_SERIES_DEFAULT,
    PackageManager,
    RepoFile,
    isc_repo_files,
    isc_repo_name,
)
from pelagos.platform.runner import CommandError, CommandResult, CommandRunner, FakeRunner
from pelagos.platform.services import ServiceManager
from pelagos.platform.users import (
    PELAGOS_USER,
    ensure_supplementary_groups,
    ensure_system_user,
    give_tree_to,
    group_exists,
    user_exists,
    user_groups,
)

__all__ = [
    "ENGINES",
    "ISC_SERIES_DEFAULT",
    "KEA_DAEMONS",
    "PELAGOS_USER",
    "CommandError",
    "CommandResult",
    "CommandRunner",
    "Distro",
    "FakeRunner",
    "PackageManager",
    "PlatformPaths",
    "RepoFile",
    "ServiceManager",
    "detect_distro",
    "distro_from_fields",
    "ensure_supplementary_groups",
    "ensure_system_user",
    "find_binary",
    "find_kea_hooks_dir",
    "give_tree_to",
    "group_exists",
    "isc_repo_files",
    "isc_repo_name",
    "parse_os_release",
    "platform_paths",
    "selinux_enforcing",
    "user_exists",
    "user_groups",
]
