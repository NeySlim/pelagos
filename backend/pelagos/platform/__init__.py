# SPDX-License-Identifier: Apache-2.0
"""Distro abstraction (WP-INSTALLER): paths, users, services and package names per distro family."""

from pelagos.platform.distro import (
    Distro,
    PlatformPaths,
    detect_distro,
    find_binary,
    find_kea_hooks_dir,
    platform_paths,
)

__all__ = ["Distro", "PlatformPaths", "detect_distro", "find_binary", "find_kea_hooks_dir", "platform_paths"]
