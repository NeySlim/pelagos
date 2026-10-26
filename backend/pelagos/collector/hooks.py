# SPDX-License-Identifier: Apache-2.0
"""Kea hook libraries no package owns (compiled by hand): they are linked against one Kea version
and break at the next upgrade. Ownership comes from `dpkg -S` or `rpm -qf`, answers are cached."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path, PurePosixPath
from typing import Any

# (library name pattern, built-in option that does the same job)
BUILTIN_EQUIVALENTS = (
    (re.compile(r"(sanitize|sanitise|clean).*host|host.*(sanitize|sanitise|clean)", re.I), "hostname-char"),
)
Runner = Callable[[list[str]], int | None]
_NOT_OWNED = re.compile(r"no path found|is not owned|not owned by any package", re.I)


def _run(argv: list[str]) -> int | None:
    """0 when owned, 1 when the tool says nobody owns it, None on any other failure."""
    try:
        done = subprocess.run(argv, capture_output=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    if done.returncode == 0:
        return 0
    text = (done.stderr + done.stdout).decode(errors="replace")
    return 1 if done.returncode == 1 and _NOT_OWNED.search(text) else None


def package_tool() -> list[str] | None:
    """The command asking which package owns a file, None when the host has neither dpkg nor rpm."""
    if shutil.which("dpkg"):
        return ["dpkg", "-S"]
    if shutil.which("rpm"):
        return ["rpm", "-qf"]
    return None


class HookOwnership:
    """`custom(path)`: True when the library exists and no package owns it, False when one does,
    None when it cannot be told (file missing, no package tool)."""

    def __init__(self, runner: Runner = _run, tool: Callable[[], list[str] | None] = package_tool) -> None:
        self.runner = runner
        self.tool = tool
        self._cache: dict[tuple[str, int], bool | None] = {}

    def custom(self, library: str) -> bool | None:
        path = Path(library)
        if not path.is_absolute():
            return None
        try:
            stamp = path.stat().st_mtime_ns
        except OSError:
            return None
        key = (library, stamp)
        if key not in self._cache:
            value = self._unowned(path)
            if value is None:
                return None
            self._cache[key] = value
        return self._cache[key]

    def _unowned(self, path: Path) -> bool | None:
        tool = self.tool()
        if tool is None:
            return None
        for candidate in dict.fromkeys([str(path), os.path.realpath(path)]):
            code = self.runner([*tool, candidate])
            if code is None:
                return None
            if code == 0:
                return False
        return True


def builtin_equivalent(library: str) -> str | None:
    name = PurePosixPath(library).name
    return next((option for pattern, option in BUILTIN_EQUIVALENTS if pattern.search(name)), None)


def custom_libraries(running: dict[str, Any], ownership: HookOwnership) -> list[str]:
    """Absolute paths of the hook libraries Kea runs that no package owns."""
    out = []
    for hook in running.get("hooks-libraries") or []:
        library = str(hook.get("library") or "") if isinstance(hook, dict) else ""
        if library and ownership.custom(library):
            out.append(library)
    return out
