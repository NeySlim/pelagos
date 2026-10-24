# SPDX-License-Identifier: Apache-2.0
"""Command execution for the installer: argv lists, never a shell, sudo -n when not root, dry-run."""

from __future__ import annotations

import os
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any


class CommandError(Exception):
    def __init__(self, argv: list[str], returncode: int, output: str) -> None:
        super().__init__(f"{' '.join(argv)} exited {returncode}: {output.strip()[-2000:]}")
        self.argv = argv
        self.returncode = returncode
        self.output = output


@dataclass(slots=True)
class CommandResult:
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str
    skipped: bool = False  # dry-run

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    @property
    def output(self) -> str:
        return (self.stdout + ("\n" + self.stderr if self.stderr else "")).strip()


class CommandRunner:
    """Runs argv lists; privileged commands are prefixed with `sudo -n` unless we already are root."""

    def __init__(self, dry_run: bool = False, sudo: str = "sudo", env: dict[str, str] | None = None) -> None:
        self.dry_run = dry_run
        self.sudo = sudo
        self.env = env
        self.log: list[list[str]] = []

    @property
    def is_root(self) -> bool:
        return os.geteuid() == 0

    def argv_for(self, argv: list[str], privileged: bool) -> list[str]:
        if privileged and not self.is_root:
            return [self.sudo, "-n", *argv]
        return list(argv)

    def run(
        self,
        argv: list[str],
        *,
        privileged: bool = False,
        check: bool = True,
        timeout: float = 600.0,
        input_text: str | None = None,
        env: dict[str, str] | None = None,
        mutates: bool = True,
    ) -> CommandResult:
        """`mutates=False` marks a read-only command that still runs in dry-run mode."""
        full = self.argv_for(argv, privileged)
        self.log.append(full)
        if self.dry_run and mutates:
            return CommandResult(full, 0, "", "", skipped=True)
        merged = dict(os.environ)
        merged["PATH"] = "/usr/sbin:/usr/local/sbin:" + merged.get("PATH", "/usr/bin:/bin")
        merged["LC_ALL"] = "C"
        merged["DEBIAN_FRONTEND"] = "noninteractive"
        if self.env:
            merged.update(self.env)
        if env:
            merged.update(env)
        try:
            proc = subprocess.run(
                full,
                capture_output=True,
                text=True,
                timeout=timeout,
                input=input_text,
                env=merged,
                check=False,
            )
        except FileNotFoundError as exc:
            raise CommandError(full, 127, str(exc)) from exc
        except subprocess.TimeoutExpired as exc:
            raise CommandError(full, 124, f"timeout after {timeout}s") from exc
        result = CommandResult(full, proc.returncode, proc.stdout or "", proc.stderr or "")
        if check and not result.ok:
            raise CommandError(full, proc.returncode, result.output)
        return result


@dataclass(slots=True)
class FakeRunner:
    """Test double: records commands and answers from a prefix table of results, texts or callables."""

    responses: dict[str, Callable[[list[str]], CommandResult] | CommandResult | str] = field(
        default_factory=dict
    )
    dry_run: bool = False
    root: bool = True
    log: list[list[str]] = field(default_factory=list)

    @property
    def is_root(self) -> bool:
        return self.root

    def argv_for(self, argv: list[str], privileged: bool) -> list[str]:
        return list(argv) if (self.root or not privileged) else ["sudo", "-n", *argv]

    def run(self, argv: list[str], *, check: bool = True, **_: Any) -> CommandResult:
        full = list(argv)
        self.log.append(full)
        joined = " ".join(full)
        key = next((k for k in self.responses if joined.startswith(k)), None)
        if key is None:
            return CommandResult(full, 0, "", "")
        resp = self.responses[key]
        if callable(resp):
            result = resp(full)
        elif isinstance(resp, str):
            result = CommandResult(full, 0, resp, "")
        else:
            result = resp
        if check and not result.ok:
            raise CommandError(full, result.returncode, result.output)
        return result

    def commands(self, prefix: str = "") -> list[str]:
        return [" ".join(a) for a in self.log if " ".join(a).startswith(prefix)]
