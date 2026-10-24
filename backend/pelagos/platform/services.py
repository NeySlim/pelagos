# SPDX-License-Identifier: Apache-2.0
"""systemd units through systemctl, with the states the installer needs to decide what to do."""

from __future__ import annotations

from typing import Protocol

from pelagos.platform.runner import CommandResult


class Runner(Protocol):
    def run(self, argv: list[str], **kwargs: object) -> CommandResult: ...


class ServiceManager:
    def __init__(self, runner: Runner, systemctl: str = "systemctl") -> None:
        self.runner = runner
        self.systemctl = systemctl

    def _query(self, verb: str, unit: str) -> str:
        res = self.runner.run(
            [self.systemctl, verb, unit], privileged=False, check=False, mutates=False, timeout=30
        )
        return res.stdout.strip()

    def is_active(self, unit: str) -> bool:
        return self._query("is-active", unit) == "active"

    def is_enabled(self, unit: str) -> bool:
        return self._query("is-enabled", unit) in ("enabled", "static", "alias")

    def exists(self, unit: str) -> bool:
        res = self.runner.run(
            [self.systemctl, "cat", unit], privileged=False, check=False, mutates=False, timeout=30
        )
        return res.ok

    def enable_now(self, unit: str) -> str:
        return self.runner.run([self.systemctl, "enable", "--now", unit], privileged=True).output

    def disable_now(self, unit: str) -> str:
        return self.runner.run([self.systemctl, "disable", "--now", unit], privileged=True).output

    def restart(self, unit: str) -> str:
        return self.runner.run([self.systemctl, "restart", unit], privileged=True).output

    def reload_or_restart(self, unit: str) -> str:
        return self.runner.run([self.systemctl, "reload-or-restart", unit], privileged=True).output

    def start(self, unit: str) -> str:
        return self.runner.run([self.systemctl, "start", unit], privileged=True).output

    def daemon_reload(self) -> str:
        return self.runner.run([self.systemctl, "daemon-reload"], privileged=True).output

    def journal(self, unit: str, lines: int = 20) -> str:
        res = self.runner.run(
            ["journalctl", "-u", unit, "-n", str(lines), "--no-pager"],
            privileged=True,
            check=False,
            mutates=False,
            timeout=30,
        )
        return res.output
