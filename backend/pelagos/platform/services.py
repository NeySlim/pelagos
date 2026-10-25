# SPDX-License-Identifier: Apache-2.0
"""systemd units through systemctl, with the states the installer needs to decide what to do."""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Protocol

from pelagos.platform.runner import CommandResult

SUPERVISOR_SOCK = "/run/supervisor.sock"
SYSTEMD_DIR = "/run/systemd/system"
EXTERNAL_ENV = "PELAGOS_EXTERNAL_ENGINES"


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


def supervisor_program(unit: str) -> str:
    """supervisord program of a systemd unit name: named.service and bind9 run as `named`,
    isc-kea-dhcp4-server and kea-dhcp4-server as `kea-dhcp4` (docker/allinone/supervisord.conf)."""
    name = unit.removesuffix(".service")
    if name in ("bind9", "named"):
        return "named"
    return name.removeprefix("isc-").removesuffix("-server")


class SupervisorServices(ServiceManager):
    """The all-in-one image runs the engines under supervisord, without systemd: the same verbs
    map onto supervisorctl programs."""

    def __init__(self, runner: Runner, supervisorctl: str = "supervisorctl") -> None:
        super().__init__(runner)
        self.supervisorctl = supervisorctl

    def _ctl(self, *args: str, check: bool = True) -> CommandResult:
        return self.runner.run(
            [self.supervisorctl, *args], privileged=True, check=check, mutates=args[0] != "status", timeout=60
        )

    def _state(self, unit: str) -> str:
        # "named  RUNNING  pid 12, uptime 0:01:02"; an unknown program answers "ERROR (no such process)".
        words = self._ctl("status", supervisor_program(unit), check=False).stdout.split()
        return words[1] if len(words) > 1 else ""

    def is_active(self, unit: str) -> bool:
        return self._state(unit) == "RUNNING"

    def is_enabled(self, unit: str) -> bool:
        return self.exists(unit)

    def exists(self, unit: str) -> bool:
        return self._state(unit) not in ("", "ERROR", "(no")

    def enable_now(self, unit: str) -> str:
        return self.start(unit)

    def disable_now(self, unit: str) -> str:
        return self._ctl("stop", supervisor_program(unit)).output

    def restart(self, unit: str) -> str:
        return self._ctl("restart", supervisor_program(unit)).output

    def reload_or_restart(self, unit: str) -> str:
        return self.restart(unit)

    def start(self, unit: str) -> str:
        if self.is_active(unit):
            return f"{supervisor_program(unit)} already running"
        return self._ctl("start", supervisor_program(unit)).output

    def daemon_reload(self) -> str:
        return ""

    def journal(self, unit: str, lines: int = 20) -> str:
        return self._ctl("tail", supervisor_program(unit), check=False).output[-4000:]


class ExternalServices(ServiceManager):
    """Engines in their own containers (docker/compose.yaml, PELAGOS_EXTERNAL_ENGINES=1): they always
    run, are reloaded over rndc or their control socket, and are never started or restarted here."""

    def is_active(self, unit: str) -> bool:
        return True

    def is_enabled(self, unit: str) -> bool:
        return True

    def exists(self, unit: str) -> bool:
        return True

    def _elsewhere(self, unit: str) -> str:
        return f"{unit} runs in its own container: nothing to do here"

    def enable_now(self, unit: str) -> str:
        return self._elsewhere(unit)

    def start(self, unit: str) -> str:
        return self._elsewhere(unit)

    def disable_now(self, unit: str) -> str:
        raise RuntimeError(f"{unit} runs in its own container: stop it there")

    def restart(self, unit: str) -> str:
        raise RuntimeError(f"{unit} runs in its own container: restart it there")

    def reload_or_restart(self, unit: str) -> str:
        return self.restart(unit)

    def daemon_reload(self) -> str:
        return ""

    def journal(self, unit: str, lines: int = 20) -> str:
        return self._elsewhere(unit)


def service_manager_for(runner: Runner) -> ServiceManager:
    """systemctl where systemd runs; supervisorctl in the all-in-one image; nothing to drive when
    the engines are other containers."""
    if Path(SYSTEMD_DIR).is_dir():
        return ServiceManager(runner)
    if shutil.which("supervisorctl") and Path(SUPERVISOR_SOCK).exists():
        return SupervisorServices(runner)
    if os.environ.get(EXTERNAL_ENV) == "1":
        return ExternalServices(runner)
    return ServiceManager(runner)
