# SPDX-License-Identifier: Apache-2.0
"""rndc client: runs the rndc binary with an explicit configuration, never through a shell."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from pelagos.connectors.base import ConnectorDenied, ConnectorTimeout, ConnectorUnavailable

SBIN_DIRS = ("/usr/sbin", "/usr/local/sbin")


def find_binary(name: str) -> str | None:
    """PATH first, then the sbin directories a non-root user usually lacks."""
    found = shutil.which(name)
    if found:
        return found
    for d in SBIN_DIRS:
        candidate = Path(d) / name
        if candidate.is_file():
            return str(candidate)
    return None


class RndcClient:
    def __init__(
        self,
        conf_path: Path,
        server: str = "127.0.0.1",
        port: int = 953,
        binary: str | None = None,
        timeout: float = 15.0,
    ) -> None:
        self.conf_path = conf_path
        self.server = server
        self.port = port
        self.binary = binary or find_binary("rndc")
        self.timeout = timeout

    def run(self, *args: str) -> str:
        if not self.binary:
            raise ConnectorUnavailable("rndc binary not found")
        cmd = [self.binary, "-c", str(self.conf_path), "-s", self.server, "-p", str(self.port), *args]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout, check=False)
        except subprocess.TimeoutExpired as exc:
            raise ConnectorTimeout(f"rndc {' '.join(args)} timed out") from exc
        if proc.returncode != 0:
            err = (proc.stderr or proc.stdout).strip()
            if "connection refused" in err or "connect failed" in err:
                raise ConnectorUnavailable(err)
            if "permission denied" in err.lower() or "no matching key" in err.lower():
                raise ConnectorDenied(err)
            raise ConnectorUnavailable(err or f"rndc exited {proc.returncode}")
        return proc.stdout

    def status(self) -> dict[str, str]:
        return parse_kv(self.run("status"))

    def zonestatus(self, zone: str, view: str | None = None) -> dict[str, str]:
        args = ["zonestatus", zone] + ([view] if view else [])
        return parse_kv(self.run(*args))


def parse_kv(text: str) -> dict[str, str]:
    """`key: value` lines of rndc status / zonestatus; repeated keys are joined with newlines."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        value = value.strip()
        out[key] = (out[key] + "\n" + value) if key in out else value
    return out
