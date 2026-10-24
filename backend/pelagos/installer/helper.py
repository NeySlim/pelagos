# SPDX-License-Identifier: Apache-2.0
"""Privileged installer helper: install, import and security work as root for the node processes.

The web process and the collector run as the unprivileged `pelagos` user, but the installer edits
the engines' files, installs packages and restarts services. `pelagos helper` runs as root behind
the socket-activated `pelagos-helper.socket` (`/run/pelagos-helper.sock`, root:pelagos 0660): one
JSON request line per connection, answered by `{"progress": Job}` lines and one final
`{"result": ...}` or `{"error", "type"}` line. Only the operations below exist; the group that can
reach the socket can do what `admin:install` allows, nothing more.
"""

from __future__ import annotations

import json
import os
import socket
from collections.abc import Callable
from pathlib import Path
from typing import IO, Any

from pelagos.domain import Job, Plan, PlanScope

SOCKET_ENV = "PELAGOS_HELPER_SOCKET"
DEFAULT_SOCKET = "/run/pelagos-helper.sock"
OPERATIONS = ("detect", "audit", "plan_install", "plan_import", "plan_security", "apply")
INSTALLER_SCOPES = (PlanScope.INSTALL, PlanScope.IMPORT, PlanScope.SECURITY)
MAX_REQUEST = 4 << 20


class HelperError(Exception):
    """The helper refused or failed an operation; `kind` is "value" for bad input."""

    def __init__(self, message: str, kind: str = "internal") -> None:
        super().__init__(message)
        self.kind = kind


def socket_path() -> Path:
    return Path(os.environ.get(SOCKET_ENV) or DEFAULT_SOCKET)


def available() -> bool:
    """True when this process must and can delegate: not root, and the helper socket exists."""
    return os.geteuid() != 0 and socket_path().is_socket()


# Server ------------------------------------------------------------------------------------------


def handle(request: dict[str, Any], env_factory: Callable[[], Any], emit: Callable[[dict], None]) -> Any:
    """Runs one operation with a fresh InstallerEnv; raises HelperError("...", "value") on bad input."""
    op = request.get("op")
    if op not in OPERATIONS:
        raise HelperError(f"unknown operation {op!r}", "value")
    env = env_factory()
    created_by = str(request.get("created_by") or "")
    try:
        if op == "detect":
            from pelagos.installer.detect import detect_env

            return detect_env(env)
        if op == "audit":
            from pelagos.installer.security_audit import run_audit

            return [f.to_dict() for f in run_audit(env)]
        if op == "plan_install":
            from pelagos.installer.install import build_install_plan

            plan = build_install_plan(
                env,
                list(request["engines"]),
                request.get("source", "distro"),
                request.get("isc_series"),
                created_by,
            )
            return plan.to_dict()
        if op == "plan_import":
            from pelagos.installer.importer import build_import_plan

            return build_import_plan(env, list(request["engines"]), created_by).to_dict()
        if op == "plan_security":
            from pelagos.installer.security_audit import build_security_plan

            d2 = request.get("d2_node_ids")
            return build_security_plan(
                env, list(request["finding_ids"]), created_by, list(d2) if d2 is not None else None
            ).to_dict()
    except (KeyError, TypeError, ValueError) as exc:
        raise HelperError(str(exc), "value") from None
    return _apply(request, env, emit)


def _apply(request: dict[str, Any], env: Any, emit: Callable[[dict], None]) -> dict[str, Any]:
    from pelagos.installer.jobs import apply_plan

    try:
        plan = Plan.from_dict(request["plan"])
    except (KeyError, TypeError, ValueError) as exc:
        raise HelperError(f"invalid plan: {exc}", "value") from None
    if plan.scope not in INSTALLER_SCOPES:
        raise HelperError(f"not an installer plan: {plan.scope}", "value")
    job = apply_plan(plan, env, Job(plan_id=plan.id), lambda j: emit({"progress": j.to_dict()}))
    _give_back(env)
    return job.to_dict()


def _give_back(env: Any) -> None:
    """Files root wrote under /etc/pelagos and /var/lib/pelagos go back to the service user."""
    from pelagos.platform import PELAGOS_USER, give_tree_to

    paths = env.node_paths
    if paths.node_toml.exists():
        try:
            give_tree_to(PELAGOS_USER, [paths.etc, paths.var], skip=[paths.etc / "pelagos.env"])
        except (OSError, KeyError):
            pass


def serve_stream(reader: IO[bytes], writer: IO[bytes], env_factory: Callable[[], Any]) -> int:
    """One request from `reader`, answers on `writer` (the accepted socket under systemd)."""

    def emit(obj: dict[str, Any]) -> None:
        writer.write(json.dumps(obj, default=str).encode() + b"\n")
        writer.flush()

    line = reader.readline(MAX_REQUEST)
    try:
        request = json.loads(line or b"{}")
        if not isinstance(request, dict):
            raise ValueError("request must be a JSON object")
    except ValueError as exc:
        emit({"error": f"bad request: {exc}", "type": "value"})
        return 2
    try:
        emit({"result": handle(request, env_factory, emit)})
        return 0
    except HelperError as exc:
        emit({"error": str(exc), "type": exc.kind})
    except Exception as exc:  # reported to the caller, which fails its job with it
        emit({"error": f"{type(exc).__name__}: {exc}", "type": "internal"})
    return 1


def serve_stdio(node_paths: Any = None) -> int:
    """`pelagos helper`: stdin and stdout are the connection systemd accepted."""
    from pelagos.installer.env import InstallerEnv

    if os.geteuid() != 0:
        print(json.dumps({"error": "pelagos helper must run as root", "type": "internal"}), flush=True)
        return 1
    # The connection moves to private descriptors: prints go to the journal, children read /dev/null.
    conn_in, conn_out = os.dup(0), os.dup(1)
    devnull = os.open(os.devnull, os.O_RDONLY)
    os.dup2(devnull, 0)
    os.dup2(2, 1)
    os.close(devnull)
    return serve_stream(
        os.fdopen(conn_in, "rb", buffering=0),
        os.fdopen(conn_out, "wb", buffering=0),
        lambda: InstallerEnv.detect(node_paths=node_paths),
    )


# Client ------------------------------------------------------------------------------------------


class HelperClient:
    """Calls the helper from the node processes; one connection per operation."""

    def __init__(self, path: Path | None = None, timeout: float = 3600.0) -> None:
        self.path = path or socket_path()
        self.timeout = timeout

    def call(self, op: str, progress: Callable[[dict], None] | None = None, **args: Any) -> Any:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(self.timeout)
            try:
                sock.connect(str(self.path))
            except OSError as exc:
                raise HelperError(f"privileged helper {self.path} unavailable: {exc}") from None
            sock.sendall(json.dumps({"op": op, **args}, default=str).encode() + b"\n")
            sock.shutdown(socket.SHUT_WR)
            with sock.makefile("rb") as stream:
                for raw in stream:
                    msg = json.loads(raw)
                    if "progress" in msg:
                        if progress is not None:
                            progress(msg["progress"])
                        continue
                    if "error" in msg:
                        raise HelperError(str(msg["error"]), str(msg.get("type") or "internal"))
                    return msg.get("result")
        raise HelperError("privileged helper closed the connection without an answer")

    def detect(self) -> dict[str, Any]:
        return self.call("detect")

    def audit(self) -> list[dict[str, Any]]:
        return self.call("audit")

    def plan(self, op: str, created_by: str, **args: Any) -> Plan:
        return Plan.from_dict(self.call(op, created_by=created_by, **args))

    def apply(self, plan: Plan, job: Job, progress: Callable[[Job], None]) -> Job:
        """Runs `plan` as root; its steps are appended to `job` as they progress."""
        base = list(job.steps)

        def relay(remote: dict[str, Any]) -> None:
            job.steps = base + list(remote.get("steps") or [])
            progress(job)

        remote = Job.from_dict(self.call("apply", progress=relay, plan=plan.to_dict()))
        job.steps = base + list(remote.steps)
        return remote


__all__ = [
    "DEFAULT_SOCKET",
    "OPERATIONS",
    "HelperClient",
    "HelperError",
    "available",
    "handle",
    "serve_stdio",
    "serve_stream",
    "socket_path",
]
