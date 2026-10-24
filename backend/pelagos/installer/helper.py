# SPDX-License-Identifier: Apache-2.0
"""Privileged installer helper: install, import and security work as root for the node processes.

The web process and the collector run as the unprivileged `pelagos` user, but the installer edits
the engines' files, installs packages and restarts services. `pelagos helper` runs as root behind
the socket-activated `pelagos-helper.socket` (`/run/pelagos-helper.sock`, root:pelagos 0660): one
JSON request line per connection, answered by `{"progress": Job}` lines and one final
`{"result": ...}` or `{"error", "type"}` line. Only the operations below exist; the group that can
reach the socket can do what `admin:install` allows, nothing more: `apply` runs only changes this
helper planned itself (recorded under a root-only directory), the dual-key steps a peer sends, and
every file path, group and package a change names must be the one this host's layout gives.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import select
import socket
import time
from collections.abc import Callable
from pathlib import Path
from typing import IO, Any

from pelagos.domain import Change, Job, Plan, PlanScope

log = logging.getLogger(__name__)

SOCKET_ENV = "PELAGOS_HELPER_SOCKET"
DEFAULT_SOCKET = "/run/pelagos-helper.sock"
PLANS_ENV = "PELAGOS_HELPER_PLANS"
DEFAULT_PLANS = "/run/pelagos-helper/plans"
PLAN_TTL = 7 * 86400
REQUEST_TIMEOUT = 30.0
SAFE_ID = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
SAFE_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
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
            return _record(plan)
        if op == "plan_import":
            from pelagos.installer.importer import build_import_plan

            return _record(build_import_plan(env, list(request["engines"]), created_by))
        if op == "plan_security":
            from pelagos.installer.security_audit import build_security_plan

            d2 = request.get("d2_node_ids")
            return _record(
                build_security_plan(
                    env, list(request["finding_ids"]), created_by, list(d2) if d2 is not None else None
                )
            )
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
    authorize(plan, env)
    job = apply_plan(plan, env, Job(plan_id=plan.id), lambda j: emit({"progress": j.to_dict()}))
    warning = _give_back(env)
    if warning:
        if job.steps:
            last = job.steps[-1]
            last["output"] = f"{last.get('output') or ''}\n{warning}".strip()
        else:
            job.error = f"{job.error or ''}\n{warning}".strip()
    return job.to_dict()


def _give_back(env: Any) -> str:
    """Files root wrote under /etc/pelagos and /var/lib/pelagos go back to the service user;
    returns a warning when that failed (the web process will then hit permission errors)."""
    from pelagos.platform import PELAGOS_USER, give_tree_to

    paths = env.node_paths
    if paths.node_toml.exists():
        try:
            give_tree_to(PELAGOS_USER, [paths.etc, paths.var], skip=[paths.etc / "pelagos.env"])
        except (OSError, KeyError) as exc:
            log.warning("ownership of %s/%s not restored: %s", paths.etc, paths.var, exc)
            return f"warning: ownership of {paths.etc} and {paths.var} not restored: {exc}"
    return ""


# Apply authorization -----------------------------------------------------------------------------


def plans_dir() -> Path:
    return Path(os.environ.get(PLANS_ENV) or DEFAULT_PLANS)


def _digest(change: dict[str, Any]) -> str:
    canonical = Change.from_dict(change).to_dict()
    return hashlib.sha256(json.dumps(canonical, sort_keys=True, default=str).encode()).hexdigest()


def _record(plan: Plan) -> dict[str, Any]:
    """Remembers the changes of a plan this helper built; only those may be applied for this node."""
    data = plan.to_dict()
    if not SAFE_ID.match(plan.id):
        raise HelperError(f"unexpected plan id {plan.id!r}")
    root = plans_dir()
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    now = time.time()
    for old in root.glob("*.json"):
        try:
            if now - old.stat().st_mtime > PLAN_TTL:
                old.unlink()
        except OSError:
            pass
    digests = sorted({_digest(c) for c in data.get("changes") or []})
    target = root / f"{plan.id}.json"
    tmp = target.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump({"node_id": plan.node_id, "scope": str(plan.scope), "changes": digests}, fh)
    os.replace(tmp, target)
    return data


def _recorded(plan_id: str) -> dict[str, Any] | None:
    if not SAFE_ID.match(plan_id):
        return None
    try:
        return json.loads((plans_dir() / f"{plan_id}.json").read_text())
    except (OSError, ValueError):
        return None


def authorize(plan: Plan, env: Any) -> None:
    """Raises HelperError("...", "value") unless every change of `plan` for this node may run as root.

    A plan made on this node must have been built by this helper, change for change. A plan made on
    a peer (received over mTLS) may only carry the dual-key switch steps. Either way, the paths,
    groups, packages and include lines named by a change must be this host's own."""
    mine = [c for c in plan.changes if env.node_id in c.node_ids]
    if plan.node_id == env.node_id:
        record = _recorded(plan.id)
        if record is None or record.get("node_id") != env.node_id:
            raise HelperError(f"plan {plan.id} was not made by this node's helper: plan it again", "value")
        known = set(record.get("changes") or [])
        for change in mine:
            if _digest(change.to_dict()) not in known:
                raise HelperError(f"change {change.target} differs from the planned one", "value")
    else:
        from pelagos.installer.security_audit import DUAL_KEY_STEPS

        if plan.scope is not PlanScope.SECURITY:
            raise HelperError(f"{plan.scope} plans from another node are not accepted", "value")
        for change in mine:
            after = change.after if isinstance(change.after, dict) else {}
            details = after.get("details") if isinstance(after.get("details"), dict) else {}
            if after.get("step") not in DUAL_KEY_STEPS:
                raise HelperError(f"change {change.target} from another node is not accepted", "value")
            for name in ("key", "new_key"):
                if name in details and not SAFE_KEY.match(str(details[name])):
                    raise HelperError(f"invalid key name {details[name]!r}", "value")
    for change in mine:
        _check_change(change, env.paths)


def _check_change(change: Change, paths: Any) -> None:
    from pelagos.installer import keasetup, managed
    from pelagos.platform import KEA_DAEMONS

    a = change.after if isinstance(change.after, dict) else {}

    def refuse(what: str) -> None:
        raise HelperError(f"change {change.target}: {what} not allowed on this host", "value")

    if "named_conf" in a and a["named_conf"] != str(paths.named_conf):
        refuse(f"named_conf {a['named_conf']}")
    if "include_dir" in a and a["include_dir"] != str(paths.bind_include_dir):
        refuse(f"include_dir {a['include_dir']}")
    if "include_lines" in a:
        allowed = {managed.include_line(paths.pelagos_conf), managed.include_line(paths.options_conf)}
        if not set(a["include_lines"]) <= allowed:
            refuse("include line")
    if "conf" in a:
        engines = [p for p in change.target.split("/") if p in KEA_DAEMONS]
        confs = {str(paths.kea_conf(KEA_DAEMONS[e])) for e in engines} or {
            str(paths.kea_conf(d)) for d in KEA_DAEMONS.values()
        }
        if a["conf"] not in confs:
            refuse(f"conf {a['conf']}")
    if "secret_file" in a:
        key = str(a.get("tsig_key") or "")
        if not SAFE_KEY.match(key) or a["secret_file"] != str(
            keasetup.secret_file_path(paths.kea_conf_dir, key)
        ):
            refuse(f"secret_file {a['secret_file']}")
    if "groups" in a and not set(a["groups"]) <= {paths.bind_group, paths.kea_group}:
        refuse(f"groups {', '.join(map(str, a['groups']))}")
    if change.target == "install/packages":
        allowed = set(paths.bind_packages) | set(paths.kea_packages_distro) | set(paths.kea_packages_isc)
        for isc in (False, True):
            allowed |= set(paths.kea_packages_for(list(KEA_DAEMONS), isc))
        if not set(a.get("install") or []) <= allowed:
            refuse("package")


def serve_stream(
    reader: IO[bytes], writer: IO[bytes], env_factory: Callable[[], Any], timeout: float | None = None
) -> int:
    """One request from `reader`, answers on `writer` (the accepted socket under systemd).
    With `timeout`, a client that sends no request within it is answered and dropped."""

    def emit(obj: dict[str, Any]) -> None:
        writer.write(json.dumps(obj, default=str).encode() + b"\n")
        writer.flush()

    line = reader.readline(MAX_REQUEST) if timeout is None else _read_line(reader.fileno(), timeout)
    if line is None:
        emit({"error": "no request", "type": "value"})
        return 2
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


def _read_line(fd: int, timeout: float) -> bytes | None:
    """The first line on `fd` (or all of it up to EOF), None when it is not complete within `timeout`."""
    deadline = time.monotonic() + timeout
    data = b""
    while b"\n" not in data and len(data) < MAX_REQUEST:
        left = deadline - time.monotonic()
        if left <= 0 or not select.select([fd], [], [], left)[0]:
            return None
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        data += chunk
    return data.split(b"\n", 1)[0][:MAX_REQUEST]


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
        timeout=REQUEST_TIMEOUT,
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
    "authorize",
    "available",
    "handle",
    "serve_stdio",
    "serve_stream",
    "socket_path",
]
