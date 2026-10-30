# SPDX-License-Identifier: Apache-2.0
"""Helpers of the lab tier: ssh to the VMs, a REST client for a node, polling."""

from __future__ import annotations

import fcntl
import functools
import http.cookiejar
import io
import json
import os
import secrets
import shlex
import ssl
import subprocess
import sys
import tarfile
import time
import tomllib
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[3]
SCRIPTS = REPO / "scripts" / "lab"
SSH_KEY = os.path.expanduser(os.environ.get("PELAGOS_LAB_SSH_KEY", "~/.ssh/id_ed25519"))
PASSWORDS = Path(os.environ.get("PELAGOS_LAB_PASSWORDS", "~/.config/pelagos-lab/passwords.toml")).expanduser()


def _generate() -> str:
    # Lower, upper, digit and "-" or "_" (Pelagos' policy and UCM's), never a leading "-" that a
    # command line would read as an option.
    while True:
        value = secrets.token_urlsafe(18)
        if (
            value[0].isalnum()
            and any(c.islower() for c in value)
            and any(c.isupper() for c in value)
            and any(c.isdigit() for c in value)
            and any(c in "-_" for c in value)
        ):
            return value


def lab_password(name: str, env: str | None = None) -> str:
    """The lab secret `name`: `env` when set, else generated on first use and kept outside the
    repository in PASSWORDS (mode 0600), so every run and every VM provisioning reuse it."""
    if env and os.environ.get(env):
        return os.environ[env]
    if os.environ.get("PELAGOS_LAB") != "1":
        return ""  # collected outside the lab tier (skipped): nothing written to disk
    PASSWORDS.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(PASSWORDS, os.O_RDWR | os.O_CREAT, 0o600)
    with os.fdopen(fd, "r+") as f:
        fcntl.flock(f, fcntl.LOCK_EX)  # parallel runs must agree on one value
        known = tomllib.loads(f.read())
        if name not in known:
            known[name] = _generate()
            f.seek(0)
            f.truncate()
            f.write("".join(f'{k} = "{v}"\n' for k, v in sorted(known.items())))
        os.fchmod(f.fileno(), 0o600)
        return str(known[name])


ADMIN_PASSWORD = lab_password("admin", "PELAGOS_LAB_ADMIN_PASSWORD")

# ssh alias, lab address
NS1 = ("lab-ns1", "10.99.0.11")
NS2 = ("lab-ns2", "10.99.0.12")
RPM = ("lab-rpm", "10.99.0.13")
CLIENT = ("lab-client", "10.99.0.14")
PKG_RPM = ("lab-pkg-rpm", "10.99.0.16")
DOCKER = ("lab-docker", "10.99.0.17")
ARM64 = ("lab-arm64", "10.99.0.18")


def ssh_argv(host: str) -> list[str]:
    return [
        "ssh",
        "-i",
        SSH_KEY,
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=15",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "LogLevel=ERROR",
        f"lab@{host}",
    ]


def ssh(
    host: str, command: str, check: bool = True, data: bytes | None = None, timeout: int = 1800
) -> tuple[int, str, str]:
    """Runs `command` on the VM at address `host`; raises AssertionError on failure when `check`."""
    res = subprocess.run(
        [*ssh_argv(host), command], input=data, capture_output=True, timeout=timeout, check=False
    )
    out = res.stdout.decode(errors="replace")
    err = res.stderr.decode(errors="replace")
    if check and res.returncode != 0:
        raise AssertionError(f"{host}: {command!r} exited {res.returncode}\n{out[-4000:]}\n{err[-4000:]}")
    return res.returncode, out, err


def scp(host: str, local: Path, remote: str) -> None:
    subprocess.run(
        [*ssh_argv(host)[:-1], f"lab@{host}", f"cat > {shlex.quote(remote)}"],
        stdin=local.open("rb"),
        check=True,
        timeout=600,
        capture_output=True,
    )


def put(host: str, path: str, content: str, mode: str = "0644") -> None:
    ssh(host, f"sudo install -D -m {mode} /dev/stdin {shlex.quote(path)}", data=content.encode())


def sudo_cat(host: str, path: str) -> str:
    return ssh(host, f"sudo cat {shlex.quote(path)}")[1]


def run_script(name: str, *args: str, timeout: int = 1800, env: dict[str, str] | None = None) -> str:
    """Runs scripts/lab/<name> from lab-dev; raises with its output on failure."""
    # Python helpers run with this interpreter: a CI image may have no python3 on PATH.
    prefix = [sys.executable] if name.endswith(".py") else []
    res = subprocess.run(
        [*prefix, str(SCRIPTS / name), *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        env={**os.environ, **(env or {})},
    )
    if res.returncode != 0:
        raise AssertionError(f"{name} {' '.join(args)} exited {res.returncode}\n{res.stdout}\n{res.stderr}")
    return res.stdout


def rollback(*vms: str) -> None:
    """Restores the VMs to their base snapshot (scripts/lab/rollback.sh), waiting for ssh."""
    for vm in vms:
        run_script("rollback.sh", vm, timeout=900)


def pve_vm(vmid: int, action: str) -> None:
    """Powers a lab VM on or off (`start`, `stop`) through the Proxmox API, as rollback.sh does.

    Starts are refused above the lab budget (scripts/lab/vm_budget.py, PELAGOS_LAB_MAX_VMS).
    """
    conf = Path(os.path.expanduser("~/.config/pelagos-lab"))
    base = os.environ.get("PVE_API") or (conf / "pve-api").read_text().strip()
    header = (conf / "pve-token").read_text().strip()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def call(method: str, path: str) -> Any:
        req = urllib.request.Request(base + path, method=method, headers={"Authorization": header})  # noqa: S310
        with urllib.request.urlopen(req, timeout=30, context=ctx) as res:  # noqa: S310 - lab API only
            return json.loads(res.read())["data"]

    if action == "start":
        run_script("vm_budget.py", "check", str(vmid))
    node = next(r["node"] for r in call("GET", "/cluster/resources?type=vm") if r.get("vmid") == vmid)
    call("POST", f"/nodes/{node}/qemu/{vmid}/status/{action}")
    want = "running" if action == "start" else "stopped"
    wait_for(
        f"VM {vmid} {want}",
        lambda: call("GET", f"/nodes/{node}/qemu/{vmid}/status/current")["status"] == want,
        timeout=180,
    )


def keep() -> bool:
    """PELAGOS_LAB_KEEP=1 leaves the VMs as the tests left them (no final rollback)."""
    return os.environ.get("PELAGOS_LAB_KEEP") == "1"


def make(*targets: str, timeout: int = 1800) -> None:
    res = subprocess.run(
        ["make", "-C", str(REPO), *targets], capture_output=True, text=True, timeout=timeout, check=False
    )
    if res.returncode != 0:
        raise AssertionError(f"make {' '.join(targets)} failed\n{res.stdout[-4000:]}\n{res.stderr[-4000:]}")


def frontend_dist() -> None:
    """Builds the UI into frontend/dist when the node modules are there, so packages carry it."""
    if (REPO / "frontend" / "node_modules").is_dir():
        make("build-frontend")


@functools.cache
def deb_package() -> Path:
    """The deb built from this checkout on lab-dev (same Debian 13 and Python as the targets)."""
    frontend_dist()
    for old in (REPO / "build" / "deb").glob("pelagos_*.deb"):
        old.unlink()
    make("deb")
    arch = subprocess.run(["dpkg", "--print-architecture"], capture_output=True, text=True, check=True).stdout
    (deb,) = (REPO / "build" / "deb").glob(f"pelagos_*_{arch.strip()}.deb")
    return deb


def source_tarball() -> bytes:
    """What the package builds need, without virtualenvs, caches or node modules."""
    skip = {".venv", "node_modules", "__pycache__", ".pytest_cache", ".ruff_cache", "build", ".pelagos-dev"}
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for item in ("backend", "packaging", "docker", "LICENSE", "NOTICE", "README.md", "Makefile"):
            tar.add(
                REPO / item,
                arcname=f"pelagos/{item}",
                filter=lambda t: None if set(Path(t.name).parts) & skip else t,
            )
        if (REPO / "frontend" / "dist" / "index.html").exists():
            tar.add(REPO / "frontend" / "dist", arcname="pelagos/frontend/dist")
    return buf.getvalue()


def upload_source(host: str, directory: str = "~/pelagos-src") -> str:
    ssh(host, f"rm -rf {directory} && mkdir -p {directory} && tar -xz -C {directory}", data=source_tarball())
    return f"{directory}/pelagos"


@functools.cache
def rpm_package() -> Path:
    """The rpm built on lab-pkg-rpm (Rocky, rpmbuild snapshot), copied back to build/lab-rpm."""
    host = PKG_RPM[1]
    frontend_dist()
    # Per-run folders: two checkouts may build on the shared builder at once.
    src = upload_source(host, f"~/pelagos-src-{os.getpid()}")
    out_dir = f"~/rpm-out-{os.getpid()}"
    ssh(
        host,
        f"cd {src} && packaging/rpm/build.sh {out_dir} >/tmp/rpm-build-{os.getpid()}.log 2>&1 "
        f"|| (tail -40 /tmp/rpm-build-{os.getpid()}.log; exit 1)",
    )
    rpms = f"{out_dir}/rpmbuild/RPMS/x86_64"
    name = ssh(host, f"cd {rpms} && ls pelagos-*.x86_64.rpm")[1].split()[0]
    out = REPO / "build" / "lab-rpm"
    out.mkdir(parents=True, exist_ok=True)
    target = out / name
    res = subprocess.run(
        [*ssh_argv(host), f"cat {rpms}/{name}"],
        capture_output=True,
        timeout=600,
        check=True,
    )
    target.write_bytes(res.stdout)
    ssh(host, f"rm -rf {src.rsplit('/', 1)[0]} {out_dir}", check=False)
    return target


def wait_for(what: str, probe: Callable[[], Any], timeout: float = 120, interval: float = 3) -> Any:
    """Calls `probe` until it returns a truthy value; the last exception or value ends in the error."""
    deadline = time.monotonic() + timeout
    last: Any = None
    while True:
        try:
            value = probe()
            if value:
                return value
            last = value
        except Exception as exc:  # polled again until the deadline
            last = exc
        if time.monotonic() > deadline:
            raise AssertionError(f"timed out after {timeout:.0f} s waiting for {what}: {last!r}")
        time.sleep(interval)


class ApiError(AssertionError):
    def __init__(self, status: int, body: Any, what: str) -> None:
        super().__init__(f"{what}: HTTP {status}: {body}")
        self.status = status
        self.body = body


@dataclass
class Api:
    """Session-authenticated client of one node's REST API (self-signed TLS)."""

    address: str
    port: int = 8443
    csrf: str = ""
    jar: http.cookiejar.CookieJar = field(default_factory=http.cookiejar.CookieJar)

    def __post_init__(self) -> None:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ctx), urllib.request.HTTPCookieProcessor(self.jar)
        )

    @property
    def base(self) -> str:
        return f"https://{self.address}:{self.port}/api/v1"

    def call(self, method: str, path: str, body: Any = None, timeout: float = 120) -> Any:
        try:
            return self._call(method, path, body, timeout)
        except ApiError as exc:
            # A restarted node forgot its sessions: log in again once.
            if exc.status != 401 or not self.csrf or path.startswith("/auth/"):
                raise
            self.login()
            return self._call(method, path, body, timeout)

    def _call(self, method: str, path: str, body: Any, timeout: float) -> Any:
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(self.base + path, data=data, method=method)  # noqa: S310 - https only
        if data is not None:
            req.add_header("Content-Type", "application/json")
        if self.csrf:
            req.add_header("X-CSRF-Token", self.csrf)
        try:
            with self.opener.open(req, timeout=timeout) as res:
                raw = res.read()
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            try:
                parsed: Any = json.loads(raw)
            except ValueError:
                parsed = raw.decode(errors="replace")
            raise ApiError(exc.code, parsed, f"{method} {path} on {self.address}") from None
        return json.loads(raw) if raw else None

    def get(self, path: str, **kw: Any) -> Any:
        return self.call("GET", path, **kw)

    def post(self, path: str, body: Any = None, **kw: Any) -> Any:
        return self.call("POST", path, body if body is not None else {}, **kw)

    def login(self, username: str = "admin", password: str = ADMIN_PASSWORD) -> dict[str, Any]:
        out = self.post("/auth/login", {"username": username, "password": password})
        self.csrf = out["csrf_token"]
        return out

    def apply(self, plan: dict[str, Any], timeout: float = 600) -> dict[str, Any]:
        """Applies a plan; a 202 Job is followed until it ends. Returns the ApplyResult or the Job."""
        assert not plan.get("error"), plan
        out = self.post(f"/plans/{plan['id']}/apply", {"confirm": True}, timeout=timeout)
        if isinstance(out, dict) and "steps" in out and "state" in out:
            job_id = out["id"]

            def done() -> Any:
                job = self.get(f"/jobs/{job_id}")
                return job if job["state"] in ("done", "failed") else None

            out = wait_for(f"job {job_id}", done, timeout=timeout, interval=2)
            assert out["state"] == "done", json.dumps(out, indent=2)
        return out


# Security findings no plan closes on the lab VMs: the Kea HA listener needs TLS by hand (and nft for
# its guard, which the cloud image lacks).
MANUAL_KINDS = frozenset({"kea_ha_listener_open"})


def fixable(findings: list[dict[str, Any]]) -> list[str]:
    """Ids of the findings a security plan can fix."""
    return [f["id"] for f in findings if f.get("remediable", True)]


def left(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Findings still open after a plan, the manual ones aside."""
    return [f for f in findings if f.get("remediable", True) or f["kind"] not in MANUAL_KINDS]


if __name__ == "__main__":
    # For the lab shell scripts: python3 backend/tests/lab/labkit.py password <name> [ENV_VAR]
    if len(sys.argv) not in (3, 4) or sys.argv[1] != "password":
        sys.exit("usage: labkit.py password <name> [ENV_VAR]")
    os.environ["PELAGOS_LAB"] = "1"
    print(lab_password(sys.argv[2], sys.argv[3] if len(sys.argv) == 4 else None))
