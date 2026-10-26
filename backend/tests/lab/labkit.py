# SPDX-License-Identifier: Apache-2.0
"""Helpers of the lab tier: ssh to the VMs, a REST client for a node, polling."""

from __future__ import annotations

import functools
import http.cookiejar
import io
import json
import os
import shlex
import ssl
import subprocess
import tarfile
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[3]
SCRIPTS = REPO / "scripts" / "lab"
SSH_KEY = os.path.expanduser(os.environ.get("PELAGOS_LAB_SSH_KEY", "~/.ssh/id_ed25519"))
ADMIN_PASSWORD = os.environ.get("PELAGOS_LAB_ADMIN_PASSWORD", "Lab-Admin-Password-1")

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


def run_script(name: str, *args: str, timeout: int = 1800) -> str:
    """Runs scripts/lab/<name> from lab-dev; raises with its output on failure."""
    res = subprocess.run(
        [str(SCRIPTS / name), *args], capture_output=True, text=True, timeout=timeout, check=False
    )
    if res.returncode != 0:
        raise AssertionError(f"{name} {' '.join(args)} exited {res.returncode}\n{res.stdout}\n{res.stderr}")
    return res.stdout


def rollback(*vms: str) -> None:
    """Restores the VMs to their base snapshot (scripts/lab/rollback.sh), waiting for ssh."""
    for vm in vms:
        run_script("rollback.sh", vm, timeout=900)


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
    src = upload_source(host)
    ssh(
        host,
        f"cd {src} && packaging/rpm/build.sh ~/rpm-out >/tmp/rpm-build.log 2>&1 "
        "|| (tail -40 /tmp/rpm-build.log; exit 1)",
    )
    name = ssh(host, "cd ~/rpm-out/rpmbuild/RPMS/x86_64 && ls pelagos-*.x86_64.rpm")[1].split()[0]
    out = REPO / "build" / "lab-rpm"
    out.mkdir(parents=True, exist_ok=True)
    target = out / name
    res = subprocess.run(
        [*ssh_argv(host), f"cat ~/rpm-out/rpmbuild/RPMS/x86_64/{name}"],
        capture_output=True,
        timeout=600,
        check=True,
    )
    target.write_bytes(res.stdout)
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
