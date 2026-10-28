# SPDX-License-Identifier: Apache-2.0
"""SFTP through the OpenSSH client (`sftp -b`): no Python SSH library to add or keep patched.

The host key is pinned by its SHA256 fingerprint: `ssh-keyscan` fetches the server's keys, the one
matching the pin becomes the only known host key, and the session runs with
`StrictHostKeyChecking=yes`, so the server has to prove it holds that key. The dedicated private key
(secret `archives/dest/<id>/ssh_key`) lives in a 0600 file for the target's lifetime only."""

from __future__ import annotations

import base64
import contextlib
import hashlib
import os
import secrets
import shutil
import subprocess
import tempfile
from collections.abc import Callable
from pathlib import Path

from pelagos.archives.destinations.base import (
    NODE_ID_RE,
    PROBE_PREFIX,
    DestinationError,
    DestinationMismatch,
    Target,
    meta_bytes,
    parse_meta,
    sidecar_names,
    sum_text,
)
from pelagos.archives.destinations.config import DestinationConfig
from pelagos.archives.model import ArchiveMeta

ALIAS = "pelagos-archive"
CONNECT_TIMEOUT = 15
# A transfer that makes no progress is cut by ServerAlive; this caps a whole batch.
BATCH_TIMEOUT = 3 * 3600
SMALL_TIMEOUT = 120
_CHUNK = 1024 * 1024
# Host key types OpenSSH negotiates for each key `ssh-keyscan` prints.
_ALGORITHMS = {"ssh-rsa": "rsa-sha2-512,rsa-sha2-256"}

Runner = Callable[..., subprocess.CompletedProcess]


def fingerprint(blob_b64: str) -> str:
    """`SHA256:...` of a public key blob, as `ssh-keygen -lf` prints it."""
    digest = hashlib.sha256(base64.b64decode(blob_b64)).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


def _q(path: str) -> str:
    return '"' + path + '"'


class SftpTarget(Target):
    def __init__(
        self,
        config: DestinationConfig,
        private_key: str,
        workdir: Path | None = None,
        spool: Path | None = None,
        sftp: str = "sftp",
        keyscan: str = "ssh-keyscan",
        runner: Runner = subprocess.run,
    ) -> None:
        super().__init__(config)
        p = config.params
        self.host, self.port, self.user = str(p["host"]), int(p["port"]), str(p["username"])
        self.base = str(p["path"])
        self.pin = str(p["host_key_fingerprint"]).rstrip("=")
        self.private_key = private_key
        # Key and known_hosts go to `workdir` (a tmpfs under /run when there is one); copies read
        # back go to `spool`, next to the local archives, since they can be large.
        self.workdir = workdir
        self.spool = spool
        self.sftp = sftp
        self.keyscan = keyscan
        self.runner = runner
        self._dir: Path | None = None
        self._algorithm: str | None = None

    # Session ----------------------------------------------------------------------------

    def _session(self) -> Path:
        if self._dir is not None:
            return self._dir
        if not self.private_key.strip():
            raise DestinationError("no SSH private key stored for this destination")
        tool = shutil.which(self.sftp) if "/" not in self.sftp else self.sftp
        if tool is None or not os.access(tool, os.X_OK):
            raise DestinationError("the OpenSSH sftp client is not installed on this node")
        d = Path(
            tempfile.mkdtemp(
                prefix="sftp-", dir=self.workdir if self.workdir and self.workdir.is_dir() else None
            )
        )
        try:
            key = d / "id"
            fd = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as fh:
                fh.write(self.private_key.strip() + "\n")
            keytype, blob = self._pinned_key()
            (d / "known_hosts").write_text(f"{ALIAS} {keytype} {blob}\n")
            self._algorithm = _ALGORITHMS.get(keytype, keytype)
        except BaseException:
            shutil.rmtree(d, ignore_errors=True)
            raise
        self._dir = d
        return d

    def _pinned_key(self) -> tuple[str, str]:
        argv = [
            self.keyscan,
            "-T",
            str(CONNECT_TIMEOUT),
            "-p",
            str(self.port),
            "-t",
            "rsa,ecdsa,ed25519",
            self.host,
        ]
        try:
            proc = self.runner(argv, capture_output=True, text=True, timeout=CONNECT_TIMEOUT * 4, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise DestinationError(f"cannot fetch the host key of {self.host}: {exc}") from exc
        seen = []
        for line in proc.stdout.splitlines():
            fields = line.split()
            if len(fields) < 3 or line.startswith("#"):
                continue
            try:
                fp = fingerprint(fields[2])
            except ValueError:
                continue
            seen.append(fp)
            if fp == self.pin:
                return fields[1], fields[2]
        if not seen:
            err = (proc.stderr or "").strip().splitlines()
            raise DestinationError(
                f"{self.host}:{self.port} did not answer with a host key {err[-1:] or ''}".strip()
            )
        raise DestinationError(
            f"host key of {self.host}:{self.port} does not match the pinned fingerprint {self.pin} "
            f"(server offers {', '.join(seen)})"
        )

    def _argv(self, batch: Path) -> list[str]:
        d = self._session()
        opts = {
            "BatchMode": "yes",
            "StrictHostKeyChecking": "yes",
            "UserKnownHostsFile": str(d / "known_hosts"),
            "GlobalKnownHostsFile": "/dev/null",
            "HostKeyAlias": ALIAS,
            "HostKeyAlgorithms": self._algorithm or "",
            "UpdateHostKeys": "no",
            "IdentityFile": str(d / "id"),
            "IdentitiesOnly": "yes",
            "PasswordAuthentication": "no",
            "KbdInteractiveAuthentication": "no",
            "ConnectTimeout": str(CONNECT_TIMEOUT),
            "ServerAliveInterval": "15",
            "ServerAliveCountMax": "4",
            "HostName": self.host,
            "Port": str(self.port),
            "User": self.user,
            "LogLevel": "ERROR",
        }
        argv = [self.sftp, "-F", "none", "-b", str(batch)]
        for k, v in opts.items():
            argv += ["-o", f"{k}={v}"]
        return [*argv, ALIAS]

    def _batch(self, commands: list[str], timeout: float = SMALL_TIMEOUT) -> str:
        """Runs the commands in one session; a command not prefixed by `-` stops it on failure."""
        d = self._session()
        batch = d / f"batch-{secrets.token_hex(4)}"
        batch.write_text("\n".join(commands) + "\n")
        try:
            proc = self.runner(
                self._argv(batch), capture_output=True, text=True, timeout=timeout, check=False
            )
        except subprocess.TimeoutExpired as exc:
            raise DestinationError(f"sftp to {self.host} timed out") from exc
        except OSError as exc:
            raise DestinationError(f"sftp cannot run: {exc}") from exc
        finally:
            batch.unlink(missing_ok=True)
        if proc.returncode != 0:
            lines = [ln for ln in (proc.stderr or "").strip().splitlines() if ln.strip()]
            raise DestinationError(
                f"sftp to {self.host}: {' '.join(lines[-2:]) or f'exit {proc.returncode}'}"
            )
        return proc.stdout or ""

    def _remote(self, *parts: str) -> str:
        return "/".join([self.base.rstrip("/"), *parts])

    def _mkdirs(self) -> list[str]:
        """`-mkdir` of the base path and each missing parent (failures ignored: they may exist)."""
        parts = [p for p in self.base.split("/") if p and p != "."]
        lead = "/" if self.base.startswith("/") else ""
        return [f"-mkdir {_q(lead + '/'.join(parts[: i + 1]))}" for i in range(len(parts))]

    def _scratch(self) -> Path:
        base = self.spool if self.spool is not None and self.spool.is_dir() else self._session()
        return Path(tempfile.mkdtemp(prefix=".sftp-", dir=base))

    # Target -----------------------------------------------------------------------------

    def put(self, archive: Path, meta: ArchiveMeta) -> None:
        name, sum_name, meta_name = sidecar_names(meta)
        folder = self._remote(meta.node_id)
        local = self._session()
        (local / "sum").write_bytes(sum_text(meta))
        (local / "meta").write_bytes(meta_bytes(meta))
        part = f"{folder}/.{name}.part"
        commands = self._mkdirs()
        commands += [
            f"-mkdir {_q(folder)}",
            f"-chmod 700 {_q(folder)}",
            f"-rm {_q(f'{folder}/{meta_name}')}",
            f"-rm {_q(part)}",
            f"put {_q(str(archive))} {_q(part)}",
            # The server's umask decides the mode of a new file: copies are made 0600 anyway.
            f"-chmod 600 {_q(part)}",
            f"-rm {_q(f'{folder}/{name}')}",
            f"rename {_q(part)} {_q(f'{folder}/{name}')}",
            f"put {_q(str(local / 'sum'))} {_q(f'{folder}/{sum_name}')}",
            f"put {_q(str(local / 'meta'))} {_q(f'{folder}/{meta_name}')}",
            *[f"-chmod 600 {_q(f'{folder}/{n}')}" for n in (sum_name, meta_name)],
        ]
        self._batch(commands, BATCH_TIMEOUT)

    def verify(self, meta: ArchiveMeta) -> None:
        name = sidecar_names(meta)[0]
        scratch = self._scratch()
        try:
            copy = scratch / "copy"
            self._batch([f"get {_q(self._remote(meta.node_id, name))} {_q(str(copy))}"], BATCH_TIMEOUT)
            h = hashlib.sha256()
            with open(copy, "rb") as fh:
                while data := fh.read(_CHUNK):
                    h.update(data)
        except OSError as exc:
            raise DestinationError(f"cannot read the copy back: {exc}") from exc
        finally:
            shutil.rmtree(scratch, ignore_errors=True)
        if h.hexdigest() != meta.sha256:
            raise DestinationMismatch(f"{name} on {self.host} does not match its sum once written")

    def list(self, origin: str | None = None) -> list[ArchiveMeta]:
        scratch = self._scratch()
        out: list[ArchiveMeta] = []
        try:
            folders = [origin] if origin else self._folders()
            for folder in folders:
                local = scratch / folder
                local.mkdir()
                # The glob stays outside the quotes, which would make it literal.
                self._batch([f"-get {_q(self._remote(folder, ''))}*.json {_q(str(local) + '/')}"])
                for p in local.iterdir():
                    meta = parse_meta(p.read_bytes(), p.name)
                    if meta is not None and meta.node_id == folder:
                        out.append(meta)
        finally:
            shutil.rmtree(scratch, ignore_errors=True)
        return sorted(out, key=lambda m: m.created_at, reverse=True)

    def _folders(self) -> list[str]:
        """Origin folders under the base path (names of node ids)."""
        text = self._batch([f"-ls -1 {_q(self.base)}"])
        out = []
        for line in text.splitlines():
            if line.startswith("sftp>"):
                continue
            name = line.strip().rstrip("/").rsplit("/", 1)[-1]
            if NODE_ID_RE.match(name):
                out.append(name)
        return sorted(set(out))

    def delete(self, meta: ArchiveMeta) -> None:
        name, sum_name, meta_name = sidecar_names(meta)
        self._batch([f"-rm {_q(self._remote(meta.node_id, n))}" for n in (meta_name, name, sum_name)])

    def probe(self) -> None:
        data = secrets.token_bytes(64)
        remote = self._remote(f"{PROBE_PREFIX}{secrets.token_hex(6)}")
        local = self._session()
        (local / "probe").write_bytes(data)
        back = local / "probe-back"
        back.unlink(missing_ok=True)
        commands = self._mkdirs()
        commands += [
            f"put {_q(str(local / 'probe'))} {_q(remote)}",
            f"get {_q(remote)} {_q(str(back))}",
            f"rm {_q(remote)}",
        ]
        try:
            self._batch(commands)
        except DestinationError:
            with contextlib.suppress(DestinationError):
                self._batch([f"-rm {_q(remote)}"])
            raise
        try:
            same = back.read_bytes() == data
        except OSError as exc:
            raise DestinationError(f"cannot read the probe back: {exc}") from exc
        if not same:
            raise DestinationMismatch(f"{remote} read back differs from what was written")

    def close(self) -> None:
        if self._dir is not None:
            shutil.rmtree(self._dir, ignore_errors=True)
            self._dir = None

    def __del__(self) -> None:  # the key file never outlives the target
        with contextlib.suppress(Exception):
            self.close()
