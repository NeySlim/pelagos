# SPDX-License-Identifier: Apache-2.0
"""Helper operation `bind_user_write`: rewrite one of the user's BIND configuration files.

A handover moves a statement out of a user file (named.conf.local, named.conf.options, RHEL's
/etc/named.conf) that the `pelagos` user may read but not write: Debian keeps them root:bind 0644
in /etc/bind (root:bind 2755), RHEL keeps /etc/named.conf root:named 0640 in /etc. Only a file the
host's named.conf includes (itself included), outside the Pelagos include directory, can be
written; it must be a regular file with one link, reached without a symlink, still holding the
content the caller read (sha256). Owner, group, mode and SELinux label stay; the node's write
pipeline keeps the backup and restores it through this same operation.
"""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path
from typing import Any

from pelagos.installer import bindconf

MAX_CONTENT = 4 << 20


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def allowed_files(paths: Any) -> set[Path]:
    """Files named.conf includes at any depth, without the Pelagos include dir and the rndc key
    (the control channel's key is never handed over)."""
    named_conf = Path(paths.named_conf)
    include_dir = Path(os.path.realpath(paths.bind_include_dir))
    rndc_key = getattr(paths, "rndc_key", None)
    excluded = {Path(os.path.realpath(rndc_key))} if rndc_key else set()
    files = bindconf.load_files(named_conf)
    out: set[Path] = set()
    for name in files.texts:
        p = Path(name)
        real = Path(os.path.realpath(p))
        if not p.is_absolute() or real.is_relative_to(include_dir) or real in excluded:
            continue
        out.add(p)
    return out


def _read_nofollow(dir_fd: int, name: str) -> tuple[os.stat_result, bytes]:
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError("not a regular file")
        with os.fdopen(os.dup(fd), "rb") as fh:
            return st, fh.read()
    finally:
        os.close(fd)


def write(env: Any, path: str, content: str, sha256: str) -> dict[str, Any]:
    """Atomically replace `path` with `content` if it still hashes to `sha256`; returns the new hash."""
    if not isinstance(path, str) or not os.path.isabs(path):
        raise ValueError("path must be absolute")
    if not isinstance(content, str) or "\0" in content:
        raise ValueError("content must be text")
    data = content.encode()
    if len(data) > MAX_CONTENT:
        raise ValueError("content too large")
    target = Path(path)
    if os.path.realpath(target) != str(target):
        raise ValueError(f"{path} is reached through a symlink")
    if target not in allowed_files(env.paths):
        raise ValueError(f"{path} is not a BIND configuration file of this host outside the Pelagos files")
    dir_fd = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    tmp_name: str | None = None
    try:
        try:
            st, old = _read_nofollow(dir_fd, target.name)
        except OSError as exc:
            raise ValueError(f"{path}: {exc.strerror}") from None
        if st.st_nlink != 1:
            raise ValueError(f"{path} has {st.st_nlink} hard links")
        if _sha256(old) != sha256:
            raise ValueError(f"{path} changed since it was read")
        tmp_name = f".{target.name}.pelagos-helper.{os.urandom(6).hex()}"
        fd = os.open(tmp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dir_fd)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fchown(fh.fileno(), st.st_uid, st.st_gid)
            os.fchmod(fh.fileno(), stat.S_IMODE(st.st_mode))
            _copy_label(target, fh.fileno())
            os.fsync(fh.fileno())
        # Still the same file as checked: a swap in between is refused, not overwritten.
        now = os.stat(target.name, dir_fd=dir_fd, follow_symlinks=False)
        if (now.st_dev, now.st_ino) != (st.st_dev, st.st_ino):
            raise ValueError(f"{path} was replaced while being written")
        os.rename(tmp_name, target.name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        tmp_name = None
        os.fsync(dir_fd)
    finally:
        if tmp_name is not None:
            try:
                os.unlink(tmp_name, dir_fd=dir_fd)
            except OSError:
                pass
        os.close(dir_fd)
    return {"path": path, "sha256": _sha256(data)}


def _copy_label(source: Path, fd: int) -> None:
    try:
        label = os.getxattr(source, "security.selinux", follow_symlinks=False)
    except OSError:
        return  # no SELinux, or no label
    try:
        os.setxattr(fd, "security.selinux", label)
    except OSError:
        pass


__all__ = ["MAX_CONTENT", "allowed_files", "write"]
