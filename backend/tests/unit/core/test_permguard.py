# SPDX-License-Identifier: Apache-2.0
"""Permission guard (core.permguard): the writer's own operations, probes and their findings."""

# ruff: noqa: S103

from __future__ import annotations

import errno
import os
import re
import stat
import subprocess
from pathlib import Path

import pytest

from pelagos.core import permguard
from pelagos.domain import messages

pytestmark = pytest.mark.unit

BACKEND = Path(__file__).resolve().parents[3] / "pelagos"
as_root = pytest.mark.skipif(os.geteuid() == 0, reason="root writes and reads anything")


def _no_setgid_argument(monkeypatch: pytest.MonkeyPatch) -> None:
    """What RestrictSUIDSGID=yes does: any mode argument carrying S_ISGID or S_ISUID is EPERM."""
    real_mkdir, real_chmod = os.mkdir, os.chmod

    def mkdir(path, mode=0o777, *a, **kw):  # type: ignore[no-untyped-def]
        if mode & (stat.S_ISGID | stat.S_ISUID):
            raise PermissionError(errno.EPERM, "Operation not permitted", str(path))
        return real_mkdir(path, mode, *a, **kw)

    def chmod(path, mode, *a, **kw):  # type: ignore[no-untyped-def]
        if mode & (stat.S_ISGID | stat.S_ISUID):
            raise PermissionError(errno.EPERM, "Operation not permitted", str(path))
        return real_chmod(path, mode, *a, **kw)

    monkeypatch.setattr(os, "mkdir", mkdir)
    monkeypatch.setattr(os, "chmod", chmod)


def test_group_dir_inherits_setgid_without_asking_for_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parent = tmp_path / "cache"
    parent.mkdir()
    os.chmod(parent, 0o2775)
    _no_setgid_argument(monkeypatch)
    created = permguard.make_group_dir(parent / "pelagos" / "rpz", None)
    assert created == [parent / "pelagos", parent / "pelagos" / "rpz"]
    for d in created:
        assert stat.S_IMODE(d.stat().st_mode) == 0o2775  # setgid from the parent, group writable


def test_group_dir_without_setgid_parent_is_group_writable(tmp_path: Path) -> None:
    os.chmod(tmp_path, 0o755)
    (d,) = permguard.make_group_dir(tmp_path / "zones", None)
    assert stat.S_IMODE(d.stat().st_mode) == 0o775
    assert permguard.make_group_dir(tmp_path / "zones", None) == []  # idempotent


def test_no_setgid_mode_argument_in_the_service_code() -> None:
    """The services run with RestrictSUIDSGID=yes: no mkdir/chmod/open there may name S_ISGID or
    S_ISUID. The installer runs as root in the helper or the CLI, outside that filter."""
    pattern = re.compile(r"(chmod|mkdir|os\.open|fchmod|mkstemp)\([^)]*(0o[2-7][0-7]{3}\b|S_ISGID|S_ISUID)")
    offenders = []
    for path in BACKEND.rglob("*.py"):
        rel = path.relative_to(BACKEND)
        if rel.parts[0] == "installer":
            continue
        for n, line in enumerate(path.read_text().splitlines(), 1):
            if pattern.search(line):
                offenders.append(f"{rel}:{n}: {line.strip()}")
    assert offenders == []


def test_missing_dir_under_writable_parent_is_created_by_the_writer(tmp_path: Path) -> None:
    target = permguard.Target(tmp_path / "pelagos" / "rpz", permguard.DIR, "bind", "rpz_dir", subdirs=True)
    (check,) = permguard.run([target])
    assert check.ok and check.route == "create" and check.probed == str(tmp_path)
    assert list(tmp_path.iterdir()) == []  # the probe leaves nothing behind


def test_existing_dir_probe_runs_file_and_subdir_creation(tmp_path: Path) -> None:
    (check,) = permguard.run([permguard.Target(tmp_path, permguard.DIR, "bind", "zone_dir", subdirs=True)])
    assert check.ok and check.route == "direct"
    assert list(tmp_path.iterdir()) == []


def test_eperm_on_the_probe_is_a_refusal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The prod case: mkdir refused with EPERM although the permissions allow it."""

    def refused(d: Path) -> None:
        raise OSError(errno.EPERM, "Operation not permitted", str(d))

    monkeypatch.setattr(permguard, "_mkdir", refused)
    target = permguard.Target(
        tmp_path / "pelagos", permguard.DIR, "bind", "zone_dir", group=None, subdirs=True
    )
    (check,) = permguard.run([target])
    # The parent is writable: the helper's audit has no fix for it, so no finding id is published.
    assert not check.ok and check.problem == "refused" and not check.remediable
    assert check.command == f"install -d -o {check.group} -g {check.group} -m 2775 {tmp_path / 'pelagos'}"
    data = check.to_dict()
    assert "finding_id" not in data
    assert "the service is refused the operation (EPERM)" in data["text"]


def test_eperm_on_an_existing_folder_never_changes_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refused(*_a, **_kw):  # type: ignore[no-untyped-def]
        raise OSError(errno.EPERM, "Operation not permitted")

    monkeypatch.setattr(permguard.tempfile, "mkstemp", refused)
    (check,) = permguard.run([permguard.Target(tmp_path, permguard.DIR, "bind", "zone_dir", group="bind")])
    assert not check.ok and check.problem == "refused" and not check.remediable
    assert check.command.startswith("usermod -aG bind pelagos && systemctl restart ")
    assert "install -d" not in check.command and "chmod" not in check.command
    assert "finding_id" not in check.to_dict()


def test_probe_folder_removed_when_its_chown_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def chown(*_a, **_kw):  # type: ignore[no-untyped-def]
        raise PermissionError(errno.EPERM, "Operation not permitted")

    monkeypatch.setattr(permguard, "_gid", lambda _g: os.getgid() + 1)
    monkeypatch.setattr(permguard.os, "chown", chown)
    (check,) = permguard.run(
        [permguard.Target(tmp_path / "zones", permguard.DIR, "bind", "zone_dir", group="x")]
    )
    assert not check.ok
    assert list(tmp_path.iterdir()) == []  # no .pelagos-probe.* left behind


def test_mkdir_errno_read_under_a_french_locale(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """mkdir(1) runs under LC_ALL=C whatever the unit's LANG: EROFS stays a sandbox finding."""
    seen: dict[str, str] = {}

    def run(*_a, **kw):  # type: ignore[no-untyped-def]
        seen.update(kw["env"])
        lang = kw["env"].get("LC_ALL") or kw["env"].get("LANG")
        text = (
            "mkdir: Read-only file system"
            if lang == "C"
            else "mkdir: Système de fichiers accessible en lecture seulement"
        )
        return subprocess.CompletedProcess(_a[0], 1, "", text)

    monkeypatch.setenv("LANG", "fr_FR.UTF-8")
    monkeypatch.setattr(permguard.subprocess, "run", run)
    with pytest.raises(OSError) as exc:
        permguard._mkdir(tmp_path / "zones")
    assert exc.value.errno == errno.EROFS and seen["LC_ALL"] == "C"

    def slow(*_a, **_kw):  # type: ignore[no-untyped-def]
        raise subprocess.TimeoutExpired("mkdir", 30)

    monkeypatch.setattr(permguard.subprocess, "run", slow)
    with pytest.raises(OSError):
        permguard._mkdir(tmp_path / "zones")


def test_read_only_mount_names_the_sandbox(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def rofs(*_a, **_kw):  # type: ignore[no-untyped-def]
        raise OSError(errno.EROFS, "Read-only file system")

    monkeypatch.setattr(permguard.tempfile, "mkstemp", rofs)
    (check,) = permguard.run([permguard.Target(tmp_path, permguard.DIR, "bind", "zone_dir")])
    assert not check.ok and check.problem == "read_only" and not check.remediable
    assert f"ReadWritePaths=-{tmp_path}" in check.command
    assert "outside the paths the service may write" in check.to_dict()["text"]


@as_root
def test_unwritable_parent_finding_names_owner_mode_and_command(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    cache.mkdir()
    os.chmod(cache, 0o755)
    os.chmod(cache, 0o555)
    try:
        target = permguard.Target(cache / "pelagos" / "rpz", permguard.DIR, "bind", "rpz_dir", subdirs=True)
        (check,) = permguard.run([target])
    finally:
        os.chmod(cache, 0o755)
    assert not check.ok and check.problem == "denied" and check.mode == "0555" and check.probed == str(cache)
    assert check.fix == {
        "action": "create_dir",
        "path": str(cache / "pelagos"),
        "owner": check.group,
        "group": check.group,
    }
    text = messages.render(check.message())
    assert text.startswith(f"RPZ folder {cache / 'pelagos' / 'rpz'}: cannot be created")
    assert f"install -d -o {check.group} -g {check.group} -m 2775 {cache / 'pelagos'}" in text


@as_root
def test_unreadable_file_proposes_the_group(tmp_path: Path) -> None:
    conf = tmp_path / "kea-dhcp-ddns.conf"
    conf.write_text("{}")
    os.chmod(conf, 0o000)
    (check,) = permguard.run([permguard.Target(conf, permguard.READ, "d2", "kea_file")])
    assert not check.ok and check.problem == "not_readable"
    assert check.command.startswith("chgrp ") and check.command.endswith(f"chmod g+r {conf}")


@as_root
def test_unwritable_file_goes_through_the_helper_when_there_is_one(tmp_path: Path) -> None:
    conf = tmp_path / "named.conf.local"
    conf.write_text("")
    os.chmod(conf, 0o444)
    os.chmod(tmp_path, 0o555)
    try:
        target = permguard.Target(conf, permguard.FILE, "bind", "config_file", privileged=True)
        (helped,) = permguard.run([target], helper_available=True)
        (alone,) = permguard.run([target], helper_available=False)
    finally:
        os.chmod(tmp_path, 0o755)
    assert helped.ok and helped.route == "helper"
    assert not alone.ok and alone.problem == "denied"


def test_raw_errno_of_an_apply_is_translated() -> None:
    path = "/etc/bind/cache/pelagos"
    text = f"cannot create zone directory {path}: [Errno 1] Operation not permitted: '{path}'"
    message = permguard.message_for_text(text)
    assert message is not None
    rendered = messages.render(message)
    assert "the operation was refused to the Pelagos service" in rendered
    assert "/etc/bind/cache/pelagos" in rendered
    assert permguard.message_for_text("named-checkconf: syntax error") is None
    m = permguard.apply_error(OSError(errno.EACCES, "Permission denied", "/etc/kea/x"))
    assert (
        messages.render(m)
        == "cannot write /etc/kea/x: the Pelagos service has no write permission there (Permission denied)"
    )


def test_state_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "permissions.json"
    permguard.save_state(path, "n1", [{"path": "/x", "ok": True}])
    assert permguard.load_state(path)["checks"] == [{"path": "/x", "ok": True}]
    assert stat.S_IMODE(path.stat().st_mode) == 0o640
    assert permguard.load_state(tmp_path / "absent.json") is None
