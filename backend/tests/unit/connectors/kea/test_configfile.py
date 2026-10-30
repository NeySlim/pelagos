# SPDX-License-Identifier: Apache-2.0
"""KeaConfigFile: unreadable includes block writes, masked secrets never reach the files."""

from __future__ import annotations

import contextlib
import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from pelagos.connectors.base import ConnectorError
from pelagos.connectors.kea.configfile import KeaConfigFile
from pelagos.core.write_pipeline import WritePipeline

pytestmark = pytest.mark.unit

ROOT = "DhcpDdns"


@contextlib.contextmanager
def unreadable(path: Path) -> Iterator[None]:
    """`path` cannot be read until the block ends. Root ignores file modes, so as root the file is
    swapped for a directory of the same name, which fails to read with an OSError just the same."""
    if os.geteuid() != 0:
        path.chmod(0)
        try:
            yield
        finally:
            path.chmod(0o644)
        return
    saved = path.with_name(path.name + ".saved")
    path.rename(saved)
    path.mkdir()
    try:
        yield
    finally:
        path.rmdir()
        saved.rename(path)


class Socket:
    def __init__(self, body: dict[str, Any]) -> None:
        self.body = body
        self.calls: list[str] = []

    def config_get(self) -> dict[str, Any]:
        return {ROOT: self.body}

    def call(self, command: str, arguments: Any = None) -> dict[str, Any]:
        self.calls.append(command)
        return {}


def make(
    tmp_path: Path, main: str, parts: dict[str, str], running: dict[str, Any]
) -> tuple[KeaConfigFile, Socket]:
    for name, text in parts.items():
        (tmp_path / name).write_text(text)
    conf = tmp_path / "kea-dhcp-ddns.conf"
    conf.write_text(main)
    sock = Socket(running)
    file = KeaConfigFile(
        conf, ROOT, "d2", lambda: sock, WritePipeline, tmp_path / "backups", "node", cwd=tmp_path
    )
    return file, sock


def key(name: str, secret: str) -> dict[str, str]:
    return {"name": name, "algorithm": "HMAC-SHA256", "secret": secret}


def test_an_unreadable_include_blocks_writes(tmp_path):
    part = tmp_path / "subs.json"
    file, sock = make(
        tmp_path,
        f'{{"DhcpDdns": {{ <?include "{part}"?> "port": 53001 }}}}',
        {"subs.json": '"dns-server-timeout": 3600,'},
        {"dns-server-timeout": 1, "port": 53001},
    )
    with pytest.raises(Exception, match="differs"):
        file.guard(sock.body)
    with unreadable(part):
        with pytest.raises(ConnectorError, match=f"cannot read included file {part}"):
            file.document()
        with pytest.raises(ConnectorError, match="cannot read included file"):
            file.guard(sock.body)
    # The top-level file itself unreadable: Kea owns it, config-write persists; the preflight says
    # the apply cannot back it up.
    with unreadable(file.path):
        assert file.document() is None and file.guard(sock.body) is None
        if os.geteuid() != 0:
            assert "cannot read" in (file.write_problem() or "")


KEYS_MAIN = '{"DhcpDdns": {\n  // keys live apart\n  <?include "%s"?>\n  "port": 53001\n}}\n'


def test_adopt_running_never_writes_a_masked_secret(tmp_path):
    keys = tmp_path / "keys.json"
    file, sock = make(
        tmp_path,
        KEYS_MAIN % keys,
        {"keys.json": '"tsig-keys": [{"name": "k1", "algorithm": "HMAC-SHA256", "secret": "REALSECRET1"}],'},
        {"port": 53001, "tsig-keys": [key("k1", "*****"), key("k2", "*****")]},
    )
    with pytest.raises(ConnectorError, match=r"masked value .*tsig-keys\[1\]/secret"):
        file.plan_adopt("running", sock.body, file.document())
    # A key the file knows gets its clear secret back from the file.
    sock.body = {"port": 53001, "tsig-keys": [key("k1", "*****")]}
    keys.write_text(
        '"tsig-keys": [{"name": "k0", "algorithm": "HMAC-SHA256", "secret": "S0"},'
        ' {"name": "k1", "algorithm": "HMAC-SHA256", "secret": "REALSECRET1"}],'
    )
    change, diff, _ = file.plan_adopt("running", sock.body, file.document())
    assert change.after["mode"] == "patch" and "REALSECRET1" not in diff
    file.apply_adopt(change, "adopt", lambda body: None)  # type: ignore[arg-type,return-value]
    assert (
        "REALSECRET1" in keys.read_text() and "k0" not in keys.read_text() and "*****" not in keys.read_text()
    )


def test_persist_takes_secrets_from_the_applied_values(tmp_path):
    keys = tmp_path / "keys.json"
    before = {"port": 53001, "tsig-keys": [key("k1", "*****")]}
    file, sock = make(
        tmp_path,
        KEYS_MAIN % keys,
        {"keys.json": '"tsig-keys": [{"name": "k1", "algorithm": "HMAC-SHA256", "secret": "S1"}],'},
        before,
    )
    doc = file.guard(before)
    sock.body = {"port": 53001, "tsig-keys": [key("k1", "*****"), key("k2", "*****")]}
    with pytest.raises(ConnectorError, match="masked value"):
        file.persist(doc, before, "change")
    applied = {"tsig-keys": [key("k1", "S1"), key("k2", "S2")]}
    assert file.persist(doc, before, "change", [applied]).startswith("patched keys.json")
    text = keys.read_text()
    assert '"S1"' in text and '"S2"' in text and "*****" not in text
    # A secret changed by the plan replaces the old one in the file, although config-get masks both.
    doc = file.guard(sock.body)
    applied = {"tsig-keys": [key("k1", "NEW1"), key("k2", "S2")]}
    file.persist(doc, sock.body, "rotate", [applied])
    assert '"NEW1"' in keys.read_text() and '"S1"' not in keys.read_text()


def test_includes_on_a_read_only_mount_block_writes(tmp_path, monkeypatch):
    """Pelagos writes included files itself: a sandboxed directory is refused before any change."""
    import os
    from types import SimpleNamespace

    from pelagos.core import writable

    part = tmp_path / "subs.json"
    file, sock = make(
        tmp_path,
        f'{{"DhcpDdns": {{ <?include "{part}"?> "port": 53001 }}}}',
        {"subs.json": '"dns-server-timeout": 3,'},
        {"dns-server-timeout": 3, "port": 53001},
    )
    assert file.guard(sock.body) is not None
    monkeypatch.setattr(writable.os, "statvfs", lambda p: SimpleNamespace(f_flag=os.ST_RDONLY))
    with pytest.raises(ConnectorError, match="read-only mount"):
        file.guard(sock.body)
    assert sock.calls == []


class FakeHelperClient:
    """Stands for the root helper: runs kea_file_write as this user on a closed directory."""

    calls: list[dict[str, Any]] = []
    refuse: str | None = None

    def __init__(self, timeout: float = 0) -> None:
        pass

    def call(self, op: str, **args: Any) -> Any:
        from pelagos.installer import helper as helper_mod
        from pelagos.installer.bind_user_file import replace_checked

        FakeHelperClient.calls.append({"op": op, **args})
        if FakeHelperClient.refuse and args["path"].endswith(FakeHelperClient.refuse):
            raise helper_mod.HelperError(f"{args['path']} refused")
        target = Path(args["path"])
        parent_mode = target.parent.stat().st_mode & 0o777
        target.parent.chmod(0o750)
        try:
            return replace_checked(
                target, args["content"].encode(), args["sha256"], bool(args.get("dry_run"))
            )
        finally:
            target.parent.chmod(parent_mode)


@pytest.fixture
def closed_kea(tmp_path, monkeypatch):
    """Debian's /etc/kea: a directory and files this process reads but cannot write."""
    from pelagos.installer import helper as helper_mod

    FakeHelperClient.calls = []
    FakeHelperClient.refuse = None
    monkeypatch.setattr(helper_mod, "available", lambda: True)
    monkeypatch.setattr(helper_mod, "HelperClient", FakeHelperClient)
    keys = tmp_path / "keys.json"
    file, sock = make(
        tmp_path,
        KEYS_MAIN % keys,
        {"keys.json": '"tsig-keys": [{"name": "k1", "algorithm": "HMAC-SHA256", "secret": "S1"}],'},
        {"port": 53001, "tsig-keys": [key("k1", "S1")]},
    )
    for p in (keys, file.path):
        p.chmod(0o440)
    (tmp_path / "backups").mkdir()
    tmp_path.chmod(0o550)
    yield file, sock, keys
    tmp_path.chmod(0o750)


@pytest.mark.skipif(os.geteuid() == 0, reason="root writes any directory")
def test_closed_kea_dir_is_written_through_the_helper(closed_kea):
    file, sock, keys = closed_kea
    doc = file.document()
    assert file.write_problem() is None
    assert [c["dry_run"] for c in FakeHelperClient.calls] == [True, True]
    applied = {"port": 53001, "tsig-keys": [key("k1", "S2")]}
    sock.body = applied
    assert file.persist(doc, {"port": 53001, "tsig-keys": [key("k1", "S1")]}, "rotate", [applied]).startswith(
        "patched keys.json"
    )
    assert '"S2"' in keys.read_text() and keys.stat().st_mode & 0o777 == 0o440


@pytest.mark.skipif(os.geteuid() == 0, reason="root writes any directory")
def test_closed_kea_dir_without_helper_is_a_preflight_problem(closed_kea, monkeypatch):
    from pelagos.installer import helper as helper_mod

    file, _sock, _keys = closed_kea
    FakeHelperClient.refuse = "keys.json"
    assert "keys.json refused" in (file.write_problem() or "")
    monkeypatch.setattr(helper_mod, "available", lambda: False)
    assert "no privileged helper" in (file.write_problem() or "")


def test_a_file_kea_rewrites_itself_is_probed_as_the_daemon(tmp_path):
    from pelagos.core import permguard

    file, _sock = make(tmp_path, '{"DhcpDdns": {"ip-address": "127.0.0.1"}}', {}, {})
    daemon = [t for t in file.permission_targets() if t.kind == permguard.DAEMON]
    assert [(t.path, t.daemon) for t in daemon] == [(file.path, "kea-dhcp-ddns")]
    assert not [t for t in file.permission_targets(writes=False) if t.kind == permguard.DAEMON]
    # With includes Pelagos writes the files itself: no daemon probe.
    file, _sock = make(tmp_path, '{"DhcpDdns": <?include "part.json"?>}', {"part.json": "{}"}, {})
    assert not [t for t in file.permission_targets() if t.kind == permguard.DAEMON]
