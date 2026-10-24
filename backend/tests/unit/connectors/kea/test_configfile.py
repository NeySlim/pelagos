# SPDX-License-Identifier: Apache-2.0
"""KeaConfigFile: unreadable includes block writes, masked secrets never reach the files."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from pelagos.connectors.base import ConnectorError
from pelagos.connectors.kea.configfile import KeaConfigFile
from pelagos.core.write_pipeline import WritePipeline

pytestmark = pytest.mark.unit

ROOT = "DhcpDdns"


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
    part.chmod(0)
    try:
        with pytest.raises(ConnectorError, match=f"cannot read included file {part}"):
            file.document()
        with pytest.raises(ConnectorError, match="cannot read included file"):
            file.guard(sock.body)
    finally:
        part.chmod(0o644)
    # The top-level file itself unreadable: Kea owns it, config-write persists.
    file.path.chmod(0)
    try:
        assert file.document() is None and file.guard(sock.body) is None
    finally:
        file.path.chmod(0o644)


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
