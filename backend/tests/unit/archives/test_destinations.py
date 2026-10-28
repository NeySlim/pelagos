# SPDX-License-Identifier: Apache-2.0
"""Archive destinations: entry validation, the mounted folder and SFTP targets (the real OpenSSH
`sftp` client against a local `sftp-server` when installed), host key pinning."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from pelagos.archives.destinations import config as dconf
from pelagos.archives.destinations.base import DestinationError, DestinationMismatch
from pelagos.archives.destinations.mounted import MountedTarget
from pelagos.archives.destinations.sftp import SftpTarget, fingerprint
from pelagos.archives.model import ArchiveMeta, archive_filename

pytestmark = pytest.mark.unit

NODE = "01JNODE0000000000000000001"
OTHER = "01JNODE0000000000000000002"
SFTP_SERVER = next(
    (
        p
        for p in ("/usr/lib/openssh/sftp-server", "/usr/libexec/openssh/sftp-server")
        if os.access(p, os.X_OK)
    ),
    None,
)
needs_sftp = pytest.mark.skipif(
    SFTP_SERVER is None or shutil.which("sftp") is None,
    reason="OpenSSH sftp and sftp-server are not installed (apt install openssh-client openssh-sftp-server)",
)


def make_archive(folder: Path, at: datetime, node: str = NODE, size: int = 3000) -> tuple[Path, ArchiveMeta]:
    folder.mkdir(parents=True, exist_ok=True)
    name = archive_filename("ns1" if node == NODE else "ns2", at)
    path = folder / name
    data = os.urandom(size)
    path.write_bytes(data)
    meta = ArchiveMeta(
        id=f"A{int(at.timestamp())}",
        node_id=node,
        created_at=at,
        size=size,
        sha256=hashlib.sha256(data).hexdigest(),
        destinations=["local"],
        filename=name,
        recipients=["age1example"],
    )
    return path, meta


T0 = datetime(2026, 6, 1, 3, 15, tzinfo=UTC)


# Entries ----------------------------------------------------------------------------------------

FP = "SHA256:" + "A" * 43


@pytest.mark.parametrize(
    "raw",
    [
        {"id": "nas", "type": "mounted", "params": {"path": "/mnt/archives/"}},
        {"id": "peers", "type": "peer", "params": {"node_ids": []}},
        {"id": "peers2", "type": "peer"},
        {
            "id": "off-site",
            "type": "sftp",
            "params": {
                "host": "192.0.2.10",
                "username": "pelagos",
                "path": "archives",
                "host_key_fingerprint": FP,
            },
            "keep": {"daily": 3, "weekly": 2, "monthly": 1},
        },
    ],
)
def test_valid_entries(raw) -> None:
    dest = dconf.parse(raw)
    assert dest.id == raw["id"] and dest.enabled
    if dest.type == "mounted":
        assert dest.params == {"path": "/mnt/archives"}
    if dest.type == "sftp":
        assert dest.params["port"] == 22 and dest.keep == {"daily": 3, "weekly": 2, "monthly": 1}


@pytest.mark.parametrize(
    ("raw", "field"),
    [
        ({"id": "local", "type": "mounted", "params": {"path": "/mnt"}}, "id"),
        ({"id": "a b", "type": "mounted", "params": {"path": "/mnt"}}, "id"),
        ({"id": "x", "type": "s3"}, "type"),
        ({"id": "x", "type": "mounted", "params": {"path": "relative"}}, "path"),
        ({"id": "x", "type": "mounted", "params": {"path": "/"}}, "path"),
        ({"id": "x", "type": "peer", "params": {"node_ids": "all"}}, "node_ids"),
        ({"id": "x", "type": "sftp", "params": {"host": "-oProxyCommand=x", "username": "u"}}, "host"),
        (
            {
                "id": "x",
                "type": "sftp",
                "params": {"host": "h", "username": "u", "host_key_fingerprint": FP, "path": 'a"b'},
            },
            "path",
        ),
        ({"id": "x", "type": "sftp", "params": {"host": "h", "username": "u", "path": "a*"}}, "path"),
        ({"id": "x", "type": "sftp", "params": {"host": "h", "username": "u"}}, "fingerprint"),
        ({"id": "x", "type": "sftp", "params": {"host": "h", "username": "u", "port": 0}}, "port"),
        ({"id": "x", "type": "mounted", "params": {"path": "/mnt"}, "keep": {"daily": -1}}, "keep"),
    ],
)
def test_invalid_entries(raw, field) -> None:
    with pytest.raises(dconf.DestinationConfigError, match=field):
        dconf.parse(raw)


def test_keep_counts_and_received_keep() -> None:
    settings = {
        "archives": {
            "keep_daily_count": 5,
            "destinations": [
                {"id": "all", "type": "peer", "params": {"node_ids": []}, "keep": {"daily": 2, "weekly": 9}},
                {"id": "one", "type": "peer", "params": {"node_ids": [OTHER]}, "keep": {"daily": 4}},
                {"id": "off", "type": "peer", "enabled": False, "keep": {"daily": 50}},
                {"id": "nas", "type": "mounted", "params": {"path": "/mnt/a"}},
                {"id": "bad", "type": "mounted", "params": {"path": "x"}},
            ],
        }
    }
    good, bad = dconf.configured(settings)
    assert [d.id for d in good] == ["all", "one", "nas"] and list(bad) == ["bad"]
    assert dconf.keep_counts(good[2], settings) == (5, 4, 6)
    assert dconf.received_keep(settings, OTHER, NODE) == (4, 9, 0)
    assert dconf.received_keep(settings, "elsewhere", NODE) == (2, 9, 0)
    assert dconf.received_keep({"archives": {}}, OTHER, NODE) == (7, 4, 6)


# Mounted folder ---------------------------------------------------------------------------------


def mounted(path: Path, mount: bool = True) -> MountedTarget:
    return MountedTarget(
        dconf.parse({"id": "nas", "type": "mounted", "params": {"path": str(path)}}), ismount=lambda _p: mount
    )


def test_mounted_put_verify_list_delete(tmp_path) -> None:
    root = tmp_path / "nas"
    root.mkdir()
    target = mounted(root)
    archive, meta = make_archive(tmp_path / "local", T0)
    target.put(archive, meta)
    folder = root / NODE
    assert sorted(p.name for p in folder.iterdir()) == sorted(
        [meta.filename, meta.filename + ".sha256", meta.filename + ".json"]
    )
    assert (folder / (meta.filename + ".sha256")).read_text() == f"{meta.sha256}  {meta.filename}\n"
    assert oct(folder.stat().st_mode & 0o777) == "0o700"
    assert oct((folder / meta.filename).stat().st_mode & 0o777) == "0o600"
    target.verify(meta)
    assert [m.id for m in target.list(NODE)] == [meta.id]
    _, other = make_archive(tmp_path / "o", T0, node=OTHER)
    target.put(tmp_path / "o" / other.filename, other)
    assert {m.id for m in target.list()} == {meta.id, other.id} and len(target.list(OTHER)) == 1
    # A copy altered on the server is caught by the read back.
    (folder / meta.filename).write_bytes(b"x" * meta.size)
    with pytest.raises(DestinationMismatch):
        target.verify(meta)
    target.delete(meta)
    assert target.list(NODE) == [] and not any(folder.iterdir())
    target.probe()
    assert sorted(p.name for p in root.iterdir()) == [NODE, OTHER]


def test_mounted_refuses_a_folder_that_is_not_mounted(tmp_path) -> None:
    archive, meta = make_archive(tmp_path / "local", T0)
    with pytest.raises(DestinationError, match="not a mount point"):
        mounted(tmp_path, mount=False).put(archive, meta)
    with pytest.raises(DestinationError, match="not a mount point"):
        mounted(tmp_path / "absent", mount=False).probe()


def test_mounted_list_skips_foreign_sidecars(tmp_path) -> None:
    root = tmp_path / "nas"
    target = mounted(root)
    root.mkdir()
    archive, meta = make_archive(tmp_path / "local", T0)
    target.put(archive, meta)
    # A sidecar that names another file or sits in another node's folder is not listed.
    (root / OTHER).mkdir()
    shutil.copy(root / NODE / (meta.filename + ".json"), root / OTHER / (meta.filename + ".json"))
    (root / NODE / "junk.tar.gz.age.json").write_text("{}")
    assert [m.id for m in target.list()] == [meta.id]


# SFTP -------------------------------------------------------------------------------------------


def host_key() -> tuple[str, str]:
    key = ed25519.Ed25519PrivateKey.generate().public_key()
    line = key.public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
    keytype, blob = line.split()[:2]
    return keytype, blob


class Server:
    """ssh-keyscan answers with `blob`; sftp talks to a local sftp-server (`-D`), so the batch
    commands, quoting and globbing are those of the real client."""

    def __init__(self, keytype: str, blob: str) -> None:
        self.keytype, self.blob = keytype, blob
        self.calls: list[list[str]] = []
        self.known_hosts: list[str] = []

    def __call__(self, argv, **kw):
        self.calls.append(list(argv))
        if argv[0] == "ssh-keyscan":
            out = f"# {argv[-1]}:22 SSH-2.0-OpenSSH_10.0\n{argv[-1]} {self.keytype} {self.blob}\n"
            return subprocess.CompletedProcess(argv, 0, out, "")
        opts = dict(a.split("=", 1) for a in argv if "=" in a)
        self.known_hosts.append(Path(opts["UserKnownHostsFile"]).read_text())
        assert Path(opts["IdentityFile"]).stat().st_mode & 0o777 == 0o600
        local = [argv[0], "-D", SFTP_SERVER, *argv[1:-1]]
        return subprocess.run(local, **kw)


def sftp_target(tmp_path: Path, server: Server, path: str, pin: str | None = None) -> SftpTarget:
    config = dconf.parse(
        {
            "id": "off-site",
            "type": "sftp",
            "params": {
                "host": "sftp.example.lan",
                "username": "pelagos",
                "path": path,
                "host_key_fingerprint": pin or fingerprint(server.blob),
            },
        }
    )
    (tmp_path / "run").mkdir(exist_ok=True)
    (tmp_path / "spool").mkdir(exist_ok=True)
    return SftpTarget(
        config,
        "-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n",
        workdir=tmp_path / "run",
        spool=tmp_path / "spool",
        runner=server,
    )


@needs_sftp
def test_sftp_round_trip_with_the_openssh_client(tmp_path) -> None:
    server = Server(*host_key())
    remote = tmp_path / "srv" / "archives with space"
    target = sftp_target(tmp_path, server, str(remote))
    archive, meta = make_archive(tmp_path / "local", T0, size=300_000)
    target.put(archive, meta)
    folder = remote / NODE
    assert sorted(p.name for p in folder.iterdir()) == sorted(
        [meta.filename, meta.filename + ".sha256", meta.filename + ".json"]
    )
    assert (folder / meta.filename).read_bytes() == archive.read_bytes()
    target.verify(meta)
    _, older = make_archive(tmp_path / "local", T0 - timedelta(days=1))
    target.put(tmp_path / "local" / older.filename, older)
    _, other = make_archive(tmp_path / "o", T0, node=OTHER)
    target.put(tmp_path / "o" / other.filename, other)
    assert [m.id for m in target.list(NODE)] == [meta.id, older.id]
    assert {m.id for m in target.list()} == {meta.id, older.id, other.id}
    (folder / meta.filename).write_bytes(b"x" * meta.size)
    with pytest.raises(DestinationMismatch):
        target.verify(meta)
    target.put(archive, meta)  # replaces the bad copy
    target.verify(meta)
    target.delete(older)
    assert [m.id for m in target.list(NODE)] == [meta.id]
    target.probe()
    assert not [p for p in remote.iterdir() if p.name.startswith(".pelagos-probe")]
    # Every session pinned the scanned key, strictly, and nothing is left in the work folders.
    assert all(k == f"pelagos-archive {server.keytype} {server.blob}\n" for k in server.known_hosts)
    sftp_calls = [c for c in server.calls if c[0] == "sftp"]
    assert all("StrictHostKeyChecking=yes" in c and "BatchMode=yes" in c for c in sftp_calls)
    assert sum(c[0] == "ssh-keyscan" for c in server.calls) == 1
    target.close()
    assert not any((tmp_path / "run").iterdir()) and not any((tmp_path / "spool").iterdir())


@needs_sftp
def test_sftp_list_of_an_empty_destination(tmp_path) -> None:
    server = Server(*host_key())
    target = sftp_target(tmp_path, server, str(tmp_path / "srv" / "new"))
    assert target.list() == [] and target.list(NODE) == []
    target.probe()
    assert (tmp_path / "srv" / "new").is_dir()


def test_sftp_refuses_a_host_key_that_does_not_match_the_pin(tmp_path) -> None:
    server = Server(*host_key())
    other = fingerprint(host_key()[1])
    target = sftp_target(tmp_path, server, "archives", pin=other)
    target.sftp = "/bin/true"
    with pytest.raises(DestinationError, match="does not match the pinned fingerprint"):
        target.probe()
    assert [c[0] for c in server.calls] == ["ssh-keyscan"]
    assert not any((tmp_path / "run").iterdir())


def test_sftp_without_key_or_client(tmp_path) -> None:
    server = Server(*host_key())
    target = sftp_target(tmp_path, server, "archives")
    target.private_key = ""
    with pytest.raises(DestinationError, match="no SSH private key"):
        target.probe()
    target = sftp_target(tmp_path, server, "archives")
    target.sftp = str(tmp_path / "missing-sftp")
    with pytest.raises(DestinationError, match="not installed"):
        target.probe()


def test_fingerprint_matches_ssh_keygen(tmp_path) -> None:
    keygen = shutil.which("ssh-keygen")
    if keygen is None:
        pytest.skip("ssh-keygen is not installed")
    keytype, blob = host_key()
    (tmp_path / "k.pub").write_text(f"{keytype} {blob}\n")
    out = subprocess.run([keygen, "-lf", str(tmp_path / "k.pub")], capture_output=True, text=True, check=True)
    assert out.stdout.split()[1] == fingerprint(blob)
