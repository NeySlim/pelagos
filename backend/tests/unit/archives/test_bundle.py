# SPDX-License-Identifier: Apache-2.0
"""Archive files: name, manifest, sums, encrypted tar round trip, damage detection, `age` interop."""

from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import tarfile
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest

from pelagos.archives import age, bundle
from pelagos.archives.model import (
    ArchiveError,
    ArchiveMeta,
    Manifest,
    archive_filename,
    parse_filename,
)

pytestmark = pytest.mark.unit

AGE = shutil.which("age")
WHEN = datetime(2026, 10, 28, 3, 15, 7, tzinfo=UTC)


def _tree(root: Path) -> dict[str, Path]:
    etc = root / "etc" / "bind"
    etc.mkdir(parents=True)
    (etc / "named.conf").write_text('include "/etc/bind/pelagos/zones.conf";\n')
    (etc / "rndc.key").write_text('key "rndc-key" { algorithm hmac-sha256; secret "c2VjcmV0"; };\n')
    (etc / "rndc.key").chmod(0o640)
    big = root / "var" / "kea-leases4.csv"
    big.parent.mkdir(parents=True)
    big.write_bytes(os.urandom(300_000))
    return {"conf": etc / "named.conf", "key": etc / "rndc.key", "leases": big}


def _write(root: Path, recipients: list[str], **kw) -> tuple[ArchiveMeta, Path]:
    files = _tree(root / "src")
    with bundle.ArchiveWriter(
        root / "out",
        node_id="01NODE",
        node_name="ns1",
        recipients=recipients,
        versions={"pelagos": "0.2.2", "bind": "9.20.15", "kea": "2.6.3"},
        engines=["bind", "kea"],
        created_at=WHEN,
        **kw,
    ) as w:
        assert w.add_file(files["conf"], "bind.user_files")
        assert w.add_file(files["key"], "bind.managed")
        assert w.add_file(files["leases"], "kea.leases")
        assert not w.add_file(root / "src" / "missing.conf", "bind.managed")
        w.add_bytes("/etc/kea/kea-dhcp4.conf", b'{"Dhcp4": {}}', "kea4.config", owner="root:_kea")
        w.add_zone(
            "_default", "example.lan", 2026102801, "axfr", b"example.lan. 3600 IN SOA ns1. h. 1 2 3 4 5\n"
        )
        w.add_zone("internal", "0/25.2.0.192.in-addr.arpa", 7, "axfr", b"; classless\n")
        w.add_zone("_default", "static.example.lan", 3, "file")
        meta = w.finish(destinations=["local"])
    return meta, root / "out" / meta.filename


def test_filename_round_trip() -> None:
    name = archive_filename("ns2", datetime(2026, 1, 2, 4, 5, 6, tzinfo=timezone(timedelta(hours=1))))
    assert name == "ns2-20260102T030506Z.tar.gz.age"
    assert parse_filename(name) == ("ns2", datetime(2026, 1, 2, 3, 5, 6, tzinfo=UTC))
    assert parse_filename("dhcp-a-20260102T030506Z.tar.gz.age")[0] == "dhcp-a"
    assert parse_filename("ns2-20260102.tar.gz.age") is None
    assert parse_filename("ns2-20260102T030506Z.tar.gz.age.sha256") is None
    for bad in ("", "../x", "a/b", "-x"):
        with pytest.raises(ArchiveError):
            archive_filename(bad, WHEN)


def test_write_and_read_back(tmp_path: Path) -> None:
    cluster, operator = age.generate_identity(), age.generate_identity()
    meta, path = _write(tmp_path, [age.recipient_of(cluster), age.recipient_of(operator)])
    assert path.name == "ns1-20261028T031507Z.tar.gz.age"
    assert path.stat().st_mode & 0o777 == 0o600
    assert (tmp_path / "out").stat().st_mode & 0o777 == 0o700
    assert meta.size == path.stat().st_size and meta.sha256 == bundle.sha256_file(path)
    assert meta.destinations == ["local"] and not meta.complete
    assert ArchiveMeta.from_dict(json.loads(json.dumps(meta.to_dict()))) == meta
    assert sorted(p.name for p in (tmp_path / "out").iterdir()) == [path.name, path.name + ".sha256"]
    assert bundle.verify_sum(path)

    for identity in (cluster, operator):
        manifest = bundle.read_manifest(path, [identity])
        assert manifest.archive_id == meta.id and manifest.node_name == "ns1"
        assert manifest.created_at == WHEN and manifest.versions["kea"] == "2.6.3"
        assert not manifest.complete and manifest.unreadable == [str(tmp_path / "src" / "missing.conf")]
    key = next(f for f in manifest.files if f.path.endswith("rndc.key"))
    assert key.mode == 0o640 and key.part == "bind.managed" and ":" in key.owner
    assert Manifest.from_dict(json.loads(json.dumps(manifest.to_dict()))) == manifest
    assert [z.source for z in manifest.zones] == ["axfr", "axfr", "file"]
    assert manifest.zones[2].sha256 == ""


def test_extract_and_select(tmp_path: Path) -> None:
    identity = age.generate_identity()
    _, path = _write(tmp_path, [age.recipient_of(identity)])
    dest = tmp_path / "x"
    bundle.extract(path, [identity], dest)
    src = tmp_path / "src"
    leases = dest / bundle.file_member(str(src / "var" / "kea-leases4.csv"))
    assert leases.read_bytes() == (src / "var" / "kea-leases4.csv").read_bytes()
    assert leases.stat().st_mode & 0o777 == 0o600
    zone = dest / bundle.zone_member("internal", "0/25.2.0.192.in-addr.arpa")
    assert zone.name == "0%2F25.2.0.192.in-addr.arpa.zone" and zone.read_bytes() == b"; classless\n"
    assert not (dest / "manifest.json").exists()

    _, members = bundle.read_members(path, [identity], lambda n: n.startswith("zones/"))
    assert set(members) == {
        bundle.zone_member("_default", "example.lan"),
        bundle.zone_member("internal", "0/25.2.0.192.in-addr.arpa"),
    }


def test_wrong_identity_and_truncation(tmp_path: Path) -> None:
    identity = age.generate_identity()
    _, path = _write(tmp_path, [age.recipient_of(identity)])
    with pytest.raises(age.AgeNoMatchError):
        bundle.read_manifest(path, [age.generate_identity()])
    data = path.read_bytes()
    for cut in (1, 1000, len(data) // 2):
        path.write_bytes(data[:-cut])
        assert not bundle.verify_sum(path)
        with pytest.raises((age.AgePayloadError, ArchiveError)):
            bundle.read_manifest(path, [identity])


def _repack(path: Path, identity: str, recipient: str, edit) -> None:
    """Rewrites the archive with `edit(name, data) -> data | None` applied to each member."""
    plain = io.BytesIO(age.decrypt(path.read_bytes(), [identity]))
    out = io.BytesIO()
    with tarfile.open(fileobj=plain, mode="r:gz") as src, tarfile.open(fileobj=out, mode="w:gz") as dst:
        for info in src:
            data = edit(info.name, src.extractfile(info).read())
            if data is None:
                continue
            info.size = len(data)
            dst.addfile(info, io.BytesIO(data))
    path.write_bytes(age.encrypt(out.getvalue(), [recipient]))


def test_member_not_matching_manifest_refused(tmp_path: Path) -> None:
    identity = age.generate_identity()
    recipient = age.recipient_of(identity)
    _, path = _write(tmp_path, [recipient])
    _repack(path, identity, recipient, lambda n, d: d + b"#" if n.endswith("named.conf") else d)
    with pytest.raises(ArchiveError, match="does not match"):
        bundle.read_manifest(path, [identity])
    _repack(path, identity, recipient, lambda n, d: None if n == "manifest.json" else d)
    with pytest.raises(ArchiveError, match="no manifest"):
        bundle.read_manifest(path, [identity])


def test_unsafe_member_refused(tmp_path: Path) -> None:
    identity = age.generate_identity()
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:gz") as tar:
        info = tarfile.TarInfo("../evil")
        info.size = 1
        tar.addfile(info, io.BytesIO(b"x"))
    path = tmp_path / "ns1-20261028T031507Z.tar.gz.age"
    path.write_bytes(age.encrypt(out.getvalue(), [age.recipient_of(identity)]))
    with pytest.raises(ArchiveError, match="unsafe"):
        bundle.extract(path, [identity], tmp_path / "x")
    assert not (tmp_path / "evil").exists()


def test_failed_write_leaves_nothing(tmp_path: Path) -> None:
    identity = age.generate_identity()
    with pytest.raises(RuntimeError):
        with bundle.ArchiveWriter(
            tmp_path, node_id="n", node_name="ns1", recipients=[age.recipient_of(identity)], created_at=WHEN
        ) as w:
            w.add_bytes("/etc/x", b"x", "bind.managed")
            raise RuntimeError("boom")
    assert list(tmp_path.iterdir()) == []
    with pytest.raises(ArchiveError, match="absolute"):
        with bundle.ArchiveWriter(
            tmp_path, node_id="n", node_name="ns1", recipients=[age.recipient_of(identity)]
        ) as w:
            w.add_bytes("relative/path", b"", "bind.managed")
    assert list(tmp_path.iterdir()) == []


def test_no_clear_text_on_disk(tmp_path: Path) -> None:
    identity = age.generate_identity()
    _write(tmp_path, [age.recipient_of(identity)])
    for p in (tmp_path / "out").iterdir():
        assert b"rndc-key" not in p.read_bytes() and b"Dhcp4" not in p.read_bytes()


def test_sum_file_format(tmp_path: Path) -> None:
    identity = age.generate_identity()
    meta, path = _write(tmp_path, [age.recipient_of(identity)])
    assert bundle.sum_path(path).read_text() == f"{meta.sha256}  {path.name}\n"
    if shutil.which("sha256sum"):
        subprocess.run(
            ["sha256sum", "-c", bundle.sum_path(path).name], cwd=path.parent, check=True, capture_output=True
        )
    bundle.sum_path(path).write_text("garbage\n")
    with pytest.raises(ArchiveError):
        bundle.verify_sum(path)


@pytest.mark.skipif(AGE is None, reason="the age tool is not installed (apt install age)")
def test_age_tool_opens_archive(tmp_path: Path) -> None:
    """Disaster path: `age -d -i key archive | tar xz` without Pelagos."""
    cluster, operator = age.generate_identity(), age.generate_identity()
    _, path = _write(tmp_path, [age.recipient_of(cluster), age.recipient_of(operator)])
    key = tmp_path / "operator.key"
    key.write_text(operator + "\n")
    plain = subprocess.run([AGE, "-d", "-i", str(key), str(path)], capture_output=True, check=True).stdout
    with tarfile.open(fileobj=io.BytesIO(plain), mode="r:gz") as tar:
        names = tar.getnames()
        manifest = json.loads(tar.extractfile("manifest.json").read())
    assert names[-1] == "manifest.json" and manifest["format"] == 1 and manifest["node_name"] == "ns1"
    assert "files/etc/kea/kea-dhcp4.conf" in names
