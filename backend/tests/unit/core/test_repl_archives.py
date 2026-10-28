# SPDX-License-Identifier: Apache-2.0
"""Archives between two live nodes over mTLS (`/repl/v1/archives`): upload spooled to disk, sum
checked on receipt, origin bound to the caller, retention on receipt, listing and download; then a
scheduled run with a peer destination and the retired identity check across nodes."""

from __future__ import annotations

import hashlib
import io
import json
import os
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from pelagos.archives import keys
from pelagos.archives.model import ArchiveMeta, archive_filename
from pelagos.collector.archives import ArchiveRunner
from pelagos.collector.main import Backends
from pelagos.core.replication import ReplicationError
from tests.unit.core.test_replication import Cluster, LiveNode

pytestmark = pytest.mark.unit

T0 = datetime(2026, 6, 1, 3, 15, tzinfo=UTC)


@pytest.fixture
def pair(tmp_root: Path) -> Iterator[tuple[LiveNode, LiveNode]]:
    c = Cluster(tmp_root)
    try:
        a = c.first()
        yield a, c.enroll(a)
    finally:
        c.stop_all()


def archive(folder: Path, node: LiveNode, at: datetime, size: int) -> tuple[Path, ArchiveMeta]:
    folder.mkdir(parents=True, exist_ok=True)
    name = archive_filename(node.ctx.node.name, at)
    data = os.urandom(size)
    (folder / name).write_bytes(data)
    meta = ArchiveMeta(
        id=f"A{int(at.timestamp())}",
        node_id=node.id,
        created_at=at,
        size=size,
        sha256=hashlib.sha256(data).hexdigest(),
        filename=name,
        recipients=["age1example"],
    )
    return folder / name, meta


def client(src: LiveNode, dst: LiveNode):
    return src.service.replicator.client(src.ctx.cluster().peer(dst.id))


def settings(node: LiveNode, **values) -> None:
    node.ctx.config_store.update_cluster(
        lambda c: c.settings.setdefault("archives", {}).update(values), "test"
    )


def test_peer_stores_lists_and_serves(pair, tmp_root) -> None:
    a, b = pair
    # Over 1 MiB: the body is spooled to disk by the server before the handler runs.
    path, meta = archive(tmp_root / "out", a, T0, 3 * 1024 * 1024 + 5)
    answer = client(a, b).put_archive(path, meta.to_dict())
    assert answer["stored"] and answer["archive"]["id"] == meta.id
    folder = b.paths.archives_dir / "peers" / a.id
    assert sorted(p.name for p in folder.iterdir()) == sorted(
        [meta.filename, meta.filename + ".sha256", meta.filename + ".json"]
    )
    assert (folder / meta.filename).read_bytes() == path.read_bytes()
    assert oct((folder / meta.filename).stat().st_mode & 0o777) == "0o600"
    assert {oct(d.stat().st_mode & 0o777) for d in (folder, folder.parent)} == {"0o700"}
    assert not any((b.paths.archives_dir / ".incoming").iterdir())
    items = client(a, b).list_archives(a.id)["items"]
    assert [i["id"] for i in items] == [meta.id] and "in_use" not in client(a, b).list_archives(a.id)
    everything = client(a, b).list_archives()
    assert everything["in_use"] == ["age1example"] and everything["in_use_known"] is True
    sink = io.BytesIO()
    client(a, b).fetch_archive(meta.id, sink)
    assert sink.getvalue() == path.read_bytes()
    with pytest.raises(ReplicationError) as err:
        client(a, b).fetch_archive("A0", io.BytesIO())
    assert err.value.status == 404
    # Sent again (a retry after a bad read back): replaced, still one copy.
    client(a, b).put_archive(path, meta.to_dict())
    assert len(list(folder.iterdir())) == 3


def test_refusals(pair, tmp_root) -> None:
    a, b = pair
    path, meta = archive(tmp_root / "out", a, T0, 2000)
    bad = meta.to_dict() | {"sha256": "0" * 64}
    with pytest.raises(ReplicationError) as err:
        client(a, b).put_archive(path, bad)
    assert err.value.status == 400 and err.value.code == "checksum_mismatch"
    # A node cannot file an archive as another node's.
    spoof = meta.to_dict() | {"node_id": b.id}
    with pytest.raises(ReplicationError) as err:
        client(a, b).put_archive(path, spoof)
    assert err.value.status == 403
    assert not (b.paths.archives_dir / "peers").exists() or not any(
        (b.paths.archives_dir / "peers").iterdir()
    )
    assert not any((b.paths.archives_dir / ".incoming").iterdir())


def test_size_limit_refused_before_reading(pair, tmp_root) -> None:
    a, b = pair
    settings(b, max_archive_mb=1)
    path, meta = archive(tmp_root / "out", a, T0, 2 * 1024 * 1024)
    der = x509.load_pem_x509_certificate((a.paths.pki_dir / "node.crt").read_bytes()).public_bytes(
        Encoding.DER
    )
    environ = {
        "REQUEST_METHOD": "POST",
        "PATH_INFO": "/repl/v1/archives",
        "CONTENT_LENGTH": str(path.stat().st_size),
        "wsgi.input": io.BytesIO(b""),
        "pelagos.client_cert": der,
        "HTTP_X_PELAGOS_META": json.dumps(meta.to_dict()),
    }
    assert b.service.app.spool_dir("POST", "/repl/v1/archives", environ) is None
    status = []
    body = b.service.app(environ, lambda s, h: status.append(s))
    assert status == ["413 Payload Too Large"] and json.loads(b"".join(body))["code"] == "too_large"
    # Without a node certificate nothing is spooled either.
    assert (
        b.service.app.spool_dir("POST", "/repl/v1/archives", environ | {"pelagos.client_cert": None}) is None
    )


def test_retention_on_receipt(pair, tmp_root) -> None:
    a, b = pair
    dest = {"id": "peers", "type": "peer", "params": {"node_ids": []}, "keep": {"daily": 2}}
    settings(b, destinations=[dest])
    sent = []
    for day in range(4):
        path, meta = archive(tmp_root / "out", a, T0 + timedelta(days=day), 1000)
        client(a, b).put_archive(path, meta.to_dict())
        sent.append(meta.id)
    held = [i["id"] for i in client(a, b).list_archives(a.id)["items"]]
    assert held == sent[:-3:-1]


def test_scheduled_run_sends_to_the_peer_and_prunes_across_nodes(pair) -> None:
    a, b = pair
    out = []
    a.ctx.config_store.update_cluster(
        lambda c: out.append(keys.generate_cluster_identity(c, a.ctx.secrets, by="test")), "test"
    )
    peer_dest = {
        "id": "peers",
        "type": "peer",
        "params": {"node_ids": []},
        "keep": {"daily": 1, "weekly": 0, "monthly": 0},
    }
    settings(a, test_restore_days=0, local_keep_count=1, destinations=[peer_dest])
    a.service.replicator.push_all()
    assert b.ctx.settings()["archives"]["destinations"] == [peer_dest]
    clock = [T0.timestamp()]
    runner = ArchiveRunner(a.ctx, Backends(), clock=lambda: clock[0], helper=lambda: None, tz=UTC)
    first = runner.run()
    assert first is not None and first.destinations == ["local", "peers"]
    copy = b.paths.archives_dir / "peers" / a.id / first.filename
    assert copy.read_bytes() == runner.store.path(first).read_bytes()
    old = keys.encryption_recipients(a.ctx.settings())[0]
    a.ctx.config_store.update_cluster(lambda c: keys.generate_cluster_identity(c, a.ctx.secrets, by="t"), "t")
    # b has not listed its destination yet: it cannot vouch for it, so the identity is kept.
    clock[0] += 3600
    runner.run()
    assert not copy.exists()  # retention on receipt: b keeps the newest only
    assert keys.retired_secret(old) in a.ctx.cluster().secrets
    # Once b ran with the destinations, it vouches for what it knows of: the identity goes.
    b_runner = ArchiveRunner(b.ctx, Backends(), clock=lambda: clock[0], helper=lambda: None, tz=UTC)
    a.service.replicator.push_all()
    b_runner.run()
    clock[0] += 3600
    runner.run()
    assert keys.retired_secret(old) not in a.ctx.cluster().secrets
