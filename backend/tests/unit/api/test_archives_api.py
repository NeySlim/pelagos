# SPDX-License-Identifier: Apache-2.0
"""Administration > Backups over the API (batch B6): settings, the cluster identity and operator keys,
destinations with a write-only SSH key and a test, runs as jobs, the list of every node's archives,
download, upload and the pruning of retired identities."""

from __future__ import annotations

import io
import json
import time
from datetime import timedelta
from types import SimpleNamespace

import pytest

from pelagos.archives import age, keys
from pelagos.archives.bundle import ArchiveWriter
from pelagos.archives.destinations.base import DestinationError
from pelagos.archives.store import ArchiveStore
from pelagos.domain import Peer, utcnow
from pelagos.services.archive_service import node_state, probe_local
from pelagos.services.errors import ServiceError
from tests.conftest import ADMIN_PASSWORD

pytestmark = pytest.mark.unit

A = "/api/v1/admin/archives"
KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----\n"
SFTP = {
    "type": "sftp",
    "name": "Off site",
    "params": {
        "host": "backup.example.lan",
        "username": "pelagos",
        "path": "archives",
        "host_key_fingerprint": "SHA256:" + "A" * 43,
    },
    "secrets": {"ssh_key": KEY},
}


def generate(client, password=ADMIN_PASSWORD, op="generate"):
    return client.post(f"{A}/identity", json={"op": op, "password": password})


def wait_job(client, job):
    for _ in range(200):
        job = client.get(f"/api/v1/jobs/{job['id']}").get_json()
        if job["state"] in ("done", "failed"):
            return job
        time.sleep(0.02)
    raise AssertionError(job)


def write_archive(node_ctx, directory=None, node_id=None, name="ns1", created_at=None):
    recipients = keys.encryption_recipients(node_ctx.settings())
    store = ArchiveStore(node_ctx.paths.archives_dir)
    store.ensure()
    with ArchiveWriter(
        directory or store.local,
        node_id=node_id or node_ctx.node.id,
        node_name=name,
        recipients=recipients,
        created_at=created_at,
    ) as w:
        w.add_bytes("/etc/bind/named.conf", b"options {};\n", "bind.user_files")
        meta = w.finish(["local"])
    if directory is None:
        store.save_meta(meta)
    return meta


def test_identity_once_with_password_and_schedule_guard(admin, node_ctx):
    body = admin.get(A).get_json()
    assert body["recipients"] == [] and body["identity"]["stored"] is False
    assert body["settings"]["schedule_enabled"] is False and "destinations" not in body["settings"]
    assert body["nodes"][0]["node_id"] == node_ctx.node.id and body["nodes"][0]["reachable"]
    r = admin.put(f"{A}/settings", json={"schedule_enabled": True})
    assert r.status_code == 400 and r.get_json()["errors"][0]["field"] == "schedule_enabled"
    r = admin.put("/api/v1/admin/settings", json={"archives": {"schedule_enabled": True}})
    assert r.status_code == 400 and "recipient" in r.get_json()["detail"]
    assert generate(admin, "wrong").status_code == 401
    r = generate(admin)
    assert r.status_code == 200, r.get_json()
    identity = r.get_json()["identity"]
    assert age.is_identity(identity) and r.get_json()["identity_state"]["stored"]
    overview = admin.get(A).get_json()
    assert identity not in json.dumps(overview)
    assert overview["identity"]["recipient"] == age.recipient_of(identity)
    assert generate(admin).status_code == 409
    r = admin.put(f"{A}/settings", json={"schedule_enabled": True, "start_time": "02:30"})
    assert r.status_code == 200 and r.get_json()["settings"]["start_time"] == "02:30"
    assert admin.put(f"{A}/settings", json={"start_time": "25:00"}).status_code == 400
    assert admin.put(f"{A}/settings", json={"destinations": []}).status_code == 400
    recipient = age.recipient_of(identity)
    r = admin.post(f"{A}/identity", json={"op": "remove_recipient", "recipient": recipient})
    assert r.status_code == 409 and keys.recipients(node_ctx.settings())
    ops = [e.request.get("op") for e in node_ctx.audit_log.read() if e.action == "admin.archive.op"]
    assert ops.count("generate") == 2 and identity not in json.dumps(
        [e.to_dict() for e in node_ctx.audit_log.read()]
    )


def test_operator_recipients_rotate_and_prune(admin, node_ctx, role_client):
    assert role_client("viewer").get(A).status_code == 403
    assert generate(admin).status_code == 200
    operator = age.recipient_of(age.generate_identity())
    r = admin.post(f"{A}/identity", json={"op": "add_recipient", "recipient": operator, "label": "safe"})
    assert r.status_code == 200 and [x["kind"] for x in r.get_json()["recipients"]] == ["cluster", "operator"]
    r = admin.post(f"{A}/identity", json={"op": "add_recipient", "recipient": "age1nope"})
    assert r.status_code == 400
    old = keys.recipients(node_ctx.settings())[0]["recipient"]
    r = generate(admin, op="rotate")
    assert r.status_code == 200 and r.get_json()["identity_state"]["retired"] == [old]
    meta = write_archive(node_ctx)
    assert meta.recipients and old not in meta.recipients
    r = admin.post(f"{A}/identity", json={"op": "prune_retired"})
    assert r.status_code == 200, r.get_json()
    assert r.get_json()["dropped"] == [old] and r.get_json()["identity_state"]["retired"] == []
    r = admin.post(f"{A}/identity", json={"op": "remove_recipient", "recipient": operator})
    assert r.status_code == 200 and len(r.get_json()["recipients"]) == 1
    assert admin.post(f"{A}/identity", json={"op": "nope"}).status_code == 400


def test_prune_keeps_while_an_archive_has_no_recorded_recipients(admin, node_ctx):
    assert generate(admin).status_code == 200
    meta = write_archive(node_ctx)
    store = ArchiveStore(node_ctx.paths.archives_dir)
    meta.recipients = None
    store.save_meta(meta)
    assert generate(admin, op="rotate").status_code == 200
    body = admin.post(f"{A}/identity", json={"op": "prune_retired"}).get_json()
    assert body["dropped"] == [] and "without recorded recipients" in body["kept_because"]


def test_destinations_secret_write_only(admin, node_ctx):
    r = admin.post(f"{A}/destinations", json={**SFTP, "secrets": {}})
    assert r.status_code == 400 and r.get_json()["errors"][0]["field"] == "secrets.ssh_key"
    r = admin.post(
        f"{A}/destinations", json={**SFTP, "params": {**SFTP["params"], "host_key_fingerprint": "x"}}
    )
    assert r.status_code == 400 and r.get_json()["errors"][0]["field"] == "params.host_key_fingerprint"
    r = admin.post(f"{A}/destinations", json=SFTP)
    assert r.status_code == 201, r.get_json()
    dest = r.get_json()
    assert dest["secrets"] == {"ssh_key": True} and dest["error"] is None
    assert node_ctx.get_secret(f"archives/dest/{dest['id']}/ssh_key") == KEY
    assert "OPENSSH" not in json.dumps(admin.get(A).get_json())
    stored = node_ctx.settings()["archives"]["destinations"][0]
    assert "secrets" not in stored and "keep" not in stored
    moved = {"params": {**SFTP["params"], "host": "other.example.lan"}}
    r = admin.put(f"{A}/destinations/{dest['id']}", json=moved)
    assert r.status_code == 400 and r.get_json()["errors"][0]["field"] == "secrets.ssh_key"
    r = admin.put(f"{A}/destinations/{dest['id']}", json={"keep": {"daily": 3, "weekly": 0, "monthly": 1}})
    assert r.status_code == 200 and r.get_json()["keep"] == {"daily": 3, "weekly": 0, "monthly": 1}
    assert admin.put(f"{A}/destinations/{dest['id']}", json={"type": "peer"}).status_code == 400
    r = admin.post(f"{A}/destinations", json={"type": "peer", "name": "Pair", "params": {"node_ids": ["zz"]}})
    assert r.status_code == 400 and "unknown node" in r.get_json()["errors"][0]["message"]
    assert admin.delete(f"{A}/destinations/{dest['id']}").status_code == 204
    assert f"archives/dest/{dest['id']}/ssh_key" not in node_ctx.cluster().secrets
    assert admin.delete(f"{A}/destinations/{dest['id']}").status_code == 404
    actions = [e.action for e in node_ctx.audit_log.read() if e.action.startswith("admin.archive.")]
    assert actions == ["admin.archive.add", "admin.archive.replace", "admin.archive.delete"]
    assert KEY not in json.dumps([e.to_dict() for e in node_ctx.audit_log.read()])


def test_destination_test_uses_given_or_stored_key(admin, services, tmp_path):
    seen = []

    class Target:
        label = "t"

        def __init__(self, config, ctx):
            self.config, self.ctx = config, ctx

        def probe(self):
            seen.append(self.ctx.get_secret(f"archives/dest/{self.config.id}/ssh_key"))
            if self.config.params.get("host") == "down.example.lan":
                raise DestinationError("connection refused")

        def close(self):
            pass

    services.archives.targets = lambda config, ctx, spool: [Target(config, ctx)]
    dest = admin.post(f"{A}/destinations", json=SFTP).get_json()
    r = admin.post(f"{A}/destinations/test", json={"destination_id": dest["id"]})
    assert r.status_code == 200 and r.get_json()["ok"] and seen[-1] == KEY
    unsaved = {k: v for k, v in SFTP.items() if k != "secrets"}
    r = admin.post(f"{A}/destinations/test", json={**unsaved, "scope": dest["id"]})
    assert r.get_json()["ok"] and seen[-1] == KEY
    down = {**unsaved, "params": {**SFTP["params"], "host": "down.example.lan"}, "scope": dest["id"]}
    r = admin.post(f"{A}/destinations/test", json=down)
    body = r.get_json()
    assert body["ok"] is False and body["error"] == "connection refused" and seen[-1] == ""
    folder = tmp_path / "share"
    folder.mkdir()
    services.archives.targets = __import__(
        "pelagos.archives.destinations.factory", fromlist=["build_targets"]
    ).build_targets
    r = admin.post(
        f"{A}/destinations/test", json={"type": "mounted", "name": "nas", "params": {"path": str(folder)}}
    )
    assert r.get_json()["ok"] is False and "mount point" in r.get_json()["error"]


def test_peer_destination_test_writes_a_probe(admin, services, node_ctx):
    peer = Peer(id="n2", name="ns2", url="https://192.0.2.2:8444", cert_fingerprint="sha256:00")
    node_ctx.config_store.update_cluster(lambda c: c.nodes.append(peer), updated_by="t")
    listed = []
    client = SimpleNamespace(list_archives=lambda origin=None: listed.append(origin) or {"items": []})
    services.peers.client = lambda p: client
    services.peers.action = lambda p, name, body, timeout=None: {"ok": True, "free_bytes": 10, "fits": False}
    r = admin.post(f"{A}/destinations/test", json={"type": "peer", "name": "pair", "params": {}})
    body = r.get_json()
    assert listed == [node_ctx.node.id] and body["ok"] is False and "free space" in body["error"]

    def unsupported(p, name, body, timeout=None):
        raise ServiceError("not_supported", "upgrade")

    services.peers.action = unsupported
    body = admin.post(
        f"{A}/destinations/test", json={"type": "peer", "name": "pair", "params": {}}
    ).get_json()
    assert body["ok"] and "listed only" in body["targets"][0]["note"]


def test_run_waits_for_the_collector(admin, services, node_ctx):
    assert admin.post(f"{A}/run", json={}).status_code == 409
    assert generate(admin).status_code == 200
    assert admin.post(f"{A}/run", json={"node_ids": ["zz"]}).status_code == 400
    svc = services.archives
    svc.poll_seconds = 0.01
    store = ArchiveStore(node_ctx.paths.archives_dir)

    def signal(sock, event):
        assert event == "archive"
        meta = write_archive(node_ctx, created_at=utcnow() + timedelta(seconds=1))
        state = store.load_state()
        state.last_attempt = state.last_success = meta.created_at
        state.last_archive_id, state.complete = meta.id, True
        store.save_state(state)
        return True

    svc.signal = signal
    r = admin.post(f"{A}/run", json={})
    assert r.status_code == 202
    job = wait_job(admin, r.get_json())
    assert job["state"] == "done", job
    step = next(s for s in job["steps"] if s["name"].startswith("archive:"))
    assert step["node_id"] == node_ctx.node.id and step["output"]["complete"] is True
    svc.signal = lambda sock, event: False
    job = wait_job(admin, admin.post(f"{A}/run", json={}).get_json())
    assert job["state"] == "failed" and "not running" in json.dumps(job["steps"])


def test_list_merges_holders_download_and_upload(admin, services, node_ctx, tmp_path):
    assert generate(admin).status_code == 200
    own = write_archive(node_ctx)
    peer = Peer(id="n2", name="ns2", url="https://192.0.2.2:8444", cert_fingerprint="sha256:00")
    node_ctx.config_store.update_cluster(lambda c: c.nodes.append(peer), updated_by="t")
    lost = write_archive(node_ctx, directory=tmp_path / "elsewhere", node_id="n3", name="old3")
    data = (tmp_path / "elsewhere" / lost.filename).read_bytes()
    copy_of_own = {**own.to_dict(), "destinations": ["local"]}

    class Client:
        def list_archives(self, origin=None):
            return {"items": [copy_of_own, lost.to_dict()]}

        def fetch_archive(self, archive_id, sink):
            sink.write(data)

    services.peers.client = lambda p: Client()
    body = admin.get(f"{A}/list").get_json()
    assert body["total"] == 2 and body["meta"]["unreachable"] == []
    row = next(x for x in body["items"] if x["id"] == own.id)
    assert row["held_by"] == [node_ctx.node.id, "n2"] and row["node_name"] == "ns1"
    assert admin.get(f"{A}/list?node_id=n3").get_json()["total"] == 1
    assert admin.get(f"{A}/list?destination_id=local").get_json()["total"] == 2
    r = admin.get(f"{A}/{own.id}/download")
    assert r.status_code == 200 and r.headers["X-Pelagos-Sha256"] == own.sha256
    assert own.filename in r.headers["Content-Disposition"] and len(r.data) == own.size
    r = admin.get(f"{A}/{lost.id}/download")
    assert r.status_code == 200 and r.data == data
    assert not list((node_ctx.paths.archives_dir / ".restore").iterdir())
    assert admin.get(f"{A}/nope/download").status_code == 404
    r = admin.post(
        f"{A}/upload",
        data={"file": (io.BytesIO(data), lost.filename)},
        content_type="multipart/form-data",
    )
    assert r.status_code == 201, r.get_json()
    assert r.get_json()["node_id"] == "n3" and r.get_json()["destinations"] == ["upload"]
    r = admin.post(
        f"{A}/upload", data={"file": (io.BytesIO(data), lost.filename)}, content_type="multipart/form-data"
    )
    assert r.status_code == 409
    r = admin.post(
        f"{A}/upload", data={"file": (io.BytesIO(b"junk"), "x.age")}, content_type="multipart/form-data"
    )
    assert r.status_code == 400
    ops = [e.request.get("op") for e in node_ctx.audit_log.read() if e.action == "admin.archive.op"]
    assert ops.count("download") == 2 and ops.count("upload") == 1


def test_overview_reports_peer_state_and_destination_failures(admin, services, node_ctx):
    peer = Peer(id="n2", name="ns2", url="https://192.0.2.2:8444", cert_fingerprint="sha256:00")
    node_ctx.config_store.update_cluster(lambda c: c.nodes.append(peer), updated_by="t")
    dest = admin.post(f"{A}/destinations", json={"type": "peer", "name": "pair", "params": {}}).get_json()
    state = {"failures": {dest["id"]: 2}, "errors": {dest["id"]: "refused"}, "last_error": None}

    def action(p, name, body, timeout=None):
        assert name == "archive.state"
        return {"node_id": "n2", "state": state, "last_archive": None, "count": 0}

    services.peers.action = action
    body = admin.get(A).get_json()
    n2 = next(n for n in body["nodes"] if n["node_id"] == "n2")
    assert n2["reachable"] and n2["name"] == "ns2" and n2["failures"] == {dest["id"]: 2}
    assert body["destinations"][0]["status"] == [{"node_id": "n2", "failures": 2, "error": "refused"}]

    def offline(p, name, body, timeout=None):
        raise ServiceError("engine_unavailable", "node ns2 is offline")

    services.peers.action = offline
    n2 = next(n for n in admin.get(A).get_json()["nodes"] if n["node_id"] == "n2")
    assert n2["reachable"] is False and "offline" in n2["error"]


def test_peer_action_helpers(node_ctx):
    assert node_state(node_ctx)["last_archive"] is None
    probe = probe_local(node_ctx)
    assert probe["ok"] and probe["max_bytes"] == 512 * 1024 * 1024
    assert not [p for p in (node_ctx.paths.archives_dir / ".incoming").iterdir() if "probe" in p.name]
