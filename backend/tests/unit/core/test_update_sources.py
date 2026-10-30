# SPDX-License-Identifier: Apache-2.0
"""Rollout records and release sources of section 29: turns, order, actions, upload, peers, GitHub."""

from __future__ import annotations

import hashlib
import io
import json
import threading
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pelagos.core import release as rel
from pelagos.core import update_rollout as ur
from pelagos.core import update_sources as src
from pelagos.domain.common import to_rfc3339

pytestmark = pytest.mark.unit

NOW = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)


def _sums(files: dict[str, bytes]) -> bytes:
    return "".join(f"{hashlib.sha256(d).hexdigest()}  {n}\n" for n, d in sorted(files.items())).encode()


def _release(version: str = "0.3.1") -> dict[str, bytes]:
    files = {
        f"pelagos_{version}-1_amd64.deb": b"amd64",
        f"pelagos_{version}-1_arm64.deb": b"arm64",
        "release.json": json.dumps({"version": version}).encode(),
        "NOTES.md": b"notes",
    }
    files["SHA256SUMS"] = _sums(files)
    return files


# Rollout records -----------------------------------------------------------------------------


def test_default_order_puts_primaries_last() -> None:
    order = ur.default_order(["dns", "ha", "a", "b"], dns_primaries={"dns"}, ha_primaries={"ha", "dns"})
    assert order == ["a", "b", "ha", "dns"]
    assert ur.dns_primaries({"ddns": {"roles": {"v/z": {"primary": "n1"}, "bad": 3}}}) == {"n1"}


def test_turn_opens_after_the_previous_node_and_the_pause() -> None:
    r = ur.new_rollout("pelagos", ["a", "b", "c"], created_by="x", now=NOW, version="0.3.1")
    assert ur.my_turn(r, "a", NOW, 60)
    assert not ur.my_turn(r, "b", NOW + timedelta(hours=1), 60)
    r.nodes["a"].state, r.nodes["a"].finished_at = "done", to_rfc3339(NOW)
    assert not ur.my_turn(r, "b", NOW + timedelta(seconds=59), 60)
    assert ur.my_turn(r, "b", NOW + timedelta(seconds=60), 60)
    r.nodes["b"].state = "skipped"
    assert ur.my_turn(r, "c", NOW + timedelta(seconds=60), 60)
    r.state = "failed"
    assert not ur.my_turn(r, "c", NOW + timedelta(hours=1), 60)


def test_stalled_pending_node_counts_from_its_turn() -> None:
    r = ur.new_rollout("pelagos", ["a", "b"], created_by="x", now=NOW, version="0.3.1")
    r.nodes["a"].state, r.nodes["a"].finished_at = "done", to_rfc3339(NOW)
    assert ur.stalled(r, NOW + timedelta(seconds=659), 300, 60) is None
    assert ur.stalled(r, NOW + timedelta(seconds=660), 300, 60) == {
        "node_id": "b",
        "step": "wait",
        "minutes": 10,
    }


def test_actions_resume_cancel_rollback() -> None:
    r = ur.new_rollout(
        "pelagos",
        ["a", "b", "c"],
        created_by="x",
        now=NOW,
        version="0.3.1",
        from_versions={"a": "0.3.0-1", "b": "0.3.0-1"},
    )
    with pytest.raises(ur.ActionRefused):
        ur.resume(r, NOW)
    r.nodes["a"].state, r.nodes["a"].to_version = "done", "0.3.1-1"
    r.nodes["b"].state, r.nodes["b"].error, r.state = "rolled_back", "health", "failed"
    ur.resume(r, NOW)
    assert (r.state, r.nodes["b"].state, r.nodes["b"].error, r.nodes["b"].from_version) == (
        "running",
        "pending",
        None,
        "0.3.0-1",
    )
    back = ur.rollback_of(r, "0.3.0", "admin", NOW)
    assert (back.kind, back.order, back.version, back.auto_rollback) == ("rollback", ["a"], "0.3.0", False)
    assert back.nodes["a"].from_version == "0.3.1-1"
    ur.cancel(r, NOW)
    assert r.state == "cancelled" and r.nodes["c"].state == "skipped" and r.nodes["a"].state == "done"
    with pytest.raises(ur.ActionRefused):
        ur.cancel(r, NOW)


def test_finished_rollouts_go_to_history_capped(node_ctx) -> None:
    for i in range(ur.HISTORY_KEEP + 2):
        r = ur.new_rollout("pelagos", ["a"], created_by="x", now=NOW + timedelta(minutes=i), version="0.3.1")
        r.state, r.finished_at = "done", to_rfc3339(NOW)
        node_ctx.config_store.update_cluster(lambda c, r=r: ur.write(c, r), updated_by="test")
    past = ur.history(node_ctx.settings())
    assert len(past) == ur.HISTORY_KEEP
    assert past[0]["id"] == r.id and past[0]["nodes"] == [
        {"node_id": "a", "state": "pending", "to_version": "0.3.1"}
    ]
    assert ur.load(node_ctx.settings()) is None


# Upload and peers ------------------------------------------------------------------------------


def test_stage_upload_checks_sums_and_finds_the_version(tmp_path: Path) -> None:
    files = _release()
    out = src.stage_upload(tmp_path, [(n, io.BytesIO(d)) for n, d in files.items()])
    assert out["version"] == "0.3.1"
    assert (tmp_path / "0.3.1" / "NOTES.md").read_bytes() == b"notes"
    bad = dict(files, **{"NOTES.md": b"changed"})
    with pytest.raises(src.SourceError) as exc:
        src.stage_upload(tmp_path, [(n, io.BytesIO(d)) for n, d in bad.items()])
    assert exc.value.reason == "checksum"
    with pytest.raises(src.SourceError) as exc:
        src.stage_upload(
            tmp_path, [*((n, io.BytesIO(d)) for n, d in files.items()), ("extra.txt", io.BytesIO(b""))]
        )
    assert exc.value.reason == "unlisted"
    with pytest.raises(src.SourceError) as exc:
        src.stage_upload(tmp_path, [("../x", io.BytesIO(b""))])
    assert exc.value.reason == "missing"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["0.3.1"]


def test_stage_upload_of_a_release_without_manifest(tmp_path: Path) -> None:
    files = {"pelagos_0.2.5-1_amd64.deb": b"a"}
    files["SHA256SUMS"] = _sums(files)
    assert src.stage_upload(tmp_path, [(n, io.BytesIO(d)) for n, d in files.items()])["version"] == "0.2.5"


def test_held_releases_serve_listed_files_and_signature(tmp_path: Path) -> None:
    files = _release()
    folder = tmp_path / "0.3.1"
    folder.mkdir()
    for n, d in files.items():
        (folder / n).write_bytes(d)
    private = Ed25519PrivateKey.generate()
    sig = rel.sign_checksums(files["SHA256SUMS"], private)
    (folder / "SHA256SUMS.sig").write_text(sig.to_text())
    (folder / "stray").write_bytes(b"x")
    keys = {sig.key_id: private.public_key()}
    store = src.HeldReleases(tmp_path, keys=lambda: keys)
    listing = store.listing("0.3.1")
    assert listing["signature"] == "valid"
    assert [f["name"] for f in listing["files"]][:2] == ["SHA256SUMS", "SHA256SUMS.sig"]
    assert store.path("0.3.1", "NOTES.md") == folder / "NOTES.md"
    assert store.path("0.3.1", "stray") is None and store.listing("0.9.9") is None
    assert src.HeldReleases(tmp_path, keys=dict).listing("0.3.1")["signature"] == "unknown_key"

    class Client:
        def release_listing(self, version):
            return store.listing(version)

        def fetch_release_file(self, version, name, sink):
            sink.write(store.path(version, name).read_bytes())

    incoming = tmp_path / "incoming"
    src.fetch_from_peer(Client(), "0.3.1", incoming)
    assert (incoming / "0.3.1" / "SHA256SUMS.sig").exists()
    (folder / "NOTES.md").write_bytes(b"altered")
    with pytest.raises(src.SourceError):
        src.fetch_from_peer(Client(), "0.3.1", tmp_path / "incoming2")


# GitHub ------------------------------------------------------------------------------------------


class FakeGithub(ThreadingHTTPServer):
    def __init__(self, files: dict[str, bytes]) -> None:
        super().__init__(("127.0.0.1", 0), Handler)
        self.files = files
        self.ids = {name: i + 1 for i, name in enumerate(sorted(files))}
        self.auth: list[tuple[str, str | None]] = []


class Handler(BaseHTTPRequestHandler):
    server: FakeGithub

    def log_message(self, *args) -> None:
        pass

    def _send(self, code: int, body: bytes, headers: dict[str, str] | None = None) -> None:
        self.send_response(code)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        s = self.server
        s.auth.append((self.path, self.headers.get("Authorization")))
        release = {
            "tag_name": "v0.3.1",
            "published_at": "2026-10-30T00:00:00Z",
            "body": "notes",
            "assets": [{"name": n, "id": i} for n, i in s.ids.items()],
        }
        if self.path in ("/repos/o/r/releases/latest", "/repos/o/r/releases/tags/v0.3.1"):
            return self._send(200, json.dumps(release).encode())
        if self.path.startswith("/repos/o/r/releases/assets/"):
            asset = int(self.path.rsplit("/", 1)[1])
            # Storage redirect, as GitHub answers with a 302 to a signed URL.
            return self._send(302, b"", {"Location": f"/storage/{asset}"})
        if self.path.startswith("/storage/"):
            name = next(n for n, i in s.ids.items() if i == int(self.path.rsplit("/", 1)[1]))
            return self._send(200, s.files[name])
        return self._send(404, b"{}")


@pytest.fixture
def github():
    files = _release()
    server = FakeGithub(files)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()


def test_github_latest_check_and_download(github, tmp_path: Path) -> None:
    api = f"http://127.0.0.1:{github.server_address[1]}"
    gh = src.GithubSource("o/r", "tok", api=api)
    available = gh.check(keys={})
    assert (available["version"], available["signature"], available["signed"]) == ("0.3.1", "unsigned", False)
    out = gh.download(gh.release("0.3.1"), tmp_path)
    assert out["version"] == "0.3.1"
    assert (tmp_path / "0.3.1" / "pelagos_0.3.1-1_arm64.deb").read_bytes() == b"arm64"
    assets = [a for p, a in github.auth if "/assets/" in p]
    assert assets and all(a == "Bearer tok" for a in assets)
    with pytest.raises(src.SourceError):
        gh.release("0.9.0")
    with pytest.raises(src.SourceError):
        src.GithubSource("not a repo")


def test_check_github_records_errors_without_raising(tmp_path: Path) -> None:
    def broken(repo, token):
        class S:
            def check(self):
                raise src.SourceError("github", "HTTP 404")

        return S()

    rec = src.check_github(tmp_path, "o/r", None, "2026-10-30T00:00:00Z", factory=broken)
    assert rec["error"] == "github: HTTP 404" and src.read_available(tmp_path)["available"] == []
