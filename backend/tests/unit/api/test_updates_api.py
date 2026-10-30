# SPDX-License-Identifier: Apache-2.0
"""/admin/updates* (section 29): overview, upload, settings, check, plan and apply, rollout actions."""

from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path

import pytest

from pelagos.core import update_rollout as ur
from pelagos.domain.common import utcnow
from pelagos.services.errors import ServiceError

pytestmark = pytest.mark.unit

V1 = "/api/v1"
NEW = "0.9.0"
OLD = "0.2.6.dev0"


@pytest.fixture
def admin(login):
    from tests.conftest import ADMIN_PASSWORD

    return login("admin", ADMIN_PASSWORD)


def _sums(files: dict[str, bytes]) -> bytes:
    return "".join(f"{hashlib.sha256(b).hexdigest()}  {n}\n" for n, b in sorted(files.items())).encode()


def _release_files(version: str = NEW) -> dict[str, bytes]:
    deb = f"pelagos_{version}-1_amd64.deb"
    manifest = {
        "format": 1,
        "name": "pelagos",
        "version": version,
        "state_schema": 1,
        "published_at": "2026-10-30T08:00:00Z",
        "notes": "NOTES.md",
        "packages": [{"file": deb, "format": "deb", "arch": "amd64", "version": f"{version}-1"}],
    }
    files = {deb: b"deb bytes", "release.json": json.dumps(manifest).encode(), "NOTES.md": b"# Notes\n"}
    files["SHA256SUMS"] = _sums(files)
    return files


def _hold(services, version: str = NEW) -> Path:
    """A release the helper verified: packages/<version>/ on this node."""
    folder = Path(services.ctx.paths.upgrade_dir) / "packages" / version
    folder.mkdir(parents=True)
    for name, data in _release_files(version).items():
        (folder / name).write_bytes(data)
    return folder


class FakeHelper:
    def __init__(self, error: str | None = None, signature: str = "unsigned") -> None:
        self.error = error
        self.signature = signature
        self.calls: list[tuple[str, bool]] = []

    def update_verify(self, version: str, allow_unsigned: bool = False) -> dict:
        self.calls.append((version, allow_unsigned))
        if self.error:
            raise (
                ServiceError("validation_error", "unused")
                if self.error == "service"
                else _HelperError(self.error)
            )
        return {
            "version": version,
            "signature": self.signature,
            "key_id": None,
            "state_schema": 1,
            "sha256": "x",
        }


class _HelperError(Exception):
    kind = "value"


def test_overview_lists_nodes_releases_engines_and_settings(admin, services):
    _hold(services)
    services.updates.engine_reader = lambda ctx: [
        {"engine": "bind", "package": "bind9", "installed": "1:9.20.11-4", "candidate": "1:9.20.15-1"}
    ]
    body = admin.get(f"{V1}/admin/updates").get_json()
    node = body["nodes"][0]
    assert node["node_id"] == services.ctx.node.id and node["version"] == OLD
    assert (node["arch"], node["package_format"], node["previous_kept"], node["reachable"]) == (
        "amd64",
        "deb",
        None,
        True,
    )
    assert "engines" not in node
    release = body["available"][0]
    assert release["version"] == NEW and release["signature"] == "unsigned" and release["signed"] is False
    assert release["notes"] == "# Notes\n" and release["state_schema"] == 1
    assert body["engines"] == [
        {
            "node_id": services.ctx.node.id,
            "engine": "bind",
            "package": "bind9",
            "installed": "1:9.20.11-4",
            "candidate": "1:9.20.15-1",
            "cves": [],
        }
    ]
    assert body["rollout"] is None and body["docker"] is None
    assert body["settings"]["source"] == "upload" and body["settings"]["github_token_stored"] is False
    assert admin.get(f"{V1}/admin/updates/rollout").get_json() is None


def _upload(client, files: dict[str, bytes]):
    data = {"files": [(io.BytesIO(b), n) for n, b in files.items()]}
    return client.post(f"{V1}/admin/updates/upload", data=data, content_type="multipart/form-data")


def test_upload_stages_the_files_and_asks_the_helper(admin, services, node_ctx):
    helper = FakeHelper()
    services.updates.helper = lambda: helper
    resp = _upload(admin, _release_files())
    assert resp.status_code == 201, resp.get_json()
    out = resp.get_json()
    assert out["version"] == NEW and out["signature"] == "unsigned" and out["signed"] is False
    assert helper.calls == [(NEW, True)]
    assert (Path(node_ctx.paths.upgrade_incoming) / NEW / "SHA256SUMS").is_file()
    assert node_ctx.audit_log.query(action="admin.update.upload")[0][0].result.value == "ok"


def test_upload_refusals(admin, services):
    services.updates.helper = lambda: FakeHelper("signature_invalid: SHA256SUMS.sig does not verify")
    resp = _upload(admin, _release_files())
    assert resp.status_code == 422 and resp.get_json()["reason"] == "signature_invalid"
    files = _release_files()
    files.pop("SHA256SUMS")
    resp = _upload(admin, files)
    assert resp.status_code == 422 and resp.get_json()["reason"] == "missing"
    files = _release_files()
    files["extra.txt"] = b"x"
    assert _upload(admin, files).get_json()["reason"] == "unlisted"
    assert admin.post(f"{V1}/admin/updates/upload", json={}).status_code == 400


def test_settings_validate_and_store_the_token(admin, services, node_ctx):
    url = f"{V1}/admin/updates/settings"
    resp = admin.put(url, json={"source": "github"})
    assert resp.status_code == 400 and resp.get_json()["errors"][0]["field"] == "github_repository"
    assert admin.put(url, json={"pause_seconds": -1}).status_code == 400
    assert admin.put(url, json={"rollout": {}}).status_code == 400
    assert admin.put(url, json={"github_repository": "not a repo"}).status_code == 400
    resp = admin.put(
        url,
        json={
            "source": "github",
            "github_repository": "example/pelagos",
            "github_token": "tok",
            "pause_seconds": 5,
        },
    )
    assert resp.status_code == 200, resp.get_json()
    settings = resp.get_json()["settings"]
    assert settings["github_repository"] == "example/pelagos" and settings["github_token_stored"] is True
    assert settings["pause_seconds"] == 5
    assert node_ctx.get_secret("updates/github_token") == "tok"
    entry = node_ctx.audit_log.query(action="admin.update.settings")[0][0]
    assert entry.request["github_token"] == "set"
    resp = admin.put(url, json={"github_token": None})
    assert resp.get_json()["settings"]["github_token_stored"] is False


def test_check_reads_github(admin, services, node_ctx):
    assert admin.post(f"{V1}/admin/updates/check", json={}).get_json()["error"] is None
    admin.put(
        f"{V1}/admin/updates/settings", json={"source": "github", "github_repository": "example/pelagos"}
    )

    class Source:
        def __init__(self, repo, token):
            assert (repo, token) == ("example/pelagos", None)

        def check(self):
            return {
                "version": NEW,
                "source": "github",
                "signature": "valid",
                "signed": True,
                "key_id": "a" * 16,
            }

    services.updates.github = Source
    out = admin.post(f"{V1}/admin/updates/check", json={}).get_json()
    assert out["error"] is None and out["available"][0]["version"] == NEW and out["available"][0]["signed"]
    assert admin.get(f"{V1}/admin/updates").get_json()["available"][0]["source"] == "github"
    admin.put(f"{V1}/admin/updates/settings", json={"github_repository": "", "source": "upload"})
    assert node_ctx.audit_log.query(action="admin.update.check")[0]


def _plan(client, **body):
    return client.post(f"{V1}/admin/updates/plan", json={"kind": "pelagos", **body})


def test_unsigned_release_plan_apply_and_audit(admin, services, node_ctx):
    from tests.conftest import ADMIN_PASSWORD

    _hold(services)
    resp = _plan(admin, version=NEW)
    assert resp.status_code == 400
    assert resp.get_json()["errors"][0] == {
        "field": "accept_unsigned",
        "message": "update.refused.unsigned_not_accepted",
    }
    assert _plan(admin, version=NEW, accept_unsigned=True, confirm_version="0.9").status_code == 400
    assert _plan(admin, version="0.1.0").status_code == 400
    assert (
        _plan(admin, version=NEW, order=["nobody"], accept_unsigned=True, confirm_version=NEW).status_code
        == 400
    )
    resp = _plan(admin, version=NEW, accept_unsigned=True, confirm_version=NEW)
    assert resp.status_code == 200, resp.get_json()
    plan = resp.get_json()
    me = services.ctx.node.id
    assert plan["scope"] == "update" and plan["requires_confirmation"] is True
    update = plan["update"]
    assert update["order"] == [me] and update["signature"] == "unsigned"
    assert update["unsigned_warning"] == {"key": "plan.update.unsigned", "params": {"version": NEW}}
    assert update["state_schema_changed"] is False and update["auto_rollback"] is True
    assert update["artifacts"]["deb/amd64"]["file"] == f"pelagos_{NEW}-1_amd64.deb"
    assert plan["changes"][0]["target"] == f"node/{me}/pelagos"

    apply = f"{V1}/plans/{plan['id']}/apply"
    resp = admin.post(apply, json={"confirm": True})
    assert resp.status_code == 400 and resp.get_json()["errors"][0]["field"] == "password"
    assert admin.post(apply, json={"confirm": True, "password": "wrong"}).status_code == 401
    resp = admin.post(apply, json={"confirm": True, "password": ADMIN_PASSWORD})
    assert resp.status_code == 200 and resp.get_json()["state"] == "applied", resp.get_json()

    rollout = ur.load(node_ctx.settings())
    assert (
        rollout.version == NEW and rollout.plan_id == plan["id"] and rollout.unsigned_accepted_by == "admin"
    )
    assert rollout.artifacts == update["artifacts"] and rollout.nodes[me].from_version == OLD
    accepted = node_ctx.audit_log.query(action="update.unsigned_accepted")[0][0]
    assert accepted.user == "admin" and accepted.request["version"] == NEW
    assert accepted.request["checksums_sha256"] == update["checksums_sha256"]
    assert node_ctx.audit_log.query(action="update.apply")[0]
    wire = admin.get(f"{V1}/admin/updates/rollout").get_json()
    assert wire["id"] == rollout.id and wire["nodes"][0]["node_id"] == me

    resp = _plan(admin, version=NEW, accept_unsigned=True, confirm_version=NEW)
    assert resp.status_code == 409


def test_signed_release_needs_no_acceptance(admin, services, node_ctx):
    var = Path(node_ctx.paths.var) / "upgrade"
    var.mkdir(parents=True, exist_ok=True)
    entry = {"version": NEW, "source": "github", "signature": "valid", "signed": True, "key_id": "a" * 16}
    (var / "available.json").write_text(json.dumps({"available": [entry], "checked_at": None, "error": None}))
    resp = _plan(admin, version=NEW, auto_rollback=True)
    assert resp.status_code == 200, resp.get_json()
    update = resp.get_json()["update"]
    # No release.json read here: the state schema is unknown, so no automatic rollback.
    assert update["unsigned_warning"] is None and update["state_schema_changed"] is True
    assert update["auto_rollback"] is False and update["source"] == "github"
    entry["signature"] = "invalid"
    (var / "available.json").write_text(json.dumps({"available": [entry], "checked_at": None, "error": None}))
    resp = _plan(admin, version=NEW)
    assert resp.status_code == 422 and resp.get_json()["reason"] == "signature_invalid"


def _write_rollout(node_ctx, rollout) -> None:
    node_ctx.config_store.update_cluster(lambda c: ur.write(c, rollout), updated_by="test")


def test_actions_cancel_resume_and_history(admin, services, node_ctx):
    me = services.ctx.node.id
    r = ur.new_rollout(
        "pelagos", [me], created_by="admin", now=utcnow(), version=NEW, from_versions={me: OLD}
    )
    _write_rollout(node_ctx, r)
    url = f"{V1}/admin/updates/rollout/{r.id}/action"
    assert (
        admin.post(f"{V1}/admin/updates/rollout/OTHER/action", json={"action": "cancel"}).status_code == 404
    )
    assert admin.post(url, json={"action": "resume"}).status_code == 409
    assert admin.post(url, json={"action": "bogus"}).status_code == 400
    assert admin.post(url, json={"action": "rollback"}).status_code == 400
    resp = admin.post(url, json={"action": "cancel"})
    assert resp.status_code == 200 and resp.get_json()["state"] == "cancelled"
    assert ur.load(node_ctx.settings()) is None
    page = admin.get(f"{V1}/admin/updates/history?page=1&per_page=5").get_json()
    assert page["total"] == 1 and page["items"][0]["id"] == r.id and page["items"][0]["state"] == "cancelled"
    assert node_ctx.audit_log.query(action="admin.update.cancel")[0]


def test_rollback_action_goes_back_over_the_done_nodes(admin, services, node_ctx):
    from tests.conftest import ADMIN_PASSWORD

    me = services.ctx.node.id
    r = ur.new_rollout(
        "pelagos", [me], created_by="admin", now=utcnow(), version=NEW, from_versions={me: OLD}
    )
    r.nodes[me].state = "done"
    r.state = "failed"
    _write_rollout(node_ctx, r)
    url = f"{V1}/admin/updates/rollout/{r.id}/action"
    assert admin.post(url, json={"action": "rollback", "password": "nope"}).status_code == 401
    resp = admin.post(url, json={"action": "rollback", "password": ADMIN_PASSWORD})
    assert resp.status_code == 200, resp.get_json()
    back = resp.get_json()
    assert back["kind"] == "rollback" and back["version"] == OLD and back["id"] != r.id
    assert ur.load(node_ctx.settings()).id == back["id"]
    assert ur.history(node_ctx.settings())[0]["id"] == r.id


def test_engine_packages_plan(admin, services):
    services.updates.engine_reader = lambda ctx: [
        {"engine": "bind", "package": "bind9", "installed": "1:9.20.11-4", "candidate": "1:9.20.15-1"},
        {"engine": "kea4", "package": "kea-dhcp4-server", "installed": "2.6.3-1", "candidate": None},
    ]
    me = services.ctx.node.id
    body = {"kind": "engine_packages", "packages": ["bind9"], "node_ids": [me]}
    resp = admin.post(f"{V1}/admin/updates/plan", json=body)
    assert resp.status_code == 200, resp.get_json()
    update = resp.get_json()["update"]
    assert update["packages"] == {"bind9": "1:9.20.15-1"} and update["order"] == [me]
    assert update["checks"][-2:] == ["engine_checks", "ha"]
    body["packages"] = ["kea-dhcp4-server"]
    assert admin.post(f"{V1}/admin/updates/plan", json=body).status_code == 400
    body["node_ids"] = ["nobody"]
    assert admin.post(f"{V1}/admin/updates/plan", json=body).status_code == 400


def test_plan_rollback_removes_a_rollout_not_started(admin, services, node_ctx):
    from tests.conftest import ADMIN_PASSWORD

    _hold(services)
    plan = _plan(admin, version=NEW, accept_unsigned=True, confirm_version=NEW).get_json()
    admin.post(f"{V1}/plans/{plan['id']}/apply", json={"confirm": True, "password": ADMIN_PASSWORD})
    assert ur.load(node_ctx.settings()) is not None
    resp = admin.post(f"{V1}/plans/{plan['id']}/rollback")
    assert resp.status_code == 200, resp.get_json()
    assert ur.load(node_ctx.settings()) is None


def test_peer_action_answers_the_node_row(services):
    from pelagos.services.peer_actions import UPDATES_NODE, PeerActions

    actions = PeerActions(services.ctx, services.registry)
    actions._updates = services.updates
    row = actions(UPDATES_NODE, {}, "other")
    assert row["node_id"] == services.ctx.node.id and row["version"] == OLD and row["engines"] == []
