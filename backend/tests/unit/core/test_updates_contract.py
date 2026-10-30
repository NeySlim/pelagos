# SPDX-License-Identifier: Apache-2.0
"""Contract C3 of the updates from the UI (section 29): release files, signature format, rollout
records in cluster.toml, settings, permission and scope, helper operations, `/repl/v1/releases`."""

from __future__ import annotations

import base64
import hashlib
import io
import json
from collections.abc import Iterator
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from pelagos.auth.rbac import PERMISSIONS
from pelagos.core import settings_registry as reg
from pelagos.core.replication import ReplicationError
from pelagos.domain import PlanScope
from pelagos.domain.alerts import EXCEPTABLE_KINDS, AlertKind
from pelagos.domain.plan import SCOPE_PERMISSIONS
from pelagos.domain.updates import (
    HELPER_OPERATIONS,
    ReleaseManifest,
    ReleasePackage,
    ReleaseSignature,
    Rollout,
    RolloutNode,
    SignatureState,
    key_id,
    parse_checksums,
    safe_file,
    valid_version,
)
from pelagos.installer import helper
from tests.unit.core.test_replication import Cluster, LiveNode

pytestmark = pytest.mark.unit


def test_checksums_parse_sha256sum_output_and_refuse_anything_else() -> None:
    a, b = "a" * 64, "b" * 64
    text = f"{a}  pelagos_0.3.0-1_amd64.deb\n{b} *release.json\n\n"
    assert parse_checksums(text) == {"pelagos_0.3.0-1_amd64.deb": a, "release.json": b}
    for bad in (
        "",
        f"{a}  ../etc/passwd\n",
        f"{a[:-1]}  x.deb\n",
        f"{a}  x.deb\n{b}  x.deb\n",
        f"{a}\tx.deb\n",
    ):
        with pytest.raises(ValueError):
            parse_checksums(bad)


def test_signature_format_verifies_with_cryptography_and_refuses_malformed_files() -> None:
    private = Ed25519PrivateKey.generate()
    raw = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    sums = b"0" * 64 + b"  pelagos_0.3.0-1_amd64.deb\n"
    text = ReleaseSignature(key_id(raw), private.sign(sums)).to_text()
    sig = ReleaseSignature.from_text(text)
    assert sig.key_id == hashlib.sha256(raw).hexdigest()[:16]
    Ed25519PublicKey.from_public_bytes(raw).verify(sig.signature, sums)
    with pytest.raises(InvalidSignature):
        Ed25519PublicKey.from_public_bytes(raw).verify(sig.signature, sums + b"x")
    body = json.loads(text)
    for change in (
        {"format": "other"},
        {"algorithm": "rsa"},
        {"key_id": "XYZ"},
        {"signature": "not base64!"},
        {"signature": base64.b64encode(b"short").decode()},
    ):
        with pytest.raises(ValueError):
            ReleaseSignature.from_text(json.dumps({**body, **change}))
    with pytest.raises(ValueError):
        ReleaseSignature.from_text("garbage")
    with pytest.raises(ValueError):
        key_id(b"short")


def test_signature_states_split_refused_from_accepted_with_confirmation() -> None:
    assert SignatureState.UNSIGNED.needs_acceptance and SignatureState.UNKNOWN_KEY.needs_acceptance
    assert not SignatureState.VALID.needs_acceptance and not SignatureState.INVALID.needs_acceptance


def test_manifest_problems() -> None:
    good = ReleaseManifest(
        version="0.3.0",
        state_schema=1,
        packages=[
            ReleasePackage("pelagos_0.3.0-1_amd64.deb", "deb", "amd64", "0.3.0-1"),
            ReleasePackage("pelagos_0.3.0-1_arm64.deb", "deb", "arm64", "0.3.0-1"),
        ],
    )
    assert good.problems() == []
    assert ReleaseManifest.from_dict(json.loads(json.dumps(good.to_dict()))) == good
    assert good.package_for("deb", "arm64").file == "pelagos_0.3.0-1_arm64.deb"
    assert good.package_for("rpm", "x86_64") is None
    bad = ReleaseManifest(version="0.3", state_schema=0, name="other", packages=[good.packages[0]] * 2)
    assert len(bad.problems()) == 4
    assert valid_version("0.3.0") and valid_version("0.3.0~rc1") and not valid_version("0.3")
    assert safe_file("SHA256SUMS.sig") and not safe_file("../x") and not safe_file(".hidden")


def test_rollout_round_trips_through_toml_without_null_and_lists_nodes_in_order() -> None:
    r = Rollout(
        id="01JB0ZK4Q9X3M5N7P8R2T4V6W8",
        kind="pelagos",
        version="0.3.0",
        order=["n2", "n1"],
        nodes={"n1": RolloutNode("n1"), "n2": RolloutNode("n2", state="done", from_version="0.2.5")},
        created_by="admin",
    )
    toml = r.to_toml()
    assert "step" not in toml["nodes"]["n1"] and "unsigned_accepted_by" not in toml
    # cluster.toml keys the node rows by node id; the row itself may lack node_id.
    toml["nodes"]["n1"].pop("node_id")
    back = Rollout.from_toml(toml)
    assert back == r and back.active()
    assert [n["node_id"] for n in r.to_api()["nodes"]] == ["n2", "n1"]
    assert Rollout.from_toml({"kind": "pelagos"}) is None


def test_permission_scope_alerts_and_helper_operations() -> None:
    assert "admin:updates" in PERMISSIONS
    assert SCOPE_PERMISSIONS[PlanScope.UPDATE] == "admin:updates"
    assert {AlertKind("update_available"), AlertKind("update_failed"), AlertKind("update_stalled")}
    assert AlertKind.UPDATE_AVAILABLE in EXCEPTABLE_KINDS and AlertKind.UPDATE_FAILED not in EXCEPTABLE_KINDS
    assert set(HELPER_OPERATIONS) <= set(helper.OPERATIONS)
    with pytest.raises(helper.HelperError, match="batch U2"):
        helper.handle({"op": "update_verify"}, lambda: None, lambda _: None)


def test_updates_settings_domain() -> None:
    assert "updates" in reg.DOMAINS
    assert reg.get({}, "updates.source") == "upload"
    assert reg.get({}, "updates.pause_seconds") == 60
    assert reg.get({}, "updates.auto_rollback_enabled") is True
    body = {"updates": {"source": "ftp", "rollout": {}, "github_repository": "a/b"}}
    fields = dict(reg.validate(body, reg.defaults()))
    assert fields["updates.source"] == "invalid name"
    assert fields["updates.rollout"] == fields["updates.github_repository"] == "set through its own screen"


class Store:
    def __init__(self, folder: Path) -> None:
        self.folder = folder

    def listing(self, version: str):
        if version != "0.3.0":
            return None
        return {
            "version": version,
            "files": [{"name": "SHA256SUMS", "size": 3, "sha256": "x"}],
            "signature": "valid",
        }

    def path(self, version: str, name: str):
        p = self.folder / name
        return p if version == "0.3.0" and p.exists() else None


@pytest.fixture
def pair(tmp_root: Path) -> Iterator[tuple[LiveNode, LiveNode]]:
    c = Cluster(tmp_root)
    try:
        a = c.first()
        yield a, c.enroll(a)
    finally:
        c.stop_all()


def test_peer_serves_release_files_only_when_it_holds_them(pair, tmp_root) -> None:
    a, b = pair
    peer = a.service.replicator.client(a.ctx.cluster().peer(b.id))
    with pytest.raises(ReplicationError):
        peer.release_listing("0.3.0")
    folder = tmp_root / "rel"
    folder.mkdir()
    (folder / "SHA256SUMS").write_bytes(b"abc")
    b.service.app.releases = Store(folder)
    assert peer.release_listing("0.3.0")["signature"] == "valid"
    sink = io.BytesIO()
    peer.fetch_release_file("0.3.0", "SHA256SUMS", sink)
    assert sink.getvalue() == b"abc"
    for version, name in (("0.2.0", "SHA256SUMS"), ("0.3.0", "missing.deb"), ("0.3.0", "..x")):
        with pytest.raises(ReplicationError):
            peer.fetch_release_file(version, name, io.BytesIO())
