# SPDX-License-Identifier: Apache-2.0
"""cluster.toml without any generic collection: same bytes and digest as the release before them."""

from __future__ import annotations

import tomllib

import pytest
import tomli_w

from pelagos.core import cluster_merge as cm
from pelagos.core.config_store import ClusterConfig

pytestmark = pytest.mark.unit

# Written by 661603d4 (0.3.6.dev0); settings left out: their defaults grow with every release.
GOLDEN = """\
schema_version = 1
version = 3
updated_at = "2026-10-24T10:00:00.000Z"
updated_by = "user:admin@node:A"
cluster_id = "01JB0ZK4Q9X3M5N7P8R2T4V6W9"
revoked = [
    "sha256:dead",
]

[[nodes]]
id = "A"
name = "ns1"
url = "https://ns1.example.lan:8444"
cert_fingerprint = "sha256:a"
enrolled_at = "2026-10-24T09:00:00.000Z"

[nodes.modules]
bind = true
kea4 = false
kea6 = false
d2 = false

[[users]]
id = "U1"
username = "admin"
password_hash = "$argon2id$x"
roles = [
    "admin",
]
enabled = true
must_change_password = false
created_at = "2026-10-24T09:00:00.000Z"
updated_at = "2026-10-24T09:00:00.000Z"

[users.preferences]
language = "fr"

[users.webauthn]

[[roles]]
name = "ops"
permissions = [
    "read:dns",
]
builtin = false

[modules]
dhcpv6 = false
advanced_editor = true

[secrets]
"tsig/ddi-admin" = "enc:v1:a"

[replication.stamps]
"modules/advanced_editor" = "1@A"
"modules/dhcpv6" = "1@A"
"nodes/A" = "1@A"
"nodes/A/cert_fingerprint" = "1@A"
"nodes/A/enrolled_at" = "1@A"
"nodes/A/modules/bind" = "2@A"
"nodes/A/modules/d2" = "1@A"
"nodes/A/modules/kea4" = "1@A"
"nodes/A/modules/kea6" = "1@A"
"nodes/A/name" = "1@A"
"nodes/A/url" = "1@A"
"revoked/sha256%3Adead" = "1@A"
"roles/ops" = "1@A"
"roles/ops/builtin" = "1@A"
"roles/ops/permissions" = "1@A"
"secrets/tsig%2Fddi-admin" = "1@A"
"users/U1" = "1@A"
"users/U1/created_at" = "1@A"
"users/U1/enabled" = "1@A"
"users/U1/must_change_password" = "1@A"
"users/U1/password_hash" = "1@A"
"users/U1/preferences/language" = "3@A"
"users/U1/roles" = "1@A"
"users/U1/updated_at" = "1@A"
"users/U1/username" = "1@A"

[replication.tombstones]
"roles/old" = "2@A"
"""
# Digest of GOLDEN without settings entries, computed by 661603d4.
GOLDEN_DIGEST = "sha256:01505b515f02c4a6911ec874b246faa25b48eedf6b27abb52daf4764ee218c18"


def _without_settings(cfg: ClusterConfig) -> tuple[str, str]:
    data = tomllib.loads(cfg.dumps())
    data.pop("settings")
    state = cfg.state()
    kept = cm.State(
        {p: v for p, v in state.values.items() if not p.startswith("settings/")},
        {p: s for p, s in state.stamps.items() if not p.startswith("settings/")},
        dict(state.tombstones),
    )
    return tomli_w.dumps(data), kept.digest()


def test_a_file_without_collections_round_trips_byte_for_byte():
    text, digest = _without_settings(ClusterConfig.from_toml(tomllib.loads(GOLDEN)))
    assert text == GOLDEN
    assert digest == GOLDEN_DIGEST


@pytest.mark.skip(reason="F0-REPL: contract, implemented next")
def test_a_registered_but_unused_collection_changes_neither_bytes_nor_digest():
    """COLLECTIONS with a fake entry and no record: dumps() and digest() equal those of an empty registry."""


@pytest.mark.skip(reason="F0-REPL: contract, implemented next")
def test_bases_never_reach_cluster_toml():
    """A write records bases in cluster.bases.json only: cluster.toml bytes as without bases."""
