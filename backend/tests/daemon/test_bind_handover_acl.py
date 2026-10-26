# SPDX-License-Identifier: Apache-2.0
"""Hand over of ACLs and keys against a real named, used by a zone that stays in the user file."""

from __future__ import annotations

from pathlib import Path

import pytest

from pelagos.domain.plan import Change, ChangeOp, PlanState
from tests.daemon import bind_custom
from tests.daemon.test_bind_backend import make_backend, setup_includes

pytestmark = pytest.mark.daemon


@pytest.fixture
def server(tmp_root: Path):
    root = tmp_root / "hand"
    root.mkdir()
    (root / "named.conf.local").write_text(
        'acl "lan" { 127.0.0.1;   192.0.2.0/24; };\n'
        'key "extra" { algorithm hmac-sha256; secret "c2VjcmV0LWZvci10ZXN0cw=="; };\n'
        f'zone "legacy.example.lan" {{ type primary; file "{root}/zones/legacy.example.lan.db";'
        " allow-transfer { lan; key extra; }; };\n"
    )
    srv = bind_custom.start(
        root,
        f'include "{root}/named.conf.local";\n',
        files={"legacy.example.lan.db": bind_custom.zone_text("legacy.example.lan")},
    )
    try:
        yield srv
    finally:
        srv.stop()


def test_acl_and_key_used_by_a_user_zone(server, tmp_root: Path) -> None:
    backend = make_backend(server, tmp_root)
    setup_includes(backend)
    plan = backend.plan_config_change(
        [Change(ChangeOp.REPLACE, "handover/acls/lan"), Change(ChangeOp.REPLACE, "handover/keys/extra")]
    )
    assert plan.state is PlanState.VALIDATED, plan.validations
    result = backend.apply(plan)
    assert result.ok, result.message
    tree = backend.read_config()
    assert all(e.managed for e in [*tree.acls, *tree.keys] if e.name in ("lan", "extra"))
    assert "type: primary" in server.rndc("zonestatus", "legacy.example.lan")
