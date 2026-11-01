# SPDX-License-Identifier: Apache-2.0
"""A dns.config rollback against a real named once the backup retention removed the plan's backup
set (section 6): 409 precondition_failed, nothing written, the plan still applied."""

from __future__ import annotations

import time

import pytest

from pelagos.collector.series import purge_backups
from tests.daemon.api_node import V1, apply, login, make_app, make_node, planned

pytestmark = pytest.mark.daemon


@pytest.fixture
def api(tmp_root, named_server):
    ctx = make_node(tmp_root / "node", named=named_server)
    yield login(make_app(ctx)), ctx
    from pelagos.services.container import Services

    Services.of(ctx).close()


def test_config_rollback_refused_once_the_backup_is_purged(api, named_server):
    client, ctx = api
    setup = planned(
        client.post(f"{V1}/dns/config/plan", json={"changes": [{"op": "add", "target": "pelagos/includes"}]})
    )
    assert apply(client, setup)["state"] == "applied"
    acls = named_server.root / "pelagos" / "acls.conf"
    stmt = "acl guarded {\n\t192.0.2.0/25;\n};"
    plan = planned(
        client.post(
            f"{V1}/dns/config/plan",
            json={"changes": [{"op": "add", "target": f"raw:{acls}", "after": stmt, "before": None}]},
        )
    )
    applied = apply(client, plan)
    assert applied["state"] == "applied" and applied["rollback_until"], applied
    backups = ctx.paths.backups_dir / "bind"
    assert list(backups.glob(f"*-{plan['id']}"))

    # The retention pass, days later, with the shortest backups_days.
    assert purge_backups(ctx.paths.backups_dir, 1, time.time() + 3 * 86400) >= 1
    assert not list(backups.glob(f"*-{plan['id']}"))
    text = acls.read_text()
    status = named_server.rndc("status")

    r = client.post(f"{V1}/plans/{plan['id']}/rollback")
    assert r.status_code == 409, r.get_json()
    body = r.get_json()
    assert body["code"] == "precondition_failed" and "no backup found" in body["detail"]
    assert acls.read_text() == text and "acl guarded" in text
    held = client.get(f"{V1}/plans/{plan['id']}").get_json()
    assert held["state"] == "applied" and held["rollback_until"] == applied["rollback_until"]
    assert "server is up and running" in status and "server is up" in named_server.rndc("status")
