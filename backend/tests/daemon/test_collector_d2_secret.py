# SPDX-License-Identifier: Apache-2.0
"""A D2 plan with a new TSIG secret, built on one node and applied on its peer over /repl/v1."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from pelagos.connectors.base import ConnectorContext
from pelagos.connectors.kea.d2 import D2Backend
from pelagos.core.plan_secrets import SEALED, seal_backend_secrets
from pelagos.core.replication import ReplicationClient
from pelagos.domain import Engine, PlanState
from tests.fixtures import kea as kea_fx
from tests.unit.core.test_replication import Cluster

pytestmark = pytest.mark.daemon

SECRET = base64.b64encode(b"fedcba9876543210fedcba9876543210").decode()


def make_d2(daemon: kea_fx.KeaDaemon, backups: Path, node_id: str) -> D2Backend:
    ctx = ConnectorContext(
        node_id=node_id,
        engine_config={
            "socket_dir": str(daemon.socket_path.parent),
            "d2_socket": daemon.socket_path.name,
            "d2_conf": str(daemon.config_path),
            "d2_secret_dir": str(daemon.root),
        },
        backup_root=backups,
        get_secret=lambda name: None,
        settings={},
    )
    return D2Backend(ctx)


def test_peer_applies_a_d2_plan_with_a_new_secret(kea_d2, tmp_root):
    cluster = Cluster(tmp_root / "cluster")
    try:
        a = cluster.first()
        b = cluster.enroll(a)
        # B drives the daemon with a backend that never saw the plan being built.
        b.service.registry.register(Engine.D2, make_d2(kea_d2, tmp_root / "b-backups", b.id))
        builder = make_d2(kea_d2, tmp_root / "a-backups", a.id)
        cfg = json.loads(json.dumps(builder.config_get()))
        cfg["tsig-keys"].append({"name": "ddi-peer", "algorithm": "HMAC-SHA256", "secret": SECRET})
        cfg["reverse-ddns"]["ddns-domains"][0]["key-name"] = "ddi-peer"
        plan = builder.plan_config_replace({"DhcpDdns": cfg}, "alice")
        assert plan.state is PlanState.VALIDATED, plan.validations
        client = ReplicationClient(a.ctx.cluster().peer(b.id), a.service.client_context)

        # Without the sealed secret the peer cannot write the file and fails cleanly.
        unsealed = client.apply_plan(plan)
        assert not unsealed.ok
        secret_path = kea_d2.root / "ddi-peer.secret"
        assert not secret_path.exists()

        assert seal_backend_secrets(plan, builder, a.ctx.secrets) == 1
        assert SECRET not in json.dumps(plan.to_dict()) and SEALED in json.dumps(plan.to_dict())
        result = client.apply_plan(plan)
        assert result.ok, result.message
        assert secret_path.read_text() == SECRET
        running = {k["name"]: k for k in builder.config_get()["tsig-keys"]}
        assert running["ddi-peer"]["secret-file"] == str(secret_path)
        # The audit entry on B never holds the secret.
        assert SECRET not in json.dumps([e.to_dict() for e in b.ctx.audit_log.read()])
    finally:
        cluster.stop_all()
