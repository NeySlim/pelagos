# SPDX-License-Identifier: Apache-2.0
"""A Pelagos node whose node.toml points at the fixture daemons, served by the real Flask app.

Used by the daemon-tier API tests (test_api_*.py): every request goes through the API, the services
and the real connectors (BindBackend, KeaBackend, D2Backend) to the running named and Kea.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pelagos.core.bootstrap import bootstrap_first_node, dev_paths
from pelagos.core.context import NodeContext
from tests.conftest import ADMIN_PASSWORD
from tests.fixtures import kea as kea_fx
from tests.fixtures import named as named_fx

V1 = "/api/v1"


def bind_table(server: named_fx.NamedServer) -> dict[str, Any]:
    return {
        "named_conf": str(server.named_conf),
        "include_dir": str(server.root / "pelagos"),
        "zone_dir": str(server.root / "pelagos-zones"),
        "rndc_conf": str(server.rndc_conf),
        "rndc_port": server.rndc_port,
        "statistics_url": server.stats_url,
        "query_port": server.dns_port,
    }


def make_node(
    root: Path,
    named: named_fx.NamedServer | None = None,
    dhcp4: kea_fx.KeaDaemon | None = None,
    d2: kea_fx.KeaDaemon | None = None,
) -> NodeContext:
    """bootstrap_first_node with [engines] for the given daemons and the TSIG secrets in cluster.toml."""
    engines: dict[str, Any] = {"bind": False, "kea4": False, "kea6": False, "d2": False}
    if named is not None:
        engines["bind"] = bind_table(named)
    kea: dict[str, Any] = {}
    if dhcp4 is not None:
        engines["kea4"] = True
        kea.update(
            socket_dir=str(dhcp4.socket_path.parent),
            dhcp4_socket=dhcp4.socket_path.name,
            dhcp4_conf=str(dhcp4.config_path),
        )
    if d2 is not None:
        engines["d2"] = True
        # D2 has its own socket directory in the fixtures: an absolute socket name points there.
        kea.update(d2_socket=str(d2.socket_path), d2_conf=str(d2.config_path), d2_secret_dir=str(d2.root))
    if kea:
        engines["kea"] = kea
    paths = dev_paths(root)
    bootstrap_first_node(paths, name="ns1", admin_password=ADMIN_PASSWORD, engines=engines)
    ctx = NodeContext.build(paths)
    if named is not None:
        box = ctx.secrets
        assert box is not None

        def store(cfg: Any) -> None:
            for name, secret in named.keys.items():
                cfg.secrets[f"tsig/{name}"] = box.encrypt(f"tsig/{name}", secret)

        ctx.config_store.update_cluster(store, updated_by="test")
    return ctx


def make_app(ctx: NodeContext) -> Any:
    from pelagos.app import create_app

    app = create_app(ctx.paths, context=ctx, static_dir=ctx.paths.opt / "none")
    app.config["TESTING"] = True
    return app


def login(app: Any) -> Any:
    client = app.test_client()
    resp = client.post(f"{V1}/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD})
    assert resp.status_code == 200, resp.get_json()
    client.environ_base["HTTP_X_CSRF_TOKEN"] = resp.get_json()["csrf_token"]
    return client


def apply(client: Any, plan: dict[str, Any], confirm: bool = False) -> dict[str, Any]:
    r = client.post(f"{V1}/plans/{plan['id']}/apply", json={"confirm": confirm})
    assert r.status_code == 200, r.get_json()
    return r.get_json()


def planned(resp: Any) -> dict[str, Any]:
    assert resp.status_code == 200, resp.get_json()
    plan = resp.get_json()
    assert plan["state"] == "validated", plan
    return plan
