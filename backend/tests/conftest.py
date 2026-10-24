# SPDX-License-Identifier: Apache-2.0
"""Shared fixtures: temp node tree, Flask client, real named and Kea daemons (daemon tier)."""

from __future__ import annotations

import os
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pelagos.core.bootstrap import bootstrap_first_node, dev_paths
from pelagos.core.context import NodeContext
from pelagos.core.paths import Paths
from tests.fixtures import kea as kea_fx
from tests.fixtures import named as named_fx
from tests.fixtures.ports import find_binary

ADMIN_PASSWORD = "Fixture-Admin-Password-1"


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Skip tiers whose prerequisites are missing instead of failing them."""
    have_named = find_binary("named") is not None and find_binary("rndc") is not None
    have_kea = kea_fx.kea_available()
    lab = os.environ.get("PELAGOS_LAB") == "1"
    for item in items:
        if "lab" in item.keywords and not lab:
            item.add_marker(pytest.mark.skip(reason="lab tier needs PELAGOS_LAB=1"))
        if "daemon" in item.keywords:
            if "kea" in item.nodeid and not have_kea:
                item.add_marker(pytest.mark.skip(reason="kea-dhcp4 (executable) and its hooks are required"))
            if "bind" in item.nodeid and not have_named:
                item.add_marker(pytest.mark.skip(reason="named and rndc are required"))


@pytest.fixture
def tmp_root() -> Iterator[Path]:
    # A short path: Unix socket paths are capped near 108 bytes.
    with tempfile.TemporaryDirectory(prefix="plg-", dir=os.environ.get("PELAGOS_TEST_TMP")) as d:
        yield Path(d)


@pytest.fixture
def node_paths(tmp_root: Path) -> Paths:
    paths = dev_paths(tmp_root / "node")
    bootstrap_first_node(
        paths, name="ns1", admin_password=ADMIN_PASSWORD, engines={"bind": True, "kea4": True}
    )
    return paths


@pytest.fixture
def node_ctx(node_paths: Paths) -> NodeContext:
    return NodeContext.build(node_paths)


@pytest.fixture
def app(node_paths: Paths, node_ctx: NodeContext):
    from pelagos.app import create_app

    app = create_app(node_paths, context=node_ctx, static_dir=node_paths.opt / "none")
    app.config["TESTING"] = True
    return app


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def admin_client(client):
    """Logged-in test client; the CSRF token is sent on every unsafe request."""
    resp = client.post("/api/v1/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD})
    assert resp.status_code == 200, resp.get_json()
    token = resp.get_json()["csrf_token"]
    client.environ_base["HTTP_X_CSRF_TOKEN"] = token
    client.csrf_token = token
    return client


# Daemon tier ----------------------------------------------------------------


@pytest.fixture
def named_server(tmp_root: Path) -> Iterator[named_fx.NamedServer]:
    server = named_fx.start_named(tmp_root / "ns1")
    try:
        yield server
    finally:
        server.stop()


@pytest.fixture
def named_secondary(tmp_root: Path, named_server: named_fx.NamedServer) -> Iterator[named_fx.NamedServer]:
    """A second named transferring from named_server; the primary is restarted with also-notify."""
    secondary = named_fx.start_named(
        tmp_root / "ns2", role="secondary", keys=named_server.keys, primary_port=named_server.dns_port
    )
    try:
        yield secondary
    finally:
        secondary.stop()


@pytest.fixture
def kea_dhcp4(tmp_root: Path) -> Iterator[kea_fx.KeaDaemon]:
    hooks = kea_fx.kea_hooks_dir()
    assert hooks is not None
    daemon = kea_fx.start_kea("kea-dhcp4", tmp_root / "kea4", kea_fx.dhcp4_config(tmp_root / "kea4", hooks))
    try:
        yield daemon
    finally:
        daemon.stop()


@pytest.fixture
def kea_dhcp6(tmp_root: Path) -> Iterator[kea_fx.KeaDaemon]:
    hooks = kea_fx.kea_hooks_dir()
    assert hooks is not None
    daemon = kea_fx.start_kea("kea-dhcp6", tmp_root / "kea6", kea_fx.dhcp6_config(tmp_root / "kea6", hooks))
    try:
        yield daemon
    finally:
        daemon.stop()


@pytest.fixture
def kea_d2(tmp_root: Path, named_server: named_fx.NamedServer) -> Iterator[kea_fx.KeaDaemon]:
    """D2 pointed at the fixture named with the kea-ddns key."""
    from tests.fixtures.ports import free_port

    root = tmp_root / "d2"
    root.mkdir()
    cfg = kea_fx.d2_config(
        root, named_server.dns_port, "kea-ddns", named_server.keys["kea-ddns"], free_port()
    )
    daemon = kea_fx.start_kea("kea-dhcp-ddns", root, cfg)
    try:
        yield daemon
    finally:
        daemon.stop()
