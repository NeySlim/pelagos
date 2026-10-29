# SPDX-License-Identifier: Apache-2.0
"""API fixtures: the app wired to fake backends, users of the four built-in roles, logged-in clients."""

from __future__ import annotations

from collections.abc import Callable

import pytest

from pelagos.auth.passwords import hash_password
from pelagos.core.context import NodeContext
from pelagos.domain import Family, User, new_id
from pelagos.services.container import Services
from pelagos.services.registry import ConnectorRegistry
from tests.conftest import ADMIN_PASSWORD
from tests.unit.installer.fakes import make_env
from tests.unit.services.fakes import FakeDdnsBackend, FakeDhcpBackend, FakeDnsBackend, fake_context

ROLE_USERS = {"viewer": "vera", "dns-operator": "dora", "dhcp-operator": "dhani", "admin": "admin"}
USER_PASSWORD = "Role-User-Password-42"


@pytest.fixture
def fake_registry(node_ctx: NodeContext) -> ConnectorRegistry:
    node_id = node_ctx.node.id
    backups = node_ctx.paths.backups_dir
    return ConnectorRegistry(
        dns=FakeDnsBackend(fake_context(node_id, "bind", backups / "bind")),
        kea4=FakeDhcpBackend(fake_context(node_id, "kea4", backups / "kea4"), Family.V4),
        kea6=FakeDhcpBackend(fake_context(node_id, "kea6", backups / "kea6"), Family.V6),
        d2=FakeDdnsBackend(fake_context(node_id, "d2", backups / "d2")),
    )


@pytest.fixture
def services(node_ctx: NodeContext, fake_registry: ConnectorRegistry, tmp_path) -> Services:
    def setup(cfg) -> None:
        cfg.modules["dhcpv6"] = True
        for role, name in ROLE_USERS.items():
            if name != "admin":
                cfg.users.append(
                    User(id=new_id(), username=name, password_hash=hash_password(USER_PASSWORD), roles=[role])
                )

    node_ctx.config_store.update_cluster(setup, updated_by="test")
    node_ctx.login_limiter.limit = 1000
    svc = Services(node_ctx, registry=fake_registry)
    # The installer endpoints work on an empty fake host, never on the machine running the tests.
    fake_host = make_env(tmp_path / "host")
    svc.install.env_factory = lambda: fake_host
    svc.kea_migration.env_factory = lambda: fake_host
    svc.kea_migration._own_env = False
    yield svc
    svc.close()


@pytest.fixture
def app(node_paths, node_ctx: NodeContext, services: Services):
    from pelagos.app import create_app

    app = create_app(node_paths, context=node_ctx, static_dir=node_paths.opt / "none")
    app.config["TESTING"] = True
    return app


def _login(app, username: str, password: str, totp_code: str | None = None):
    client = app.test_client()
    body = {"username": username, "password": password}
    if totp_code:
        body["totp_code"] = totp_code
    resp = client.post("/api/v1/auth/login", json=body)
    assert resp.status_code == 200, resp.get_json()
    client.environ_base["HTTP_X_CSRF_TOKEN"] = resp.get_json()["csrf_token"]
    client.login_answer = resp.get_json()
    return client


@pytest.fixture
def login(app) -> Callable[..., object]:
    return lambda username, password=USER_PASSWORD, totp_code=None: _login(app, username, password, totp_code)


@pytest.fixture
def role_client(app) -> Callable[[str], object]:
    """role_client("viewer") -> a client logged in as the user holding only that built-in role."""

    def make(role: str):
        name = ROLE_USERS[role]
        return _login(app, name, ADMIN_PASSWORD if name == "admin" else USER_PASSWORD)

    return make


@pytest.fixture
def admin(role_client):
    return role_client("admin")
