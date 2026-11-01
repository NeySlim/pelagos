# SPDX-License-Identifier: Apache-2.0
"""GET /metrics (section 30): token or network access, disabled switch, no audit, plain text."""

from __future__ import annotations

from datetime import timedelta

import pytest

from pelagos.auth import api_tokens as tk
from pelagos.domain import ApiToken, utcnow

pytestmark = pytest.mark.unit

P = "/api/v1"


def make_token(node_ctx, username: str, permissions: list[str], cidrs: list[str] | None = None) -> str:
    uid = next(u.id for u in node_ctx.cluster().users if u.username == username)
    token_id, secret = tk.new_token()
    record = ApiToken(
        id=token_id, name=f"m-{username}", user_id=uid, secret_hash=tk.digest(secret),
        expires_at=utcnow() + timedelta(days=30), permissions=permissions, cidrs=cidrs or [],
    )  # fmt: skip
    node_ctx.config_store.update_cluster(lambda c: c.api_tokens.append(record), updated_by="test")
    return secret


def get(app, token=None, addr="198.51.100.9"):
    client = app.test_client()
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return client.get("/metrics", headers=headers, environ_overrides={"REMOTE_ADDR": addr})


def test_viewer_token_reads_the_text(app, node_ctx) -> None:
    r = get(app, make_token(node_ctx, "vera", ["read:series"]))
    assert r.status_code == 200
    assert r.headers["Content-Type"].startswith("text/plain; version=0.0.4")
    assert "pelagos_build_info" in r.get_data(as_text=True)


def test_token_without_read_series_is_forbidden(app, node_ctx) -> None:
    r = get(app, make_token(node_ctx, "vera", ["read:dns"]))
    assert r.status_code == 403


def test_no_token_outside_the_networks_is_401(app) -> None:
    r = get(app)
    assert r.status_code == 401
    assert r.mimetype == "application/problem+json"


def test_wrong_token_is_401_even_from_an_allowed_network(app, node_ctx) -> None:
    node_ctx.config_store.update_cluster(
        lambda c: c.settings.setdefault("metrics", {}).update(allowed_networks=["198.51.100.0/24"]),
        updated_by="test",
    )
    assert get(app).status_code == 200
    assert get(app, "pel_0000000000000000_" + "A" * 43).status_code == 401


def test_allowed_network_needs_no_token(app, node_ctx) -> None:
    node_ctx.config_store.update_cluster(
        lambda c: c.settings.setdefault("metrics", {}).update(allowed_networks=["198.51.100.0/24"]),
        updated_by="test",
    )
    assert get(app).status_code == 200
    assert get(app, addr="203.0.113.5").status_code == 401


def test_disabled_answers_404(app, node_ctx) -> None:
    node_ctx.config_store.update_cluster(
        lambda c: c.settings.setdefault("metrics", {}).update(endpoint_enabled=False), updated_by="test"
    )
    assert get(app, make_token(node_ctx, "vera", ["read:series"])).status_code == 404


def test_scrapes_are_never_audited(app, node_ctx) -> None:
    token = make_token(node_ctx, "vera", ["read:series"])
    for _ in range(3):
        assert get(app, token).status_code == 200
    assert not [e for e in node_ctx.audit_log.read() if e.action == "auth.token_call"]


def test_token_cidr_applies(app, node_ctx) -> None:
    token = make_token(node_ctx, "vera", ["read:series"], cidrs=["203.0.113.0/24"])
    assert get(app, token).status_code == 401
    assert get(app, token, addr="203.0.113.7").status_code == 200
