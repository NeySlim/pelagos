# SPDX-License-Identifier: Apache-2.0
"""Connectors read the current [settings]: a setting changed after start applies without a restart."""

from __future__ import annotations

import pytest

from pelagos.services.registry import connector_context

pytestmark = pytest.mark.unit


def test_default_ns_set_after_start_reaches_the_connector(node_ctx):
    cctx = connector_context(node_ctx, "bind", {})
    assert not (cctx.current_settings().get("dns") or {}).get("default_ns")
    node_ctx.config_store.update_cluster(
        lambda c: c.settings.setdefault("dns", {}).__setitem__("default_ns", ["ns1.example.lan."]),
        updated_by="test",
    )
    assert cctx.current_settings()["dns"]["default_ns"] == ["ns1.example.lan."]
    # The snapshot of the build stays as it was; only current_settings() follows the file.
    assert not (cctx.settings.get("dns") or {}).get("default_ns")
