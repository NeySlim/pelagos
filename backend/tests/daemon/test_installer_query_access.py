# SPDX-License-Identifier: Apache-2.0
"""The SOA probe the import uses, against a real named with a zone whose allow-query excludes localhost."""

from __future__ import annotations

from pathlib import Path

import pytest

from pelagos.installer.env import Tools
from tests.daemon import bind_custom

pytestmark = pytest.mark.daemon

BODY = """
zone "open.lan" { type primary; file "open.lan.db"; };
zone "closed.lan" { type primary; file "closed.lan.db"; allow-query { 192.0.2.99; }; };
"""


def test_soa_probe_sees_the_refusal(tmp_path: Path):
    server = bind_custom.start(
        tmp_path,
        BODY,
        files={
            "open.lan.db": bind_custom.zone_text("open.lan"),
            "closed.lan.db": bind_custom.zone_text("closed.lan"),
        },
    )
    try:
        tools = Tools(None)  # type: ignore[arg-type]  # the probe uses no environment
        assert tools.soa_answered("127.0.0.1", server.dns_port, "open.lan.") is True
        assert tools.soa_answered("127.0.0.1", server.dns_port, "closed.lan.") is False
    finally:
        server.stop()
