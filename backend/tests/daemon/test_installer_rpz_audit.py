# SPDX-License-Identifier: Apache-2.0
"""A real named serving the policy zones Pelagos renders (file in its RPZ cache folder, no transfer,
localhost queries, no notify) next to an operator's own policy zone: the security audit proposes
nothing for the former, from the cluster RPZ state, and still flags the latter."""

from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest

from pelagos.connectors.bind.dns_client import DnsClient
from pelagos.core.config_store import ConfigStore
from pelagos.installer.security_audit import run_audit
from tests.daemon import bind_custom
from tests.unit.installer.fakes import join_cluster, make_env

pytestmark = pytest.mark.daemon

RPZ = {"categories": {"security": {"enabled": True, "level": "normal", "addons": ["hagezi-fake"]}}}
MANAGED = ("pelagos-allow.rpz.invalid", "hagezi-tif-medium.rpz.invalid", "hagezi-fake.rpz.invalid")
USER_ZONE = "blocked.rpz.invalid"


def _zone(name: str, file: str) -> str:
    return (
        f'zone "{name}" {{ type primary; file "{file}"; allow-transfer {{ none; }}; '
        "notify no; allow-query { localhost; }; };\n"
    )


@pytest.fixture
def server(tmp_root: Path):
    policy = " ".join(f'zone "{z}";' for z in (*MANAGED, USER_ZONE))
    body = "".join(_zone(z, f"{{zones}}/pelagos/rpz/{z}.db") for z in MANAGED)
    body += _zone(USER_ZONE, f"{{zones}}/{USER_ZONE}.db")
    rpz_text = bind_custom.zone_text("rpz.invalid", extra="ads.example.com CNAME .\n")
    files = {f"{USER_ZONE}.db": rpz_text}
    (tmp_root / "named/zones/pelagos/rpz").mkdir(parents=True)
    for z in MANAGED:
        (tmp_root / f"named/zones/pelagos/rpz/{z}.db").write_text(rpz_text)
    srv = bind_custom.start(
        tmp_root / "named",
        body,
        files=files,
        options=f"\tallow-transfer {{ key ddi-read; }};\n\tresponse-policy {{ {policy} }};\n",
        recursion=True,
    )
    try:
        yield srv
    finally:
        srv.stop()


def test_audit_skips_pelagos_rpz_zones_on_a_real_named(server, tmp_root):
    env = make_env(tmp_root / "installer")
    env.paths = dataclasses.replace(env.paths, named_conf=server.named_conf, bind_include_dir=server.root)
    env.services.active.add(env.bind_unit())
    join_cluster(env)
    store = ConfigStore(env.node_paths.node_toml, env.node_paths.cluster_toml)
    store.update_cluster(lambda c: c.settings.__setitem__("rpz", RPZ), updated_by="node:test")
    # named loaded every policy zone: the audit reads the configuration it really serves.
    client = DnsClient(port=server.dns_port)
    for z in (*MANAGED, USER_ZONE):
        assert client.soa_serial(z) == 2026102401

    by_zone: dict[str, set[str]] = {}
    for f in run_audit(env):
        if zone := f.details.get("zone"):
            by_zone.setdefault(zone.rstrip("."), set()).add(f.kind)
    assert not set(MANAGED) & set(by_zone)
    assert {"transfer_without_read_key", "static_zone"} <= by_zone[USER_ZONE]
