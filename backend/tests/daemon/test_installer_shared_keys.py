# SPDX-License-Identifier: Apache-2.0
"""A node whose keys.conf holds its own ddi-read (imported before replication brought the shared one),
against a real named: the audit finds it, the security plan rewrites keys.conf from cluster.toml with
named-checkconf and rndc reconfig, then AXFR signed with the shared secret works and the old one fails."""

from __future__ import annotations

import dataclasses
import subprocess
from pathlib import Path

import pytest

from pelagos.connectors.base import ConnectorDenied
from pelagos.connectors.bind.dns_client import DnsClient, TsigKey
from pelagos.core.config_store import ConfigStore
from pelagos.domain import JobState
from pelagos.installer import managed
from pelagos.installer.jobs import apply_plan
from pelagos.installer.security_audit import build_security_plan, run_audit
from tests.daemon import bind_custom
from tests.fixtures.ports import find_binary
from tests.unit.installer.fakes import join_cluster, make_env

pytestmark = pytest.mark.daemon

BODY = 'zone "example.lan" { type primary; file "example.lan.db"; };\n'
FID = "bind:shared_key_divergence:ddi-read"


@pytest.fixture
def server(tmp_root: Path):
    srv = bind_custom.start(
        tmp_root / "named",
        BODY,
        files={"example.lan.db": bind_custom.zone_text("example.lan")},
        options="\tallow-transfer { key ddi-read; };\n",
    )
    try:
        yield srv
    finally:
        srv.stop()


def _env(server, tmp_root: Path):
    env = make_env(tmp_root / "installer")
    env.paths = dataclasses.replace(env.paths, named_conf=server.named_conf, bind_include_dir=server.root)
    checkconf = find_binary("named-checkconf")

    def real_checkconf(named_conf: Path) -> tuple[bool, str]:
        res = subprocess.run([checkconf, str(named_conf)], capture_output=True, text=True, check=False)
        return res.returncode == 0, res.stdout + res.stderr

    def real_rndc(_conf, *args: str) -> tuple[bool, str]:
        try:
            return True, server.rndc(*args)
        except RuntimeError as exc:
            return False, str(exc)

    env.tools.checkconf = real_checkconf
    env.tools.rndc = real_rndc
    env.services.active.add(env.bind_unit())
    return env


def test_divergent_read_key_is_rewritten_from_cluster_toml(server, tmp_root):
    env = _env(server, tmp_root)
    box = join_cluster(env)
    own, shared = server.keys["ddi-read"], managed.new_secret()
    store = ConfigStore(env.node_paths.node_toml, env.node_paths.cluster_toml)

    def put(cluster):
        cluster.secrets["tsig/ddi-read"] = box.encrypt("tsig/ddi-read", shared)
        cluster.secrets["tsig/ddi-admin"] = box.encrypt("tsig/ddi-admin", server.keys["ddi-admin"])

    store.update_cluster(put, updated_by="node:peer")
    client = DnsClient(port=server.dns_port)
    with pytest.raises(ConnectorDenied):  # the other node signs with the shared secret: BADSIG
        client.axfr("example.lan", TsigKey("ddi-read", shared))

    findings = {f.id: f for f in run_audit(env) if f.kind == "shared_key_divergence"}
    assert set(findings) == {FID}

    job = apply_plan(build_security_plan(env, [FID], created_by="admin"), env)
    assert job.state is JobState.DONE, job.error
    assert any(r.rtype == "SOA" for r in client.axfr("example.lan", TsigKey("ddi-read", shared)))
    with pytest.raises(ConnectorDenied):
        client.axfr("example.lan", TsigKey("ddi-read", own))
    assert not [f for f in run_audit(env) if f.kind == "shared_key_divergence"]
