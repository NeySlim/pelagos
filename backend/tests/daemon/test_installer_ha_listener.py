# SPDX-License-Identifier: Apache-2.0
"""The HA listener remediation on a real hot-standby pair of kea-dhcp4: restrict-commands and the
TLS switch of the manual procedure keep the pair in sync and lock out an ordinary client."""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from collections.abc import Iterator
from pathlib import Path

import pytest

from pelagos.core import ca
from pelagos.installer import ha_listener
from tests.daemon.test_kea_ha import ha_config, local_state
from tests.fixtures import kea as kea_fx
from tests.fixtures.ports import free_port, wait_for

pytestmark = pytest.mark.daemon


def _post(url: str, command: str, context: ssl.SSLContext | None = None) -> dict:
    req = urllib.request.Request(  # noqa: S310 - http(s) URL of a test listener
        url, data=json.dumps({"command": command}).encode(), headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=10, context=context) as resp:  # noqa: S310 - test listener
            body = json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return {"result": None, "http": exc.code}  # a refused command answers 403
    return body[0] if isinstance(body, list) else body


def _rel(cfg: dict) -> dict:
    return cfg["Dhcp4"]["hooks-libraries"][-1]["parameters"]["high-availability"][0]


def _start(tmp_root: Path, ports: list[int], extra: dict | None = None) -> list[kea_fx.KeaDaemon]:
    hooks = kea_fx.kea_hooks_dir()
    assert hooks is not None
    daemons = []
    for i in (1, 2):
        root = tmp_root / f"ha{i}"
        cfg = ha_config(root, hooks, i, ports)
        _rel(cfg).update(extra or {})
        daemons.append(kea_fx.start_kea("kea-dhcp4", root, cfg))
    return daemons


@pytest.fixture
def ports() -> list[int]:
    return [free_port(), free_port()]


@pytest.fixture
def pair(tmp_root: Path, ports: list[int]) -> Iterator[list[kea_fx.KeaDaemon]]:
    daemons = _start(tmp_root, ports, {"restrict-commands": False})
    try:
        yield daemons
    finally:
        for d in daemons:
            d.stop()


def _synced(daemons: list[kea_fx.KeaDaemon]) -> None:
    wait_for(
        lambda: [local_state(d) for d in daemons] == ["hot-standby", "hot-standby"],
        timeout=45,
        what="HA hot-standby",
    )


def test_restrict_commands_keeps_the_pair_and_shuts_config_get(pair, ports):
    _synced(pair)
    url = f"http://127.0.0.1:{ports[0]}/"
    assert _post(url, "config-get")["result"] == 0  # the open listener of the finding
    # Each node on its own, standby first: the pair keeps talking in between.
    for daemon in reversed(pair):
        cfg = json.loads(daemon.config_path.read_text())
        new, changed = ha_listener.with_restrict_commands(cfg)
        assert changed == 1
        daemon.config_path.write_text(json.dumps(new))
        assert daemon.command("config-reload")["result"] == 0, daemon.log_text()
    _synced(pair)
    assert _post(url, "config-get") == {"result": None, "http": 403}
    assert _post(url, "ha-heartbeat")["result"] == 0
    (lst,) = ha_listener.listeners("kea4", json.loads(pair[0].config_path.read_text()), "3.2.0")
    assert lst.restrict_commands


def _issue(tmp_root: Path) -> tuple[Path, dict[str, dict[str, str]]]:
    """A cluster CA and one certificate per peer (serverAuth and clientAuth), as core.ca issues them."""
    root = ca.create_root("cluster-test")
    d = tmp_root / "tls"
    d.mkdir()
    (d / "ca.crt").write_bytes(root.cert_pem)
    files = {}
    for name in ("server1", "server2"):
        key_pem, csr = ca.node_csr(name, name, [])
        pair = ca.KeyPair(key_pem, ca.sign_node(root, csr))
        ca.write_pair(pair, d / f"{name}.key", d / f"{name}.crt")
        files[name] = {"cert-file": str(d / f"{name}.crt"), "key-file": str(d / f"{name}.key")}
    return d / "ca.crt", files


def test_tls_switch_standby_first_then_primary(tmp_root, ports):
    anchor, certs = _issue(tmp_root)
    daemons = _start(tmp_root, ports)
    try:
        _synced(daemons)
        for daemon in reversed(daemons):  # the standby, then the primary
            cfg = json.loads(daemon.config_path.read_text())
            rel = _rel(cfg)
            rel.update({"trust-anchor": str(anchor), "require-client-certs": True})
            for peer in rel["peers"]:
                peer.update(certs[peer["name"]])
                peer["url"] = peer["url"].replace("http://", "https://")
            daemon.config_path.write_text(json.dumps(cfg))
            assert daemon.command("config-reload")["result"] == 0, daemon.log_text()
        _synced(daemons)
        (lst,) = ha_listener.listeners("kea4", json.loads(daemons[0].config_path.read_text()), "3.2.0")
        assert lst.tls and not lst.open
        no_cert = ssl.create_default_context(cafile=str(anchor))
        no_cert.check_hostname = False
        with pytest.raises((ssl.SSLError, urllib.error.URLError, ConnectionError)):
            _post(f"https://127.0.0.1:{ports[0]}/", "ha-heartbeat", no_cert)
        with pytest.raises((urllib.error.URLError, ConnectionError, OSError)):
            _post(f"http://127.0.0.1:{ports[0]}/", "ha-heartbeat")
        with_cert = ssl.create_default_context(cafile=str(anchor))
        with_cert.check_hostname = False
        with_cert.load_cert_chain(certs["server2"]["cert-file"], certs["server2"]["key-file"])
        assert _post(f"https://127.0.0.1:{ports[0]}/", "ha-heartbeat", with_cert)["result"] == 0
    finally:
        for d in daemons:
            d.stop()
