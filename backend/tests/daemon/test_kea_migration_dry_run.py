# SPDX-License-Identifier: Apache-2.0
"""Dry-run validation with real Kea 3.x daemons copied out of the host's packages into a fake tree.

The tree mimics `dpkg-deb -x` of the ISC packages: daemons, libkea-* and hooks away from /usr, run
with LD_LIBRARY_PATH and KEA_HOOKS_PATH. The download itself is proven in the lab (needs Internet).
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from pelagos.connectors.kea import migration as mig
from pelagos.installer import kea_migration as km
from pelagos.platform import CommandRunner, distro_from_fields

pytestmark = pytest.mark.daemon

DATA = Path(__file__).parents[1] / "unit" / "connectors" / "kea" / "data"
PACKAGES = ("isc-kea-common", "isc-kea-dhcp4", "isc-kea-dhcp-ddns", "isc-kea-hooks")
DEBIAN = distro_from_fields(
    {"ID": "debian", "VERSION_ID": "13", "VERSION_CODENAME": "trixie", "PRETTY_NAME": "x"}
)


def _package_files(name: str) -> list[Path]:
    try:
        out = subprocess.run(["dpkg-query", "-L", name], capture_output=True, text=True, check=False).stdout
    except FileNotFoundError:
        return []
    return [Path(p) for p in out.splitlines() if p.startswith("/usr/") and Path(p).is_file()]


@pytest.fixture(scope="module")
def workspace(tmp_path_factory) -> km.Workspace:
    lists = {p: _package_files(p) for p in PACKAGES}
    if not all(lists.values()):
        pytest.skip("ISC Kea 3.x packages are not installed on this host")
    root = tmp_path_factory.mktemp("dry-run")
    ws = km.Workspace(CommandRunner(), DEBIAN, "3.2", "isc", root)
    for files in lists.values():
        for f in files:
            dest = ws.tree / f.relative_to("/")
            dest.parent.mkdir(parents=True, exist_ok=True)
            try:
                shutil.copy2(f, dest)
            except PermissionError:
                pytest.skip(f"{f} is not readable by this user (add it to the Kea group)")
    for lib in (ws.tree / Path(ws.hooks_dir()).parent.parent.relative_to("/")).glob("libkea-*.so.*.*.*"):
        soname = lib.name.rsplit(".", 2)[0]
        if not (lib.parent / soname).exists():
            (lib.parent / soname).symlink_to(lib.name)
    return ws


def _tls(tmp: Path) -> dict[str, str]:
    key, crt = tmp / "node.key", tmp / "node.crt"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(crt),
            "-days",
            "2",
            "-subj",
            "/CN=ns1",
            "-addext",
            "subjectAltName=IP:192.0.2.11",
        ],
        capture_output=True,
        check=True,
    )
    return {"trust-anchor": str(crt), "cert-file": str(crt), "key-file": str(key)}


def _converted(ws: km.Workspace, tmp: Path, engine: str, name: str) -> mig.Conversion:
    cfg = json.loads((DATA / name).read_text())
    if engine == "kea4":
        rel = cfg["Dhcp4"]["hooks-libraries"][2]["parameters"]["high-availability"][0]
        rel.update(_tls(tmp))
    return mig.convert(engine, cfg, ws.layout(tmp))


def test_extracted_tree_knows_its_version_and_hooks(workspace):
    assert workspace.version("kea4").startswith("3.")
    assert {"libdhcp_ha.so", "libdhcp_lease_cmds.so"} <= workspace.hooks()


def test_converted_production_files_pass(workspace, tmp_path):
    kea4 = _converted(workspace, tmp_path, "kea4", "kea26-migration-dhcp4.json")
    res = workspace.validate("kea4", kea4.after, kea4.files, "/etc/kea/kea-dhcp4.conf")
    assert res["ok"], res["output"]
    d2 = _converted(workspace, tmp_path, "d2", "kea26-migration-d2.json")
    res = workspace.validate("d2", d2.after, d2.files, "/etc/kea/kea-dhcp-ddns.conf")
    assert res["ok"], res["output"]


def test_unconverted_files_fail(workspace, tmp_path):
    d2 = json.loads((DATA / "kea26-migration-d2.json").read_text())
    res = workspace.validate("d2", d2, {}, "/etc/kea/kea-dhcp-ddns.conf")
    assert not res["ok"] and "NOT SECURE" in km.error_line(res["output"])
    kea4 = _converted(workspace, tmp_path, "kea4", "kea26-migration-dhcp4.json").after
    kea4["Dhcp4"]["control-sockets"][0]["socket-name"] = "/tmp/kea4-ctrl-socket"
    res = workspace.validate("kea4", kea4, {}, "/etc/kea/kea-dhcp4.conf")
    assert not res["ok"] and "socket-name" in km.error_line(res["output"])


def test_hooks_load_under_t_capital(workspace, tmp_path):
    """-T loads the HA hook, which reads the TLS key: a missing key is caught before migrating."""
    conv = _converted(workspace, tmp_path, "kea4", "kea26-migration-dhcp4.json")
    rel = conv.after["Dhcp4"]["hooks-libraries"][2]["parameters"]["high-availability"][0]
    rel["key-file"] = str(tmp_path / "missing.key")
    res = workspace.validate("kea4", conv.after, {}, "/etc/kea/kea-dhcp4.conf")
    assert not res["ok"]
    assert "missing.key" in km.error_line(res["output"])
    assert str(workspace.tree) not in res["output"]
