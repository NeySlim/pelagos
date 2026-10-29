# SPDX-License-Identifier: Apache-2.0
"""The Kea 3.x dry run on real nodes: the `kea_dry_run` helper operation of this checkout, run as root.

lab-ns1 (Debian 13, Kea 2.6.3 from Debian, its own libkea-* in /usr/lib) for ISC 3.2 and Debian
backports 3.0, lab-rpm (Rocky 10) for dnf with a converted Dhcp4 file given in the request.
Checked: the packages really download and their daemons validate the converted files (mode
`dry_run`), and the node's package sources, keys and caches are left as they were. Read-only: no
rollback, the VMs are left as found.
"""

from __future__ import annotations

import importlib
import io
import json
import shlex
import tarfile
from pathlib import Path

import pytest

from tests.lab.labkit import NS1, RPM, ssh, upload_source

pytestmark = pytest.mark.lab

DATA = Path(__file__).parents[1] / "unit" / "connectors" / "kea" / "data"
# What a dry run must leave as it was: sources, keys, the package databases and caches.
STATE = {
    "debian": "sudo sh -c 'cd / && find etc/apt var/lib/apt/lists var/cache/apt/archives "
    'usr/share/keyrings -type f -printf "%p %s %T@\\n" | sort; dpkg-query -W | sha256sum\'',
    "rocky": 'sudo sh -c \'cd / && find etc/yum.repos.d etc/pki/rpm-gpg var/cache/dnf -printf "%p %s %T@\\n" '
    "2>/dev/null | sort; rpm -qa | sort | sha256sum; rpm -q gpg-pubkey || true'",
}
# Modules the helper imports that a bare node lacks, from this checkout's venv: pure Python, plus
# cryptography for Rocky 10, whose Python (3.12) matches the venv's wheels.
DEPS = ("tomli_w", "dns", "idna")
ROCKY_DEPS = ("cryptography", "cffi", "_cffi_backend")
SCRIPT = """
import json, sys
from pelagos.installer import helper
from pelagos.installer.env import InstallerEnv
request = json.load(sys.stdin)
print(json.dumps(helper.handle(request, InstallerEnv.detect, lambda _m: None)))
"""


def deps_tarball(names: tuple[str, ...]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name in names:
            path = Path(importlib.import_module(name).__file__)
            if path.name == "__init__.py":
                path = path.parent
            tar.add(path, arcname=path.name, filter=lambda t: None if "__pycache__" in t.name else t)
    return buf.getvalue()


def dry_run(host: str, request: dict, deps: tuple[str, ...] = DEPS) -> dict:
    ssh(host, "sudo rm -rf ~/pelagos-k1")
    src = upload_source(host, "~/pelagos-k1")
    ssh(
        host,
        "rm -rf ~/pelagos-k1/deps && mkdir -p ~/pelagos-k1/deps && tar -xz -C ~/pelagos-k1/deps",
        data=deps_tarball(deps),
    )
    path = f"$HOME/{src[2:]}/backend:$HOME/pelagos-k1/deps"
    cmd = f"cd / && sudo PYTHONPATH={path} python3 -B -c {shlex.quote(SCRIPT)}"
    out = ssh(host, cmd, data=json.dumps(request).encode(), timeout=1200)[1]
    return json.loads(out.strip().splitlines()[-1])


def check(report: dict, engines: set[str], series: str) -> None:
    assert set(report["validation"]) == engines
    for engine, result in report["validation"].items():
        assert result["mode"] == "dry_run", (engine, result)
        assert result["ok"], (engine, result["output"])
        assert result["version"].startswith(series + "."), result
    assert not [f for f in report["findings"] if f["severity"] == "blocking"], report["findings"]
    assert report["target_version"].startswith(series + ".")


@pytest.mark.parametrize(("series", "source"), [("3.2", "isc"), ("3.0", "backports")])
def test_debian_node_dry_run(series, source):
    host = NS1[1]
    if ssh(host, "test -s /etc/kea/kea-dhcp4.conf || sudo test -s /etc/kea/kea-dhcp4.conf", check=False)[0]:
        pytest.skip("lab-ns1 has no Kea configuration (run the K1 provisioning or test_kea26_lab first)")
    before = ssh(host, STATE["debian"])[1]
    report = dry_run(host, {"op": "kea_dry_run", "series": series, "source": source})
    check(report, set(report["validation"]) or {"kea4"}, series)
    assert "kea4" in report["validation"]
    assert ssh(host, STATE["debian"])[1] == before
    assert not ssh(host, "sudo ls -d /tmp/pelagos-kea-dry-run-* 2>/dev/null", check=False)[1].strip()


def test_rocky_node_dry_run():
    host = RPM[1]
    cfg = json.loads((DATA / "kea26-migration-dhcp4.json").read_text())
    root = cfg["Dhcp4"]
    # No HA here: the TLS files of the fixture do not exist on this node.
    root["hooks-libraries"] = [h for h in root["hooks-libraries"] if "ha" not in h["library"]]
    before = ssh(host, STATE["rocky"])[1]
    report = dry_run(
        host,
        {"op": "kea_dry_run", "series": "3.2", "source": "isc", "configs": {"kea4": cfg}},
        DEPS + ROCKY_DEPS,
    )
    check(report, {"kea4"}, "3.2")
    assert ssh(host, STATE["rocky"])[1] == before
