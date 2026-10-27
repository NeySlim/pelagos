# SPDX-License-Identifier: Apache-2.0
"""The syntax warnings Pelagos reports are the ones the real kea-dhcp4 prints with -t."""

from __future__ import annotations

import re
import subprocess

import pytest

from pelagos.core.keadoc import KeaDocument
from tests.fixtures.kea import kea_env
from tests.fixtures.ports import find_binary

pytestmark = pytest.mark.daemon

WARNING = re.compile(
    r"DHCP4_CONFIG_SYNTAX_WARNING .*?: (?P<path>[^\s:]+):(?P<line>\d+)\.(?P<col>\d+): (?P<msg>.*)"
)

CONF = """{
  "Dhcp4": {
    "interfaces-config": { "interfaces": [ "*" ], },
    "lease-database": { "type": "memfile", "persist": false },
    "subnet4": [
      { "id": 1, "subnet": "192.0.2.0/24", "pools": [ { "pool": "192.0.2.10 - 192.0.2.50" } ], },
    ]
  }
}
"""


def test_extra_commas_match_kea_dash_t(tmp_path):
    binary = find_binary("kea-dhcp4")
    if not binary:
        pytest.skip("kea-dhcp4 not installed")
    path = tmp_path / "kea-dhcp4.conf"
    path.write_text(CONF)
    out = subprocess.run(
        [binary, "-t", str(path)], capture_output=True, text=True, env=kea_env(tmp_path), check=False
    )
    assert out.returncode == 0, out.stdout + out.stderr
    kea = [
        (int(m["line"]), int(m["col"]))
        for m in map(WARNING.search, (out.stdout + out.stderr).splitlines())
        if m
    ]
    ours = [(w["line"], w["column"]) for w in KeaDocument(path).syntax_warnings()]
    assert kea and ours == kea
