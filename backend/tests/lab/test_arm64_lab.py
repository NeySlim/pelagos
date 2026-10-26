# SPDX-License-Identifier: Apache-2.0
"""arm64 delivery on lab-arm64, an amd64 VM with qemu: the arm64 deb is built from this checkout
in an emulated Debian 13 container (packaging/deb/container-build.sh, qemu-user), then installed
and started on a Debian 13 arm64 VM under qemu-system, next to BIND and Kea 2.6 from Debian
(packaging/tests/deb-systemd-smoke.sh). This is the CI fallback when no arm runner is available.
lab-arm64 starts from its `emul` snapshot (docker, qemu, cloud image cached) and is rolled back at
the end unless PELAGOS_LAB_KEEP=1."""

from __future__ import annotations

import pytest

from tests.lab import labkit
from tests.lab.labkit import ssh

pytestmark = pytest.mark.lab

HOST = labkit.ARM64[1]


@pytest.fixture(scope="module")
def arm64_host():
    labkit.rollback("lab-arm64")
    labkit.frontend_dist()
    src = labkit.upload_source(HOST)
    yield src
    if not labkit.keep():
        labkit.rollback("lab-arm64")


def test_1_build_the_arm64_deb_under_emulation(arm64_host):
    _, out, _ = ssh(HOST, f"cd {arm64_host} && packaging/deb/container-build.sh arm64 2>&1", timeout=3500)
    assert "build host: aarch64, dpkg arm64" in out, out[-4000:]
    _, info, _ = ssh(HOST, f"dpkg-deb -f {arm64_host}/build/deb/pelagos_*_arm64.deb Architecture Depends")
    assert "Architecture: arm64" in info and "python3.13" in info, info


def test_2_install_and_start_on_an_arm64_vm(arm64_host):
    _, out, _ = ssh(
        HOST,
        f"cd {arm64_host} && SMOKE_MODE=vm packaging/tests/deb-systemd-smoke.sh "
        "build/deb/pelagos_*_arm64.deb 2>&1",
        check=False,
        timeout=3500,
    )
    assert "all checks passed (arm64, vm)" in out, out[-6000:]
    assert "ok:   runs on aarch64" in out
    assert "ok:   Kea 2.6 resolved the bare hook names in /usr/lib/aarch64-linux-gnu/kea/hooks" in out
