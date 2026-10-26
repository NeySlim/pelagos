# SPDX-License-Identifier: Apache-2.0
"""Docker delivery on lab-docker: the node image is built from this checkout, docker/compose.yaml
comes up next to the ISC BIND and Kea images (packaging/tests/compose-smoke.sh), and lab-dev
reaches /api/v1/health over HTTPS. lab-docker starts from its `docker` snapshot (engine and ISC
images present) and is rolled back at the end unless PELAGOS_LAB_KEEP=1."""

from __future__ import annotations

import pytest

from tests.lab import labkit
from tests.lab.labkit import Api, ssh, wait_for

pytestmark = pytest.mark.lab

HOST = labkit.DOCKER[1]


@pytest.fixture(scope="module")
def docker_host():
    labkit.rollback("lab-docker")
    yield HOST
    if not labkit.keep():
        labkit.rollback("lab-docker")


def test_compose_stack_serves_health(docker_host):
    labkit.frontend_dist()
    src = labkit.upload_source(docker_host)
    ssh(
        docker_host,
        f"cd {src} && docker build -q -f docker/Dockerfile -t pelagos:latest . >/tmp/docker-build.log 2>&1 "
        "|| (tail -40 /tmp/docker-build.log; exit 1)",
        timeout=2400,
    )
    # The smoke script checks health, rndc, the statistics channel and both Kea sockets inside.
    _, out, _ = ssh(
        docker_host,
        f"cd {src} && KEEP=1 BIND_DNS_PORT=5300 PELAGOS_HTTPS_PORT=8443 "
        "bash packaging/tests/compose-smoke.sh pelagos:latest",
        timeout=1200,
    )
    assert "all checks passed" in out, out
    health = wait_for("health from lab-dev", lambda: Api(docker_host).get("/health"), timeout=120)
    assert health["status"] == "ok" and health["replication"] == "ready"
    version = Api(docker_host).get("/version")
    assert version["api"] == "v1"
    ssh(
        docker_host,
        "for p in $(docker compose ls -a -q | grep '^pelagos-smoke-'); do "
        "docker compose -p $p down -v --remove-orphans >/dev/null 2>&1; done; true",
    )


def test_deb_starts_in_a_systemd_container(docker_host):
    """Container mode of the deb smoke test (the amd64 CI job): privileged Debian 13 with systemd,
    BIND and Kea 2.6 from Debian, the hardened units, import and API."""
    labkit.frontend_dist()
    src = labkit.upload_source(docker_host, "~/pelagos-deb-src")
    ssh(
        docker_host,
        f"cd {src} && packaging/deb/container-build.sh amd64 >/tmp/deb-build.log 2>&1",
        timeout=2400,
    )
    _, out, _ = ssh(
        docker_host,
        f"cd {src} && SMOKE_MODE=container packaging/tests/deb-systemd-smoke.sh "
        "build/deb/pelagos_*_amd64.deb 2>&1",
        check=False,
        timeout=1800,
    )
    assert "all checks passed (amd64, container)" in out, out[-6000:]
    assert "systemd: running" in out
    assert "ok:   Kea 2.6 resolved the bare hook names in /usr/lib/x86_64-linux-gnu/kea/hooks" in out
