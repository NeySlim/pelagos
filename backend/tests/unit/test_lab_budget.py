# SPDX-License-Identifier: Apache-2.0
"""The lab VM budget guard (scripts/lab/vm_budget.py) and its use by rollback.sh."""

from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

SCRIPTS = Path(__file__).resolve().parents[3] / "scripts" / "lab"
_spec = importlib.util.spec_from_file_location("vm_budget", SCRIPTS / "vm_budget.py")
assert _spec and _spec.loader
vm_budget = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(vm_budget)

GW, DEV = 9001, 9002


def vm(vmid: int, status: str = "running", pool: str = "pelagos") -> dict:
    return {"vmid": vmid, "name": f"vm{vmid}", "status": status, "pool": pool, "node": "pve"}


def fleet(running: int) -> list[dict]:
    """Gateway and dev VM running, `running` test VMs running, one stopped test VM 9100."""
    base = [vm(GW), vm(DEV), vm(9100, "stopped"), vm(8000, pool="other")]
    return [*base, *(vm(9200 + i) for i in range(running))]


def test_check_counts_only_test_vms_of_the_pool():
    ok, msg = vm_budget.check(fleet(9), [9100], 10, "pelagos", {GW, DEV})
    assert ok, msg
    ok, msg = vm_budget.check(fleet(10), [9100], 10, "pelagos", {GW, DEV})
    assert not ok
    assert "PELAGOS_LAB_MAX_VMS=10" in msg and "10 test VMs running" in msg


def test_check_ignores_running_and_infra_targets():
    assert vm_budget.check(fleet(10), [9200, GW], 10, "pelagos", {GW, DEV})[0]


def test_check_counts_every_target_to_start():
    resources = [*fleet(8), vm(9101, "stopped")]
    assert not vm_budget.check(resources, [9100, 9101, 9102], 10, "pelagos", {GW, DEV})[0]


def test_without_infra_config_everything_counts(monkeypatch, tmp_path):
    monkeypatch.delenv("PELAGOS_LAB_INFRA_VMIDS", raising=False)
    monkeypatch.setenv("PVE_CONF_DIR", str(tmp_path))
    assert vm_budget.infra_vmids() is None
    (tmp_path / "infra-vmids").write_text(f"{GW}\n{DEV}\n")
    assert vm_budget.infra_vmids() == {GW, DEV}
    monkeypatch.setenv("PELAGOS_LAB_INFRA_VMIDS", "1,2")
    assert vm_budget.infra_vmids() == {1, 2}


class FakePve:
    """Minimal Proxmox API: cluster resources plus a log of every other request."""

    def __init__(self, resources: list[dict]) -> None:
        self.calls: list[str] = []
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def _reply(self) -> None:
                fake.calls.append(f"{self.command} {self.path}")
                data = fake.resources if self.path.startswith("/cluster/resources") else None
                body = json.dumps({"data": data}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            do_GET = do_POST = do_PUT = _reply  # noqa: N815 - http.server handler names

            def log_message(self, *args: object) -> None:
                pass

        self.resources = resources
        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()


@pytest.fixture
def pve(tmp_path) -> Iterator[FakePve]:
    resources = [vm(GW), vm(DEV), vm(9111, "stopped"), *(vm(9200 + i) for i in range(10))]
    fake = FakePve(resources)
    (tmp_path / "pve-token").write_text("PVEAPIToken=test\n")
    (tmp_path / "infra-vmids").write_text(f"{GW} {DEV}\n")
    yield fake
    fake.server.shutdown()


@pytest.mark.skipif(not (shutil.which("jq") and shutil.which("curl")), reason="rollback.sh needs curl and jq")
def test_rollback_refused_before_any_change(pve, tmp_path):
    env = {"PATH": "/usr/bin:/bin", "HOME": str(tmp_path), "PVE_CONF_DIR": str(tmp_path), "PVE_API": pve.url}
    res = subprocess.run(
        [str(SCRIPTS / "rollback.sh"), "9111", "--no-wait"],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert res.returncode == 3, res
    assert "lab budget exceeded" in res.stderr
    assert not [c for c in pve.calls if not c.startswith("GET /cluster/resources")], pve.calls

    res = subprocess.run(
        [str(SCRIPTS / "vm_budget.py"), "check", "9111"],
        env={**env, "PELAGOS_LAB_MAX_VMS": "11"},
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert res.returncode == 0, res


@pytest.mark.skipif(not (shutil.which("jq") and shutil.which("curl")), reason="rollback.sh needs curl and jq")
def test_rollback_unknown_vm_fails_cleanly(pve, tmp_path):
    env = {"PATH": "/usr/bin:/bin", "HOME": str(tmp_path), "PVE_CONF_DIR": str(tmp_path), "PVE_API": pve.url}
    res = subprocess.run(
        [str(SCRIPTS / "rollback.sh"), "typo", "--no-wait"],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert res.returncode == 1, res
    assert "unknown VM typo" in res.stderr and "Traceback" not in res.stderr
    assert not pve.calls


def test_check_rejects_non_integer_vmids(capsys):
    assert vm_budget.main(["check", ""]) == 2
    assert vm_budget.main(["check", "9111", "lab-ns1"]) == 2
    assert "must be integers" in capsys.readouterr().err


def test_pve_vm_start_refused_above_budget(pve, tmp_path, monkeypatch):
    from tests.lab import labkit

    conf = tmp_path / ".config" / "pelagos-lab"
    conf.mkdir(parents=True)
    (conf / "pve-token").write_text("PVEAPIToken=test\n")
    (conf / "pve-api").write_text(pve.url + "\n")
    (conf / "infra-vmids").write_text(f"{GW} {DEV}\n")
    monkeypatch.setenv("HOME", str(tmp_path))
    unset = ("PVE_API", "PVE_CONF_DIR", "PVE_TOKEN_FILE", "PELAGOS_LAB_INFRA_VMIDS", "PELAGOS_LAB_MAX_VMS")
    for var in unset:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("PELAGOS_LAB_POOL", "pelagos")
    # Like the CI image: no python3 on PATH, the helper runs with the test interpreter.
    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.setattr(labkit, "wait_for", lambda *a, **k: pytest.fail("start was not refused"))
    with pytest.raises(AssertionError, match="lab budget exceeded"):
        labkit.pve_vm(9111, "start")
    assert not [c for c in pve.calls if not c.startswith("GET /cluster/resources")], pve.calls
