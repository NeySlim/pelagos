# SPDX-License-Identifier: Apache-2.0
"""Partial apply on the reference pair with ns2 powered off (B1-KEAOFFLINE, run before merge).

Starts from the pair test_pair_lab leaves running (lab-ns1, lab-ns2 with Pelagos, Kea 2.6.3 HA
hot-standby from Debian 13, lab-client on the DHCP segment): run `PELAGOS_LAB_KEEP=1 pytest
tests/lab/test_pair_lab.py` first. lab-ns2 is powered off through the Proxmox API (pve_vm), not
only its Kea. lab-client runs dhcp_probe.py in a loop (INIT-REBOOT every second) during the partial
apply: the DHCP gap of the survivor (Kea 2.6: config-set, HA back to waiting) is measured and
printed for docs/user/dhcp.md. Steps: node_unreachable, partial apply, alert, ns2 back and writes
refused, reconcile, config-get identical, rollback of the reconciled partial refused, the pair back
in hot-standby without ha_terminated. The pair is left as it ends.
"""

from __future__ import annotations

import itertools
import json
import time
from pathlib import Path
from typing import Any

import pytest

from tests.lab.labkit import CLIENT, NS1, NS2, Api, ApiError, pve_vm, scp, ssh, wait_for

pytestmark = pytest.mark.lab

A1, A2 = NS1[1], NS2[1]
NS2_VMID = 9112
IFACE = "ens19"
MAC_LOOP = "02:00:00:00:0b:01"
PROBE = Path(__file__).with_name("dhcp_probe.py")
SUBNET = {"id": 77, "subnet": "10.99.77.0/24", "pools": [{"pool": "10.99.77.10 - 10.99.77.20"}]}
STATE: dict[str, Any] = {}


def api(address: str) -> Api:
    key = f"api:{address}"
    if key not in STATE:
        client = Api(address)
        wait_for(f"{address} login", lambda: client.login(), timeout=300, interval=5)
        STATE[key] = client
    return STATE[key]  # type: ignore[return-value]


def ids() -> dict[str, str]:
    if "ids" not in STATE:
        STATE["ids"] = {n["peer"]["name"]: n["peer"]["id"] for n in api(A1).get("/nodes")["items"]}
    return STATE["ids"]


def ha_state(host: str) -> str:
    cmd = json.dumps({"command": "ha-heartbeat"})
    out = ssh(host, f"echo '{cmd}' | sudo socat - UNIX-CONNECT:/run/kea/kea4-ctrl-socket", check=False)[1]
    try:
        return str(json.loads(out)["arguments"]["state"])
    except (ValueError, KeyError, TypeError):
        return "unknown"


def config_alert() -> dict | None:
    items = api(A1).get("/alerts?state=open&kind=config_divergence")["items"]
    return next((a for a in items if a["subject"] == "kea4:config-hash"), None)


def subnet_plan(sid: int) -> dict:
    change = {"op": "add", "target": f"subnet4/{sid}", "after": {**SUBNET, "id": sid}}
    return api(A1).post("/dhcp/v4/subnets/plan", {"change": change})


class Probe:
    """dhcp_probe.py on lab-client: one INIT-REBOOT a second, logged as JSON lines."""

    unit = "pelagos-probe-offline"

    def start(self, ip: str) -> None:
        ssh(
            CLIENT[0],
            f"sudo systemctl stop {self.unit} 2>/dev/null; sudo rm -f /tmp/{self.unit}.log",
            check=False,
        )
        ssh(
            CLIENT[0],
            f"sudo systemd-run --unit {self.unit} -p StandardOutput=file:/tmp/{self.unit}.log"
            f" python3 /tmp/dhcp_probe.py loop {IFACE} {MAC_LOOP} {ip} 900",
        )

    def stop(self) -> list[dict]:
        ssh(CLIENT[0], f"sudo systemctl stop {self.unit}", check=False)
        out = ssh(CLIENT[0], f"cat /tmp/{self.unit}.log")[1]
        return [json.loads(x) for x in out.splitlines() if x.strip()]


def longest_gap(lines: list[dict]) -> float:
    """Longest run of seconds without an ACK."""
    acks = [x["t"] for x in lines if x.get("result") == "ack"]
    return max((b - a for a, b in itertools.pairwise(acks)), default=0.0)


class TestKeaHaOffline:
    def test_00_reference_pair_is_up(self):
        assert {"ns1", "ns2"} <= set(ids())
        wait_for(
            "hot-standby", lambda: ha_state(A1) == ha_state(A2) == "hot-standby", timeout=180, interval=5
        )
        scp(CLIENT[0], PROBE, "/tmp/dhcp_probe.py")
        STATE["ip"] = ssh(CLIENT[0], f"sudo python3 /tmp/dhcp_probe.py get {IFACE} {MAC_LOOP}", timeout=120)[
            1
        ].strip()
        assert STATE["ip"].startswith("10.99.1."), STATE

    def test_01_ns2_powered_off_apply_answers_node_unreachable(self):
        pve_vm(NS2_VMID, "stop")
        wait_for("ns1 sees its partner lost", lambda: ha_state(A1) == "partner-down", timeout=300, interval=5)
        plan = subnet_plan(SUBNET["id"])
        STATE["plan"] = plan
        with pytest.raises(ApiError) as exc:
            api(A1).post(f"/plans/{plan['id']}/apply", {"confirm": True})
        body = exc.value.body
        assert exc.value.status == 409 and body["code"] == "node_unreachable", body
        assert body["partial_allowed"] is True and body["node_names"] == ["ns2"], body
        assert body["nodes"] == [{"node_id": ids()["ns2"], "reason": "unreachable"}], body

    def test_02_partial_subnet_on_ns1_and_dhcp_gap_measured(self):
        probe = Probe()
        probe.start(STATE["ip"])
        time.sleep(10)
        plan = STATE["plan"]
        result = api(A1).post(f"/plans/{plan['id']}/apply", {"confirm": True, "partial": True}, timeout=600)
        assert result["state"] == "applied", result
        stored = api(A1).get(f"/plans/{plan['id']}")
        assert stored["partial"] is True and stored["skipped_node_ids"] == [ids()["ns2"]], stored
        assert any(i["kind"] == "ha_restart" for i in stored["impact"]), stored["impact"]
        wait_for("ns1 back in partner-down", lambda: ha_state(A1) == "partner-down", timeout=300, interval=2)
        time.sleep(15)
        gap = longest_gap(probe.stop())
        STATE["gap"] = gap
        print(f"DHCP gap on the survivor during the partial apply: {gap:.1f} s")
        assert gap < 180, gap

    def test_03_divergence_alert_names_the_plan(self):
        alert = wait_for("config_divergence with the partial", config_alert, timeout=120, interval=5)
        assert alert["severity"] == "warning", alert
        plans = alert["details"]["expected_from_plan"][0]["plans"]
        assert plans[0]["plan_id"] == STATE["plan"]["id"], alert
        assert alert["details"]["reconcile"] == [
            {"source_node_id": ids()["ns1"], "target_node_id": ids()["ns2"]}
        ]

    def test_04_ns2_powered_on_writes_answer_reconcile_required(self):
        pve_vm(NS2_VMID, "start")
        wait_for("ns2 answers", lambda: api(A2).get("/nodes") is not None, timeout=600, interval=10)
        wait_for(
            "alert critical once ns2 is back",
            lambda: (config_alert() or {}).get("severity") == "critical",
            timeout=300,
            interval=10,
        )
        with pytest.raises(ApiError) as exc:
            subnet_plan(SUBNET["id"] + 1)
        assert exc.value.status == 409 and exc.value.body["code"] == "reconcile_required", exc.value.body
        STATE["ha_after_return"] = (ha_state(A1), ha_state(A2))
        print(f"HA states after ns2 came back, before reconciliation: {STATE['ha_after_return']}")

    def test_05_reconcile_from_ns1_then_config_get_identical(self):
        body = {"source_node_id": ids()["ns1"], "target_node_id": ids()["ns2"]}
        plan = api(A1).post("/dhcp/v4/config/reconcile/plan", body)
        assert plan["requires_confirmation"] and "reconcile" in plan["requires_confirmation_reasons"], plan
        assert api(A1).apply(plan)["state"] == "applied"
        subnets = {
            n: {s["id"] for s in api(A1).get(f"/dhcp/v4/subnets?node_id={ids()[n]}")["items"]}
            for n in ("ns1", "ns2")
        }
        assert SUBNET["id"] in subnets["ns1"] and subnets["ns1"] == subnets["ns2"], subnets
        wait_for("alert closed", lambda: config_alert() is None, timeout=300, interval=10)

    def test_06_rollback_of_the_reconciled_partial_is_refused(self):
        with pytest.raises(ApiError) as exc:
            api(A1).post(f"/plans/{STATE['plan']['id']}/rollback")
        assert exc.value.status == 409 and exc.value.body["code"] == "plan_state", exc.value.body

    def test_07_pair_back_in_hot_standby(self):
        wait_for(
            "hot-standby", lambda: ha_state(A1) == ha_state(A2) == "hot-standby", timeout=300, interval=5
        )
        assert not api(A1).get("/alerts?state=open&kind=ha_terminated")["items"]
        # Clean the lab subnet with a normal plan to both nodes.
        change = {"op": "delete", "target": f"subnet4/{SUBNET['id']}"}
        plan = api(A1).post("/dhcp/v4/subnets/plan", {"change": change})
        assert api(A1).apply(plan)["state"] == "applied"
        print(f"measured: gap {STATE.get('gap')} s, HA after return {STATE.get('ha_after_return')}")
