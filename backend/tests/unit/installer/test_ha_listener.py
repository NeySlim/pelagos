# SPDX-License-Identifier: Apache-2.0
"""The Kea HA listener in the security audit: finding, firewall guards it recognizes, remediation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pelagos.domain import JobState, Severity
from pelagos.installer import ha_listener, keaconf
from pelagos.installer.jobs import apply_plan
from pelagos.installer.security_audit import build_security_plan, run_audit
from pelagos.platform import CommandResult
from tests.unit.installer.fakes import make_env

pytestmark = pytest.mark.unit

FID = "kea:kea_ha_listener_open:kea4:192.0.2.11:8001"


def ha_dhcp4(me: str = "server1", host: str = "192.0.2.11", peer: str = "192.0.2.12", **rel: object) -> dict:
    def url(a: str) -> str:
        return f"http://[{a}]:8001/" if ":" in a else f"http://{a}:8001/"

    ha = {
        "this-server-name": me,
        "mode": "hot-standby",
        "peers": [
            {"name": "server1", "url": url(host), "role": "primary"},
            {"name": "server2", "url": url(peer), "role": "standby"},
        ],
        **rel,
    }
    return {
        "Dhcp4": {
            "interfaces-config": {"interfaces": []},
            "control-socket": {"socket-type": "unix", "socket-name": "kea4-ctrl-socket"},
            "hooks-libraries": [
                {"library": "/usr/lib/kea/hooks/libdhcp_lease_cmds.so"},
                {"library": "/usr/lib/kea/hooks/libdhcp_ha.so", "parameters": {"high-availability": [ha]}},
            ],
            "subnet4": [],
        }
    }


# The prod guard as `nft -j list ruleset` prints it (captured from nft 1.1.3 on Debian 13).
PROD_GUARD = {
    "nftables": [
        {"metainfo": {"version": "1.1.3", "json_schema_version": 1}},
        {"table": {"family": "inet", "name": "kea_ha_guard", "handle": 1}},
        {
            "chain": {
                "family": "inet",
                "table": "kea_ha_guard",
                "name": "input",
                "handle": 1,
                "type": "filter",
                "hook": "input",
                "prio": 0,
                "policy": "accept",
            }
        },
        {
            "rule": {
                "family": "inet",
                "table": "kea_ha_guard",
                "chain": "input",
                "expr": [
                    {
                        "match": {
                            "op": "==",
                            "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                            "right": 8001,
                        }
                    },
                    {
                        "match": {
                            "op": "==",
                            "left": {"payload": {"protocol": "ip", "field": "saddr"}},
                            "right": "192.0.2.12",
                        }
                    },
                    {"accept": None},
                ],
            }
        },
        {
            "rule": {
                "family": "inet",
                "table": "kea_ha_guard",
                "chain": "input",
                "expr": [
                    {
                        "match": {
                            "op": "==",
                            "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                            "right": 8001,
                        }
                    },
                    {"match": {"op": "==", "left": {"meta": {"key": "iif"}}, "right": "lo"}},
                    {"accept": None},
                ],
            }
        },
        {
            "rule": {
                "family": "inet",
                "table": "kea_ha_guard",
                "chain": "input",
                "expr": [
                    {
                        "match": {
                            "op": "==",
                            "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                            "right": 8001,
                        }
                    },
                    {"drop": None},
                ],
            }
        },
    ]
}

IPTABLES_GUARD = """*filter
:INPUT ACCEPT [0:0]
-A INPUT -s 192.0.2.12/32 -p tcp -m tcp --dport 8001 -j ACCEPT
-A INPUT -p tcp -m multiport --dports 8001,8002 -j DROP
COMMIT
"""


def _env(tmp_path: Path, config: dict, version: str = "2.6.3", nft: bool = True):
    env = make_env(tmp_path, kea_version=version)
    env.binaries.update(
        {"nft": "/usr/sbin/nft" if nft else None, "iptables-save": None, "ip6tables-save": None}
    )
    d = tmp_path / "etc/kea"
    d.mkdir(parents=True, exist_ok=True)
    (d / "kea-dhcp4.conf").write_text(json.dumps(config, indent=2))
    return env


def _ruleset(env, doc: dict) -> None:
    env.runner.responses["nft -j list ruleset"] = json.dumps(doc)


def _ha(env) -> list:
    return [f for f in run_audit(env) if f.kind == "kea_ha_listener_open"]


def test_listener_parsing_follows_kea_defaults():
    cfg = ha_dhcp4()
    (lst,) = ha_listener.listeners("kea4", cfg, "2.6.3")
    assert (lst.host, lst.port, lst.server, lst.peers) == ("192.0.2.11", 8001, "server1", ["192.0.2.12"])
    assert lst.open and not lst.tls and not lst.restrict_commands  # 2.6: restrict-commands defaults false
    assert ha_listener.listeners("kea4", cfg, "3.0.0")[0].restrict_commands  # default true since 3.0.0
    assert not ha_listener.listeners("kea4", ha_dhcp4(host="127.0.0.1"), "2.6.3")[0].open
    tls = {"trust-anchor": "/etc/kea/ca.pem", "cert-file": "/etc/kea/c.pem", "key-file": "/etc/kea/k.pem"}
    assert not ha_listener.listeners("kea4", ha_dhcp4(**tls), "2.6.3")[0].open
    assert ha_listener.listeners("kea4", ha_dhcp4(**tls, **{"require-client-certs": False}), "2.6.3")[0].open
    # Without HA+MT the HA traffic goes through kea-ctrl-agent: no dedicated listener.
    assert (
        ha_listener.listeners(
            "kea4", ha_dhcp4(**{"multi-threading": {"enable-multi-threading": False}}), "2.6.3"
        )
        == []
    )
    no_core_mt = ha_dhcp4()
    no_core_mt["Dhcp4"]["multi-threading"] = {"enable-multi-threading": False}
    assert ha_listener.listeners("kea4", no_core_mt, "2.6.3") == []
    v6 = ha_dhcp4(host="2001:db8::11", peer="2001:db8::12")
    assert ha_listener.listeners("kea6", {"Dhcp6": v6["Dhcp4"]}, "3.2.0")[0].address == "[2001:db8::11]:8001"


def test_open_listener_is_critical_and_remediable(tmp_path):
    env = _env(tmp_path, ha_dhcp4())
    (f,) = _ha(env)
    assert f.id == FID and f.severity is Severity.CRITICAL
    out = f.to_dict()
    assert out["remediable"] and not out["mitigated"]
    assert (
        "every command" in f.description and "192.0.2.12" in f.proposal and "restrict-commands" in f.proposal
    )
    assert "standby (or secondary) first" in f.proposal


def test_restricted_listener_still_open(tmp_path):
    env = _env(tmp_path, ha_dhcp4(), version="3.2.0")
    (f,) = _ha(env)
    assert f.severity is Severity.CRITICAL and "dhcp-disable" in f.description
    assert "Set restrict-commands" not in f.proposal  # already the default


@pytest.mark.parametrize("source", ["nft", "iptables"])
def test_existing_guard_mitigates(tmp_path, source):
    env = _env(tmp_path, ha_dhcp4())
    if source == "nft":
        _ruleset(env, PROD_GUARD)
    else:
        env.binaries["iptables-save"] = "/usr/sbin/iptables-save"
        env.runner.responses["iptables-save"] = IPTABLES_GUARD
    (f,) = _ha(env)
    assert f.severity is Severity.WARNING
    assert f.details["mitigated"] and f.details["guard_allowed"] == (
        ["192.0.2.12"] if source == "nft" else ["192.0.2.12/32"]
    )
    assert "mitigated" in f.description
    assert f.to_dict()["remediable"]  # restrict-commands is still false on 2.6
    restricted = _env(tmp_path / "b", ha_dhcp4(**{"restrict-commands": True}))
    _ruleset(restricted, PROD_GUARD)
    (g,) = _ha(restricted)
    assert not g.to_dict()["remediable"] and "TLS" in g.to_dict()["manual_action"]


def test_rules_that_do_not_guard(tmp_path):
    env = _env(tmp_path, ha_dhcp4())
    accept_all = json.loads(json.dumps(PROD_GUARD))
    accept_all["nftables"] = [*accept_all["nftables"][:3], accept_all["nftables"][4]]  # no drop rule
    _ruleset(env, accept_all)
    assert _ha(env)[0].severity is Severity.CRITICAL
    other_port = json.loads(json.dumps(PROD_GUARD).replace("8001", "9001"))
    _ruleset(env, other_port)
    assert not _ha(env)[0].details["mitigated"]
    policy_drop = {
        "nftables": [
            {
                "chain": {
                    "family": "inet",
                    "table": "filter",
                    "name": "input",
                    "hook": "input",
                    "policy": "drop",
                }
            },
            PROD_GUARD["nftables"][3],
        ]
    }
    assert ha_listener.nft_guard(policy_drop, 8001) is not None
    assert ha_listener.iptables_guard("-A INPUT -p tcp --dport 8001 -j ACCEPT\n", 8001) is None


def test_active_guard_unit_counts_when_rules_unreadable(tmp_path):
    env = _env(tmp_path, ha_dhcp4(), nft=False)
    env.services.active.add("kea-ha-guard.service")
    (f,) = _ha(env)
    assert f.details["mitigated"] and f.details["guard"] == "service kea-ha-guard.service"


class Counters:
    """`nft -j list table` answers whose counters move like a peer's heartbeats (or a blocked peer)."""

    def __init__(self, peer_gets_through: bool) -> None:
        self.calls = 0
        self.through = peer_gets_through

    def __call__(self, argv: list[str]) -> CommandResult:
        self.calls += 1
        acc, drop = (self.calls, 0) if self.through else (0, self.calls)
        rules = [
            {"rule": {"expr": [{"counter": {"packets": acc}}, {"accept": None}]}},
            {"rule": {"expr": [{"counter": {"packets": drop}}, {"drop": None}]}},
        ]
        return CommandResult(argv, 0, json.dumps({"nftables": rules}), "")


def _fix(env, through: bool):
    env.runner.responses["nft -j list table inet pelagos_kea_ha_guard"] = Counters(through)
    return apply_plan(build_security_plan(env, [FID]), env)


def test_remediation_restricts_then_guards(tmp_path, monkeypatch):
    from pelagos.installer import security_audit

    monkeypatch.setattr(security_audit, "_sleep", lambda s: None)
    env = _env(tmp_path, ha_dhcp4())
    job = _fix(env, through=True)
    assert job.state is JobState.DONE, job.error
    cfg = keaconf.loads((tmp_path / "etc/kea/kea-dhcp4.conf").read_text())
    rel = cfg["Dhcp4"]["hooks-libraries"][1]["parameters"]["high-availability"][0]
    assert rel["restrict-commands"] is True
    rules = (env.node_paths.etc / ha_listener.GUARD_FILE).read_text()
    assert "ip saddr { 192.0.2.12 } tcp dport { 8001 } counter accept" in rules
    assert "tcp dport { 8001 } counter drop" in rules
    unit = (env.paths.systemd_dir / ha_listener.GUARD_UNIT).read_text()
    assert f"ExecStart=/usr/sbin/nft -f {env.node_paths.etc / ha_listener.GUARD_FILE}" in unit
    assert ("enable_now", ha_listener.GUARD_UNIT) in env.services.calls
    assert "peer traffic seen" in json.dumps(job.steps)


def test_guard_removed_when_peer_is_blocked(tmp_path, monkeypatch):
    from pelagos.installer import security_audit

    monkeypatch.setattr(security_audit, "_sleep", lambda s: None)
    monkeypatch.setattr(ha_listener.time, "monotonic", iter(range(0, 1000, 10)).__next__)
    env = _env(tmp_path, ha_dhcp4(**{"restrict-commands": True}))
    job = _fix(env, through=False)
    assert job.state is JobState.FAILED and "guard removed" in (job.error or "")
    assert not (env.node_paths.etc / ha_listener.GUARD_FILE).exists()
    assert not (env.paths.systemd_dir / ha_listener.GUARD_UNIT).exists()
    assert ("disable_now", ha_listener.GUARD_UNIT) in env.services.calls
    assert ["/usr/sbin/nft", "delete", "table", "inet", ha_listener.GUARD_TABLE] in env.runner.log


def test_mitigated_finding_raises_no_alert():
    from pelagos.collector.security import security_outcome

    base = {"id": FID, "kind": "kea_ha_listener_open", "engine": "kea", "subject": "s", "description": "d"}
    assert len(security_outcome([{**base, "mitigated": False}], "n1").alerts) == 1
    assert security_outcome([{**base, "mitigated": True}], "n1").alerts == []
