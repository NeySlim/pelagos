# SPDX-License-Identifier: Apache-2.0
"""The HA listener guard as a managed object (adoption of a hand-made guard, edit by plan) and the
managed_drift findings with their adopt and restore plans."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pelagos.core import ha_maintenance
from pelagos.domain import JobState
from pelagos.installer import drift, ha_guard, ha_listener, keaconf, ledger
from pelagos.installer.jobs import apply_plan
from pelagos.installer.security_audit import build_security_plan, run_audit
from pelagos.platform import CommandResult
from tests.unit.installer.test_ha_listener import PROD_GUARD, _env, ha_dhcp4

pytestmark = pytest.mark.unit

LEGACY_RULES = """#!/usr/sbin/nft -f
table inet kea_ha_guard
delete table inet kea_ha_guard
table inet kea_ha_guard {
\tchain input {
\t\ttype filter hook input priority 0; policy accept;
\t\ttcp dport 8001 ip saddr 192.0.2.12 accept
\t\ttcp dport 8001 iif "lo" accept
\t\ttcp dport 8001 drop
\t}
}
"""
LEGACY_UNIT = """[Unit]
Description=Kea HA listener guard
After=nftables.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f /etc/nftables.d/kea-ha-guard.nft
ExecStop=/usr/sbin/nft delete table inet kea_ha_guard

[Install]
WantedBy=multi-user.target
"""
ADOPT_ID = "kea:kea_ha_guard_unmanaged:kea_ha_guard"
# The negative form a script set up in production (policy accept), as `nft -f` and `nft -j` show it.
NEG_RULES = """table inet kea_ha_guard
delete table inet kea_ha_guard
table inet kea_ha_guard {
\tchain input {
\t\ttype filter hook input priority 0; policy accept;
\t\ttcp dport 8001 ip daddr 192.0.2.11 ip saddr != { 192.0.2.12, 192.0.2.11 } counter drop
\t\ttcp dport { 8001, 8002 } ip6 daddr 2001:db8::11 ip6 saddr != 2001:db8::12 counter drop
\t}
}
"""


def _neg_rule(handle: int, ports: object, fam: str, daddr: str, allowed: object) -> dict:
    expr = [
        {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": ports}},
        {"match": {"op": "==", "left": {"payload": {"protocol": fam, "field": "daddr"}}, "right": daddr}},
        {"match": {"op": "!=", "left": {"payload": {"protocol": fam, "field": "saddr"}}, "right": allowed}},
        {"counter": {"packets": 0, "bytes": 0}},
        {"drop": None},
    ]
    return {
        "rule": {"family": "inet", "table": "kea_ha_guard", "chain": "input", "handle": handle, "expr": expr}
    }


NEG_GUARD = {
    "nftables": [
        {
            "metainfo": {
                "version": "1.1.3",
                "release_name": "Commodore Bullmoose #4",
                "json_schema_version": 1,
            }
        },
        {"table": {"family": "inet", "name": "kea_ha_guard", "handle": 2}},
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
        _neg_rule(3, 8001, "ip", "192.0.2.11", {"set": ["192.0.2.11", "192.0.2.12"]}),
        _neg_rule(5, {"set": [8001, 8002]}, "ip6", "2001:db8::11", "2001:db8::12"),
    ]
}
NEG_PEERS = ["192.0.2.11", "192.0.2.12", "2001:db8::12"]


def _match(field: str, proto: str, right: object) -> dict:
    return {"match": {"op": "==", "left": {"payload": {"protocol": proto, "field": field}}, "right": right}}


def table_doc(table: str, ports: list[int], peers: list[str]) -> dict:
    rules = [
        {
            "rule": {
                "table": table,
                "expr": [
                    _match("saddr", "ip", p),
                    _match("dport", "tcp", port),
                    {"counter": {"packets": 0}},
                    {"accept": None},
                ],
            }
        }
        for p in peers
        for port in ports
    ]
    rules.append(
        {
            "rule": {
                "table": table,
                "expr": [
                    _match("dport", "tcp", ports[0]),
                    {"counter": {"packets": 0}},
                    {"drop": None},
                ],
            }
        }
    )
    return {"nftables": [{"table": {"family": "inet", "name": table}}, *rules]}


class Host:
    """nft and systemd as far as the guards go: the legacy table until deleted, Pelagos's table loaded
    from its rules file while its unit is active."""

    def __init__(self, env, legacy: bool = True, doc: dict = PROD_GUARD, rules: str = LEGACY_RULES) -> None:
        self.env = env
        self.doc = doc
        self.legacy_loaded = legacy
        env.runner.responses["nft -j list ruleset"] = lambda argv: CommandResult(argv, 0, "", "")
        env.runner.responses["nft -j list table inet kea_ha_guard"] = self.list_legacy
        env.runner.responses["nft -j list table inet pelagos_kea_ha_guard"] = self.list_mine
        env.runner.responses["/usr/sbin/nft delete table inet kea_ha_guard"] = self.delete_legacy
        if legacy:
            root = Path(env.paths.root)
            (root / "etc/nftables.d").mkdir(parents=True, exist_ok=True)
            (root / ha_guard.LEGACY_RULES).write_text(rules)
            env.paths.systemd_dir.mkdir(parents=True, exist_ok=True)
            (env.paths.systemd_dir / ha_guard.LEGACY_UNIT).write_text(
                LEGACY_UNIT.replace("/etc/nftables.d", str(root / "etc/nftables.d"))
            )
            env.services.active.add(ha_guard.LEGACY_UNIT)

    def list_legacy(self, argv):
        return CommandResult(argv, 0, json.dumps(self.doc) if self.legacy_loaded else "", "")

    def delete_legacy(self, argv):
        self.legacy_loaded = False
        return CommandResult(argv, 0, "", "")

    def list_mine(self, argv):
        rules = ha_guard.rules_path(self.env)
        if ha_listener.GUARD_UNIT not in self.env.services.active or not rules.exists():
            return CommandResult(argv, 1, "", "No such file or directory")
        st = ha_guard.parse_text(rules.read_text())
        return CommandResult(argv, 0, json.dumps(table_doc(ha_listener.GUARD_TABLE, st.ports, st.peers)), "")


@pytest.fixture
def quick(monkeypatch):
    monkeypatch.setattr(ha_guard, "_sleep", lambda s: None)
    monkeypatch.setattr(ha_listener.time, "monotonic", iter(range(0, 100000, 10)).__next__)


def _kinds(env) -> dict[str, list]:
    out: dict[str, list] = {}
    for f in run_audit(env):
        out.setdefault(f.kind, []).append(f)
    return out


def test_normalize_peers():
    assert ha_guard.normalize_peers(["192.0.2.13", "192.0.2.12/32", "2001:db8::1", "198.51.100.0/24"]) == [
        "192.0.2.12",
        "192.0.2.13",
        "198.51.100.0/24",
        "2001:db8::1",
    ]
    for bad in ([], ["192.0.2.1; flush ruleset"], ["ns2"], [""], "192.0.2.1"):
        with pytest.raises(ValueError):
            ha_guard.normalize_peers(bad)


def test_tables_and_text_parse_alike():
    assert ha_guard.parse_table(PROD_GUARD, "kea_ha_guard").peers == ["192.0.2.12"]
    assert ha_guard.parse_table(PROD_GUARD, "kea_ha_guard").ports == [8001]
    text = ha_listener.render_guard([8001, 8002], ["192.0.2.12", "2001:db8::12", "198.51.100.0/24"])
    st = ha_guard.parse_text(text)
    assert st.ports == [8001, 8002] and st.peers == ["192.0.2.12", "198.51.100.0/24", "2001:db8::12"]


def test_negative_form_is_read_from_json_and_text():
    for st in (ha_guard.parse_table(NEG_GUARD, "kea_ha_guard"), ha_guard.parse_text(NEG_RULES)):
        assert st.ports == [8001, 8002] and st.peers == NEG_PEERS
    # Neither a deny list nor a negated accept admits anything.
    other = "tcp dport 8001 ip saddr 198.51.100.7 drop\ntcp dport 8001 ip saddr != 198.51.100.8 accept\n"
    assert ha_guard.parse_text(other).peers == []


def test_negative_hand_made_guard_is_adopted_with_its_addresses(tmp_path, quick):
    env = _env(tmp_path, ha_dhcp4())
    host = Host(env, doc=NEG_GUARD, rules=NEG_RULES)
    (found,) = _kinds(env)["kea_ha_guard_unmanaged"]
    assert found.details["peers"] == NEG_PEERS and found.details["ports"] == [8001, 8002]
    assert found.details["remediable"] and "?" not in found.description
    job = apply_plan(build_security_plan(env, [ADOPT_ID]), env)
    assert job.state is JobState.DONE, job.error
    assert not host.legacy_loaded
    status = ha_guard.status(env)
    assert status["legacy"] is None and status["managed"]["peers"] == NEG_PEERS
    assert status["managed"]["ports"] == [8001, 8002] and status["differences"] == []
    text = ha_guard.rules_path(env).read_text()
    assert "ip saddr { 192.0.2.11, 192.0.2.12 }" in text and "ip6 saddr { 2001:db8::12 }" in text


def test_hand_made_guard_is_reported_and_adopted(tmp_path, quick):
    env = _env(tmp_path, ha_dhcp4())
    host = Host(env)
    (found,) = _kinds(env)["kea_ha_guard_unmanaged"]
    assert found.id == ADOPT_ID and found.details["peers"] == ["192.0.2.12"] and found.details["remediable"]
    # The listener finding still sees the hand-made guard as a mitigation.
    assert _kinds(env)["kea_ha_listener_open"][0].details["mitigated"]
    job = apply_plan(build_security_plan(env, [ADOPT_ID]), env)
    assert job.state is JobState.DONE, job.error
    assert not host.legacy_loaded
    assert not (env.paths.systemd_dir / ha_guard.LEGACY_UNIT).exists()
    assert not (Path(env.paths.root) / ha_guard.LEGACY_RULES).exists()
    assert ("disable_now", ha_guard.LEGACY_UNIT) in env.services.calls
    # Pelagos's guard was enabled before the old one went: never unguarded.
    calls = env.services.calls
    enabled = calls.index(("enable_now", ha_listener.GUARD_UNIT))
    assert enabled < calls.index(("disable_now", ha_guard.LEGACY_UNIT))
    status = ha_guard.status(env)
    assert status["legacy"] is None and status["managed"]["peers"] == ["192.0.2.12"]
    assert status["loaded"] == {"peers": ["192.0.2.12"], "ports": [8001]} and status["differences"] == []
    backup = Path(status["managed"]["adopted_from"]["backup"])
    assert (backup / "kea-ha-guard.nft").read_text() == LEGACY_RULES
    kinds = _kinds(env)
    assert "kea_ha_guard_unmanaged" not in kinds and "managed_drift" not in kinds
    # Idempotent: a second adoption has nothing left to do.
    assert "already adopted" in ha_guard.adopt(env)


def test_failed_adoption_puts_the_hand_made_guard_back(tmp_path, quick, monkeypatch):
    env = _env(tmp_path, ha_dhcp4())
    host = Host(env)
    monkeypatch.setattr(host, "delete_legacy", lambda argv: CommandResult(argv, 1, "", "busy"))
    env.runner.responses["/usr/sbin/nft delete table inet kea_ha_guard"] = host.delete_legacy
    job = apply_plan(build_security_plan(env, [ADOPT_ID]), env)
    assert job.state is JobState.FAILED and "still loaded" in (job.error or "")
    assert (env.paths.systemd_dir / ha_guard.LEGACY_UNIT).read_text().startswith("[Unit]")
    assert (Path(env.paths.root) / ha_guard.LEGACY_RULES).read_text() == LEGACY_RULES
    assert ha_guard.LEGACY_UNIT in env.services.active and host.legacy_loaded
    assert not ha_guard.rules_path(env).exists() and ledger.get(env, ha_guard.KEY) is None


def test_unsafe_exec_stop_is_never_run(tmp_path, quick):
    env = _env(tmp_path, ha_dhcp4())
    Host(env)
    unit = env.paths.systemd_dir / ha_guard.LEGACY_UNIT
    unit.write_text(unit.read_text().replace("delete table inet kea_ha_guard", "flush ruleset"))
    job = apply_plan(build_security_plan(env, [ADOPT_ID]), env)
    assert job.state is JobState.DONE, job.error
    assert ("disable_now", ha_guard.LEGACY_UNIT) not in env.services.calls


def test_guard_peers_edited_by_plan(tmp_path, quick):
    env = _env(tmp_path, ha_dhcp4())
    Host(env)
    apply_plan(build_security_plan(env, [ADOPT_ID]), env)
    plan = ha_guard.build_plan(env, ["192.0.2.12", "192.0.2.13"], "admin")
    assert plan.changes[0].after["details"]["ports"] == [8001]
    assert "+ 192.0.2.13" in plan.diff
    job = apply_plan(plan, env)
    assert job.state is JobState.DONE, job.error
    assert "ip saddr { 192.0.2.12, 192.0.2.13 }" in ha_guard.rules_path(env).read_text()
    assert ha_guard.status(env)["managed"]["peers"] == ["192.0.2.12", "192.0.2.13"]
    assert "managed_drift" not in _kinds(env)
    with pytest.raises(ValueError):
        ha_guard.build_plan(env, ["192.0.2.12 } accept; tcp dport 22"], "admin")


def test_guard_plan_refused_while_a_hand_made_guard_remains(tmp_path):
    env = _env(tmp_path, ha_dhcp4())
    Host(env)
    with pytest.raises(ValueError, match="adopt it first"):
        ha_guard.build_plan(env, ["192.0.2.12"], "admin")


def _drift(env) -> dict[str, object]:
    return {f.details["object"]: f for f in _kinds(env).get("managed_drift", [])}


def test_guard_drift_restore_and_adopt(tmp_path, quick):
    env = _env(tmp_path, ha_dhcp4())
    Host(env)
    apply_plan(build_security_plan(env, [ADOPT_ID]), env)
    rules = ha_guard.rules_path(env)
    good = rules.read_text()
    rules.write_text(good.replace("192.0.2.12", "192.0.2.99"))
    found = _drift(env)["ha_guard"]
    assert found.details["actions"] == ["adopt", "restore"]
    assert any("content changed" in d for d in found.details["differences"])
    assert any("admits 192.0.2.99" in d for d in found.details["differences"])
    assert found.to_dict()["differences"] == found.details["differences"]
    job = apply_plan(build_security_plan(env, [found.id + "#restore"]), env)
    assert job.state is JobState.DONE, job.error
    assert rules.read_text() == good and "ha_guard" not in _drift(env)
    # Adopt: the node's addresses become Pelagos's.
    rules.write_text(good.replace("192.0.2.12", "192.0.2.99"))
    job = apply_plan(build_security_plan(env, [found.id + "#adopt"]), env)
    assert job.state is JobState.DONE, job.error
    assert ledger.get(env, "ha_guard")["state"]["peers"] == ["192.0.2.99"] and "ha_guard" not in _drift(env)


def _rel(path: Path) -> dict:
    cfg = keaconf.loads(path.read_text())
    return cfg["Dhcp4"]["hooks-libraries"][1]["parameters"]["high-availability"][0]


def _edit(path: Path, fn) -> None:
    cfg = keaconf.loads(path.read_text())
    fn(cfg["Dhcp4"]["hooks-libraries"][1]["parameters"]["high-availability"][0])
    path.write_text(json.dumps(cfg, indent=2))


def test_ha_relationship_drift(tmp_path):
    env = _env(tmp_path, ha_dhcp4(**{"restrict-commands": True}))
    conf = tmp_path / "etc/kea/kea-dhcp4.conf"
    assert "managed_drift" not in _kinds(env)  # first sight: recorded
    assert ledger.get(env, "kea_ha:kea4:server1")["state"]["relationship"]["restrict-commands"] is True

    def by_hand(rel):
        rel["restrict-commands"] = False
        rel["peers"][1]["url"] = "https://192.0.2.12:8001/"

    _edit(conf, by_hand)
    found = _drift(env)["kea_ha:kea4:server1"]
    diffs = found.details["differences"]
    assert "restrict-commands: false (Pelagos: true)" in diffs
    assert 'peer server2 url: "https://192.0.2.12:8001/" (Pelagos: "http://192.0.2.12:8001/")' in diffs
    # A Pelagos write after the difference was reported does not absorb it.
    ha_maintenance.mark(env.node_paths, "kea4", "write")
    assert "kea_ha:kea4:server1" in _drift(env)
    job = apply_plan(build_security_plan(env, [found.id + "#restore"]), env)
    assert job.state is JobState.DONE, job.error
    rel = _rel(conf)
    assert rel["restrict-commands"] is True and rel["peers"][1]["url"] == "http://192.0.2.12:8001/"
    assert "kea_ha:kea4:server1" not in _drift(env)


def test_pelagos_write_rebaselines_an_unseen_change(tmp_path):
    env = _env(tmp_path, ha_dhcp4())
    conf = tmp_path / "etc/kea/kea-dhcp4.conf"
    run_audit(env)
    _edit(conf, lambda rel: rel.update({"restrict-commands": True}))
    ha_maintenance.mark(env.node_paths, "kea4", "write", now=10**10)
    assert "kea_ha:kea4:server1" not in _drift(env)
    assert ledger.get(env, "kea_ha:kea4:server1")["state"]["relationship"]["restrict-commands"] is True


def test_ha_relationship_adopt(tmp_path):
    env = _env(tmp_path, ha_dhcp4())
    conf = tmp_path / "etc/kea/kea-dhcp4.conf"
    run_audit(env)
    _edit(conf, lambda rel: rel.update({"heartbeat-delay": 5000}))
    found = _drift(env)["kea_ha:kea4:server1"]
    job = apply_plan(build_security_plan(env, [found.id + "#adopt"]), env)
    assert job.state is JobState.DONE, job.error
    assert _rel(conf)["heartbeat-delay"] == 5000 and not _drift(env)


def test_owned_file_drift(tmp_path):
    env = _env(tmp_path, ha_dhcp4())
    env.services.units.add("kea-dhcp4-server.service")
    dropin = drift.owned_files(env)[0]
    dropin.parent.mkdir(parents=True, exist_ok=True)
    dropin.write_text("# pelagos:managed v1\n[Service]\nExecStartPre=-/bin/rm -f /run/kea/sock\n")
    assert not _drift(env)  # seeded
    dropin.write_text("[Service]\n")
    found = _drift(env)[f"file:{dropin}"]
    assert found.details["differences"] == [f"{dropin}: content changed"]
    job = apply_plan(build_security_plan(env, [found.id + "#restore"]), env)
    assert job.state is JobState.DONE, job.error
    assert dropin.read_text().startswith("# pelagos:managed v1") and not _drift(env)


def test_split_choice():
    assert drift.split_choice("kea:managed_drift:ha_guard#adopt") == ("kea:managed_drift:ha_guard", "adopt")
    assert drift.split_choice("kea:x:y#z") == ("kea:x:y#z", None)


def test_drift_finding_raises_an_alert():
    from pelagos.collector.security import security_outcome
    from pelagos.domain import AlertKind

    f = {"id": "kea:managed_drift:ha_guard", "kind": "managed_drift", "engine": "kea", "subject": "ha_guard"}
    (alert,) = security_outcome([{**f, "description": "d"}], "n1").alerts
    assert alert.kind is AlertKind.MANAGED_DRIFT
