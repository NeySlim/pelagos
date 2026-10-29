# SPDX-License-Identifier: Apache-2.0
"""Security audit findings on the legacy config and their remediation, the dual-key switch included."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pelagos.domain import JobState, PlanScope, Severity
from pelagos.installer import bindconf, keaconf, managed
from pelagos.installer.importer import build_import_plan
from pelagos.installer.jobs import apply_plan
from pelagos.installer.security_audit import (
    BindAuditInput,
    KeaAuditInput,
    audit_bind,
    audit_kea,
    build_security_plan,
    run_audit,
)
from tests.unit.installer.fakes import DATA, copy_kea, debian_tree, legacy_tree, make_env

pytestmark = pytest.mark.unit

LEGACY_IDS = {
    "bind:weak_rndc_key:rndc-key",
    "bind:weak_shared_kea_key:kea-ddns",
    "bind:weak_tsig_key:legacy-xfr",
    "bind:allow_update_by_address:_default/example.lan.",
    "bind:allow_update_by_address:_default/2.0.192.in-addr.arpa.",
    "bind:open_allow_transfer:options",
    "bind:open_recursion:options",
    "bind:dnssec_validation_off:options",
    "bind:rndc_nonlocal:*",
    "bind:stats_nonlocal:0.0.0.0",
    "bind:version_disclosed:options",
}


def _others(findings: list) -> list:
    """Findings other than version_disclosed, which every stock options block gets."""
    return [f for f in findings if f.kind != "version_disclosed"]


def _d2_with_md5(tmp: Path, version_key: str = "secret") -> Path:
    d = tmp / "etc/kea"
    d.mkdir(parents=True, exist_ok=True)
    conf = d / "kea-dhcp-ddns.conf"
    conf.write_text(
        json.dumps(
            {
                "DhcpDdns": {
                    "ip-address": "127.0.0.1",
                    "port": 53001,
                    "control-socket": {"socket-type": "unix", "socket-name": "kea-ddns-ctrl-socket"},
                    "tsig-keys": [
                        {
                            "name": "kea-ddns",
                            "algorithm": "HMAC-MD5",
                            version_key: "bGVnYWN5LWtlYS1kZG5zLXNlY3JldC0wMDAwMDAwMDAwMDA=",
                        }
                    ],
                    "forward-ddns": {"ddns-domains": [{"name": "example.lan.", "key-name": "kea-ddns"}]},
                    "reverse-ddns": {"ddns-domains": []},
                }
            },
            indent=2,
        )
    )
    return conf


def test_legacy_findings(tmp_path):
    env = legacy_tree(tmp_path)
    findings = {f.id: f for f in run_audit(env)}
    assert set(findings) == LEGACY_IDS
    assert findings["bind:weak_shared_kea_key:kea-ddns"].severity is Severity.CRITICAL
    assert findings["bind:weak_tsig_key:legacy-xfr"].severity is Severity.WARNING  # sha1
    assert findings["bind:weak_rndc_key:rndc-key"].details["file"].endswith("rndc.key")
    upd = findings["bind:allow_update_by_address:_default/example.lan."]
    assert upd.details["kea_key"] == "kea-ddns"
    assert "grant ddi-admin zonesub A AAAA PTR CNAME TXT SRV MX NS CAA DHCID;" in upd.proposal
    assert 'grant "kea-ddns" zonesub A AAAA PTR DHCID;' in upd.proposal
    for f in findings.values():
        d = f.to_dict()
        assert set(d) == {
            "id",
            "kind",
            "severity",
            "engine",
            "subject",
            "description",
            "proposal",
            "risk",
            "remediable",
            "mitigated",
            "description_message",
            "proposal_message",
            "risk_message",
            "manual_action",
            "manual_action_message",
        }
        assert d["description"] and d["proposal"] and d["risk"]
        assert (d["manual_action"] is None) == d["remediable"]


def test_audit_from_printed_config_matches_user_files(tmp_path):
    """named-checkconf -p output gives the same BIND findings as the user files (rndc key aside)."""
    printed = bindconf.parse((DATA / "bind" / "legacy-p.conf").read_text())
    files = bindconf.ConfigFiles(root=Path("p.conf"), order=["p.conf"])
    files.statements["p.conf"] = printed
    files.texts["p.conf"] = (DATA / "bind" / "legacy-p.conf").read_text()
    kinds = {
        f.kind for f in audit_bind(BindAuditInput(files=files, rndc_key="rndc-key", kea_keys={"kea-ddns"}))
    }
    assert kinds == {k.split(":")[1] for k in LEGACY_IDS}


def _stats_kinds(inet: str) -> set[str]:
    text = f"statistics-channels {{ {inet} }};\n"
    files = bindconf.ConfigFiles(root=Path("s.conf"), order=["s.conf"])
    files.statements["s.conf"] = bindconf.parse(text)
    files.texts["s.conf"] = text
    return {f.kind for f in audit_bind(BindAuditInput(files=files))}


def test_stats_channel_on_loopback_is_not_a_finding():
    assert _stats_kinds("inet 127.0.0.1 port 8053 allow { any; };") == set()
    assert _stats_kinds("inet ::1 port 8053 allow { any; };") == set()
    assert _stats_kinds("inet 192.0.2.53 port 8053 allow { 127.0.0.1; };") == {"stats_nonlocal"}
    assert _stats_kinds("inet * port 8053 allow { any; };") == {"stats_nonlocal"}


def test_clean_default_has_no_finding(tmp_path):
    env = debian_tree(tmp_path)
    assert _others(run_audit(env)) == []
    rocky = bindconf.parse((DATA / "bind" / "rocky-default-p.conf").read_text())
    files = bindconf.ConfigFiles(root=Path("r"), order=["r"], statements={"r": rocky}, texts={"r": ""})
    assert _others(audit_bind(BindAuditInput(files=files))) == []


def test_kea_findings():
    agent = keaconf.loads((DATA / "kea" / "rocky-3.0-kea-ctrl-agent.conf").read_text())
    d2 = {
        "DhcpDdns": {
            "tsig-keys": [
                {"name": "kea-ddns", "algorithm": "HMAC-MD5", "secret": "eA=="},
                {"name": "other", "algorithm": "HMAC-SHA256", "secret": "eA=="},
            ]
        }
    }
    d4 = {
        "Dhcp4": {
            "control-sockets": [{"socket-type": "http", "socket-address": "192.0.2.1", "socket-port": 8004}]
        }
    }
    found = audit_kea(
        KeaAuditInput(
            configs={"d2": d2, "kea4": d4},
            versions={"d2": "3.0.3"},
            ctrl_agent=agent,
            ctrl_agent_unit="kea-ctrl-agent.service",
            socket_dir="/run/kea",
            socket_dir_mode=0o755,
        )
    )
    ids = {f.id: f for f in found}
    assert set(ids) == {
        "kea:kea_ctrl_agent_http:127.0.0.1:8000",
        "kea:kea_http_socket_plain:kea4:192.0.2.1",
        "kea:kea_socket_dir_mode:/run/kea",
        "kea:weak_shared_kea_key:kea-ddns",
        "kea:kea_tsig_clear_secret:kea-ddns",
        "kea:kea_tsig_clear_secret:other",
    }
    assert ids["kea:kea_ctrl_agent_http:127.0.0.1:8000"].severity is Severity.WARNING
    assert ids["kea:kea_http_socket_plain:kea4:192.0.2.1"].to_dict()["remediable"] is False


def test_clear_secret_with_an_unusable_file_name_is_manual():
    keys = [{"name": n, "algorithm": "HMAC-SHA256", "secret": "eA=="} for n in ("ok", "a/b", "x\n")]
    found = audit_kea(
        KeaAuditInput(configs={"d2": {"DhcpDdns": {"tsig-keys": keys}}}, versions={"d2": "3.0.3"})
    )
    clear = {f.subject: f for f in found if f.kind == "kea_tsig_clear_secret"}
    assert clear["ok"].details["remediation"] == "secret_file"
    for name in ("a/b", "x\n"):
        assert clear[name].to_dict()["remediable"] is False and "remediation" not in clear[name].details


def _apply(env, ids):
    plan = build_security_plan(env, ids, created_by="admin")
    assert plan.scope is PlanScope.SECURITY and plan.requires_confirmation
    job = apply_plan(plan, env)
    return plan, job


def test_remediate_bind_hardening(tmp_path):
    env = legacy_tree(tmp_path)
    assert apply_plan(build_import_plan(env, ["bind"]), env).state is JobState.DONE
    ids = [
        "bind:weak_tsig_key:legacy-xfr",
        "bind:allow_update_by_address:_default/2.0.192.in-addr.arpa.",
        "bind:open_allow_transfer:options",
        "bind:open_recursion:options",
        "bind:dnssec_validation_off:options",
        "bind:rndc_nonlocal:*",
        "bind:stats_nonlocal:0.0.0.0",
    ]
    _plan, job = _apply(env, ids)
    assert job.state is JobState.DONE, job.error
    assert [s["name"] for s in job.steps][1:] == [f"security/{i}" for i in ids]
    remaining = {f.id for f in run_audit(env)}
    assert remaining == (LEGACY_IDS - set(ids)) | ACCESS_IDS
    etc = tmp_path / "etc/bind"
    local = (etc / "named.conf.local").read_text()
    assert "algorithm hmac-sha1" not in local
    files = bindconf.load_files(etc / "named.conf")
    top = list(files.top_level())
    xfr = next(k for k in bindconf.keys(top) if k.name == "legacy-xfr")
    assert xfr.algorithm == "hmac-sha256" and len(xfr.secret) == 44
    zone = next(z for z in bindconf.zones(top) if z.name == "2.0.192.in-addr.arpa.")
    assert zone.elements("allow-update") == []
    assert zone.elements("update-policy") == [
        "grant ddi-admin zonesub A AAAA PTR CNAME TXT SRV MX NS CAA DHCID"
    ]
    opts = next(s for s in top if s.name == "options")
    assert bindconf.option_value(opts, "allow-transfer") == ["key ddi-read"]
    assert bindconf.option_value(opts, "allow-recursion") == ["localhost", "localnets"]
    assert bindconf.option_value(opts, "dnssec-validation") == ["auto"]
    named = (etc / "named.conf").read_text()
    assert 'inet 127.0.0.1 port 953 allow { 127.0.0.1; } keys { "rndc-key"; };' in named
    assert "inet 127.0.0.1 port 8053 allow { 127.0.0.1; };" in named
    # Comments in the user files survive the edits.
    assert "# Keys shared with Kea D2" in local and "/* The forward zone" in local


ACCESS_IDS = {
    "bind:update_without_admin_key:_default/corp.example.lan.",
    "bind:transfer_without_read_key:_default/corp.example.lan.",
    "bind:transfer_without_read_key:_default/2.0.192.in-addr.arpa.",
}


def test_pelagos_access_findings_appear_after_import_and_are_fixed(tmp_path):
    env = legacy_tree(tmp_path)
    assert not ACCESS_IDS & {f.id for f in run_audit(env)}  # the Pelagos keys do not exist yet
    assert apply_plan(build_import_plan(env, ["bind"]), env).state is JobState.DONE
    findings = {f.id: f for f in run_audit(env)}
    assert ACCESS_IDS <= set(findings)
    corp = findings["bind:update_without_admin_key:_default/corp.example.lan."]
    assert corp.details["remediation"] == "update_policy_grant"
    _plan, job = _apply(env, sorted(ACCESS_IDS))
    assert job.state is JobState.DONE, job.error
    assert not ACCESS_IDS & {f.id for f in run_audit(env)}
    top = list(bindconf.load_files(tmp_path / "etc/bind/named.conf").top_level())
    zones = {z.name: z for z in bindconf.zones(top)}
    assert zones["corp.example.lan."].elements("update-policy") == [
        "grant kea-ddns zonesub ANY",
        "grant ddi-admin zonesub A AAAA PTR CNAME TXT SRV MX NS CAA DHCID",
    ]
    assert zones["corp.example.lan."].elements("allow-transfer") == ["key ddi-read", "key legacy-xfr"]
    assert zones["2.0.192.in-addr.arpa."].elements("allow-transfer") == [
        "key ddi-read",
        "192.0.2.2",
        "key legacy-xfr",
    ]


def test_secondary_without_transfer_rules_gets_one_in_options(tmp_path):
    env = debian_tree(tmp_path)
    local = tmp_path / "etc/bind/named.conf.local"
    local.write_text(
        'zone "example.lan" {\n\ttype secondary;\n\tprimaries { 192.0.2.1; };\n\tfile "db.example.lan";\n};\n'
    )
    assert apply_plan(build_import_plan(env, ["bind"]), env).state is JobState.DONE
    found = [f for f in run_audit(env) if f.kind == "transfer_without_read_key"]
    assert [f.id for f in found] == ["bind:transfer_without_read_key:options"]
    assert found[0].details["remediation"] == "allow_transfer_add"
    _plan, job = _apply(env, [found[0].id])
    assert job.state is JobState.DONE, job.error
    top = bindconf.load_files(tmp_path / "etc/bind/named.conf").top_level()
    opts = next(s for s in top if s.name == "options")
    assert bindconf.option_value(opts, "allow-transfer") == ["key ddi-read"]
    assert _others(run_audit(env)) == []


def test_remediation_needs_import_keys(tmp_path):
    env = legacy_tree(tmp_path)
    _plan, job = _apply(env, ["bind:open_allow_transfer:options"])
    assert job.state is JobState.FAILED and "run the import first" in job.error


def test_rndc_key_regeneration(tmp_path):
    env = legacy_tree(tmp_path)
    env.services.active.add("named.service")
    _plan, job = _apply(env, ["bind:weak_rndc_key:rndc-key"])
    assert job.state is JobState.DONE, job.error
    key = bindconf.keys(bindconf.parse((tmp_path / "etc/bind/rndc.key").read_text()))[0]
    assert (key.name, key.algorithm) == ("rndc-key", "hmac-sha256")
    # rndc cannot reconfig across a key change: named is restarted, then rndc status verifies.
    assert ("restart", "named.service") in env.services.calls
    assert ("rndc", "status") in env.tools.calls


def test_failed_validation_rolls_back(tmp_path):
    env = legacy_tree(tmp_path)
    before = (tmp_path / "etc/bind/named.conf.local").read_text()
    env.tools.checkconf_ok = False
    _plan, job = _apply(env, ["bind:weak_tsig_key:legacy-xfr"])
    assert job.state is JobState.FAILED and "rolled back: True" in job.error
    assert (tmp_path / "etc/bind/named.conf.local").read_text() == before


def test_dual_key_switch(tmp_path):
    env = legacy_tree(tmp_path)
    conf = _d2_with_md5(tmp_path)
    assert apply_plan(build_import_plan(env, ["bind"]), env).state is JobState.DONE
    fid = "bind:weak_shared_kea_key:kea-ddns"
    plan = build_security_plan(env, [fid])
    assert [c.target for c in plan.changes] == [
        f"security/{fid}/1-bind-add",
        f"security/{fid}/2-d2-switch",
        f"security/{fid}/3-bind-remove",
    ]
    assert all(c.node_ids == ["node-a"] for c in plan.changes)
    job = apply_plan(plan, env)
    assert job.state is JobState.DONE, job.error
    etc = tmp_path / "etc/bind"
    files = bindconf.load_files(etc / "named.conf")
    top = list(files.top_level())
    keys = {k.name: k for k in bindconf.keys(top)}
    assert "kea-ddns" not in keys and keys["kea-ddns-sha256"].algorithm == "hmac-sha256"
    zones = {z.name: z for z in bindconf.zones(top)}
    assert zones["example.lan."].elements("allow-update") == ["192.0.2.5", "key kea-ddns-sha256"]
    assert zones["corp.example.lan."].elements("update-policy") == ["grant kea-ddns-sha256 zonesub ANY"]
    d2 = keaconf.loads(conf.read_text())["DhcpDdns"]
    assert d2["tsig-keys"] == [
        {
            "name": "kea-ddns-sha256",
            "algorithm": "HMAC-SHA256",
            "secret-file": str(tmp_path / "etc/kea/kea-ddns-sha256.tsig"),
        }
    ]
    assert d2["forward-ddns"]["ddns-domains"][0]["key-name"] == "kea-ddns-sha256"
    secret = (tmp_path / "etc/kea/kea-ddns-sha256.tsig").read_text().strip()
    assert secret == keys["kea-ddns-sha256"].secret
    assert "bind:weak_shared_kea_key:kea-ddns" not in {f.id for f in run_audit(env)}


def test_dual_key_removes_a_key_kept_in_a_file_named_after_it(tmp_path):
    env = debian_tree(tmp_path)
    etc = tmp_path / "etc/bind"
    key = 'key "kea-ddns" {\n\talgorithm hmac-md5;\n\tsecret "bWQ1LXNlY3JldA==";\n};\n'
    (etc / "kea-ddns.key").write_text(key)
    (etc / "named.conf.local").write_text(
        f'include "{etc}/kea-ddns.key";\n'
        'zone "example.lan" {\n\ttype primary;\n\tfile "db.example.lan";\n'
        "\tallow-update { key kea-ddns; };\n};\n"
    )
    _d2_with_md5(tmp_path)
    assert apply_plan(build_import_plan(env, ["bind"]), env).state is JobState.DONE
    job = apply_plan(build_security_plan(env, ["bind:weak_shared_kea_key:kea-ddns"]), env)
    assert job.state is JobState.DONE, job.error
    assert "still referenced" not in job.steps[-1]["output"]
    top = list(bindconf.load_files(etc / "named.conf").top_level())
    assert "kea-ddns" not in {k.name for k in bindconf.keys(top)}
    assert f'include "{etc}/kea-ddns.key";' in (etc / "named.conf.local").read_text()
    assert not [f for f in run_audit(env) if f.kind.startswith("weak")]


def test_dual_key_intermediate_state_accepts_both(tmp_path):
    """After step 1 alone (another node still on the old key), BIND grants both keys."""
    env = legacy_tree(tmp_path)
    _d2_with_md5(tmp_path)
    apply_plan(build_import_plan(env, ["bind"]), env)
    plan = build_security_plan(env, ["bind:weak_shared_kea_key:kea-ddns"], d2_node_ids=["node-b"])
    assert plan.changes[1].node_ids == ["node-b"]
    plan.changes[2].node_ids = ["node-b"]  # keep step 3 off this node to observe the middle state
    job = apply_plan(plan, env)
    assert job.state is JobState.DONE, job.error
    top = list(bindconf.load_files(tmp_path / "etc/bind/named.conf").top_level())
    zones = {z.name: z for z in bindconf.zones(top)}
    assert zones["example.lan."].elements("allow-update") == [
        "key kea-ddns",
        "192.0.2.5",
        "key kea-ddns-sha256",
    ]
    assert zones["corp.example.lan."].elements("update-policy") == [
        "grant kea-ddns zonesub ANY",
        "grant kea-ddns-sha256 zonesub ANY",
    ]


def test_kea_only_remediations(tmp_path):
    env = debian_tree(tmp_path)
    conf = _d2_with_md5(tmp_path)
    (tmp_path / "run/kea").mkdir(parents=True)
    (tmp_path / "run/kea").chmod(0o755)
    findings = {f.id for f in run_audit(env)}
    assert "kea:kea_socket_dir_mode:" + str(tmp_path / "run/kea") in findings
    assert "kea:kea_tsig_clear_secret:kea-ddns" in findings
    ids = ["kea:kea_socket_dir_mode:" + str(tmp_path / "run/kea"), "kea:kea_tsig_clear_secret:kea-ddns"]
    _plan, job = _apply(env, ids)
    assert job.state is JobState.DONE, job.error
    assert (tmp_path / "run/kea").stat().st_mode & 0o777 == 0o750
    key = keaconf.tsig_keys(keaconf.loads(conf.read_text()))[0]
    assert "secret" not in key and Path(key["secret-file"]).read_text().strip().startswith("bGVnYWN5")


def test_unknown_or_manual_findings_are_refused(tmp_path):
    env = legacy_tree(tmp_path)
    with pytest.raises(ValueError, match="unknown finding"):
        build_security_plan(env, ["bind:nope:x"])
    copy_kea(tmp_path, {})  # no Kea config: only BIND findings
    assert all(f.engine == "bind" for f in run_audit(env))


def test_dual_key_on_bind_only_node_runs_step_one_only(tmp_path):
    """D2 lives on another node: this node adds the new key and leaves steps 2 and 3 to the operator."""
    env = legacy_tree(tmp_path)
    assert apply_plan(build_import_plan(env, ["bind"]), env).state is JobState.DONE
    fid = "bind:weak_shared_kea_key:kea-ddns"
    plan = build_security_plan(env, [fid])
    assert [c.node_ids for c in plan.changes] == [["node-a"], [], []]
    assert [c.after["manual"] for c in plan.changes] == [False, True, True]
    job = apply_plan(plan, env)
    assert job.state is JobState.DONE, job.error
    assert [s["name"] for s in job.steps] == ["security/preconditions", f"security/{fid}/1-bind-add"]
    keys = {
        k.name for k in bindconf.keys(list(bindconf.load_files(tmp_path / "etc/bind/named.conf").top_level()))
    }
    assert {"kea-ddns", "kea-ddns-sha256"} <= keys  # the remote D2 still signs with the old key


def test_dual_key_on_d2_only_node_runs_step_two_only(tmp_path):
    env = make_env(tmp_path)
    conf = _d2_with_md5(tmp_path)
    fid = "kea:weak_shared_kea_key:kea-ddns"
    plan = build_security_plan(env, [fid])
    assert [c.node_ids for c in plan.changes] == [[], ["node-a"], []]
    # The BIND node already added the new key; its secret reaches this node through the cluster.
    keys_conf = env.paths.keys_conf
    keys_conf.parent.mkdir(parents=True)
    keys_conf.write_text(managed.render_keys_conf({"kea-ddns-sha256": ("hmac-sha256", "bmV3c2VjcmV0")}))
    job = apply_plan(plan, env)
    assert job.state is JobState.DONE, job.error
    assert [s["name"] for s in job.steps] == ["security/preconditions", f"security/{fid}/2-d2-switch"]
    key = keaconf.tsig_keys(keaconf.loads(conf.read_text()))[0]
    assert key["name"] == "kea-ddns-sha256"
    assert not (tmp_path / "etc/bind/named.conf").exists()


def test_static_zone_conversion_to_dynamic(tmp_path):
    import dataclasses
    import getpass

    env = debian_tree(tmp_path)
    # named runs as us here: the zone directory of the temp tree is ours, so the journal fits.
    env.paths = dataclasses.replace(env.paths, bind_user=getpass.getuser())
    local = tmp_path / "etc/bind/named.conf.local"
    local.write_text(
        'zone "localhost.localdomain" IN {\n\ttype master;\n\tfile "named.localhost";\n'
        "\tallow-update { none; };\n};\n"
        'zone "static.example.lan" {\n\ttype primary;\n\tfile "db.static";\n\tallow-update { none; };\n};\n'
    )
    assert _others(run_audit(env)) == []  # before the import: no Pelagos key to propose
    assert apply_plan(build_import_plan(env, ["bind"]), env).state is JobState.DONE
    found = {f.kind: f for f in _others(run_audit(env))}
    # The distribution's localhost zone is left alone; the static zone is read and may be converted.
    assert set(found) == {"static_zone", "transfer_without_read_key"}
    static = found["static_zone"]
    assert static.id == "bind:static_zone:_default/static.example.lan." and static.severity is Severity.INFO
    assert "zone file" in static.description and "rndc freeze" in static.risk and ".jnl" in static.risk
    assert static.proposal.startswith("Replace allow-update { none; } by update-policy")
    _plan, job = _apply(env, [static.id, found["transfer_without_read_key"].id])
    assert job.state is JobState.DONE, job.error
    top = list(bindconf.load_files(tmp_path / "etc/bind/named.conf").top_level())
    zone = {z.name: z for z in bindconf.zones(top)}["static.example.lan."]
    assert zone.elements("update-policy") == [
        "grant ddi-admin zonesub A AAAA PTR CNAME TXT SRV MX NS CAA DHCID"
    ]
    assert zone.elements("allow-update") == []
    assert _others(run_audit(env)) == []


def test_conversion_refuses_a_directory_named_cannot_write(tmp_path):
    import getpass
    import grp
    import os

    from pelagos.installer import zone_audit

    zones = tmp_path / "zones"
    zones.mkdir()
    (tmp_path / "named.conf").write_text(
        f'options {{ directory "{zones}"; }};\nzone "s.example.lan" {{ type primary; file "s.db"; }};\n'
    )
    files = bindconf.load_files(tmp_path / "named.conf")
    zone = bindconf.zones(list(files.top_level()))[0]

    class Paths:
        bind_user = getpass.getuser()
        bind_group = grp.getgrgid(os.getgid()).gr_name

    class Env:
        paths = Paths()

    zones.chmod(0o555)
    try:
        assert "cannot write" in zone_audit.journal_problem(Env(), files, zone)
    finally:
        zones.chmod(0o755)
    assert zone_audit.journal_problem(Env(), files, zone) is None


VIEWS = """
key "partner" { algorithm hmac-sha256; secret "c2VjcmV0LWZvci1wYXJ0bmVy"; };
view "inside" {
\tmatch-clients { 192.0.2.0/24; localhost; };
\tzone "split.example.lan" { type primary; file "inside.db"; update-policy { grant partner zonesub A; }; };
};
view "outside" {
\tallow-transfer { key partner; };
\tzone "split.example.lan" { type primary; file "outside.db"; update-policy { grant partner zonesub A; }; };
};
"""


def test_views_get_one_key_each(tmp_path):
    env = debian_tree(tmp_path)
    (tmp_path / "etc/bind/named.conf.local").write_text(VIEWS)
    conf = tmp_path / "etc/bind/named.conf"
    # With views every zone lives in a view: the top-level root hints go.
    conf.write_text(conf.read_text().replace(f'include "{tmp_path}/etc/bind/named.conf.root-hints";', ""))
    assert apply_plan(build_import_plan(env, ["bind"]), env).state is JobState.DONE
    found = {f.id: f for f in run_audit(env) if f.kind == "view_key"}
    assert set(found) == {"bind:view_key:inside", "bind:view_key:outside"}
    outside = found["bind:view_key:outside"]
    assert "`!key ddi-outside;` first in those of inside" in outside.proposal
    assert "keep their view" in outside.risk
    other = [f.id for f in run_audit(env) if f.kind != "view_key"]
    _plan, job = _apply(env, [*other, *found])
    assert job.state is JobState.DONE, job.error
    top = list(bindconf.load_files(conf).top_level())
    views = {v.words[0].strip('"'): v for v in top if v.name == "view"}
    assert bindconf.acl_elements(views["inside"].sub("match-clients")) == [
        "!key ddi-outside",
        "key ddi-inside",
        "192.0.2.0/24",
        "localhost",
    ]
    assert bindconf.acl_elements(views["outside"].sub("match-clients")) == ["key ddi-outside", "any"]
    assert bindconf.acl_elements(views["outside"].sub("allow-transfer")) == ["key ddi-outside", "key partner"]
    zones = {(z.view, z.name): z for z in bindconf.zones(top)}
    assert (
        zones[("inside", "split.example.lan.")]
        .elements("update-policy")[-1]
        .startswith("grant ddi-inside zonesub")
    )
    assert {k.name for k in bindconf.keys(top)} >= {"ddi-inside", "ddi-outside"}
    assert _others(run_audit(env)) == []


def _views_env(tmp_path, options_extra: str = ""):
    env = debian_tree(tmp_path)
    (tmp_path / "etc/bind/named.conf.local").write_text(VIEWS)
    opts = tmp_path / "etc/bind/named.conf.options"
    opts.write_text(
        opts.read_text().replace("};", f"\t{options_extra}\n}};") if options_extra else opts.read_text()
    )
    conf = tmp_path / "etc/bind/named.conf"
    conf.write_text(conf.read_text().replace(f'include "{tmp_path}/etc/bind/named.conf.root-hints";', ""))
    assert apply_plan(build_import_plan(env, ["bind"]), env).state is JobState.DONE
    return env, conf


def test_view_key_keeps_the_transfer_clients_of_the_options(tmp_path):
    env, conf = _views_env(tmp_path, "allow-transfer { 192.0.2.12; key ddi-read; };")
    _plan, job = _apply(env, [f.id for f in run_audit(env)])
    assert job.state is JobState.DONE, job.error
    top = list(bindconf.load_files(conf).top_level())
    views = {v.words[0].strip('"'): v for v in top if v.name == "view"}
    # The new view-level list overrides the options one: it carries its clients along.
    assert bindconf.acl_elements(views["inside"].sub("allow-transfer")) == [
        "key ddi-inside",
        "192.0.2.12",
        "key ddi-read",
    ]
    assert _others(run_audit(env)) == []


def test_zone_added_to_a_keyed_view_gets_the_view_key(tmp_path):
    env, conf = _views_env(tmp_path)
    _plan, job = _apply(env, [f.id for f in run_audit(env)])
    assert job.state is JobState.DONE, job.error
    local = tmp_path / "etc/bind/named.conf.local"
    local.write_text(
        local.read_text().replace(
            'view "inside" {',
            'view "inside" {\n\tzone "new.example.lan" { type primary; file "new.db"; '
            "update-policy { grant partner zonesub A; }; allow-transfer { key partner; }; };",
        )
    )
    found = {f.kind: f for f in run_audit(env)}
    assert set(found) == {"update_without_admin_key", "transfer_without_read_key"}
    assert "ddi-inside" in found["update_without_admin_key"].description
    assert found["transfer_without_read_key"].details["key"] == "ddi-inside"
    _plan, job = _apply(env, [f.id for f in found.values()])
    assert job.state is JobState.DONE, job.error
    zones = {(z.view, z.name): z for z in bindconf.zones(list(bindconf.load_files(conf).top_level()))}
    new = zones[("inside", "new.example.lan.")]
    assert new.elements("update-policy")[-1].startswith("grant ddi-inside zonesub")
    assert new.elements("allow-transfer") == ["key ddi-inside", "key partner"]
    assert _others(run_audit(env)) == []


def test_inherited_allow_update_makes_a_zone_dynamic(tmp_path):
    env = debian_tree(tmp_path)
    opts = tmp_path / "etc/bind/named.conf.options"
    opts.write_text(
        opts.read_text().replace("};", "\tallow-update { key partner; };\n\tallow-transfer { any; };\n};")
    )
    (tmp_path / "etc/bind/named.conf.local").write_text(
        'key "partner" { algorithm hmac-sha256; secret "c2VjcmV0LWZvci1wYXJ0bmVy"; };\n'
        'zone "dyn.example.lan" { type primary; file "dyn.db"; };\n'
        'zone "none.example.lan" { type primary; file "none.db"; allow-update { none; }; };\n'
    )
    assert apply_plan(build_import_plan(env, ["bind"]), env).state is JobState.DONE
    found = {f.id: f for f in run_audit(env) if f.kind in ("static_zone", "update_without_admin_key")}
    assert set(found) == {
        "bind:static_zone:_default/none.example.lan.",
        "bind:update_without_admin_key:_default/dyn.example.lan.",
    }
    update = found["bind:update_without_admin_key:_default/dyn.example.lan."]
    assert update.details["remediation"] == "update_key_add" and "inherits" in update.proposal
    _plan, job = _apply(env, [update.id])
    assert job.state is JobState.DONE, job.error
    options = next(
        s for s in bindconf.load_files(tmp_path / "etc/bind/named.conf").top_level() if s.name == "options"
    )
    assert bindconf.acl_elements(options.sub("allow-update")) == ["key ddi-admin", "key partner"]
    assert not [f for f in run_audit(env) if f.kind == "update_without_admin_key"]


def test_secret_file_migration_keeps_comments_and_includes(tmp_path):
    env = debian_tree(tmp_path)
    conf = _d2_with_md5(tmp_path)
    keys = conf.parent / "d2-keys.json"
    body = json.loads(conf.read_text())["DhcpDdns"]
    keys.write_text(f'// TSIG keys of the D2 server\n"tsig-keys": {json.dumps(body.pop("tsig-keys"))},\n')
    rest = json.dumps(body, indent=2)[1:-2]
    conf.write_text(f'// D2 managed by hand\n{{"DhcpDdns": {{\n  <?include "{keys}"?>\n{rest}\n}}}}\n')
    _plan, job = _apply(env, ["kea:kea_tsig_clear_secret:kea-ddns"])
    assert job.state is JobState.DONE, job.error
    main, part = conf.read_text(), keys.read_text()
    assert main.startswith("// D2 managed by hand") and f'<?include "{keys}"?>' in main
    assert "tsig-keys" not in main and "secret-file" in part and '"secret"' not in part
    assert part.startswith("// TSIG keys of the D2 server")
    key = keaconf.tsig_keys(keaconf.loads(main, str(conf)))[0]
    assert Path(key["secret-file"]).read_text().strip().startswith("bGVnYWN5")


def test_remote_named_keeps_its_network_listeners(tmp_path):
    """A named reached over the network (compose): moving rndc and statistics to 127.0.0.1 is not offered."""
    from pelagos.core.config_store import ConfigStore, NodeConfig

    env = legacy_tree(tmp_path)
    local = {f.id: f for f in run_audit(env)}
    assert local["bind:rndc_nonlocal:*"].to_dict()["remediable"]
    env.node_paths.ensure()
    remote = {"rndc_address": "bind", "statistics_url": "http://bind:8053/json/v1"}
    ConfigStore(env.node_paths.node_toml, env.node_paths.cluster_toml).save_node(
        NodeConfig(id=env.node_id, name=env.node_id, engines={"bind": False, "disabled": {"bind": remote}})
    )
    found = {f.id: f.to_dict() for f in run_audit(env)}
    assert not found["bind:rndc_nonlocal:*"]["remediable"]
    assert not found["bind:stats_nonlocal:0.0.0.0"]["remediable"]
    assert found["bind:open_recursion:options"]["remediable"]
    with pytest.raises(ValueError, match="no automatic remediation"):
        build_security_plan(env, ["bind:rndc_nonlocal:*"])


def test_update_policy_local_is_left_to_the_operator(tmp_path):
    env = legacy_tree(tmp_path)
    assert apply_plan(build_import_plan(env, ["bind"]), env).state is JobState.DONE
    local = tmp_path / "etc/bind/named.conf.local"
    zone_file = tmp_path / "var/lib/bind/db.local.example.lan"
    local.write_text(
        local.read_text()
        + f'zone "local.example.lan" {{ type primary; file "{zone_file}"; update-policy local; }};\n'
    )
    finding = next(
        f for f in run_audit(env) if f.id == "bind:update_without_admin_key:_default/local.example.lan."
    )
    out = finding.to_dict()
    assert out["remediable"] is False
    assert "update-policy local" in out["manual_action"] and "grant ddi-admin zonesub" in out["manual_action"]


# Names found in a production /etc/kea: backups and a package copy, none loaded by Kea.
PROD_STRAYS = [
    "kea-dhcp-ddns.conf.bak-20261024-1056",
    "tsig-keys.json.bak-20261024-1056",
    "kea-dhcp-ddns.conf.dpkg-dist",
    "kea-dhcp4.conf.orig",
    "kea-dhcp4.conf.ori",
    "kea-dhcp6.conf~",
    "kea-dhcp6.conf.dpkg-old",
]


def _d2_with_include(tmp: Path) -> tuple[Path, list[str]]:
    """Debian-like D2: tsig-keys.json included, a secret file and an HA CA folder referenced."""
    folder = _d2_with_md5(tmp).parent
    secret = folder / "pelagos" / "kea-ddns.secret"
    secret.parent.mkdir()
    secret.write_text("c2VjcmV0\n")
    (folder / "tsig-keys.json").write_text(
        json.dumps({"name": "k2", "algorithm": "HMAC-SHA256", "secret-file": str(secret)})
    )
    conf = folder / "kea-dhcp-ddns.conf"
    conf.write_text(
        conf.read_text().replace(
            '"tsig-keys": [', f'"tsig-keys": [ <?include "{folder}/tsig-keys.json"?>,', 1
        )
    )
    ca = folder / "tls" / "ca"
    ca.mkdir(parents=True)
    (ca / "ca.pem").write_text("pem\n")
    (ca / "ca.pem.bak-20261024-1056").write_text("old\n")
    agent = folder / "kea-ctrl-agent.conf"
    agent.write_text(
        json.dumps({"Control-agent": {"trust-anchor": str(ca), "cert-file": str(folder / "none.pem")}})
    )
    for name in PROD_STRAYS:
        (folder / name).write_text("{}\n")
    (folder / "notes.txt").write_text("not a Kea file\n")
    loaded = ["kea-dhcp-ddns.conf", "tsig-keys.json", "pelagos/kea-ddns.secret", "tls/ca/ca.pem"]
    return folder, loaded


def test_kea_files_the_service_cannot_read(tmp_path, monkeypatch):
    """Only files Kea loads are reported (configuration, includes, referenced secret and TLS files);
    the production backups and package copies beside them are not, nor touched by the plan."""
    import os

    from pelagos.installer import kea_modes

    env = debian_tree(tmp_path)
    folder, loaded = _d2_with_include(tmp_path)
    strays = [*PROD_STRAYS, "notes.txt", "tls/ca/ca.pem.bak-20261024-1056"]
    for name in loaded + strays:
        (folder / name).chmod(0o640)
    (folder / "tsig-keys.json").chmod(0o600)
    me, kea = os.getgid(), 4242
    # The files' group (ours) is not one of the service's; the Kea group (ours, for chgrp) is.
    monkeypatch.setattr(kea_modes, "service_ids", lambda: (os.getuid() + 1, {kea}))
    monkeypatch.setattr(kea_modes, "kea_gid", lambda _env: kea)
    finding = next(f for f in run_audit(env) if f.kind == "kea_file_unreadable")
    paths = {i["path"]: i for i in finding.details["files"]}
    assert set(paths) == {str(folder / n) for n in loaded}
    assert paths[str(folder / "tsig-keys.json")]["target_mode"] == "0640"
    assert "chgrp" in finding.to_dict()["proposal"] and "bak" not in finding.to_dict()["description"]
    monkeypatch.setattr(kea_modes, "kea_gid", lambda _env: me)
    monkeypatch.setattr(kea_modes, "service_ids", lambda: (os.getuid() + 1, {me}))
    for name in strays:
        (folder / name).chmod(0o600)
    finding = next(f for f in run_audit(env) if f.kind == "kea_file_unreadable")
    # Group ours already, but no group read on the 0600 include: only that one is fixed.
    assert [i["path"] for i in finding.details["files"]] == [str(folder / "tsig-keys.json")]
    _plan, job = _apply(env, [finding.id])
    assert job.state is JobState.DONE, job.error
    assert (folder / "tsig-keys.json").stat().st_mode & 0o777 == 0o640
    assert all((folder / n).stat().st_mode & 0o777 == 0o600 for n in strays)
    assert not [f for f in run_audit(env) if f.kind == "kea_file_unreadable"]


def test_kea_unreadable_include_is_reported(tmp_path, monkeypatch):
    """Read as the service, an include it cannot open is still reported beside its parent."""
    import os

    from pelagos.installer import kea_modes

    env = debian_tree(tmp_path)
    folder, _loaded = _d2_with_include(tmp_path)
    include = folder / "tsig-keys.json"
    real = kea_modes.KeaDocument

    def as_service(path, **kw):
        def reader(p):
            if p == include:
                raise PermissionError(13, "Permission denied", str(p))
            return p.read_text()

        return real(path, reader=reader, **kw)

    monkeypatch.setattr(kea_modes, "KeaDocument", as_service)
    include.chmod(0o600)
    me = os.getgid()
    monkeypatch.setattr(kea_modes, "kea_gid", lambda _env: me)
    monkeypatch.setattr(kea_modes, "service_ids", lambda: (os.getuid() + 1, {me}))
    assert [i["path"] for i in kea_modes.issues(env)] == [str(include)]


def test_kea_modes_plan_skips_files_kea_does_not_load(tmp_path, monkeypatch):
    """A plan made before the fix may still name a backup: it is left alone."""
    import os

    from pelagos.installer import kea_modes

    env = debian_tree(tmp_path)
    folder, _loaded = _d2_with_include(tmp_path)
    stray = folder / "kea-dhcp-ddns.conf.bak-20261024-1056"
    stray.chmod(0o600)
    monkeypatch.setattr(kea_modes, "kea_gid", lambda _env: os.getgid())
    item = {"path": str(stray), "mode": "0600", "group": "x", "target_mode": "0640", "target_group": "y"}
    assert "not a file Kea loads" in kea_modes.apply(env, [item])
    assert stray.stat().st_mode & 0o777 == 0o600


def test_kea_modes_apply_rolls_back(tmp_path, monkeypatch):
    import os

    from pelagos.installer import kea_modes

    env = debian_tree(tmp_path)
    a, b = tmp_path / "a.conf", tmp_path / "b.conf"
    for p in (a, b):
        p.write_text("{}")
        p.chmod(0o600)
    monkeypatch.setattr(kea_modes, "kea_gid", lambda _env: os.getgid())
    monkeypatch.setattr(kea_modes, "loaded_files", lambda _env: [a, b])
    monkeypatch.setattr(kea_modes, "_kea_reads", lambda _env, p: "kea cannot read" if p == str(b) else None)
    items = [
        {"path": str(p), "mode": "0600", "group": "x", "target_mode": "0640", "target_group": "y"}
        for p in (a, b)
    ]
    with pytest.raises(RuntimeError, match="restored"):
        kea_modes.apply(env, items)
    assert a.stat().st_mode & 0o777 == 0o600 and b.stat().st_mode & 0o777 == 0o600
