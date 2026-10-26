# SPDX-License-Identifier: Apache-2.0
"""BindBackend without a server: rndc, DNS and named-checkconf are replaced by fakes."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from pelagos.connectors.base import ConnectorContext, ConnectorDenied, ConnectorUnavailable, NotSupported
from pelagos.connectors.bind import BindBackend
from pelagos.connectors.bind.rndc import RndcNotFound, parse_dnssec_status, zone_args, zone_status_from
from pelagos.domain.dns import RRset, ZoneKind
from pelagos.domain.plan import Change, ChangeOp, PlanScope, PlanState, PreconditionKind

pytestmark = pytest.mark.unit

NS = ["ns1.example.net."]
# A new primary whose name server lives in the zone: its address comes with it.
LAB_ZONE = {
    "kind": "primary",
    "notes": "n",
    "ns": ["ns1.lab.example.lan."],
    "records": [{"name": "ns1", "rtype": "A", "ttl": 3600, "rdata": ["192.0.2.53"]}],
}

ZONE_DATA = [
    RRset("example.lan.", "SOA", 3600, ["ns1.example.lan. hostmaster.example.lan. 42 3600 900 1209600 300"]),
    RRset("www.example.lan.", "A", 300, ["192.0.2.10"]),
]


def script(path: Path, body: str) -> str:
    path.write_text("#!/bin/sh\n" + body + "\n")
    path.chmod(0o755)
    return str(path)


@pytest.fixture
def conf_tree(tmp_root: Path) -> Path:
    """A user named.conf that already carries the two Pelagos include lines."""
    etc = tmp_root / "etc"
    (etc / "pelagos").mkdir(parents=True)
    (etc / "named.conf").write_text(
        'key "ddi-admin" { algorithm hmac-sha256; secret "c2VjcmV0LWZvci10ZXN0cw=="; };\n'
        f'options {{\n\tdirectory "{tmp_root}/var";\n\trecursion no;\n'
        f'\tinclude "{etc}/pelagos/options.conf";\n}};\n'
        'zone "example.lan" { type primary; file "example.lan.db"; };\n'
        f'include "{etc}/pelagos/pelagos.conf";\n'
    )
    for name in ("keys.conf", "acls.conf", "zones.conf", "options.conf"):
        (etc / "pelagos" / name).write_text("# pelagos:managed v1\n")
    (etc / "pelagos" / "pelagos.conf").write_text(
        "# pelagos:managed v1\n"
        + "".join(f'include "{etc}/pelagos/{n}.conf";\n' for n in ("keys", "acls", "zones"))
    )
    (tmp_root / "var").mkdir()
    return etc


class Recorder:
    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.zones: set[str] = set()

    def run(self, *args: str) -> str:
        self.calls.append(args)
        if args[0] == "status":
            return "version: BIND 9.20.30-1~deb13u1-Debian (Stable Release) <id:>\nserver is up and running\n"
        return ""

    def status(self) -> dict[str, str]:
        return {"version": "BIND 9.20.30", "last configured": "now"}

    def zonestatus(self, zone: str, view: str | None = None) -> dict[str, str]:
        if zone.rstrip(".") not in self.zones:
            raise RndcNotFound(f"no matching zone '{zone}' in any view")
        return {"type": "primary"}


def make_backend(tmp_root: Path, etc: Path | None = None, ok: bool = True) -> tuple[BindBackend, Recorder]:
    etc = etc or tmp_root / "etc"
    ctx = ConnectorContext(
        node_id="n1",
        engine_config={
            "named_conf": str(etc / "named.conf"),
            "include_dir": str(etc / "pelagos"),
            "zone_dir": str(tmp_root / "var" / "pelagos"),
            "checkconf": script(tmp_root / "checkconf", "exit 0" if ok else "echo bad config; exit 1"),
            "checkzone": script(tmp_root / "checkzone", "exit 0"),
        },
        backup_root=tmp_root / "backups",
        get_secret={"tsig/ddi-read": "c2VjcmV0", "tsig/ddi-admin": "c2VjcmV0"}.get,
        settings={"plan_ttl_seconds": 60, "dns": {"read_key": "ddi-read", "admin_key": "ddi-admin"}},
    )
    backend = BindBackend(ctx)
    rec = Recorder()
    backend.rndc = rec  # type: ignore[assignment]
    return backend, rec


def test_rrset_plan_and_apply(tmp_root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    backend, _ = make_backend(tmp_root)
    monkeypatch.setattr(backend, "read_zone", lambda zone, view=None: ZONE_DATA)
    plan = backend.plan_rrset_changes(
        "example.lan",
        [Change(ChangeOp.REPLACE, "example.lan/www/A", after={"rdata": ["192.0.2.11"]})],
        created_by="alice",
    )
    assert plan.state is PlanState.VALIDATED and plan.scope is PlanScope.DNS_RRSET
    assert (plan.expires_at - plan.created_at).total_seconds() == 60
    kinds = [(p.kind, p.value) for p in plan.preconditions]
    assert kinds == [(PreconditionKind.RRSET_EXISTS, "192.0.2.10"), (PreconditionKind.SOA_SERIAL, "42")]
    sent: list[Any] = []

    def fake_update(zone: str, key: Any, build: Any) -> str:
        import dns.update

        msg = dns.update.Update(zone)
        build(msg)
        sent.append((zone, key.name, msg))
        return sent_rcode[0]

    sent_rcode = ["NOERROR"]
    monkeypatch.setattr(backend.dns, "update", fake_update)
    result = backend.apply(plan)
    assert result.ok and result.node_id == "n1"
    assert sent[0][0] == "example.lan." and sent[0][1] == "ddi-admin."
    assert backend.details[plan.id]["apply"]["request"]["update"].startswith(
        "zone example.lan.\nprereq yxrrset"
    )

    sent_rcode[0] = "NXRRSET"
    failed = backend.apply(plan)
    assert not failed.ok and "prerequisite failed" in failed.message

    def denied(*_: Any) -> str:
        raise ConnectorDenied("UPDATE to example.lan refused: REFUSED")

    monkeypatch.setattr(backend.dns, "update", denied)
    assert "REFUSED" in backend.apply(plan).message

    empty = backend.plan_rrset_changes("example.lan", [])
    assert empty.state is PlanState.FAILED and empty.error == "no change"


def test_zone_plan_apply_and_rollback(tmp_root: Path, conf_tree: Path) -> None:
    backend, rec = make_backend(tmp_root, conf_tree)
    zones_conf = conf_tree / "pelagos" / "zones.conf"
    plan = backend.plan_zone_change(Change(ChangeOp.ADD, "_default/lab.example.lan", after=LAB_ZONE), "alice")
    assert plan.state is PlanState.VALIDATED, plan.validations
    zone_file = tmp_root / "var" / "pelagos" / "lab.example.lan.db"
    assert plan.changes[0].after["file"] == str(zone_file)
    pre = {p.subject: p.value for p in plan.preconditions}
    assert set(pre) == {str(zones_conf), str(zone_file)} and pre[str(zone_file)] == "absent"
    rec.zones.add("lab.example.lan")  # what reconfig would make visible
    result = backend.apply(plan)
    assert result.ok, result.message
    assert ("reconfig",) in rec.calls
    assert 'zone "lab.example.lan" {' in zones_conf.read_text()
    assert "IN SOA ns1.lab.example.lan. hostmaster.lab.example.lan." in zone_file.read_text()
    assert oct(zone_file.stat().st_mode & 0o777) == "0o664"
    assert oct(zones_conf.stat().st_mode & 0o777) == "0o640"
    # named creates the journal next to the zone file: the directory is setgid and group writable.
    assert oct(zone_file.parent.stat().st_mode & 0o7777) == "0o2775"
    # Re-applying is a precondition failure: zones.conf moved on since the plan.
    again = backend.apply(plan)
    assert not again.ok and "file_sha256" in again.message

    rolled = backend.rollback(plan)
    assert rolled.ok and rolled.rolled_back
    assert zones_conf.read_text() == "# pelagos:managed v1\n" and not zone_file.exists()


def test_zone_plan_failures(tmp_root: Path, conf_tree: Path) -> None:
    backend, _ = make_backend(tmp_root, conf_tree)
    user = backend.plan_zone_change(
        Change(ChangeOp.REPLACE, "_default/example.lan", after={"kind": "primary"})
    )
    assert user.state is PlanState.FAILED and "user file" in user.error
    view = backend.plan_zone_change(Change(ChangeOp.ADD, "inside/x.example.lan", after={"kind": "primary"}))
    assert "no view 'inside'" in view.error
    sec = backend.plan_zone_change(
        Change(ChangeOp.ADD, "_default/s.example.lan", after={"kind": "secondary"})
    )
    assert "needs primaries" in sec.error
    gone = backend.plan_zone_change(Change(ChangeOp.DELETE, "_default/none.example.lan"))
    assert "not managed by Pelagos" in gone.error
    # Without the top-level include line, a zone in zones.conf would never load.
    named = conf_tree / "named.conf"
    named.write_text(named.read_text().replace(f'include "{conf_tree}/pelagos/pelagos.conf";\n', ""))
    missing = backend.plan_zone_change(
        Change(ChangeOp.ADD, "_default/y.example.lan", after={"kind": "primary"})
    )
    assert "is not included" in missing.error


def test_checkconf_failure_at_plan_time(tmp_root: Path, conf_tree: Path) -> None:
    backend, _ = make_backend(tmp_root, conf_tree, ok=False)
    plan = backend.plan_config_change(
        [Change(ChangeOp.ADD, "acls/lan", after={"elements": ["192.0.2.0/24"]})]
    )
    assert plan.state is PlanState.FAILED and plan.scope is PlanScope.DNS_ACL
    assert plan.validations[0].tool == "named-checkconf" and "bad config" in plan.validations[0].output


def test_checkconf_failure_at_apply_restores_without_reconfig(tmp_root: Path, conf_tree: Path) -> None:
    backend, rec = make_backend(tmp_root, conf_tree)
    plan = backend.plan_config_change([Change(ChangeOp.ADD, "options/notify-rate", after="20")])
    assert plan.state is PlanState.VALIDATED
    backend.checkconf = script(tmp_root / "failing", "echo injected; exit 1")
    options_conf = conf_tree / "pelagos" / "options.conf"
    before = options_conf.read_text()
    result = backend.apply(plan)
    assert not result.ok and result.rolled_back and "injected" in result.message
    assert options_conf.read_text() == before
    assert ("reconfig",) not in rec.calls


def test_key_plans_mask_secrets(tmp_root: Path, conf_tree: Path) -> None:
    backend, _ = make_backend(tmp_root, conf_tree)
    plan = backend.plan_config_change([Change(ChangeOp.ADD, "keys/xfr", after={"algorithm": "hmac-sha512"})])
    assert plan.state is PlanState.VALIDATED and not plan.requires_confirmation
    secret = plan.changes[0].after["secret"]
    assert len(secret) == 88 and secret not in plan.diff and 'secret "****";' in plan.diff
    assert backend.apply(plan).ok
    rotate = backend.plan_config_change(
        [Change(ChangeOp.REPLACE, "keys/xfr", after={"secret": "bmV3LXNlY3JldA=="})]
    )
    assert rotate.requires_confirmation and rotate.changes[0].before == {
        "name": "xfr",
        "algorithm": "hmac-sha512",
        "secret": "****",
        "notes": None,
    }
    bad = backend.plan_config_change([Change(ChangeOp.ADD, "keys/k2", after={"algorithm": "hmac-md4"})])
    assert "unsupported TSIG algorithm" in bad.error
    user = backend.plan_config_change([Change(ChangeOp.DELETE, "keys/ddi-admin")])
    assert "user file" in user.error
    unknown = backend.plan_config_change([Change(ChangeOp.ADD, "options/not-an-option", after="1")])
    assert "not an options statement" in unknown.error
    raw = backend.plan_config_change([Change(ChangeOp.ADD, "raw:../named.conf", after="acl x { none; };")])
    assert "not a managed file" in raw.error
    assert backend.plan_config_change([]).error == "no change"


def test_include_setup_plan(tmp_root: Path) -> None:
    etc = tmp_root / "etc"
    etc.mkdir()
    (tmp_root / "var").mkdir()
    (etc / "named.conf").write_text(f'options {{\n\tdirectory "{tmp_root}/var";\n}};\n')
    backend, _ = make_backend(tmp_root, etc)
    plan = backend.plan_include_setup()
    assert plan.state is PlanState.VALIDATED, plan.validations
    assert f'+\tinclude "{etc}/pelagos/options.conf";' in plan.diff
    assert backend.apply(plan).ok
    tree = backend.read_config()
    assert tree.pelagos["include_line_present"] and tree.pelagos["options_include_present"]
    assert all(tree.pelagos["managed_files"].values())
    assert backend.plan_include_setup().error == "no change"


def test_capabilities_when_everything_is_down(tmp_root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    backend, _ = make_backend(tmp_root)

    def down(*_: Any, **__: Any) -> Any:
        raise ConnectorUnavailable("down")

    monkeypatch.setattr(backend.rndc, "status", down)
    monkeypatch.setattr(backend.stats, "fetch", down)
    monkeypatch.setattr(backend.dns, "soa_serial", down)
    caps = backend.capabilities()
    assert not caps.running and not caps.rndc and not caps.statistics_channel
    assert caps.tsig_admin_key == "ddi-admin"


def test_rndc_helpers() -> None:
    assert zone_args("example.lan.") == ["example.lan"]
    assert zone_args("example.lan", "_default") == ["example.lan"]
    assert zone_args("example.lan", "internal") == ["example.lan", "IN", "internal"]
    st = zone_status_from(
        "example.lan",
        None,
        "n1",
        {
            "type": "secondary",
            "serial": "7",
            "files": "a.db",
            "dynamic": "no",
            "secure": "yes",
            "next refresh": "Sat, 24 Oct 2026 12:29:37 GMT",
            "expires": "bogus",
        },
    )
    assert st.kind is ZoneKind.SECONDARY and st.config_serial == 7 and st.signed and not st.dynamic
    assert st.next_refresh and st.next_refresh.hour == 12 and st.expires is None
    status = parse_dnssec_status(
        "dnssec-policy: default\ncurrent time:  Sat Oct 24 12:29:39 2026\n\n"
        "key: 46805 (ECDSAP256SHA256), CSK\n  published:      yes - since Sat Oct 24 12:29:37 2026\n"
        "  key signing:    yes\n\n  No rollover scheduled\n  - goal:           omnipresent\n"
    )
    assert status["policy"] == "default" and status["signed"]
    (key,) = status["keys"]
    assert key["id"] == 46805 and key["algorithm"] == "ECDSAP256SHA256" and key["roles"] == ["CSK"]
    assert key["states"]["goal"] == "omnipresent" and key["notes"] == ["No rollover scheduled"]
    assert parse_dnssec_status("Zone does not have dnssec-policy\n")["signed"] is False


def test_zone_files_stay_in_pelagos_directories(tmp_root: Path, conf_tree: Path) -> None:
    backend, _ = make_backend(tmp_root, conf_tree)
    planted = tmp_root / "elsewhere" / "deep" / "planted.txt"
    outside = backend.plan_zone_change(
        Change(ChangeOp.ADD, "_default/z2.example.lan", after={"kind": "primary", "file": str(planted)})
    )
    assert outside.state is PlanState.FAILED and "outside" in outside.error
    assert not any(str(planted) == p.subject for p in outside.preconditions)
    escape = backend.plan_zone_change(
        Change(ChangeOp.ADD, "_default/z3.example.lan", after={"kind": "primary", "file": "../../etc/x.db"})
    )
    assert "outside" in escape.error
    sec = backend.plan_zone_change(
        Change(
            ChangeOp.ADD,
            "_default/s.example.lan",
            after={"kind": "secondary", "primaries": ["192.0.2.1"], "file": "/tmp/s.db"},
        )
    )
    assert "outside" in sec.error
    inside = backend.plan_zone_change(
        Change(ChangeOp.ADD, "_default/z4.example.lan", after={"kind": "primary", "file": "z4.db", "ns": NS})
    )
    assert inside.state is PlanState.VALIDATED, inside.error
    assert inside.changes[0].after["file"] == "z4.db"


def test_new_zone_records_relative_owners(tmp_root: Path, conf_tree: Path) -> None:
    backend, _ = make_backend(tmp_root, conf_tree)
    after = {
        "kind": "primary",
        "ns": ["ns1.example.lan."],
        "records": [
            {"name": "www", "rtype": "A", "ttl": 300, "rdata": ["192.0.2.10"]},
            {"name": "@", "rtype": "TXT", "ttl": 300, "rdata": ['"v=1"']},
        ],
    }
    plan = backend.plan_zone_change(Change(ChangeOp.ADD, "_default/r.example.lan", after=after))
    assert plan.state is PlanState.VALIDATED, plan.error
    names = [r["name"] for r in plan.changes[0].after["records"]]
    assert names == ["www.r.example.lan.", "r.example.lan."]
    assert "www.r.example.lan. 300 IN A 192.0.2.10" in plan.diff
    after["records"] = [{"name": "www.other.lan.", "rtype": "A", "ttl": 300, "rdata": ["192.0.2.1"]}]
    bad = backend.plan_zone_change(Change(ChangeOp.ADD, "_default/r2.example.lan", after=after))
    assert bad.state is PlanState.FAILED and "outside zone" in bad.error


def test_managed_key_wins_over_cluster_secret(tmp_root: Path, conf_tree: Path) -> None:
    backend, _ = make_backend(tmp_root, conf_tree)
    assert backend._require_key("read").secret == "c2VjcmV0"  # not in keys.conf: cluster secret
    plan = backend.plan_config_change(
        [Change(ChangeOp.ADD, "keys/ddi-read", after={"secret": "cm90YXRlZA=="})]
    )
    assert backend.apply(plan).ok
    key = backend._require_key("read")
    assert key.secret == "cm90YXRlZA==" and key.algorithm == "hmac-sha256"
    rotate = backend.plan_config_change(
        [Change(ChangeOp.REPLACE, "keys/ddi-read", after={"secret": "YWdhaW4="})]
    )
    assert backend.apply(rotate).ok
    assert backend._require_key("read").secret == "YWdhaW4="
    # A user key is still overridden by the cluster secret.
    assert backend._require_key("admin").secret == "c2VjcmV0"


def test_views_need_a_view_key(tmp_root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    backend, _ = make_backend(tmp_root)
    seen: list[Any] = []
    monkeypatch.setattr(backend.dns, "axfr", lambda zone, key=None: seen.append(key) or ZONE_DATA)
    with pytest.raises(NotSupported, match="view_keys"):
        backend.read_zone("example.lan", "inside")
    with pytest.raises(NotSupported):
        backend.plan_rrset_changes("example.lan", [], view="inside")
    backend.ctx.settings["dns"]["view_keys"] = {"inside": {"read": "ddi-admin"}}
    backend.read_zone("example.lan", "inside")
    backend.read_zone("example.lan", "_default")
    assert [k.name for k in seen] == ["ddi-admin.", "ddi-read."]


def test_unreadable_named_conf_is_unavailable(tmp_root: Path, conf_tree: Path) -> None:
    backend, _ = make_backend(tmp_root, conf_tree)
    backend.named_conf = conf_tree  # a directory: IsADirectoryError
    with pytest.raises(ConnectorUnavailable, match="not readable"):
        backend.read_config()
    backend.named_conf = conf_tree / "absent.conf"
    with pytest.raises(ConnectorUnavailable, match="missing"):
        backend.list_zones()
    assert backend.capabilities().views == []


def test_rollback_refuses_over_a_later_plan(tmp_root: Path, conf_tree: Path) -> None:
    backend, _ = make_backend(tmp_root, conf_tree)
    first = backend.plan_config_change([Change(ChangeOp.ADD, "acls/a", after={"elements": ["192.0.2.0/25"]})])
    assert backend.apply(first).ok
    second = backend.plan_config_change(
        [Change(ChangeOp.ADD, "acls/b", after={"elements": ["192.0.2.128/25"]})]
    )
    assert backend.apply(second).ok
    acls = (conf_tree / "pelagos" / "acls.conf").read_text()
    refused = backend.rollback(first)
    assert not refused.ok and "rollback refused" in refused.message
    assert (conf_tree / "pelagos" / "acls.conf").read_text() == acls
    assert backend.rollback(second).ok and backend.rollback(first).ok
    assert backend.pop_details(first.id)["rollback"]["backup_dir"]
    assert first.id not in backend.details


def test_details_are_bounded(tmp_root: Path) -> None:
    from pelagos.connectors.bind.backend import MAX_DETAILS

    backend, _ = make_backend(tmp_root)
    for i in range(MAX_DETAILS + 10):
        backend._plan_details(f"p{i}")
    assert len(backend.details) == MAX_DETAILS and "p0" not in backend.details


def test_static_zone_follows_named_and_the_default_view(
    tmp_root: Path, conf_tree: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend, rec = make_backend(tmp_root, conf_tree)
    assert backend.static_zone("example.lan") is not None  # rndc cannot tell: the config decides
    rec.zones.add("example.lan")
    monkeypatch.setattr(rec, "zonestatus", lambda zone, view=None: {"type": "primary", "dynamic": "yes"})
    assert backend.static_zone("example.lan") is None  # named reports it dynamic: UPDATE it is
    conf = conf_tree / "named.conf"
    conf.write_text(
        conf.read_text().replace(
            'zone "example.lan" { type primary; file "example.lan.db"; };',
            'view "inside" { zone "example.lan" { type primary; file "example.lan.db"; }; };',
        )
    )
    assert backend.config_zone("example.lan") is None
    assert backend.config_zone("example.lan", "inside") is not None


@pytest.mark.parametrize(
    ("after", "error"),
    [
        ({"kind": "primary"}, "needs name servers"),
        ({"kind": "primary", "ns": ["localhost."]}, "serves the zone to nobody"),
        ({"kind": "primary", "ns": ["ns1.n.example.lan."]}, "add its A or AAAA record"),
    ],
)
def test_new_primary_needs_real_name_servers(tmp_root: Path, conf_tree: Path, after, error) -> None:
    backend, _ = make_backend(tmp_root, conf_tree)
    plan = backend.plan_zone_change(Change(ChangeOp.ADD, "_default/n.example.lan", after=after))
    assert plan.state is PlanState.FAILED and error in plan.error


def test_new_primary_falls_back_to_the_default_ns_setting(tmp_root: Path, conf_tree: Path) -> None:
    backend, _ = make_backend(tmp_root, conf_tree)
    backend.ctx.settings["dns"]["default_ns"] = ["ns1.example.net.", "ns2.example.net."]
    plan = backend.plan_zone_change(Change(ChangeOp.ADD, "_default/d.example.lan", after={"kind": "primary"}))
    assert plan.state is PlanState.VALIDATED, plan.error
    assert plan.changes[0].after["ns"] == ["ns1.example.net.", "ns2.example.net."]


def test_strip_rndc_noise_removes_the_default_configuration_warning():
    from pelagos.connectors.bind.rndc import strip_rndc_noise

    raw = (
        "WARNING: key file (/etc/bind/rndc.key) exists, but using default configuration file "
        "(/etc/bind/rndc.conf)\nzone reload queued\n"
    )
    assert strip_rndc_noise(raw).strip() == "zone reload queued"
    assert strip_rndc_noise("plain") == "plain"
