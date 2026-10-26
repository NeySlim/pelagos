# SPDX-License-Identifier: Apache-2.0
"""Hand over: statements move from user files to the managed files, the rest of the file is untouched."""

from __future__ import annotations

from pathlib import Path

import pytest

from pelagos.connectors.base import ConnectorContext
from pelagos.connectors.bind import BindBackend, handover
from pelagos.connectors.bind.namedconf import load_tree, parse
from pelagos.domain.plan import Change, ChangeOp, PlanState
from tests.fixtures.ports import find_binary
from tests.unit.connectors.bind.test_bind_backend_unit import Recorder

pytestmark = pytest.mark.unit

OPTIONS = """\
// Options of this server
options {
\tdirectory "{var}";   // zone files

\t# recursion stays off for the LAN
\trecursion    no ;
\tdnssec-validation   auto;
\tmax-ncache-ttl 600; /* five minutes */
\tallow-recursion {  192.0.2.0/24;
\t\t2001:db8::/64; };
\tlisten-on { 127.0.0.1; }; listen-on-v6 { none; };
};
"""

LOCAL = """\
// Local zones
acl   "lan" { 192.0.2.0/24;   2001:db8::/64; };   // trusted

zone "example.lan" {
    type primary;       // main zone
    file "example.lan.db";
    allow-transfer { key "xfr"; };
};
zone "other.lan" { type primary; file "other.lan.db"; };
"""

KEYS = 'key "xfr" { algorithm hmac-sha256; secret "c2VjcmV0LWZvci10ZXN0cw=="; };\n'


@pytest.fixture
def backend(tmp_root: Path) -> BindBackend:
    etc = tmp_root / "etc"
    (etc / "pelagos").mkdir(parents=True)
    var = tmp_root / "var"
    var.mkdir()
    (etc / "named.conf").write_text(
        "".join(f'include "{etc}/named.conf.{n}";\n' for n in ("options", "keys", "local"))
    )
    (etc / "named.conf.options").write_text(OPTIONS.replace("{var}", str(var)))
    (etc / "named.conf.keys").write_text(KEYS)
    (etc / "named.conf.local").write_text(LOCAL)
    for zone in ("example.lan", "other.lan"):
        (var / f"{zone}.db").write_text(
            f"$TTL 3600\n@ IN SOA ns1.{zone}. h.{zone}. 1 3600 900 1209600 300\n@ IN NS ns1.{zone}.\n"
        )
    ctx = ConnectorContext(
        node_id="n1",
        engine_config={
            "named_conf": str(etc / "named.conf"),
            "include_dir": str(etc / "pelagos"),
            "zone_dir": str(var / "pelagos"),
            "checkconf": find_binary("named-checkconf"),
            "checkzone": find_binary("named-checkzone"),
        },
        backup_root=tmp_root / "backups",
        get_secret={}.get,
        settings={"plans": {"ttl_seconds": 60}, "dns": {"read_key": "ddi-read", "admin_key": "ddi-admin"}},
    )
    be = BindBackend(ctx)
    be.rndc = Recorder()  # type: ignore[assignment]
    setup = be.plan_include_setup()
    assert setup.state is PlanState.VALIDATED, setup.validations
    assert be.apply(setup).ok
    return be


def etc(backend: BindBackend) -> Path:
    return backend.named_conf.parent


def hand(backend: BindBackend, *targets: str, comment: bool = True) -> object:
    changes = [Change(ChangeOp.REPLACE, t, after={"comment": comment}) for t in targets]
    return backend.plan_config_change(changes)


def test_candidates_list_user_statements(backend: BindBackend) -> None:
    rows = {r["target"]: r for r in handover.candidates(backend.read_config(check=False))}
    assert "handover/options/recursion" in rows and "handover/options/max-ncache-ttl" in rows
    assert "handover/options/directory" not in rows
    assert rows["handover/options/recursion"]["managed_file"] == "options.conf"
    assert {"handover/acls/lan", "handover/keys/xfr"} <= set(rows)
    assert rows["handover/zones/_default/example.lan."]["managed_file"] == "zones.conf"
    assert rows["handover/keys/xfr"]["value"].endswith("secret ****")


def test_option_moves_and_file_is_kept_byte_for_byte(backend: BindBackend) -> None:
    path = etc(backend) / "named.conf.options"
    before = path.read_text()
    plan = hand(backend, "handover/options/recursion", "handover/options/max-ncache-ttl")
    assert plan.state is PlanState.VALIDATED, plan.validations
    assert any(v.tool == "effective-value" and v.ok for v in plan.validations)
    assert "options.conf" in plan.diff and "named.conf.options" in plan.diff
    assert backend.apply(plan).ok
    after = path.read_text()
    assert "\t# moved to options.conf by Pelagos\n" in after
    for kept in ("// Options of this server", "# recursion stays off for the LAN", "validation   auto;"):
        assert kept in before and kept in after
    assert "recursion    no ;" not in after and "max-ncache-ttl" not in after
    assert "listen-on { 127.0.0.1; }; listen-on-v6 { none; };" in after
    managed = (etc(backend) / "pelagos" / "options.conf").read_text()
    assert "recursion no;" in managed and "max-ncache-ttl 600;" in managed
    tree = backend.read_config()
    entries = {e.name: e for e in tree.options}
    assert entries["recursion"].managed and entries["max-ncache-ttl"].managed
    assert not entries["dnssec-validation"].managed
    assert tree.pelagos["checkconf"]["ok"]


def test_without_comment_the_line_is_removed(backend: BindBackend) -> None:
    path = etc(backend) / "named.conf.options"
    plan = hand(backend, "handover/options/dnssec-validation", comment=False)
    assert backend.apply(plan).ok
    text = path.read_text()
    assert "dnssec-validation" not in text and "moved to" not in text
    include = f'\tinclude "{etc(backend)}/pelagos/options.conf";\n'
    expected = OPTIONS.replace("{var}", str(backend.named_conf.parent.parent / "var"))
    assert text.replace(include, "") == expected.replace("\tdnssec-validation   auto;\n", "")


def test_multiline_option_value(backend: BindBackend) -> None:
    plan = hand(backend, "handover/options/allow-recursion")
    assert plan.state is PlanState.VALIDATED, plan.validations
    assert backend.apply(plan).ok
    managed = (etc(backend) / "pelagos" / "options.conf").read_text()
    assert "192.0.2.0/24;" in managed and "2001:db8::/64;" in managed


def test_zone_acl_and_key(backend: BindBackend) -> None:
    plan = hand(backend, "handover/zones/_default/example.lan", "handover/acls/lan", "handover/keys/xfr")
    assert plan.state is PlanState.VALIDATED, plan.validations
    assert "c2VjcmV0LWZvci10ZXN0cw==" not in plan.diff and "c2VjcmV0LWZvci10ZXN0cw==" not in str(plan.changes)
    assert plan.requires_confirmation
    assert backend.apply(plan).ok
    local = (etc(backend) / "named.conf.local").read_text()
    assert 'zone "other.lan" { type primary; file "other.lan.db"; };' in local
    assert "example.lan" not in local.replace("# moved to zones.conf", "")
    assert "// Local zones" in local
    zones = (etc(backend) / "pelagos" / "zones.conf").read_text()
    assert 'zone "example.lan"' in zones and "allow-transfer" in zones
    assert 'key "xfr"' in (etc(backend) / "pelagos" / "keys.conf").read_text()
    assert 'acl "lan"' in (etc(backend) / "pelagos" / "acls.conf").read_text()
    checkconf = find_binary("named-checkconf")
    tree = load_tree(backend.named_conf, "n1", checkconf=checkconf, include_dir=backend.include_dir)
    zone = next(z for z in tree.zones if z.name == "example.lan.")
    assert zone.source.value == "pelagos" and tree.pelagos["checkconf"]["ok"]
    assert next(z for z in tree.zones if z.name == "other.lan.").source.value == "user_conf"


def test_refusals(backend: BindBackend) -> None:
    for target in ("handover/options/directory", "handover/options/nope", "handover/acls/none"):
        plan = hand(backend, target)
        assert plan.state is PlanState.FAILED
    assert backend.plan_config_change([Change(ChangeOp.DELETE, "handover/options/recursion")]).state is (
        PlanState.FAILED
    )
    assert hand(backend, "handover/bogus/x").state is PlanState.FAILED
    assert hand(backend, "handover/zones/x").state is PlanState.FAILED


RNDC_KEY = 'key "rndc-key" {\n\talgorithm hmac-sha256;\n\tsecret "cm5kYy1zZWNyZXQtZm9yLXRlc3Rz";\n};\n'
CONTROLS = (
    'key "ctl" { algorithm hmac-sha256; secret "Y3RsLXNlY3JldC1mb3ItdGVzdHM="; };\n'
    'controls { inet 127.0.0.1 port 953 allow { 127.0.0.1; } keys { "ctl"; }; };\n'
    'view "v1" { match-clients { any; }; key "inview" { algorithm hmac-sha256; '
    'secret "dmlldy1zZWNyZXQtZm9yLXRlc3Rz"; }; };\n'
)


def test_control_channel_and_view_keys_are_not_offered(backend: BindBackend) -> None:
    (etc(backend) / "rndc.key").write_text(RNDC_KEY)
    with (etc(backend) / "named.conf").open("a") as f:
        f.write(f'include "{etc(backend)}/rndc.key";\n' + CONTROLS)
    rows = {r["target"] for r in handover.candidates(backend.read_config(check=False))}
    assert "handover/keys/xfr" in rows
    assert not rows & {"handover/keys/rndc-key", "handover/keys/ctl", "handover/keys/inview"}
    for name in ("rndc-key", "ctl", "inview"):
        plan = hand(backend, f"handover/keys/{name}")
        assert plan.state is PlanState.FAILED
    assert "stays in the user file" in hand(backend, "handover/keys/ctl").error
    assert "rndc-key" not in (etc(backend) / "pelagos" / "keys.conf").read_text()


def test_replay_skips_a_statement_this_node_does_not_have(backend: BindBackend) -> None:
    plan = hand(backend, "handover/options/recursion", "handover/acls/lan")
    assert plan.state is PlanState.VALIDATED
    (etc(backend) / "named.conf.local").write_text(LOCAL.replace('acl   "lan"', 'acl "gone"'))
    plan.preconditions = []  # as on a peer: the file hashes belong to the planning node
    again = backend.apply(plan)
    assert again.ok
    managed = (etc(backend) / "pelagos" / "options.conf").read_text()
    assert "recursion no;" in managed
    assert 'acl "lan"' not in (etc(backend) / "pelagos" / "acls.conf").read_text()


def test_effective_value_change_fails_the_plan(backend: BindBackend, monkeypatch: pytest.MonkeyPatch) -> None:
    real = handover.print_effective
    calls = {"n": 0}

    def drifting(binary: str | None, conf: Path, timeout: float = 30.0) -> str | None:
        out = real(binary, conf, timeout)
        calls["n"] += 1
        return out.replace("recursion no;", "recursion yes;") if out and calls["n"] % 2 == 0 else out

    monkeypatch.setattr(handover, "print_effective", drifting)
    plan = hand(backend, "handover/options/recursion")
    assert plan.state is PlanState.FAILED and "effective value would change" in plan.error


def test_apply_rolls_back_when_the_effective_value_changes(
    backend: BindBackend, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = etc(backend) / "named.conf.options"
    before = path.read_text()
    plan = hand(backend, "handover/options/recursion")
    assert plan.state is PlanState.VALIDATED
    real = handover.print_effective
    state = {"n": 0}

    def drifting(binary: str | None, conf: Path, timeout: float = 30.0) -> str | None:
        out = real(binary, conf, timeout)
        state["n"] += 1
        return out.replace("recursion no;", "recursion yes;") if out and state["n"] > 1 else out

    monkeypatch.setattr(handover, "print_effective", drifting)
    result = backend.apply(plan)
    assert not result.ok and result.rolled_back
    assert path.read_text() == before
    assert "recursion" not in (etc(backend) / "pelagos" / "options.conf").read_text()


def test_replace_with_comment_needs_a_line_of_its_own() -> None:
    doc = parse("options { a 1; b 2; };\n")
    node = doc.find("a", "options")[0]
    assert doc.replace_with_comment(node, "# x") is False
    assert doc.serialize() == "options { a 1; b 2; };\n"
    lone = parse("options {\n\ta 1; // why\n};\n")
    assert lone.replace_with_comment(lone.find("a", "options")[0], "# moved") is True
    assert lone.serialize() == "options {\n\t# moved // why\n};\n"
