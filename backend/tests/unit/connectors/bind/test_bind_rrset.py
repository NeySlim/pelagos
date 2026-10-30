# SPDX-License-Identifier: Apache-2.0
"""RRset plans without a server: targets, checks, prerequisites, UPDATE content, diff and inverse."""

from __future__ import annotations

import dns.update
import pytest

from pelagos.connectors.bind import rrset as rr
from pelagos.domain.dns import RRset
from pelagos.domain.plan import Change, ChangeOp, PreconditionKind

pytestmark = pytest.mark.unit

ZONE = "example.lan."
CURRENT = [
    RRset("example.lan.", "SOA", 3600, ["ns1.example.lan. hostmaster.example.lan. 7 3600 900 1209600 300"]),
    RRset("example.lan.", "NS", 3600, ["ns1.example.lan."]),
    RRset("www.example.lan.", "A", 300, ["192.0.2.10"]),
    RRset("alias.example.lan.", "CNAME", 300, ["www.example.lan."]),
]


def change(op: str, target: str, after=None, before=None) -> Change:
    return Change(op=ChangeOp(op), target=target, after=after, before=before)


def test_owner_and_target() -> None:
    assert rr.owner_name("@", ZONE) == "example.lan."
    assert rr.owner_name("WWW", ZONE) == "www.example.lan."
    assert rr.owner_name("pc1.example.lan.", ZONE) == "pc1.example.lan."
    with pytest.raises(rr.RRsetError, match="outside zone"):
        rr.owner_name("www.example.net.", ZONE)
    assert rr.parse_target("example.lan/www/a", ZONE) == ("www.example.lan.", "A")
    assert rr.parse_target("/www/AAAA", ZONE) == ("www.example.lan.", "AAAA")
    for bad in ("www/A", "other.lan/www/A", "example.lan/www/NOPE"):
        with pytest.raises(rr.RRsetError):
            rr.parse_target(bad, ZONE)


def test_normalize_rdata() -> None:
    assert rr.normalize_rdata("A", ["192.0.2.2", "192.0.2.1", "192.0.2.1"], ZONE) == [
        "192.0.2.1",
        "192.0.2.2",
    ]
    assert rr.normalize_rdata("CNAME", "www", ZONE) == ["www.example.lan."]
    assert rr.normalize_rdata("MX", ["10 mail"], ZONE) == ["10 mail.example.lan."]
    assert rr.normalize_rdata("TXT", ['"hello world"'], ZONE) == ['"hello world"']
    with pytest.raises(rr.RRsetError, match="invalid A rdata"):
        rr.normalize_rdata("A", ["not-an-ip"], ZONE)


def test_resolve_add_replace_delete() -> None:
    changes = [
        change("add", "example.lan/pc1/A", {"rdata": ["192.0.2.42"], "ttl": 600}),
        change("replace", "example.lan/www/A", {"rdata": ["192.0.2.11"]}),
        change("delete", "example.lan/alias/CNAME"),
    ]
    resolved, errors = rr.resolve_changes(ZONE, changes, CURRENT)
    assert errors == []
    add, rep, dele = resolved
    assert add.after == RRset("pc1.example.lan.", "A", 600, ["192.0.2.42"]) and add.before is None
    # A replace without ttl keeps the current one.
    assert rep.before.rdata == ["192.0.2.10"] and rep.after.ttl == 300
    assert dele.before.rdata == ["www.example.lan."] and dele.after is None
    pre = rr.preconditions(resolved, "n1")
    assert [(p.kind, p.subject, p.value) for p in pre] == [
        (PreconditionKind.RRSET_ABSENT, "pc1.example.lan./A", ""),
        (PreconditionKind.RRSET_EXISTS, "www.example.lan./A", "192.0.2.10"),
        (PreconditionKind.RRSET_EXISTS, "alias.example.lan./CNAME", "www.example.lan."),
    ]
    assert rr.diff_text(resolved) == (
        "+pc1.example.lan. 600 IN A 192.0.2.42\n"
        "-www.example.lan. 300 IN A 192.0.2.10\n"
        "+www.example.lan. 300 IN A 192.0.2.11\n"
        "-alias.example.lan. 300 IN CNAME www.example.lan."
    )
    assert rr.summary_text(ZONE, resolved) == "example.lan.: 1 add, 1 delete, 1 replace"


@pytest.mark.parametrize(
    "c, message",
    [
        (change("add", "example.lan/www/A", {"rdata": ["192.0.2.1"]}), "already exists"),
        (change("replace", "example.lan/nope/A", {"rdata": ["192.0.2.1"]}), "does not exist"),
        (change("delete", "example.lan/nope/A"), "does not exist"),
        (change("add", "example.lan/@/SOA", {"rdata": ["a. b. 1 2 3 4 5"]}), "cannot be changed"),
        (change("add", "example.lan/www/CNAME", {"rdata": ["x"]}), "cannot coexist"),
        (change("add", "example.lan/alias/A", {"rdata": ["192.0.2.1"]}), "is a CNAME"),
        (change("add", "example.lan/pc/A", {"rdata": []}), "rdata is empty"),
        (change("add", "example.lan/pc/A", {"rdata": ["192.0.2.1"], "ttl": -1}), "out of range"),
        (
            change("replace", "example.lan/www/A", {"rdata": ["192.0.2.1"]}, before={"rdata": ["192.0.2.9"]}),
            "changed since it was read",
        ),
        (change("add", "example.lan/pc/HINFO", {"rdata": ['"a" "b"']}), "not in the update types"),
    ],
)
def test_resolve_rejects(c: Change, message: str) -> None:
    resolved, errors = rr.resolve_changes(ZONE, [c], CURRENT, allowed_types=["A", "AAAA", "CNAME", "SOA"])
    assert resolved == [] and len(errors) == 1 and message in errors[0]


def test_duplicate_targets_rejected() -> None:
    c = change("add", "example.lan/pc/A", {"rdata": ["192.0.2.1"]})
    _, errors = rr.resolve_changes(ZONE, [c, c], CURRENT)
    assert errors == ["pc.example.lan. A appears twice in the plan"]


def test_update_message_and_text() -> None:
    changes = [
        change("add", "example.lan/pc1/A", {"rdata": ["192.0.2.42"], "ttl": 600}),
        change("replace", "example.lan/www/A", {"rdata": ["192.0.2.11"]}),
    ]
    resolved, _ = rr.resolve_changes(ZONE, changes, CURRENT)
    msg = dns.update.Update(ZONE)
    rr.build_update(msg, resolved)
    prereq = [r.to_text() for r in msg.prerequisite]
    # nxrrset is class NONE without rdata; the value-dependent yxrrset carries the rdata with TTL 0.
    assert prereq == ["pc1.example.lan. NONE A", "www.example.lan. 0 IN A 192.0.2.10"]
    update = sorted(r.to_text() for r in msg.update)
    assert update == [
        "pc1.example.lan. 600 IN A 192.0.2.42",
        "www.example.lan. 0 NONE A 192.0.2.10",
        "www.example.lan. 300 IN A 192.0.2.11",
    ]
    assert rr.update_text(ZONE, resolved) == (
        "zone example.lan.\n"
        "prereq nxrrset pc1.example.lan. IN A\n"
        "prereq yxrrset www.example.lan. IN A 192.0.2.10\n"
        "update add pc1.example.lan. 600 IN A 192.0.2.42\n"
        "update add www.example.lan. 300 IN A 192.0.2.11\n"
        "update delete www.example.lan. IN A 192.0.2.10\n"
        "send"
    )


def test_inverse_and_plan_round_trip() -> None:
    changes = [
        change("add", "example.lan/pc1/A", {"rdata": ["192.0.2.42"]}),
        change("replace", "example.lan/www/A", {"rdata": ["192.0.2.11"]}),
        change("delete", "example.lan/alias/CNAME"),
    ]
    resolved, _ = rr.resolve_changes(ZONE, changes, CURRENT)
    plan_changes = [rr.to_change(ZONE, rc) for rc in resolved]
    assert plan_changes[0].target == "example.lan./pc1.example.lan./A"
    again = rr.rrset_changes_from_plan(ZONE, [Change.from_dict(c.to_dict()) for c in plan_changes])
    assert again == resolved
    inv = [rr.inverse(rc) for rc in again]
    assert [i.op for i in inv] == [ChangeOp.DELETE, ChangeOp.REPLACE, ChangeOp.ADD]
    assert inv[0].before == resolved[0].after and inv[1].after == resolved[1].before
    assert inv[2].after == resolved[2].before
    assert [rr.inverse(i) for i in inv] == resolved


def test_apex_ns_is_replaced_never_emptied() -> None:
    """named ignores deleting the last apex NS: the new set goes in first, then the old ones leave."""
    current = [*CURRENT, RRset(name=ZONE, rtype="NS", ttl=3600, rdata=["ns-old.example.lan."])]
    resolved, errors = rr.resolve_changes(
        ZONE, [change("replace", "example.lan/@/NS", {"rdata": ["ns1.example.lan."]})], current
    )
    assert not errors
    assert rr.update_text(ZONE, resolved).splitlines()[2:4] == [
        "update add example.lan. 3600 IN NS ns1.example.lan.",
        "update delete example.lan. IN NS ns-old.example.lan.",
    ]
    _, errors = rr.resolve_changes(ZONE, [change("delete", "example.lan/@/NS")], current)
    assert errors and "apex" in errors[0]


def test_cname_next_to_data_added_by_the_same_plan() -> None:
    a = change("add", "example.lan/both/A", {"rdata": ["192.0.2.77"]})
    cname = change("add", "example.lan/both/CNAME", {"rdata": ["www"]})
    _resolved, errors = rr.resolve_changes(ZONE, [a, cname], CURRENT)
    assert any("a CNAME cannot coexist" in e for e in errors)
    _resolved, errors = rr.resolve_changes(ZONE, [cname, a], CURRENT)
    assert any("is a CNAME; other data cannot coexist" in e for e in errors)
    # Replacing a CNAME by an A in one plan stays allowed.
    swap = [
        change("delete", "example.lan/alias/CNAME"),
        change("add", "example.lan/alias/A", {"rdata": ["192.0.2.5"]}),
    ]
    assert rr.resolve_changes(ZONE, swap, CURRENT)[1] == []


def test_errors_carry_translatable_messages() -> None:
    from pelagos.domain import messages

    changes = [
        change("add", "example.lan/www/A", after={"ttl": 300, "rdata": ["999.1.1.1"]}),
        change("add", "example.lan/www/CNAME", after={"ttl": 300, "rdata": ["x.example.lan."]}),
        change("add", "example.lan/alias/A", after={"ttl": 300, "rdata": ["192.0.2.1"]}),
        change("add", "example.lan/x/TXT", after={"ttl": 300, "rdata": ["a"]}),
        change("delete", "example.lan/nope/TXT"),
    ]
    out: list = []
    _, errors = rr.resolve_changes(ZONE, changes, CURRENT, error_messages=out)
    assert len(errors) == len(out) == 4
    assert [m["key"] for m in out] == [
        "rrset.invalid_rdata",
        "rrset.cname_other_data",
        "rrset.is_cname",
        "rrset.missing",
    ]
    assert out[0]["params"] == {"rtype": "A", "value": "999.1.1.1"}
    joined = rr.errors_message(out)
    assert messages.render(joined).splitlines()[0] == "999.1.1.1 is not a valid A value"
    assert rr.errors_message([]) is None


@pytest.mark.parametrize("owner", ["a" * 64, "x..y"])
def test_malformed_owner_is_an_rrset_error(owner):
    with pytest.raises(rr.RRsetError, match="invalid owner"):
        rr.owner_name(owner, "example.lan.")
