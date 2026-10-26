# SPDX-License-Identifier: Apache-2.0
"""PTR next to A/AAAA in record plans, orphan PTRs and admin exceptions, over the API with fake engines.

The fake BIND serves example.lan. (www 192.0.2.10 and 2001:db8::10, pc1 192.0.2.100 with a DHCID)
and 2.0.192.in-addr.arpa. (PTR of .10 and .100); no reverse zone covers 2001:db8::/64.
"""

from __future__ import annotations

import pytest

from pelagos.domain import RRset

pytestmark = pytest.mark.unit

ZONE = "/api/v1/dns/zones/example.lan/records/plan"
REV = "2.0.192.in-addr.arpa."


def a_change(op: str, owner: str, *ips: str, before: list[str] | None = None) -> dict:
    change = {"op": op, "target": f"{owner}/A"}
    if ips:
        change["after"] = {"ttl": 300, "rdata": list(ips)}
    if before is not None:
        change["before"] = {"name": f"{owner}.example.lan.", "rtype": "A", "ttl": 300, "rdata": before}
    return change


def ptr_targets(dns, ip_last: int) -> list[str] | None:
    rr = dns.rrsets[REV].get((f"{ip_last}.{REV}", "PTR"))
    return rr.rdata if rr else None


def apply(client, plan: dict, confirm: bool = False) -> dict:
    r = client.post(f"/api/v1/plans/{plan['id']}/apply", json={"confirm": confirm})
    assert r.status_code == 200, r.get_json()
    return r.get_json()


def test_coverage(admin, fake_registry):
    r = admin.post(
        "/api/v1/dns/ptr/coverage",
        json={"addresses": ["192.0.2.10", "192.0.2.55", "2001:db8::10", "nope"], "name": "web.example.lan"},
    )
    assert r.status_code == 200, r.get_json()
    items = {i["ip"]: i for i in r.get_json()["items"]}
    assert items["192.0.2.10"]["covered"] and items["192.0.2.10"]["reverse_zone"] == REV
    assert items["192.0.2.10"]["current"] == ["www.example.lan."] and items["192.0.2.10"]["conflict"]
    assert items["192.0.2.55"]["covered"] and items["192.0.2.55"]["current"] == []
    assert not items["192.0.2.55"]["conflict"]
    assert items["2001:db8::10"]["covered"] is False and items["2001:db8::10"]["reason"] == "no_reverse_zone"
    assert items["nope"]["reason"] == "invalid"
    r = admin.post("/api/v1/dns/ptr/coverage", json={"addresses": "192.0.2.1"})
    assert r.status_code == 400


def test_add_a_with_ptr_is_one_plan(admin, fake_registry):
    dns = fake_registry.dns
    r = admin.post(ZONE, json={"changes": [a_change("add", "printer", "192.0.2.40")], "ptr": {"sync": True}})
    assert r.status_code == 200, r.get_json()
    plan = r.get_json()
    assert {c["target"] for c in plan["changes"]} == {
        "example.lan./printer.example.lan./A",
        f"{REV}/40.{REV}/PTR",
    }
    assert plan["requires_confirmation"] is False
    assert plan["summary_message"]["key"] == "common.with_note"
    apply(admin, plan)
    assert ptr_targets(dns, 40) == ["printer.example.lan."]
    r = admin.post(f"/api/v1/plans/{plan['id']}/rollback")
    assert r.status_code == 200, r.get_json()
    assert ptr_targets(dns, 40) is None
    assert ("printer.example.lan.", "A") not in dns.rrsets["example.lan."]


def test_without_ptr_option_the_plan_is_unchanged(admin):
    r = admin.post(ZONE, json={"changes": [a_change("add", "printer", "192.0.2.40")]})
    assert [c["target"] for c in r.get_json()["changes"]] == ["example.lan./printer.example.lan./A"]
    r = admin.post(ZONE, json={"changes": [a_change("add", "printer", "192.0.2.40")], "ptr": {"sync": False}})
    assert [c["target"] for c in r.get_json()["changes"]] == ["example.lan./printer.example.lan./A"]


def test_address_change_moves_the_ptr(admin, fake_registry):
    dns = fake_registry.dns
    change = a_change("replace", "www", "192.0.2.11", before=["192.0.2.10"])
    r = admin.post(ZONE, json={"changes": [change], "ptr": {"sync": True}})
    plan = r.get_json()
    assert r.status_code == 200, plan
    ptr = {c["target"]: c for c in plan["changes"] if c["target"].endswith("/PTR")}
    assert ptr[f"{REV}/10.{REV}/PTR"]["op"] == "delete"
    assert ptr[f"{REV}/11.{REV}/PTR"]["op"] == "add"
    apply(admin, plan)
    assert ptr_targets(dns, 10) is None
    assert ptr_targets(dns, 11) == ["www.example.lan."]


def test_ptr_pointing_elsewhere_needs_confirmation(admin, fake_registry):
    dns = fake_registry.dns
    # pc1's address is reused by a new name: the PTR of .100 points to pc1 now.
    r = admin.post(ZONE, json={"changes": [a_change("add", "kiosk", "192.0.2.100")], "ptr": {"sync": True}})
    plan = r.get_json()
    assert plan["requires_confirmation"] is True
    assert any(v["tool"] == "ptr" and "pc1.example.lan." in v["output"] for v in plan["validations"])
    assert "pc1.example.lan." in plan["summary"]
    r = admin.post(f"/api/v1/plans/{plan['id']}/apply", json={"confirm": False})
    assert r.status_code == 428
    apply(admin, plan, confirm=True)
    assert ptr_targets(dns, 100) == ["kiosk.example.lan."]


def test_kept_address_never_overwrites_a_ptr(admin, fake_registry):
    dns = fake_registry.dns
    dns.rrsets[REV][(f"10.{REV}", "PTR")] = RRset(f"10.{REV}", "PTR", 300, ["web.example.lan."])
    # A TTL edit of www keeps 192.0.2.10, whose PTR names another host: left alone.
    change = {
        "op": "replace",
        "target": "www/A",
        "after": {"ttl": 600, "rdata": ["192.0.2.10", "192.0.2.12"]},
    }
    plan = admin.post(ZONE, json={"changes": [change], "ptr": {"sync": True}}).get_json()
    targets = {c["target"] for c in plan["changes"]}
    assert f"{REV}/10.{REV}/PTR" not in targets and f"{REV}/12.{REV}/PTR" in targets
    assert plan["requires_confirmation"] is False


def test_delete_a_offers_the_ptr(admin, fake_registry):
    dns = fake_registry.dns
    body = {"changes": [{"op": "delete", "target": "pc1/A"}], "ptr": {"sync": False, "delete": True}}
    plan = admin.post(ZONE, json=body).get_json()
    assert f"{REV}/100.{REV}/PTR" in {c["target"] for c in plan["changes"]}
    apply(admin, plan)
    assert ptr_targets(dns, 100) is None
    # Without `delete`, the PTR stays.
    body = {"changes": [{"op": "delete", "target": "www/A"}], "ptr": {"sync": False, "delete": False}}
    plan = admin.post(ZONE, json=body).get_json()
    assert [c["target"] for c in plan["changes"]] == ["example.lan./www.example.lan./A"]


def test_multi_address_rrset_keeps_other_ptr_targets(admin, fake_registry):
    dns = fake_registry.dns
    dns.rrsets[REV][(f"10.{REV}", "PTR")] = RRset(
        f"10.{REV}", "PTR", 300, ["www.example.lan.", "alias.example.lan."]
    )
    body = {"changes": [{"op": "delete", "target": "www/A"}], "ptr": {"delete": True}}
    plan = admin.post(ZONE, json=body).get_json()
    [ptr] = [c for c in plan["changes"] if c["target"].endswith("/PTR")]
    assert ptr["op"] == "replace" and ptr["after"]["rdata"] == ["alias.example.lan."]


def test_uncovered_address_is_noted(admin):
    change = {"op": "add", "target": "v6host/AAAA", "after": {"ttl": 300, "rdata": ["2001:db8::99"]}}
    plan = admin.post(ZONE, json={"changes": [change], "ptr": {"sync": True}}).get_json()
    assert [c["target"] for c in plan["changes"]] == ["example.lan./v6host.example.lan./AAAA"]
    assert "2001:db8::99" in plan["summary"]


def test_reverse_view_is_used(admin, services, monkeypatch):
    seen: list[tuple[str, str | None]] = []
    real = services.ptr.reverse_zone

    def spy(ip, view, zones=None):
        seen.append((ip, view))
        return real(ip, None, zones)

    monkeypatch.setattr(services.ptr, "reverse_zone", spy)
    monkeypatch.setattr(services.ptr, "_rrset", lambda zone, view, name, rtype: None)
    body = {"changes": [a_change("add", "printer", "192.0.2.40")], "ptr": {"reverse_view": "outside"}}
    admin.post(ZONE, json=body)
    assert seen == [("192.0.2.40", "outside")]


def test_orphans_list_and_cleanup(admin, fake_registry):
    dns = fake_registry.dns
    rev = dns.rrsets[REV]
    rev[(f"70.{REV}", "PTR")] = RRset(f"70.{REV}", "PTR", 300, ["www.example.lan."])
    rev[(f"80.{REV}", "PTR")] = RRset(f"80.{REV}", "PTR", 300, ["printer.example.lan."])
    rev[(f"80.{REV}", "DHCID")] = RRset(
        f"80.{REV}", "DHCID", 300, ["AAIBY2/AuCccgoJbsaxcQc9TUapptP69lOjxfNuVAA2kjEA="]
    )
    rev[(f"90.{REV}", "PTR")] = RRset(f"90.{REV}", "PTR", 300, ["mail.example.net."])
    r = admin.get("/api/v1/dns/ptr/orphans")
    assert r.status_code == 200, r.get_json()
    body = r.get_json()
    items = {i["ip"]: i for i in body["items"]}
    assert sorted(items) == ["192.0.2.70", "192.0.2.80", "192.0.2.90"]
    assert items["192.0.2.70"]["fix"] == "delete" and items["192.0.2.70"]["zone"] == REV
    assert items["192.0.2.80"]["fix"] == "create_a" and items["192.0.2.80"]["ddns"] is True
    assert items["192.0.2.90"]["category"] == "external"
    assert body["counts"] == {"orphan": 2, "external": 1, "excepted": 0}
    plan = admin.post(
        "/api/v1/dns/ptr/orphans/plan",
        json={
            "delete": [{"zone": REV, "name": f"70.{REV}", "target": "www.example.lan."}],
            "create": [{"ip": "192.0.2.80", "target": "printer.example.lan."}],
        },
    ).get_json()
    assert plan["requires_confirmation"] is True
    assert plan["summary_message"]["key"] == "plan.ptr.cleanup"
    apply(admin, plan, confirm=True)
    assert ptr_targets(dns, 70) is None
    assert dns.rrsets["example.lan."][("printer.example.lan.", "A")].rdata == ["192.0.2.80"]
    left = {i["ip"] for i in admin.get("/api/v1/dns/ptr/orphans").get_json()["items"]}
    assert left == {"192.0.2.90"}


def test_orphans_plan_validation(admin):
    r = admin.post("/api/v1/dns/ptr/orphans/plan", json={})
    assert r.status_code == 400
    r = admin.post(
        "/api/v1/dns/ptr/orphans/plan",
        json={"delete": [{"zone": "example.lan.", "name": "www.example.lan.", "target": "x.example.lan."}]},
    )
    assert r.status_code == 400
    r = admin.post(
        "/api/v1/dns/ptr/orphans/plan", json={"create": [{"ip": "bad", "target": "x.example.lan."}]}
    )
    assert r.status_code == 400
    r = admin.post(
        "/api/v1/dns/ptr/orphans/plan", json={"create": [{"ip": "192.0.2.80", "target": "x.example.net."}]}
    )
    assert r.status_code == 400


def test_exceptions_lifecycle(admin, role_client, node_ctx, fake_registry):
    dns = fake_registry.dns
    dns.rrsets[REV][(f"90.{REV}", "PTR")] = RRset(f"90.{REV}", "PTR", 300, ["mail.example.net."])
    r = admin.post(
        "/api/v1/alerts/exceptions", json={"kind": "ptr_mismatch", "key": "192.0.2.90|mail.example.net."}
    )
    assert r.status_code == 400 and r.get_json()["errors"][0]["field"] == "comment"
    r = admin.post("/api/v1/alerts/exceptions", json={"kind": "nope", "key": "x", "comment": "c"})
    assert r.status_code == 400
    # An outage is never kept as a choice; a health check such as disk space may be.
    r = admin.post(
        "/api/v1/alerts/exceptions", json={"kind": "ha_terminated", "key": "ha:kea4", "comment": "c"}
    )
    assert r.status_code == 400
    disk = {"kind": "disk_space", "key": "n1|disk:/srv/archive", "comment": "archive volume, full by design"}
    r = admin.post("/api/v1/alerts/exceptions", json=disk)
    assert r.status_code == 201
    assert admin.delete(f"/api/v1/alerts/exceptions/{r.get_json()['id']}").status_code in (200, 204)
    body = {"kind": "ptr_mismatch", "key": "192.0.2.90|mail.example.net.", "comment": "mail relay of the ISP"}
    r = admin.post("/api/v1/alerts/exceptions", json=body)
    assert r.status_code == 201, r.get_json()
    created = r.get_json()
    assert created["created_by"] == "admin" and created["comment"] == "mail relay of the ISP"
    assert admin.post("/api/v1/alerts/exceptions", json=body).status_code == 409
    # Replicated state: the record is in cluster.toml.
    assert [e["key"] for e in node_ctx.cluster().exceptions] == ["192.0.2.90|mail.example.net."]
    assert "[[exceptions]]" in node_ctx.config_store.cluster_path.read_text()
    items = role_client("viewer").get("/api/v1/alerts/exceptions").get_json()["items"]
    assert [i["id"] for i in items] == [created["id"]]
    assert role_client("viewer").post("/api/v1/alerts/exceptions", json=body).status_code == 403
    orphan = admin.get("/api/v1/dns/ptr/orphans").get_json()
    [item] = [i for i in orphan["items"] if i["ip"] == "192.0.2.90"]
    assert item["excepted"] is True and item["exception"]["id"] == created["id"]
    assert orphan["counts"]["excepted"] == 1
    actions = [e.action for e in node_ctx.audit_log.read()]
    assert "alert.exception.add" in actions
    assert admin.delete(f"/api/v1/alerts/exceptions/{created['id']}").status_code == 204
    assert admin.delete(f"/api/v1/alerts/exceptions/{created['id']}").status_code == 404
    assert node_ctx.cluster().exceptions == []
    actions = [e.action for e in node_ctx.audit_log.read()]
    assert "alert.exception.revoke" in actions


def test_security_exceptions_need_admin_settings(admin, role_client):
    op = role_client("dns-operator")
    sec = {"kind": "insecure_key", "key": "n1|key:old", "comment": "lab key"}
    disk = {"kind": "disk_space", "key": "n1|disk:/srv/a", "comment": "full by design"}
    assert op.post("/api/v1/alerts/exceptions", json=sec).status_code == 403
    assert op.post("/api/v1/alerts/exceptions", json=disk).status_code == 201
    made = admin.post("/api/v1/alerts/exceptions", json=sec)
    assert made.status_code == 201
    assert op.delete(f"/api/v1/alerts/exceptions/{made.get_json()['id']}").status_code == 403
    assert admin.delete(f"/api/v1/alerts/exceptions/{made.get_json()['id']}").status_code == 204


DHCID = "AAIBY2/AuCccgoJbsaxcQc9TUapptP69lOjxfNuVAA2kjEA="


def test_orphan_delete_takes_the_ddns_dhcid(admin, fake_registry):
    dns = fake_registry.dns
    rev = dns.rrsets[REV]
    rev[(f"80.{REV}", "PTR")] = RRset(f"80.{REV}", "PTR", 300, ["gone.example.lan."])
    rev[(f"80.{REV}", "DHCID")] = RRset(f"80.{REV}", "DHCID", 300, [DHCID])
    plan = admin.post(
        "/api/v1/dns/ptr/orphans/plan",
        json={"delete": [{"zone": REV, "name": f"80.{REV}", "target": "gone.example.lan."}]},
    ).get_json()
    ops = {c["target"]: c["op"] for c in plan["changes"]}
    assert ops == {f"{REV}/80.{REV}/PTR": "delete", f"{REV}/80.{REV}/DHCID": "delete"}
    apply(admin, plan, confirm=True)
    assert (f"80.{REV}", "PTR") not in rev and (f"80.{REV}", "DHCID") not in rev


def test_orphan_delete_keeps_dhcid_while_a_ptr_target_stays(admin, fake_registry):
    dns = fake_registry.dns
    rev = dns.rrsets[REV]
    rev[(f"80.{REV}", "PTR")] = RRset(f"80.{REV}", "PTR", 300, ["gone.example.lan.", "pc1.example.lan."])
    rev[(f"80.{REV}", "DHCID")] = RRset(f"80.{REV}", "DHCID", 300, [DHCID])
    plan = admin.post(
        "/api/v1/dns/ptr/orphans/plan",
        json={"delete": [{"zone": REV, "name": f"80.{REV}", "target": "gone.example.lan."}]},
    ).get_json()
    assert [c["target"] for c in plan["changes"]] == [f"{REV}/80.{REV}/PTR"]


def test_record_delete_takes_the_ddns_dhcid(admin, fake_registry):
    dns = fake_registry.dns
    dns.rrsets[REV][(f"100.{REV}", "DHCID")] = RRset(f"100.{REV}", "DHCID", 300, [DHCID])
    body = {"changes": [{"op": "delete", "target": "pc1/A"}], "ptr": {"sync": False, "delete": True}}
    plan = admin.post(ZONE, json=body).get_json()
    assert f"{REV}/100.{REV}/DHCID" in {c["target"] for c in plan["changes"]}
    apply(admin, plan)
    assert (f"100.{REV}", "DHCID") not in dns.rrsets[REV]


def test_kept_address_pointing_elsewhere_is_noted(admin, fake_registry):
    dns = fake_registry.dns
    dns.rrsets[REV][(f"10.{REV}", "PTR")] = RRset(f"10.{REV}", "PTR", 300, ["web.example.lan."])
    change = {"op": "replace", "target": "www/A", "after": {"ttl": 600, "rdata": ["192.0.2.10"]}}
    plan = admin.post(ZONE, json={"changes": [change], "ptr": {"sync": True}}).get_json()
    assert "web.example.lan." in plan["summary"] and plan["requires_confirmation"] is False
    change["after"]["rdata"] = ["192.0.2.10", "192.0.2.12"]
    plan = admin.post(ZONE, json={"changes": [change], "ptr": {"sync": True}}).get_json()
    assert "web.example.lan." in plan["summary"] and plan["requires_confirmation"] is False


def test_exception_duplicate_is_refused_under_the_lock(admin, node_ctx, monkeypatch):
    from pelagos.services import exceptions_service

    body = {"kind": "duplicate_ip", "key": "192.0.2.31", "comment": "two NICs of one host"}
    assert admin.post("/api/v1/alerts/exceptions", json=body).status_code == 201
    # A request that read the file before the first write passes the early check, not the locked one.
    real = exceptions_service._same
    calls: list[int] = []

    def racing(entries, kind, key):
        calls.append(1)
        return False if len(calls) == 1 else real(entries, kind, key)

    monkeypatch.setattr(exceptions_service, "_same", racing)
    assert admin.post("/api/v1/alerts/exceptions", json=body).status_code == 409
    assert len(calls) == 2 and len(node_ctx.cluster().exceptions) == 1


def test_revoke_drops_every_record_of_the_pair(admin, node_ctx):
    def add(c):
        for i in ("a", "b"):
            c.exceptions.append({"id": i, "kind": "duplicate_ip", "key": "192.0.2.31", "comment": "c"})
        c.exceptions.append({"id": "c", "kind": "duplicate_ip", "key": "192.0.2.32", "comment": "c"})

    node_ctx.config_store.update_cluster(add, updated_by="test")
    assert admin.delete("/api/v1/alerts/exceptions/a").status_code == 204
    assert [e["id"] for e in node_ctx.cluster().exceptions] == ["c"]
