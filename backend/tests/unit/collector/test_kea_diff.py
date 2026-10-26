# SPDX-License-Identifier: Apache-2.0
"""Kea pollers: peer differences, HA grace period, external changes, hooks no package owns."""

from __future__ import annotations

import copy
from typing import Any

import pytest

from pelagos.collector.hooks import HookOwnership, builtin_equivalent
from pelagos.collector.kea_shared import divergent, shared_hashes
from pelagos.collector.pollers.bind import BindPoller, managed_files_diff
from pelagos.collector.pollers.kea import KeaPoller
from pelagos.collector.series import SeriesStore, connect
from pelagos.domain import AlertKind, HAPartner
from tests.unit.collector.fakes import NODE, FakeDhcpBackend, FakeDnsBackend
from tests.unit.collector.test_pollers import SETTINGS, Clock, kinds

pytestmark = pytest.mark.unit


@pytest.fixture
def store(tmp_root):
    conn = connect(tmp_root / "series.sqlite")
    yield SeriesStore(conn)
    conn.close()


def peer_config(arch: str, hw: str, extra_hooks: tuple[str, ...] = ()) -> dict[str, Any]:
    """A Kea 2.6 pair member: the hook directory depends on the architecture."""
    hooks = f"/usr/lib/{arch}-linux-gnu/kea/hooks"
    ha = [
        {
            "this-server-name": "ns1",
            "mode": "hot-standby",
            "peers": [
                {"name": "ns1", "url": "http://192.0.2.11:8000/", "role": "primary"},
                {"name": "ns2", "url": "http://192.0.2.12:8000/", "role": "standby"},
            ],
        }
    ]
    return {
        "Dhcp4": {
            "hooks-libraries": [
                {"library": f"{hooks}/libdhcp_lease_cmds.so"},
                {"library": f"{hooks}/libdhcp_ha.so", "parameters": {"high-availability": ha}},
                *({"library": f"{hooks}/{name}"} for name in extra_hooks),
            ],
            "subnet4": [
                {
                    "id": 1,
                    "subnet": "192.0.2.0/24",
                    "reservations": [
                        {"hw-address": hw, "ip-address": "192.0.2.60", "hostname": "kiosk"},
                        {"hw-address": "aa:bb:cc:dd:ee:09", "ip-address": "192.0.2.61", "hostname": "badge"},
                    ],
                }
            ],
        }
    }


def payloads(**configs: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {node: shared_hashes(cfg) for node, cfg in configs.items()}


def test_peer_difference_names_the_reservation_that_differs():
    a = peer_config("x86_64", "aa:bb:cc:dd:ee:01")
    b = peer_config("aarch64", "aa:bb:cc:dd:ee:02")
    b["Dhcp4"]["subnet4"][0]["reservations"].reverse()
    hashes, groups = divergent(payloads(n1=a, n2=b))
    assert set(hashes) == {"n1", "n2"}
    [diff] = groups[0]["differences"]
    assert diff["nodes"] == ["n1", "n2"] and diff["count"] == 2
    assert diff["items"] == [
        "/config/subnet4[id=1]/reservations[hw-address=aa:bb:cc:dd:ee:01]: only on n1 "
        "(hostname=kiosk, ip-address=192.0.2.60)",
        "/config/subnet4[id=1]/reservations[hw-address=aa:bb:cc:dd:ee:02]: only on n2 "
        "(hostname=kiosk, ip-address=192.0.2.60)",
    ]


def test_hooks_are_compared_by_file_name_across_architectures():
    a = peer_config("x86_64", "aa:bb:cc:dd:ee:01")
    b = peer_config("aarch64", "aa:bb:cc:dd:ee:01")
    assert divergent(payloads(n1=a, n2=b)) == ({}, [])
    a = peer_config("x86_64", "aa:bb:cc:dd:ee:01", ("libkea_sanitize_hostname.so",))
    hashes, groups = divergent(payloads(n1=a, n2=b))
    assert set(hashes) == {"n1", "n2"}
    assert groups[0]["differences"][0]["items"] == ["/config/hooks: 'libkea_sanitize_hostname.so' only on n1"]


# HA grace period ------------------------------------------------------------


def waiting(kea: FakeDhcpBackend) -> None:
    kea.ha.state = "waiting"
    kea.ha.partner = HAPartner(role="standby", state="hot-standby", in_touch=False)


def settled(kea: FakeDhcpBackend) -> None:
    kea.ha.state = "hot-standby"
    kea.ha.partner = HAPartner(role="standby", state="hot-standby", in_touch=True)


def test_a_wait_shorter_than_the_grace_period_raises_nothing(store):
    clock = Clock()
    kea = FakeDhcpBackend()
    poller = KeaPoller(kea, NODE, store, SETTINGS, clock)
    poller.poll()
    waiting(kea)
    clock.advance(10)
    assert poller.poll().alerts == []
    clock.advance(20)
    assert poller.poll().alerts == []
    settled(kea)
    clock.advance(10)
    assert poller.poll().alerts == []
    # The history keeps both moves.
    assert store.counts()["ha_transitions"] == 2


def test_a_wait_seen_only_by_the_live_pass_is_absorbed(store):
    clock = Clock()
    kea = FakeDhcpBackend()
    poller = KeaPoller(kea, NODE, store, SETTINGS, clock)
    poller.poll()
    waiting(kea)
    clock.advance(20)
    poller.heartbeat()
    clock.advance(5)
    poller.heartbeat()
    settled(kea)
    clock.advance(35)
    assert poller.poll().alerts == []


def test_a_lasting_wait_raises_after_the_grace_period(store):
    clock = Clock()
    kea = FakeDhcpBackend()
    poller = KeaPoller(kea, NODE, store, SETTINGS, clock)
    poller.poll()
    waiting(kea)
    clock.advance(10)
    assert poller.poll().alerts == []
    clock.advance(60)
    assert kinds(poller.poll()) == {AlertKind.HA_PARTNER_DOWN}


def test_grace_period_is_a_setting_and_terminated_is_never_absorbed(store):
    clock = Clock()
    kea = FakeDhcpBackend()
    poller = KeaPoller(kea, NODE, store, {**SETTINGS, "alerts_ha_grace_seconds": 300}, clock)
    poller.poll()
    clock.advance(10)
    kea.ha.state = "terminated"
    assert AlertKind.HA_DEGRADED in kinds(poller.poll())


def test_a_reload_done_by_pelagos_keeps_the_alerts_quiet(store):
    clock = Clock()
    kea = FakeDhcpBackend()
    poller = KeaPoller(kea, NODE, store, {**SETTINGS, "alerts_ha_grace_seconds": 0}, clock)
    poller.poll()
    poller.reloading = lambda _engine: True
    waiting(kea)
    clock.advance(10)
    assert poller.poll().alerts == []
    poller.reloading = lambda _engine: False
    clock.advance(10)
    assert kinds(poller.poll()) == {AlertKind.HA_PARTNER_DOWN}


# External changes -----------------------------------------------------------


def test_a_change_without_a_pelagos_write_is_reported_once_confirmed(store):
    clock = Clock()
    kea = FakeDhcpBackend()
    running = {"Dhcp4": {"hash": "h1", "subnet4": [{"id": 1, "subnet": "192.0.2.0/24", "reservations": []}]}}
    kea.config_get = lambda: running  # type: ignore[method-assign]
    poller = KeaPoller(kea, NODE, store, SETTINGS, clock)
    seen: list[tuple[str, dict[str, Any]]] = []
    poller.external.emit = lambda engine, details: seen.append((engine, details))
    poller.poll()
    kea.hash = "other"
    running = copy.deepcopy(running)
    running["Dhcp4"]["subnet4"][0]["reservations"].append({"hw-address": "aa:bb:cc:dd:ee:01"})
    clock.advance(60)
    poller.poll()
    assert seen == []  # confirmed one poll later
    clock.advance(60)
    poller.poll()
    [(engine, details)] = seen
    assert engine == "kea4" and details["count"] == 1
    assert details["differences"] == [
        "/subnet4[id=1]/reservations[hw-address=aa:bb:cc:dd:ee:01]: only on current"
    ]
    clock.advance(60)
    poller.poll()
    assert len(seen) == 1


def test_a_change_after_a_pelagos_write_is_not_external(store):
    clock = Clock()
    kea = FakeDhcpBackend()
    poller = KeaPoller(kea, NODE, store, SETTINGS, clock)
    seen: list[Any] = []
    poller.external.emit = lambda engine, details: seen.append(details)
    poller.external.last_write = lambda _engine: clock.now - 30
    poller.poll()
    kea.hash = "after-a-plan"
    kea.config_get = lambda: {"Dhcp4": {"valid-lifetime": 60}}  # type: ignore[method-assign]
    clock.advance(60)
    poller.poll()
    clock.advance(60)
    poller.poll()
    assert seen == []


def test_managed_bind_files_changed_by_hand_are_reported(store, tmp_root):
    clock = Clock()
    include = tmp_root / "pelagos"
    include.mkdir()
    (include / "acls.conf").write_text('acl "lan" { 192.0.2.0/24; };\n')
    dns = FakeDnsBackend()
    dns.include_dir = include  # type: ignore[attr-defined]
    poller = BindPoller(dns, NODE, store, clock)
    seen: list[dict[str, Any]] = []
    poller.external.emit = lambda engine, details: seen.append(details)
    poller.poll()
    (include / "acls.conf").write_text('acl "lan" { 192.0.2.0/24; 198.51.100.0/24; };\n')
    for _ in range(2):
        clock.advance(60)
        poller.poll()
    [details] = seen
    assert any("198.51.100.0/24" in line for line in details["differences"])
    assert managed_files_diff({"a.conf": "x\n"}, {"a.conf": "x\n"}) == []


# Hooks no package owns ------------------------------------------------------


def test_a_hook_no_package_owns_raises_an_alert_with_the_builtin_option(store, tmp_root):
    clock = Clock()
    owned = tmp_root / "libdhcp_ha.so"
    custom = tmp_root / "libkea_sanitize_hostname.so"
    other = tmp_root / "libcustom_audit.so"
    for p in (owned, custom, other):
        p.write_bytes(b"\x7fELF")
    kea = FakeDhcpBackend()
    running = {"Dhcp4": {"hooks-libraries": [{"library": str(p)} for p in (owned, custom, other)]}}
    kea.config_get = lambda: running  # type: ignore[method-assign]
    poller = KeaPoller(kea, NODE, store, SETTINGS, clock)
    poller.ownership = HookOwnership(
        runner=lambda argv: 0 if argv[-1].endswith("libdhcp_ha.so") else 1, tool=lambda: ["dpkg", "-S"]
    )
    alerts = [a for a in poller.poll().alerts if a.kind is AlertKind.CUSTOM_HOOK]
    by_name = {a.details["library"].rsplit("/", 1)[-1]: a for a in alerts}
    assert set(by_name) == {"libkea_sanitize_hostname.so", "libcustom_audit.so"}
    assert by_name["libkea_sanitize_hostname.so"].details["builtin_option"] == "hostname-char"
    assert by_name["libkea_sanitize_hostname.so"].title_message["key"] == "alert.custom_hook_builtin"
    assert by_name["libcustom_audit.so"].title_message["key"] == "alert.custom_hook"
    assert by_name["libcustom_audit.so"].subject == "kea4:hook:libcustom_audit.so"
    off = KeaPoller(kea, NODE, store, {**SETTINGS, "alerts_custom_hooks": False}, clock)
    off.ownership = poller.ownership
    assert [a for a in off.poll().alerts if a.kind is AlertKind.CUSTOM_HOOK] == []


def test_ownership_cannot_be_told_without_a_package_tool_or_a_file(tmp_root):
    lib = tmp_root / "libx.so"
    lib.write_bytes(b"")
    assert HookOwnership(tool=lambda: None).custom(str(lib)) is None
    assert (
        HookOwnership(runner=lambda _a: 1, tool=lambda: ["rpm", "-qf"]).custom(str(tmp_root / "no.so"))
        is None
    )
    assert HookOwnership(runner=lambda _a: None, tool=lambda: ["rpm", "-qf"]).custom(str(lib)) is None
    assert HookOwnership(runner=lambda _a: 1, tool=lambda: ["rpm", "-qf"]).custom(str(lib)) is True
    assert builtin_equivalent("/opt/kea/libdhcp_ha.so") is None
