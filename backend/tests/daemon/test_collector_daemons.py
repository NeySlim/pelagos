# SPDX-License-Identifier: Apache-2.0
"""The collector polling a real named, kea-dhcp4 and kea-dhcp-ddns: snapshots, series, alerts, acks."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pelagos.collector.alerts import ack_entry
from pelagos.collector.events import EventSink
from pelagos.collector.main import Backends, Collector
from pelagos.collector.series import SeriesStore, connect
from pelagos.connectors.base import ConnectorContext
from pelagos.connectors.bind import BindBackend
from pelagos.connectors.kea.backend import KeaBackend
from pelagos.connectors.kea.d2 import D2Backend
from pelagos.domain import AlertKind, AlertState, Family

pytestmark = pytest.mark.daemon

ALERT_SETTINGS = {"alerts_pool_warning_percent": 1, "alerts_pool_critical_percent": 95}


def context(
    node_id: str, engine_config: dict, backups: Path, secrets: dict | None = None
) -> ConnectorContext:
    return ConnectorContext(
        node_id=node_id,
        engine_config=engine_config,
        backup_root=backups,
        get_secret=(secrets or {}).get,
        settings={"dns": {"read_key": "ddi-read", "admin_key": "ddi-admin"}},
    )


@pytest.fixture
def rig(node_ctx, named_server, kea_dhcp4, kea_d2, tmp_root):
    node = node_ctx.node.id
    backups = tmp_root / "backups"
    bind = BindBackend(
        context(
            node,
            {
                "named_conf": str(named_server.named_conf),
                "include_dir": str(named_server.root / "pelagos"),
                "rndc_conf": str(named_server.rndc_conf),
                "rndc_port": named_server.rndc_port,
                "statistics_url": named_server.stats_url,
                "query_port": named_server.dns_port,
            },
            backups,
            {f"tsig/{n}": s for n, s in named_server.keys.items()},
        )
    )
    kea4 = KeaBackend(
        context(
            node,
            {
                "socket_dir": str(kea_dhcp4.socket_path.parent),
                "dhcp4_socket": kea_dhcp4.socket_path.name,
                "dhcp4_conf": str(kea_dhcp4.config_path),
            },
            backups,
        ),
        Family.V4,
    )
    d2 = D2Backend(
        context(
            node,
            {
                "socket_dir": str(kea_d2.socket_path.parent),
                "d2_socket": kea_d2.socket_path.name,
                "d2_conf": str(kea_d2.config_path),
            },
            backups,
        )
    )
    node_ctx.config_store.update_cluster(lambda c: c.settings.update(ALERT_SETTINGS), updated_by="test")
    conn = connect(node_ctx.paths.series_db)
    store = SeriesStore(conn)
    collector = Collector(
        node_ctx,
        store,
        Backends(dns=bind, kea4=kea4, d2=d2),
        None,
        EventSink(node_ctx.paths.events_sock, node),
    )
    yield collector, kea_dhcp4
    conn.close()


def kinds(alerts) -> dict[AlertKind, list]:
    out: dict[AlertKind, list] = {}
    for a in alerts:
        out.setdefault(a.kind, []).append(a)
    return out


def test_collector_polls_bind_and_kea(rig):
    collector, kea4 = rig
    node = collector.node_id
    store = collector.store
    kea4.ok("lease4-add", {"ip-address": "192.0.2.150", "hw-address": "aa:bb:cc:dd:ee:10", "subnet-id": 1})

    first = collector.cycle()
    assert first.errors == {}, first.errors
    # Pool alerts open on the second poll in a row (hysteresis); everything else on the first.
    report = collector.cycle()
    assert report.errors == {}, report.errors
    opened = kinds(first.opened) | kinds(report.opened)
    # Every daemon answers, every zone is loaded and the Kea files match what the daemons run.
    assert AlertKind.DAEMON_DOWN not in opened and AlertKind.ZONE_ERROR not in opened
    assert AlertKind.CONFIG_DIVERGENCE not in opened, opened.get(AlertKind.CONFIG_DIVERGENCE)
    # One lease in a pool of 100 crosses the 1 % warning threshold set for the test.
    assert [a.subject for a in opened[AlertKind.POOL_NEAR_FULL]] == [
        "kea4:subnet:1:pool:192.0.2.100-192.0.2.199"
    ]

    zones = {z["zone"]: z for z in store.snapshot(node, "bind", "zones")[1]}
    assert zones["example.lan."]["serial"] > 0 and zones["example.lan."]["kind"] == "primary"
    assert store.latest_serial("example.lan.", "_default", node)[1] == zones["example.lan."]["serial"]
    assert store.snapshot(node, "bind", "stats") is not None
    utilization = store.snapshot(node, "kea4", "utilization")[1]
    assert utilization[0]["assigned"] == 1 and utilization[0]["total"] == 100
    assert store.latest_pool_samples(node, "kea4")[0]["assigned"] == 1
    assert set(store.snapshot(node, "kea4", "config_hash")[1]) == {"hash", "normalized"}
    assert "update-sent" in store.snapshot(node, "d2", "stats")[1]["totals"]
    cache = store.engine_snapshot(node, "kea4")
    assert {"capabilities", "status", "ha", "utilization", "subnets", "config_hash"} <= set(cache["kinds"])

    # An acknowledgement written by the web process is replayed onto the alert.
    alert = opened[AlertKind.POOL_NEAR_FULL][0]
    collector.ctx.audit_log.append(ack_entry(node, alert, "alice", "expected"))
    assert [a.id for a in collector.apply_acks()] == [alert.id]
    assert collector.alerts.get(alert.id).state is AlertState.ACKED
    assert collector.alerts.summary()["acked"] == 1

    # Someone edits the file without reloading Kea: the running configuration no longer matches it.
    cfg = json.loads(kea4.config_path.read_text())
    cfg["Dhcp4"]["valid-lifetime"] = 7200
    kea4.config_path.write_text(json.dumps(cfg, indent=2))
    report = collector.cycle()
    divergence = kinds(report.opened)[AlertKind.CONFIG_DIVERGENCE]
    assert [a.subject for a in divergence] == ["kea4:config-file"]
    assert divergence[0].details["differences"] == ["/valid-lifetime: 7200 in the file, 3600 running"]

    # kea-dhcp4 stops: daemon_down, and the pool alert of the stopped daemon resolves.
    kea4.stop()
    report = collector.cycle()
    down = kinds(report.opened)[AlertKind.DAEMON_DOWN]
    assert [(a.engine.value, a.severity.value) for a in down] == [("kea4", "critical")]
    assert AlertKind.POOL_NEAR_FULL in kinds(report.resolved)
    listed, total = collector.alerts.list(state="open")
    assert total == len(listed) and any(a.kind is AlertKind.DAEMON_DOWN for a in listed)
    audit = [e.action for e in collector.ctx.audit_log.read()]
    assert "alert.raise" in audit and "alert.resolve" in audit


def test_live_pass_on_real_daemons(rig, named_server):
    """Kea answers the ack counter the lease watch keys on; a dynamic update moves the zone serial,
    which the next BIND poll turns into a `zones` event."""
    import dns.query
    import dns.tsigkeyring
    import dns.update

    collector, kea4 = rig
    poller = collector.kea[0]
    assert isinstance(poller.ack_counter(), int)
    collector.cycle()
    kea4.ok("lease4-add", {"ip-address": "192.0.2.170", "hw-address": "02:00:5e:00:01:70", "subnet-id": 1})
    poller.last_walk = 0.0  # the periodic walk is due
    collector.live()
    _ts, recent = collector.store.snapshot(collector.node_id, "kea4", "recent_leases")
    assert "192.0.2.170" in {r["ip_address"] for r in recent}
    keyring = dns.tsigkeyring.from_text({"ddi-admin": named_server.keys["ddi-admin"]})
    update = dns.update.UpdateMessage("example.lan.", keyring=keyring, keyalgorithm="hmac-sha256")
    update.add("live-daemon", 300, "A", "192.0.2.92")
    dns.query.tcp(update, "127.0.0.1", port=named_server.dns_port, timeout=5)
    seen: list[tuple] = []
    collector.events.emit = lambda topic, event, data, **opts: seen.append((topic, event, data))  # type: ignore[method-assign]
    collector.poll_bind()
    zones = [d for t, e, d in seen if t == "zones" and e == "serial"]
    assert [z["zone"] for z in zones] == ["example.lan."] and zones[0]["serial"] > zones[0]["previous"]
