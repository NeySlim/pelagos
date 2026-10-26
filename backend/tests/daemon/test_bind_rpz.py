# SPDX-License-Identifier: Apache-2.0
"""RPZ subscriptions against a real named: the plan declares the zones, a converted list is loaded and
rewrites an answer, the allow zone and a client exemption win, a bad update keeps the old list."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import dns.flags
import dns.message
import dns.query
import dns.rcode
import pytest

from pelagos.connectors.base import ConnectorContext
from pelagos.connectors.bind import BindBackend
from pelagos.domain.plan import Change, ChangeOp, PlanState
from pelagos.rpz import fetch as fetch_mod
from pelagos.rpz import model, sync
from pelagos.services.rpz_service import RpzService
from tests.daemon import bind_custom
from tests.fixtures import named as named_fx

pytestmark = pytest.mark.daemon

ZONE = "example.lan"
LIST = b"# fixture list\nads.example.lan\ntracker.example.net\n"
MANAGED = "# pelagos:managed v1\n"


class Rig:
    def __init__(self, server: named_fx.NamedServer, backend: BindBackend, root: Path) -> None:
        self.server, self.backend, self.root = server, backend, root
        self.settings: dict[str, Any] = {"rpz": {"categories": {}, "subscriptions": {}}}
        self.responses: list[Any] = []

    def subscribe(self, **kw: Any) -> None:
        entry = {"url": "https://lists.example.com/l.txt", "format": "domains", "interval_hours": 24, **kw}
        self.settings["rpz"]["subscriptions"]["blocklist"] = entry

    def plan_and_apply(self) -> None:
        subs = [s.to_dict() for s in model.resolve(self.settings)]
        cfg = model.config(self.settings)
        allow = {
            "domains": [a["domain"] for a in cfg["allow"]],
            "clients": [c["cidr"] for c in cfg["exempt_clients"]],
        }
        change = Change(
            ChangeOp.REPLACE, "rpz/state", after={"subs": subs, "allow": allow, "break_dnssec": True}
        )
        plan = self.backend.plan_config_change([change], "test")
        assert plan.state is PlanState.VALIDATED, [v.output for v in plan.validations]
        result = self.backend.apply(plan)
        assert result.ok, result.message

    def fetch(self, url: str, *_: Any, **__: Any) -> fetch_mod.Fetched:
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return fetch_mod.Fetched(200, item, '"v1"', "Mon, 26 Oct 2026 06:00:00 GMT", None)

    def update(self, **kw: Any) -> sync.SyncReport:
        env = self.backend.rpz_env(log_path=str(self.root / "named.stdout"))
        env.fetch = self.fetch
        return sync.Syncer(env, lambda: self.settings).run(**kw)

    def ask(self, name: str, rtype: str = "A") -> dns.message.Message:
        query = dns.message.make_query(name, rtype)
        return dns.query.udp(query, "127.0.0.1", port=self.server.dns_port, timeout=5)

    def rcode(self, name: str) -> str:
        return dns.rcode.to_text(self.ask(name).rcode())


@pytest.fixture
def rig(tmp_root: Path) -> Iterator[Rig]:
    root = tmp_root / "rpz"
    inc = root / "pelagos"
    inc.mkdir(parents=True)
    for name in ("keys", "acls", "zones", "options"):
        (inc / f"{name}.conf").write_text(MANAGED)
    (inc / "pelagos.conf").write_text(
        MANAGED + "".join(f'include "{inc}/{n}.conf";\n' for n in ("keys", "acls", "zones"))
    )
    server = bind_custom.start(
        root,
        f'zone "{ZONE}" {{ type primary; file "{ZONE}.db"; }};\ninclude "{inc}/pelagos.conf";\n',
        options=f'\tinclude "{inc}/options.conf";\n',
        files={
            f"{ZONE}.db": bind_custom.zone_text(ZONE, extra="ads IN A 192.0.2.66\nwww2 IN A 192.0.2.67\n")
        },
        recursion=True,
    )
    ctx = ConnectorContext(
        node_id="n1",
        engine_config={
            "named_conf": str(server.named_conf),
            "include_dir": str(inc),
            "zone_dir": str(root / "zones" / "pelagos"),
            "rndc_conf": str(server.rndc_conf),
            "rndc_port": server.rndc_port,
            "statistics_url": server.stats_url,
            "query_port": server.dns_port,
            "reload_wait_seconds": 1,
        },
        backup_root=tmp_root / "backups" / "bind",
        get_secret=lambda name: None,
        settings={"plans": {"ttl_seconds": 600}, "dns": {"read_key": "ddi-read", "admin_key": "ddi-admin"}},
    )
    try:
        yield Rig(server, BindBackend(ctx), root)
    finally:
        server.stop()


def test_a_subscribed_list_rewrites_answers_and_exceptions_win(rig: Rig) -> None:
    assert rig.rcode(f"ads.{ZONE}") == "NOERROR"
    rig.subscribe()
    rig.plan_and_apply()
    tree = rig.backend.read_config()
    assert any(o.name == "response-policy" for o in tree.options)
    assert rig.backend.rpz_zone_loaded("blocklist.rpz.invalid") and rig.backend.rpz_zone_loaded(
        model.ALLOW_ZONE
    )
    # Declared and empty until the collector downloads the list.
    assert rig.rcode(f"ads.{ZONE}") == "NOERROR"
    rig.responses.append(LIST)
    assert rig.update().updated == ["blocklist"]
    assert rig.rcode(f"ads.{ZONE}") == "NXDOMAIN"
    assert rig.rcode(f"www2.{ZONE}") == "NOERROR"
    # The wildcard rule covers subdomains of a listed name.
    assert rig.rcode(f"x.ads.{ZONE}") == "NXDOMAIN"
    state = sync.load_state(rig.backend.rpz_state_path())
    assert state["subs"]["blocklist"]["entries"] == 2 and state["subs"]["blocklist"]["status"] == "ok"

    # One click: the allow zone is first, so the name is served again.
    rig.settings["rpz"]["allow"] = [{"domain": f"ads.{ZONE}"}]
    rig.update()
    answer = rig.ask(f"ads.{ZONE}")
    assert dns.rcode.to_text(answer.rcode()) == "NOERROR" and "192.0.2.66" in answer.answer[0].to_text()
    # A client exemption (rpz-client-ip passthru) lets this client through for every list.
    rig.settings["rpz"]["allow"] = []
    rig.settings["rpz"]["exempt_clients"] = [{"cidr": "127.0.0.1"}]
    rig.update()
    assert rig.rcode(f"ads.{ZONE}") == "NOERROR"
    rig.settings["rpz"]["exempt_clients"] = []
    rig.update()
    assert rig.rcode(f"ads.{ZONE}") == "NXDOMAIN"

    # The rewrite log gives the list and the rule; counters per list and per category.
    rig.update()
    log = sync.load_state(rig.backend.rpz_state_path())["log"]
    assert log["by_list"]["blocklist"]["hits"] >= 3 and log["by_list"]["allow"]["hits"] >= 1
    hit = next(e for e in log["recent"] if e["qname"] == f"ads.{ZONE}" and e["list"] == "blocklist")
    assert hit["client"] == "127.0.0.1" and hit["action"] == "NXDOMAIN" and hit["rule"] == f"ads.{ZONE}"


def test_actions_nodata_redirect_and_passthru(rig: Rig) -> None:
    rig.subscribe(action="nodata")
    rig.plan_and_apply()
    rig.responses.append(LIST)
    rig.update()
    nodata = rig.ask(f"ads.{ZONE}")
    assert dns.rcode.to_text(nodata.rcode()) == "NOERROR" and nodata.answer == []

    rig.subscribe(action="redirect", redirect="192.0.2.80")
    rig.plan_and_apply()
    rig.responses.append(LIST)
    rig.update(only="blocklist")
    redirected = rig.ask(f"ads.{ZONE}")
    assert [r.to_text() for r in redirected.answer[0]] == ["192.0.2.80"]

    rig.subscribe(action="redirect", redirect="block.example.lan")
    rig.plan_and_apply()
    rig.responses.append(LIST)
    rig.update(only="blocklist")
    cname = rig.ask(f"ads.{ZONE}")
    assert "block.example.lan." in cname.answer[0].to_text()

    # Passthru only logs: the answer is the real one, the hit is counted.
    rig.subscribe(action="passthru")
    rig.plan_and_apply()
    rig.responses.append(LIST)
    rig.update(only="blocklist")
    assert "192.0.2.66" in rig.ask(f"ads.{ZONE}").answer[0].to_text()
    rig.update()
    assert any(
        e["action"] == "PASSTHRU" for e in sync.load_state(rig.backend.rpz_state_path())["log"]["recent"]
    )


def test_a_bad_update_keeps_the_loaded_list_and_the_why_lookup_names_the_rule(rig: Rig) -> None:
    rig.subscribe()
    rig.plan_and_apply()
    rig.responses.append(LIST)
    rig.update()
    # Empty and shrunk lists are refused; the zone keeps blocking.
    rig.responses.append(b"# nothing\n")
    failed = rig.update(only="blocklist").failed
    assert "empty" in failed["blocklist"]
    assert rig.rcode(f"ads.{ZONE}") == "NXDOMAIN"
    rig.responses.append(fetch_mod.FetchError("HTTP 410: the list is gone or moved"))
    assert "410" in rig.update(only="blocklist").failed["blocklist"]
    assert rig.rcode(f"ads.{ZONE}") == "NXDOMAIN"
    # The lookup behind "why is this domain blocked?" reads the rule from the policy zone.
    rig.backend.dns.port = rig.server.dns_port
    hit = RpzService._lookup(rig.backend, "blocklist.rpz.invalid", f"x.ads.{ZONE}".split("."))
    assert hit == (f"*.ads.{ZONE}", "wildcard", ".")
    assert RpzService._lookup(rig.backend, "blocklist.rpz.invalid", f"www2.{ZONE}".split(".")) is None


def test_removing_the_subscription_restores_the_configuration(rig: Rig) -> None:
    rig.subscribe()
    rig.plan_and_apply()
    rig.responses.append(LIST)
    rig.update()
    assert rig.rcode(f"ads.{ZONE}") == "NXDOMAIN"
    rig.settings["rpz"]["subscriptions"].clear()
    subs: list[dict[str, Any]] = []
    plan = rig.backend.plan_config_change(
        [Change(ChangeOp.REPLACE, "rpz/state", after={"subs": subs, "allow": {}})], "test"
    )
    assert plan.state is PlanState.VALIDATED and plan.requires_confirmation
    assert rig.backend.apply(plan).ok
    assert rig.rcode(f"ads.{ZONE}") == "NOERROR"
    assert not any(o.name == "response-policy" for o in rig.backend.read_config().options)
    assert "rpz.invalid" not in (rig.root / "pelagos" / "zones.conf").read_text()
