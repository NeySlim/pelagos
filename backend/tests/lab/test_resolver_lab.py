# SPDX-License-Identifier: Apache-2.0
"""Resolver health and forwarder fallback (section 25, batch R5) on a real pair: lab-r5a ns1 and
lab-r5b ns2 (BIND 9.20 and Kea 2.6 from Debian 13, `provision.sh pair`, snapshot `legacy`).

Recursion is turned on in the user's options first, as production runs; then the deb of this
checkout on both, ns2 enrolled, BIND imported. Real traffic gives the measures and the series; the
slow checks probe the real root and TLD servers. An nftables rule on each node then drops every
outgoing DNS packet except to Quad9: `resolver:roots` and `resolver:tld:*` open, the quad9
fallback plan makes names resolve again, the rule goes, the direct probes become healthy,
`return_ready` turns true and the collectors return on their own at the deadline, byte for byte.
Last, the automatic fallback (off by default) applies the quad9 plan by itself on a second cut, and
the return plan puts things back.

The VMs are rolled back to `legacy` first and left as the test ends.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from pelagos import __version__
from tests.lab.labkit import ADMIN_PASSWORD, Api, deb_package, put, rollback, scp, ssh, wait_for

pytestmark = pytest.mark.lab

A1, A2 = "10.99.0.55", "10.99.0.56"
VMS = ("lab-r5a", "lab-r5b")
OPTIONS = "/etc/bind/pelagos/options.conf"
CONF = "/etc/bind/named.conf.options"
# Quad9 with filtering, the first preset (https://quad9.net/service/service-addresses-and-features/,
# read on 2026-10-28): the only DNS servers the cut leaves reachable.
QUAD9_V4 = ("9.9.9.9", "149.112.112.112")
QUAD9_V6 = ("2620:fe::fe", "2620:fe::9")
NFT = "/etc/nftables-r5lab.conf"
CUT = (
    "table inet r5lab {\n"
    "  chain out {\n"
    "    type filter hook output priority 0; policy accept;\n"
    f"    ip daddr {{ {', '.join(QUAD9_V4)}, 127.0.0.0/8, 10.99.0.0/24 }} accept\n"
    f"    ip6 daddr {{ {', '.join(QUAD9_V6)}, ::1 }} accept\n"
    "    udp dport { 53, 853 } drop\n"
    "    tcp dport { 53, 853 } drop\n"
    "  }\n"
    "}\n"
)
STATE: dict[str, Any] = {}


def api(address: str = A1) -> Api:
    key = f"api:{address}"
    if key not in STATE:
        client = Api(address)
        wait_for(f"{address} login", lambda: client.login(), timeout=300, interval=5)
        STATE[key] = client
    return STATE[key]  # type: ignore[return-value]


def ids() -> dict[str, str]:
    """address -> node id."""
    if "ids" not in STATE:
        nodes = {n["peer"]["name"]: n["peer"]["id"] for n in api().get("/nodes")["items"]}
        STATE["ids"] = {A1: nodes["ns1"], A2: nodes["ns2"]}
    return STATE["ids"]


def resolve(host: str, name: str = "www.debian.org") -> str:
    """What the node's resolver answers for `name` from an empty cache: an address or the last rcode.
    Right after a flush named answers SERVFAIL for a few seconds while it primes again: retried."""
    ssh(host, "sudo rndc flush")
    status = ""
    for _ in range(8):
        out = ssh(host, f"dig +tries=1 +time=8 @127.0.0.1 {name} A", check=False)[1]
        status = next(
            (ln.split("status: ")[1].split(",")[0] for ln in out.splitlines() if "status: " in ln), "TIMEOUT"
        )
        if status == "NOERROR":
            answers = ssh(host, f"dig +short +tries=1 +time=8 @127.0.0.1 {name} A", check=False)[1].split()
            return next((a for a in answers if a[0].isdigit()), "NODATA")
        time.sleep(2)
    return status


def health() -> dict[str, Any]:
    return api().get("/dns/resolver/health")


def node_health(address: str) -> dict[str, Any] | None:
    return next((n for n in health()["nodes"] if n["node_id"] == ids()[address]), None)


def open_alerts(prefix: str, severity: str | None = None) -> dict[str, dict]:
    """Open resolver_health alerts of the cluster whose subject starts with `prefix`, by node id."""
    items = api().get("/alerts?per_page=500")["items"]
    return {
        a["node_id"]: a
        for a in items
        if a["kind"] == "resolver_health"
        and a["state"] != "resolved"
        and a["subject"].startswith(prefix)
        and (severity is None or a["severity"] == severity)
    }


def cut(on: bool) -> None:
    for host in (A1, A2):
        if on:
            put(host, NFT, CUT)
            ssh(host, f"sudo nft -f {NFT}")
        else:
            ssh(host, "sudo nft delete table inet r5lab", check=False)


def options(host: str) -> str:
    return ssh(host, f"sudo cat {OPTIONS}")[1]


def audit(address: str, action: str) -> list[dict]:
    return [
        e for e in api(address).get(f"/audit?action={action}&per_page=200")["items"] if e["action"] == action
    ]


class TestResolverLab:
    def test_00_legacy_pair(self):
        rollback(*VMS)
        for host in (A1, A2):
            ssh(host, "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q nftables", timeout=600)
            ssh(host, "sudo nft delete table inet r5lab", check=False)
            # Production resolves recursively: the legacy pair only serves its zones.
            sed = "s/recursion no;/recursion yes;\\n\\tallow-recursion { localhost; localnets; };/"
            ssh(host, f"sudo sed -i '{sed}' {CONF} && sudo named-checkconf && sudo rndc reconfig")

    def test_01_deploy_init_enroll_import(self):
        deb = deb_package()
        for host in (A1, A2):
            scp(host, deb, "/tmp/pelagos.deb")
            ssh(
                host,
                "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q /tmp/pelagos.deb",
                timeout=900,
            )
        ssh(
            A1,
            f"sudo PELAGOS_ADMIN_PASSWORD={ADMIN_PASSWORD} pelagos init --name ns1 "
            f"--web-url https://{A1}:8443 --replication-url https://{A1}:8444 "
            "&& sudo systemctl start pelagos pelagos-collector",
        )
        token = api(A1).post("/nodes/enroll-token", {})
        ssh(
            A2,
            f"sudo pelagos enroll --url {token['url']} --token {token['token']} "
            f"--ca-fingerprint {token['ca_fingerprint']} --name ns2 "
            f"--replication-url https://{A2}:8444 --web-url https://{A2}:8443 "
            "&& sudo systemctl start pelagos pelagos-collector",
        )

        def both_current() -> bool:
            nodes = api(A1).get("/nodes")["items"]
            return len(nodes) == 2 and all(
                n["status"] == "online" and n.get("version") == __version__ for n in nodes
            )

        wait_for("both nodes online on this version", both_current, timeout=300, interval=5)
        for address in (A1, A2):
            api(address).apply(api(address).post("/install/import/plan", {"engines": ["bind"]}))
        # Fast passes; one failed probe is enough to open the probe alerts.
        api().call(
            "PUT",
            "/admin/settings",
            {
                "collector": {"poll_seconds": 10, "peer_poll_seconds": 15, "consistency_seconds": 60},
                "checks": {"resolver_roots_failures": 1, "resolver_tld_failures": 1},
                "resolver": {"probe_interval_seconds": 60, "fallback_return_healthy_minutes": 1},
            },
        )

    def test_02_recursive_resolvers(self):
        """The pair resolves recursively like production does, recursion set in the user's options."""
        for address in (A1, A2):
            assert "recursion yes;" in ssh(address, "sudo named-checkconf -p")[1]
            assert "forward" not in options(address)
            wait_for(f"{address} resolves", lambda h=address: resolve(h)[0].isdigit(), timeout=60)

    def test_03_measures_and_series(self):
        names = " ".join(f"{w}.example.{t}" for w in ("www", "mail", "ftp") for t in ("com", "net", "org"))
        names += " www.debian.org www.isc.org www.iana.org www.wikipedia.org www.kernel.org"

        def traffic() -> None:
            for host in (A1, A2):
                ssh(
                    host,
                    f"for n in {names}; do dig +short +tries=1 @127.0.0.1 $n A >/dev/null; done",
                    check=False,
                )

        def measured() -> list[dict] | None:
            traffic()
            entries = health()["nodes"]
            ok = [
                e
                for e in entries
                if e["error"] is None
                and e["rates"]["queries_out"] is not None
                and e["latency_ms"]["p95"] is not None
                and e["cache"]["nodes"]
            ]
            return ok if len(ok) == 2 else None

        entries = wait_for("resolver measures on both nodes", measured, timeout=300, interval=10)
        for e in entries:
            assert e["latency_ms"]["p50"] <= e["latency_ms"]["p95"], e
            assert (
                e["rates"]["timeouts_percent"] is not None and e["rates"]["cache_hit_percent"] is not None
            ), e
        frm = int(time.time()) - 3600
        out = api().get(f"/series/resolver?metric=queries_out_per_second&from={frm}&step=60")
        assert out["unavailable"] == [], out
        assert {s["key"]["node_id"] for s in out["series"] if s["points"]} == set(ids().values()), out

    def test_04_probes_healthy(self):
        def probed() -> dict | None:
            entries = health()["nodes"]
            if len(entries) != 2:
                return None
            for e in entries:
                tlds = {t["tld"]: t for t in e["tlds"]}
                if len(e["roots"]) < 13 or not {"com", "net", "org", "arpa"} <= set(tlds):
                    return None
                if not all(r["ok"] for r in e["roots"] if r["family"] == 4):
                    return None
                if not all(t["ok"] and t["servers"] == 2 for t in tlds.values()):
                    return None
            return {e["node_id"]: e for e in entries}

        entries = wait_for("root and TLD probes on both nodes", probed, timeout=300, interval=10)
        for e in entries.values():
            letters = {r["letter"] for r in e["roots"] if r["family"] == 4}
            assert letters == set("abcdefghijklm"), letters
            assert e["probes_healthy_since"] not in ("unhealthy", "unknown"), e
        out = health()
        assert out["fallback"] is None and out["return_ready"] is False
        assert out["thresholds"]["latency_p95_ms"]["warning"] == 800
        assert {q["id"] for q in out["presets"]} >= {"quad9", "quad9_unfiltered", "cloudflare"}
        assert open_alerts("resolver:roots") == {} and open_alerts("resolver:tld:") == {}

    def test_05_roots_cut(self):
        STATE["before"] = {h: options(h) for h in (A1, A2)}
        cut(True)
        for host in (A1, A2):
            assert resolve(host) in ("SERVFAIL", "TIMEOUT")
        roots = wait_for(
            "resolver:roots on both nodes",
            lambda: (lambda f: f if len(f) == 2 else None)(open_alerts("resolver:roots", "critical")),
            timeout=300,
            interval=10,
        )
        assert all(a["details"]["remediation"] == "resolver_fallback" for a in roots.values()), roots
        tld = wait_for(
            "resolver:tld:com on both nodes",
            lambda: (lambda f: f if len(f) == 2 else None)(open_alerts("resolver:tld:com")),
            timeout=300,
            interval=10,
        )
        assert all(a["details"]["remediation"] == "resolver_fallback" for a in tld.values()), tld
        wait_for(
            "probes unhealthy on both nodes",
            lambda: all(e["probes_healthy_since"] == "unhealthy" for e in health()["nodes"]),
            timeout=180,
            interval=10,
        )

    def test_06_fallback_to_quad9(self):
        plan = api().post("/dns/resolver/fallback/plan", {"preset": "quad9", "forward": "first", "hours": 1})
        assert plan["requires_confirmation"], plan
        api().apply(plan)
        for host in (A1, A2):
            text = options(host)
            assert "forward first;" in text and all(a in text for a in QUAD9_V4 + QUAD9_V6), text
            assert "dnssec-validation" not in text.replace(STATE["before"][host], "")
            wait_for(f"{host} resolves through Quad9", lambda h=host: resolve(h)[0].isdigit(), timeout=90)
        fallback = health()["fallback"]
        assert fallback["preset"] == "quad9" and sorted(fallback["node_ids"]) == sorted(ids().values())
        assert fallback["before"][ids()[A1]] == {"forward": None, "forwarders": None}, fallback
        STATE["fallback_id"] = fallback["id"]
        # The local resolver answers again: resolver:roots resolves; the direct probes still fail.
        wait_for(
            "resolver:roots resolved", lambda: open_alerts("resolver:roots") == {}, timeout=300, interval=10
        )
        assert health()["return_ready"] is False

    def test_07_automatic_return(self):
        cut(False)

        def ready() -> bool:
            out = health()
            return out["return_ready"] and all(
                e["probes_healthy_since"] not in ("unhealthy", "unknown") for e in out["nodes"]
            )

        wait_for("return_ready", ready, timeout=600, interval=15)
        wait_for(
            "resolver:tld:com resolved", lambda: open_alerts("resolver:tld:") == {}, timeout=300, interval=10
        )
        until = (datetime.now(UTC) + timedelta(seconds=20)).isoformat().replace("+00:00", "Z")
        api().call("PUT", "/dns/resolver/fallback", {"until": until})
        wait_for(
            "automatic return on both nodes", lambda: health()["fallback"] is None, timeout=300, interval=10
        )
        # The audit is replicated: each collector's own return, by system, seen from ns1.
        done = [
            e
            for e in audit(A1, "dns.resolver.op")
            if e["request"].get("fallback_id") == STATE["fallback_id"] and e["request"].get("op") == "return"
        ]
        assert sorted(e["node_id"] for e in done) == sorted(ids().values()), done
        assert all(e["user"] == "system" and e["result"] == "ok" for e in done), done
        for address in (A1, A2):
            assert options(address) == STATE["before"][address], address
            assert resolve(address)[0].isdigit()

    def test_08_automatic_fallback_then_return_plan(self):
        api().call(
            "PUT",
            "/admin/settings",
            {"resolver": {"fallback_auto_enabled": True, "fallback_after_seconds": 60}},
        )
        cut(True)
        try:
            fallback = wait_for("automatic fallback", lambda: health()["fallback"], timeout=600, interval=10)
            assert (
                fallback["by"] == "system"
                and fallback["preset"] == "quad9"
                and fallback["forward"] == "first"
            )
            for host in (A1, A2):
                wait_for(f"{host} resolves through Quad9", lambda h=host: resolve(h)[0].isdigit(), timeout=90)
        finally:
            cut(False)
        api().call("PUT", "/admin/settings", {"resolver": {"fallback_auto_enabled": False}})
        api().apply(api().post("/dns/resolver/fallback/return/plan", {}))
        assert health()["fallback"] is None
        for address in (A1, A2):
            assert options(address) == STATE["before"][address], address
            assert resolve(address)[0].isdigit()
