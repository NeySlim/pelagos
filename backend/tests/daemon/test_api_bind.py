# SPDX-License-Identifier: Apache-2.0
"""The API against a real named: zones with serials and transfer status, record add/apply/rollback,
per-node audit material, raw:<file> statements merged losslessly, the editor's tree and grammar."""

from __future__ import annotations

import subprocess
import time
from pathlib import Path
from typing import Any

import pytest

from tests.daemon.api_node import V1, apply, login, make_app, make_node, planned
from tests.fixtures.ports import find_binary

pytestmark = pytest.mark.daemon


@pytest.fixture
def api(tmp_root, named_server):
    ctx = make_node(tmp_root / "node", named=named_server)
    app = make_app(ctx)
    yield login(app), ctx
    from pelagos.services.container import Services

    Services.of(ctx).close()


def records(client, zone: str = "example.lan") -> dict[tuple[str, str], list[str]]:
    page = client.get(f"{V1}/dns/zones/{zone}/records?per_page=500").get_json()
    return {(r["name"], r["rtype"]): r["rdata"] for r in page["items"]}


def test_zones_and_records_through_the_api(api, named_server):
    client, ctx = api
    zones = {z["zone"]["name"]: z for z in client.get(f"{V1}/dns/zones").get_json()["items"]}
    assert {"example.lan.", "2.0.192.in-addr.arpa."} <= set(zones)
    assert zones["example.lan."]["serials"] == {ctx.node.id: 2026102401}
    assert zones["example.lan."]["status"] == {}  # a primary zone has no transfer timers

    plan = planned(
        client.post(
            f"{V1}/dns/zones/example.lan/records/plan",
            json={
                "changes": [
                    {"op": "add", "target": "api-test/A", "after": {"ttl": 300, "rdata": ["192.0.2.81"]}}
                ]
            },
        )
    )
    result = apply(client, plan)
    assert result["state"] == "applied" and result["results"][0]["ok"], result
    assert records(client)[("api-test.example.lan.", "A")] == ["192.0.2.81"]

    entries = client.get(f"{V1}/audit?action=dns.rrset&per_page=10").get_json()["items"]
    node = next(e for e in entries if e["request"].get("entry") == "node")
    assert node["plan_id"] == plan["id"] and node["node_id"] == ctx.node.id
    assert (
        "api-test.example.lan." in node["request"]["update"]
        and node["request"]["key"].rstrip(".") == "ddi-admin"
    )
    assert node["response"]["rcode"] == "NOERROR"
    assert result["results"][0]["audit_ids"] == [node["id"]]

    rb = client.post(f"{V1}/plans/{plan['id']}/rollback").get_json()
    assert rb["state"] == "rolled_back", rb
    assert ("api-test.example.lan.", "A") not in records(client)

    # A plan whose TTL ran out answers 410, not 404.
    expired = planned(
        client.post(
            f"{V1}/dns/zones/example.lan/records/plan",
            json={
                "changes": [{"op": "add", "target": "late/A", "after": {"ttl": 60, "rdata": ["192.0.2.82"]}}]
            },
        )
    )
    from datetime import timedelta

    from pelagos.domain import utcnow

    ctx.plan_store.get(expired["id"]).expires_at = utcnow() - timedelta(seconds=1)
    r = client.post(f"{V1}/plans/{expired['id']}/apply", json={})
    assert r.status_code == 410 and r.get_json()["code"] == "plan_expired"


def test_raw_statement_in_a_managed_file_keeps_the_rest(api, named_server):
    client, _ctx = api
    setup = planned(
        client.post(f"{V1}/dns/config/plan", json={"changes": [{"op": "add", "target": "pelagos/includes"}]})
    )
    assert apply(client, setup)["state"] == "applied"
    acls = named_server.root / "pelagos" / "acls.conf"
    original = acls.read_text()
    # A hand comment and a statement written in a non-canonical style must survive untouched.
    kept = '// kept: office printers\nacl "printers" { 192.0.2.200; 192.0.2.201; };\n'
    acls.write_text(original + kept)
    named_server.rndc("reconfig")

    stmt = "acl office {\n\t192.0.2.0/25;\n};"
    plan = planned(
        client.post(
            f"{V1}/dns/config/plan",
            json={"changes": [{"op": "add", "target": f"raw:{acls}", "after": stmt, "before": None}]},
        )
    )
    assert plan["changes"][0]["target"] == "raw:acls.conf"
    assert apply(client, plan)["state"] == "applied"
    text = acls.read_text()
    assert text.startswith(original + kept) and "acl office" in text
    checkconf = find_binary("named-checkconf")
    assert subprocess.run([checkconf, str(named_server.named_conf)], capture_output=True).returncode == 0

    plan = planned(
        client.post(
            f"{V1}/dns/config/plan",
            json={
                "changes": [
                    {
                        "op": "replace",
                        "target": f"raw:{acls}",
                        "before": stmt,
                        "after": "acl office {\n\t192.0.2.0/24;\n};",
                    }
                ]
            },
        )
    )
    assert apply(client, plan)["state"] == "applied"
    text = acls.read_text()
    assert "192.0.2.0/24" in text and "192.0.2.0/25" not in text and kept in text

    # The user's own named.conf is never a raw target.
    r = client.post(
        f"{V1}/dns/config/plan",
        json={"changes": [{"op": "add", "target": f"raw:{named_server.named_conf}", "after": stmt}]},
    )
    assert r.status_code == 400 and "never rewritten" in r.get_json()["detail"]


def test_editor_tree_and_grammar_of_the_real_server(api, named_server):
    client, ctx = api
    tree = client.get(f"{V1}/advanced/bind/tree").get_json()
    assert tree["node_id"] == ctx.node.id and tree["files"][0]["path"] == str(named_server.named_conf)
    top = {s["name"]: s for s in tree["files"][0]["statements"]}
    assert isinstance(top["options"]["children"], list) and top["options"]["value"] is None
    zone = next(s for s in tree["files"][0]["statements"] if s["name"] == "zone")
    assert zone["value"].startswith('"') and any(c["name"] == "type" for c in zone["children"])
    for f in tree["files"]:
        for s in f["statements"]:
            if s["name"] == "key":
                assert all(c["value"] == "****" for c in s["children"] if c["name"] == "secret")
    grammar = client.get(f"{V1}/advanced/bind/grammar").get_json()
    names = {s["name"] for s in grammar["statements"]}
    assert {"options", "zone", "key", "acl", "recursion"} <= names


def test_secondary_zone_status_in_the_zone_list(tmp_root, named_server, named_secondary):
    ctx = make_node(tmp_root / "node2", named=named_secondary)
    client = login(make_app(ctx))
    deadline = time.monotonic() + 20
    while True:
        zones = {z["zone"]["name"]: z for z in client.get(f"{V1}/dns/zones").get_json()["items"]}
        status = zones["example.lan."]["status"].get(ctx.node.id, {})
        if status.get("expires") or time.monotonic() > deadline:
            break
        time.sleep(0.2)
    assert zones["example.lan."]["zone"]["kind"] == "secondary"
    assert status["expires"] and status["next_refresh"], status
    assert status["serial"] == 2026102401


def scrape(client, ctx) -> dict[str, float]:
    """GET /metrics from an allowed network (127.0.0.1) as {sample: value}."""
    ctx.config_store.update_cluster(
        lambda c: c.settings.setdefault("metrics", {}).update(allowed_networks=["127.0.0.0/8"]),
        updated_by="test",
    )
    r = client.get("/metrics")
    assert r.status_code == 200, r.get_data(as_text=True)
    return {
        line.rsplit(" ", 1)[0]: float(line.rsplit(" ", 1)[1])
        for line in r.get_data(as_text=True).splitlines()
        if line and not line.startswith("#")
    }


def test_metrics_bind_counters_match_dns_stats(api):
    client, ctx = api
    before = client.get(f"{V1}/dns/stats").get_json()
    samples = scrape(client, ctx)
    after = client.get(f"{V1}/dns/stats").get_json()
    node = ctx.self_node().peer.name
    for qtype, low in before["qtypes"].items():
        value = samples[f'pelagos_bind_queries_total{{node="{node}",qtype="{qtype}"}}']
        assert low <= value <= after["qtypes"][qtype]
    for rcode, low in before["rcodes"].items():
        value = samples[f'pelagos_bind_responses_total{{node="{node}",rcode="{rcode}"}}']
        assert low <= value <= after["rcodes"][rcode]
    assert samples['pelagos_scrape_success{source="bind"}'] == 1

# Non-blocking web worker (section 2): the real gunicorn worker serves /health while another
# request waits on a slow named-checkconf or works through a zone transfer.
HEALTH_BUDGET = 0.1


def _gunicorn(ctx, tmp_root):
    """The packaged command line: gunicorn_conf.py (monkey patch, gevent worker) on a free port."""
    import os
    import sys

    from pelagos.core.webcert import pem
    from tests.fixtures.ports import free_port

    key = pem.generate_key()
    (tmp_root / "web.key").write_bytes(pem.key_pem(key))
    (tmp_root / "web.crt").write_bytes(pem.cert_pem(pem.self_signed(key, ["127.0.0.1"])))
    port = free_port()
    conf = Path(__file__).resolve().parents[2] / "pelagos" / "gunicorn_conf.py"
    env = dict(os.environ, PELAGOS_HOME=str(ctx.paths.etc.parent))
    log = (tmp_root / "gunicorn.log").open("w")
    proc = subprocess.Popen(
        [sys.executable, "-m", "gunicorn", "-c", str(conf), "-b", f"127.0.0.1:{port}",
         "--certfile", str(tmp_root / "web.crt"), "--keyfile", str(tmp_root / "web.key"),
         "--no-control-socket", "--access-logfile", "/dev/null", "pelagos.app:wsgi_app()"],
        env=env, stdout=log, stderr=subprocess.STDOUT,
    )  # fmt: skip
    return proc, port


class _Web:
    def __init__(self, port: int, cafile: Path) -> None:
        import ssl

        self.port = port
        self.tls = ssl.create_default_context(cafile=str(cafile))
        self.headers: dict[str, str] = {}

    def request(self, method: str, path: str, body: Any = None, timeout: float = 60) -> tuple[int, Any]:
        import http.client
        import json

        conn = http.client.HTTPSConnection("127.0.0.1", self.port, context=self.tls, timeout=timeout)
        try:
            payload = None if body is None else json.dumps(body)
            conn.request(
                method, path, body=payload, headers={"Content-Type": "application/json", **self.headers}
            )
            resp = conn.getresponse()
            data = resp.read()
            cookie = resp.getheader("Set-Cookie")
            if cookie and path.endswith("/auth/login"):
                self.headers["Cookie"] = cookie.split(";")[0]
                self.headers["X-CSRF-Token"] = json.loads(data)["csrf_token"]
            return resp.status, json.loads(data) if data else None
        finally:
            conn.close()

    def health_during(self, work: Any) -> tuple[Any, list[float]]:
        """`work()` in this thread, /health polled on one keep-alive connection meanwhile."""
        import http.client
        import threading

        stop, latencies = threading.Event(), []

        def poll() -> None:
            conn = http.client.HTTPSConnection("127.0.0.1", self.port, context=self.tls, timeout=30)
            while not stop.is_set():
                started = time.monotonic()
                conn.request("GET", f"{V1}/health")
                conn.getresponse().read()
                latencies.append(time.monotonic() - started)
                time.sleep(0.02)
            conn.close()

        poller = threading.Thread(target=poll)
        poller.start()
        time.sleep(0.2)
        try:
            result = work()
        finally:
            stop.set()
            poller.join()
        return result, latencies


def _wait_for_name(server: Any, name: str) -> None:
    import dns.message
    import dns.query

    deadline = time.monotonic() + 20
    while True:
        answer = dns.query.udp(
            dns.message.make_query(name, "A"), "127.0.0.1", port=server.dns_port, timeout=2
        )
        if answer.answer or time.monotonic() > deadline:
            assert answer.answer, f"{name} not loaded"
            return
        time.sleep(0.2)


@pytest.fixture
def web(tmp_root, named_server):
    from tests.conftest import ADMIN_PASSWORD

    checkconf = find_binary("named-checkconf")
    slow = tmp_root / "slow-checkconf"
    slow.write_text(f'#!/bin/sh\nsleep 1.5\nexec {checkconf} "$@"\n')
    slow.chmod(0o755)
    ctx = make_node(tmp_root / "node", named=named_server)
    node = ctx.config_store.load_node()
    node.engines["bind"]["checkconf"] = str(slow)
    ctx.config_store.save_node(node)
    proc, port = _gunicorn(ctx, tmp_root)
    client = _Web(port, tmp_root / "web.crt")
    try:
        deadline = time.monotonic() + 30
        while True:
            try:
                if client.request("GET", f"{V1}/health")[0] == 200:
                    break
            except OSError:
                pass
            if proc.poll() is not None or time.monotonic() > deadline:
                pytest.fail("gunicorn did not start:\n" + (tmp_root / "gunicorn.log").read_text())
            time.sleep(0.1)
        status, _ = client.request(
            "POST", f"{V1}/auth/login", {"username": "admin", "password": ADMIN_PASSWORD}
        )
        assert status == 200
        yield client
    finally:
        proc.terminate()
        proc.wait(15)


def test_health_answers_during_a_slow_checkconf(web) -> None:
    change = {"op": "add", "target": "acls/web", "after": {"name": "web", "elements": ["192.0.2.0/24"]}}
    (status, plan), latencies = web.health_during(
        lambda: web.request("POST", f"{V1}/dns/acls/plan", {"change": change})
    )
    assert status == 200 and plan["state"] == "validated", plan
    assert len(latencies) >= 20  # /health kept answering through the 1.5 s checkconf
    assert max(latencies) < HEALTH_BUDGET, sorted(latencies)[-5:]


def test_health_answers_during_a_zone_transfer(web, named_server) -> None:
    zone_file = named_server.root / "zones" / "example.lan.db"
    named_server.rndc("freeze", "example.lan")
    with zone_file.open("a") as fh:
        fh.writelines(f"bulk{i} 300 IN A 10.0.{i >> 8}.{i & 255}\n" for i in range(10000))
    named_server.rndc("thaw", "example.lan")
    _wait_for_name(named_server, "bulk9999.example.lan.")
    (status, page), latencies = web.health_during(
        lambda: web.request("GET", f"{V1}/dns/zones/example.lan/records?per_page=10")
    )
    assert status == 200 and page["total"] > 10000, page
    assert max(latencies) < HEALTH_BUDGET, sorted(latencies)[-5:]
