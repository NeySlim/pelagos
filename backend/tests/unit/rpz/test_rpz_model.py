# SPDX-License-Identifier: Apache-2.0
"""Catalog, settings resolution, policy text, memory estimate, conditional download, alert poller."""

from __future__ import annotations

import io
import json
import time
import urllib.error
from email.message import Message
from pathlib import Path
from typing import Any

import pytest

from pelagos.collector import series as series_mod
from pelagos.collector.pollers.rpz import RpzPoller
from pelagos.domain import AlertKind
from pelagos.rpz import catalog, estimate, fetch, logparse, model
from tests.unit.rpz.test_rpz_sync import NOW, Node, body, ok

pytestmark = pytest.mark.unit


def test_catalog_file_is_consistent_and_follows_the_brief() -> None:
    data = catalog.load()
    assert data["version"] >= "2026-10-26"
    urls = {i["url"] for i in data["lists"].values()}
    assert "https://small.oisd.nl/rpz" in urls and "https://nsfw.oisd.nl/rpz" in urls
    assert not any("abuse.ch" in u for u in urls)
    assert all(u.startswith("https://") for u in urls)
    assert set(data["categories"]) == {
        "ads",
        "security",
        "adult",
        "gambling",
        "bypass",
        "social",
        "piracy",
        "spam_tlds",
    }
    for item in data["lists"].values():
        assert item["license"] and item["entries"] > 0 and item["format"] in ("rpz", "hosts", "domains")
    assert catalog.level_lists("ads", "light") == ["oisd-small"]
    assert catalog.level_lists("social", "strict") == ["hagezi-social"]  # nearest level it has
    assert catalog.list_category("hagezi-popupads") == "ads"
    assert catalog.category_summary("adult")["strict"]["entries"] >= 900000


def test_catalog_validation_rejects_broken_data() -> None:
    bad = {
        "lists": {"x": {"name": "x", "url": "http://x", "format": "rpz", "entries": 1, "license": "l"}},
        "categories": {},
    }
    with pytest.raises(catalog.CatalogError):
        catalog.validate(bad)
    bad = {"lists": {}, "categories": {"c": {"levels": {"normal": ["missing"]}, "lists": []}}}
    with pytest.raises(catalog.CatalogError):
        catalog.validate(bad)


def test_resolve_turns_selections_into_subscriptions_in_order() -> None:
    settings = {
        "rpz": {
            "categories": {
                "ads": {
                    "enabled": True,
                    "level": "normal",
                    "addons": ["hagezi-popupads"],
                    "action": "nodata",
                },
                "security": {
                    "enabled": False,
                    "level": "custom",
                    "lists": ["hagezi-tif.mini"],
                    "urls": [{"url": "https://example.com/own.txt", "format": "domains"}],
                },
            },
            "subscriptions": {"zz": {"url": "https://example.com/z.txt"}},
            "order": ["zz"],
        }
    }
    subs = model.resolve(settings)
    assert [s.id for s in subs][:3] == ["zz", "oisd-big", "hagezi-popupads"]
    by_id = {s.id: s for s in subs}
    assert by_id["oisd-big"].action == "nodata" and by_id["oisd-big"].zone == "oisd-big.rpz.invalid"
    assert by_id["hagezi-tif.mini"].enabled is False
    assert by_id["hagezi-tif.mini"].zone == "hagezi-tif-mini.rpz.invalid"
    extra = next(s for s in subs if s.source == "category_url")
    assert extra.category == "security" and extra.url == "https://example.com/own.txt"
    assert [s.id for s in model.for_node(subs, "n1")] == ["zz", "oisd-big", "hagezi-popupads"]


def test_nodes_filter_and_response_policy_text() -> None:
    subs = [
        model.Sub("a", "a", zone="a.rpz.invalid", action="nxdomain"),
        model.Sub("b", "b", zone="b.rpz.invalid", action="redirect", redirect="block.example.lan"),
        model.Sub("c", "c", zone="c.rpz.invalid", action="redirect", redirect="192.0.2.80", nodes=["n2"]),
        model.Sub("d", "d", zone="d.rpz.invalid", action="passthru"),
        model.Sub("e", "e", zone="e.rpz.invalid", action="nodata", enabled=False),
        model.Sub("f", "f", kind="axfr", zone="dbl.example.net"),
    ]
    mine = model.for_node(subs, "n1")
    assert [s.id for s in mine] == ["a", "b", "d", "f"]
    text = model.response_policy_value(mine)
    nd = "min-update-interval 0;"
    assert text == (
        f'{{ zone "pelagos-allow.rpz.invalid" policy passthru {nd} zone "a.rpz.invalid" policy nxdomain {nd} '
        f'zone "b.rpz.invalid" policy cname block.example.lan. {nd} '
        f'zone "d.rpz.invalid" policy passthru {nd} zone "dbl.example.net" {nd} }} break-dnssec yes'
    )
    assert "break-dnssec" not in model.response_policy_value(mine, break_dnssec=False)
    assert model.policy_clause(subs[2]) == "policy given"


def test_subscription_input_rules() -> None:
    ok_body = {"url": "https://example.com/l.txt", "format": "hosts", "action": "passthru"}
    assert model.clean_subscription("mine", ok_body, set())["action"] == "passthru"
    for sub_id, data, field in [
        ("Bad Id", ok_body, "id"),
        ("oisd-small", ok_body, "id"),
        ("mine", {**ok_body, "url": "file:///etc/passwd"}, "url"),
        ("mine", {**ok_body, "format": "csv"}, "format"),
        ("mine", {"kind": "axfr", "zone": "z.example", "primaries": []}, "primaries"),
        (
            "mine",
            {"kind": "axfr", "zone": "z.example", "primaries": ["192.0.2.1"], "tsig_algorithm": "hmac-md5"},
            "tsig_algorithm",
        ),
        (
            "mine",
            {
                "kind": "axfr",
                "zone": "z.example",
                "primaries": ["192.0.2.1"],
                "action": "redirect",
                "redirect": "192.0.2.9",
            },
            "redirect",
        ),
    ]:
        with pytest.raises(model.RpzInputError) as exc:
            model.clean_subscription(sub_id, data, set())
        assert exc.value.field == field, (sub_id, data)
    cleaned = model.clean_subscription("mine", ok_body, set())
    assert None not in cleaned.values()  # TOML has no null


def test_memory_estimate_and_warning_levels() -> None:
    cfg = model.config({})
    assert estimate.entries_mb(1_000_000, 500) == 500.0
    ok_node = estimate.assess([118000], 16384, cfg)
    assert ok_node["level"] == "ok" and ok_node["memory_mb"] == 94.4 and ok_node["peak_mb"] == 188.8
    assert estimate.assess([190000], 2048, cfg)["level"] == "caution"
    assert estimate.assess([950000], 4096, cfg)["level"] == "high"
    assert estimate.assess([950000, 250000], 2048, cfg)["level"] == "high"
    assert estimate.assess([950000], None, cfg)["level"] == "ok"
    assert estimate.assess([], 4096, cfg)["entries"] == 0


def test_node_ram_reads_meminfo(tmp_path: Path) -> None:
    info = tmp_path / "meminfo"
    info.write_text("MemTotal:        3995000 kB\nMemFree: 1 kB\n")
    assert estimate.node_ram_mb(info) == 3901
    assert estimate.node_ram_mb(tmp_path / "missing") is None


class Resp(io.BytesIO):
    def __init__(self, data: bytes, headers: dict[str, str]) -> None:
        super().__init__(data)
        self.headers = Message()
        for k, v in headers.items():
            self.headers[k] = v

    def __enter__(self) -> Resp:
        return self

    def __exit__(self, *exc: Any) -> None:
        return None


def test_fetch_sends_validators_and_reads_cache_headers() -> None:
    seen = {}

    def opener(request: Any, timeout: float) -> Resp:
        seen.update(request.header_items())
        return Resp(
            b"a.example.com\n",
            {
                "ETag": '"x"',
                "Last-Modified": "Mon, 26 Oct 2026 06:00:00 GMT",
                "Cache-Control": "public, max-age=3600",
            },
        )

    got = fetch.fetch(
        "https://example.com/l", etag='"old"', last_modified="Sun, 25 Oct 2026 06:00:00 GMT", opener=opener
    )
    assert seen["If-none-match"] == '"old"' and seen["If-modified-since"].startswith("Sun")
    assert got.status == 200 and got.etag == '"x"' and got.stream().read() == b"a.example.com\n"
    assert got.expires is not None and got.expires > 1_700_000_000


def test_fetch_handles_304_gone_gzip_and_size_cap() -> None:
    import gzip

    def raising(code: int):
        def opener(request: Any, timeout: float):
            raise urllib.error.HTTPError("https://example.com", code, "x", Message(), None)

        return opener

    assert fetch.fetch("https://example.com/l", etag='"e"', opener=raising(304)).status == 304
    with pytest.raises(fetch.FetchError, match="410"):
        fetch.fetch("https://example.com/l", opener=raising(410))
    with pytest.raises(fetch.FetchError, match="HTTP 500"):
        fetch.fetch("https://example.com/l", opener=raising(500))
    packed = gzip.compress(b"x.example.com\n")
    assert (
        fetch.fetch(
            "https://example.com/l", opener=lambda r, timeout: Resp(packed, {"Content-Encoding": "gzip"})
        )
        .stream()
        .read()
        == b"x.example.com\n"
    )
    with pytest.raises(fetch.FetchError, match="larger"):
        fetch.fetch("https://example.com/l", max_bytes=10, opener=lambda r, timeout: Resp(b"x" * 100, {}))
    with pytest.raises(fetch.FetchError):
        fetch.fetch(
            "https://example.com/l", opener=lambda r, timeout: (_ for _ in ()).throw(TimeoutError("slow"))
        )


def _serve(handler_cls):
    import threading
    from http.server import ThreadingHTTPServer

    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_fetch_refuses_loopback_and_redirects_to_it_unless_allowed() -> None:
    from http.server import BaseHTTPRequestHandler

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.1:{self.server.server_port}/list")
                self.end_headers()
                return
            if self.path == "/ftp":
                self.send_response(302)
                self.send_header("Location", "ftp://127.0.0.1/x")
                self.end_headers()
                return
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"evil.example\n")

        def log_message(self, *args):
            pass

    srv = _serve(H)
    base = f"http://127.0.0.1:{srv.server_port}"
    try:
        for path in ("/list", "/redirect"):
            with pytest.raises(fetch.FetchError, match="may not use"):
                fetch.fetch(base + path, timeout=5)
        got = fetch.fetch(base + "/redirect", timeout=5, allow_private=True)
        assert got.stream().read() == b"evil.example\n"
        with pytest.raises(fetch.FetchError, match="http or https"):
            fetch.fetch(base + "/ftp", timeout=5, allow_private=True)
    finally:
        srv.shutdown()


def test_refused_addresses() -> None:
    for ip in ("127.0.0.1", "10.1.2.3", "169.254.169.254", "0.0.0.0", "::1", "fe80::1", "::ffff:127.0.0.1"):  # noqa: S104
        assert fetch.refused_address(ip), ip
    assert not fetch.refused_address("93.184.216.34") and not fetch.refused_address("2606:4700::1111")


def test_fetch_has_a_total_deadline() -> None:
    class Slow:
        headers: dict[str, str] = {}

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, n):
            time.sleep(0.05)
            return b"a.example\n"

    with pytest.raises(fetch.FetchError, match="not finished"):
        fetch.fetch("https://example.com/l", max_seconds=0.2, opener=lambda r, timeout: Slow())


def test_urls_and_ids_with_a_trailing_newline_are_refused() -> None:
    for bad in ("http://a.example/x\n", "http://a.example\n"):
        with pytest.raises(model.RpzInputError):
            model.check_url(bad)
    assert model.SUB_ID.fullmatch("mylist\n") is None and model.HOST.fullmatch("a.example\n") is None


def test_a_log_window_without_a_newline_is_skipped(tmp_path) -> None:
    from pelagos.rpz import logparse

    log = tmp_path / "rpz.log"
    log.write_bytes(b"\x00" * 100)
    cur = logparse.Cursor()
    assert logparse.read_new(log, cur, limit=50) == [] and cur.offset == 50
    assert logparse.read_new(log, cur, limit=50) == [] and cur.offset == 100
    with log.open("ab") as fh:
        fh.write(b"next line\n")
    assert logparse.read_new(log, cur, limit=50) == ["next line"]


def test_http_dates() -> None:
    assert fetch.parse_http_date("Mon, 26 Oct 2026 06:00:00 GMT") == 1792994400
    assert fetch.parse_http_date("garbage") is None and fetch.parse_http_date(None) is None


def test_log_parser_and_zone_lookup() -> None:
    line = (
        "26-Oct-2026 10:00:01.100 rpz: info: client @0x7f 2001:db8::5#40001 (ads.example.com): "
        "rpz QNAME NXDOMAIN rewrite ads.example.com/A/IN via ads.example.com.big.rpz.invalid"
    )
    ev = logparse.parse_line(line)
    assert (
        ev
        and ev["client"] == "2001:db8::5"
        and ev["trigger"] == "QNAME"
        and ev["rule"] == "ads.example.com.big.rpz.invalid"
    )
    assert logparse.parse_line("26-Oct-2026 10:00:01.100 general: info: nothing") is None
    zones = {"big.rpz.invalid": "big", "rpz.invalid": "other"}
    assert logparse.zone_of(ev["rule"], zones) == ("big.rpz.invalid", "ads.example.com")
    assert logparse.zone_of("x.unknown.example", zones) is None


def test_log_reader_follows_rotation(tmp_path: Path) -> None:
    path = tmp_path / "rpz.log"
    cursor = logparse.Cursor()
    assert logparse.read_new(path, cursor) == []
    path.write_text("one\ntwo\npart")
    assert logparse.read_new(path, cursor) == ["one", "two"]
    path.write_text("one\ntwo\npartial done\n")
    assert logparse.read_new(path, cursor) == ["partial done"]
    path.unlink()
    path.write_text("fresh\n")  # rotated: a new inode starts from its beginning
    assert logparse.read_new(path, cursor) == ["fresh"]


class StubBackend:
    def __init__(self, node: Node) -> None:
        self.node = node

    def rpz_node_state(self) -> dict[str, Any]:
        from pelagos.rpz import sync

        return {"state": sync.load_state(self.node.env.state_path), "ram_mb": 2048}

    def rpz_env(self, log_path: str = "") -> Any:
        return self.node.env


def test_poller_runs_the_sync_publishes_the_snapshot_and_raises_alerts(tmp_path: Path) -> None:
    node = Node(tmp_path)
    node.subscribe()
    store = series_mod.SeriesStore(series_mod.connect(tmp_path / "series.sqlite"))
    poller = RpzPoller(
        StubBackend(node), "n1", store, lambda: node.settings, lambda: node.now, synchronous=True
    )
    node.responses.append(ok(body(10)))
    first = poller.poll()
    assert first.alerts == [] and first.kinds == {AlertKind.RPZ_UPDATE.value}
    second = poller.poll()  # the snapshot now shows the list the first pass installed
    _ts, snap = store.snapshot("n1", "bind", "rpz")
    assert snap["ram_mb"] == 2048 and snap["state"]["subs"]["mine"]["entries"] == 10
    assert second.alerts == []
    node.now += 25 * 3600
    node.responses.append(ok(body(2), etag='"v2"'))  # shrank: rejected, alert next pass
    poller.poll()
    third = poller.poll()
    [alert] = third.alerts
    assert (
        alert.kind is AlertKind.RPZ_UPDATE
        and alert.subject == "rpz:mine"
        and "shrank" in alert.details["error"]
    )
    assert alert.title_message["key"] == "alert.rpz_update"
    json.dumps(alert.to_dict(), default=str)
    poller.request("mine")
    node.responses.append(ok(body(9), etag='"v3"'))
    poller.poll()
    assert poller.poll().alerts == []
    assert NOW  # the shared clock constant is imported for the fixtures above


def test_poller_alert_carries_the_translated_error(tmp_path: Path) -> None:
    node = Node(tmp_path)
    node.subscribe()
    store = series_mod.SeriesStore(series_mod.connect(tmp_path / "series.sqlite"))
    poller = RpzPoller(
        StubBackend(node), "n1", store, lambda: node.settings, lambda: node.now, synchronous=True
    )
    node.responses.append(PermissionError(13, "Permission denied", str(node.env.rpz_dir / "tmpab12")))
    poller.poll()
    [alert] = poller.poll().alerts
    error = alert.title_message["params"]["error"]
    assert error["key"] == "permission.apply_error" and "tmpab12" not in alert.title


def test_poller_reports_a_stuck_update_and_keeps_publishing(tmp_path: Path) -> None:
    import threading

    node = Node(tmp_path)
    node.subscribe()
    store = series_mod.SeriesStore(series_mod.connect(tmp_path / "series.sqlite"))
    poller = RpzPoller(StubBackend(node), "n1", store, lambda: node.settings, lambda: node.now)
    hold = threading.Event()
    poller._thread = threading.Thread(target=hold.wait, daemon=True)
    poller._thread.start()
    poller._started = node.now
    try:
        assert poller.poll().alerts == []  # running, not late yet: nothing changes
        node.now += 3 * 3600
        out = poller.poll()
        [alert] = [a for a in out.alerts if a.subject == "rpz-stuck"]
        assert alert.title_message["key"] == "alert.rpz_stuck"
        assert store.snapshot("n1", "bind", "rpz") is not None
    finally:
        hold.set()
