# SPDX-License-Identifier: Apache-2.0
"""List updates with fake downloads: install, revalidation, rejected lists, allow zone, log counters."""

from __future__ import annotations

import errno
import shutil
from pathlib import Path
from typing import Any

import pytest

from pelagos.rpz import fetch as fetch_mod
from pelagos.rpz import model, sync

pytestmark = pytest.mark.unit

NOW = 1_793_000_000
NATIVE = (
    b"$TTL 300\n@ SOA localhost. root.localhost. ( 1 1 1 1 1 )\n  NS localhost.\n%b.example.com CNAME .\n"
)
HOUR = 3600


class Node:
    """A node's side of the sync: files in tmp_path, rndc and downloads replaced by recorders."""

    def __init__(self, tmp_path: Path) -> None:
        self.reloads: list[str] = []
        self.fetches: list[tuple[str, str, str]] = []
        self.responses: list[Any] = []
        self.loaded = True
        self.reload_error: str | None = None
        self.now = float(NOW)
        self.env = sync.SyncEnv(
            node_id="n1",
            rpz_dir=tmp_path / "rpz",
            state_path=tmp_path / "rpz-state.json",
            reload=self.reload,
            zone_loaded=lambda zone: self.loaded,
            zone_info=lambda zone: {"serial": "42", "nodes": "1000"},
            checkzone=shutil.which("named-checkzone"),
            clock=lambda: self.now,
            fetch=self.fetch,
            log_path=tmp_path / "rpz.log",
        )
        self.settings: dict[str, Any] = {"rpz": {"categories": {}, "subscriptions": {}}}

    def reload(self, zone: str) -> str:
        self.reloads.append(zone)
        if self.reload_error:
            raise RuntimeError(self.reload_error)
        return "ok"

    def fetch(self, url: str, etag: str = "", modified: str = "", **_: Any) -> fetch_mod.Fetched:
        self.fetches.append((url, etag, modified))
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    def subscribe(self, sub_id: str = "mine", **kw: Any) -> str:
        entry = {"url": "https://lists.example.com/l.txt", "format": "domains", "interval_hours": 24, **kw}
        self.settings["rpz"]["subscriptions"][sub_id] = entry
        return model.zone_for(sub_id)

    def list_reloads(self) -> list[str]:
        return [z for z in self.reloads if z != model.ALLOW_ZONE]

    def run(self, **kw: Any) -> sync.SyncReport:
        return sync.Syncer(self.env, lambda: self.settings).run(**kw)

    def state(self) -> dict[str, Any]:
        return sync.load_state(self.env.state_path)

    def file(self, sub_id: str = "mine") -> Path:
        return self.env.rpz_dir / model.zone_file_name(model.zone_for(sub_id))


def body(n: int) -> bytes:
    return "".join(f"host{i}.example.com\n" for i in range(n)).encode()


def ok(text: bytes, **kw: Any) -> fetch_mod.Fetched:
    return fetch_mod.Fetched(
        200,
        text,
        kw.get("etag", '"v1"'),
        kw.get("modified", "Mon, 26 Oct 2026 06:00:00 GMT"),
        kw.get("expires"),
    )


@pytest.fixture
def node(tmp_path: Path) -> Node:
    return Node(tmp_path)


def test_first_download_is_converted_checked_and_loaded(node: Node) -> None:
    zone = node.subscribe()
    node.responses.append(ok(body(100)))
    report = node.run()
    assert report.updated == ["mine"]
    assert node.list_reloads() == [zone]
    text = node.file().read_text()
    assert "host7.example.com CNAME ." in text and "*.host7.example.com CNAME ." in text
    entry = node.state()["subs"]["mine"]
    assert entry["entries"] == 100 and entry["status"] == "ok" and entry["bytes"] == len(text)
    assert entry["etag"] == '"v1"' and entry["source_date"] == fetch_mod.parse_http_date(
        "Mon, 26 Oct 2026 06:00:00 GMT"
    )
    assert entry["next_check"] == NOW + 24 * HOUR
    assert not list(node.env.rpz_dir.glob(".*.tmp"))


def test_not_due_means_no_download_and_force_means_download(node: Node) -> None:
    node.subscribe()
    node.responses.append(ok(body(10)))
    node.run()
    node.now += HOUR
    node.run()
    assert len(node.fetches) == 1
    node.responses.append(fetch_mod.Fetched(304, b"", '"v1"', "x", None))
    node.run(only="mine")
    assert len(node.fetches) == 2


def test_revalidation_sends_etag_and_keeps_file_on_304(node: Node) -> None:
    node.subscribe()
    node.responses.append(ok(body(10)))
    node.run()
    before = node.file().read_bytes()
    node.now += 25 * HOUR
    node.responses.append(fetch_mod.Fetched(304, b"", '"v1"', "Mon, 26 Oct 2026 06:00:00 GMT", None))
    report = node.run()
    assert report.unchanged == ["mine"]
    assert node.fetches[-1][1:] == ('"v1"', "Mon, 26 Oct 2026 06:00:00 GMT")
    assert node.file().read_bytes() == before and len(node.list_reloads()) == 1
    assert node.state()["subs"]["mine"]["next_check"] == NOW + 25 * HOUR + 24 * HOUR


def test_a_lost_copy_is_downloaded_again_without_validators(node: Node) -> None:
    """The zone folder recreated (the plan writes an empty stub): no 304 may keep the stub."""
    node.subscribe()
    node.responses.append(ok(body(10)))
    node.run()
    node.file().write_text("$TTL 300\n@ SOA localhost. root.localhost. 1 1h 15m 30d 2h\n@ NS localhost.\n")
    node.now += HOUR  # well before the next check
    node.responses.append(ok(body(10)))
    report = node.run()
    assert report.updated == ["mine"] and node.fetches[-1][1:] == ("", "")
    assert "host7.example.com CNAME ." in node.file().read_text()


def test_expires_header_postpones_the_next_check(node: Node) -> None:
    node.subscribe(interval_hours=1)
    node.responses.append(ok(body(10), expires=NOW + 5 * 86400))
    node.run()
    # An hour would do for the interval, but the provider asked for five days (the floor is one hour).
    assert node.state()["subs"]["mine"]["next_check"] == NOW + 5 * 86400


def test_a_list_that_shrank_or_emptied_keeps_the_old_copy(node: Node) -> None:
    node.subscribe()
    node.responses.append(ok(body(100)))
    node.run()
    good = node.file().read_bytes()
    node.now += 25 * HOUR
    node.responses.append(ok(body(30), etag='"v2"'))
    report = node.run()
    assert "shrank by 70%" in report.failed["mine"]
    assert node.file().read_bytes() == good
    entry = node.state()["subs"]["mine"]
    assert entry["status"] == "rejected" and entry["etag"] == '"v1"' and entry["entries"] == 100
    node.now += 7 * HOUR
    node.responses.append(ok(b"# only comments\n"))
    assert "empty" in node.run().failed["mine"]
    assert node.file().read_bytes() == good
    # Within the limit it goes through again.
    node.now += 7 * HOUR
    node.responses.append(ok(body(60), etag='"v3"'))
    assert node.run().updated == ["mine"]
    assert node.state()["subs"]["mine"]["failures"] == 0


def test_named_checkzone_refusal_keeps_the_old_copy(node: Node, tmp_path: Path) -> None:
    node.subscribe(format="rpz")
    node.responses.append(ok(NATIVE % b"a"))
    node.run()
    good = node.file().read_bytes()
    node.env.checkzone = str(tmp_path / "checkzone")
    (tmp_path / "checkzone").write_text("#!/bin/sh\necho 'dns_rdata_fromtext: near x: bad'; exit 1\n")
    (tmp_path / "checkzone").chmod(0o755)
    node.now += 25 * HOUR
    node.responses.append(ok(NATIVE % b"b"))
    assert "bad" in node.run().failed["mine"]
    assert node.file().read_bytes() == good


def test_failed_reload_puts_the_previous_file_back(node: Node) -> None:
    node.subscribe()
    node.responses.append(ok(body(10)))
    node.run()
    good = node.file().read_bytes()
    node.now += 25 * HOUR
    node.reload_error = "rndc: connect failed"
    node.responses.append(ok(body(12), etag='"v2"'))
    assert "rndc reload failed" in node.run().failed["mine"]
    assert node.file().read_bytes() == good


def test_download_error_is_retried_with_backoff_and_reported(node: Node) -> None:
    node.subscribe()
    node.responses.append(fetch_mod.FetchError("HTTP 410: the list is gone or moved"))
    node.run()
    entry = node.state()["subs"]["mine"]
    assert entry["status"] == "error" and entry["failures"] == 1 and entry["next_check"] == NOW + 900
    cfg = model.config(node.settings)
    found = sync.findings(model.resolve(node.settings), node.state(), cfg, NOW)
    assert found[0]["reason"] == "failed" and "410" in found[0]["error"]
    assert not node.file().exists()


def test_stale_finding_after_three_intervals_without_success(node: Node) -> None:
    node.subscribe(interval_hours=24)
    node.responses.append(ok(body(10)))
    node.run()
    subs, cfg = model.resolve(node.settings), model.config(node.settings)
    assert sync.findings(subs, node.state(), cfg, NOW + 70 * HOUR) == []
    late = sync.findings(subs, node.state(), cfg, NOW + 73 * HOUR)
    assert late[0]["reason"] == "stale" and late[0]["hours"] == 73


def test_changed_subscription_downloads_again_without_validators(node: Node) -> None:
    node.subscribe()
    node.responses.append(ok(body(10)))
    node.run()
    node.subscribe(action="redirect", redirect="192.0.2.80")
    node.responses.append(ok(body(10)))
    node.run()
    assert node.fetches[-1][1:] == ("", "")
    assert "A 192.0.2.80" in node.file().read_text()


def test_zone_not_declared_yet_writes_the_file_without_reload(node: Node) -> None:
    node.subscribe()
    node.loaded = False
    node.env.rpz_dir.mkdir()
    node.responses.append(ok(body(10)))
    node.run()
    assert node.list_reloads() == [] and node.file().exists()
    assert node.state()["subs"]["mine"]["status"] == "waiting_config"


def test_no_folder_and_no_zone_yet_waits_for_the_plan_without_failing(node: Node) -> None:
    node.subscribe()
    node.loaded = False
    report = node.run()
    assert node.fetches == [] and report.failed == {} and not node.env.rpz_dir.exists()
    entry = node.state()["subs"]["mine"]
    assert entry["status"] == "waiting_config"
    assert entry["error_message"] == {"key": "rpz.dir_missing", "params": {"path": str(node.env.rpz_dir)}}
    cfg = model.config(node.settings)
    assert sync.findings(model.resolve(node.settings), node.state(), cfg, NOW) == []
    # Once the plan made the folder, the list is fetched and the waiting note goes.
    node.env.rpz_dir.mkdir()
    node.responses.append(ok(body(10)))
    node.run()
    assert node.fetches and "error_message" not in node.state()["subs"]["mine"]


def test_a_write_error_is_worded_without_the_temp_file(node: Node) -> None:
    node.subscribe()
    tmp = node.env.rpz_dir / "tmposvuzh2x"
    node.responses.append(FileNotFoundError(2, "No such file or directory", str(tmp)))
    node.run()
    entry = node.state()["subs"]["mine"]
    assert entry["status"] == "error" and "tmposvuzh2x" not in entry["error"]
    message = entry["error_message"]
    assert message["key"] == "permission.apply_error" and message["params"]["path"] == str(node.env.rpz_dir)
    cfg = model.config(node.settings)
    found = sync.findings(model.resolve(node.settings), node.state(), cfg, NOW)
    assert found[0]["error_message"] == message


def test_a_full_disk_or_a_missing_tool_is_not_called_a_permission_problem(node: Node) -> None:
    node.subscribe()
    node.responses.append(OSError(errno.ENOSPC, "No space left on device", str(node.env.rpz_dir / "tmpx")))
    node.run()
    message = node.state()["subs"]["mine"]["error_message"]
    assert message["params"]["reason"]["key"] == "permission.errno.no_space"
    node.responses.append(FileNotFoundError(2, "No such file or directory", "/usr/bin/named-checkzone"))
    node.run(force=True)
    message = node.state()["subs"]["mine"]["error_message"]
    assert message["key"] == "rpz.update_failed" and message["params"]["path"] == "/usr/bin/named-checkzone"


def test_other_nodes_and_disabled_subscriptions_are_left_alone(node: Node) -> None:
    node.subscribe("elsewhere", nodes=["n2"])
    node.subscribe("off", enabled=False)
    node.run()
    assert node.fetches == [] and node.state()["subs"] == {}


def test_allow_zone_follows_the_allow_list(node: Node) -> None:
    node.settings["rpz"]["allow"] = [{"domain": "ok.example.com"}]
    node.settings["rpz"]["exempt_clients"] = [{"cidr": "192.0.2.0/24"}]
    node.subscribe()
    node.responses.append(ok(body(5)))
    node.run()
    allow_file = node.env.rpz_dir / model.zone_file_name(model.ALLOW_ZONE)
    text = allow_file.read_text()
    assert "ok.example.com CNAME rpz-passthru." in text and "24.0.2.0.192.rpz-client-ip" in text
    assert model.ALLOW_ZONE in node.reloads
    reloads = len(node.reloads)
    node.run()
    assert len(node.reloads) == reloads  # nothing changed
    node.settings["rpz"]["allow"] = []
    node.run()
    assert "ok.example.com" not in allow_file.read_text()


def test_transferred_zone_reports_its_status(node: Node) -> None:
    node.settings["rpz"]["subscriptions"]["dq"] = {
        "kind": "axfr",
        "zone": "dbl.rpz.example.net",
        "primaries": ["192.0.2.53"],
        "tsig_key": "k",
    }
    node.run()
    entry = node.state()["subs"]["dq"]
    assert (
        entry["status"] == "ok"
        and entry["serial"] == 42
        and entry["entries"] == 1000
        and entry["entries_approx"]
    )
    node.loaded = False
    node.run()
    assert node.state()["subs"]["dq"]["status"] == "error"


LOG = (
    "26-Oct-2026 10:00:01.100 rpz: info: client @0x7f 192.0.2.5#40001 (ads.example.com): "
    "rpz QNAME NXDOMAIN rewrite ads.example.com/A/IN via ads.example.com.mine.rpz.invalid\n"
    "26-Oct-2026 10:00:02.200 rpz: info: client @0x7f 192.0.2.5#40002 (x.ads.example.com): "
    "rpz QNAME NXDOMAIN rewrite x.ads.example.com/AAAA/IN via *.ads.example.com.mine.rpz.invalid\n"
    "26-Oct-2026 10:00:03.300 rpz: info: client @0x7f 192.0.2.6#40003 (ok.example.com): "
    "rpz QNAME PASSTHRU rewrite ok.example.com/A/IN via ok.example.com.pelagos-allow.rpz.invalid\n"
    "26-Oct-2026 10:00:04.400 general: info: unrelated line\n"
    "26-Oct-2026 10:00:05.500 rpz: info: client @0x7f 192.0.2.7#4 (z.example.org): rpz QNAME N"
)


def test_rewrite_log_gives_counters_per_list_and_category(node: Node) -> None:
    node.settings["rpz"]["categories"] = {"ads": {"enabled": True, "level": "light"}}
    node.subscribe("mine", category="ads")
    node.responses.append(ok(body(5)))
    node.env.log_path.write_text(LOG)
    node.run()
    log = node.state()["log"]
    assert log["by_list"]["mine"]["hits"] == 2 and log["by_list"]["allow"]["hits"] == 1
    # `mine` is a custom subscription filed under ads; the catalog list of the same category counts too.
    assert log["by_category"]["ads"] == 2
    first = log["recent"][0]
    assert (
        first["client"] == "192.0.2.5"
        and first["qname"] == "ads.example.com"
        and first["rule"] == "ads.example.com"
    )
    assert log["recent"][1]["rule"] == "*.ads.example.com"
    # The unfinished last line is read once it is complete, not before.
    with node.env.log_path.open("a") as fh:
        fh.write("XDOMAIN rewrite z.example.org/A/IN via z.example.org.mine.rpz.invalid\n")
    node.run()
    assert node.state()["log"]["by_list"]["mine"]["hits"] == 3


def test_log_events_are_capped(node: Node) -> None:
    node.subscribe()
    node.responses.append(ok(body(5)))
    node.settings["rpz"]["log_events"] = 3
    node.env.log_path.write_text(LOG * 3)
    node.run()
    assert len(node.state()["log"]["recent"]) == 3


def test_accept_shrink_installs_a_smaller_list_but_not_an_empty_one(node: Node) -> None:
    node.subscribe()
    node.responses.append(ok(body(100)))
    node.run()
    node.now += 25 * HOUR
    node.responses.append(ok(body(30), etag='"v2"'))
    assert "shrank" in node.run().failed["mine"]
    node.now += HOUR
    node.responses.append(ok(body(30), etag='"v2"'))
    assert node.run(only="mine", accept_shrink=True).updated == ["mine"]
    assert node.state()["subs"]["mine"]["entries"] == 30
    node.now += HOUR
    node.responses.append(ok(b"# nothing\n", etag='"v3"'))
    assert "empty" in node.run(only="mine", accept_shrink=True).failed["mine"]


def test_accept_shrink_needs_a_named_list(node: Node) -> None:
    node.subscribe()
    node.responses.append(ok(body(100)))
    node.run()
    node.now += 25 * HOUR
    node.responses.append(ok(body(30), etag='"v2"'))
    assert "shrank" in node.run(accept_shrink=True).failed["mine"]


def test_long_expires_does_not_raise_a_stale_finding(node: Node) -> None:
    node.subscribe(interval_hours=24)
    node.responses.append(ok(body(10), expires=NOW + 7 * 86400))
    node.run()
    subs, cfg = model.resolve(node.settings), model.config(node.settings)
    assert sync.findings(subs, node.state(), cfg, NOW + 6 * 86400) == []
    assert sync.findings(subs, node.state(), cfg, NOW + 15 * 86400)[0]["reason"] == "stale"


def test_gunzip_is_capped_and_log_times_sort_across_months() -> None:
    import gzip

    from pelagos.rpz import logparse

    assert fetch_mod.gunzip(gzip.compress(b"a" * 1000), 5_000) == b"a" * 1000
    with pytest.raises(fetch_mod.FetchError):
        fetch_mod.gunzip(gzip.compress(b"a" * 1_000_000), 100_000)
    assert logparse.parse_time("31-Oct-2026 23:00:00.5") < logparse.parse_time("01-Nov-2026 00:00:00.1")
