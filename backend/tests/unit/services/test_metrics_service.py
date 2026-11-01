# SPDX-License-Identifier: Apache-2.0
"""MetricsService (section 30): families, cache, plan counter, failing sources, text format."""

# ruff: noqa: F811
from __future__ import annotations

import re
import shutil
import subprocess
from types import SimpleNamespace

import pytest

from pelagos.services import metrics_service as ms
from pelagos.services.container import Services
from tests.unit.api.conftest import app, fake_registry, services  # noqa: F401

pytestmark = pytest.mark.unit

SAMPLE = re.compile(
    r'^[a-zA-Z_:][a-zA-Z0-9_:]*(\{([a-zA-Z_][a-zA-Z0-9_]*="([^"\\]|\\.)*"(,|(?=\})))*\})? -?[0-9.e+-]+$'
)


def validate(text: str) -> dict[str, str]:
    """House validator of the text format: HELP then TYPE per family, samples together, no repeats."""
    types: dict[str, str] = {}
    seen: set[str] = set()
    current = None
    assert text.endswith("\n")
    for line in text.splitlines():
        if line.startswith("# HELP "):
            current = line.split()[2]
            assert current not in seen, f"family {current} split"
            seen.add(current)
        elif line.startswith("# TYPE "):
            _, _, name, mtype = line.split()
            assert name == current and mtype in ("gauge", "counter")
            types[name] = mtype
        else:
            assert SAMPLE.match(line), line
            assert line.split("{")[0].split(" ")[0] == current, line
    return types


def test_render_is_valid_and_has_the_families(services: Services, app) -> None:
    text = services.metrics.render()
    types = validate(text)
    for name in (
        "pelagos_build_info", "pelagos_node_up", "pelagos_alerts", "pelagos_bind_queries_total",
        "pelagos_bind_responses_total", "pelagos_kea_packets_total", "pelagos_scrape_success",
    ):  # fmt: skip
        assert name in types, name
    assert types["pelagos_bind_queries_total"] == "counter"
    assert 'pelagos_bind_queries_total{node="' in text and 'qtype="AAAA"} 200' in text
    assert 'engine="kea4",packet="ack-sent"} 1400' in text
    assert 'pelagos_scrape_success{source="bind"} 1' in text


def test_counters_match_the_stats_routes(services: Services) -> None:
    stats = services.dns.stats(None)
    kea = services.dhcp4.statistics(None)["statistics"]
    text = services.metrics.render()
    for qtype, count in stats["qtypes"].items():
        assert f'qtype="{qtype}"}} {count}' in text
    assert f'packet="received"}} {kea["pkt4-received"][0][0]}' in text


def test_no_secret_in_the_exposition(services: Services) -> None:
    text = services.metrics.render().lower()
    for word in ("secret", "password", "tsig", "token"):
        assert word not in text


def test_cache_holds_ten_seconds(services: Services, monkeypatch) -> None:
    calls = []
    monkeypatch.setattr(services.metrics, "_build", lambda: calls.append(1) or "x 1\n")
    services.metrics.render(now=100.0)
    services.metrics.render(now=109.0)
    assert len(calls) == 1
    services.metrics.render(now=110.5)
    assert len(calls) == 2


def test_a_failing_source_is_reported_not_fatal(services: Services, monkeypatch) -> None:
    def boom(_node_id):
        raise RuntimeError("down")

    monkeypatch.setattr(services.dns, "stats", boom)
    text = services.metrics.render()
    validate(text)
    assert 'pelagos_scrape_success{source="bind"} 1' in text  # a node read failing is logged, left out
    assert "pelagos_bind_queries_total" not in text
    assert 'pelagos_scrape_success{source="alerts"} 1' in text


def test_plan_counter_by_scope_and_result(services: Services, monkeypatch) -> None:
    plan = SimpleNamespace(scope=SimpleNamespace(value="dns.record"))
    monkeypatch.setattr(services.ctx.plan_store, "get", lambda pid: plan)
    for event in ("applied", "applied", "failed", "step"):
        services.events.publish("plans", event, {"plan_id": "p1"})
    text = services.metrics.render()
    assert 'pelagos_plan_applied_total{scope="dns.record",result="applied"} 2' in text
    assert 'pelagos_plan_applied_total{scope="dns.record",result="failed"} 1' in text
    assert validate(text)["pelagos_plan_applied_total"] == "counter"


def test_label_escaping() -> None:
    out = ms.Exposition()
    out.add("m", "gauge", "h", 1, a='x"y\\z\nw')
    assert 'a="x\\"y\\\\z\\nw"' in out.text()


@pytest.mark.skipif(shutil.which("promtool") is None, reason="promtool not installed")
def test_promtool_accepts_the_output(services: Services) -> None:
    r = subprocess.run(
        ["promtool", "check", "metrics"], input=services.metrics.render(), text=True, capture_output=True
    )
    assert r.returncode == 0, r.stderr
