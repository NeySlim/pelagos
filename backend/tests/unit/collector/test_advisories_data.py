# SPDX-License-Identifier: Apache-2.0
"""The shipped ISC advisory data: provenance, parseable ranges, and what production versions match."""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest

from pelagos.collector.checks import advisories
from pelagos.collector.checks.versions import version_tuple

pytestmark = pytest.mark.unit

DATA = advisories.load()
CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
SCRIPT = Path(__file__).resolve().parents[4] / "scripts" / "update-isc-advisories.py"


def test_dataset_is_dated_and_sourced():
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", DATA["verified"])
    assert DATA["sources"] and all(s.startswith("https://kb.isc.org/docs/") for s in DATA["sources"])
    assert advisories.valid(DATA)


@pytest.mark.parametrize("entry", DATA["entries"], ids=lambda e: e.get("id", "?"))
def test_every_entry_has_a_cve_an_isc_source_and_parseable_ranges(entry):
    assert CVE.match(entry.get("id", ""))
    assert entry.get("source") == f"https://kb.isc.org/docs/{entry['id'].lower()}"
    assert entry["severity"] in advisories.SEVERITIES
    ranges = (entry.get("ranges") or []) + (entry.get("ranges_preview") or [])
    assert ranges
    for r in ranges:
        low, high = version_tuple(r["from"]), version_tuple(r["to"])
        assert low is not None and high is not None and low <= high
        if r.get("fixed"):
            assert version_tuple(r["fixed"]) > high


def ids(engine: str, version: str) -> list[str]:
    return sorted(e["id"] for e in advisories.affected(engine, version, DATA))


def test_production_bind_9_20_26_matches_the_isc_matrix():
    # Fixed in 9.20.29 (9.20.28 was withdrawn) and in 9.20.30.
    assert ids("bind", "9.20.26-1~deb13u1") == [
        "CVE-2026-19033",
        "CVE-2026-19630",
        "CVE-2026-19662",
        "CVE-2026-19666",
        "CVE-2026-19667",
        "CVE-2026-19668",
        "CVE-2026-19941",
        "CVE-2026-75029",
        "CVE-2026-76163",
        "CVE-2026-77119",
        "CVE-2026-77692",
        "CVE-2026-78301",
        "CVE-2026-80274",
        "CVE-2026-81563",
        "CVE-2026-81736",
        "CVE-2026-94300",
        "CVE-2026-96888",
        "CVE-2026-97313",
    ]


def test_production_kea_2_6_3():
    assert ids("kea", "2.6.3") == ["CVE-2026-3608"]
    assert ids("kea", "2.6.5") == []
    assert ids("kea", "3.0.1") == ["CVE-2025-11232", "CVE-2026-3608"]


def test_supported_preview_versions_use_their_own_ranges():
    preview = ids("bind", "9.20.10-S1")
    assert "CVE-2025-40776" in preview  # ECS: Supported Preview Edition only
    assert "CVE-2025-40776" not in ids("bind", "9.20.10")
    assert ids("bind", "9.20.30-S1") == []


def _script():
    spec = importlib.util.spec_from_file_location("update_isc_advisories", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ARTICLE = """# CVE-2099-0001: Example flaw

**Program impacted:** [BIND 9](https://www.isc.org/bind/)

**Versions affected:**

BIND

- 9.11.0 -> 9.18.50
- 9.20.0 -> 9.20.29

BIND Supported Preview Edition

- 9.20.9-S1 -> 9.20.29-S1

Versions back to 9.1.0 are believed to be affected.

**Severity:** High

**CVSS Score:** 7.5

**Solution:**

- 9.20.30
- 9.20.30-S1

**Acknowledgments:**

- Someone 1.2.3
"""


def test_update_script_parses_an_advisory():
    entry = _script().parse_advisory("CVE-2099-0001", "bind", ARTICLE, None)
    assert entry["summary"] == "Example flaw" and entry["cvss"] == 7.5
    assert entry["source"] == "https://kb.isc.org/docs/cve-2099-0001"
    assert entry["ranges"] == [
        {"from": "9.11.0", "to": "9.18.50", "fixed": "9.20.30"},
        {"from": "9.20.0", "to": "9.20.29", "fixed": "9.20.30"},
    ]
    assert entry["ranges_preview"] == [{"from": "9.20.9", "to": "9.20.29", "fixed": "9.20.30-S1"}]


ANNOUNCE_JUNE = """From someone at isc.org  Wed Jun 25 15:39:04 2025
Date: Wed, 25 Jun 2025 11:39:04 -0400
Subject: [kea-announce] Kea 3.0.0 is released!

Kea 3.0.0 is a new stable version.
"""
ANNOUNCE_JULY = """From someone at isc.org  Wed Jul 30 12:00:00 2025
Date: Wed, 30 Jul 2025 08:00:00 -0400
Subject: [kea-announce] Kea 2.6.4 and 3.0.1 released

Maintenance of Kea 2.4.2 ended with the release of Kea 3.0.0. Please make plans to update.
"""


def test_update_script_dates_an_ended_series_by_the_release_that_ended_it(monkeypatch):
    mod = _script()
    pages = {"2025-June.txt": ANNOUNCE_JUNE, "2025-July.txt": ANNOUNCE_JULY}
    monkeypatch.setattr(mod, "get_url", lambda url, name, cache: pages.get(url.rsplit("/", 1)[-1], ""))
    out = mod.kea_series({}, None, mod.dt.date(2026, 10, 29))
    assert out["2.4"]["maintained"] is False and out["2.4"]["eol"] == "2025-06-25"
    assert out["2.4"]["successor"] == "3.0" and out["2.4"]["source"].endswith("2025-July.txt")
