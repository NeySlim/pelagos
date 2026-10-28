# SPDX-License-Identifier: Apache-2.0
"""Root hints file: digest of the records only, InterNIC header, staleness."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from pelagos.connectors.bind import hints

pytestmark = pytest.mark.unit

RECORDS = (
    ".                        3600000      NS    A.ROOT-SERVERS.NET.\n"
    "A.ROOT-SERVERS.NET.      3600000      A     198.41.0.4\n"
)


def header(day: str, version: int) -> str:
    return f";       last update:     {day}\n;       related version of root zone:     {version}\n;\n"


def test_digest_ignores_header_comments_case_and_spacing():
    a = hints.parse(header("October 28, 2026", 2026102801) + RECORDS)
    b = hints.parse(
        "; other comment\n" + header("October 27, 2026", 2026102701) + RECORDS.lower().replace("  ", "\t")
    )
    assert a["sha256"] == b["sha256"]
    assert a["related_version"] == 2026102801 and a["last_update"] == "October 28, 2026"
    changed = hints.parse(RECORDS.replace("198.41.0.4", "192.0.2.4"))
    assert changed["sha256"] != a["sha256"] and changed["related_version"] is None


def test_read_reports_errors_as_data(tmp_path):
    path = tmp_path / "root.hints"
    assert hints.read(path)["error"].startswith("FileNotFoundError")
    path.write_text(header("April 18, 2024", 2024041801) + RECORDS)
    info = hints.read(path)
    assert info["error"] is None and info["file"] == str(path) and info["related_version"] == 2024041801


def test_staleness():
    now = datetime(2026, 10, 28, tzinfo=UTC)
    assert hints.staleness({"related_version": 2024041801}, now) is None
    assert hints.staleness({"related_version": 2023051001}, now) == "renumbered"
    assert hints.staleness({"related_version": 2024041801}, datetime(2029, 6, 1, tzinfo=UTC)) == "old"
    assert hints.staleness({"related_version": None}, now) is None
