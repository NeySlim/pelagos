# SPDX-License-Identifier: Apache-2.0
"""Item 37: one advisory alert per engine, and the distribution's own fixes (Debian tracker, dnf)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pelagos.collector.checks import advisories, distro
from pelagos.domain import Engine, Severity

pytestmark = pytest.mark.unit

EXCERPT = Path(__file__).parent / "data" / "debian_tracker_excerpt.json"
DATA = advisories.load()


def tracker(tmp_path: Path) -> dict:
    """The excerpt (real tracker entries of 2026-10-27) through the streaming extractor."""
    raw = EXCERPT.read_bytes()
    chunks = [raw[i : i + 97] for i in range(0, len(raw), 97)]
    entries = distro.extract_sources(chunks, distro.TRACKER_SOURCES)
    body = {"schema": 1, "source": distro.DEBIAN_TRACKER_URL, "packages": distro.trim(entries)}
    (tmp_path / distro.TRACKER_NAME).write_text(json.dumps(body))
    return distro.load_tracker(tmp_path)


def deb(name: str, source: str, installed: str, candidate: str | None = None) -> distro.Package:
    return distro.Package(
        manager="deb",
        name=name,
        source=source,
        installed=installed,
        candidate=candidate or installed,
        release="trixie",
        distribution_build=True,
    )


@pytest.mark.parametrize(
    ("a", "b", "sign"),
    [
        ("1:9.20.26-1~deb13u1", "1:9.20.30-1~deb13u1", -1),
        ("1:9.20.30-1~deb13u1", "1:9.20.29-1~deb13u1", 1),
        ("9.20.30-1", "1:9.20.26-1~deb13u1", -1),
        ("2.6.3-1+deb13u1", "2.6.3-1", 1),
        ("2.6.3-1~bpo13+1", "2.6.3-1", -1),
        ("2.6.3~rc1", "2.6.3", -1),
        ("2.6.10-1", "2.6.9-1", 1),
        ("1.0-1.10", "1.0-1.2", 1),
        ("0:1.0", "1.0", 0),
    ],
)
def test_debian_version_order_matches_dpkg(a, b, sign):
    # Expectations checked with `dpkg --compare-versions` on Debian 13.
    assert distro.deb_compare(a, b) == sign


def test_extractor_reads_only_the_wanted_keys_and_ignores_quoted_text(tmp_path):
    raw = EXCERPT.read_bytes()
    found = distro.extract_sources([raw[i : i + 13] for i in range(0, len(raw), 13)], ["bind9", "isc-kea"])
    assert set(found) == {"bind9", "isc-kea"}
    assert set(found["bind9"]) == {"CVE-2026-19033", "CVE-2026-94300", "CVE-2026-97313"}
    trixie = distro.trim(found)["isc-kea"]["CVE-2026-3608"]["trixie"]
    assert trixie["status"] == "resolved" and trixie["fixed_version"] == "2.6.3-1+deb13u1"


def test_kea_2_6_3_debian_package_carries_the_cve_2026_3608_fix(tmp_path):
    # https://security-tracker.debian.org/tracker/CVE-2026-3608: fixed for trixie in 2.6.3-1+deb13u1.
    pkg = deb("kea-dhcp4-server", "isc-kea", "2.6.3-1+deb13u1")
    assert (
        advisories.advisory_alerts("n1", {Engine.KEA4: "2.6.3"}, DATA, {Engine.KEA4: pkg}, tracker(tmp_path))
        == []
    )
    entries, reason = advisories.engine_advisories(Engine.KEA4, "2.6.3", DATA, pkg, tracker(tmp_path))
    assert reason is None and [(e["id"], e["status"]) for e in entries] == [("CVE-2026-3608", "fixed")]


def test_bind_9_20_26_with_9_20_30_candidate_asks_for_the_package_update(tmp_path):
    pkg = deb("bind9", "bind9", "1:9.20.26-1~deb13u1", "1:9.20.30-1~deb13u1")
    alerts = advisories.advisory_alerts(
        "n1", {Engine.BIND: "9.20.26"}, DATA, {Engine.BIND: pkg}, tracker(tmp_path)
    )
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.subject == "bind:advisories"
    # The excerpt lacks 15 of the CVEs (unknown), the 3 it has are fixed in the candidate.
    assert alert.title_message["key"] == "alert.security_advisories_update"
    status = {c["cve"]: c["status"] for c in alert.details["cves"]}
    assert len(status) == 18
    assert status["CVE-2026-94300"] == "update" and status["CVE-2026-19033"] == "update"
    assert status["CVE-2026-81736"] == "unknown"
    assert alert.details["package"]["candidate"] == "1:9.20.30-1~deb13u1"
    assert alert.details["distribution_data"]["name"] == "Debian security tracker"


def test_only_updates_left_gives_the_update_title(tmp_path):
    data = {
        **DATA,
        "entries": [e for e in DATA["entries"] if e["id"] in ("CVE-2026-19033", "CVE-2026-94300")],
    }
    old = deb("bind9", "bind9", "1:9.20.26-1~deb13u1", "1:9.20.30-1~deb13u1")
    (alert,) = advisories.advisory_alerts(
        "n1", {Engine.BIND: "9.20.26"}, data, {Engine.BIND: old}, tracker(tmp_path)
    )
    assert alert.title_message["key"] == "alert.security_advisories_update"
    assert alert.title_message["params"]["candidate"] == "1:9.20.30-1~deb13u1"
    assert "update the package bind9" in alert.title


def test_one_alert_per_engine_with_the_list_and_the_worst_severity():
    alerts = advisories.advisory_alerts("n1", {Engine.BIND: "9.20.26", Engine.KEA4: "2.6.3"}, DATA)
    assert sorted(a.subject for a in alerts) == ["bind:advisories", "kea4:advisories"]
    bind = next(a for a in alerts if a.engine is Engine.BIND)
    assert bind.details["cves"][0]["url"].startswith("https://kb.isc.org/docs/cve-")
    assert len(bind.details["cves"]) == 18 and bind.title_message["params"]["count"] == 18
    assert bind.title_message["key"] == "alert.security_advisories_upstream"
    assert bind.details["distribution_data"]["reason"] == "no_package"
    assert "security tracker" in bind.details["note"]
    worst = {
        advisories.SEVERITIES[e["severity"]]
        for e in DATA["entries"]
        if e["id"] in {c["cve"] for c in bind.details["cves"]}
    }
    assert bind.severity is (Severity.CRITICAL if Severity.CRITICAL in worst else Severity.WARNING)


def test_no_tracker_or_foreign_build_falls_back_to_upstream_labelled(tmp_path):
    pkg = deb("kea-dhcp4-server", "isc-kea", "2.6.3-1+deb13u1")
    (alert,) = advisories.advisory_alerts("n1", {Engine.KEA4: "2.6.3"}, DATA, {Engine.KEA4: pkg}, None)
    assert alert.details["distribution_data"] == {"name": None, "reason": "no_tracker"}
    assert alert.title_message["key"] == "alert.security_advisories_upstream"
    isc = distro.Package(
        "deb", "isc-kea-dhcp4", "isc-kea", "2.6.3-isc20250701", release="trixie", distribution_build=False
    )
    _, reason = distro.verdicts(["CVE-2026-3608"], isc, tracker(tmp_path))
    assert reason == "not_distribution_build"


def test_daemon_not_restarted_after_the_upgrade_gets_no_credit(tmp_path):
    pkg = deb("kea-dhcp4-server", "isc-kea", "2.6.3-1+deb13u1")
    (alert,) = advisories.advisory_alerts(
        "n1", {Engine.KEA4: "2.6.2"}, DATA, {Engine.KEA4: pkg}, tracker(tmp_path)
    )
    assert alert.details["distribution_data"]["reason"] == "package_differs"


DPKG = "ii \tbind9\t1:9.20.26-1~deb13u1\n"
POLICY = """bind9:
  Installed: 1:9.20.26-1~deb13u1
  Candidate: 1:9.20.30-1~deb13u1
  Version table:
     1:9.20.30-1~deb13u1 500
        500 http://deb.debian.org/debian-security trixie-security/main amd64 Packages
 *** 1:9.20.26-1~deb13u1 500
        500 http://deb.debian.org/debian trixie/main amd64 Packages
        100 /var/lib/dpkg/status
"""


def test_read_debian_package_from_dpkg_and_apt_policy():
    calls = []

    def run(argv):
        calls.append(argv[0])
        return {"dpkg-query": DPKG, "apt-cache": POLICY}.get(argv[0])

    pkg = distro.read_deb(Engine.BIND, run, codename="trixie")
    assert (pkg.name, pkg.source, pkg.installed, pkg.candidate) == (
        "bind9",
        "bind9",
        "1:9.20.26-1~deb13u1",
        "1:9.20.30-1~deb13u1",
    )
    assert pkg.distribution_build and calls == ["dpkg-query", "apt-cache"]
    assert distro.read_deb(Engine.KEA6, lambda argv: "un \tkea-dhcp6-server\t\n", codename="trixie") is None


# `dnf -q -C updateinfo list --with-cve --all` on Rocky Linux 10.2 (2026-10-27), shortened.
UPDATEINFO = """i CVE-2025-40778  Important/Sec. bind-32:9.18.33-10.el10_1.2.x86_64
i RLSA-2025:21034 Important/Sec. bind-32:9.18.33-10.el10_1.2.x86_64
i CVE-2026-1519   Important/Sec. bind-utils-32:9.18.33-10.el10_1.3.x86_64
  CVE-2026-13204  Important/Sec. bind-32:9.18.33-15.el10_2.14.x86_64
i CVE-2025-9615   Low/Sec.       NetworkManager-1:1.56.0-1.el10.x86_64
"""


def test_rpm_cves_from_dnf_updateinfo():
    def run(argv):
        return {"rpm": "32:9.18.33-15.el10_2.12\n", "dnf": UPDATEINFO}.get(argv[0])

    pkg = distro.read_rpm(Engine.BIND, run)
    assert pkg.installed == "32:9.18.33-15.el10_2.12"
    assert pkg.rpm_cves == {
        "CVE-2025-40778": ("fixed", "bind-32:9.18.33-10.el10_1.2.x86_64"),
        "CVE-2026-13204": ("update", "bind-32:9.18.33-15.el10_2.14.x86_64"),
    }
    found, reason = distro.verdicts(["CVE-2025-40778", "CVE-2026-13204", "CVE-2026-1"], pkg, None)
    assert reason is None
    assert [v["status"] for v in found.values()] == ["fixed", "update", "unknown"]


def test_fetch_refuses_plain_http(tmp_path):
    assert distro.fetch_debian_tracker("http://example.lan/json", tmp_path) is False
    assert distro.load_tracker(tmp_path) is None
