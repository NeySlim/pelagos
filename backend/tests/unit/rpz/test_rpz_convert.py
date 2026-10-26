# SPDX-License-Identifier: Apache-2.0
"""List converters on small fixtures: every output is accepted by named-checkzone."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from pelagos.rpz import convert as conv

pytestmark = pytest.mark.unit
DATA = Path(__file__).parent / "data"


def checkzone(tmp_path: Path, text: str) -> subprocess.CompletedProcess[str]:
    path = tmp_path / "z.db"
    path.write_text(text)
    return subprocess.run(
        ["named-checkzone", "-q", "-k", "ignore", "list.rpz.invalid", str(path)],
        capture_output=True,
        text=True,
        check=False,
    )


def domains(result: conv.Converted) -> list[str]:
    return result.domains


@pytest.mark.parametrize(
    ("name", "fmt", "expected"),
    [
        ("native.rpz", "rpz", ["ads.example.com", "tracker.example.net"]),
        (
            "hosts.txt",
            "hosts",
            [
                "a.example.com",
                "ads.example.com",
                "b.example.com",
                "metrics.example.net",
                "not-a-block.example.org",
            ],
        ),
        ("domains.txt", "domains", ["phish.example.org", "upper.example.com", "wild.example.org"]),
        ("adblock.txt", "adblock", ["ads.example.com", "cdn.example.org", "tracker.example.net"]),
    ],
)
def test_each_format_gives_a_valid_zone(tmp_path: Path, name: str, fmt: str, expected: list[str]) -> None:
    result = conv.convert((DATA / name).read_text(), fmt, 2026102601, keep_domains=True)
    assert domains(result) == expected
    assert result.entries == len(expected)
    assert checkzone(tmp_path, result.text).returncode == 0
    for d in expected:
        assert f"{d} CNAME ." in result.text and f"*.{d} CNAME ." in result.text


def test_native_rpz_keeps_only_qname_blocks() -> None:
    result = conv.convert((DATA / "native.rpz").read_text(), "rpz", 1, keep_domains=True)
    # The passthru rule and the covered subdomain are not blocks of their own.
    assert "ok.example.org" not in result.text and "sub.tracker.example.net" not in result.text


def test_hosts_skips_loopback_entries_and_counts_junk() -> None:
    result = conv.convert((DATA / "hosts.txt").read_text(), "hosts", 1)
    assert "localhost CNAME" not in result.text and "ip6-localhost" not in result.text
    assert result.skipped >= 1


def test_adblock_ignores_exceptions_cosmetics_and_narrow_rules() -> None:
    result = conv.convert((DATA / "adblock.txt").read_text(), "adblock", 1, keep_domains=True)
    assert "ok.example.com" not in result.text and "img.example.org" not in result.text
    assert "path.example.com" not in result.text and "wild" not in result.text


def test_redirect_to_ip_writes_address_records(tmp_path: Path) -> None:
    result = conv.convert("ads.example.com\n", "domains", 1, redirect_ip="192.0.2.80")
    assert "ads.example.com A 192.0.2.80" in result.text and "*.ads.example.com A 192.0.2.80" in result.text
    assert checkzone(tmp_path, result.text).returncode == 0
    v6 = conv.convert("ads.example.com\n", "domains", 1, redirect_ip="2001:db8::80")
    assert "ads.example.com AAAA 2001:db8::80" in v6.text
    with pytest.raises(ValueError):
        conv.convert("ads.example.com\n", "domains", 1, redirect_ip="not an ip")


def test_html_error_page_is_not_a_native_rpz() -> None:
    with pytest.raises(conv.ConvertError):
        conv.convert("<html>\n<body>Service unavailable</body>\n</html>\n", "rpz", 1)


def test_idn_names_are_encoded_and_bad_names_dropped() -> None:
    result = conv.convert("bücher.example\nbad!name.example\n-x.example\n", "domains", 1, keep_domains=True)
    assert domains(result) == ["xn--bcher-kva.example"]


def test_detect_format() -> None:
    assert conv.detect_format((DATA / "native.rpz").read_text()) == "rpz"
    assert conv.detect_format((DATA / "hosts.txt").read_text()) == "hosts"
    assert conv.detect_format((DATA / "adblock.txt").read_text()) == "adblock"
    assert conv.detect_format((DATA / "domains.txt").read_text()) == "domains"
    assert conv.detect_format("") == "domains"


def test_allow_zone_has_passthru_names_and_client_triggers(tmp_path: Path) -> None:
    text = conv.allow_zone_text(["ok.example.com"], ["192.0.2.0/24", "192.0.2.7", "2001:db8::/32"], 7)
    assert "ok.example.com CNAME rpz-passthru." in text
    assert "24.0.2.0.192.rpz-client-ip CNAME rpz-passthru." in text
    assert "32.7.2.0.192.rpz-client-ip CNAME rpz-passthru." in text
    assert "32.db8.2001.rpz-client-ip CNAME rpz-passthru." in text
    assert checkzone(tmp_path, text).returncode == 0


def test_client_ip_owner_forms() -> None:
    assert conv.client_ip_owner("192.0.2.7") == "32.7.2.0.192.rpz-client-ip"
    assert conv.client_ip_owner("10.0.0.0/8") == "8.0.0.0.10.rpz-client-ip"
    assert conv.client_ip_owner("2001:db8::1") == "128.1.zz.db8.2001.rpz-client-ip"


def test_count_rules_matches_entries() -> None:
    result = conv.convert((DATA / "domains.txt").read_text(), "domains", 1)
    assert conv.count_rules(result.text) == result.entries


def test_native_wildcard_only_rule_is_read_as_a_rule_for_the_name() -> None:
    text = (
        "$TTL 300\n@ IN SOA ns.example.lan. h.example.lan. 1 3600 600 86400 300\n"
        "*.only-wild.example.net CNAME .\nok.example.org CNAME rpz-passthru.\n"
    )
    result = conv.convert(text, "rpz", 1, keep_domains=True)
    assert result.entries == 1 and "only-wild.example.net CNAME ." in result.text
    assert result.skipped == 1  # the passthru rule is counted, not dropped silently
