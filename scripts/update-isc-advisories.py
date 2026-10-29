#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Rebuild backend/pelagos/data/isc_advisories.json from the ISC knowledge base.

Reads the Markdown export of the BIND matrices, the BIND and Kea advisory lists and every
advisory they name (kb.isc.org serves `<page>.md`), and the kea-announce archives for the end of
life of a Kea series ("Kea 2.6 - all versions - are now EOL"). Prints a diff against the shipped
file; `--write` replaces it. Review the diff before committing: the parsing is best effort.
"""

from __future__ import annotations

import argparse
import datetime as dt
import difflib
import email.utils
import json
import re
import sys
import urllib.request
from pathlib import Path

KB = "https://kb.isc.org/docs/"
ANNOUNCE = "https://lists.isc.org/pipermail/kea-announce/"
ANNOUNCE_MONTHS = 24
BIND_MATRICES = ["aa-00913", "bind-9-software-vulnerability-matrix-9-18"]
LISTS = {"bind": "all-bind-advisories", "kea": "all-kea-advisories"}
# Oldest version still worth an entry: older advisories only concern end-of-life branches.
FLOOR = {"bind": (9, 18, 0), "kea": (2, 4, 0)}
TARGET = Path(__file__).resolve().parents[1] / "backend" / "pelagos" / "data" / "isc_advisories.json"

_CVE_LINK = re.compile(r"\[(CVE-\d{4}-\d+)\]\(/docs/([a-z0-9-]+)\)", re.IGNORECASE)
_VERSION = r"\d+\.\d+\.\d+(?:-S\d+)?"
_RANGE = re.compile(rf"({_VERSION})(?:\s*->\s*({_VERSION}))?")
_SEVERITY = re.compile(r"\*\*Severity:\*\*\s*(\w+)", re.IGNORECASE)
_CVSS = re.compile(r"CVSS Score:\**\s*([\d.]+)", re.IGNORECASE)
_POSTED = re.compile(r"\*\*Posting date:\*\*\s*(.+)", re.IGNORECASE)
_PROGRAM = re.compile(r"\*\*Program impacted:\*\*\s*(.+)", re.IGNORECASE)
_TITLE = re.compile(r"^#\s+(.+)$", re.MULTILINE)


def get(page: str, cache: Path | None) -> str:
    """One knowledge base page as Markdown, from `cache` when it holds a copy."""
    if cache is not None and (cache / f"{page}.md").is_file():
        return (cache / f"{page}.md").read_text()
    url = f"{KB}{page}.md"
    req = urllib.request.Request(url, headers={"User-Agent": "pelagos-advisories/1"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        text = resp.read().decode()
    if cache is not None:
        cache.mkdir(parents=True, exist_ok=True)
        (cache / f"{page}.md").write_text(text)
    return text


def get_url(url: str, name: str, cache: Path | None) -> str:
    if cache is not None and (cache / name).is_file():
        return (cache / name).read_text()
    req = urllib.request.Request(url, headers={"User-Agent": "pelagos-advisories/1"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        text = resp.read().decode("utf-8", "replace")
    if cache is not None:
        cache.mkdir(parents=True, exist_ok=True)
        (cache / name).write_text(text)
    return text


_EOL_SUBJECT = re.compile(r"^Subject: \[kea-announce\] Kea (\d+\.\d+)\b.*\bnow EOL", re.MULTILINE)
_OBSOLETED = re.compile(r"release of Kea (\d+\.\d+)\.\d+,? we obsoleted Kea (\d+\.\d+)")
_DATE = re.compile(r"^Date: (.+)$", re.MULTILINE)


def eol_announcements(text: str) -> dict[str, dict]:
    """Series declared end of life in one monthly archive: series -> {"eol","successor"}."""
    out: dict[str, dict] = {}
    for message in re.split(r"\n(?=From \S+ at \S+ )", text):
        subject = _EOL_SUBJECT.search(message)
        if not subject:
            continue
        date = _DATE.search(message)
        eol = None
        if date:
            try:
                eol = email.utils.parsedate_to_datetime(date.group(1)).date().isoformat()
            except (TypeError, ValueError):
                eol = None
        succ = _OBSOLETED.search(message)
        out[subject.group(1)] = {"eol": eol, "successor": succ.group(1) if succ else None}
    return out


def kea_series(current: dict, cache: Path | None, today: dt.date) -> dict:
    """The `series.kea` map: the current one plus every end of life announced over the last
    ANNOUNCE_MONTHS months. A series is only ever added or marked obsolete, never removed."""
    out = {k: dict(v) for k, v in current.items()}
    year, month = today.year, today.month
    for _ in range(ANNOUNCE_MONTHS):
        name = f"{year}-{dt.date(year, month, 1):%B}.txt"
        try:
            text = get_url(ANNOUNCE + name, f"kea-announce-{name}", cache)
        except OSError:
            text = ""
        for series, found in eol_announcements(text).items():
            entry = out.setdefault(series, {})
            if entry.get("maintained") is False and entry.get("eol"):
                continue
            entry.update(
                maintained=False,
                eol=found["eol"],
                successor=found["successor"] or entry.get("successor"),
                source=ANNOUNCE + name,
                checked_at=today.isoformat(),
            )
        month -= 1
        if month == 0:
            year, month = year - 1, 12
    return dict(sorted(out.items(), key=lambda kv: vtuple(kv[0])))


def vtuple(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in v.split("-")[0].split("."))


def section(text: str, header: str) -> list[str]:
    """Lines after `**<header>:**` up to the next bold header, the header line's tail included."""
    out: list[str] = []
    inside = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.lower().startswith(f"**{header.lower()}:**"):
            inside = True
            out.append(stripped[len(header) + 5 :])
            continue
        if inside and stripped.startswith("**"):
            break
        if inside:
            out.append(stripped)
    return out


def affected_ranges(text: str) -> list[tuple[str, str]]:
    """(from, to) pairs of the "Versions affected" section: the header's own line and the list items.
    Prose ("earlier versions are believed affected") and notes in brackets are ignored."""
    pairs = []
    for i, line in enumerate(section(text, "Versions affected")):
        if i and not line.startswith(("-", "*")):
            continue
        line = re.sub(r"\([^)]*\)", "", line)
        if "prior to" in line.lower():
            continue
        for m in _RANGE.finditer(line):
            pairs.append((m.group(1), m.group(2) or m.group(1)))
    return pairs


def solutions(text: str) -> list[str]:
    out = []
    for line in section(text, "Solution"):
        if not line.startswith(("-", "*")):
            continue
        if "upgrade to" in line:
            line = line.split("upgrade to", 1)[1]
        out += [m.group(1) for m in _RANGE.finditer(line)]
    return out


def fixed_for(to: str, fixes: list[str]) -> str | None:
    """The fix of the same branch as `to`, else the oldest later release of the same edition."""
    preview = "-S" in to
    later = sorted(
        (f for f in fixes if ("-S" in f) == preview and vtuple(f) > vtuple(to)),
        key=vtuple,
    )
    same = [f for f in later if vtuple(f)[:2] == vtuple(to)[:2]]
    return (same or later or [None])[0]


def strip_s(v: str) -> str:
    return v.split("-")[0]


def parse_advisory(cve: str, engine: str, text: str, title: str | None) -> dict | None:
    """The data file entry of one advisory, None when it concerns no supported branch."""
    program = _PROGRAM.search(text)
    if program and not re.search(r"\b(bind|kea)\b", program.group(1), re.IGNORECASE):
        return None
    pairs = affected_ranges(text)
    fixes = solutions(text)
    ranges, preview = [], []
    for low, high in pairs:
        r = {"from": strip_s(low), "to": strip_s(high), "fixed": fixed_for(high, fixes)}
        (preview if "-S" in high else ranges).append(r)
    if not any(vtuple(r["to"]) >= FLOOR[engine] for r in ranges + preview):
        return None
    sev = _SEVERITY.search(text)
    cvss = _CVSS.search(text)
    if title is None:
        m = _TITLE.search(text)
        title = m.group(1).split(":", 1)[-1] if m else ""
    entry: dict = {
        "id": cve.upper(),
        "engine": engine,
        "severity": sev.group(1).lower() if sev else "high",
        "cvss": float(cvss.group(1)) if cvss else None,
        "published": None,
        "summary": " ".join(title.split()),
        "url": f"{KB}{cve.lower()}",
        "source": f"{KB}{cve.lower()}",
        "ranges": ranges,
    }
    posted = _POSTED.search(text)
    if posted:
        try:
            entry["published"] = dt.datetime.strptime(posted.group(1).strip(), "%d %B %Y").date().isoformat()
        except ValueError:
            pass
    if preview:
        entry["ranges_preview"] = preview
    return entry


def list_titles(text: str) -> dict[str, str]:
    """CVE id to title, from an advisory list table."""
    out = {}
    for line in text.splitlines():
        m = _CVE_LINK.search(line)
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if m and len(cells) >= 2:
            out[m.group(1).upper()] = cells[1]
    return out


def build(cache: Path | None, verified: str) -> dict:
    found: dict[str, tuple[str, str, str | None]] = {}  # id -> (engine, slug, title)
    for engine, page in LISTS.items():
        text = get(page, cache)
        titles = list_titles(text)
        for m in _CVE_LINK.finditer(text):
            found.setdefault(m.group(1).upper(), (engine, m.group(2), titles.get(m.group(1).upper())))
    for page in BIND_MATRICES:  # the matrices sometimes name advisories the list misses
        for m in _CVE_LINK.finditer(get(page, cache)):
            found.setdefault(m.group(1).upper(), ("bind", m.group(2), None))
    entries = []
    for cve, (engine, slug, title) in found.items():
        if not slug.startswith("cve-"):
            continue  # pre-2019 advisories use aa-NNNNN pages and predate every supported branch
        entry = parse_advisory(cve, engine, get(slug, cache), title)
        if entry is not None:
            entries.append(entry)
    entries.sort(key=lambda e: (e["engine"], e["published"] or "", e["id"]), reverse=True)
    return {
        "schema": 1,
        "verified": verified,
        "sources": [f"{KB}{p}" for p in BIND_MATRICES + list(LISTS.values())],
        "entries": entries,
    }


def render(data: dict) -> str:
    """Indented JSON with one range per line."""
    text = json.dumps(data, indent=2, ensure_ascii=False)
    text = re.sub(
        r'\{\s*("from"[^{}]*?)\s*\}',
        lambda m: "{" + re.sub(r",\s*\n\s*", ", ", m.group(1)) + "}",
        text,
    )
    return text + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--file", type=Path, default=TARGET, help="data file to compare with or replace")
    ap.add_argument(
        "--cache",
        type=Path,
        help="directory keeping the fetched pages (reused when present)",
    )
    ap.add_argument(
        "--write",
        action="store_true",
        help="replace the file instead of printing a diff",
    )
    args = ap.parse_args()
    current = json.loads(args.file.read_text())
    today = dt.date.today().isoformat()
    built = build(args.cache, today)
    data = {k: v for k, v in current.items() if k != "entries"}
    data.update({"verified": today, "updated": today, "sources": built["sources"]})
    current_kea = (current.get("series") or {}).get("kea") or {}
    series = kea_series(current_kea, args.cache, dt.date.fromisoformat(today))
    data.pop("series", None)
    data["series"] = {**(current.get("series") or {}), "kea": series}
    if built["entries"] != current.get("entries") or series != current_kea:
        data["revision"] = int(current.get("revision", 0)) + 1
    data["entries"] = built["entries"]
    old, new = render(current), render(data)
    if args.write:
        args.file.write_text(new)
        print(f"{args.file}: {len(data['entries'])} entries, revision {data.get('revision')}")
        return 0
    sys.stdout.writelines(difflib.unified_diff(old.splitlines(True), new.splitlines(True), "current", "isc"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
