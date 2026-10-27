# SPDX-License-Identifier: Apache-2.0
"""Item 37: distribution packages of BIND and Kea against the distribution's security data.

Debian: `dpkg-query` and `apt-cache policy` give the installed and candidate package versions, the
Debian security tracker says in which package version each CVE is fixed. Its JSON
(https://security-tracker.debian.org/tracker/data/json, format checked 2026-10-27) is one object
{source package: {CVE id: {"releases": {codename: {"status", "fixed_version", "repositories"}}}}}, about
14 MB gzipped: only the BIND and Kea source packages are kept, in the node's var directory.
RPM distributions: `dnf -C updateinfo list --with-cve --all` (local metadata cache, dnf 4) lists the
CVE fixes installed (`i`) or available for the packages. A CVE it does not list stays unknown.
"""

from __future__ import annotations

import gzip
import json
import logging
import re
import shutil
import subprocess
import urllib.request
import zlib
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pelagos.collector.checks.versions import version_tuple
from pelagos.domain import Engine

log = logging.getLogger(__name__)

DEBIAN_TRACKER_URL = "https://security-tracker.debian.org/tracker/data/json"
TRACKER_NAME = "debian_security_tracker.json"
TRACKER_SOURCES = ("bind9", "isc-kea")
MAX_TRACKER_BYTES = 400_000_000
DEB_PACKAGES = {Engine.BIND: "bind9", Engine.KEA4: "kea-dhcp4-server", Engine.KEA6: "kea-dhcp6-server"}
RPM_PACKAGES = {Engine.BIND: "bind", Engine.KEA4: "kea", Engine.KEA6: "kea"}
_DEBIAN_BUILD = re.compile(r"[~+](?:deb|bpo)\d")

# Verdict of one CVE for the installed package.
FIXED = "fixed"  # the installed package carries the fix
UPDATE = "update"  # a package with the fix is available: update the package
OPEN = "open"  # the distribution has no fix in the installed or the candidate version
UNKNOWN = "unknown"  # no distribution data for this CVE: upstream versions only

Runner = Callable[[list[str]], str | None]


@dataclass
class Package:
    manager: str  # "deb" or "rpm"
    name: str
    source: str
    installed: str
    candidate: str | None = None
    release: str | None = None  # Debian codename
    distribution_build: bool = True
    # RPM: CVE id -> (FIXED or UPDATE, package NEVRA of the advisory), from dnf updateinfo.
    rpm_cves: dict[str, tuple[str, str]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        out = asdict(self)
        out.pop("rpm_cves")
        return out


def run_command(argv: list[str], timeout: float = 60.0) -> str | None:
    """stdout of a read-only package query, None when the tool is missing or fails."""
    if shutil.which(argv[0]) is None:
        return None
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    return proc.stdout if proc.returncode == 0 else None


# Debian version comparison (dpkg's verrevcmp) ---------------------------------------------------


def _order(c: str) -> int:
    if not c or c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    if c == "~":
        return -1
    return ord(c) + 256


def _verrevcmp(a: str, b: str) -> int:
    i = j = 0
    while i < len(a) or j < len(b):
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _order(a[i] if i < len(a) else "")
            bc = _order(b[j] if j < len(b) else "")
            if ac != bc:
                return ac - bc
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        first = 0
        while i < len(a) and j < len(b) and a[i].isdigit() and b[j].isdigit():
            first = first or (ord(a[i]) - ord(b[j]))
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first:
            return first
    return 0


def _split(version: str) -> tuple[int, str, str]:
    epoch, _, rest = version.strip().partition(":") if ":" in version else ("0", "", version.strip())
    upstream, _, revision = rest.rpartition("-") if "-" in rest else (rest, "", "")
    return int(epoch or 0), upstream, revision


def deb_compare(a: str, b: str) -> int:
    """Sign of a - b in Debian version order (epoch, upstream, revision; `~` sorts first)."""
    ea, ua, ra = _split(a)
    eb, ub, rb = _split(b)
    if ea != eb:
        return 1 if ea > eb else -1
    c = _verrevcmp(ua, ub) or _verrevcmp(ra, rb)
    return (c > 0) - (c < 0)


def upstream_of(version: str | None) -> tuple[int, ...] | None:
    """Upstream release of a package version ("1:9.20.30-1~deb13u1" gives (9, 20, 30))."""
    if not version:
        return None
    return version_tuple(version.split(":", 1)[-1])


# Reading the installed packages ------------------------------------------------------------------


def os_codename(path: Path = Path("/etc/os-release")) -> str | None:
    try:
        for line in path.read_text().splitlines():
            if line.startswith("VERSION_CODENAME="):
                return line.partition("=")[2].strip().strip('"') or None
    except OSError:
        pass
    return None


def parse_apt_policy(text: str) -> tuple[str | None, str | None]:
    """(installed, candidate) of one package in `apt-cache policy <package>`."""
    found: dict[str, str | None] = {"Installed": None, "Candidate": None}
    for line in text.splitlines():
        key, _, value = line.strip().partition(":")
        if key in found and found[key] is None:
            value = value.strip()
            found[key] = None if value in ("", "(none)") else value
    return found["Installed"], found["Candidate"]


def read_deb(engine: Engine, run: Runner = run_command, codename: str | None = None) -> Package | None:
    name = DEB_PACKAGES.get(engine)
    if name is None:
        return None
    out = run(["dpkg-query", "-W", "-f=${db:Status-Abbrev}\t${source:Package}\t${Version}\n", name])
    if not out:
        return None
    status, _, rest = out.strip("\n").partition("\t")
    source, _, version = rest.partition("\t")
    if not status.startswith("ii") or not version:
        return None
    policy = run(["apt-cache", "policy", name]) or ""
    installed, candidate = parse_apt_policy(policy)
    return Package(
        manager="deb",
        name=name,
        source=source or name,
        installed=installed or version,
        candidate=candidate,
        release=codename if codename is not None else os_codename(),
        distribution_build=bool(_DEBIAN_BUILD.search(version)),
    )


def parse_updateinfo(text: str, name: str) -> dict[str, tuple[str, str]]:
    """CVE -> (FIXED or UPDATE, NEVRA) for package `name` in `dnf updateinfo list --with-cve --all`."""
    out: dict[str, tuple[str, str]] = {}
    for line in text.splitlines():
        parts = line.split()
        installed = bool(parts) and parts[0] == "i"
        if installed:
            parts = parts[1:]
        if len(parts) < 3 or not parts[0].startswith("CVE-"):
            continue
        nevra = parts[-1]
        if nevra.rsplit("-", 2)[0] != name:
            continue
        verdict = FIXED if installed else UPDATE
        if out.get(parts[0], (None,))[0] != FIXED:
            out[parts[0]] = (verdict, nevra)
    return out


def read_rpm(engine: Engine, run: Runner = run_command) -> Package | None:
    name = RPM_PACKAGES.get(engine)
    if name is None:
        return None
    out = run(["rpm", "-q", "--qf", "%{EPOCH}:%{VERSION}-%{RELEASE}\n", name])
    if not out or not out.strip():
        return None
    version = out.strip().splitlines()[0].replace("(none):", "")
    info = run(["dnf", "-q", "-C", "updateinfo", "list", "--with-cve", "--all"]) or ""
    cves = parse_updateinfo(info, name)
    updates = [nevra for verdict, nevra in cves.values() if verdict == UPDATE]
    return Package(
        manager="rpm",
        name=name,
        source=name,
        installed=version,
        candidate=max(updates) if updates else None,
        rpm_cves=cves,
    )


def read_package(engine: Engine, run: Runner = run_command) -> Package | None:
    """The distribution package that provides the daemon, None outside a package install."""
    return read_deb(engine, run) or read_rpm(engine, run)


# The Debian security tracker ---------------------------------------------------------------------


def extract_sources(chunks: Iterable[bytes], names: Iterable[str]) -> dict[str, Any]:
    """The objects of the given top-level keys of the tracker JSON, read as a stream: the whole
    document (about 90 MB) is never held in memory. Inside JSON strings quotes are escaped, so the
    marker `"<name>":{` only matches a key."""
    wanted = {f'"{n}":{{': n for n in names}
    longest = max(len(m) for m in wanted)
    found: dict[str, Any] = {}
    decoder = json.JSONDecoder()
    buf = ""
    capture: str | None = None
    for chunk in chunks:
        buf += chunk.decode("utf-8", errors="replace")
        while True:
            if capture is None:
                hits = [(buf.find(m), m) for m in wanted if wanted[m] not in found]
                hits = [h for h in hits if h[0] >= 0]
                if not hits:
                    buf = buf[-longest:]
                    break
                pos, marker = min(hits)
                capture = wanted[marker]
                buf = buf[pos + len(marker) - 1 :]
            try:
                obj, end = decoder.raw_decode(buf)
            except ValueError:
                break  # object not complete yet: wait for more data
            found[capture] = obj
            capture = None
            buf = buf[end:]
        if len(found) == len(wanted):
            break
    return found


def trim(entries: dict[str, Any]) -> dict[str, Any]:
    """Keep status and fixed_version per release, and the repository versions (the Debian builds)."""
    out: dict[str, Any] = {}
    for source, cves in entries.items():
        kept: dict[str, Any] = {}
        for cve, info in (cves or {}).items():
            releases = {}
            for rel, r in ((info or {}).get("releases") or {}).items():
                releases[rel] = {
                    "status": r.get("status"),
                    "fixed_version": r.get("fixed_version"),
                    "repositories": r.get("repositories") or {},
                }
            kept[cve] = releases
        out[source] = kept
    return out


def _gunzip_stream(resp: Any, limit: int) -> Iterable[bytes]:
    gz = resp.headers.get("Content-Encoding", "") == "gzip"
    inflate = zlib.decompressobj(16 + zlib.MAX_WBITS) if gz else None
    total = 0
    while True:
        raw = resp.read(1 << 20)
        if not raw:
            break
        data = inflate.decompress(raw) if inflate else raw
        total += len(data)
        if total > limit:
            raise ValueError("tracker data too large")
        yield data


def fetch_debian_tracker(url: str, var_dir: Path, timeout: float = 60.0) -> bool:
    """Download the tracker (https only) and keep the BIND and Kea entries in `var_dir`."""
    if not url.startswith("https://"):
        return False
    req = urllib.request.Request(url, headers={"Accept-Encoding": "gzip"})  # noqa: S310 (https checked)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (https checked above)
            entries = extract_sources(_gunzip_stream(resp, MAX_TRACKER_BYTES), TRACKER_SOURCES)
            modified = resp.headers.get("Last-Modified")
    except (OSError, ValueError, zlib.error, gzip.BadGzipFile) as exc:
        log.warning("Debian security tracker not fetched: %s", exc)
        return False
    if not entries:
        log.warning("Debian security tracker from %s has no BIND or Kea entry", url)
        return False
    body = {
        "schema": 1,
        "source": url,
        "fetched": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "last_modified": modified,
        "packages": trim(entries),
    }
    target = var_dir / TRACKER_NAME
    tmp = target.with_suffix(".tmp")
    tmp.write_text(json.dumps(body, separators=(",", ":")))
    tmp.replace(target)
    return True


def load_tracker(var_dir: Path) -> dict[str, Any] | None:
    try:
        data = json.loads((var_dir / TRACKER_NAME).read_text())
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or data.get("schema") != 1 or not isinstance(data.get("packages"), dict):
        return None
    return data


# Verdicts ----------------------------------------------------------------------------------------


def _debian_build(pkg: Package, entries: dict[str, Any]) -> bool:
    """A Debian build: its revision says so, or the tracker lists this version in a repository."""
    if pkg.distribution_build:
        return True
    for releases in entries.values():
        if pkg.installed in ((releases.get(pkg.release or "") or {}).get("repositories") or {}).values():
            return True
    return False


def verdicts(
    cves: Iterable[str], pkg: Package | None, tracker: dict[str, Any] | None
) -> tuple[dict[str, dict[str, Any]], str | None]:
    """Per CVE {"status": FIXED/UPDATE/OPEN/UNKNOWN, "fixed_version"?}, and why the distribution data
    does not apply when it does not (None when it does)."""
    ids = list(cves)
    unknown = {c: {"status": UNKNOWN} for c in ids}
    if pkg is None:
        return unknown, "no_package"
    if pkg.manager == "rpm":
        out: dict[str, dict[str, Any]] = {}
        for c in ids:
            verdict, nevra = pkg.rpm_cves.get(c, (UNKNOWN, None))
            out[c] = {"status": verdict, **({"package": nevra} if nevra else {})}
        return out, None
    if tracker is None:
        return unknown, "no_tracker"
    entries = (tracker.get("packages") or {}).get(pkg.source)
    if entries is None or not pkg.release:
        return unknown, "no_tracker"
    if not _debian_build(pkg, entries):
        return unknown, "not_distribution_build"
    out = {}
    for c in ids:
        rel = (entries.get(c) or {}).get(pkg.release)
        if not rel:
            out[c] = {"status": UNKNOWN}
            continue
        fixed = rel.get("fixed_version")
        if rel.get("status") != "resolved" or not fixed:
            out[c] = {"status": OPEN}
        elif fixed == "0" or deb_compare(pkg.installed, fixed) >= 0:
            out[c] = {"status": FIXED, "fixed_version": fixed}
        elif pkg.candidate and deb_compare(pkg.candidate, fixed) >= 0:
            out[c] = {"status": UPDATE, "fixed_version": fixed}
        else:
            out[c] = {"status": OPEN, "fixed_version": fixed}
    return out, None
