# SPDX-License-Identifier: Apache-2.0
"""Item 28: ISC security advisories against the installed BIND and Kea versions.

The data is a versioned file (pelagos/data/isc_advisories.json). A newer copy in the node's var
directory (placed by hand or fetched when settings.checks.advisories_fetch_enabled is on) wins over it.
Versions are compared as upstream versions; distribution backports come from distro.py (item 37). The
data is rebuilt from kb.isc.org by scripts/update-isc-advisories.py.
Subject: `<engine>:advisories` (kind security_advisory), one alert per engine with the CVE list.
"""

from __future__ import annotations

import json
import logging
import re
import urllib.request
from pathlib import Path
from typing import Any

from pelagos.collector.checks import distro
from pelagos.collector.checks.versions import version_tuple
from pelagos.domain import Alert, AlertKind, Engine, Severity, messages

log = logging.getLogger(__name__)

PACKAGED = Path(__file__).resolve().parents[2] / "data" / "isc_advisories.json"
OVERRIDE_NAME = "isc_advisories.json"
MAX_BYTES = 2_000_000
_PREVIEW = re.compile(r"\s*(?:BIND\s+)?\d+(?:\.\d+)*-S\d")
SEVERITIES = {
    "critical": Severity.CRITICAL,
    "high": Severity.WARNING,
    "medium": Severity.WARNING,
    "low": Severity.INFO,
}


def valid(data: Any) -> bool:
    if not isinstance(data, dict) or data.get("schema") != 1 or not isinstance(data.get("entries"), list):
        return False
    for e in data["entries"]:
        if not isinstance(e, dict) or e.get("engine") not in ("bind", "kea") or not e.get("id"):
            return False
        for r in (e.get("ranges") or []) + (e.get("ranges_preview") or []):
            if version_tuple(r.get("from")) is None or version_tuple(r.get("to")) is None:
                return False
    return True


def _rank(data: dict[str, Any]) -> tuple[int, str]:
    """Order of two datasets: the `revision` counter first, the `updated` date as a tie-break."""
    rev = data.get("revision")
    return (rev if isinstance(rev, int) else 0, str(data.get("updated", "")))


def load(var_dir: Path | None = None, packaged: Path = PACKAGED) -> dict[str, Any]:
    """The packaged data, or the override in `var_dir` when it is valid and not older (by revision)."""
    data = json.loads(packaged.read_text())
    if var_dir is not None:
        try:
            other = json.loads((var_dir / OVERRIDE_NAME).read_text())
        except (OSError, ValueError):
            return data
        if valid(other) and _rank(other) >= _rank(data):
            return other
    return data


def affected(engine: str, version: str | None, data: dict[str, Any]) -> list[dict[str, Any]]:
    """Entries of `engine` ("bind" or "kea") whose upstream ranges contain `version`. A BIND
    Supported Preview Edition version ("9.20.11-S1") is matched against `ranges_preview` only."""
    current = version_tuple(version)
    if current is None:
        return []
    key = "ranges_preview" if _PREVIEW.match(version or "") else "ranges"
    out = []
    for entry in data.get("entries", []):
        if entry["engine"] != engine:
            continue
        for r in entry.get(key) or []:
            if version_tuple(r["from"]) <= current <= version_tuple(r["to"]):  # type: ignore[operator]
                out.append({**entry, "fixed": r.get("fixed")})
                break
    return out


_RANK = {Severity.INFO: 0, Severity.WARNING: 1, Severity.CRITICAL: 2}
NOTE_UPSTREAM = (
    "Upstream version check: distribution packages may carry the fix without changing the version, "
    "check your distribution's security tracker."
)


def _short(ids: list[str]) -> str:
    return ", ".join(ids[:3]) + (f" +{len(ids) - 3}" if len(ids) > 3 else "")


def engine_advisories(
    engine: Engine,
    version: str | None,
    data: dict[str, Any],
    pkg: distro.Package | None = None,
    tracker: dict[str, Any] | None = None,
) -> tuple[list[dict[str, Any]], str | None]:
    """The ISC entries that match `version`, each with its distribution verdict (`status`), and why
    the distribution data does not apply (None when it does)."""
    family = "bind" if engine is Engine.BIND else "kea"
    entries = affected(family, version, data)
    if pkg is not None and distro.upstream_of(pkg.installed) != version_tuple(version):
        # The running daemon is not the installed package (not restarted yet, or built elsewhere).
        found, reason = {e["id"]: {"status": distro.UNKNOWN} for e in entries}, "package_differs"
    else:
        found, reason = distro.verdicts([e["id"] for e in entries], pkg, tracker)
    return [{**e, **found[e["id"]]} for e in entries], reason


def _cve_details(e: dict[str, Any]) -> dict[str, Any]:
    out = {
        "cve": e["id"],
        "status": e["status"],
        "severity": e.get("severity"),
        "cvss": e.get("cvss"),
        "summary": e.get("summary", ""),
        "fixed_in": e.get("fixed"),
        "url": e.get("source") or e.get("url"),
    }
    if e.get("fixed_version"):
        out["distribution_fixed_version"] = e["fixed_version"]
    if e.get("package"):
        out["distribution_package"] = e["package"]
    return out


def _source(pkg: distro.Package | None, tracker: dict[str, Any] | None, reason: str | None) -> dict[str, Any]:
    if reason is not None or pkg is None:
        return {"name": None, "reason": reason}
    if pkg.manager == "rpm":
        return {"name": "dnf updateinfo"}
    return {
        "name": "Debian security tracker",
        "url": (tracker or {}).get("source"),
        "fetched": (tracker or {}).get("fetched"),
    }


def advisory_alerts(
    node_id: str,
    installed: dict[Engine, str | None],
    data: dict[str, Any],
    packages: dict[Engine, distro.Package | None] | None = None,
    tracker: dict[str, Any] | None = None,
) -> list[Alert]:
    """One alert per engine with the CVEs that still apply. A CVE the distribution package fixes
    is listed under `fixed_by_distribution` and raises nothing on its own."""
    out: list[Alert] = []
    dataset = data.get("verified") or data.get("updated") or "?"
    for engine, version in installed.items():
        pkg = (packages or {}).get(engine)
        entries, reason = engine_advisories(engine, version, data, pkg, tracker)
        remaining = [e for e in entries if e["status"] != distro.FIXED]
        if not remaining:
            continue
        ids = [e["id"] for e in remaining]
        statuses = {e["status"] for e in remaining}
        common = {"engine": engine.value, "version": version, "count": len(ids), "cves": _short(ids)}
        if distro.OPEN in statuses and pkg is not None:
            message = messages.msg(
                "alert.security_advisories_open",
                **common,
                package=pkg.name,
                installed=pkg.installed,
                dataset=dataset,
            )
        elif distro.UPDATE in statuses and pkg is not None:
            message = messages.msg(
                "alert.security_advisories_update",
                **common,
                package=pkg.name,
                candidate=pkg.candidate or "?",
                dataset=dataset,
            )
        else:
            message = messages.msg("alert.security_advisories_upstream", **common, dataset=dataset)
        severity = max(
            (SEVERITIES.get(str(e.get("severity", "")).lower(), Severity.WARNING) for e in remaining),
            key=_RANK.__getitem__,
        )
        out.append(
            Alert(
                kind=AlertKind.SECURITY_ADVISORY,
                severity=severity,
                node_id=node_id,
                engine=engine,
                subject=f"{engine.value}:advisories",
                **messages.fields("title", message),
                details={
                    "version": version,
                    "cves": [_cve_details(e) for e in remaining],
                    "fixed_by_distribution": [e["id"] for e in entries if e["status"] == distro.FIXED],
                    "package": pkg.to_dict() if pkg else None,
                    "distribution_data": _source(pkg, tracker, reason),
                    "dataset_updated": data.get("updated"),
                    "dataset_verified": data.get("verified"),
                    "dataset_revision": data.get("revision"),
                    **({"note": NOTE_UPSTREAM} if statuses == {distro.UNKNOWN} else {}),
                },
            )
        )
    return out


def fetch(url: str, var_dir: Path, timeout: float = 15.0) -> bool:
    """Download a data file (https only) and keep it as the override when it is valid."""
    if not url.startswith("https://"):
        return False
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310 (https checked above)
            body = resp.read(MAX_BYTES + 1)
        data = json.loads(body)
    except (OSError, ValueError) as exc:
        log.warning("advisory data not fetched: %s", exc)
        return False
    if len(body) > MAX_BYTES or not valid(data):
        log.warning("advisory data from %s rejected", url)
        return False
    target = var_dir / OVERRIDE_NAME
    tmp = target.with_suffix(".tmp")
    tmp.write_bytes(body)
    tmp.replace(target)
    return True
