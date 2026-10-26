# SPDX-License-Identifier: Apache-2.0
"""Item 28: ISC security advisories against the installed BIND and Kea versions.

The data is a versioned file (pelagos/data/isc_advisories.json). A newer copy in the node's var
directory (placed by hand or fetched when settings.checks.advisories_fetch_enabled is on) wins over it.
Versions are compared as upstream versions: distribution backports are not seen. The data is
rebuilt from kb.isc.org by scripts/update-isc-advisories.py.
Subject: `<engine>:<CVE id>` (kind security_advisory).
"""

from __future__ import annotations

import json
import logging
import re
import urllib.request
from pathlib import Path
from typing import Any

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


def advisory_alerts(node_id: str, installed: dict[Engine, str | None], data: dict[str, Any]) -> list[Alert]:
    out: list[Alert] = []
    for engine, version in installed.items():
        family = "bind" if engine is Engine.BIND else "kea"
        for entry in affected(family, version, data):
            out.append(
                Alert(
                    kind=AlertKind.SECURITY_ADVISORY,
                    severity=SEVERITIES.get(str(entry.get("severity", "")).lower(), Severity.WARNING),
                    node_id=node_id,
                    engine=engine,
                    subject=f"{engine.value}:{entry['id']}",
                    **messages.fields(
                        "title",
                        messages.msg(
                            "alert.security_advisory",
                            engine=engine.value,
                            version=version,
                            cve=entry["id"],
                            summary=entry.get("summary", ""),
                            dataset=data.get("verified") or data.get("updated") or "?",
                        ),
                    ),
                    details={
                        "cve": entry["id"],
                        "version": version,
                        "fixed_in": entry.get("fixed"),
                        "url": entry.get("source") or entry.get("url"),
                        "cvss": entry.get("cvss"),
                        "dataset_updated": data.get("updated"),
                        "dataset_verified": data.get("verified"),
                        "dataset_revision": data.get("revision"),
                        "note": "Upstream version check: distribution packages may carry the fix without "
                        "changing the version, check your distribution's security tracker.",
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
