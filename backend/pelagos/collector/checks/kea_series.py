# SPDX-License-Identifier: Apache-2.0
"""Item 59: a node runs a Kea series that ISC no longer maintains (kind kea_series_obsolete).

The maintenance state of each series comes from `series.kea` of pelagos/data/isc_advisories.json
(section 26), never from code: 2.6 is end of life since 2026-07-30 (kea-announce, July 2026).
Subject: `kea:series`, one alert per node, raised for the first obsolete engine of kea4 and kea6.
"""

from __future__ import annotations

from typing import Any

from pelagos.collector.checks import distro
from pelagos.collector.checks.versions import version_tuple
from pelagos.domain import Alert, AlertKind, Engine, Severity, messages

SUBJECT = "kea:series"
ENGINES = (Engine.KEA4, Engine.KEA6)


def series_of(version: str | None) -> str | None:
    """`<major>.<minor>` of a version ("2.6.3-1+deb13u1" gives "2.6")."""
    t = version_tuple(version)
    return f"{t[0]}.{t[1]}" if t and len(t) >= 2 else None


def series_info(series: str | None, data: dict[str, Any]) -> dict[str, Any]:
    """{"maintained": bool|None,"eol","successor","source","checked_at"} of a Kea series. A series the
    data does not list is obsolete when it is older than a listed obsolete one, unknown otherwise."""
    empty = {"maintained": None, "eol": None, "successor": None, "source": None, "checked_at": None}
    known = ((data.get("series") or {}).get("kea") or {}) if isinstance(data, dict) else {}
    if not series or not isinstance(known, dict):
        return empty
    entry = known.get(series)
    if isinstance(entry, dict):
        return {**empty, **{k: entry.get(k) for k in empty}}
    mine = version_tuple(series)
    obsolete = sorted(
        (
            (version_tuple(name), e)
            for name, e in known.items()
            if isinstance(e, dict) and e.get("maintained") is False and version_tuple(name)
        ),
        key=lambda pair: pair[0],
    )
    newer = [e for t, e in obsolete if mine is not None and t > mine]  # type: ignore[operator]
    if not newer:
        return empty
    return {
        **empty,
        "maintained": False,
        "successor": newer[0].get("successor"),
        "source": newer[0].get("source"),
    }


def package_source(name: str, version: str) -> str:
    """distro, isc or backports, from the package that owns the daemon."""
    if name.startswith("isc-"):
        return "isc"
    if "~bpo" in version:
        return "backports"
    return "distro"


def series_alerts(
    node_id: str,
    installed: dict[Engine, str | None],
    data: dict[str, Any],
    packages: dict[Engine, distro.Package | None] | None = None,
) -> list[Alert]:
    """At most one alert for the node: the first of kea4, kea6 whose series is not maintained."""
    for engine in ENGINES:
        version = installed.get(engine)
        series = series_of(version)
        info = series_info(series, data)
        if info["maintained"] is not False:
            continue
        pkg = (packages or {}).get(engine)
        source = package_source(pkg.name, pkg.installed) if pkg else "unknown"
        message = messages.msg(
            "alert.kea_series_obsolete", engine=engine.value, version=version, series=series
        )
        return [
            Alert(
                kind=AlertKind.KEA_SERIES_OBSOLETE,
                severity=Severity.INFO,
                node_id=node_id,
                engine=engine,
                subject=SUBJECT,
                **messages.fields("title", message),
                details={
                    "engine": engine.value,
                    "version": version,
                    "series": series,
                    "source": source,
                    "package": pkg.name if pkg else None,
                    "eol": info["eol"],
                    "successor": info["successor"],
                    "reference": info["source"],
                    "checked_at": info["checked_at"],
                    "remediation": "kea_migration",
                },
            )
        ]
    return []
