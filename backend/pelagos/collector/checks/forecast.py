# SPDX-License-Identifier: Apache-2.0
"""Item 27: "full in about N days" from the trend of the pool series.

Subject: the pool subject of the fixed-threshold alerts (`<engine>:subnet:<id>:pool:<pool>`), kind
`pool_forecast`.
"""

from __future__ import annotations

from typing import Any

from pelagos.collector.checks.settings import CheckSettings
from pelagos.collector.rules import pool_subject
from pelagos.domain import Alert, AlertKind, Engine, Severity, messages

MIN_POINTS = 12
MIN_R2 = 0.3  # a sawtooth day/night pattern fits a line badly and says nothing about the trend


def days_to_full(points: list[tuple[int, int]], total: int) -> float | None:
    """Days until `total` at the least-squares slope of (ts, assigned); None without a rising trend."""
    n = len(points)
    if n < MIN_POINTS or total <= 0:
        return None
    t0 = points[0][0]
    xs = [p[0] - t0 for p in points]
    ys = [float(p[1]) for p in points]
    if xs[-1] < 6 * 3600:
        return None
    mx, my = sum(xs) / n, sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    sxy = sum((x - mx) * (y - my) for x, y in zip(xs, ys, strict=True))
    syy = sum((y - my) ** 2 for y in ys)
    if sxx == 0 or syy == 0 or sxy <= 0:
        return None
    if sxy * sxy / (sxx * syy) < MIN_R2:
        return None
    slope = sxy / sxx  # addresses per second
    room = total - ys[-1]
    return max(room, 0.0) / slope / 86400


def forecast_alerts(
    node_id: str,
    engine: str,
    series: list[dict[str, Any]],
    percent_now: dict[str, float],
    warning_percent: float,
    cfg: CheckSettings,
) -> list[Alert]:
    """`series`: SeriesStore.pools rows; `percent_now`: pool subject -> use now.

    A pool already over the warning percent has its fixed-threshold alert: no forecast on top.
    """
    out: list[Alert] = []
    for row in series:
        key = row["key"]
        subject = pool_subject(engine, key["subnet_id"], key["pool"])
        if percent_now.get(subject, 0.0) >= warning_percent:
            continue
        pts = [(int(p[0]), int(p[1])) for p in row["points"]]
        total = int(row["points"][-1][2]) if row["points"] else 0
        days = days_to_full(pts, total)
        if days is None or days > cfg.forecast_warning_days:
            continue
        severity = Severity.CRITICAL if days <= cfg.forecast_critical_days else Severity.WARNING
        shown = max(round(days), 1)
        out.append(
            Alert(
                kind=AlertKind.POOL_FORECAST,
                severity=severity,
                node_id=node_id,
                engine=Engine(engine),
                subject=subject,
                **messages.fields(
                    "title",
                    messages.msg(
                        "alert.pool_forecast", pool=key["pool"], subnet_id=key["subnet_id"], days=shown
                    ),
                ),
                details={
                    "subnet_id": key["subnet_id"],
                    "pool": key["pool"],
                    "days": round(days, 1),
                    "total": total,
                    "assigned": pts[-1][1],
                    "window_days": cfg.forecast_window_days,
                },
            )
        )
    return out
