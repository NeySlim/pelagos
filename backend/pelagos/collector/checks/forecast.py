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
# Under this use a forecast needs its trend confirmed on both halves of the window: a half-empty
# pool whose day peaks fit a line once is not filling up.
MIN_PERCENT = 60.0


def _slope(points: list[tuple[int, int]]) -> float | None:
    """Least-squares slope of (ts, assigned) in addresses per second; None without a rising trend
    that fits a line (R2 at least MIN_R2) over at least six hours."""
    n = len(points)
    if n < MIN_POINTS:
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
    return sxy / sxx


def days_to_full(points: list[tuple[int, int]], total: int) -> float | None:
    """Days until `total` at the least-squares slope of (ts, assigned); None without a rising trend."""
    if total <= 0:
        return None
    slope = _slope(points)
    if slope is None:
        return None
    room = total - float(points[-1][1])
    return max(room, 0.0) / slope / 86400


def confirmed(points: list[tuple[int, int]]) -> bool:
    """The trend rises on each half of the window on its own, not only across the whole of it."""
    if len(points) < 2 * MIN_POINTS:
        return False
    middle = (points[0][0] + points[-1][0]) / 2
    first = [p for p in points if p[0] <= middle]
    second = [p for p in points if p[0] > middle]
    return _slope(first) is not None and _slope(second) is not None


def forecast_alerts(
    node_id: str,
    engine: str,
    series: list[dict[str, Any]],
    percent_now: dict[str, float],
    warning_percent: float,
    cfg: CheckSettings,
) -> list[Alert]:
    """`series`: SeriesStore.pools rows; `percent_now`: pool subject -> use now.

    A pool already over the warning percent has its fixed-threshold alert: no forecast on top. A
    pool under MIN_PERCENT is forecast only when both halves of the window confirm the trend.
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
        used = percent_now.get(subject, 100.0 * pts[-1][1] / total if total else 0.0)
        if used < MIN_PERCENT and not confirmed(pts):
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
                    "confirmed": confirmed(pts),
                },
            )
        )
    return out
