# SPDX-License-Identifier: Apache-2.0
"""Cumulative counters sampled over time: increase over a window, surviving daemon restarts."""

from __future__ import annotations


class CounterSeries:
    """(timestamp, value) samples of one daemon counter; a value below the previous one is a reset."""

    def __init__(self, keep_seconds: int) -> None:
        self.keep = keep_seconds
        self.samples: list[tuple[int, int]] = []

    def add(self, ts: int, value: int) -> None:
        if self.samples and ts <= self.samples[-1][0]:
            return
        self.samples.append((ts, value))
        cut = ts - self.keep
        while len(self.samples) > 2 and self.samples[1][0] < cut:
            self.samples.pop(0)

    def increase(self, start: int, end: int) -> tuple[int, int]:
        """(increase, seconds covered) by the sample pairs whose later point is in (start, end]."""
        total = covered = 0
        for (t0, v0), (t1, v1) in zip(self.samples, self.samples[1:], strict=False):
            if start < t1 <= end:
                total += v1 - v0 if v1 >= v0 else v1
                covered += t1 - t0
        return total, covered
