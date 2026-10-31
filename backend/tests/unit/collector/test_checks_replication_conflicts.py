# SPDX-License-Identifier: Apache-2.0
"""collector.checks.replication_conflicts: replication_conflict alerts from audit entries."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.unit

SKIP = pytest.mark.skip(reason="F0-REPL: contract, implemented next")


@SKIP
def test_observe_opens_one_alert_per_path_and_forgets_after_24h():
    """Two entries of one path: one alert with count 2; entries older than 24 h: no alert."""


@SKIP
def test_observe_ignores_entries_of_other_nodes():
    """Entries replicated from another node raise nothing here."""
