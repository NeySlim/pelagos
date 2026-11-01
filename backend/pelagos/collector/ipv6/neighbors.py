# SPDX-License-Identifier: Apache-2.0
"""Former home of the neighbor source, now `pelagos.collector.neighbors` (IPv4 and IPv6).

This name is the same module object, so patching `run_ip` here patches the source itself."""

from __future__ import annotations

import sys

from pelagos.collector import neighbors as _neighbors

sys.modules[__name__] = _neighbors
