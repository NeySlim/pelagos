# SPDX-License-Identifier: Apache-2.0
"""Helpers for the BIND connector unit tests: the data directory and a reader mapping /etc paths to it."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

DATA = Path(__file__).parent / "data"


def mapped_reader(mapping: dict[str, Path]) -> Callable[[Path], str]:
    """Read files by their production path from the data directory; unknown paths are missing."""

    def read(path: Path) -> str:
        source = mapping.get(str(path))
        if source is None:
            raise FileNotFoundError(str(path))
        return source.read_text()

    return read


@pytest.fixture
def data_dir() -> Path:
    return DATA
