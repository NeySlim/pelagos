# SPDX-License-Identifier: Apache-2.0
"""No shipped code, config or script hardcodes a multiarch library directory.

Captured engine outputs under tests may keep the path of the host they came from.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO = Path(__file__).resolve().parents[4]
SCANNED = ("backend/pelagos", "backend/tests/fixtures", "docker", "packaging", "scripts", ".github")
# The triplet table itself.
ALLOWED = {"backend/pelagos/platform/distro.py"}
TRIPLET = re.compile(r"/usr/lib/(x86_64|aarch64|arm|i386|powerpc64le|s390x|riscv64)-linux-gnu")
TEXT = {".py", ".sh", ".conf", ".json", ".yml", ".yaml", ".toml", ".j2", ".service", ""}


def test_no_hardcoded_multiarch_dir():
    offenders = []
    for top in SCANNED:
        for path in sorted((REPO / top).rglob("*")):
            rel = path.relative_to(REPO).as_posix()
            if not path.is_file() or rel in ALLOWED or path.suffix not in TEXT or "__pycache__" in rel:
                continue
            for n, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
                if TRIPLET.search(line):
                    offenders.append(f"{rel}:{n}: {line.strip()}")
    assert not offenders, "hardcoded multiarch directory:\n" + "\n".join(offenders)
