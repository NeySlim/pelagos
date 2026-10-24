# SPDX-License-Identifier: Apache-2.0
"""Byte-exact round trip of the BIND system test configurations.

Runs only when PELAGOS_BIND_SRC points at a BIND source tree (for instance an unpacked
bind-9.20.x tarball). Every `named*.conf*` file under bin/tests/system is checked. The `.j2`
templates are reduced to plain text first: `{{ expr }}` becomes a port number, `{% tag %}` and
`{# comment #}` are removed, so both branches of a conditional stay in the text.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

from pelagos.connectors.bind.namedconf import ParseError, parse, serialize

pytestmark = pytest.mark.unit

SRC = os.environ.get("PELAGOS_BIND_SRC")
_EXPR = re.compile(r"\{\{.*?\}\}", re.S)
_TAG = re.compile(r"\{%.*?%\}|\{#.*?#\}", re.S)


def detemplate(text: str) -> str:
    return _TAG.sub("", _EXPR.sub("5300", text))


def corpus(root: Path) -> list[Path]:
    return sorted(p for p in (root / "bin" / "tests" / "system").rglob("named*.conf*") if p.is_file())


@pytest.mark.skipif(not SRC, reason="PELAGOS_BIND_SRC is not set")
def test_system_test_configs_round_trip() -> None:
    files = corpus(Path(str(SRC)))
    assert len(files) > 500, "not a BIND source tree"
    failures: list[str] = []
    for path in files:
        text = path.read_text(encoding="utf-8", errors="surrogateescape")
        if path.suffix == ".j2":
            text = detemplate(text)
        try:
            out = serialize(parse(text, str(path)))
        except ParseError as exc:
            failures.append(f"{path}: {exc}")
            continue
        if out != text:
            failures.append(f"{path}: round trip differs")
    assert not failures, f"{len(failures)}/{len(files)} failed:\n" + "\n".join(failures[:20])


def test_detemplate() -> None:
    src = "options {\n{% if x %}\n  port {{ port }};\n{% endif %}\n{# note #}};\n"
    assert detemplate(src) == "options {\n\n  port 5300;\n\n};\n"
