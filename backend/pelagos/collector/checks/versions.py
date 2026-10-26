# SPDX-License-Identifier: Apache-2.0
"""Item 25: different versions of one engine across the nodes. Subject: `<engine>:version`."""

from __future__ import annotations

import re

from pelagos.domain import Alert, AlertKind, Engine, Severity, messages

_NUM = re.compile(r"\d+(?:\.\d+)*")


def version_tuple(text: str | None) -> tuple[int, ...] | None:
    """Leading dotted number of a version string ("9.20.26-1~deb13u1" gives (9, 20, 26))."""
    m = _NUM.match((text or "").strip().removeprefix("BIND ").strip())
    return tuple(int(x) for x in m.group(0).split(".")) if m else None


def version_alert(engine: str, versions: dict[str, str | None], names: dict[str, str]) -> Alert | None:
    """Nodes running the engine with a known version; a different series is a warning, a different
    patch level or packaging suffix alone is information."""
    known = {n: v for n, v in versions.items() if v and version_tuple(v)}
    if len({v for v in known.values()}) < 2:
        return None
    tuples = {version_tuple(v) for v in known.values()}
    if len(tuples) == 1:
        return None  # same release, only the packaging differs
    series = {t[:2] for t in tuples if t}
    severity = Severity.WARNING if len(series) > 1 else Severity.INFO
    shown = "; ".join(f"{names.get(n, n)} {v}" for n, v in sorted(known.items()))
    return Alert(
        kind=AlertKind.VERSION_MISMATCH,
        severity=severity,
        node_id=None,
        engine=Engine(engine),
        subject=f"{engine}:version",
        **messages.fields("title", messages.msg("alert.version_mismatch", engine=engine, versions=shown)),
        details={"versions": dict(sorted(known.items()))},
    )
