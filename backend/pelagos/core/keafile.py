# SPDX-License-Identifier: Apache-2.0
"""Kea configuration file parsing: JSON with `//`, `#`, `/* */` comments and trailing commas.

Shared by the installer and the collector; `<?include?>` is refused since the daemon resolves it.
"""

from __future__ import annotations

import json
import re
from typing import Any

_INCLUDE_RE = re.compile(r"<\?include\s+\"([^\"]+)\"\s*\?>")


class KeaConfigError(ValueError):
    pass


def strip_comments(text: str) -> str:
    """Removes the three comment kinds outside strings; keeps the JSON otherwise byte-identical."""
    out: list[str] = []
    i, n = 0, len(text)
    in_str = False
    while i < n:
        ch = text[i]
        if in_str:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_str = False
            i += 1
            continue
        if ch == '"':
            in_str = True
            out.append(ch)
            i += 1
        elif text.startswith("//", i) or ch == "#":
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def strip_trailing_commas(text: str) -> str:
    """Drops a comma followed only by blanks and `}` or `]`, which Kea's parser tolerates and JSON not."""
    out: list[str] = []
    i, n = 0, len(text)
    in_str = False
    while i < n:
        ch = text[i]
        if in_str:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            in_str = ch != '"'
        elif ch == '"':
            in_str = True
            out.append(ch)
        elif ch == ",":
            j = i + 1
            while j < n and text[j] in " \t\r\n":
                j += 1
            if j >= n or text[j] not in "}]":
                out.append(ch)
        else:
            out.append(ch)
        i += 1
    return "".join(out)


def has_include(text: str) -> bool:
    return bool(_INCLUDE_RE.search(text))


def loads(text: str, path: str | None = None) -> dict[str, Any]:
    """Parses a Kea config file; `<?include?>` directives are refused (the daemon resolves them)."""
    if has_include(text):
        raise KeaConfigError(f"{path or 'config'} uses <?include?>, which is not parsed here")
    try:
        data = json.loads(strip_trailing_commas(strip_comments(text)))
    except json.JSONDecodeError as exc:
        raise KeaConfigError(f"{path or 'config'}: invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise KeaConfigError(f"{path or 'config'}: top level is not an object")
    return data
