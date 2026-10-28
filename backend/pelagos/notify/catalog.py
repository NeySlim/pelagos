# SPDX-License-Identifier: Apache-2.0
"""Server copy of the UI translations used by notifications (pelagos/data/i18n/<lang>.json).

The files are generated from the frontend catalogs (`make notify-catalogs`), so there is one set of
translations. A key missing in a language falls back to English, then to the backend CATALOG.
"""

from __future__ import annotations

import json
import re
import sys
from functools import cache
from pathlib import Path
from typing import Any

from pelagos.domain import messages

LANGUAGES = ("en", "fr")
NAMESPACES = ("messages", "notify")
DATA = Path(__file__).resolve().parents[1] / "data" / "i18n"
_PLACEHOLDER = re.compile(r"\{\{\s*(\w+)\s*\}\}")


def build(locales: Path) -> dict[str, dict[str, Any]]:
    """The server catalogs from the frontend `src/i18n/locales` directory."""
    out: dict[str, dict[str, Any]] = {}
    for lang in LANGUAGES:
        out[lang] = {ns: json.loads((locales / lang / f"{ns}.json").read_text("utf-8")) for ns in NAMESPACES}
    return out


def dump(catalog: dict[str, Any]) -> str:
    return json.dumps(catalog, ensure_ascii=False, indent=1, sort_keys=True) + "\n"


@cache
def load(lang: str) -> dict[str, Any]:
    if lang not in LANGUAGES:
        lang = "en"
    try:
        return json.loads((DATA / f"{lang}.json").read_text("utf-8"))
    except (OSError, ValueError):
        return {}


def _lookup(ns: dict[str, Any], key: str, flat: bool) -> str | None:
    if flat:
        value = ns.get(key)
    else:
        value = ns
        for part in key.split("."):
            value = value.get(part) if isinstance(value, dict) else None
    return value if isinstance(value, str) else None


def _template(lang: str, ns: str, key: str, count: Any) -> str | None:
    flat = ns == "messages"
    for code in (lang, "en") if lang != "en" else ("en",):
        table = load(code).get(ns) or {}
        if isinstance(count, int) and not isinstance(count, bool):
            # i18next plural forms: French uses "one" for 0 and 1, English for 1 only.
            form = "one" if (count in (0, 1) if code == "fr" else count == 1) else "other"
            found = _lookup(table, f"{key}_{form}", flat)
            if found is not None:
                return found
        found = _lookup(table, key, flat)
        if found is not None:
            return found
    return None


def interpolate(template: str, params: dict[str, Any]) -> str:
    return _PLACEHOLDER.sub(lambda m: str(params.get(m.group(1), "")), template)


def text(lang: str, key: str, /, **params: Any) -> str:
    """A string of the `notify` namespace; the key itself when it is missing everywhere."""
    template = _template(lang, "notify", key, params.get("count"))
    return interpolate(template, params) if template is not None else key


def _value(lang: str, value: Any, clip: int) -> str:
    if messages.is_message(value):
        return message(lang, value, clip=clip)
    if isinstance(value, dict) and "join" in value:
        return str(value.get("sep", ", ")).join(_value(lang, v, clip) for v in value["join"])
    if isinstance(value, list | tuple):
        return ", ".join(_value(lang, v, clip) for v in value)
    out = "" if value is None else str(value)
    # Parameters carry names from the engines (DHCP host names): bounded, whatever the client sent.
    return out if len(out) <= clip else out[: clip - 3] + "..."


def message(lang: str, msg: dict[str, Any], fallback: str = "", *, clip: int = 80) -> str:
    """A backend message ({"key", "params"}) in `lang`, like the UI renders it; `fallback` if unknown."""
    raw = msg.get("params") or {}
    template = _template(lang, "messages", msg.get("key", ""), raw.get("count"))
    if template is None:
        if msg.get("key") in messages.CATALOG:
            try:
                return messages.render(msg)
            except (KeyError, IndexError, ValueError):
                return fallback
        return fallback
    return interpolate(template, {k: _value(lang, v, clip) for k, v in raw.items()})


def main(argv: list[str]) -> int:
    """python -m pelagos.notify.catalog <frontend/src/i18n/locales> [<out dir>]"""
    locales = Path(argv[0])
    out = Path(argv[1]) if len(argv) > 1 else DATA
    out.mkdir(parents=True, exist_ok=True)
    for lang, catalog in build(locales).items():
        (out / f"{lang}.json").write_text(dump(catalog), "utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
