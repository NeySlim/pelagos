# SPDX-License-Identifier: Apache-2.0
"""The built-in catalog of public RPZ and block lists (catalog.json, versioned with the code)."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

LEVELS = ("light", "normal", "strict")
CATALOG_FILE = Path(__file__).with_name("catalog.json")


class CatalogError(ValueError):
    pass


@lru_cache(maxsize=1)
def load() -> dict[str, Any]:
    data = json.loads(CATALOG_FILE.read_text("utf-8"))
    validate(data)
    return data


def validate(data: dict[str, Any]) -> None:
    lists = data.get("lists") or {}
    for list_id, item in lists.items():
        for key in ("name", "url", "format", "entries", "license"):
            if key not in item:
                raise CatalogError(f"list {list_id}: missing {key}")
        if not str(item["url"]).startswith("https://"):
            raise CatalogError(f"list {list_id}: url must be https")
        if item["format"] not in ("rpz", "hosts", "domains", "adblock"):
            raise CatalogError(f"list {list_id}: unknown format {item['format']}")
    for cat_id, cat in (data.get("categories") or {}).items():
        used = [i for ids in cat.get("levels", {}).values() for i in ids] + cat.get("addons", [])
        for list_id in [*used, *cat.get("lists", [])]:
            if list_id not in lists:
                raise CatalogError(f"category {cat_id}: unknown list {list_id}")
        if not set(cat.get("levels", {})) <= set(LEVELS) or not cat.get("levels"):
            raise CatalogError(f"category {cat_id}: levels must be among {LEVELS}")


def lists() -> dict[str, dict[str, Any]]:
    return load()["lists"]


def categories() -> dict[str, dict[str, Any]]:
    return load()["categories"]


def list_category(list_id: str) -> str | None:
    for cat_id, cat in categories().items():
        if list_id in cat["lists"] or list_id in cat.get("addons", []):
            return cat_id
    return None


def level_lists(category: str, level: str) -> list[str]:
    """List ids of a level; a level the category does not define falls to the nearest one it has."""
    cat = categories()[category]
    levels = cat["levels"]
    if level in levels:
        return list(levels[level])
    order = [lv for lv in LEVELS if lv in levels]
    wanted = LEVELS.index(level)
    return list(levels[min(order, key=lambda lv: abs(LEVELS.index(lv) - wanted))])


def category_summary(category: str) -> dict[str, Any]:
    """Per level: lists with entries; used by the UI to show size before subscribing."""
    cat = categories()[category]
    out: dict[str, Any] = {}
    for level in cat["levels"]:
        ids = level_lists(category, level)
        out[level] = {"lists": ids, "entries": sum(lists()[i]["entries"] for i in ids)}
    return out
