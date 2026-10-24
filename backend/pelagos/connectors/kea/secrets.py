# SPDX-License-Identifier: Apache-2.0
"""Masked secrets coming back from the advanced editor.

GET /dhcp/{family}/config masks every secret (`***`); the editor posts the whole object back. Every
masked value is put back from the running configuration (same JSON path first, then by key and
owner) or from the file; one that cannot be resolved refuses the plan, never reaches config-set.
"""

from __future__ import annotations

import copy
from typing import Any

from pelagos.core.keafile import KEA_REDACTED, is_sensitive_kea_key, restore_secrets


def _by_path(target: Any, source: Any) -> None:
    if isinstance(target, dict) and isinstance(source, dict):
        for k, v in target.items():
            if k not in source:
                continue
            src = source[k]
            if is_sensitive_kea_key(k) and v in KEA_REDACTED:
                if isinstance(src, str) and src not in KEA_REDACTED:
                    target[k] = src
            else:
                _by_path(v, src)
    elif isinstance(target, list) and isinstance(source, list) and len(target) == len(source):
        for t, s in zip(target, source, strict=True):
            _by_path(t, s)


def unmask(
    config: dict[str, Any], running: dict[str, Any], filed: Any = None
) -> tuple[dict[str, Any], list[str]]:
    """(copy of `config` with masked secrets restored, paths still masked). `running` is the body
    config-get returns (same shape as `config`), `filed` the file's value when it can be read."""
    out = copy.deepcopy(config)
    _by_path(out, running)
    missing = restore_secrets(out, [], [running, filed if filed is not None else {}])
    return out, missing


def masked_refusal(missing: list[str]) -> str:
    shown = ", ".join(missing[:3]) + (f" (+{len(missing) - 3} more)" if len(missing) > 3 else "")
    return f"masked secret with no known value: {shown}; type the secret again or leave it unchanged"
