# SPDX-License-Identifier: Apache-2.0
"""Gotify: `POST /message` with an application token in `X-Gotify-Key`, never in the URL
(https://github.com/gotify/server/blob/master/docs/spec.json and https://gotify.net/docs/msgextras,
checked 2026-10-28).
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from pelagos.notify.http import HttpRequest
from pelagos.notify.model import Batch, Channel, SendError
from pelagos.notify.transports import Issue, SendContext, check_url, http_send, join_url, rendered

DEFAULT_PRIORITIES = {"critical": 8, "warning": 5, "info": 2}


def priority(params: Mapping[str, Any], level: str) -> int:
    table = {**DEFAULT_PRIORITIES, **(params.get("priorities") or {})}
    return int(table.get(level, table["info"]))


def payload(channel: Channel, batch: Batch) -> dict[str, Any]:
    r = rendered(channel, batch)
    level = r.level if r.level in DEFAULT_PRIORITIES else "info"
    extras: dict[str, Any] = {"client::display": {"contentType": "text/plain"}}
    if r.click:
        extras["client::notification"] = {"click": {"url": r.click}}
    return {
        "title": r.subject,
        "message": r.text,
        "priority": priority(channel.params, level),
        "extras": extras,
    }


def send(channel: Channel, secrets: Mapping[str, str], batch: Batch, ctx: SendContext) -> int | None:
    url, token = channel.params.get("url"), secrets.get("token")
    if not url or not token:
        raise SendError("Gotify channel needs url and an application token")
    headers = {"Content-Type": "application/json", "X-Gotify-Key": token}
    body = json.dumps(payload(channel, batch), ensure_ascii=False).encode()
    req = HttpRequest(
        "POST", join_url(str(url), "/message"), headers, body, ca_pem=channel.params.get("ca_pem")
    )
    return http_send(ctx, req).status


def validate(params: Mapping[str, Any], secrets: set[str]) -> list[Issue]:
    issues: list[Issue] = []
    check_url(params, "url", "token" in secrets, issues)
    prios = params.get("priorities") or {}
    if not isinstance(prios, Mapping):
        issues.append(Issue("params.priorities", "object expected"))
    else:
        for name, value in prios.items():
            if name not in DEFAULT_PRIORITIES:
                issues.append(Issue(f"params.priorities.{name}", "critical, warning or info"))
            elif not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 10:
                issues.append(Issue(f"params.priorities.{name}", "integer 0 to 10"))
    return issues
