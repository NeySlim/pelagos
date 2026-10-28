# SPDX-License-Identifier: Apache-2.0
"""Generic webhook (`pelagos.notification.v1`, optional HMAC-SHA256 signature) and its Home
Assistant preset: `POST /api/webhook/<webhook_id>` with a JSON body, read by the automation as
`trigger.json` (https://www.home-assistant.io/docs/automation/trigger/, checked 2026-10-28).
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any
from urllib.parse import quote

from pelagos.notify.http import HttpRequest
from pelagos.notify.model import Batch, Channel, SendError
from pelagos.notify.render import signature, webhook_payload
from pelagos.notify.transports import Issue, SendContext, check_url, http_send, join_url

HEADER_NAME = r"^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}$"
# Headers Pelagos sets itself or that would break the request.
RESERVED = frozenset({"host", "content-length", "content-type", "transfer-encoding", "connection"})
WEBHOOK_ID = r"^[A-Za-z0-9_-]{1,128}$"


def body_of(channel: Channel, batch: Batch) -> bytes:
    return json.dumps(
        webhook_payload(batch, channel.language), ensure_ascii=False, separators=(",", ":")
    ).encode()


def base_headers(batch: Batch) -> dict[str, str]:
    return {"Content-Type": "application/json", "X-Pelagos-Delivery": batch.id}


class Webhook:
    def send(
        self, channel: Channel, secrets: Mapping[str, str], batch: Batch, ctx: SendContext
    ) -> int | None:
        url = channel.params.get("url")
        if not url:
            raise SendError("webhook channel needs a url")
        body = body_of(channel, batch)
        headers = {
            str(k): str(v)
            for k, v in (channel.params.get("headers") or {}).items()
            if str(k).lower() not in RESERVED and not str(k).lower().startswith("x-pelagos-")
        }
        headers.update(base_headers(batch))
        secret = secrets.get("hmac_secret")
        if secret:
            ts = int(ctx.now())
            headers["X-Pelagos-Timestamp"] = str(ts)
            headers["X-Pelagos-Signature"] = signature(secret, ts, body)
        req = HttpRequest("POST", str(url), headers, body, ca_pem=channel.params.get("ca_pem"))
        return http_send(ctx, req).status

    def validate(self, params: Mapping[str, Any], secrets: set[str]) -> list[Issue]:
        issues: list[Issue] = []
        check_url(params, "url", "hmac_secret" in secrets, issues)
        headers = params.get("headers") or {}
        if not isinstance(headers, Mapping):
            return [*issues, Issue("params.headers", "object expected")]
        for name, value in headers.items():
            key = str(name).lower()
            if not re.fullmatch(HEADER_NAME, str(name)):
                issues.append(Issue(f"params.headers.{name}", "invalid header name"))
            elif key in RESERVED or key.startswith("x-pelagos-"):
                issues.append(Issue(f"params.headers.{name}", "set by Pelagos"))
            elif not isinstance(value, str) or re.search(r"[\r\n\x00]", value) or len(value) > 1024:
                issues.append(
                    Issue(f"params.headers.{name}", "single-line string of at most 1024 characters")
                )
        return issues


class HomeAssistant:
    """The webhook id is the secret: it is the whole authentication of a Home Assistant webhook."""

    def send(
        self, channel: Channel, secrets: Mapping[str, str], batch: Batch, ctx: SendContext
    ) -> int | None:
        url, hook = channel.params.get("url"), secrets.get("webhook_id")
        if not url or not hook:
            raise SendError("Home Assistant channel needs url and a webhook id")
        target = join_url(str(url), "/api/webhook/" + quote(hook, safe=""))
        req = HttpRequest(
            "POST", target, base_headers(batch), body_of(channel, batch), ca_pem=channel.params.get("ca_pem")
        )
        return http_send(ctx, req).status

    def validate(self, params: Mapping[str, Any], secrets: set[str]) -> list[Issue]:
        issues: list[Issue] = []
        check_url(params, "url", "webhook_id" in secrets, issues)
        return issues


def valid_webhook_id(value: str) -> bool:
    return bool(re.fullmatch(WEBHOOK_ID, value))
