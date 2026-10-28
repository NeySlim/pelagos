# SPDX-License-Identifier: Apache-2.0
"""ntfy: JSON publish on the server root (https://docs.ntfy.sh/publish/, "Publish as JSON",
checked 2026-10-28). Auth `Authorization: Bearer tk_...` or Basic; messages over 4,096 bytes
would become attachments, so the text is cut below that.
"""

from __future__ import annotations

import base64
import json
import re
from collections.abc import Mapping
from typing import Any

from pelagos.notify.http import HttpRequest
from pelagos.notify.model import Batch, Channel, SendError
from pelagos.notify.transports import Issue, SendContext, check_url, http_send, rendered

MESSAGE_MAX = 4096
TOPIC_PATTERN = r"^[-_A-Za-z0-9]{1,64}$"
PRIORITY = {"critical": 5, "warning": 4, "info": 3, "resolved": 2, "test": 3}
TAGS = {
    "critical": "rotating_light",
    "warning": "warning",
    "info": "information_source",
    "resolved": "white_check_mark",
    "test": "test_tube",
}


def cut(text: str, limit: int = MESSAGE_MAX) -> str:
    data = text.encode()
    if len(data) <= limit:
        return text
    return data[: limit - 3].decode("utf-8", "ignore") + "..."


def auth_header(params: Mapping[str, Any], secrets: Mapping[str, str]) -> str | None:
    if secrets.get("token"):
        return "Bearer " + secrets["token"]
    if secrets.get("password"):
        user = str(params.get("username") or "")
        return "Basic " + base64.b64encode(f"{user}:{secrets['password']}".encode()).decode()
    return None


def payload(channel: Channel, batch: Batch) -> dict[str, Any]:
    r = rendered(channel, batch)
    body: dict[str, Any] = {
        "topic": channel.params["topic"],
        "title": r.subject,
        "message": cut(r.text),
        "priority": PRIORITY[r.level],
        "tags": [TAGS[r.level], "pelagos"],
    }
    if r.click:
        body["click"] = r.click
    return body


def send(channel: Channel, secrets: Mapping[str, str], batch: Batch, ctx: SendContext) -> int | None:
    url, topic = channel.params.get("url"), channel.params.get("topic")
    if not url or not topic:
        raise SendError("ntfy channel needs url and topic")
    headers = {"Content-Type": "application/json"}
    auth = auth_header(channel.params, secrets)
    if auth:
        headers["Authorization"] = auth
    body = json.dumps(payload(channel, batch), ensure_ascii=False).encode()
    # Publishing as JSON goes to the root URL of the server, the topic is in the body.
    req = HttpRequest("POST", str(url).rstrip("/") + "/", headers, body, ca_pem=channel.params.get("ca_pem"))
    return http_send(ctx, req).status


def validate(params: Mapping[str, Any], secrets: set[str]) -> list[Issue]:
    issues: list[Issue] = []
    check_url(params, "url", bool(secrets & {"token", "password"}), issues)
    topic = params.get("topic")
    if not isinstance(topic, str) or not re.fullmatch(TOPIC_PATTERN, topic):
        issues.append(Issue("params.topic", "1 to 64 letters, digits, - or _"))
    if "password" in secrets and "token" not in secrets and not params.get("username"):
        issues.append(Issue("params.username", "required with a password"))
    return issues
