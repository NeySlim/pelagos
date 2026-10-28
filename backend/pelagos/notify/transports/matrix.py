# SPDX-License-Identifier: Apache-2.0
"""Matrix: `PUT /_matrix/client/v3/rooms/{roomId}/send/m.room.message/{txnId}` with a bot's
`Authorization: Bearer` token (https://spec.matrix.org/v1.11/client-server-api/, checked
2026-10-28). txnId is "<batch id>.<channel id>": a resend gets the original event back, and
two channels sharing one bot token never collide (the scope is the access token, not the room).
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any
from urllib.parse import quote

from pelagos.notify.http import HttpRequest
from pelagos.notify.model import Batch, Channel, SendError
from pelagos.notify.transports import Issue, SendContext, check_url, http_send, join_url, rendered

# Room ids are "!opaque:server", or "!opaque" alone from room version 12 on.
ROOM_PATTERN = r"^![^\s/:]+(:\S+)?$"


def path(room_id: str, txn_id: str) -> str:
    return f"/_matrix/client/v3/rooms/{quote(room_id, safe='')}/send/m.room.message/{quote(txn_id, safe='')}"


def txn_id(batch: Batch, channel: Channel) -> str:
    return f"{batch.id}.{channel.id}"


def payload(channel: Channel, batch: Batch) -> dict[str, Any]:
    r = rendered(channel, batch)
    return {
        "msgtype": "m.text",
        "body": r.subject + "\n\n" + r.text,
        "format": "org.matrix.custom.html",
        "formatted_body": r.html,
    }


def send(channel: Channel, secrets: Mapping[str, str], batch: Batch, ctx: SendContext) -> int | None:
    server, room, token = (
        channel.params.get("homeserver"),
        channel.params.get("room_id"),
        secrets.get("token"),
    )
    if not server or not room or not token:
        raise SendError("Matrix channel needs homeserver, room_id and an access token")
    headers = {"Content-Type": "application/json", "Authorization": "Bearer " + token}
    body = json.dumps(payload(channel, batch), ensure_ascii=False).encode()
    url = join_url(str(server), path(str(room), txn_id(batch, channel)))
    return http_send(ctx, HttpRequest("PUT", url, headers, body, ca_pem=channel.params.get("ca_pem"))).status


def validate(params: Mapping[str, Any], secrets: set[str]) -> list[Issue]:
    issues: list[Issue] = []
    check_url(params, "homeserver", "token" in secrets, issues)
    room = params.get("room_id")
    if not isinstance(room, str) or not re.fullmatch(ROOM_PATTERN, room):
        issues.append(Issue("params.room_id", "room id expected (!opaque:server), not an alias"))
    return issues
