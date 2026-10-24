# SPDX-License-Identifier: Apache-2.0
"""WebSocket endpoint GET /api/v1/ws (section 18).

gevent-websocket upgrades the connection before the view runs and hands it in
`environ["wsgi.websocket"]`. The view checks the session cookie and the Origin,
then runs two loops: this one reads client actions, a sender thread (a
greenlet under the gevent worker) drains the subscriber queue to the socket.
A refused socket is closed with 4401 (no session) or 4403 (bad Origin or a
restricted session). Each topic needs the read permission of its data.
"""

from __future__ import annotations

import json
import logging
import queue
import struct
import threading
from typing import Any
from urllib.parse import urlsplit

from flask import Flask, Response, request

from pelagos.api.errors import ApiError, problem_response
from pelagos.auth.rbac import has_permission
from pelagos.auth.sessions import COOKIE_NAME
from pelagos.core.context import NodeContext
from pelagos.services.events import TOPICS, EventHub, Subscriber

log = logging.getLogger(__name__)

CLIENT_TOPICS = TOPICS - {"system"}
CLOSE_UNAUTHENTICATED = 4401
CLOSE_FORBIDDEN = 4403
SEND_POLL_SECONDS = 1.0
MAX_MESSAGE = 4096
# None: any authenticated session (plan and job events carry ids and states only).
TOPIC_PERMISSIONS: dict[str, str | None] = {
    "audit": "read:audit",
    "alerts": "read:alerts",
    "leases": "read:dhcp",
    "ha": "read:dhcp",
    "nodes": "read:nodes",
    "plans": None,
    "jobs": None,
}


def origin_allowed(origin: str | None, host: str | None, web_url: str | None = None) -> bool:
    """Same-origin only: the Origin host:port equals the Host header (or the node's web_url)."""
    if not origin:
        return False
    netloc = urlsplit(origin).netloc.lower()
    allowed = {h.lower() for h in (host, urlsplit(web_url or "").netloc) if h}
    return netloc in allowed


class SocketSession:
    """One connected client; `ws` needs receive(), send(text), close(code, message) and `closed`."""

    def __init__(
        self, ws: Any, hub: EventHub, ctx: NodeContext, session_id: str, permissions: set[str]
    ) -> None:
        self.ws = ws
        self.hub = hub
        self.ctx = ctx
        self.session_id = session_id
        self.permissions = set(permissions)
        self.sub: Subscriber = hub.subscribe(set())
        self._stop = threading.Event()
        self._send_lock = threading.Lock()

    def alive(self) -> bool:
        return self.ctx.sessions.peek(self.session_id) is not None

    def allowed(self, topic: str) -> bool:
        required = TOPIC_PERMISSIONS.get(topic)
        return required is None or has_permission(self.permissions, required)

    def send(self, message: dict[str, Any]) -> None:
        with self._send_lock:
            if not getattr(self.ws, "closed", False):
                self.ws.send(json.dumps(message, separators=(",", ":"), default=str))

    def system(self, event: str, data: dict[str, Any]) -> None:
        self.send(self.hub.message("system", event, data))

    def handle(self, raw: Any) -> None:
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="replace")
        if not isinstance(raw, str) or len(raw) > MAX_MESSAGE:
            self.system("error", {"message": "text frames of JSON only, at most 4096 bytes"})
            return
        try:
            msg = json.loads(raw)
        except ValueError:
            self.system("error", {"message": "invalid JSON"})
            return
        action = msg.get("action") if isinstance(msg, dict) else None
        if action == "ping":
            self.system("pong", {})
            return
        if action in ("subscribe", "unsubscribe"):
            topics = msg.get("topics")
            if not isinstance(topics, list) or not all(isinstance(t, str) for t in topics):
                self.system("error", {"message": "topics must be a list of strings"})
                return
            unknown = sorted(set(topics) - CLIENT_TOPICS)
            wanted = set(topics) & CLIENT_TOPICS
            forbidden = sorted(t for t in wanted if action == "subscribe" and not self.allowed(t))
            if action == "subscribe":
                self.sub.topics |= wanted - set(forbidden)
            else:
                self.sub.topics -= wanted
            extra: dict[str, Any] = {}
            if unknown:
                extra["unknown"] = unknown
            if forbidden:
                extra["forbidden"] = forbidden
            self.system("subscribed", {"topics": sorted(self.sub.topics), **extra})
            return
        self.system("error", {"message": "action must be subscribe, unsubscribe or ping"})

    def _sender(self) -> None:
        while not self._stop.is_set():
            try:
                message = self.sub.queue.get(timeout=SEND_POLL_SECONDS)
            except queue.Empty:
                if not self.alive():
                    self.close(CLOSE_UNAUTHENTICATED, "session expired")
                continue
            try:
                self.send(message)
            except Exception:  # the socket went away under us
                self._stop.set()

    def run(self) -> None:
        sender = threading.Thread(target=self._sender, name="pelagos-ws-send", daemon=True)
        sender.start()
        try:
            while not self._stop.is_set():
                raw = self.ws.receive()
                if raw is None:
                    break
                if not self.alive():
                    self.close(CLOSE_UNAUTHENTICATED, "session expired")
                    break
                self.handle(raw)
        except Exception as exc:
            log.debug("websocket closed: %s", exc)
        finally:
            self._stop.set()
            self.hub.unsubscribe(self.sub)
            sender.join(timeout=SEND_POLL_SECONDS * 2)

    def close(self, code: int, reason: str) -> None:
        self._stop.set()
        try:
            close_socket(self.ws, code, reason)
        except Exception as exc:
            log.debug("websocket close failed: %s", exc)


def close_socket(ws: Any, code: int, reason: str) -> None:
    """gevent-websocket 0.10 sends `message` (a str, UTF-8 encoded) as the whole close payload, so the
    code goes in front of it; 4401 and 4403 are two ASCII bytes, which keeps the payload valid UTF-8."""
    if not getattr(ws, "closed", False):
        ws.close(code, struct.pack("!H", code).decode("latin-1") + reason)


def register_ws(app: Flask, prefix: str) -> None:
    def ws_view() -> Response:
        from pelagos.services.container import Services

        ctx: NodeContext = app.extensions["pelagos"]
        ws = request.environ.get("wsgi.websocket")
        if ws is None:
            return problem_response(
                ApiError(
                    "validation_error", "WebSocket upgrade required (served by the gevent-websocket worker)"
                )
            )
        session = ctx.sessions.get(request.cookies.get(COOKIE_NAME))
        if session is None:
            log.warning("websocket refused from %s: no session", request.remote_addr)
            close_socket(ws, CLOSE_UNAUTHENTICATED, "authentication required")
            return Response(status=204)
        if not origin_allowed(request.headers.get("Origin"), request.host, ctx.node.web_url):
            log.warning("websocket refused: origin %s", request.headers.get("Origin"))
            close_socket(ws, CLOSE_FORBIDDEN, "origin not allowed")
            return Response(status=204)
        if session.restriction:
            log.warning("websocket refused: session restricted to %s", session.restriction)
            close_socket(ws, CLOSE_FORBIDDEN, f"session restricted: {session.restriction}")
            return Response(status=204)
        SocketSession(ws, Services.of(ctx).events, ctx, session.id, session.permissions).run()
        return Response(status=204)

    # Werkzeug routes Upgrade: websocket requests only to rules flagged websocket=True.
    app.add_url_rule(f"{prefix}/ws", "pelagos_ws", ws_view, methods=["GET"], websocket=True)
    app.add_url_rule(f"{prefix}/ws", "pelagos_ws_plain", ws_view, methods=["GET"])
