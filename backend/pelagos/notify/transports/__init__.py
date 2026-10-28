# SPDX-License-Identifier: Apache-2.0
"""One transport per channel type behind `send`, the single entry point of the dispatcher and the
API's "Test" (section 22). All I/O goes through SendContext, so tests inject fakes.
"""

from __future__ import annotations

import ipaddress
import re
import ssl
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import urlsplit

from pelagos import __version__
from pelagos.notify import http as nhttp
from pelagos.notify.model import Batch, Channel, ChannelType, SendError, SendResult
from pelagos.notify.render import Rendered, render

USER_AGENT = f"pelagos/{__version__}"
DETAIL_MAX = 200


@dataclass(slots=True)
class SendContext:
    http: nhttp.HttpClient = nhttp.default_client
    # smtplib-compatible factory: smtp(security, host, port, timeout, ssl_context) -> SMTP object.
    smtp: Callable[..., Any] | None = None
    timeout: float = 15.0
    now: Callable[[], float] = time.time


@dataclass(frozen=True, slots=True)
class Issue:
    field: str
    message: str
    level: str = "error"  # "error" refuses the channel, "warning" is shown and kept


class Transport(Protocol):
    def send(
        self, channel: Channel, secrets: Mapping[str, str], batch: Batch, ctx: SendContext
    ) -> int | None:
        """Deliver the batch; return the service's status code, raise SendError on failure."""
        ...

    def validate(self, params: Mapping[str, Any], secrets: set[str]) -> list[Issue]: ...


def _registry() -> dict[str, Transport]:
    from pelagos.notify.transports import email, gotify, matrix, ntfy, webhook

    return {
        ChannelType.EMAIL: email,
        ChannelType.NTFY: ntfy,
        ChannelType.GOTIFY: gotify,
        ChannelType.MATRIX: matrix,
        ChannelType.WEBHOOK: webhook.Webhook(),
        ChannelType.HOME_ASSISTANT: webhook.HomeAssistant(),
    }


def transport(kind: str) -> Transport:
    try:
        return _registry()[kind]
    except KeyError:
        raise SendError(f"unknown channel type {kind!r}") from None


def scrub(text: str, secrets: Mapping[str, str]) -> str:
    """Error texts never carry a secret, whatever the service echoed back."""
    for value in secrets.values():
        if value and len(value) >= 4:
            text = text.replace(value, "***")
    return text


def send(
    channel: Channel | Mapping[str, Any],
    secrets: Mapping[str, str],
    batch: Batch,
    ctx: SendContext | None = None,
) -> SendResult:
    """Send one batch to one channel. Never raises: every failure is a SendResult with a scrubbed
    error and the retry decision (transient or not)."""
    ctx = ctx or SendContext()
    ch = channel if isinstance(channel, Channel) else Channel.from_table(channel)
    secrets = {k: v for k, v in secrets.items() if v}
    start = time.monotonic()
    status: int | None = None
    try:
        status = transport(ch.type).send(ch, secrets, batch, ctx)
        result = SendResult(ok=True, status=status)
    except SendError as exc:
        result = SendResult(ok=False, status=exc.status, error=exc.error, retry=exc.retry)
    except ssl.SSLCertVerificationError as exc:
        result = SendResult(
            ok=False, error=f"TLS verification failed: {getattr(exc, 'verify_message', None) or exc}"
        )
    except (OSError, TimeoutError) as exc:
        result = SendResult(ok=False, error=f"connection failed: {exc}", retry=True)
    except Exception as exc:
        result = SendResult(ok=False, error=f"unexpected error: {type(exc).__name__}: {exc}")
    result.duration_ms = int((time.monotonic() - start) * 1000)
    if result.error:
        result.error = scrub(result.error, secrets)[:1000]
    return result


def validate(channel: Mapping[str, Any], secrets: set[str]) -> list[Issue]:
    """Problems of a channel table; `secrets` names the secrets that are set."""
    kind = channel.get("type")
    if kind not in set(ChannelType):
        return [Issue("type", "one of " + ", ".join(ChannelType))]
    issues: list[Issue] = []
    if channel.get("language", "en") not in ("en", "fr"):
        issues.append(Issue("language", "en or fr"))
    params = channel.get("params") or {}
    if not isinstance(params, Mapping):
        return [*issues, Issue("params", "object expected")]
    ca = params.get("ca_pem")
    if ca:
        try:
            nhttp.tls_context(ca)
        except SendError as exc:
            issues.append(Issue("params.ca_pem", exc.error))
    return issues + transport(str(kind)).validate(params, secrets)


# Helpers shared by the HTTP transports.


def check_url(
    params: Mapping[str, Any], name: str, secret_set: bool, issues: list[Issue], *, required: bool = True
) -> str | None:
    value = params.get(name)
    if not value:
        if required:
            issues.append(Issue(f"params.{name}", "required"))
        return None
    parts = urlsplit(str(value)) if isinstance(value, str) else None
    if parts is None or parts.scheme not in ("http", "https") or not parts.hostname:
        issues.append(Issue(f"params.{name}", "http or https URL expected"))
        return None
    if parts.username or parts.password:
        issues.append(Issue(f"params.{name}", "credentials go in the secrets, not in the URL"))
    if parts.query or parts.fragment:
        issues.append(Issue(f"params.{name}", "no query or fragment"))
    if parts.scheme == "http" and secret_set:
        issues.append(Issue(f"params.{name}", "plain http carries the secret unencrypted", "warning"))
    return str(value)


def join_url(base: str, path: str) -> str:
    return base.rstrip("/") + path


def detail(body: bytes) -> str:
    text = body[:DETAIL_MAX].decode("utf-8", "replace")
    return re.sub(r"[\x00-\x1f\x7f]+", " ", text).strip()


def http_send(ctx: SendContext, request: nhttp.HttpRequest) -> nhttp.HttpResponse:
    """Perform a request and classify the answer: 2xx returned, 3xx/4xx final, 408/425/429/5xx
    transient."""
    request.headers.setdefault("User-Agent", USER_AGENT)
    request.timeout = ctx.timeout
    if request.ca_pem:
        nhttp.tls_context(request.ca_pem)  # a broken extra CA fails the same with every client
    resp = ctx.http(request)
    if 200 <= resp.status < 300:
        return resp
    info = detail(resp.body)
    suffix = f": {info}" if info else ""
    if 300 <= resp.status < 400:
        raise SendError(f"HTTP {resp.status}: redirect not followed", status=resp.status)
    retry = resp.status >= 500 or resp.status in (408, 425, 429)
    raise SendError(f"HTTP {resp.status}{suffix}", status=resp.status, retry=retry)


def is_loopback(host: str) -> bool:
    if host.lower() in ("localhost", "localhost.localdomain"):
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def rendered(channel: Channel, batch: Batch) -> Rendered:
    return render(batch, channel.language)


__all__ = ["Issue", "SendContext", "send", "transport", "validate"]
