# SPDX-License-Identifier: Apache-2.0
"""E-mail over SMTP (smtplib): STARTTLS (587) or implicit TLS (465), certificate always verified;
no TLS only toward a loopback relay. Plain text, one message to every recipient.
"""

from __future__ import annotations

import re
import smtplib
import ssl
from collections.abc import Mapping
from email.message import EmailMessage
from email.utils import formatdate, getaddresses, parseaddr
from typing import Any

from pelagos.notify.http import tls_context
from pelagos.notify.model import Batch, Channel, SendError
from pelagos.notify.transports import Issue, SendContext, is_loopback, rendered

SECURITIES = ("starttls", "tls", "none")
ADDRESS = r"^[^@\s<>,;]+@[^@\s<>,;]+$"


def default_smtp(
    security: str, host: str, port: int, timeout: float, context: ssl.SSLContext
) -> smtplib.SMTP:
    if security == "tls":
        return smtplib.SMTP_SSL(host, port, timeout=timeout, context=context)
    return smtplib.SMTP(host, port, timeout=timeout)


def recipients(params: Mapping[str, Any]) -> list[str]:
    to = params.get("to") or []
    if isinstance(to, str):
        to = [to]
    return [addr for _, addr in getaddresses([str(t) for t in to]) if addr]


def message(channel: Channel, batch: Batch) -> EmailMessage:
    r = rendered(channel, batch)
    params = channel.params
    sender = str(params.get("from") or "")
    domain = parseaddr(sender)[1].rpartition("@")[2] or "pelagos.invalid"
    msg = EmailMessage()
    msg["Subject"] = r.subject
    msg["From"] = sender
    msg["To"] = ", ".join(recipients(params))
    msg["Date"] = formatdate(batch.sent_at.timestamp(), usegmt=True)
    # Same Message-ID on a resend: mail clients and some relays drop the duplicate.
    msg["Message-ID"] = f"<{batch.id}.{channel.id}@{domain}>"
    msg["Auto-Submitted"] = "auto-generated"
    msg["X-Pelagos-Delivery"] = batch.id
    msg.set_content(r.text + "\n")
    return msg


def _code_error(prefix: str, code: int, text: Any) -> SendError:
    reply = text.decode("utf-8", "replace") if isinstance(text, bytes) else str(text)
    reply = " ".join(reply.split())[:200]
    # SMTP 4yz replies are transient (RFC 5321 section 4.2.1), 5yz final.
    return SendError(f"{prefix}: {code} {reply}".rstrip(), status=code, retry=400 <= code < 500)


def send(channel: Channel, secrets: Mapping[str, str], batch: Batch, ctx: SendContext) -> int | None:
    params = channel.params
    host, security = str(params.get("host") or ""), str(params.get("security") or "starttls")
    port = int(params.get("port") or (465 if security == "tls" else 587))
    to = recipients(params)
    if not host or not to or not params.get("from"):
        raise SendError("e-mail channel needs host, from and at least one recipient")
    if security not in SECURITIES:
        raise SendError(f"unknown security {security!r}")
    if security == "none" and not is_loopback(host):
        raise SendError("SMTP without TLS is allowed toward a loopback address only")
    context = tls_context(params.get("ca_pem"))
    factory = ctx.smtp or default_smtp
    msg = message(channel, batch)
    try:
        smtp = factory(security, host, port, ctx.timeout, context)
        try:
            if security == "starttls":
                smtp.ehlo()
                if not smtp.has_extn("starttls"):
                    raise SendError("the server does not offer STARTTLS")
                smtp.starttls(context=context)
                smtp.ehlo()
            username, password = params.get("username"), secrets.get("password")
            if username and password:
                smtp.login(str(username), password)
            smtp.send_message(msg, to_addrs=to)
        finally:
            try:
                smtp.quit()
            except (smtplib.SMTPException, OSError):
                smtp.close()
    except smtplib.SMTPAuthenticationError as exc:
        raise SendError(f"authentication refused: {exc.smtp_code}", status=exc.smtp_code) from None
    except smtplib.SMTPRecipientsRefused as exc:
        codes = [code for code, _ in exc.recipients.values()]
        transient = bool(codes) and all(400 <= c < 500 for c in codes)
        raise SendError(
            f"every recipient refused ({', '.join(str(c) for c in codes)})",
            status=codes[0] if codes else None,
            retry=transient,
        ) from None
    except smtplib.SMTPResponseException as exc:
        raise _code_error("SMTP error", exc.smtp_code, exc.smtp_error) from None
    except smtplib.SMTPNotSupportedError as exc:
        raise SendError(f"SMTP: {exc}") from None
    except smtplib.SMTPServerDisconnected as exc:
        raise SendError(f"SMTP server disconnected: {exc}", retry=True) from None
    return 250


def validate(params: Mapping[str, Any], secrets: set[str]) -> list[Issue]:
    issues: list[Issue] = []
    host = params.get("host")
    if not isinstance(host, str) or not host.strip():
        issues.append(Issue("params.host", "required"))
    port = params.get("port")
    if port is not None and (not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535):
        issues.append(Issue("params.port", "integer 1 to 65535"))
    security = params.get("security", "starttls")
    if security not in SECURITIES:
        issues.append(Issue("params.security", "starttls, tls or none"))
    elif security == "none" and isinstance(host, str) and host and not is_loopback(host):
        issues.append(Issue("params.security", "no TLS only toward a loopback address"))
    elif security == "none":
        issues.append(Issue("params.security", "no TLS: messages travel in clear", "warning"))
    if not re.fullmatch(ADDRESS, parseaddr(str(params.get("from") or ""))[1] or ""):
        issues.append(Issue("params.from", "e-mail address expected"))
    to = params.get("to")
    if not isinstance(to, list) or not to:
        issues.append(Issue("params.to", "at least one address"))
    else:
        for i, addr in enumerate(to):
            if not isinstance(addr, str) or not re.fullmatch(ADDRESS, parseaddr(addr)[1] or ""):
                issues.append(Issue(f"params.to.{i}", "e-mail address expected"))
    if "password" in secrets and not params.get("username"):
        issues.append(Issue("params.username", "required with a password"))
    return issues
