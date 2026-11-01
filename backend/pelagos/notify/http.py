# SPDX-License-Identifier: Apache-2.0
"""The HTTP client the transports use, injected so unit tests never open a socket.

TLS is always verified (an extra CA may be trusted per channel), redirects are never followed and
at most 4 KiB of a response body is read. A `TargetGuard` refuses local targets and the cluster's
own nodes, and pins the connection to the address it checked (section 22, outgoing target guard).
"""

from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any, Protocol
from urllib.parse import urlsplit

from pelagos.notify.model import SendError

BODY_MAX = 4096
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


def system_resolve(host: str, port: int) -> list[str]:
    """Every address of `host` (a literal resolves to itself)."""
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return list(dict.fromkeys(str(info[4][0]) for info in infos))


def refused_reason(ip: IPAddress) -> str | None:
    """Why an address is never a notification target, or None when it may be one."""
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    for test, reason in (
        ("is_loopback", "loopback"),
        ("is_link_local", "link-local"),
        ("is_unspecified", "unspecified"),
        ("is_multicast", "multicast"),
        ("is_reserved", "reserved"),
    ):
        if getattr(ip, test):
            return reason
    if isinstance(ip, ipaddress.IPv4Address) and ip in ipaddress.IPv4Network("0.0.0.0/8"):
        return "unspecified"
    return None


def parse_ip(value: str) -> IPAddress | None:
    try:
        return ipaddress.ip_address(value.strip("[]").split("%", 1)[0])
    except ValueError:
        return None


@dataclass(slots=True)
class TargetGuard:
    """Refuses loopback, link-local and other non-routable targets and the nodes of the cluster.

    `node_hosts` are the host parts of the nodes' URLs, resolved on first use; `pick` checks every
    address of the target and returns the one to connect to."""

    node_hosts: tuple[str, ...] = ()
    resolve: Callable[[str, int], list[str]] = system_resolve
    _nodes: set[IPAddress] | None = None

    def nodes(self) -> set[IPAddress]:
        if self._nodes is None:
            found: set[IPAddress] = set()
            for host in self.node_hosts:
                literal = parse_ip(host)
                if literal is not None:
                    found.add(literal)
                    continue
                try:
                    found.update(ip for ip in map(parse_ip, self.resolve(host, 443)) if ip is not None)
                except OSError:
                    pass  # a node whose name does not resolve cannot be reached by name either
            self._nodes = found
        return self._nodes

    def reason(self, ip: IPAddress) -> str | None:
        found = refused_reason(ip)
        if found is not None:
            return found
        plain = ip.ipv4_mapped if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped else ip
        if ip in self.nodes() or plain in self.nodes():
            return "a node of the cluster"
        return None

    def pick(self, host: str, port: int) -> str:
        literal = parse_ip(host)
        if literal is not None:
            addresses = [literal]
        else:
            if host.lower().rstrip(".") in ("localhost", "localhost.localdomain") or host.lower().endswith(
                ".localhost"
            ):
                raise SendError("target address refused: loopback")
            try:
                addresses = [ip for ip in map(parse_ip, self.resolve(host, port)) if ip is not None]
            except OSError as exc:
                raise OSError(f"cannot resolve {host}: {exc}") from None
            if not addresses:
                raise OSError(f"cannot resolve {host}")
        for ip in addresses:
            why = self.reason(ip)
            if why is not None:
                raise SendError(f"target address refused: {ip} is {why}")
        return str(addresses[0])

    @classmethod
    def of_cluster(cls, nodes: Iterable[Any], **kwargs: Any) -> TargetGuard:
        hosts: list[str] = []
        for node in nodes:
            for url in (getattr(node, "url", None), getattr(node, "web_url", None)):
                host = urlsplit(url).hostname if isinstance(url, str) and url else None
                if host and host not in hosts:
                    hosts.append(host)
        return cls(tuple(hosts), **kwargs)


@dataclass(slots=True)
class HttpRequest:
    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    timeout: float = 15.0
    ca_pem: str | None = None
    # Set by the dispatcher and the API test unless notifications.local_targets_enabled is on.
    guard: TargetGuard | None = None


@dataclass(slots=True)
class HttpResponse:
    status: int
    body: bytes = b""
    headers: dict[str, str] = field(default_factory=dict)


class HttpClient(Protocol):
    def __call__(self, request: HttpRequest) -> HttpResponse:
        """Perform the request; raise OSError (or a subclass) when no answer came back."""
        ...


def tls_context(ca_pem: str | None) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if ca_pem:
        try:
            ctx.load_verify_locations(cadata=ca_pem)
        except (ssl.SSLError, ValueError) as exc:
            raise SendError(f"invalid extra CA: {exc}") from None
    return ctx


def default_client(request: HttpRequest) -> HttpResponse:
    """Default client on http.client: one request, no redirect, bounded body, overall deadline."""
    parts = urlsplit(request.url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise SendError("URL must be http or https with a host")
    port = parts.port
    deadline = time.monotonic() + request.timeout
    pinned = (
        request.guard.pick(parts.hostname, port or (443 if parts.scheme == "https" else 80))
        if request.guard is not None
        else None
    )
    conn: http.client.HTTPConnection
    if parts.scheme == "https":
        conn = http.client.HTTPSConnection(
            parts.hostname, port, timeout=request.timeout, context=tls_context(request.ca_pem)
        )
    else:
        conn = http.client.HTTPConnection(parts.hostname, port, timeout=request.timeout)
    if pinned is not None:
        _pin(conn, pinned)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    try:
        conn.request(request.method, path, body=request.body or None, headers=request.headers)
        if conn.sock is not None:
            conn.sock.settimeout(max(0.1, deadline - time.monotonic()))
        resp = conn.getresponse()
        body = resp.read(BODY_MAX)
        return HttpResponse(resp.status, body, {k.lower(): v for k, v in resp.getheaders()})
    except (TimeoutError, http.client.HTTPException) as exc:
        raise OSError(str(exc) or type(exc).__name__) from None
    finally:
        conn.close()


def _pin(conn: http.client.HTTPConnection, address: str) -> None:
    """Connect to the checked address; TLS still verifies the certificate against the host name."""

    def create(target: tuple[str, int], timeout: Any = None, source: Any = None) -> socket.socket:
        return socket.create_connection((address, target[1]), timeout, source)

    conn._create_connection = create  # type: ignore[attr-defined]
