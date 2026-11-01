# SPDX-License-Identifier: Apache-2.0
"""The HTTP client the transports use, injected so unit tests never open a socket.

TLS is always verified (an extra CA may be trusted per channel), redirects are never followed and
at most 4 KiB of a response body is read. A `TargetGuard` refuses local targets and the cluster's
own nodes, and pins the connection to the address it checked (section 22, outgoing target guard).
"""

from __future__ import annotations

import ctypes
import ctypes.util
import http.client
import ipaddress
import logging
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
log = logging.getLogger(__name__)


class _SockAddr(ctypes.Structure):
    _fields_ = [("family", ctypes.c_ushort)]


class _IfAddrs(ctypes.Structure):
    pass


_IfAddrs._fields_ = [
    ("next", ctypes.POINTER(_IfAddrs)),
    ("name", ctypes.c_char_p),
    ("flags", ctypes.c_uint),
    ("addr", ctypes.POINTER(_SockAddr)),
    ("netmask", ctypes.POINTER(_SockAddr)),
    ("ifu", ctypes.c_void_p),
    ("data", ctypes.c_void_p),
]


def interface_addresses() -> set[IPAddress]:
    """Every IPv4 and IPv6 address of this host's interfaces (getifaddrs); empty when unreadable."""
    try:
        libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
        head = ctypes.POINTER(_IfAddrs)()
        if libc.getifaddrs(ctypes.byref(head)) != 0:
            raise OSError(ctypes.get_errno(), "getifaddrs failed")
    except (OSError, AttributeError) as exc:
        log.warning("interface addresses not read for the notification target guard: %s", exc)
        return set()
    out: set[IPAddress] = set()
    try:
        node = head
        while node:
            sa = node.contents.addr
            if sa:
                family, base = sa.contents.family, ctypes.addressof(sa.contents)
                # Read only the bytes the family holds: sockaddr_in (16) or sockaddr_in6 (28).
                if family == socket.AF_INET:
                    out.add(ipaddress.IPv4Address(ctypes.string_at(base + 4, 4)))
                elif family == socket.AF_INET6:
                    out.add(ipaddress.IPv6Address(ctypes.string_at(base + 8, 16)))
            node = node.contents.next
    finally:
        libc.freeifaddrs(head)
    return out


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


def _name(host: str) -> str:
    return host.lower().rstrip(".")


def parse_ip(value: str) -> IPAddress | None:
    try:
        return ipaddress.ip_address(value.strip("[]").split("%", 1)[0])
    except ValueError:
        return None


@dataclass(slots=True)
class TargetGuard:
    """Refuses loopback, link-local and other non-routable targets, the nodes of the cluster and the
    addresses of this host's interfaces.

    `node_hosts` are the host parts of the nodes' URLs, resolved on first use; a node name that does
    not resolve refuses any target of that name. `pick` checks every address of the target and
    returns the one to connect to."""

    node_hosts: tuple[str, ...] = ()
    resolve: Callable[[str, int], list[str]] = system_resolve
    local: Callable[[], set[IPAddress]] = interface_addresses
    _nodes: set[IPAddress] | None = None
    _unresolved: set[str] = field(default_factory=set)
    _own: set[IPAddress] | None = None

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
                    self._unresolved.add(_name(host))
            self._nodes = found
        return self._nodes

    def own(self) -> set[IPAddress]:
        if self._own is None:
            self._own = set(self.local())
        return self._own

    def reason(self, ip: IPAddress) -> str | None:
        found = refused_reason(ip)
        if found is not None:
            return found
        plain = ip.ipv4_mapped if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped else ip
        if ip in self.own() or plain in self.own():
            return "an address of this node"
        if ip in self.nodes() or plain in self.nodes():
            return "a node of the cluster"
        return None

    def pick(self, host: str, port: int) -> str:
        literal = parse_ip(host)
        if literal is not None:
            addresses = [literal]
        else:
            name = _name(host)
            if name in ("localhost", "localhost.localdomain") or name.endswith(".localhost"):
                raise SendError("target address refused: loopback")
            self.nodes()
            if name in self._unresolved:
                raise SendError(
                    f"target address refused: {host} names a node of the cluster that does not resolve"
                )
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
