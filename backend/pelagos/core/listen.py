# SPDX-License-Identifier: Apache-2.0
"""Listen addresses given at init and enroll: parsing and a free-port check."""

from __future__ import annotations

import errno
import socket


class ListenError(ValueError):
    """An address that is malformed or whose port another process holds."""


def split_listen(value: str) -> tuple[str, int]:
    """`host:port` (host may be empty, `*` or a bracketed IPv6) as (host, port)."""
    host, sep, port = value.rpartition(":")
    if not sep or not port.isdigit() or not 0 < int(port) < 65536:
        raise ListenError(f"{value!r} is not host:port")
    return host.strip("[]"), int(port)


def check_free(label: str, value: str) -> None:
    """Raise ListenError when the port of `value` is already bound on that address."""
    host, port = split_listen(value)
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        try:
            sock.bind((host or "0.0.0.0", port))  # noqa: S104 - a probe, nothing listens
        except OSError as exc:
            if exc.errno == errno.EADDRINUSE:
                raise ListenError(
                    f"{label} {value}: port {port} is already in use; pick another with --{label}"
                ) from None
            if exc.errno == errno.EACCES:
                raise ListenError(f"{label} {value}: port {port} needs more privileges") from None
            raise ListenError(f"{label} {value}: cannot bind ({exc.strerror})") from None


def url_with_port(host: str, listen: str) -> str:
    """Default `https://host:port` URL for a listen address."""
    return f"https://{host}:{split_listen(listen)[1]}"
