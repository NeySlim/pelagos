# SPDX-License-Identifier: Apache-2.0
"""Engine connectors. Only this package speaks rndc, DNS UPDATE, AXFR and the Kea control protocol."""

from pelagos.connectors.base import (
    ConnectorContext,
    ConnectorDenied,
    ConnectorError,
    ConnectorTimeout,
    ConnectorUnavailable,
    DdnsBackend,
    DhcpBackend,
    DnsBackend,
    NotSupported,
    PreconditionFailed,
    ValidationFailed,
)

__all__ = [
    "ConnectorContext",
    "ConnectorDenied",
    "ConnectorError",
    "ConnectorTimeout",
    "ConnectorUnavailable",
    "DdnsBackend",
    "DhcpBackend",
    "DnsBackend",
    "NotSupported",
    "PreconditionFailed",
    "ValidationFailed",
]
