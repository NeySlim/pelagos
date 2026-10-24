# SPDX-License-Identifier: Apache-2.0
"""dnspython helpers: SOA query, AXFR with TSIG, signed UPDATE. No subprocess, no shell."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

import dns.exception
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.tsig
import dns.tsigkeyring
import dns.update
import dns.zone

from pelagos.connectors.base import ConnectorDenied, ConnectorTimeout, ConnectorUnavailable
from pelagos.domain.dns import RRset, normalize_name

ALGORITHMS = {
    "hmac-md5": dns.tsig.HMAC_MD5,
    "hmac-sha1": dns.tsig.HMAC_SHA1,
    "hmac-sha224": dns.tsig.HMAC_SHA224,
    "hmac-sha256": dns.tsig.HMAC_SHA256,
    "hmac-sha384": dns.tsig.HMAC_SHA384,
    "hmac-sha512": dns.tsig.HMAC_SHA512,
}


class TsigKey:
    def __init__(self, name: str, secret: str, algorithm: str = "hmac-sha256") -> None:
        self.name = normalize_name(name)
        self.secret = secret
        self.algorithm = algorithm.lower()
        if self.algorithm not in ALGORITHMS:
            raise ValueError(f"unsupported TSIG algorithm {algorithm}")

    @property
    def keyring(self) -> dict[dns.name.Name, Any]:
        return dns.tsigkeyring.from_text({self.name: self.secret})

    @property
    def dns_algorithm(self) -> dns.name.Name:
        return ALGORITHMS[self.algorithm]


class DnsClient:
    def __init__(self, server: str = "127.0.0.1", port: int = 53, timeout: float = 10.0) -> None:
        self.server = server
        self.port = port
        self.timeout = timeout

    def soa_serial(self, zone: str) -> int | None:
        q = dns.message.make_query(normalize_name(zone), dns.rdatatype.SOA)
        try:
            resp = dns.query.udp(q, self.server, port=self.port, timeout=self.timeout)
        except dns.exception.Timeout as exc:
            raise ConnectorTimeout(f"SOA query for {zone} timed out") from exc
        except OSError as exc:
            raise ConnectorUnavailable(str(exc)) from exc
        if resp.rcode() != dns.rcode.NOERROR:
            return None
        for rrset in resp.answer:
            if rrset.rdtype == dns.rdatatype.SOA:
                return int(rrset[0].serial)
        return None

    def axfr(self, zone: str, key: TsigKey | None = None) -> list[RRset]:
        """Full transfer grouped into RRsets; absolute lowercase owner names."""
        origin = dns.name.from_text(normalize_name(zone))
        try:
            xfr = dns.query.xfr(
                self.server,
                origin,
                port=self.port,
                timeout=self.timeout,
                keyring=key.keyring if key else None,
                keyname=key.name if key else None,
                keyalgorithm=key.dns_algorithm if key else None,
                relativize=False,
            )
            z = dns.zone.from_xfr(xfr, relativize=False)
        except (dns.exception.FormError, dns.tsig.PeerError, dns.query.TransferError) as exc:
            raise ConnectorDenied(f"AXFR of {zone} refused: {exc}") from exc
        except dns.exception.Timeout as exc:
            raise ConnectorTimeout(f"AXFR of {zone} timed out") from exc
        except OSError as exc:
            raise ConnectorUnavailable(str(exc)) from exc
        grouped: dict[tuple[str, str, int], list[str]] = defaultdict(list)
        for name, node in z.nodes.items():
            for rdataset in node.rdatasets:
                key_ = (name.to_text().lower(), dns.rdatatype.to_text(rdataset.rdtype), rdataset.ttl)
                grouped[key_].extend(r.to_text() for r in rdataset)
        return [
            RRset(name=n, rtype=t, ttl=ttl, rdata=sorted(rd)) for (n, t, ttl), rd in sorted(grouped.items())
        ]

    def update(self, zone: str, key: TsigKey, build: Any) -> str:
        """Send a signed UPDATE; `build(msg)` adds prerequisites and changes. Returns the rcode text."""
        msg = dns.update.Update(
            normalize_name(zone), keyring=key.keyring, keyname=key.name, keyalgorithm=key.dns_algorithm
        )
        build(msg)
        try:
            resp = dns.query.tcp(msg, self.server, port=self.port, timeout=self.timeout)
        except dns.exception.Timeout as exc:
            raise ConnectorTimeout(f"UPDATE to {zone} timed out") from exc
        except OSError as exc:
            raise ConnectorUnavailable(str(exc)) from exc
        rcode = dns.rcode.to_text(resp.rcode())
        if rcode in ("REFUSED", "NOTAUTH", "BADKEY", "BADSIG"):
            raise ConnectorDenied(f"UPDATE to {zone} refused: {rcode}")
        return rcode


def update_text(msg: dns.update.Update) -> str:
    """nsupdate-like rendering of an UPDATE for the audit log."""
    return msg.to_text()
