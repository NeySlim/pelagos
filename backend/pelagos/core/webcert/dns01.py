# SPDX-License-Identifier: Apache-2.0
"""DNS-01 challenges: TXT records under _acme-challenge, put by a signed UPDATE to a zone Pelagos
serves (key ddi-acme, limited by update-policy) or through a DNS provider API, checked on every
authoritative server of the zone before the ACME server is told, removed afterwards.

Providers follow UCM's extensible layout (services/acme/dns_providers/base.py, hetzner.py).
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype
import dns.resolver
import dns.tsig
import dns.tsigkeyring
import dns.update

from pelagos.core.webcert import http
from pelagos.core.webcert.acme import Challenge

ACME_KEY = "ddi-acme"
TXT_TTL = 60
PROPAGATION_TIMEOUT = 180.0
POLL_SECONDS = 2.0
QUERY_TIMEOUT = 5.0
TSIG_ALGORITHMS = {
    "hmac-sha256": dns.tsig.HMAC_SHA256,
    "hmac-sha384": dns.tsig.HMAC_SHA384,
    "hmac-sha512": dns.tsig.HMAC_SHA512,
}


class DnsChallengeError(Exception):
    """A TXT record could not be put, seen or removed; the message is safe to show."""


def fqdn(name: str) -> str:
    return name.rstrip(".").lower() + "."


def challenge_name(domain: str, delegation_zone: str | None = None) -> str:
    """Where the TXT goes: _acme-challenge.<domain>, or the name it is delegated to by CNAME."""
    domain = domain.removeprefix("*.").rstrip(".").lower()
    if delegation_zone:
        return fqdn(f"{domain.replace('.', '-')}.{delegation_zone.rstrip('.')}")
    return fqdn(f"_acme-challenge.{domain}")


def delegation_records(domains: list[str], delegation_zone: str) -> list[dict[str, str]]:
    """The CNAME records the admin creates at the public DNS host to delegate the challenges."""
    out = []
    for d in dict.fromkeys(x.removeprefix("*.") for x in domains):
        out.append(
            {
                "name": fqdn(f"_acme-challenge.{d}"),
                "type": "CNAME",
                "value": challenge_name(d, delegation_zone),
            }
        )
    return out


@dataclass(slots=True)
class Server:
    host: str
    port: int = 53

    def __str__(self) -> str:
        return f"{self.host}:{self.port}" if self.port != 53 else self.host


def _query(name: str, rtype: str, server: Server, recursive: bool = False) -> dns.message.Message:
    q = dns.message.make_query(name, dns.rdatatype.from_text(rtype))
    if not recursive:
        q.flags &= ~dns.flags.RD
    try:
        return dns.query.udp(q, server.host, port=server.port, timeout=QUERY_TIMEOUT)
    except (dns.exception.DNSException, OSError) as exc:
        raise DnsChallengeError(f"{rtype} query for {name} to {server} failed: {exc}") from exc


def zone_of(name: str, server: Server) -> str:
    """The zone holding `name` on an authoritative server: the SOA owner it answers with."""
    resp = _query(name, "SOA", server)
    for section in (resp.answer, resp.authority):
        for rrset in section:
            if rrset.rdtype == dns.rdatatype.SOA:
                return rrset.name.to_text().lower()
    raise DnsChallengeError(
        f"{server} serves no zone holding {name} (rcode {dns.rcode.to_text(resp.rcode())})"
    )


def txt_values(name: str, server: Server) -> list[str]:
    resp = _query(name, "TXT", server)
    out: list[str] = []
    for rrset in resp.answer:
        if rrset.rdtype == dns.rdatatype.TXT:
            for rd in rrset:
                out.append(b"".join(rd.strings).decode(errors="replace"))
    return out


def authoritative_servers(zone: str, server: Server | None) -> list[Server]:
    """Addresses of the zone's NS, asked to `server` (port kept) or to the system resolver."""
    found: list[Server] = []
    port = server.port if server else 53
    try:
        if server is not None:
            resp = _query(zone, "NS", server)
            ns_names = [
                rd.target.to_text()
                for rrset in resp.answer
                if rrset.rdtype == dns.rdatatype.NS
                for rd in rrset
            ]
        else:
            ns_names = [rd.target.to_text() for rd in dns.resolver.resolve(zone, "NS")]
    except (DnsChallengeError, dns.exception.DNSException):
        ns_names = []
    for ns in ns_names:
        for rtype in ("A", "AAAA"):
            addresses: list[str] = []
            try:
                if server is not None:
                    resp = _query(ns, rtype, server)
                    addresses = [
                        rd.to_text()
                        for rrset in resp.answer
                        if rrset.rdtype == dns.rdatatype.from_text(rtype)
                        for rd in rrset
                    ]
                # A server on another port than 53 (a test or a private listener) answers alone.
                if not addresses and (server is None or server.port == 53):
                    addresses = [rd.to_text() for rd in dns.resolver.resolve(ns, rtype)]
            except (DnsChallengeError, dns.exception.DNSException, OSError):
                continue
            found.extend(Server(a, port) for a in addresses)
    if server is not None and all(s.host != server.host or s.port != server.port for s in found):
        found.insert(0, server)
    unique: dict[str, Server] = {str(s): s for s in found}
    return list(unique.values())


class DnsProvider(ABC):
    """Puts and removes TXT records. To add a provider: subclass, set TYPE and CREDENTIALS,
    register it in PROVIDERS."""

    TYPE = "base"
    LABEL = "base"
    CREDENTIALS: tuple[str, ...] = ()

    @abstractmethod
    def add_txt(self, name: str, value: str) -> None: ...

    @abstractmethod
    def delete_txt(self, name: str, value: str) -> None: ...

    def check_servers(self, name: str) -> list[Server]:
        """Servers on which the TXT must be visible before the ACME server is told."""
        try:
            zone = dns.resolver.zone_for_name(name).to_text()
        except dns.exception.DNSException:
            return []
        return authoritative_servers(zone, None)

    def test(self) -> str:
        return "ok"


class Rfc2136Provider(DnsProvider):
    """Signed UPDATE to the primary server of a zone Pelagos serves (key ddi-acme)."""

    TYPE = "rfc2136"
    LABEL = "Zone served by Pelagos (signed UPDATE)"

    def __init__(self, server: Server, key_name: str, secret: str, algorithm: str = "hmac-sha256") -> None:
        self.server = server
        self.key_name = key_name
        self.secret = secret
        if algorithm not in TSIG_ALGORITHMS:
            raise DnsChallengeError(f"unsupported TSIG algorithm {algorithm}")
        self.algorithm = algorithm

    def _update(self, name: str, build: Callable[[dns.update.Update, str], None]) -> None:
        zone = zone_of(name, self.server)
        keyring = dns.tsigkeyring.from_text({self.key_name: self.secret})
        msg = dns.update.Update(
            zone, keyring=keyring, keyname=self.key_name, keyalgorithm=TSIG_ALGORITHMS[self.algorithm]
        )
        build(msg, name)
        try:
            resp = dns.query.tcp(msg, self.server.host, port=self.server.port, timeout=QUERY_TIMEOUT * 2)
        except (dns.exception.DNSException, OSError) as exc:
            raise DnsChallengeError(f"UPDATE of {zone} on {self.server} failed: {exc}") from exc
        rcode = dns.rcode.to_text(resp.rcode())
        if rcode != "NOERROR":
            hint = (
                " (check the update-policy grant for key " + self.key_name + ")" if rcode == "REFUSED" else ""
            )
            raise DnsChallengeError(f"UPDATE of {name} in {zone} refused: {rcode}{hint}")

    def add_txt(self, name: str, value: str) -> None:
        self._update(name, lambda m, n: m.add(n, TXT_TTL, "TXT", f'"{value}"'))

    def delete_txt(self, name: str, value: str) -> None:
        self._update(name, lambda m, n: m.delete(n, "TXT", f'"{value}"'))

    def check_servers(self, name: str) -> list[Server]:
        return authoritative_servers(zone_of(name, self.server), self.server)

    def test(self) -> str:
        return f"{self.server} answers"


class HetznerProvider(DnsProvider):
    """Hetzner DNS through the Hetzner Cloud API (UCM services/acme/dns_providers/hetzner.py)."""

    TYPE = "hetzner"
    LABEL = "Hetzner DNS"
    CREDENTIALS = ("api_token",)
    BASE_URL = "https://api.hetzner.cloud/v1"

    def __init__(self, api_token: str, base_url: str | None = None) -> None:
        if not api_token:
            raise DnsChallengeError("the Hetzner API token is missing")
        self.token = api_token
        self.base_url = (base_url or self.BASE_URL).rstrip("/")
        self._zones: list[dict[str, Any]] | None = None

    def _call(self, method: str, path: str, body: Any = None) -> Any:
        try:
            resp = http.request(
                method, self.base_url + path, body=body, headers={"Authorization": f"Bearer {self.token}"}
            )
        except http.HttpError as exc:
            raise DnsChallengeError(f"Hetzner API: {exc}") from exc
        if resp.status == 404 and method in ("GET", "DELETE"):
            return None
        if not resp.ok:
            raise DnsChallengeError(
                f"Hetzner API {method} {path}: {resp.excerpt().replace(self.token, '***')}"
            )
        return resp.json()

    def _zone(self, name: str) -> dict[str, Any]:
        if self._zones is None:
            data = self._call("GET", "/zones?per_page=100") or {}
            self._zones = list(data.get("zones", []))
        labels = name.rstrip(".").split(".")
        for i in range(len(labels) - 1):
            candidate = ".".join(labels[i:])
            for zone in self._zones:
                if zone.get("name", "").rstrip(".").lower() == candidate:
                    return zone
        raise DnsChallengeError(f"no Hetzner zone holds {name}")

    def _rrset_path(self, name: str) -> tuple[str, str]:
        zone = self._zone(name)
        zname = zone["name"].rstrip(".").lower()
        relative = name.rstrip(".").lower()[: -len(zname) - 1] or "@"
        return f"/zones/{zone['id']}/rrsets/{relative}/TXT", relative

    def add_txt(self, name: str, value: str) -> None:
        path, relative = self._rrset_path(name)
        quoted = f'"{value}"'
        current = self._call("GET", path)
        records = list(((current or {}).get("rrset") or {}).get("records", []))
        if any(r.get("value") == quoted for r in records):
            return
        if records:
            self._call("PATCH", path, {"records": [*records, {"value": quoted}], "ttl": TXT_TTL})
        else:
            zone_path = path.rsplit("/rrsets/", 1)[0]
            self._call(
                "POST",
                f"{zone_path}/rrsets",
                {"name": relative, "type": "TXT", "ttl": TXT_TTL, "records": [{"value": quoted}]},
            )

    def delete_txt(self, name: str, value: str) -> None:
        path, _relative = self._rrset_path(name)
        current = self._call("GET", path)
        records = list(((current or {}).get("rrset") or {}).get("records", []))
        keep = [r for r in records if r.get("value") != f'"{value}"']
        if not records:
            return
        if keep:
            self._call("PATCH", path, {"records": keep, "ttl": TXT_TTL})
        else:
            self._call("DELETE", path)

    def test(self) -> str:
        data = self._call("GET", "/zones?per_page=100") or {}
        zones = [z.get("name") for z in data.get("zones", [])]
        return f"{len(zones)} zones: {', '.join(zones[:10])}"


PROVIDERS: dict[str, type[DnsProvider]] = {HetznerProvider.TYPE: HetznerProvider}


def provider_catalog() -> list[dict[str, Any]]:
    return [
        {"type": p.TYPE, "label": p.LABEL, "credentials": list(p.CREDENTIALS)} for p in PROVIDERS.values()
    ]


def make_provider(kind: str, credentials: dict[str, str]) -> DnsProvider:
    cls = PROVIDERS.get(kind)
    if cls is None:
        raise DnsChallengeError(f"unknown DNS provider {kind}")
    if cls is HetznerProvider:
        return HetznerProvider(credentials.get("api_token", ""), credentials.get("base_url"))
    return cls(**credentials)  # type: ignore[arg-type]


@dataclass(slots=True)
class DnsSolver:
    """ACME solver for DNS-01: put every TXT, wait until each authoritative server shows it."""

    provider: DnsProvider
    delegation_zone: str | None = None
    timeout: float = PROPAGATION_TIMEOUT
    log: Callable[[str], None] = field(default=lambda _m: None)
    sleep: Callable[[float], None] = time.sleep
    placed: list[tuple[str, str]] = field(default_factory=list)

    def present(self, challenges: list[Challenge]) -> None:
        for ch in challenges:
            name = challenge_name(ch.domain, self.delegation_zone)
            self.provider.add_txt(name, ch.txt_value)
            self.placed.append((name, ch.txt_value))
            self.log(f"TXT {name} placed")
        for name, value in self.placed:
            self.wait_visible(name, value)

    def wait_visible(self, name: str, value: str) -> None:
        servers = self.provider.check_servers(name)
        if not servers:
            self.log(f"no authoritative server found for {name}: propagation not checked")
            return
        deadline = time.monotonic() + self.timeout
        waiting = list(servers)
        while waiting:
            for server in list(waiting):
                try:
                    if value in txt_values(name, server):
                        waiting.remove(server)
                except DnsChallengeError:
                    pass
            if not waiting:
                break
            if time.monotonic() > deadline:
                raise DnsChallengeError(
                    f"TXT {name} not visible on {', '.join(str(s) for s in waiting)} "
                    f"after {int(self.timeout)} s"
                )
            self.sleep(POLL_SECONDS)
        self.log(f"TXT {name} visible on {', '.join(str(s) for s in servers)}")

    def cleanup(self, challenges: list[Challenge]) -> None:
        errors = []
        for name, value in self.placed:
            try:
                self.provider.delete_txt(name, value)
            except DnsChallengeError as exc:
                errors.append(str(exc))
        self.placed.clear()
        if errors:
            raise DnsChallengeError("; ".join(errors))
