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
from urllib.parse import quote

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

    def __init__(
        self,
        server: Server,
        key_name: str,
        secret: str,
        algorithm: str = "hmac-sha256",
        follow_primary: bool = False,
    ) -> None:
        self.server = server
        self.key_name = key_name
        self.secret = secret
        if algorithm not in TSIG_ALGORITHMS:
            raise DnsChallengeError(f"unsupported TSIG algorithm {algorithm}")
        self.algorithm = algorithm
        # The node's own BIND may hold the zone as a secondary: the UPDATE then goes to the primary
        # named in the SOA (MNAME), resolved through the same server.
        self.follow_primary = follow_primary

    def _send(
        self, zone: str, name: str, server: Server, build: Callable[[dns.update.Update, str], None]
    ) -> str:
        keyring = dns.tsigkeyring.from_text({self.key_name: self.secret})
        msg = dns.update.Update(
            zone, keyring=keyring, keyname=self.key_name, keyalgorithm=TSIG_ALGORITHMS[self.algorithm]
        )
        build(msg, name)
        try:
            resp = dns.query.tcp(msg, server.host, port=server.port, timeout=QUERY_TIMEOUT * 2)
        except (dns.exception.DNSException, OSError) as exc:
            raise DnsChallengeError(f"UPDATE of {zone} on {server} failed: {exc}") from exc
        return dns.rcode.to_text(resp.rcode())

    def primary_of(self, zone: str) -> Server | None:
        resp = _query(zone, "SOA", self.server)
        mname = next((rr[0].mname.to_text() for rr in resp.answer if rr.rdtype == dns.rdatatype.SOA), None)
        if mname is None:
            return None
        for rtype in ("A", "AAAA"):
            answer = _query(mname, rtype, self.server).answer
            for rrset in answer:
                if rrset.rdtype == dns.rdatatype.from_text(rtype):
                    return Server(rrset[0].to_text(), self.server.port)
        return None

    def _update(self, name: str, build: Callable[[dns.update.Update, str], None]) -> None:
        zone = zone_of(name, self.server)
        rcode = self._send(zone, name, self.server, build)
        if rcode in ("NOTAUTH", "REFUSED", "NOTIMP") and self.follow_primary:
            primary = self.primary_of(zone)
            if primary is not None and str(primary) != str(self.server):
                rcode = self._send(zone, name, primary, build)
        if rcode != "NOERROR":
            hint = f" (check the update-policy grant for key {self.key_name})" if rcode == "REFUSED" else ""
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
    """Hetzner DNS through the Hetzner Cloud API, the only one since the DNS Console API was shut
    down in May 2026 (docs.hetzner.cloud/reference/cloud, Zones and Zone RRSet Actions, checked
    2026-10-26). Records change through add_records and remove_records, which return an action
    that is followed until it succeeds; TXT values are sent quoted, as the API stores them."""

    TYPE = "hetzner"
    LABEL = "Hetzner DNS"
    CREDENTIALS = ("api_token",)
    BASE_URL = "https://api.hetzner.cloud/v1"
    ACTION_TIMEOUT = 60.0

    def __init__(
        self,
        api_token: str,
        base_url: str | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if not api_token:
            raise DnsChallengeError("the Hetzner API token is missing")
        self.token = api_token
        self.base_url = (base_url or self.BASE_URL).rstrip("/")
        self.sleep = sleep
        self._zones: dict[str, dict[str, Any] | None] = {}

    def _call(self, method: str, path: str, body: Any = None, missing_ok: bool = False) -> Any:
        try:
            resp = http.request(
                method, self.base_url + path, body=body, headers={"Authorization": f"Bearer {self.token}"}
            )
        except http.HttpError as exc:
            raise DnsChallengeError(f"Hetzner API: {exc}") from exc
        if resp.status == 404 and missing_ok:
            return None
        if not resp.ok:
            data = resp.json()
            err = data.get("error") if isinstance(data, dict) else None
            detail = f"{err.get('code')}: {err.get('message')}" if isinstance(err, dict) else resp.excerpt()
            detail = str(detail)[: http.ERROR_EXCERPT].replace(self.token, "***")
            raise DnsChallengeError(f"Hetzner API {method} {path.split('?')[0]}: HTTP {resp.status} {detail}")
        return resp.json()

    def _zone(self, name: str) -> dict[str, Any]:
        """The longest zone of the account holding `name`, looked up by exact name."""
        labels = name.rstrip(".").lower().split(".")
        for i in range(len(labels) - 1):
            candidate = ".".join(labels[i:])
            if candidate not in self._zones:
                data = self._call("GET", f"/zones?name={quote(candidate)}") or {}
                found = [z for z in data.get("zones", []) if str(z.get("name", "")).lower() == candidate]
                self._zones[candidate] = found[0] if found else None
            zone = self._zones[candidate]
            if zone is not None:
                return zone
        raise DnsChallengeError(f"no Hetzner zone holds {name}")

    def _rrset_path(self, name: str) -> str:
        zone = self._zone(name)
        zname = str(zone["name"]).rstrip(".").lower()
        # RRSet names are relative to the zone, lower case, "@" for the apex.
        relative = name.rstrip(".").lower()[: -len(zname) - 1] or "@"
        return f"/zones/{zone['id']}/rrsets/{quote(relative, safe='@')}/TXT"

    def _wait(self, answer: Any, what: str) -> None:
        action = (answer or {}).get("action") or {}
        deadline = time.monotonic() + self.ACTION_TIMEOUT
        while action.get("status") == "running":
            if time.monotonic() > deadline:
                raise DnsChallengeError(
                    f"Hetzner API: {what} still running after {int(self.ACTION_TIMEOUT)} s"
                )
            self.sleep(1.0)
            action = (self._call("GET", f"/actions/{action['id']}") or {}).get("action") or {}
        if action.get("status") == "error":
            err = action.get("error") or {}
            raise DnsChallengeError(f"Hetzner API: {what} failed: {err.get('code')}: {err.get('message')}")

    def _values(self, path: str) -> tuple[list[str], int | None] | None:
        rrset = (self._call("GET", path, missing_ok=True) or {}).get("rrset")
        if not rrset:
            return None
        return [str(r.get("value")) for r in rrset.get("records", [])], rrset.get("ttl")

    def add_txt(self, name: str, value: str) -> None:
        path = self._rrset_path(name)
        quoted = txt_quoted(value)
        current = self._values(path)
        if current is not None and quoted in current[0]:
            return
        body: dict[str, Any] = {"records": [{"value": quoted}]}
        # A TTL given for an existing RRSet must equal its own: only a new RRSet gets ours.
        if current is None:
            body["ttl"] = TXT_TTL
        self._wait(self._call("POST", f"{path}/actions/add_records", body), f"add TXT {name}")

    def delete_txt(self, name: str, value: str) -> None:
        path = self._rrset_path(name)
        quoted = txt_quoted(value)
        current = self._values(path)
        if current is None or quoted not in current[0]:
            return
        # The API deletes the RRSet itself once its last record goes.
        answer = self._call(
            "POST", f"{path}/actions/remove_records", {"records": [{"value": quoted}]}, missing_ok=True
        )
        if answer is not None:
            self._wait(answer, f"remove TXT {name}")

    def test(self) -> str:
        data = self._call("GET", "/zones?per_page=50") or {}
        zones = [str(z.get("name")) for z in data.get("zones", [])]
        total = ((data.get("meta") or {}).get("pagination") or {}).get("total_entries", len(zones))
        return f"{total} zones: {', '.join(zones[:10])}"


def txt_quoted(value: str) -> str:
    """A TXT value as the Hetzner API takes it: one quoted character-string (ACME values are
    43 base64url characters, nothing to escape)."""
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


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
