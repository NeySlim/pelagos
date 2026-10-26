# SPDX-License-Identifier: Apache-2.0
"""Where a node's web certificate comes from (cluster.toml [settings.certificates]), which names
it covers, when it is renewed and when its expiry raises an alert. Pure functions, no I/O.

[settings.certificates.cluster] is the source applied to every node (or to `node_ids`), each node
generating its own key; [settings.certificates.nodes.<node id>] is one node's own choice, which
wins unless it says "inherit". Secrets (EAB key, DNS API token, UCM API key) live in
cluster.toml [secrets] under certs/<scope>/<name>, never in these tables.
"""

from __future__ import annotations

import hashlib
import ipaddress
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import urlsplit

from pelagos.core.webcert import acme, pem

SELF_SIGNED, MANUAL, ACME, UCM, INHERIT = "self_signed", "manual", "acme", "ucm", "inherit"
SOURCES = (SELF_SIGNED, MANUAL, ACME, UCM)
AUTOMATIC = (ACME, UCM)
ACME_PROFILES = ("letsencrypt", "letsencrypt-staging", "private", "custom")
CHALLENGES = ("dns-01", "http-01")
DNS_METHODS = ("pelagos", "provider")
CLUSTER_SCOPE = "cluster"
# Secret names a source may carry; the API takes them in clear and stores them encrypted.
SOURCE_SECRETS = {"eab_hmac": ACME, "dns_api_token": ACME, "ucm_api_key": UCM}
DEFAULTS: dict[str, Any] = {
    "ucm_renew_days": 30,
    "retry_min_seconds": 300,
    "retry_max_seconds": 21600,
    "propagation_seconds": 180,
}
# ACME certificates are renewed when a third of their lifetime is left (24 h step-ca ones too).
ACME_RENEW_FRACTION = 1 / 3


class ConfigError(ValueError):
    """A source that cannot be used; `field` names the offending key."""

    def __init__(self, field: str, message: str) -> None:
        super().__init__(message)
        self.field = field


def cert_settings(settings: dict[str, Any]) -> dict[str, Any]:
    raw = settings.get("certificates") if isinstance(settings, dict) else None
    out = dict(DEFAULTS)
    if isinstance(raw, dict):
        out.update(raw)
    return out


def secret_name(scope: str, name: str) -> str:
    return f"certs/{scope}/{name}"


def node_scope(node_id: str) -> str:
    return f"node-{node_id}"


def account_secret(directory_url: str) -> str:
    """One ACME account key per directory, shared by every node of the cluster."""
    return "certs/acme-account/" + hashlib.sha256(directory_url.encode()).hexdigest()[:16]


def transfer_secret(node_id: str) -> str:
    """A manually uploaded key handed to another node through replication, until it installs it."""
    return f"certs/transfer/{node_id}"


def cluster_source(settings: dict[str, Any]) -> dict[str, Any] | None:
    raw = cert_settings(settings).get("cluster")
    return dict(raw) if isinstance(raw, dict) and raw.get("source") in AUTOMATIC else None


def node_source(settings: dict[str, Any], node_id: str) -> dict[str, Any] | None:
    nodes = cert_settings(settings).get("nodes")
    raw = nodes.get(node_id) if isinstance(nodes, dict) else None
    return dict(raw) if isinstance(raw, dict) else None


def cluster_applies(src: dict[str, Any], node_id: str) -> bool:
    targets = src.get("node_ids", "all")
    return targets == "all" or (isinstance(targets, list) and node_id in targets)


def effective(settings: dict[str, Any], node_id: str) -> tuple[dict[str, Any], str]:
    """(source, scope): the node's own choice, else the cluster's when it covers the node, else
    self-signed. `scope` names where its secrets live."""
    own = node_source(settings, node_id)
    if own and own.get("source") in SOURCES:
        return own, node_scope(node_id)
    cluster = cluster_source(settings)
    if cluster and cluster_applies(cluster, node_id):
        return cluster, CLUSTER_SCOPE
    return {"source": SELF_SIGNED}, node_scope(node_id)


def directory_url(src: dict[str, Any]) -> str:
    a = src.get("acme") or {}
    profile = a.get("profile", "letsencrypt-staging")
    if profile in acme.PROFILES:
        return acme.PROFILES[profile]
    return str(a.get("directory_url") or "")


def host_of(url: str | None) -> str | None:
    if not url:
        return None
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return None
    return host.lower() if host else None


def _is_ip(name: str) -> bool:
    try:
        ipaddress.ip_address(name)
    except ValueError:
        return False
    return True


def names_for(
    src: dict[str, Any], node_name: str, web_url: str | None, extra: list[str] | None = None
) -> list[str]:
    """SAN list: the cluster name when a load balancer fronts the nodes, else the web_url host and
    the node name, then the names added (common ones, then this node's). ACME takes only DNS
    names with a dot."""
    names: list[str] = []
    if src.get("mode") == "cluster" and src.get("cluster_name"):
        names.append(str(src["cluster_name"]).lower())
    else:
        host = host_of(web_url)
        if host:
            names.append(host)
        if node_name:
            names.append(node_name.lower())
    names += [str(n).lower() for n in src.get("names", []) if n]
    names += [str(n).lower() for n in (extra or []) if n]
    names = [n.rstrip(".") for n in dict.fromkeys(names) if n]
    if src.get("source") == ACME:
        names = [n for n in names if "." in n and not _is_ip(n)]
    return names


def required_names(src: dict[str, Any], node_name: str, web_url: str | None) -> list[str]:
    """What the certificate must cover for the UI to load without a name error."""
    if src.get("mode") == "cluster" and src.get("cluster_name"):
        return [str(src["cluster_name"]).lower()]
    host = host_of(web_url)
    return [host] if host else []


def renew_at(
    source: str, not_before: datetime, not_after: datetime, settings: dict[str, Any]
) -> datetime | None:
    """When an automatic source renews: ACME at a third of the lifetime left, UCM N days before."""
    if source == ACME:
        return not_after - (not_after - not_before) * ACME_RENEW_FRACTION
    if source == UCM:
        days = int(cert_settings(settings).get("ucm_renew_days", 30))
        lifetime = not_after - not_before
        # A certificate shorter than the window renews at a third left, like ACME.
        window = (
            min(timedelta(days=days), lifetime * ACME_RENEW_FRACTION)
            if lifetime < timedelta(days=3 * days)
            else timedelta(days=days)
        )
        return not_after - window
    return None


def retry_delay(failures: int, settings: dict[str, Any]) -> float:
    """Growing delay between automatic attempts: min * 2^(failures-1), capped at max."""
    cfg = cert_settings(settings)
    low = float(cfg.get("retry_min_seconds", 300))
    high = float(cfg.get("retry_max_seconds", 21600))
    return min(high, low * (2 ** max(0, failures - 1)))


def expiry_thresholds(lifetime: timedelta, settings: dict[str, Any]) -> tuple[timedelta, timedelta]:
    """(warning, critical) left before expiry. alerts_cert_warning_days and _critical_days apply to
    ordinary certificates; a short-lived one (24 h step-ca) uses a third and a tenth of its lifetime,
    so it never alerts while its renewal is on time."""
    warn = timedelta(days=int(settings.get("alerts_cert_warning_days", 30)))
    crit = timedelta(days=int(settings.get("alerts_cert_critical_days", 7)))
    return min(warn, lifetime * ACME_RENEW_FRACTION), min(crit, lifetime / 10)


def validate_source(raw: Any, cluster: bool = False) -> dict[str, Any]:
    """The stored form of a source: known keys only, checked; secrets are handled by the caller."""
    if not isinstance(raw, dict):
        raise ConfigError("source", "the source must be an object")
    source = raw.get("source")
    allowed = (*AUTOMATIC,) if cluster else (*SOURCES, INHERIT)
    if source not in allowed:
        raise ConfigError("source", f"source must be one of {', '.join(allowed)}")
    out: dict[str, Any] = {"source": source}
    if source == INHERIT:
        return out
    names = raw.get("names", [])
    if not isinstance(names, list) or not all(isinstance(n, str) for n in names):
        raise ConfigError("names", "names must be a list of host names")
    out["names"] = [n.strip().lower().rstrip(".") for n in names if n.strip()]
    for n in out["names"]:
        if not _is_ip(n) and not _valid_dns(n):
            raise ConfigError("names", f"{n} is not a valid host name")
    key_type = raw.get("key_type", pem.DEFAULT_KEY_TYPE)
    if key_type not in pem.KEY_TYPES:
        raise ConfigError("key_type", f"key_type must be one of {', '.join(pem.KEY_TYPES)}")
    out["key_type"] = key_type
    mode = raw.get("mode", "node")
    if mode not in ("node", "cluster"):
        raise ConfigError("mode", "mode must be node or cluster")
    out["mode"] = mode
    if mode == "cluster":
        cname = str(raw.get("cluster_name") or "").strip().lower().rstrip(".")
        if not _valid_dns(cname):
            raise ConfigError("cluster_name", "a cluster name is required in cluster mode")
        out["cluster_name"] = cname
    if cluster:
        targets = raw.get("node_ids", "all")
        if targets != "all" and not (isinstance(targets, list) and all(isinstance(t, str) for t in targets)):
            raise ConfigError("node_ids", 'node_ids must be "all" or a list of node ids')
        out["node_ids"] = targets
    if source == ACME:
        out["acme"] = _validate_acme(raw.get("acme") or {})
    elif source == UCM:
        out["ucm"] = _validate_ucm(raw.get("ucm") or {})
    return out


def _valid_dns(name: str) -> bool:
    if not name or len(name) > 253:
        return False
    labels = name.split(".")
    if labels[0] == "*":
        labels = labels[1:]
    return bool(labels) and all(
        0 < len(label) <= 63
        and label.replace("-", "").replace("_", "").isalnum()
        and not label.startswith("-")
        for label in labels
    )


def _pem_root(value: Any, field: str) -> str | None:
    if not value:
        return None
    text = str(value).strip()
    try:
        certs = pem.parse_material(text).certs
    except pem.CertError as exc:
        raise ConfigError(field, f"trust root: {exc}") from exc
    if not certs:
        raise ConfigError(field, "trust root: no certificate")
    return pem.chain_pem(certs).decode()


def _validate_acme(raw: dict[str, Any]) -> dict[str, Any]:
    profile = raw.get("profile", "letsencrypt-staging")
    if profile not in ACME_PROFILES:
        raise ConfigError("acme.profile", f"profile must be one of {', '.join(ACME_PROFILES)}")
    out: dict[str, Any] = {"profile": profile}
    if profile in ("private", "custom"):
        url = str(raw.get("directory_url") or "").strip()
        if not url.lower().startswith("https://"):
            raise ConfigError("acme.directory_url", "the ACME directory URL must start with https://")
        out["directory_url"] = url
        root = _pem_root(raw.get("trust_root"), "acme.trust_root")
        if root:
            out["trust_root"] = root
    email = str(raw.get("email") or "").strip()
    if email and "@" not in email:
        raise ConfigError("acme.email", "not an email address")
    if email:
        out["email"] = email
    if raw.get("eab_kid"):
        out["eab_kid"] = str(raw["eab_kid"]).strip()
    challenge = raw.get("challenge", "dns-01")
    if challenge not in CHALLENGES:
        raise ConfigError("acme.challenge", f"challenge must be one of {', '.join(CHALLENGES)}")
    out["challenge"] = challenge
    if challenge == "http-01":
        port = raw.get("http_port", 8080)
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            raise ConfigError("acme.http_port", "http_port must be a port number")
        out["http_port"] = port
    else:
        dns = raw.get("dns") or {}
        method = dns.get("method", "pelagos")
        if method not in DNS_METHODS:
            raise ConfigError("acme.dns.method", f"method must be one of {', '.join(DNS_METHODS)}")
        d: dict[str, Any] = {"method": method}
        if method == "pelagos":
            server = str(dns.get("server") or "").strip()
            if server:
                _split_server(server, "acme.dns.server")
                d["server"] = server
        else:
            from pelagos.core.webcert.dns01 import PROVIDERS

            provider = dns.get("provider", "hetzner")
            if provider not in PROVIDERS:
                raise ConfigError("acme.dns.provider", f"provider must be one of {', '.join(PROVIDERS)}")
            d["provider"] = provider
        zone = str(dns.get("delegation_zone") or "").strip().lower().rstrip(".")
        if zone:
            if not _valid_dns(zone):
                raise ConfigError("acme.dns.delegation_zone", "not a zone name")
            d["delegation_zone"] = zone
        out["dns"] = d
    return out


def _split_server(text: str, field: str) -> tuple[str, int]:
    host, port = text, 53
    if text.startswith("["):
        host, _, rest = text[1:].partition("]")
        if rest.startswith(":"):
            port = _port(rest[1:], field)
    elif text.count(":") == 1:
        host, raw = text.split(":")
        port = _port(raw, field)
    if not host:
        raise ConfigError(field, "server must be host[:port]")
    return host, port


def split_server(text: str) -> tuple[str, int]:
    return _split_server(text, "server")


def _port(raw: str, field: str) -> int:
    if not raw.isdigit() or not 1 <= int(raw) <= 65535:
        raise ConfigError(field, "bad port")
    return int(raw)


def _validate_ucm(raw: dict[str, Any]) -> dict[str, Any]:
    url = str(raw.get("url") or "").strip().rstrip("/")
    if not url.lower().startswith("https://"):
        raise ConfigError("ucm.url", "the UCM URL must start with https://")
    out: dict[str, Any] = {"url": url}
    root = _pem_root(raw.get("trust_root"), "ucm.trust_root")
    if root:
        out["trust_root"] = root
    if raw.get("ca_id") in (None, ""):
        raise ConfigError("ucm.ca_id", "choose the CA that signs")
    out["ca_id"] = raw["ca_id"]
    if raw.get("template_id") not in (None, ""):
        out["template_id"] = raw["template_id"]
    validity = raw.get("validity_days", 365)
    if not isinstance(validity, int) or isinstance(validity, bool) or not 1 <= validity <= 3650:
        raise ConfigError("ucm.validity_days", "validity_days must be between 1 and 3650")
    out["validity_days"] = validity
    out["revoke_old"] = bool(raw.get("revoke_old", False))
    return out
