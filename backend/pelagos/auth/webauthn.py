# SPDX-License-Identifier: Apache-2.0
"""Security keys and passkeys (WebAuthn Level 2) over py_webauthn: rpId, origins, ceremonies, counters.

Adapted from UCM (backend/services/webauthn_service.py): credentials live in cluster.toml instead of a
database, challenges in process memory, last use and signature counters in a per-node file.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import logging
import secrets
import threading
import time
import urllib.parse
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.exceptions import InvalidAuthenticationResponse, InvalidRegistrationResponse
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    AuthenticatorTransport,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from pelagos.core.config_store import atomic_write
from pelagos.core.locks import FileLock
from pelagos.domain.common import to_rfc3339, utcnow

log = logging.getLogger(__name__)

RP_NAME = "Pelagos"
CEREMONY_SECONDS = 300
MAX_CEREMONIES = 1000
MAX_NAME = 64
MAX_CREDENTIAL_JSON = 64 * 1024
ALGORITHMS = [
    COSEAlgorithmIdentifier.ECDSA_SHA_256,
    COSEAlgorithmIdentifier.EDDSA,
    COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
]
REGISTER, SECOND_FACTOR, PASSKEY = "register", "second_factor", "passkey"


class WebAuthnError(Exception):
    """A ceremony that cannot go on; the message is safe to show."""


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def unb64url(text: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError) as exc:
        raise WebAuthnError("malformed base64url value") from exc


# rpId ------------------------------------------------------------------------------------------


def host_of(url_or_host: str | None) -> str:
    """Lowercase host name of a URL or "host:port", without brackets or a trailing dot."""
    text = (url_or_host or "").strip()
    if not text:
        return ""
    if "://" not in text:
        text = "//" + text
    try:
        host = urllib.parse.urlsplit(text).hostname or ""
    except ValueError:
        return ""
    return host.rstrip(".").lower()


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def within(host: str, rp_id: str) -> bool:
    return bool(host and rp_id) and (host == rp_id or host.endswith("." + rp_id))


def common_domain(hosts: list[str]) -> str | None:
    """Longest common DNS suffix of at least two labels; one host gives its parent domain.

    A single label is never returned: browsers refuse an rpId such as "lan" or "com".
    """
    names = [h for h in hosts if h and not is_ip(h)]
    if not names or len(names) != len(hosts):
        return None
    if len(names) == 1:
        labels = names[0].split(".")
        if len(labels) >= 3:
            return ".".join(labels[1:])
        return names[0] if len(labels) >= 2 else None
    split = [n.split(".")[::-1] for n in names]
    common: list[str] = []
    for parts in zip(*split, strict=False):
        if len(set(parts)) != 1:
            break
        common.append(parts[0])
    return ".".join(reversed(common)) if len(common) >= 2 else None


@dataclass(slots=True)
class RpStatus:
    rp_id: str | None  # None: no setting and no common domain (the request host is used)
    source: str  # setting | common_domain | request_host
    common_domain: str | None
    nodes: list[dict[str, Any]] = field(default_factory=list)
    warning: str | None = None

    def for_host(self, host: str) -> str:
        return self.rp_id or host

    def to_dict(self) -> dict[str, Any]:
        return {
            "rp_id": self.rp_id,
            "source": self.source,
            "common_domain": self.common_domain,
            "nodes": self.nodes,
            "warning": self.warning,
        }


def rp_status(setting: str, nodes: list[tuple[str, str, str]]) -> RpStatus:
    """rpId of the cluster from `auth.webauthn_rp_id` and the nodes' (id, name, web_url)."""
    hosts = [(nid, name, host_of(url)) for nid, name, url in nodes]
    common = common_domain([h for _, _, h in hosts]) if hosts else None
    setting = (setting or "auto").strip().rstrip(".").lower()
    if setting and setting != "auto":
        rp_id, source = setting, "setting"
    elif common:
        rp_id, source = common, "common_domain"
    else:
        rp_id, source = None, "request_host"
    listed = [
        {"id": nid, "name": name, "host": h, "covered": within(h, rp_id or "")} for nid, name, h in hosts
    ]
    warning = None
    if rp_id is None and len(hosts) > 1:
        warning = "no_common_domain"
    elif rp_id is not None and any(not n["covered"] for n in listed):
        warning = "node_outside_rp_id"
    return RpStatus(rp_id, source, common, listed, warning)


def availability(rp_id: str, host: str, scheme: str) -> str | None:
    """Why WebAuthn cannot run on this request (None when it can)."""
    if not host or is_ip(host):
        return "ip_address"
    if scheme != "https" and host != "localhost":
        return "insecure"
    if not within(host, rp_id):
        return "outside_rp_id"
    return None


def expected_origin(host_header: str, scheme: str) -> str:
    """The page origin the browser reports: the request's own scheme and Host."""
    return f"{scheme}://{host_header.strip().lower()}"


# Ceremonies ------------------------------------------------------------------------------------


@dataclass(slots=True)
class Ceremony:
    id: str
    kind: str
    challenge: bytes
    rp_id: str
    origin: str
    user_id: str | None
    created: float = field(default_factory=time.monotonic)
    # Second factor: the restriction the session gets once the key answers.
    restriction: str | None = None


class CeremonyStore:
    """Pending challenges, one use each, dropped after CEREMONY_SECONDS; oldest evicted past the cap."""

    def __init__(self, ttl: float = CEREMONY_SECONDS, cap: int = MAX_CEREMONIES) -> None:
        self.ttl = ttl
        self.cap = cap
        self._items: OrderedDict[str, Ceremony] = OrderedDict()
        self._lock = threading.Lock()

    def open(self, kind: str, rp_id: str, origin: str, user_id: str | None, **extra: Any) -> Ceremony:
        cer = Ceremony(
            secrets.token_urlsafe(24), kind, secrets.token_bytes(32), rp_id, origin, user_id, **extra
        )
        with self._lock:
            self._sweep()
            self._items[cer.id] = cer
            while len(self._items) > self.cap:
                self._items.popitem(last=False)
        return cer

    def take(self, ceremony_id: Any, *kinds: str) -> Ceremony | None:
        """Pop the ceremony (whatever its kind: one use each); None unless it is one of `kinds`."""
        if not isinstance(ceremony_id, str):
            return None
        with self._lock:
            self._sweep()
            cer = self._items.pop(ceremony_id, None)
        return cer if cer is not None and cer.kind in kinds else None

    def _sweep(self) -> None:
        now = time.monotonic()
        for cid in [c for c, v in self._items.items() if now - v.created > self.ttl]:
            del self._items[cid]

    def __len__(self) -> int:
        with self._lock:
            return len(self._items)


# Per-node usage: last use and signature counter ----------------------------------------------


class UsageStore:
    """{credential id: {"last_used", "sign_count"}} on this node only (a login never replicates)."""

    def __init__(self, path: Path, lock_path: Path) -> None:
        self.path = path
        self.lock = FileLock(lock_path)
        self._mutex = threading.Lock()

    def read(self) -> dict[str, dict[str, Any]]:
        try:
            data = json.loads(self.path.read_text())
        except FileNotFoundError:
            return {}
        except (OSError, ValueError) as exc:
            log.warning("WebAuthn usage file %s unreadable: %s", self.path, exc)
            return {}
        return {str(k): v for k, v in data.items() if isinstance(v, dict)} if isinstance(data, dict) else {}

    def counter(self, credential_id: str) -> int:
        value = self.read().get(credential_id, {}).get("sign_count", 0)
        return value if isinstance(value, int) and not isinstance(value, bool) else 0

    def record(self, credential_id: str, sign_count: int) -> None:
        with self._mutex, self.lock:
            data = self.read()
            entry = data.get(credential_id, {})
            entry["last_used"] = to_rfc3339(utcnow())
            entry["sign_count"] = max(sign_count, entry.get("sign_count", 0) or 0)
            data[credential_id] = entry
            self.path.parent.mkdir(parents=True, exist_ok=True)
            atomic_write(self.path, json.dumps(data, sort_keys=True).encode(), mode=0o640)

    def forget(self, credential_ids: list[str]) -> None:
        with self._mutex, self.lock:
            data = self.read()
            if any(data.pop(cid, None) is not None for cid in list(credential_ids)):
                atomic_write(self.path, json.dumps(data, sort_keys=True).encode(), mode=0o640)


# Ceremony steps ----------------------------------------------------------------------------------


def _transports(names: list[str]) -> list[AuthenticatorTransport] | None:
    out = []
    for name in names:
        try:
            out.append(AuthenticatorTransport(name))
        except ValueError:
            continue
    return out or None


def _descriptors(creds: dict[str, Any]) -> list[PublicKeyCredentialDescriptor]:
    return [
        PublicKeyCredentialDescriptor(id=unb64url(cid), transports=_transports(list(c.transports)))
        for cid, c in creds.items()
    ]


def registration_options(
    cer: Ceremony, user_id: str, username: str, existing: dict[str, Any]
) -> dict[str, Any]:
    options = generate_registration_options(
        rp_id=cer.rp_id,
        rp_name=RP_NAME,
        user_id=user_id.encode(),
        user_name=username,
        user_display_name=username,
        challenge=cer.challenge,
        timeout=CEREMONY_SECONDS * 1000,
        exclude_credentials=_descriptors(existing) or None,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
        supported_pub_key_algs=ALGORITHMS,
    )
    return json.loads(options_to_json(options))


def authentication_options(cer: Ceremony, allowed: dict[str, Any]) -> dict[str, Any]:
    options = generate_authentication_options(
        rp_id=cer.rp_id,
        challenge=cer.challenge,
        timeout=CEREMONY_SECONDS * 1000,
        allow_credentials=_descriptors(allowed) or None,
        user_verification=(
            UserVerificationRequirement.REQUIRED
            if cer.kind == PASSKEY
            else UserVerificationRequirement.PREFERRED
        ),
    )
    return json.loads(options_to_json(options))


def check_credential_json(credential: Any) -> dict[str, Any]:
    if not isinstance(credential, dict) or len(json.dumps(credential, default=str)) > MAX_CREDENTIAL_JSON:
        raise WebAuthnError("credential must be a PublicKeyCredential JSON object")
    if not isinstance(credential.get("id"), str) or not isinstance(credential.get("response"), dict):
        raise WebAuthnError("credential must be a PublicKeyCredential JSON object")
    return credential


@dataclass(slots=True)
class Registered:
    credential_id: str
    public_key: str
    sign_count: int
    aaguid: str | None
    backup_eligible: bool
    transports: list[str]


def verify_registration(cer: Ceremony, credential: Any) -> Registered:
    credential = check_credential_json(credential)
    try:
        verified = verify_registration_response(
            credential=credential,
            expected_challenge=cer.challenge,
            expected_rp_id=cer.rp_id,
            expected_origin=cer.origin,
            supported_pub_key_algs=ALGORITHMS,
        )
    except (InvalidRegistrationResponse, ValueError, KeyError, TypeError) as exc:
        log.info("WebAuthn registration refused: %s", exc)
        raise WebAuthnError(f"the security key answer was refused: {exc}") from None
    raw = credential["response"].get("transports")
    transports = [str(t) for t in raw if isinstance(t, str)][:8] if isinstance(raw, list) else []
    aaguid = str(verified.aaguid) if verified.aaguid else None
    return Registered(
        credential_id=b64url(verified.credential_id),
        public_key=b64url(verified.credential_public_key),
        sign_count=verified.sign_count,
        aaguid=None if aaguid == "00000000-0000-0000-0000-000000000000" else aaguid,
        backup_eligible=bool(verified.credential_device_type == "multi_device"),
        transports=transports,
    )


def user_handle(credential: dict[str, Any]) -> str | None:
    """The user id the authenticator returned with a discoverable credential."""
    handle = credential.get("response", {}).get("userHandle")
    if not isinstance(handle, str) or not handle:
        return None
    try:
        return unb64url(handle).decode()
    except (WebAuthnError, UnicodeDecodeError):
        return None


def verify_assertion(cer: Ceremony, credential: dict[str, Any], stored: Any, known_count: int) -> int:
    """New signature counter of a valid assertion by `stored`; raises WebAuthnError otherwise.

    The library's own counter check is bypassed (0 passed): many passkeys always answer 0, and
    a zero answer says nothing about cloning. A non-zero counter must move past `known_count`.
    """
    try:
        verified = verify_authentication_response(
            credential=credential,
            expected_challenge=cer.challenge,
            expected_rp_id=cer.rp_id,
            expected_origin=cer.origin,
            credential_public_key=unb64url(stored.public_key),
            credential_current_sign_count=0,
            require_user_verification=cer.kind == PASSKEY,
        )
    except (InvalidAuthenticationResponse, ValueError, KeyError, TypeError) as exc:
        log.info("WebAuthn assertion refused: %s", exc)
        raise WebAuthnError("the security key answer was refused") from None
    new = verified.new_sign_count
    if new > 0 and new <= known_count:
        log.warning(
            "WebAuthn counter of %s did not move (%s <= %s): possible cloned key",
            credential["id"],
            new,
            known_count,
        )
        raise WebAuthnError("the security key answer was refused")
    return new
