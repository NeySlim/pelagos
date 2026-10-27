# SPDX-License-Identifier: Apache-2.0
"""A real UCM (Ultimate CA Manager) for the lab tier: the admin side the tests need, through UCM's
own REST API v2 (session cookie and X-CSRF-Token, as its UI does). `scripts/lab/ucm.sh` builds and
starts UCM on its VM; `provision()` makes the CA, the API key Pelagos uses and the ACME settings.
"""

from __future__ import annotations

import json
import os
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from http.cookiejar import CookieJar
from typing import Any

from cryptography import x509

FIRST_PASSWORD = "changeme123"  # UCM's documented first password (DOCKER_QUICKSTART.md)
ADMIN_PASSWORD = os.environ.get("PELAGOS_LAB_UCM_PASSWORD", "Lab-Ucm-Admin-Password-1")
CA_NAME = "Pelagos Lab UCM CA"
# What Pelagos needs and nothing more: list CAs and templates, upload and sign a CSR, export and
# revoke the certificate.
API_KEY_PERMISSIONS = [
    "read:cas",
    "read:templates",
    "read:csrs",
    "write:csrs",
    "read:certificates",
    "write:certificates",
]


class UcmAdminError(Exception):
    pass


@dataclass
class Provisioned:
    url: str
    api_key: str
    ca_id: int
    ca_pem: str
    ca_refid: str
    admin: UcmAdmin
    acme_directory: str


class UcmAdmin:
    def __init__(self, url: str, password: str = ADMIN_PASSWORD) -> None:
        self.url = url.rstrip("/")
        self.password = password
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # the lab UCM serves its own self-signed certificate
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=context), urllib.request.HTTPCookieProcessor(CookieJar())
        )
        self.csrf: str | None = None

    def call(self, method: str, path: str, body: Any = None, expect: tuple[int, ...] = (200, 201)) -> Any:
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.csrf:
            headers["X-CSRF-Token"] = self.csrf
        req = urllib.request.Request(self.url + path, data=data, headers=headers, method=method)  # noqa: S310
        try:
            with self.opener.open(req, timeout=60) as resp:
                status, raw = resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            status, raw = exc.code, exc.read()
        try:
            out = json.loads(raw or b"null")
        except ValueError:
            out = raw.decode(errors="replace")
        if status not in expect:
            raise UcmAdminError(f"{method} {path}: HTTP {status} {str(out)[:500]}")
        return out

    def raw(self, path: str) -> bytes:
        req = urllib.request.Request(self.url + path, headers={"X-CSRF-Token": self.csrf or ""})  # noqa: S310
        with self.opener.open(req, timeout=60) as resp:
            return resp.read()

    def wait_up(self, timeout: float = 300) -> None:
        deadline = time.monotonic() + timeout
        while True:
            try:
                self.raw("/health")
                return
            except (OSError, urllib.error.URLError):
                if time.monotonic() > deadline:
                    raise
                time.sleep(3)

    def login(self) -> None:
        for password in (self.password, FIRST_PASSWORD):
            try:
                out = self.call("POST", "/api/v2/auth/login", {"username": "admin", "password": password})
            except UcmAdminError:
                continue
            self.csrf = out["data"]["csrf_token"]
            if out["data"].get("force_password_change") or password != self.password:
                self.call(
                    "POST",
                    "/api/v2/account/password",
                    {"current_password": password, "new_password": self.password},
                )
            return
        raise UcmAdminError("UCM refused both the lab password and the first password")

    def ca(self) -> dict[str, Any]:
        cas = self.call("GET", "/api/v2/cas")["data"]
        found = [c for c in cas if c.get("descr") == CA_NAME or c.get("common_name") == CA_NAME]
        if found:
            return found[0]
        body = {
            "commonName": CA_NAME,
            "organization": "Pelagos lab",
            "country": "FR",
            "keyType": "EC P-256",
            "validityYears": 5,
            "type": "root",
        }
        return self.call("POST", "/api/v2/cas", body)["data"]

    def ca_pem(self, ca_id: int) -> str:
        return self.raw(f"/api/v2/cas/{ca_id}/export?format=pem").decode()

    def api_key(self, name: str) -> str:
        # UCM keeps at most 10 active keys per user and every run leaves one: revoke the earlier
        # runs' keys (same name without the trailing number) first.
        prefix = name.rstrip("0123456789")
        for key in self.call("GET", "/api/v2/account/apikeys")["data"]:
            if key["name"].startswith(prefix) and key["is_active"] and not key["is_expired"]:
                self.call("DELETE", f"/api/v2/account/apikeys/{key['id']}")
        out = self.call(
            "POST",
            "/api/v2/account/apikeys",
            {"name": name, "permissions": API_KEY_PERMISSIONS, "expires_days": 1},
        )
        data = out["data"]
        return data.get("key") or data.get("api_key") or data["token"]

    def serve_https_from_ca(self, ca_id: int, address: str) -> bool:
        """UCM's first certificate names its address as a DNS name, which no client accepts for
        an IP: serve one from the lab CA with the address as an IP SAN. True when changed."""
        host, _, port = self.url.split("://", 1)[1].rpartition(":")
        served = x509.load_pem_x509_certificate(ssl.get_server_certificate((host, int(port))).encode())
        try:
            sans = served.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            ips = [str(ip) for ip in sans.get_values_for_type(x509.IPAddress)]
        except x509.ExtensionNotFound:
            ips = []
        if address in ips and CA_NAME in served.issuer.rfc4514_string():
            return False
        cert = self.call(
            "POST",
            "/api/v2/certificates",
            {"cn": address, "ca_id": ca_id, "san_ip": [address], "validity_days": 365, "cert_type": "server"},
        )["data"]
        self.call("POST", "/api/v2/system/https/apply", {"cert_id": cert["id"]})
        return True

    def certificate(self, cert_id: Any) -> dict[str, Any]:
        return self.call("GET", f"/api/v2/certificates/{cert_id}")["data"]

    def setup_acme(self, ca_refid: str, resolver: str) -> dict[str, Any]:
        """ACME server on, issuing from the lab CA, DNS-01 looked up on `resolver` only."""
        self.call("PATCH", "/api/v2/acme/settings", {"enabled": True, "issuing_ca_id": ca_refid})
        self.call(
            "PATCH",
            "/api/v2/acme/client/settings",
            {"dns01_resolver_mode": "custom", "dns01_nameservers": resolver},
        )
        return self.call("GET", "/api/v2/acme/settings")["data"]


def provision(url: str, key_name: str, restart: Callable[[], None] | None = None) -> Provisioned:
    """CA, HTTPS certificate from that CA (UCM restarted by `restart` when it changed), API key."""
    admin = UcmAdmin(url)
    admin.wait_up()
    admin.login()
    ca = admin.ca()
    host = url.split("://", 1)[1].rstrip("/").rpartition(":")[0]
    if admin.serve_https_from_ca(int(ca["id"]), host) and restart is not None:
        restart()
        time.sleep(5)
        admin = UcmAdmin(url)
        admin.wait_up()
        admin.login()
    ca_pem = admin.ca_pem(int(ca["id"]))
    return Provisioned(
        url=url,
        api_key=admin.api_key(key_name),
        ca_id=int(ca["id"]),
        ca_refid=str(ca["refid"]),
        ca_pem=ca_pem,
        acme_directory=f"{url.rstrip('/')}/acme/directory",
        admin=admin,
    )


class DnsRelay:
    """Forwards DNS (UDP and TCP) from a lab address to a named that listens on 127.0.0.1 only,
    so the lab UCM can look the DNS-01 records up on the test's named."""

    def __init__(self, listen: str, port: int, upstream_port: int) -> None:
        self.upstream = ("127.0.0.1", upstream_port)
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind((listen, port))
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcp.bind((listen, port))
        self.tcp.listen(16)
        self.queries = 0
        self.stopped = threading.Event()
        for target in (self._udp_loop, self._tcp_loop):
            threading.Thread(target=target, daemon=True).start()

    def _udp_loop(self) -> None:
        while not self.stopped.is_set():
            try:
                data, peer = self.udp.recvfrom(65535)
            except OSError:
                return
            self.queries += 1
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as up:
                up.settimeout(5)
                try:
                    up.sendto(data, self.upstream)
                    self.udp.sendto(up.recvfrom(65535)[0], peer)
                except OSError:
                    continue

    def _tcp_loop(self) -> None:
        while not self.stopped.is_set():
            try:
                conn, _peer = self.tcp.accept()
            except OSError:
                return
            self.queries += 1
            threading.Thread(target=self._pipe, args=(conn,), daemon=True).start()

    def _pipe(self, conn: socket.socket) -> None:
        with conn, socket.create_connection(self.upstream, timeout=10) as up:
            conn.settimeout(10)
            try:
                while data := conn.recv(65535):
                    up.sendall(data)
                    conn.sendall(up.recv(65535))
            except OSError:
                return

    def close(self) -> None:
        self.stopped.set()
        self.udp.close()
        self.tcp.close()
