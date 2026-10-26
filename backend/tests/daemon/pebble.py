# SPDX-License-Identifier: Apache-2.0
"""Pebble, Let's Encrypt's ACME test server, for the daemon tier.

The binary comes from PELAGOS_PEBBLE, then PATH, then the pinned GitHub release checked against
its SHA-256 (github.com/letsencrypt/pebble/releases/tag/v2.10.1, digests read from the release
assets on 2026-10-26). Pebble looks the DNS-01 records up on the test's named (`-dnsserver`),
rejects 5 % of good nonces like its default and issues 90 day certificates from a root it makes
at start (management interface, /roots/0). Its own HTTPS listener uses a certificate made here.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import platform
import shutil
import ssl
import subprocess
import tarfile
import urllib.request
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from pelagos.domain.common import utcnow
from tests.fixtures.ports import free_port, wait_for

VERSION = "2.10.1"
RELEASE = "https://github.com/letsencrypt/pebble/releases/download/v{v}/pebble-linux-{arch}.tar.gz"
SHA256 = {
    "amd64": "4f2fcb5bca8c85c9cf73ad140fccfc0d2be40bd81ab99879c79b7b8a0b4f70ed",
    "arm64": "b53fd072a69eb7692451de4e8b0667e0bdf5cccd7e36fc51b8eaf2fcc135ed9f",
}
ARCH = {"x86_64": "amd64", "aarch64": "arm64"}
VALIDITY = timedelta(days=90)


class PebbleUnavailable(Exception):
    pass


def binary(cache: Path) -> str:
    """The pebble executable; raises PebbleUnavailable with the reason when there is none."""
    found = os.environ.get("PELAGOS_PEBBLE") or shutil.which("pebble")
    if found:
        return found
    arch = ARCH.get(platform.machine())
    if arch is None:
        raise PebbleUnavailable(f"no Pebble release for {platform.machine()}")
    target = cache / f"pebble-{VERSION}" / "pebble"
    if target.exists():
        return str(target)
    url = RELEASE.format(v=VERSION, arch=arch)
    try:
        with urllib.request.urlopen(url, timeout=60) as resp:  # noqa: S310
            data = resp.read()
    except OSError as exc:
        raise PebbleUnavailable(f"download of {url} failed: {exc}") from exc
    digest = hashlib.sha256(data).hexdigest()
    if digest != SHA256[arch]:
        raise PebbleUnavailable(f"{url}: sha256 {digest}, expected {SHA256[arch]}")
    download = cache / f"pebble-{VERSION}-download"
    download.mkdir(parents=True, exist_ok=True)
    archive = download / "pebble.tar.gz"
    archive.write_bytes(data)
    with tarfile.open(archive) as tar:
        member = next((m for m in tar.getmembers() if Path(m.name).name == "pebble" and m.isfile()), None)
        extracted = tar.extractfile(member) if member else None
        if extracted is None:
            raise PebbleUnavailable(f"{url}: no pebble binary in the archive")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(extracted.read())
    target.chmod(0o755)
    return str(target)


def _listener_pki(root: Path) -> str:
    """A CA and a 127.0.0.1 certificate for Pebble's own HTTPS listener; returns the CA PEM."""
    now = utcnow()
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Pelagos Test Pebble Listener CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True
        )
        .sign(ca_key, hashes.SHA256())
    )
    key = ec.generate_private_key(ec.SECP256R1())

    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")]))
        .issuer_name(ca_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=2))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.ip_address("127.0.0.1")), x509.DNSName("localhost")]
            ),
            critical=False,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        # Python 3.13 verifies with VERIFY_X509_STRICT, which wants the AKI on the leaf.
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    (root / "listener.crt").write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    (root / "listener.key").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    return ca.public_bytes(serialization.Encoding.PEM).decode()


@dataclass
class Pebble:
    root_dir: Path
    port: int
    management_port: int
    listener_ca_pem: str
    process: subprocess.Popen

    @property
    def directory(self) -> str:
        return f"https://127.0.0.1:{self.port}/dir"

    def issuing_root(self) -> str:
        """PEM of the root Pebble signs under (made at start, lost when it stops)."""
        context = ssl.create_default_context(cadata=self.listener_ca_pem)
        url = f"https://127.0.0.1:{self.management_port}/roots/0"
        with urllib.request.urlopen(url, context=context, timeout=10) as resp:
            return resp.read().decode()

    def stop(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)

    def log(self) -> str:
        path = self.root_dir / "pebble.log"
        return path.read_text() if path.exists() else ""


def start(exe: str, root: Path, dns_port: int) -> Pebble:
    root.mkdir(parents=True, exist_ok=True)
    listener_ca = _listener_pki(root)
    port, management, http01, tls01 = free_port(), free_port(), free_port(), free_port()
    config = {
        "pebble": {
            "listenAddress": f"127.0.0.1:{port}",
            "managementListenAddress": f"127.0.0.1:{management}",
            "certificate": str(root / "listener.crt"),
            "privateKey": str(root / "listener.key"),
            "httpPort": http01,
            "tlsPort": tls01,
            "ocspResponderURL": "",
            "externalAccountBindingRequired": False,
            "domainBlocklist": ["blocked-domain.example"],
            "retryAfter": {"authz": 1, "order": 1},
            "keyAlgorithm": "ecdsa",
            "profiles": {
                "default": {"description": "90 days", "validityPeriod": int(VALIDITY.total_seconds())}
            },
        }
    }
    (root / "pebble-config.json").write_text(json.dumps(config))
    log = (root / "pebble.log").open("w")
    proc = subprocess.Popen(
        [exe, "-config", str(root / "pebble-config.json"), "-dnsserver", f"127.0.0.1:{dns_port}"],
        stdout=log,
        stderr=subprocess.STDOUT,
        cwd=root,
        env={**os.environ, "PEBBLE_VA_NOSLEEP": "1", "PEBBLE_WFE_NONCEREJECT": "5"},
    )
    server = Pebble(root, port, management, listener_ca, proc)
    context = ssl.create_default_context(cadata=listener_ca)

    def up() -> bool:
        if proc.poll() is not None:
            raise RuntimeError("pebble exited:\n" + server.log())
        try:
            with urllib.request.urlopen(server.directory, context=context, timeout=2) as resp:  # noqa: S310
                return resp.status == 200
        except OSError:
            return False

    try:
        wait_for(up, timeout=30, what="Pebble ACME directory")
    except Exception as exc:
        server.stop()
        raise RuntimeError(f"{exc}\npebble log:\n{server.log()[-4000:]}") from exc
    return server
