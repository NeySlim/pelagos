# SPDX-License-Identifier: Apache-2.0
"""A local step-ca ACME server for the web certificate daemon tests.

The binary comes from PELAGOS_STEP_CA, then PATH, then the smallstep GitHub release downloaded
into the test session's temp dir (pinned SHA-256); the tests skip when none is available. The CA
(root and intermediate) is made here with cryptography; ACME certificates last 24 hours, like step-ca's
default. `--resolver` points the challenge lookups at the test's named; `--acme-http-port`
(with `--insecure`) moves HTTP-01 off port 80.
"""

from __future__ import annotations

import hashlib
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
from cryptography.x509.oid import NameOID

from pelagos.domain.common import utcnow
from tests.fixtures.ports import free_port, wait_for

VERSION = "0.30.2"
RELEASE = "https://github.com/smallstep/certificates/releases/download/v{v}/step-ca_linux_{v}_{arch}.tar.gz"
ARCH = {"x86_64": "amd64", "aarch64": "arm64"}
SHA256 = {
    "amd64": "126615795bafe3f2d3f890e2d628fa6e2857315fb48d0671d34b23047cc37d73",
    "arm64": "43f79d1b0b8cab9895dbadd46b0a014006f682a6b1341e1fadf0be31d4b9f4b4",
}


def binary(cache: Path) -> str | None:
    found = os.environ.get("PELAGOS_STEP_CA") or shutil.which("step-ca")
    if found:
        return found
    target = cache / f"step-ca-{VERSION}" / "step-ca"
    if target.exists():
        return str(target)
    arch = ARCH.get(platform.machine())
    if arch is None:
        return None
    download = cache / f"step-ca-{VERSION}-download"
    download.mkdir(parents=True, exist_ok=True)
    archive = download / "step-ca.tar.gz"
    try:
        with urllib.request.urlopen(RELEASE.format(v=VERSION, arch=arch), timeout=60) as resp:  # noqa: S310
            payload = resp.read()
        if hashlib.sha256(payload).hexdigest() != SHA256[arch]:
            return None
        archive.write_bytes(payload)
        with tarfile.open(archive) as tar:
            member = next(m for m in tar.getmembers() if Path(m.name).name == "step-ca" and m.isfile())
            data = tar.extractfile(member)
            assert data is not None
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data.read())
    except (OSError, StopIteration, tarfile.TarError):
        return None
    target.chmod(0o755)
    return str(target)


def _ca(
    cn: str, key: ec.EllipticCurvePrivateKey, issuer: x509.Certificate | None, signer
) -> x509.Certificate:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = utcnow()
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer.subject if issuer else name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None if issuer is None else 0), critical=True
        )
        .add_extension(
            x509.KeyUsage(True, False, False, False, False, True, True, False, False), critical=True
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(signer, hashes.SHA256())
    )


@dataclass
class StepCa:
    root_dir: Path
    port: int
    http01_port: int
    root_pem: str
    process: subprocess.Popen

    @property
    def directory(self) -> str:
        return f"https://127.0.0.1:{self.port}/acme/acme/directory"

    def stop(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)

    def log(self) -> str:
        path = self.root_dir / "step-ca.log"
        return path.read_text() if path.exists() else ""


def start(exe: str, root: Path, resolver_port: int) -> StepCa:
    root.mkdir(parents=True, exist_ok=True)
    root_key = ec.generate_private_key(ec.SECP256R1())
    inter_key = ec.generate_private_key(ec.SECP256R1())
    root_cert = _ca("Pelagos Test ACME Root", root_key, None, root_key)
    inter_cert = _ca("Pelagos Test ACME Intermediate", inter_key, root_cert, root_key)
    (root / "root.crt").write_bytes(root_cert.public_bytes(serialization.Encoding.PEM))
    (root / "inter.crt").write_bytes(inter_cert.public_bytes(serialization.Encoding.PEM))
    (root / "inter.key").write_bytes(
        inter_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(b"step-test"),
        )
    )
    (root / "password").write_text("step-test")
    port, http01 = free_port(), free_port()
    config = {
        "root": str(root / "root.crt"),
        "crt": str(root / "inter.crt"),
        "key": str(root / "inter.key"),
        "address": f"127.0.0.1:{port}",
        "dnsNames": ["127.0.0.1", "localhost"],
        "logger": {"format": "text"},
        "db": {"type": "badgerv2", "dataSource": str(root / "db")},
        "authority": {
            "provisioners": [
                {
                    "type": "ACME",
                    "name": "acme",
                    "claims": {"defaultTLSCertDuration": "24h", "maxTLSCertDuration": "24h"},
                }
            ]
        },
        "tls": {"minVersion": 1.2, "maxVersion": 1.2 if os.environ.get("SV") == "tls12" else 1.3},
    }
    (root / "ca.json").write_text(json.dumps(config))
    log = (root / "step-ca.log").open("w")
    proc = subprocess.Popen(
        [
            exe,
            str(root / "ca.json"),
            "--password-file",
            str(root / "password"),
            "--resolver",
            f"127.0.0.1:{resolver_port}",
            "--insecure",
            "--acme-http-port",
            str(http01),
        ],
        stdout=log,
        stderr=subprocess.STDOUT,
        # Go's hybrid ML-KEM key share breaks the handshake with some OpenSSL 3.5 clients
        # ("bad record MAC" on the server); plain X25519 and P-256 are all the tests need.
        env={**os.environ, **({"GODEBUG": "tlsmlkem=0"} if os.environ.get("SV") == "mlkem" else {})},
    )
    server = StepCa(root, port, http01, root_cert.public_bytes(serialization.Encoding.PEM).decode(), proc)
    context = ssl.create_default_context(cadata=server.root_pem)
    if os.environ.get("SV") == "client12":
        context.maximum_version = ssl.TLSVersion.TLSv1_2
    if os.environ.get("SV") == "curve":
        context.set_ecdh_curve("prime256v1")
    print("DIAG", ssl.OPENSSL_VERSION, platform.machine(), os.environ.get("SV"), flush=True)

    def up() -> bool:
        if proc.poll() is not None:
            raise RuntimeError("step-ca exited:\n" + server.log())
        try:
            with urllib.request.urlopen(server.directory, context=context, timeout=2) as resp:  # noqa: S310
                return resp.status == 200
        except OSError:
            return False

    try:
        wait_for(up, timeout=30, what="step-ca ACME directory")
    except Exception as exc:
        server.stop()
        raise RuntimeError(f"{exc}\nstep-ca log:\n{server.log()[-4000:]}") from exc
    return server
