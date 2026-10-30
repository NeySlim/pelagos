# SPDX-License-Identifier: Apache-2.0
"""Release signing and verification (docs/architecture.md section 29, batch U1).

`make release` writes `release.json`, `SHA256SUMS` over every other file, and `SHA256SUMS.sig`
when a private Ed25519 key is available. `verify_release` is what the privileged helper runs (U2)
before root installs anything: sums always, signature state against the packaged public keys.
Ed25519 through `cryptography` (cryptography.io, "Ed25519 signing", read on 2026-10-30:
`Ed25519PublicKey.from_public_bytes(raw).verify(signature, data)` raises `InvalidSignature`).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import stat
import sys
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from pelagos.domain.updates import (
    CHECKSUMS,
    MANIFEST,
    NOTES,
    SIGNATURE,
    STATE_SCHEMA,
    ReleaseManifest,
    ReleasePackage,
    ReleaseSignature,
    SignatureState,
    key_id,
    parse_checksums,
)

log = logging.getLogger(__name__)

# Public keys installed by the package (root owned): `<key id>.pub`, PEM SubjectPublicKeyInfo.
RELEASE_KEYS = Path(__file__).resolve().parents[1] / "data" / "release-keys"
KEY_ENV = "PELAGOS_RELEASE_KEY"
PASSWORD_ENV = "PELAGOS_RELEASE_KEY_PASSWORD"  # noqa: S105 (variable name)
_DEB = re.compile(r"^pelagos_(?P<version>[^_/]+)_(?P<arch>amd64|arm64)\.deb$")
_RPM = re.compile(r"^pelagos-(?P<version>[^-/]+-[^/]+?)\.(?P<arch>x86_64|aarch64)\.rpm$")
_MAX_SMALL = 1 << 20  # SHA256SUMS, SHA256SUMS.sig and release.json are small text files


class ReleaseRefused(ValueError):
    """The release must not be installed; `reason` is one of the helper's refusal codes."""

    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(f"{reason}: {detail}")
        self.reason = reason
        self.detail = detail


@dataclass(slots=True)
class ReleaseCheck:
    """Outcome of a verification that did not refuse: sums matched, signature not invalid."""

    signature: SignatureState
    key_id: str | None
    checksums: dict[str, str]
    checksums_sha256: str
    manifest: ReleaseManifest | None = None
    warnings: list[str] = field(default_factory=list)

    def require_accepted(self, allow_unsigned: bool) -> None:
        if self.signature.needs_acceptance and not allow_unsigned:
            raise ReleaseRefused("unsigned_not_accepted", f"signature {self.signature.value}")


def public_raw(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def public_pem(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def load_public_keys(directory: Path = RELEASE_KEYS) -> dict[str, Ed25519PublicKey]:
    """{key id: key} of every Ed25519 `*.pub` in `directory`; the id is computed, never read
    from the file name, and a file that is not an Ed25519 key is skipped with a warning."""
    keys: dict[str, Ed25519PublicKey] = {}
    if not directory.is_dir():
        return keys
    for path in sorted(directory.glob("*.pub")):
        try:
            key = serialization.load_pem_public_key(path.read_bytes())
        except (OSError, ValueError, UnsupportedAlgorithm) as exc:
            log.warning("release key %s unreadable: %s", path, exc)
            continue
        if not isinstance(key, Ed25519PublicKey):
            log.warning("release key %s is not Ed25519", path)
            continue
        keys[key_id(public_raw(key))] = key
    return keys


def load_private_key(path: Path, password: str | None = None) -> Ed25519PrivateKey:
    """PEM PKCS#8 (`openssl genpkey -algorithm ed25519`) or an OpenSSH ed25519 key."""
    data = path.read_bytes()
    secret = password.encode() if password else None
    loader = (
        serialization.load_ssh_private_key
        if data.lstrip().startswith(b"-----BEGIN OPENSSH PRIVATE KEY-----")
        else serialization.load_pem_private_key
    )
    key = loader(data, password=secret)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError(f"{path} is not an Ed25519 private key")
    return key


def sign_checksums(data: bytes, private: Ed25519PrivateKey) -> ReleaseSignature:
    return ReleaseSignature(key_id(public_raw(private.public_key())), private.sign(data))


def signature_state(
    checksums: bytes, signature_text: str | None, keys: dict[str, Ed25519PublicKey]
) -> tuple[SignatureState, str | None]:
    """State of SHA256SUMS.sig over the exact bytes of SHA256SUMS, with the key id it names."""
    if signature_text is None:
        return SignatureState.UNSIGNED, None
    try:
        sig = ReleaseSignature.from_text(signature_text)
    except ValueError:
        return SignatureState.INVALID, None
    key = keys.get(sig.key_id)
    if key is None:
        return SignatureState.UNKNOWN_KEY, sig.key_id
    try:
        key.verify(sig.signature, checksums)
    except InvalidSignature:
        return SignatureState.INVALID, sig.key_id
    return SignatureState.VALID, sig.key_id


def _regular(directory: Path, name: str) -> Path | None:
    """The file `name` of `directory` when it is a regular file, never through a symlink."""
    path = directory / name
    try:
        st = path.lstat()
    except FileNotFoundError:
        return None
    return path if stat.S_ISREG(st.st_mode) else None


def _read_small(path: Path, name: str) -> bytes:
    data = path.read_bytes()
    if len(data) > _MAX_SMALL:
        raise ReleaseRefused("checksum" if name == CHECKSUMS else "manifest", f"{name} is too large")
    return data


def file_sha256(path: Path) -> str:
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def verify_release(directory: Path, keys: dict[str, Ed25519PublicKey] | None = None) -> ReleaseCheck:
    """Check a release directory; raises ReleaseRefused (`checksum`, `missing`, `signature_invalid`,
    `manifest`, `unlisted`). Files not listed in SHA256SUMS are never read. An unsigned release or
    one signed by an unknown key passes here: the caller decides with `require_accepted`."""
    keys = load_public_keys() if keys is None else keys
    sums_path = _regular(directory, CHECKSUMS)
    if sums_path is None:
        raise ReleaseRefused("missing", f"no {CHECKSUMS}")
    sums_bytes = _read_small(sums_path, CHECKSUMS)
    try:
        sums = parse_checksums(sums_bytes.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ReleaseRefused("checksum", str(exc)) from None
    sig_path = _regular(directory, SIGNATURE)
    sig_text = None
    if sig_path is not None:
        try:
            sig_text = _read_small(sig_path, SIGNATURE).decode("utf-8")
        except (UnicodeDecodeError, ReleaseRefused):
            sig_text = ""  # malformed: INVALID below
    elif os.path.lexists(directory / SIGNATURE):
        raise ReleaseRefused("signature_invalid", f"{SIGNATURE} is not a regular file")
    state, kid = signature_state(sums_bytes, sig_text, keys)
    if state is SignatureState.INVALID:
        raise ReleaseRefused("signature_invalid", f"{SIGNATURE} does not verify {CHECKSUMS}")
    for name, expected in sums.items():
        if name in (CHECKSUMS, SIGNATURE):
            continue
        path = _regular(directory, name)
        if path is None:
            raise ReleaseRefused("missing", f"{name} is listed in {CHECKSUMS} but absent")
        if file_sha256(path) != expected:
            raise ReleaseRefused("checksum", f"{name} does not match {CHECKSUMS}")
    check = ReleaseCheck(state, kid, sums, hashlib.sha256(sums_bytes).hexdigest())
    if MANIFEST in sums:
        check.manifest = _manifest(directory / MANIFEST, sums)
    else:
        check.warnings.append(f"no {MANIFEST}: state schema unknown, no automatic rollback")
    return check


def _manifest(path: Path, sums: dict[str, str]) -> ReleaseManifest:
    try:
        data = json.loads(_read_small(path, MANIFEST))
        if not isinstance(data, dict) or not isinstance(data.get("packages", []), list):
            raise ValueError("not an object")
        data["packages"] = [ReleasePackage.from_dict(p) for p in data.get("packages", [])]
        manifest = ReleaseManifest.from_dict(data)
        problems = manifest.problems()
    except (ValueError, TypeError, AttributeError) as exc:
        raise ReleaseRefused("manifest", f"{MANIFEST} is malformed ({exc})") from None
    if problems:
        raise ReleaseRefused("manifest", "; ".join(problems))
    for p in manifest.packages:
        if p.file not in sums:
            raise ReleaseRefused("unlisted", f"{p.file} is not listed in {CHECKSUMS}")
    return manifest


def build_manifest(directory: Path, version: str, published_at: str | None = None) -> ReleaseManifest:
    """release.json for the packages found in `directory` (`make release` naming)."""
    packages: list[ReleasePackage] = []
    for path in sorted(directory.iterdir()):
        if m := _DEB.fullmatch(path.name):
            packages.append(ReleasePackage(path.name, "deb", m["arch"], m["version"]))
        elif m := _RPM.fullmatch(path.name):
            packages.append(ReleasePackage(path.name, "rpm", m["arch"], m["version"]))
    manifest = ReleaseManifest(
        version=version, state_schema=STATE_SCHEMA, packages=packages, published_at=published_at, notes=NOTES
    )
    if problems := manifest.problems():
        raise ValueError("; ".join(problems))
    return manifest


def write_manifest(directory: Path, manifest: ReleaseManifest) -> Path:
    data = {k: v for k, v in manifest.to_dict().items() if v is not None}
    path = directory / MANIFEST
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    return path


def sign_release(directory: Path, key_path: Path, password: str | None = None) -> ReleaseSignature:
    private = load_private_key(key_path, password)
    sig = sign_checksums((directory / CHECKSUMS).read_bytes(), private)
    (directory / SIGNATURE).write_text(sig.to_text())
    return sig


def generate_key(private_path: Path, public_dir: Path | None = None) -> str:
    """New Ed25519 key: private PEM PKCS#8 0600 (refuses to overwrite), public `<key id>.pub`."""
    private = Ed25519PrivateKey.generate()
    pem = private.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    private_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)
    kid = key_id(public_raw(private.public_key()))
    out = public_dir or private_path.parent
    (out / f"{kid}.pub").write_bytes(public_pem(private.public_key()))
    return kid


def main(argv: list[str] | None = None) -> int:
    """Release tooling for `scripts/release.sh`: keygen, manifest, sign, verify."""
    parser = argparse.ArgumentParser(prog="python -m pelagos.core.release")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("keygen", help="new Ed25519 release key (keep the private key out of the repository)")
    p.add_argument("private", type=Path)
    p.add_argument("--public-dir", type=Path)
    p = sub.add_parser("manifest", help=f"write {MANIFEST}")
    p.add_argument("directory", type=Path)
    p.add_argument("version")
    p.add_argument("--published-at")
    p = sub.add_parser("sign", help=f"sign {CHECKSUMS} when a key is given or in ${KEY_ENV}")
    p.add_argument("directory", type=Path)
    p.add_argument("--key", type=Path)
    p = sub.add_parser("verify", help="verify a release directory")
    p.add_argument("directory", type=Path)
    p.add_argument("--keys", type=Path, default=RELEASE_KEYS)
    args = parser.parse_args(argv)

    if args.cmd == "keygen":
        kid = generate_key(args.private, args.public_dir)
        public = (args.public_dir or args.private.parent) / f"{kid}.pub"
        print(f"key {kid}: private {args.private}, public {public}")
        print(f"ship the public key as backend/pelagos/data/release-keys/{kid}.pub")
        return 0
    if args.cmd == "manifest":
        try:
            path = write_manifest(
                args.directory, build_manifest(args.directory, args.version, args.published_at)
            )
        except ValueError as exc:
            print(f"release: {MANIFEST}: {exc}", file=sys.stderr)
            return 1
        print(f"release: wrote {path}", file=sys.stderr)
        return 0
    if args.cmd == "sign":
        key = args.key or (Path(os.environ[KEY_ENV]) if os.environ.get(KEY_ENV) else None)
        if key is None:
            print(f"release: no key (${KEY_ENV} unset): {CHECKSUMS} left unsigned", file=sys.stderr)
            return 0
        try:
            sig = sign_release(args.directory, key, os.environ.get(PASSWORD_ENV) or None)
        except (OSError, ValueError, TypeError, UnsupportedAlgorithm) as exc:
            print(f"release: cannot sign with {key}: {exc}", file=sys.stderr)
            return 1
        known = sig.key_id in load_public_keys()
        print(
            f"release: signed with key {sig.key_id}"
            + ("" if known else " (not in pelagos/data/release-keys: nodes will see an unknown key)"),
            file=sys.stderr,
        )
        return 0
    try:
        check = verify_release(args.directory, load_public_keys(args.keys))
    except ReleaseRefused as exc:
        print(json.dumps({"refused": exc.reason, "detail": exc.detail}))
        return 1
    print(
        json.dumps(
            {
                "signature": check.signature.value,
                "key_id": check.key_id,
                "version": check.manifest.version if check.manifest else None,
                "files": sorted(check.checksums),
                "warnings": check.warnings,
            }
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
