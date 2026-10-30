# SPDX-License-Identifier: Apache-2.0
"""Release signing and verification (section 29, batch U1): sums always checked, signature states
valid, unsigned, unknown key and invalid, key rotation, release.json, the `make release` tooling."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pelagos.core import release
from pelagos.core.release import ReleaseRefused, verify_release
from pelagos.domain.updates import (
    CHECKSUMS,
    MANIFEST,
    SIGNATURE,
    STATE_SCHEMA,
    ReleaseSignature,
    SignatureState,
)

pytestmark = pytest.mark.unit

DEBS = ("pelagos_0.3.0-1_amd64.deb", "pelagos_0.3.0-1_arm64.deb")


def _keys(*private: Ed25519PrivateKey) -> dict:
    return {release.key_id(release.public_raw(k.public_key())): k.public_key() for k in private}


def _write_sums(d: Path) -> None:
    names = sorted(p.name for p in d.iterdir() if p.name not in (CHECKSUMS, SIGNATURE))
    lines = [f"{hashlib.sha256((d / n).read_bytes()).hexdigest()}  {n}" for n in names]
    (d / CHECKSUMS).write_text("\n".join(lines) + "\n")


def _release(d: Path, key: Ed25519PrivateKey | None = None) -> Path:
    d.mkdir(parents=True, exist_ok=True)
    for name in DEBS:
        (d / name).write_bytes(b"deb " + name.encode())
    (d / "NOTES.md").write_text("# Pelagos 0.3.0\n")
    release.write_manifest(d, release.build_manifest(d, "0.3.0", "2026-10-30T00:00:00Z"))
    _write_sums(d)
    if key is not None:
        sig = release.sign_checksums((d / CHECKSUMS).read_bytes(), key)
        (d / SIGNATURE).write_text(sig.to_text())
    return d


def test_signed_by_a_known_key_is_valid(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    check = verify_release(_release(tmp_path, key), _keys(key))
    assert check.signature is SignatureState.VALID
    assert check.key_id == release.key_id(release.public_raw(key.public_key()))
    assert check.manifest is not None and check.manifest.version == "0.3.0"
    assert check.manifest.state_schema == STATE_SCHEMA
    assert {p.arch for p in check.manifest.packages} == {"amd64", "arm64"}
    assert check.checksums_sha256 == hashlib.sha256((tmp_path / CHECKSUMS).read_bytes()).hexdigest()
    check.require_accepted(allow_unsigned=False)


def test_unsigned_passes_only_once_accepted(tmp_path: Path) -> None:
    check = verify_release(_release(tmp_path), _keys(Ed25519PrivateKey.generate()))
    assert check.signature is SignatureState.UNSIGNED and check.key_id is None
    with pytest.raises(ReleaseRefused) as err:
        check.require_accepted(allow_unsigned=False)
    assert err.value.reason == "unsigned_not_accepted"
    check.require_accepted(allow_unsigned=True)


def test_unknown_key_needs_acceptance(tmp_path: Path) -> None:
    other = Ed25519PrivateKey.generate()
    check = verify_release(_release(tmp_path, other), _keys(Ed25519PrivateKey.generate()))
    assert check.signature is SignatureState.UNKNOWN_KEY
    assert check.key_id == release.key_id(release.public_raw(other.public_key()))
    assert check.signature.needs_acceptance


@pytest.mark.parametrize(
    "tamper",
    [
        lambda d: (d / CHECKSUMS).write_text((d / CHECKSUMS).read_text() + "0" * 64 + "  extra.txt\n"),
        lambda d: (d / SIGNATURE).write_text("not json"),
        lambda d: (d / SIGNATURE).write_text(json.dumps({"format": "other"})),
        lambda d: (d / SIGNATURE).write_bytes(b"\xff\xfe"),
    ],
    ids=["altered-sums", "not-json", "unknown-format", "not-utf8"],
)
def test_invalid_signature_is_refused(tmp_path: Path, tamper) -> None:
    key = Ed25519PrivateKey.generate()
    d = _release(tmp_path, key)
    (d / "extra.txt").write_text("x")
    tamper(d)
    with pytest.raises(ReleaseRefused) as err:
        verify_release(d, _keys(key))
    assert err.value.reason == "signature_invalid"


def test_signature_by_a_known_key_over_other_bytes_is_invalid(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    d = _release(tmp_path)
    forged = ReleaseSignature(release.key_id(release.public_raw(key.public_key())), key.sign(b"other"))
    (d / SIGNATURE).write_text(forged.to_text())
    with pytest.raises(ReleaseRefused, match=r"^signature_invalid"):
        verify_release(d, _keys(key))


def test_signature_that_is_not_a_regular_file_is_refused(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    d = _release(tmp_path / "r", key)
    (tmp_path / "elsewhere.sig").write_text((d / SIGNATURE).read_text())
    (d / SIGNATURE).unlink()
    (d / SIGNATURE).symlink_to(tmp_path / "elsewhere.sig")
    with pytest.raises(ReleaseRefused, match=r"^signature_invalid"):
        verify_release(d, _keys(key))


def test_key_rotation(tmp_path: Path) -> None:
    old, new = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    d = _release(tmp_path, new)
    assert verify_release(d, _keys(old, new)).signature is SignatureState.VALID
    assert verify_release(d, _keys(old)).signature is SignatureState.UNKNOWN_KEY


@pytest.mark.parametrize("key", [None, Ed25519PrivateKey.generate()], ids=["unsigned", "signed"])
def test_sums_are_always_checked(tmp_path: Path, key) -> None:
    d = _release(tmp_path / "a", key)
    (d / DEBS[0]).write_bytes(b"replaced")
    with pytest.raises(ReleaseRefused, match=r"^checksum"):
        verify_release(d, _keys(key) if key else {})
    d = _release(tmp_path / "b", key)
    (d / DEBS[1]).unlink()
    with pytest.raises(ReleaseRefused, match=r"^missing"):
        verify_release(d, _keys(key) if key else {})


def test_listed_symlink_is_missing_and_unlisted_files_are_ignored(tmp_path: Path) -> None:
    d = _release(tmp_path / "r")
    (d / "stray.deb").write_bytes(b"never read")
    assert "stray.deb" not in verify_release(d, {}).checksums
    target = tmp_path / "outside"
    target.write_bytes((d / DEBS[0]).read_bytes())
    (d / DEBS[0]).unlink()
    (d / DEBS[0]).symlink_to(target)
    with pytest.raises(ReleaseRefused, match=r"^missing"):
        verify_release(d, {})


def test_malformed_or_absent_sums(tmp_path: Path) -> None:
    with pytest.raises(ReleaseRefused, match=r"^missing"):
        verify_release(tmp_path, {})
    (tmp_path / CHECKSUMS).write_text("not a sum line\n")
    with pytest.raises(ReleaseRefused, match=r"^checksum"):
        verify_release(tmp_path, {})


@pytest.mark.parametrize(
    "body",
    [
        "[]",
        "{",
        json.dumps({"format": 1, "name": "pelagos", "version": "0.3.0", "state_schema": 1, "packages": [1]}),
        json.dumps({"format": 1, "name": "other", "version": "0.3.0", "state_schema": 1, "packages": []}),
        json.dumps({"format": 1, "name": "pelagos", "version": "0.3.0"}),
    ],
    ids=["array", "truncated", "package-not-object", "name", "no-schema"],
)
def test_bad_manifest_is_refused(tmp_path: Path, body: str) -> None:
    d = _release(tmp_path)
    (d / MANIFEST).write_text(body)
    _write_sums(d)
    with pytest.raises(ReleaseRefused, match=r"^manifest"):
        verify_release(d, {})


def test_manifest_package_must_be_listed(tmp_path: Path) -> None:
    d = _release(tmp_path)
    data = json.loads((d / MANIFEST).read_text())
    data["packages"][0]["file"] = "pelagos_0.3.0-1_amd64-other.deb"
    (d / MANIFEST).write_text(json.dumps(data))
    _write_sums(d)
    with pytest.raises(ReleaseRefused, match=r"^unlisted"):
        verify_release(d, {})


def test_release_without_manifest_warns(tmp_path: Path) -> None:
    d = _release(tmp_path)
    (d / MANIFEST).unlink()
    _write_sums(d)
    check = verify_release(d, {})
    assert check.manifest is None and check.warnings


def test_build_manifest_naming(tmp_path: Path) -> None:
    for name in ("pelagos_0.3.0~rc1-1_amd64.deb", "pelagos-0.3.0~rc1-1.el10.x86_64.rpm", "other_1_amd64.deb"):
        (tmp_path / name).write_bytes(b"x")
    m = release.build_manifest(tmp_path, "0.3.0~rc1")
    assert [(p.format, p.arch, p.version) for p in m.packages] == [
        ("rpm", "x86_64", "0.3.0~rc1-1.el10"),
        ("deb", "amd64", "0.3.0~rc1-1"),
    ]
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(ValueError, match="no package"):
        release.build_manifest(empty, "0.3.0")


def test_packaged_keys_load_and_skip_bad_files(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    kid = release.key_id(release.public_raw(key.public_key()))
    (tmp_path / "misnamed.pub").write_bytes(release.public_pem(key.public_key()))
    (tmp_path / "junk.pub").write_text("not a key")
    from cryptography.hazmat.primitives.asymmetric import ec

    ec_key = ec.generate_private_key(ec.SECP256R1()).public_key()
    (tmp_path / "ec.pub").write_bytes(
        ec_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    assert list(release.load_public_keys(tmp_path)) == [kid]
    assert release.load_public_keys(tmp_path / "absent") == {}
    # The shipped directory holds only well-formed Ed25519 public keys named by their id.
    for path in release.RELEASE_KEYS.glob("*.pub"):
        assert path.stem in release.load_public_keys(release.RELEASE_KEYS)
    assert not list(release.RELEASE_KEYS.glob("*.pem")) and not list(release.RELEASE_KEYS.glob("*.key"))


def test_cli_sign_without_key_is_not_an_error(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.delenv(release.KEY_ENV, raising=False)
    d = _release(tmp_path)
    assert release.main(["sign", str(d)]) == 0
    assert not (d / SIGNATURE).exists()
    assert "unsigned" in capsys.readouterr().err
    assert release.main(["verify", str(d), "--keys", str(tmp_path / "none")]) == 0
    assert json.loads(capsys.readouterr().out)["signature"] == "unsigned"


def test_cli_keygen_sign_verify(tmp_path: Path, monkeypatch, capsys) -> None:
    private = tmp_path / "secret" / "release-key.pem"
    keys = tmp_path / "keys"
    keys.mkdir()
    assert release.main(["keygen", str(private), "--public-dir", str(keys)]) == 0
    assert private.stat().st_mode & 0o777 == 0o600
    assert private.parent.stat().st_mode & 0o777 == 0o700
    with pytest.raises(FileExistsError):
        release.main(["keygen", str(private)])
    d = _release(tmp_path / "rel")
    monkeypatch.setenv(release.KEY_ENV, str(private))
    assert release.main(["sign", str(d)]) == 0
    capsys.readouterr()
    assert release.main(["verify", str(d), "--keys", str(keys)]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["signature"] == "valid" and out["version"] == "0.3.0"
    (d / DEBS[0]).write_bytes(b"altered")
    assert release.main(["verify", str(d), "--keys", str(keys)]) == 1
    assert json.loads(capsys.readouterr().out)["refused"] == "checksum"


def test_cli_sign_with_bad_key_fails(tmp_path: Path, monkeypatch) -> None:
    bad = tmp_path / "bad.pem"
    bad.write_text("garbage")
    d = _release(tmp_path / "rel")
    monkeypatch.setenv(release.KEY_ENV, str(bad))
    assert release.main(["sign", str(d)]) == 1
    monkeypatch.setenv(release.KEY_ENV, str(tmp_path / "absent.pem"))
    assert release.main(["sign", str(d)]) == 1
    assert not (d / SIGNATURE).exists()


def test_openssh_and_encrypted_private_keys(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    ssh = tmp_path / "id_ed25519"
    ssh.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption()
        )
    )
    enc = tmp_path / "enc.pem"
    enc.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(b"pass"),
        )
    )
    raw = release.public_raw(key.public_key())
    assert release.public_raw(release.load_private_key(ssh).public_key()) == raw
    assert release.public_raw(release.load_private_key(enc, "pass").public_key()) == raw
    with pytest.raises((TypeError, ValueError)):
        release.load_private_key(enc)
    ec_path = tmp_path / "ec.pem"
    from cryptography.hazmat.primitives.asymmetric import ec

    ec_path.write_bytes(
        ec.generate_private_key(ec.SECP256R1()).private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    with pytest.raises(ValueError, match="not an Ed25519"):
        release.load_private_key(ec_path)
