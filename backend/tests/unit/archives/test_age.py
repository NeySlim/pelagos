# SPDX-License-Identifier: Apache-2.0
"""age v1 format: CCTV vectors, round trips, chunk boundaries, keys, interoperability with `age`."""

from __future__ import annotations

import hashlib
import io
import shutil
import subprocess
import zlib
from pathlib import Path

import pytest

from pelagos.archives import age

pytestmark = pytest.mark.unit

VECTORS = Path(__file__).parent / "data" / "cctv_age"
AGE = shutil.which("age")
needs_age = pytest.mark.skipif(AGE is None, reason="the age tool is not installed (apt install age)")

# From the spec (https://age-encryption.org/v1, X25519 recipient type).
SPEC_IDENTITY = "AGE-SECRET-KEY-1GFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPQ4EGAEX"
SPEC_RECIPIENT = "age1zvkyg2lqzraa2lnjvqej32nkuu0ues2s82hzrye869xeexvn73equnujwj"

EXPECT = {
    "success": None,
    "no match": age.AgeNoMatchError,
    "HMAC failure": age.AgeHmacError,
    "header failure": age.AgeHeaderError,
    "payload failure": age.AgePayloadError,
}


def _vector(path: Path) -> tuple[dict[str, str], list[str], bytes]:
    head, _, body = path.read_bytes().partition(b"\n\n")
    meta: dict[str, str] = {}
    identities = []
    for line in head.decode().splitlines():
        key, _, value = line.partition(": ")
        if key == "identity":
            identities.append(value)
        else:
            meta.setdefault(key, value)
    if meta.get("compressed") == "zlib":
        body = zlib.decompress(body)
    return meta, identities, body


@pytest.mark.parametrize(
    "path",
    sorted(p for p in VECTORS.iterdir() if p.suffix != ".md" and not p.name.startswith(".")),
    ids=lambda p: p.name,
)
def test_cctv_vector(path: Path) -> None:
    meta, identities, body = _vector(path)
    identities = identities or [age.generate_identity()]
    error = EXPECT[meta["expect"]]
    released = bytearray()
    try:
        for chunk in age.Decryptor(io.BytesIO(body), identities).chunks():
            released += chunk
    except age.AgeError as exc:
        assert error is not None and type(exc) is error, f"{type(exc).__name__}: {exc}"
    else:
        assert error is None, f"expected {meta['expect']}"
    if "payload" in meta:
        # Everything released before a failure must match the expected plaintext.
        assert hashlib.sha256(released).hexdigest() == meta["payload"]


def test_vector_set_is_complete() -> None:
    names = {p.name for p in VECTORS.iterdir()}
    assert {"x25519", "x25519_multiple_recipients", "stream_258_chunks", "hmac_bad", "empty"} <= names
    assert len(names) >= 60


def test_spec_key_pair() -> None:
    assert age.recipient_of(SPEC_IDENTITY) == SPEC_RECIPIENT
    assert age.is_identity(SPEC_IDENTITY) and not age.is_identity(SPEC_RECIPIENT)
    assert age.is_recipient(SPEC_RECIPIENT) and not age.is_recipient(SPEC_IDENTITY)
    assert not age.is_recipient(SPEC_RECIPIENT.upper())
    assert not age.is_recipient(SPEC_RECIPIENT[:-1] + "q")  # checksum
    assert not age.is_recipient("age1" + "q" * 10)


def test_generated_identity_shape() -> None:
    identity = age.generate_identity()
    assert identity.startswith("AGE-SECRET-KEY-1") and identity == identity.upper()
    assert age.recipient_of(identity).startswith("age1")
    assert age.generate_identity() != identity


def test_parse_identities_file() -> None:
    identity = age.generate_identity()
    text = f"# created: 2026-10-28\n# public key: {age.recipient_of(identity)}\n\n{identity}\n"
    assert age.parse_identities(text) == [identity]
    with pytest.raises(age.AgeKeyError):
        age.parse_identities("# nothing\n")
    with pytest.raises(age.AgeKeyError):
        age.parse_identities("AGE-SECRET-KEY-1NOTAKEY\n")


@pytest.mark.parametrize("size", [0, 1, age.CHUNK - 1, age.CHUNK, age.CHUNK + 1, 3 * age.CHUNK, 200_000])
def test_round_trip_sizes(size: int) -> None:
    identity = age.generate_identity()
    data = bytes(i % 251 for i in range(size))
    blob = age.encrypt(data, [age.recipient_of(identity)])
    assert age.decrypt(blob, [identity]) == data
    header_end = blob.index(b"\n---") + 1 + 48
    chunks = max(1, -(-size // age.CHUNK))
    assert len(blob) == header_end + 16 + size + chunks * age.TAG


def test_multiple_recipients_each_decrypt() -> None:
    ids = [age.generate_identity() for _ in range(3)]
    blob = age.encrypt(b"secret", [age.recipient_of(i) for i in ids])
    assert blob.count(b"\n-> X25519 ") == 3
    for identity in ids:
        assert age.decrypt(blob, [identity]) == b"secret"
    with pytest.raises(age.AgeNoMatchError):
        age.decrypt(blob, [age.generate_identity()])
    # Any matching identity among several is enough.
    assert age.decrypt(blob, [age.generate_identity(), ids[2]]) == b"secret"


def test_streaming_writes_and_reads() -> None:
    identity = age.generate_identity()
    out = io.BytesIO()
    with age.Encryptor(out, [age.recipient_of(identity)]) as enc:
        for _ in range(10):
            enc.write(b"x" * 10_000)
    dec = age.Decryptor(io.BytesIO(out.getvalue()), [identity])
    parts = []
    while data := dec.read(7_000):
        parts.append(data)
    assert b"".join(parts) == b"x" * 100_000


@pytest.mark.parametrize("cut", [1, age.TAG, age.CHUNK])
def test_truncated_file_refused(cut: int) -> None:
    identity = age.generate_identity()
    blob = age.encrypt(b"z" * (2 * age.CHUNK + 5), [age.recipient_of(identity)])
    with pytest.raises(age.AgePayloadError):
        age.decrypt(blob[:-cut], [identity])


def test_truncated_at_chunk_boundary_refused() -> None:
    identity = age.generate_identity()
    blob = age.encrypt(b"z" * (2 * age.CHUNK + 5), [age.recipient_of(identity)])
    header = len(blob) - 16 - (2 * age.CHUNK + 5) - 3 * age.TAG
    with pytest.raises(age.AgePayloadError):
        age.decrypt(blob[: header + 16 + age.ENC_CHUNK], [identity])


def test_tampered_payload_and_header() -> None:
    identity = age.generate_identity()
    blob = bytearray(age.encrypt(b"payload", [age.recipient_of(identity)]))
    tampered = bytes(blob[:-1]) + bytes([blob[-1] ^ 1])
    with pytest.raises(age.AgePayloadError):
        age.decrypt(tampered, [identity])
    with pytest.raises(age.AgeHeaderError):
        age.decrypt(b"age-encryption.org/v2\n" + bytes(blob[22:]), [identity])
    with pytest.raises(age.AgeError):
        age.decrypt(b"not an age file", [identity])


def test_encrypt_needs_valid_recipients() -> None:
    with pytest.raises(age.AgeKeyError):
        age.encrypt(b"x", [])
    with pytest.raises(age.AgeKeyError):
        age.encrypt(b"x", [SPEC_IDENTITY])


# Interoperability with the reference tool ---------------------------------------------


def _run(args: list[str], data: bytes = b"") -> bytes:
    return subprocess.run(args, input=data, capture_output=True, check=True, timeout=60).stdout


@needs_age
@pytest.mark.parametrize("size", [0, 5, age.CHUNK, age.CHUNK + 1, 300_000])
def test_age_tool_decrypts_ours(tmp_path: Path, size: int) -> None:
    ids = [age.generate_identity(), age.generate_identity()]
    data = bytes((i * 7) % 256 for i in range(size))
    blob = age.encrypt(data, [age.recipient_of(i) for i in ids])
    (tmp_path / "f.age").write_bytes(blob)
    for n, identity in enumerate(ids):
        key = tmp_path / f"k{n}"
        key.write_text(identity + "\n")
        assert _run([AGE, "-d", "-i", str(key), str(tmp_path / "f.age")]) == data


@needs_age
@pytest.mark.parametrize("size", [0, 5, age.CHUNK, age.CHUNK + 1, 300_000])
def test_we_decrypt_age_tool_output(size: int) -> None:
    ids = [age.generate_identity(), age.generate_identity()]
    data = bytes((i * 13) % 256 for i in range(size))
    args = [AGE, "-e"]
    for identity in ids:
        args += ["-r", age.recipient_of(identity)]
    blob = _run(args, data)
    for identity in ids:
        assert age.decrypt(blob, [identity]) == data


@needs_age
def test_age_keygen_keys_match(tmp_path: Path) -> None:
    keygen = shutil.which("age-keygen")
    if keygen is None:
        pytest.skip("age-keygen is not installed")
    key = tmp_path / "key.txt"
    _run([keygen, "-o", str(key)])
    identities = age.parse_identities(key.read_text())
    assert _run([keygen, "-y", str(key)]).decode().strip() == age.recipient_of(identities[0])
    blob = age.encrypt(b"hello", [age.recipient_of(identities[0])])
    assert _run([AGE, "-d", "-i", str(key)], blob) == b"hello"
    ours = tmp_path / "ours.txt"
    ours.write_text(age.generate_identity() + "\n")
    assert _run([keygen, "-y", str(ours)]).decode().strip() == age.recipient_of(ours.read_text().strip())
