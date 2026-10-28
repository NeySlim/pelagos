# SPDX-License-Identifier: Apache-2.0
"""age v1 file encryption, X25519 recipients only, over `cryptography`.

Spec: https://age-encryption.org/v1 (C2SP age.md, editor's copy fetched 2026-10-28). Checked
against the CCTV test vectors (https://github.com/C2SP/CCTV/tree/main/age) and the `age` 1.2.1 tool.
"""

from __future__ import annotations

import base64
import binascii
import hmac
import os
from collections.abc import Iterator, Sequence
from hashlib import sha256
from typing import BinaryIO

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

INTRO = b"age-encryption.org/v1\n"
CHUNK = 64 * 1024
TAG = 16
ENC_CHUNK = CHUNK + TAG
IDENTITY_HRP = "AGE-SECRET-KEY-"
RECIPIENT_HRP = "age"
X25519_INFO = b"age-encryption.org/v1/X25519"
_MAX_LINE = 8192
_MAX_STANZAS = 1024
_B64_CHARS = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")


class AgeError(Exception):
    """Any failure to read or write an age file."""


class AgeKeyError(AgeError):
    """An identity or recipient string that is not a valid X25519 age key."""


class AgeHeaderError(AgeError):
    """The header does not parse, or a stanza addressed to us is malformed."""


class AgeNoMatchError(AgeError):
    """The header parses but no identity unwraps any stanza."""


class AgeHmacError(AgeError):
    """A file key was unwrapped but the header MAC does not match."""


class AgePayloadError(AgeError):
    """The payload is truncated, tampered with or has trailing data."""


# Bech32 (BIP 173) without the 90 character limit, as age requires.
_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_GEN = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)


def _polymod(values: Sequence[int]) -> int:
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= _GEN[i] if (top >> i) & 1 else 0
    return chk


def _hrp_expand(hrp: str) -> list[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _convert(data: bytes | Sequence[int], frm: int, to: int, pad: bool) -> list[int]:
    acc = bits = 0
    out: list[int] = []
    maxv = (1 << to) - 1
    for value in data:
        acc = (acc << frm) | value
        bits += frm
        while bits >= to:
            bits -= to
            out.append((acc >> bits) & maxv)
    if pad:
        if bits:
            out.append((acc << (to - bits)) & maxv)
    elif bits >= frm or (acc << (to - bits)) & maxv:
        raise AgeKeyError("invalid bech32 padding")
    return out


def bech32_encode(hrp: str, data: bytes) -> str:
    hrp = hrp.lower()
    words = _convert(data, 8, 5, True)
    poly = _polymod(_hrp_expand(hrp) + words + [0] * 6) ^ 1
    checksum = [(poly >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(_CHARSET[w] for w in words + checksum)


def bech32_decode(text: str) -> tuple[str, bytes]:
    if text.lower() != text and text.upper() != text:
        raise AgeKeyError("mixed case bech32 string")
    if any(ord(c) < 33 or ord(c) > 126 for c in text):
        raise AgeKeyError("invalid character in bech32 string")
    low = text.lower()
    pos = low.rfind("1")
    if pos < 1 or pos + 7 > len(low):
        raise AgeKeyError("malformed bech32 string")
    hrp, rest = low[:pos], low[pos + 1 :]
    try:
        words = [_CHARSET.index(c) for c in rest]
    except ValueError as exc:
        raise AgeKeyError("invalid bech32 character") from exc
    if _polymod(_hrp_expand(hrp) + words) != 1:
        raise AgeKeyError("bad bech32 checksum")
    return hrp, bytes(_convert(words[:-6], 5, 8, False))


# Keys -------------------------------------------------------------------------------


def generate_identity() -> str:
    """A new identity, `AGE-SECRET-KEY-1...` (32 random bytes)."""
    return bech32_encode(IDENTITY_HRP, os.urandom(32)).upper()


def _identity_key(identity: str) -> X25519PrivateKey:
    hrp, raw = bech32_decode(identity.strip())
    if hrp != IDENTITY_HRP.lower() or len(raw) != 32:
        raise AgeKeyError("not an age X25519 identity")
    return X25519PrivateKey.from_private_bytes(raw)


def _recipient_key(recipient: str) -> bytes:
    hrp, raw = bech32_decode(recipient.strip())
    if hrp != RECIPIENT_HRP or len(raw) != 32 or recipient.strip() != recipient.strip().lower():
        raise AgeKeyError("not an age X25519 recipient")
    return raw


def recipient_of(identity: str) -> str:
    """The public `age1...` recipient of an identity."""
    pub = _identity_key(identity).public_key().public_bytes_raw()
    return bech32_encode(RECIPIENT_HRP, pub)


def is_recipient(text: str) -> bool:
    try:
        _recipient_key(text)
    except AgeKeyError:
        return False
    return True


def is_identity(text: str) -> bool:
    try:
        _identity_key(text)
    except AgeKeyError:
        return False
    return True


def parse_identities(text: str) -> list[str]:
    """Identities of an `age-keygen` file: one per line, `#` comments and blank lines skipped."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        _identity_key(line)
        out.append(line)
    if not out:
        raise AgeKeyError("no identity found")
    return out


# Primitives ---------------------------------------------------------------------------


def _hkdf(ikm: bytes, salt: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt or None, info=info).derive(ikm)


def _b64(data: bytes) -> bytes:
    return base64.b64encode(data).rstrip(b"=")


def _b64decode(text: bytes) -> bytes:
    """Canonical unpadded standard base64, as the spec requires."""
    if any(c not in _B64_CHARS for c in text) or len(text) % 4 == 1:
        raise AgeHeaderError("invalid base64")
    try:
        raw = base64.b64decode(text + b"=" * (-len(text) % 4), validate=True)
    except binascii.Error as exc:
        raise AgeHeaderError("invalid base64") from exc
    if _b64(raw) != text:
        raise AgeHeaderError("non canonical base64")
    return raw


def _nonce(counter: int, last: bool) -> bytes:
    return counter.to_bytes(11, "big") + (b"\x01" if last else b"\x00")


def _wrap_x25519(file_key: bytes, recipient: bytes) -> tuple[list[bytes], bytes]:
    eph = X25519PrivateKey.generate()
    share = eph.public_key().public_bytes_raw()
    shared = eph.exchange(X25519PublicKey.from_public_bytes(recipient))
    key = _hkdf(shared, share + recipient, X25519_INFO)
    return [b"X25519", _b64(share)], ChaCha20Poly1305(key).encrypt(b"\x00" * 12, file_key, None)


def _stanza_bytes(args: list[bytes], body: bytes) -> bytes:
    enc = _b64(body)
    lines = [enc[i : i + 64] for i in range(0, len(enc), 64)]
    if not lines or len(lines[-1]) == 64:
        lines.append(b"")
    return b"-> " + b" ".join(args) + b"\n" + b"".join(line + b"\n" for line in lines)


# Writing ------------------------------------------------------------------------------


class Encryptor:
    """Writable stream: encrypts to every recipient, 64 KiB chunks, closed by `close()`."""

    def __init__(self, out: BinaryIO, recipients: Sequence[str]) -> None:
        if not recipients:
            raise AgeKeyError("at least one recipient is required")
        keys = [_recipient_key(r) for r in recipients]
        file_key = os.urandom(16)
        header = INTRO + b"".join(_stanza_bytes(*_wrap_x25519(file_key, k)) for k in keys) + b"---"
        mac = hmac.new(_hkdf(file_key, b"", b"header"), header, sha256).digest()
        nonce = os.urandom(16)
        out.write(header + b" " + _b64(mac) + b"\n" + nonce)
        self._out = out
        self._aead = ChaCha20Poly1305(_hkdf(file_key, nonce, b"payload"))
        self._buf = bytearray()
        self._counter = 0
        self._closed = False

    def write(self, data: bytes) -> int:
        if self._closed:
            raise ValueError("write to a closed age stream")
        self._buf += data
        # Keep at least one byte back: the final chunk is only known at close.
        while len(self._buf) > CHUNK:
            self._emit(bytes(self._buf[:CHUNK]), last=False)
            del self._buf[:CHUNK]
        return len(data)

    def _emit(self, chunk: bytes, last: bool) -> None:
        self._out.write(self._aead.encrypt(_nonce(self._counter, last), chunk, None))
        self._counter += 1

    def flush(self) -> None:
        self._out.flush()

    def close(self) -> None:
        if not self._closed:
            self._emit(bytes(self._buf), last=True)
            self._buf.clear()
            self._closed = True

    def __enter__(self) -> Encryptor:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def encrypt(data: bytes, recipients: Sequence[str]) -> bytes:
    import io

    out = io.BytesIO()
    with Encryptor(out, recipients) as enc:
        enc.write(data)
    return out.getvalue()


# Reading ------------------------------------------------------------------------------


def _readline(src: BinaryIO) -> bytes:
    line = src.readline(_MAX_LINE)
    if not line.endswith(b"\n"):
        raise AgeHeaderError("truncated or overlong header line")
    return line


def _check_arg(arg: bytes) -> bytes:
    if not arg or any(c < 33 or c > 126 for c in arg):
        raise AgeHeaderError("invalid stanza argument")
    return arg


def parse_header(src: BinaryIO) -> tuple[list[tuple[list[bytes], bytes]], bytes, bytes]:
    """Reads the header: (stanzas as (args, body), MAC, the bytes the MAC covers)."""
    first = src.readline(_MAX_LINE)
    if first != INTRO:
        if first.startswith(b"age-encryption.org/"):
            raise AgeHeaderError("unsupported age version")
        raise AgeHeaderError("not an age file")
    raw = bytearray(first)
    stanzas: list[tuple[list[bytes], bytes]] = []
    while True:
        line = _readline(src)
        if line.startswith(b"---"):
            raw += b"---"
            if len(line) != 48 or line[3:4] != b" ":
                raise AgeHeaderError("malformed header MAC line")
            mac = _b64decode(line[4:-1])
            break
        if not line.startswith(b"-> "):
            raise AgeHeaderError("malformed stanza")
        if len(stanzas) >= _MAX_STANZAS:
            raise AgeHeaderError("too many stanzas")
        raw += line
        args = [_check_arg(a) for a in line[3:-1].split(b" ")]
        body = bytearray()
        while True:
            bline = _readline(src)
            raw += bline
            text = bline[:-1]
            if len(text) > 64:
                raise AgeHeaderError("stanza body line longer than 64 columns")
            body += text
            if len(text) < 64:
                break
        stanzas.append((args, _b64decode(bytes(body))))
    if not stanzas:
        raise AgeHeaderError("no recipient stanza")
    return stanzas, mac, bytes(raw)


def _unwrap(stanzas: list[tuple[list[bytes], bytes]], keys: list[X25519PrivateKey]) -> bytes:
    if any(args[0] == b"scrypt" for args, _ in stanzas) and len(stanzas) > 1:
        raise AgeHeaderError("an scrypt stanza must be alone")
    for key in keys:
        own = key.public_key().public_bytes_raw()
        for args, body in stanzas:
            if args[0] != b"X25519":
                continue
            if len(args) != 2:
                raise AgeHeaderError("X25519 stanza needs exactly two arguments")
            share = _b64decode(args[1])
            if len(share) != 32 or len(body) != 32:
                raise AgeHeaderError("malformed X25519 stanza")
            try:
                shared = key.exchange(X25519PublicKey.from_public_bytes(share))
            except ValueError as exc:
                raise AgeHeaderError("low order X25519 share") from exc
            if shared == b"\x00" * 32:
                raise AgeHeaderError("low order X25519 share")
            wrap = _hkdf(shared, share + own, X25519_INFO)
            try:
                return ChaCha20Poly1305(wrap).decrypt(b"\x00" * 12, body, None)
            except InvalidTag:
                continue
    raise AgeNoMatchError("no identity matches any recipient of this file")


def _read_full(src: BinaryIO, size: int) -> bytes:
    parts = []
    while size:
        data = src.read(size)
        if not data:
            break
        parts.append(data)
        size -= len(data)
    return b"".join(parts)


class Decryptor:
    """Readable stream over the plaintext; the header is checked on construction.

    Plaintext is released chunk by chunk, each authenticated; a later failure raises
    `AgePayloadError` after the chunks already returned."""

    def __init__(self, src: BinaryIO, identities: Sequence[str]) -> None:
        keys = [_identity_key(i) for i in identities]
        if not keys:
            raise AgeKeyError("at least one identity is required")
        stanzas, mac, raw = parse_header(src)
        file_key = _unwrap(stanzas, keys)
        expected = hmac.new(_hkdf(file_key, b"", b"header"), raw, sha256).digest()
        if not hmac.compare_digest(expected, mac):
            raise AgeHmacError("header MAC mismatch")
        nonce = _read_full(src, 16)
        if len(nonce) != 16:
            raise AgeHeaderError("missing payload nonce")
        self._src = src
        self._aead = ChaCha20Poly1305(_hkdf(file_key, nonce, b"payload"))
        self._chunks = self._iter()
        self._pending = b""
        self._eof = False

    def _iter(self) -> Iterator[bytes]:
        counter = 0
        while True:
            data = _read_full(self._src, ENC_CHUNK)
            last = len(data) < ENC_CHUNK
            if not data:
                raise AgePayloadError("truncated payload: no final chunk")
            if last and counter and len(data) == TAG:
                raise AgePayloadError("empty final chunk")
            try:
                out = self._aead.decrypt(_nonce(counter, last), data, None)
            except InvalidTag:
                if last:
                    raise AgePayloadError("payload chunk fails authentication") from None
                try:
                    out = self._aead.decrypt(_nonce(counter, True), data, None)
                except InvalidTag:
                    raise AgePayloadError("payload chunk fails authentication") from None
                last = True
            yield out
            if last:
                if self._src.read(1):
                    raise AgePayloadError("trailing data after the final chunk")
                return
            counter += 1

    def chunks(self) -> Iterator[bytes]:
        if self._pending:
            yield self._pending
            self._pending = b""
        yield from self._chunks

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            return b"".join(self.chunks())
        while len(self._pending) < size and not self._eof:
            try:
                self._pending += next(self._chunks)
            except StopIteration:
                self._eof = True
        out, self._pending = self._pending[:size], self._pending[size:]
        return out

    def readable(self) -> bool:
        return True


def decrypt(data: bytes, identities: Sequence[str]) -> bytes:
    import io

    return Decryptor(io.BytesIO(data), identities).read()
