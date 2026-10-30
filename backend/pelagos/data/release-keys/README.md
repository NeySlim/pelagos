# Release public keys

Ed25519 public keys accepted for `SHA256SUMS.sig` (docs/architecture.md section 29): one
`<key id>.pub` per key, PEM SubjectPublicKeyInfo, where the key id is the first 16 hex digits of
sha256 of the 32 raw bytes of the key. The id is computed from the key, never from the file name.

Only public keys belong here. The private key stays outside the repository and is read by
`make release` from `PELAGOS_RELEASE_KEY`. Create one with:

    backend/.venv/bin/python -m pelagos.core.release keygen ~/.config/pelagos-release/release-key.pem

A new key is shipped in a release signed by the previous one.
