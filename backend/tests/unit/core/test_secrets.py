# SPDX-License-Identifier: Apache-2.0
"""SecretBox: AES-GCM round trip, name binding, key file permissions."""

from __future__ import annotations

import pytest

from pelagos.core.secrets import SecretBox, SecretError, is_encrypted, write_master_key

pytestmark = pytest.mark.unit


def test_round_trip_and_name_binding(tmp_root):
    key_path = tmp_root / "master.key"
    write_master_key(key_path)
    box = SecretBox.from_file(key_path)
    token = box.encrypt("tsig/ddi-admin", "s3cret")
    assert is_encrypted(token) and token.startswith("enc:v1:")
    assert box.decrypt("tsig/ddi-admin", token) == "s3cret"
    with pytest.raises(SecretError):
        box.decrypt("tsig/other", token)
    with pytest.raises(SecretError):
        SecretBox.from_b64(write_master_key(tmp_root / "k2")).decrypt("tsig/ddi-admin", token)


def test_loose_permissions_refused(tmp_root):
    key_path = tmp_root / "master.key"
    write_master_key(key_path)
    key_path.chmod(0o644)
    with pytest.raises(SecretError):
        SecretBox.from_file(key_path)
