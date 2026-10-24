# SPDX-License-Identifier: Apache-2.0
"""In-place rewrites (a directory we may not write) leave a journal a crash can be recovered from."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from pelagos.core import write_pipeline as wp
from pelagos.domain.plan import ValidationResult

pytestmark = pytest.mark.unit


def _pipeline(root: Path) -> wp.WritePipeline:
    return wp.WritePipeline(
        root,
        validate=lambda: ValidationResult(ok=True, tool="none"),
        reload=lambda: "ok",
        label="t",
    )


@pytest.mark.skipif(os.geteuid() == 0, reason="root writes any directory")
def test_read_only_directory_writes_in_place_and_leaves_no_journal(tmp_path):
    conf_dir = tmp_path / "kea"
    conf_dir.mkdir()
    conf = conf_dir / "kea-dhcp4.conf"
    conf.write_text('{"Dhcp4": {"valid-lifetime": 4000}}\n' * 20)
    conf.chmod(0o660)
    conf_dir.chmod(0o550)
    try:
        result = _pipeline(tmp_path / "backups").run([wp.FileChange(path=conf, content=b"{}\n")])
        assert result.ok, result.error
        assert conf.read_bytes() == b"{}\n"
        assert not any((tmp_path / "backups" / wp.JOURNAL_DIR).glob("*"))
    finally:
        conf_dir.chmod(0o750)


def test_crash_mid_write_is_recovered(tmp_path):
    backups = tmp_path / "backups"
    journal_dir = backups / "kea" / wp.JOURNAL_DIR
    journal_dir.mkdir(parents=True)
    conf = tmp_path / "kea-dhcp4.conf"
    old, new = b'{"Dhcp4": {"a": 1}}\n', b'{"Dhcp4": {"a": 2, "b": 3}}\n'
    conf.write_bytes(new[:7])  # the crash cut the write
    name = wp._journal_name(conf)
    (journal_dir / f"{name}.old").write_bytes(old)
    (journal_dir / f"{name}.json").write_text(
        json.dumps(
            {
                "path": str(conf),
                "old": str(journal_dir / f"{name}.old"),
                "old_sha256": hashlib.sha256(old).hexdigest(),
                "new_sha256": hashlib.sha256(new).hexdigest(),
            }
        )
    )
    assert wp.recover_in_place_writes(backups) == [str(conf)]
    assert conf.read_bytes() == old and not any(journal_dir.iterdir())


def test_completed_write_with_a_stale_journal_is_kept(tmp_path):
    backups = tmp_path / "backups"
    journal_dir = backups / wp.JOURNAL_DIR
    conf = tmp_path / "x.conf"
    conf.write_bytes(b"old")
    wp._write_in_place(conf, b"new content", journal_dir)
    assert conf.read_bytes() == b"new content" and not any(journal_dir.iterdir())
    # Crash after the write but before the journal was removed: the new file stays.
    name = wp._journal_name(conf)
    (journal_dir / f"{name}.old").write_bytes(b"old")
    (journal_dir / f"{name}.json").write_text(
        json.dumps(
            {
                "path": str(conf),
                "old": str(journal_dir / f"{name}.old"),
                "old_sha256": hashlib.sha256(b"old").hexdigest(),
                "new_sha256": hashlib.sha256(b"new content").hexdigest(),
            }
        )
    )
    assert wp.recover_in_place_writes(backups) == [] and conf.read_bytes() == b"new content"
    assert not any(journal_dir.iterdir())
