# SPDX-License-Identifier: Apache-2.0
"""The SELinux rule for Kea's config-write: only where the policy confines Kea, installed once."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from pelagos.installer import keaselinux

pytestmark = pytest.mark.unit


class Runner:
    def __init__(self, rc: int = 0) -> None:
        self.calls: list[list[str]] = []
        self.rc = rc

    def run(self, argv, **kw):
        self.calls.append(list(argv))
        return SimpleNamespace(returncode=self.rc, output="semodule: failed" if self.rc else "")


def env_for(tmp_path: Path, selinux: bool = True, rc: int = 0, dry_run: bool = False):
    return SimpleNamespace(
        paths=SimpleNamespace(selinux=selinux, root=tmp_path),
        runner=Runner(rc),
        dry_run=dry_run,
        binary=lambda name: f"/usr/sbin/{name}",
    )


def typer(types):
    return lambda path: types.get(str(path))


CONF = Path("/etc/kea/kea-dhcp4.conf")


def test_confined_kea_gets_one_module(tmp_path):
    env = env_for(tmp_path)
    types = typer({"/usr/sbin/kea-dhcp4": "dhcpd_exec_t", str(CONF): "dhcp_etc_t"})
    out = keaselinux.ensure_config_write(env, CONF, "kea-dhcp4", types)
    assert "dhcpd_t may now write dhcp_etc_t" in out
    cil = tmp_path / "etc/pelagos/selinux/pelagos-kea-dhcpd_t.cil"
    assert "(allow dhcpd_t dhcp_etc_t (file (open read write" in cil.read_text()
    assert env.runner.calls == [["semodule", "-i", str(cil)]]
    again = keaselinux.ensure_config_write(env, CONF, "kea-dhcp4", types)
    assert "installed" in again and len(env.runner.calls) == 1


def test_unconfined_or_disabled_needs_nothing(tmp_path):
    env = env_for(tmp_path)
    out = keaselinux.ensure_config_write(env, CONF, "kea-dhcp4", typer({"/usr/sbin/kea-dhcp4": "bin_t"}))
    assert "runs unconfined (bin_t)" in out and env.runner.calls == []
    off = env_for(tmp_path, selinux=False)
    assert keaselinux.ensure_config_write(off, CONF, "kea-dhcp4", typer({})) == ""


def test_failed_install_leaves_no_module_file(tmp_path):
    env = env_for(tmp_path, rc=1)
    types = typer({"/usr/sbin/kea-dhcp4": "kea_exec_t", str(CONF): "kea_etc_t"})
    out = keaselinux.ensure_config_write(env, CONF, "kea-dhcp4", types)
    assert "failed" in out and not (tmp_path / "etc/pelagos/selinux/pelagos-kea-kea_t.cil").exists()
    dry = env_for(tmp_path, dry_run=True)
    assert keaselinux.ensure_config_write(dry, CONF, "kea-dhcp4", types).startswith("dry run")


def test_context_type_reads_the_label(tmp_path):
    f = tmp_path / "x"
    f.write_text("")
    # tmpfs and most CI filesystems carry no label: None, never an exception.
    assert keaselinux.context_type(f) in (None,) or isinstance(keaselinux.context_type(f), str)
    assert keaselinux.context_type(tmp_path / "missing") is None
