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
    cil = tmp_path / "var/lib/pelagos-helper/selinux/pelagos-kea-dhcpd_t.cil"
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
    assert (
        "failed" in out and not (tmp_path / "var/lib/pelagos-helper/selinux/pelagos-kea-kea_t.cil").exists()
    )
    dry = env_for(tmp_path, dry_run=True)
    assert keaselinux.ensure_config_write(dry, CONF, "kea-dhcp4", types).startswith("dry run")


def test_context_type_reads_the_label(tmp_path):
    f = tmp_path / "x"
    f.write_text("")
    # tmpfs and most CI filesystems carry no label: None, never an exception.
    assert keaselinux.context_type(f) in (None,) or isinstance(keaselinux.context_type(f), str)
    assert keaselinux.context_type(tmp_path / "missing") is None


def test_generic_types_are_refused(tmp_path):
    env = env_for(tmp_path)
    types = typer({"/usr/sbin/kea-dhcp4": "dhcpd_exec_t", str(CONF): "etc_t"})
    out = keaselinux.ensure_config_write(env, CONF, "kea-dhcp4", types)
    assert "generic type" in out and "semanage fcontext -a -t dhcp_etc_t" in out
    assert env.runner.calls == [] and not (tmp_path / "var/lib/pelagos-helper/selinux").exists()


def test_included_files_and_the_other_family_are_covered(tmp_path):
    env = env_for(tmp_path)
    part = tmp_path / "subnets.json"
    part.write_text('"valid-lifetime": 3600,')
    conf4 = tmp_path / "kea-dhcp4.conf"
    conf4.write_text(f'{{"Dhcp4": {{ <?include "{part}"?> "subnet4": [] }}}}')
    conf6 = tmp_path / "kea-dhcp6.conf"
    conf6.write_text('{"Dhcp6": {}}')
    types = typer(
        {
            "/usr/sbin/kea-dhcp4": "dhcpd_exec_t",
            "/usr/sbin/kea-dhcp6": "dhcpd_exec_t",
            str(conf4): "dhcp_etc_t",
            str(part): "dhcpd_state_t",
            str(conf6): "kea_etc_t",
        }
    )
    keaselinux.ensure_config_write(env, conf4, "kea-dhcp4", types)
    out = keaselinux.ensure_config_write(env, conf6, "kea-dhcp6", types)
    cil = (tmp_path / "var/lib/pelagos-helper/selinux/pelagos-kea-dhcpd_t.cil").read_text()
    assert "dhcp_etc_t, dhcpd_state_t, kea_etc_t" in out
    for t in ("dhcp_etc_t", "dhcpd_state_t", "kea_etc_t"):
        assert f"(allow dhcpd_t {t} (file" in cil
    # An included file in a generic type is refused like the main file.
    types_generic = typer(
        {"/usr/sbin/kea-dhcp4": "dhcpd_exec_t", str(conf4): "dhcp_etc_t", str(part): "usr_t"}
    )
    assert f"{part} is labeled usr_t" in keaselinux.ensure_config_write(
        env, conf4, "kea-dhcp4", types_generic
    )


def test_service_user_files_are_never_trusted(tmp_path):
    """A planted .cil under /etc/pelagos or a symlinked module never feeds the root-loaded module."""
    env = env_for(tmp_path)
    types = typer({"/usr/sbin/kea-dhcp4": "dhcpd_exec_t", str(CONF): "dhcp_etc_t"})
    legacy = tmp_path / "etc/pelagos/selinux"
    legacy.mkdir(parents=True)
    (legacy / "pelagos-kea-dhcpd_t.cil").write_text("(allow dhcpd_t shadow_t (file (write)))\n")
    state = tmp_path / "var/lib/pelagos-helper/selinux"
    state.mkdir(parents=True)
    victim = tmp_path / "victim"
    victim.write_text("(allow dhcpd_t shadow_t (file (write)))\n(allow dhcpd_t kea_var_t (file (x)))\n")
    (state / "pelagos-kea-dhcpd_t.cil").symlink_to(victim)
    out = keaselinux.ensure_config_write(env, CONF, "kea-dhcp4", types)
    assert "shadow_t" not in out and "kea_var_t" not in out
    cil = state / "pelagos-kea-dhcpd_t.cil"
    assert not cil.is_symlink() and "shadow_t" not in cil.read_text()
    assert victim.read_text().startswith("(allow dhcpd_t shadow_t")
    assert cil.stat().st_mode & 0o777 == 0o600 and state.stat().st_mode & 0o777 == 0o700


def test_foreign_types_in_the_module_are_dropped(tmp_path):
    env = env_for(tmp_path)
    types = typer({"/usr/sbin/kea-dhcp4": "dhcpd_exec_t", str(CONF): "dhcp_etc_t"})
    state = tmp_path / "var/lib/pelagos-helper/selinux"
    state.mkdir(parents=True, mode=0o700)
    (state / "pelagos-kea-dhcpd_t.cil").write_text(
        "(allow dhcpd_t shadow_t (file (write)))\n(allow dhcpd_t kea_etc_t (file (write)))\n"
    )
    out = keaselinux.ensure_config_write(env, CONF, "kea-dhcp4", types)
    assert "dhcp_etc_t, kea_etc_t" in out
    assert "shadow_t" not in (state / "pelagos-kea-dhcpd_t.cil").read_text()


def test_symlinked_state_dir_is_refused(tmp_path):
    env = env_for(tmp_path)
    types = typer({"/usr/sbin/kea-dhcp4": "dhcpd_exec_t", str(CONF): "dhcp_etc_t"})
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (tmp_path / "var/lib").mkdir(parents=True)
    (tmp_path / "var/lib/pelagos-helper").symlink_to(elsewhere)
    out = keaselinux.ensure_config_write(env, CONF, "kea-dhcp4", types)
    assert "unusable" in out and env.runner.calls == [] and not any(elsewhere.iterdir())
