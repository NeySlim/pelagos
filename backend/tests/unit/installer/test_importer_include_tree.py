# SPDX-License-Identifier: Apache-2.0
"""import/<engine>/include-tree: a commented Kea file is split into one file per section at import,
so the lossless editor patches it afterwards and its comments survive (section 9)."""

from __future__ import annotations

import dataclasses
import grp
import json
import os

import pytest

from pelagos.core.keadoc import KeaDocument
from pelagos.domain import JobState, PlanState
from pelagos.installer.importer import build_import_plan, kea_fingerprint, verify_import
from pelagos.installer.jobs import apply_plan
from tests.unit.installer.fakes import copy_kea, debian_tree, foreign_user

pytestmark = pytest.mark.unit


def kea_env(tmp_path):
    env = debian_tree(tmp_path)
    env.tools.version = "2.6.3"
    env.paths = dataclasses.replace(
        env.paths, kea_user=foreign_user(), kea_group=grp.getgrgid(os.getgid()).gr_name
    )
    copy_kea(tmp_path, {"kea-dhcp4.conf": "debian-2.6-kea-dhcp4.conf"})
    return env, tmp_path / "etc/kea/kea-dhcp4.conf"


def tree_change(plan):
    return next((c for c in plan.changes if c.target == "import/kea4/include-tree"), None)


def test_a_commented_file_is_split_by_default(tmp_path):
    env, conf = kea_env(tmp_path)
    before = KeaDocument(conf).value
    fingerprint = kea_fingerprint(conf.read_text(), str(conf))
    plan = build_import_plan(env, ["kea4"])
    assert plan.state is PlanState.VALIDATED
    change = tree_change(plan)
    assert change is not None and change.after["comments"] > 0
    directory = tmp_path / "etc/kea/kea4.d"
    assert change.after["dir"] == str(directory)
    assert f"+ {directory}/subnet4.json" in plan.diff and "comment(s) kept" in plan.diff
    targets = [c.target for c in plan.changes]
    assert targets.index("import/kea4/include-tree") == targets.index("import/kea4/socket") + 1

    job = apply_plan(plan, env)
    assert job.state is JobState.DONE, job.error
    doc = KeaDocument(conf)
    assert doc.has_includes and all(p.parent == directory for p in doc.paths[1:])
    assert conf.read_text().startswith("// This is a basic configuration for the Kea DHCPv4 server")
    # Same configuration, every comment still somewhere in the tree.
    body = dict(doc.value["Dhcp4"])
    assert {k: v for k, v in body.items() if k != "control-socket"} == {
        k: v for k, v in before["Dhcp4"].items() if k != "control-socket"
    }
    assert kea_fingerprint(conf.read_text(), str(conf)) == fingerprint
    assert sum(len(t.splitlines()) for t in doc.texts) >= len(conf.read_text().splitlines())
    assert verify_import(env, ["kea4"], {"kea4": {"conf": str(conf), "fingerprint": fingerprint}})[
        "kea4.unchanged"
    ]
    # The files Pelagos patches later are writable through the Kea group, the folder readable by Kea.
    for part in doc.paths[1:]:
        assert part.stat().st_mode & 0o060 == 0o060
    assert directory.stat().st_mode & 0o777 == 0o750
    step = next(s for s in job.steps if s["name"] == "import/kea4/include-tree")
    assert "written" in step["output"]


def test_the_split_is_optional(tmp_path):
    env, conf = kea_env(tmp_path)
    text = conf.read_text()
    plan = build_import_plan(env, ["kea4"], include_tree=False)
    assert tree_change(plan) is None
    assert apply_plan(plan, env).state is JobState.DONE
    assert "<?include" not in conf.read_text() and conf.read_text().startswith(text[:40])


def test_a_file_without_comments_is_split_only_on_request(tmp_path):
    env, conf = kea_env(tmp_path)
    conf.write_text(json.dumps(KeaDocument(conf).value, indent=2))
    assert tree_change(build_import_plan(env, ["kea4"])) is None
    plan = build_import_plan(env, ["kea4"], include_tree=True)
    assert tree_change(plan).after["comments"] == 0
    assert apply_plan(plan, env).state is JobState.DONE
    assert KeaDocument(conf).has_includes


def test_an_existing_tree_or_folder_is_left_alone(tmp_path):
    env, _conf = kea_env(tmp_path)
    directory = tmp_path / "etc/kea/kea4.d"
    directory.mkdir()
    (directory / "mine.json").write_text("{}")
    assert tree_change(build_import_plan(env, ["kea4"])) is None
    with pytest.raises(ValueError, match="already exists"):
        build_import_plan(env, ["kea4"], include_tree=True)
    (directory / "mine.json").unlink()
    assert apply_plan(build_import_plan(env, ["kea4"]), env).state is JobState.DONE
    # A second import finds the tree: nothing more to split.
    assert tree_change(build_import_plan(env, ["kea4"])) is None


def test_dry_run_writes_nothing(tmp_path):
    env, conf = kea_env(tmp_path)
    text = conf.read_text()
    plan = build_import_plan(env, ["kea4"])
    env.dry_run = True
    job = apply_plan(plan, env)
    assert job.state is JobState.DONE, job.error
    assert conf.read_text() == text and not (tmp_path / "etc/kea/kea4.d").exists()
