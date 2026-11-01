# SPDX-License-Identifier: Apache-2.0
"""KeaConfigFile.persist on a file without includes: its comments ride into user-context before the
config-write that drops them, once (section 9)."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import pytest

from pelagos.connectors.kea.configfile import KeaConfigFile
from pelagos.core.write_pipeline import WritePipeline

pytestmark = pytest.mark.unit

MAIN = """// lab server
{ "Dhcp4": {
  "valid-lifetime": 3600,
  "subnet4": [
    // office
    { "id": 1, "subnet": "192.0.2.0/24" }
  ]
} }
"""
RUNNING = {"valid-lifetime": 3600, "subnet4": [{"id": 1, "subnet": "192.0.2.0/24"}]}


class Socket:
    def __init__(self, body: dict[str, Any], test_result: int = 0) -> None:
        self.body = body
        self.test_result = test_result
        self.calls: list[str] = []

    def config_get(self) -> dict[str, Any]:
        self.calls.append("config-get")
        return {"Dhcp4": copy.deepcopy(self.body)}

    def send(self, command: str, arguments: Any = None) -> dict[str, Any]:
        self.calls.append(command)
        return {"result": self.test_result, "text": "refused" if self.test_result else ""}

    def call(self, command: str, arguments: Any = None) -> dict[str, Any]:
        self.calls.append(command)
        if command == "config-set":
            self.body = arguments["Dhcp4"]
        return {"filename": "kea-dhcp4.conf"} if command == "config-write" else {}


def make(tmp_path: Path, text: str = MAIN, test_result: int = 0) -> tuple[KeaConfigFile, Socket]:
    conf = tmp_path / "kea-dhcp4.conf"
    conf.write_text(text)
    sock = Socket(copy.deepcopy(RUNNING), test_result)
    file = KeaConfigFile(conf, "Dhcp4", "kea4", lambda: sock, WritePipeline, tmp_path / "b", "n1")
    return file, sock


def test_comments_are_set_in_user_context_before_config_write(tmp_path):
    file, sock = make(tmp_path)
    message = file.persist(file.document(), RUNNING, "t")
    assert sock.calls == ["config-get", "config-test", "config-set", "config-write"]
    assert message.startswith("comments copied to user-context; config-write")
    assert sock.body["user-context"] == {"pelagos": {"comment": "lab server"}}
    assert sock.body["subnet4"][0]["user-context"] == {"pelagos": {"comment": "office"}}


def test_comments_already_carried_cost_no_config_set(tmp_path):
    file, sock = make(tmp_path)
    doc = file.document()
    sock.body = file.with_comments(doc, sock.body)  # the change's config-set carried them
    file.persist(doc, RUNNING, "t")
    assert sock.calls == ["config-get", "config-write"]


def test_a_refused_copy_still_persists(tmp_path):
    file, sock = make(tmp_path, test_result=1)
    message = file.persist(file.document(), RUNNING, "t")
    assert sock.calls == ["config-get", "config-test", "config-write"]
    assert "comments not copied (config-test: refused)" in message


def test_a_file_without_comments_goes_straight_to_config_write(tmp_path):
    file, sock = make(tmp_path, MAIN.replace("// lab server\n", "").replace("    // office\n", ""))
    assert file.with_comments(file.document(), RUNNING) is RUNNING
    file.persist(file.document(), RUNNING, "t")
    assert sock.calls == ["config-write"]  # nothing to copy or keep: not even a config-get


def test_a_failed_copy_never_fails_the_write(tmp_path):
    file, sock = make(tmp_path)
    real = sock.call

    def call(command, arguments=None):
        if command == "config-set":
            from pelagos.connectors.base import ConnectorError

            raise ConnectorError("config-set refused")
        return real(command, arguments)

    sock.call = call
    message = file.persist(file.document(), RUNNING, "t")
    assert message.startswith("comments not copied (config-set refused); config-write")


def test_copies_lost_by_a_rollback_come_back_before_config_write(tmp_path):
    file, sock = make(tmp_path, MAIN.replace("// lab server\n", "").replace("    // office\n", ""))
    before = copy.deepcopy(RUNNING)
    before["subnet4"][0]["user-context"] = {"pelagos": {"comment": "office"}}
    # The running configuration lost the copy (an older configuration was set back).
    file.persist(file.document(), before, "t")
    assert sock.calls == ["config-get", "config-test", "config-set", "config-write"]
    assert sock.body["subnet4"][0]["user-context"] == {"pelagos": {"comment": "office"}}


def test_comment_count_leaves_rulers_out(tmp_path):
    file, _ = make(tmp_path, MAIN.replace("// lab server", "// ------"))
    assert file.comment_count(file.document()) == 1


def test_a_removal_recorded_by_the_plan_is_not_undone(tmp_path):
    file, sock = make(tmp_path, MAIN.replace("// lab server\n", "").replace("    // office\n", ""))
    before = copy.deepcopy(RUNNING)
    before["subnet4"][0]["user-context"] = {"pelagos": {"comment": "office"}}
    file.persist(file.document(), before, "t", known=[before])
    assert sock.calls == ["config-get", "config-write"]
    assert "user-context" not in sock.body["subnet4"][0]


def test_adopt_running_config_write_fallback_copies_comments(tmp_path, monkeypatch):
    from pelagos.connectors.kea.configfile import ADOPT_RUNNING
    from pelagos.core.keadoc import KeaDocument, KeaEditError
    from pelagos.domain import Change, ChangeOp

    def refuse(self, new_value):
        raise KeaEditError("cannot place it")

    file, sock = make(tmp_path)
    monkeypatch.setattr(KeaDocument, "patch", refuse)
    change = Change(ChangeOp.REPLACE, ADOPT_RUNNING, after={"source": "running"})
    message, _ = file.apply_adopt(change, "t", lambda body: None)
    assert message.startswith("comments copied to user-context; config-write")
    assert sock.calls[-2:] == ["config-set", "config-write"]
    assert sock.body["subnet4"][0]["user-context"] == {"pelagos": {"comment": "office"}}
