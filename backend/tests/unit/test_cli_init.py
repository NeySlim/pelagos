# SPDX-License-Identifier: Apache-2.0
"""`pelagos init`: password sources, password policy, clear refusals and exit codes."""

from __future__ import annotations

import io

import pytest

from pelagos import cli

pytestmark = pytest.mark.unit

GOOD = "Init-Admin-Password-1"


class _Stdin(io.StringIO):
    def __init__(self, tty: bool) -> None:
        super().__init__("")
        self._tty = tty

    def isatty(self) -> bool:
        return self._tty


@pytest.fixture
def home(tmp_path, monkeypatch):
    for var in ("HOME", "ETC", "VAR", "RUN", "OPT", "ADMIN_PASSWORD"):
        monkeypatch.delenv(f"PELAGOS_{var}", raising=False)
    monkeypatch.setattr("sys.stdin", _Stdin(tty=False))
    monkeypatch.setattr("pelagos.core.listen.check_free", lambda *_: None)  # default ports may be busy
    return tmp_path / "node"


def _init(home, *extra):
    return cli.main(["--home", str(home), "init", "--name", "ns1", *extra])


def test_init_from_the_environment(home, monkeypatch, capsys):
    monkeypatch.setenv("PELAGOS_ADMIN_PASSWORD", GOOD)
    assert _init(home) == 0
    assert (home / "var" / "cluster.toml").exists()
    assert "node ns1" in capsys.readouterr().out


def test_no_terminal_and_no_variable_is_a_usage_error(home, capsys):
    assert _init(home) == 2
    err = capsys.readouterr().err
    assert "PELAGOS_ADMIN_PASSWORD" in err and "Traceback" not in err
    assert not (home / "etc" / "node.toml").exists()


def test_closed_terminal_is_a_usage_error(home, monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", _Stdin(tty=True))

    def eof(prompt=""):
        raise EOFError

    monkeypatch.setattr(cli.getpass, "getpass", eof)
    assert _init(home) == 2
    assert "no admin password given" in capsys.readouterr().err


def test_prompt_asks_twice(home, monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", _Stdin(tty=True))
    answers = iter([GOOD, GOOD + "x"])
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": next(answers))
    assert _init(home) == 2
    assert "differ" in capsys.readouterr().err
    answers = iter([GOOD, GOOD])
    assert _init(home) == 0


@pytest.mark.parametrize("weak", ["short-Pw-1", "alllowercaseletters", "lowercase-and-dashes"])
def test_weak_password_is_refused(home, monkeypatch, capsys, weak):
    monkeypatch.setenv("PELAGOS_ADMIN_PASSWORD", weak)
    assert _init(home) == 2
    assert "admin password refused" in capsys.readouterr().err
    assert not (home / "var" / "cluster.toml").exists()


def test_already_initialized_refuses_before_asking(home, monkeypatch, capsys):
    monkeypatch.setenv("PELAGOS_ADMIN_PASSWORD", GOOD)
    assert _init(home) == 0
    monkeypatch.delenv("PELAGOS_ADMIN_PASSWORD")
    monkeypatch.setattr("sys.stdin", _Stdin(tty=True))

    def never(prompt=""):
        raise AssertionError("asked for a password")

    monkeypatch.setattr(cli.getpass, "getpass", never)
    assert _init(home) == 1
    err = capsys.readouterr().err
    assert "already initialized" in err and "Traceback" not in err


def test_listen_options_are_written_and_urls_follow_the_port(home, monkeypatch):
    from pelagos.core.config_store import ConfigStore

    monkeypatch.setenv("PELAGOS_ADMIN_PASSWORD", GOOD)
    rc = _init(home, "--web-listen", "127.0.0.1:18443", "--replication-listen", "127.0.0.1:18444")
    assert rc == 0
    node = ConfigStore(home / "etc" / "node.toml", home / "var" / "cluster.toml").load_node()
    assert (node.web_listen, node.replication_listen) == ("127.0.0.1:18443", "127.0.0.1:18444")
    assert node.web_url == "https://ns1:18443" and node.replication_url == "https://ns1:18444"


def test_busy_port_is_a_clear_error_and_nothing_is_written(home, monkeypatch, capsys):
    import socket

    monkeypatch.undo()  # the real check, with a real busy port
    monkeypatch.setenv("PELAGOS_ADMIN_PASSWORD", GOOD)
    with socket.socket() as busy:
        busy.bind(("127.0.0.1", 0))
        busy.listen()
        port = busy.getsockname()[1]
        assert _init(home, "--web-listen", f"127.0.0.1:{port}") == 1
    err = capsys.readouterr().err
    assert f"port {port} is already in use" in err and "--web-listen" in err
    assert not (home / "etc" / "node.toml").exists()


@pytest.mark.parametrize("value", ["nonsense", "0.0.0.0:", "0.0.0.0:99999", "0.0.0.0:0"])
def test_malformed_listen_is_refused(value):
    from pelagos.core.listen import ListenError, split_listen

    with pytest.raises(ListenError, match="not host:port"):
        split_listen(value)
