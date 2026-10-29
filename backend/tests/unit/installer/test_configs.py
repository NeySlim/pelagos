# SPDX-License-Identifier: Apache-2.0
"""Reading captured `named-checkconf -p` outputs, user named.conf files and Kea configs."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pelagos.installer import bindconf, bindsetup, keaconf, keasetup

pytestmark = pytest.mark.unit

DATA = Path(__file__).parent / "data"
ANY4 = "0.0.0.0"  # noqa: S104 - a value read from a config, nothing binds


def _p(name: str) -> list[bindconf.Statement]:
    return bindconf.parse((DATA / "bind" / name).read_text(), name)


def test_debian_default_printed():
    stmts = _p("debian-default-p.conf")
    assert [s.name for s in stmts] == ["options", "zone"]
    assert bindconf.option_value(stmts[0], "directory") == ["/var/cache/bind"]
    (z,) = bindconf.zones(stmts)
    assert (z.name, z.kind, z.view) == (".", "hint", "_default")


def test_rocky_default_printed():
    stmts = _p("rocky-default-p.conf")
    names = [s.name for s in stmts]
    assert "logging" in names and "options" in names
    opts = bindconf.find_first(stmts, "options")
    assert bindconf.option_value(opts, "listen-on") == ["127.0.0.1/32"]
    assert bindconf.option_value(opts, "recursion") == ["yes"]
    zones = {z.name for z in bindconf.zones(stmts)}
    assert {"localhost.", "1.0.0.127.in-addr.arpa."} <= zones


def test_legacy_printed_keys_listeners_zones():
    stmts = _p("legacy-p.conf")
    keys = {k.name: k for k in bindconf.keys(stmts)}
    assert keys["kea-ddns"].algorithm == "hmac-md5" and keys["kea-ddns"].weak
    assert keys["legacy-xfr"].algorithm == "hmac-sha1" and keys["legacy-xfr"].weak
    (ctl,) = bindconf.inet_listeners(bindconf.find_first(stmts, "controls"))
    assert (ctl.address, ctl.port, ctl.allow, ctl.keys, ctl.local) == (
        ANY4,
        953,
        ["any"],
        ["rndc-key"],
        False,
    )
    (st,) = bindconf.inet_listeners(bindconf.find_first(stmts, "statistics-channels"))
    assert (st.address, st.port, st.allow) == (ANY4, 8053, ["any"])
    zones = {z.name: z for z in bindconf.zones(stmts)}
    assert zones["example.lan."].elements("allow-update") == ["key kea-ddns", "192.0.2.5/32"]
    assert zones["corp.example.lan."].elements("update-policy") == ["grant kea-ddns zonesub ANY"]
    assert zones["example.net."].kind == "secondary"


def test_views_and_comments():
    stmts = _p("views.conf")
    zones = bindconf.zones(stmts)
    assert [(z.view, z.name) for z in zones] == [
        ("internal", "internal.example.lan."),
        ("external", "example.lan."),
        ("external", "example.net."),
    ]
    assert zones[1].rclass == "IN"
    assert bindconf.has_include(stmts, "/etc/named/pelagos/options.conf")
    assert bindsetup.kea_key_of_zone(zones[1]) == "kea-ddns"


def test_user_files_with_includes(tmp_path):
    etc = tmp_path / "bind"
    etc.mkdir()
    for f in ("named.conf", "named.conf.local", "named.conf.options", "rndc.key"):
        (etc / f).write_text((DATA / "bind" / "legacy" / f).read_text().replace("/etc/bind", str(etc)))
    files = bindconf.load_files(etc / "named.conf")
    assert len(files.order) == 4 and files.missing == []
    top = list(files.top_level())
    assert {s.name for s in top} >= {"options", "key", "zone", "controls", "statistics-channels"}
    opts = bindsetup.find_options(files)
    assert opts.path == str(etc / "named.conf.options")
    ctl = bindsetup.controls_info(files, etc / "rndc.key")
    assert ctl["key"] == "rndc-key" and ctl["key_file"] == str(etc / "rndc.key") and ctl["port"] == 953


def test_include_line_edits_keep_everything_else():
    text = (DATA / "bind" / "debian-named.conf.options").read_text()
    stmts = bindconf.parse(text)
    opts = bindconf.find_first(stmts, "options")
    new = bindconf.insert_in_block(text, opts.block, 'include "/etc/bind/pelagos/options.conf";')
    assert new.startswith(text[: opts.block.end].rstrip(" \t"))
    reparsed = bindconf.find_first(bindconf.parse(new), "options")
    assert [s.name for s in reparsed.block.statements] == ["directory", "include"]
    top = bindconf.append_top_level("zone a { type hint; };", 'include "x";')
    assert top == 'zone a { type hint; };\ninclude "x";\n'


def test_kea_debian_26_files_with_comments():
    d4 = keaconf.loads((DATA / "kea" / "debian-2.6-kea-dhcp4.conf").read_text())
    assert keaconf.root_key(d4) == "Dhcp4"
    assert keaconf.control_socket_path(d4, Path("/run/kea")) == Path("/run/kea/kea4-ctrl-socket")
    d2 = keaconf.loads((DATA / "kea" / "debian-2.6-kea-dhcp-ddns.conf").read_text())
    assert keaconf.tsig_keys(d2) == []
    assert keaconf.control_socket_path(d2, Path("/run/kea")) == Path("/run/kea/kea-ddns-ctrl-socket")


def test_kea_rocky_ctrl_agent_is_plain_http():
    agent = keaconf.loads((DATA / "kea" / "rocky-3.0-kea-ctrl-agent.conf").read_text())
    (lst,) = keaconf.http_listeners(agent)
    assert (
        lst["socket-type"] == "http" and lst["socket-address"] == "127.0.0.1" and lst["socket-port"] == 8000
    )


def test_versions():
    assert keaconf.daemon_version_from_text("2.6.3\n") == "2.6.3"
    assert keaconf.daemon_version_from_text("BIND 9.20.30-1~deb13u1-Debian (Stable Release)") == "9.20.30"
    assert not keaconf.supports_control_sockets("2.6.3") and keaconf.supports_control_sockets("3.2.1")
    assert not keaconf.supports_secret_file("2.6.3") and keaconf.supports_secret_file("3.0.3")
    assert keasetup.needs_socket_dropin("2.6.3") and not keasetup.needs_socket_dropin("3.0.3")


def test_insert_socket_keeps_comments():
    text = (DATA / "kea" / "debian-2.6-kea-dhcp4.conf").read_text()
    config = keaconf.loads(text)
    body = config["Dhcp4"]
    body.pop("control-socket")
    stripped = json.dumps(config)  # no socket, no comments
    new, changed = keasetup.ensure_unix_socket(stripped, "kea4", "2.6.3")
    assert changed and keaconf.loads(new)["Dhcp4"]["control-socket"]["socket-name"] == "kea4-ctrl-socket"
    # A commented file without a socket: comments survive, the socket lands first in Dhcp4.
    commented = '// header\n{\n  # hash comment\n  "Dhcp4": {\n    /* c */ "valid-lifetime": 4000\n  }\n}\n'
    new, changed = keasetup.ensure_unix_socket(commented, "kea4", "3.2.1")
    assert changed and "// header" in new and "# hash comment" in new and "/* c */" in new
    cfg = keaconf.loads(new)["Dhcp4"]
    assert cfg["control-sockets"] == [{"socket-type": "unix", "socket-name": "kea4-ctrl-socket"}]
    assert cfg["valid-lifetime"] == 4000
    # Already there: untouched.
    assert keasetup.ensure_unix_socket(text, "kea4", "2.6.3") == (text, False)


def test_insert_into_empty_object():
    new = keasetup.insert_top_key('{"DhcpDdns": {}}', "DhcpDdns", "control-sockets", [{"a": 1}])
    assert keaconf.loads(new)["DhcpDdns"] == {"control-sockets": [{"a": 1}]}


def test_http_only_socket_list_gets_a_unix_socket_with_comments_kept():
    text = (
        "// agent-less server\n"
        '{ "Dhcp4": {\n'
        '    "control-sockets": [ { "socket-type": "http", "socket-port": 8004 } ], // http only\n'
        '    "valid-lifetime": 4000\n} }\n'
    )
    new, changed = keasetup.ensure_unix_socket(text, "kea4", "3.2.1")
    assert changed and "// agent-less server" in new and "// http only" in new
    sockets = keaconf.loads(new)["Dhcp4"]["control-sockets"]
    assert {s["socket-type"] for s in sockets} == {"http", "unix"}


def test_socket_and_edits_through_includes(tmp_path):
    part = tmp_path / "ddns-keys.json"
    part.write_text('// keys\n{ "name": "kea-ddns", "algorithm": "HMAC-MD5", "secret": "bGVn" }\n')
    conf = tmp_path / "kea-dhcp-ddns.conf"
    conf.write_text(
        '{ "DhcpDdns": {\n  // keys live apart\n  "tsig-keys": [ <?include "' + str(part) + '"?> ],\n'
        '  "forward-ddns": { "ddns-domains": [ { "name": "example.lan.", "key-name": "kea-ddns" } ] }\n} }\n'
    )
    files = keasetup.unix_socket_files(conf, "d2", "3.2.1")
    assert set(files) == {conf} and "<?include" in files[conf] and "// keys live apart" in files[conf]
    conf.write_text(files[conf])
    assert keasetup.unix_socket_files(conf, "d2", "3.2.1") == {}
    config = keaconf.loads(conf.read_text(), str(conf))
    entry = {"name": "pelagos-ddns", "algorithm": "HMAC-SHA256", "secret-file": "/etc/kea/pelagos-ddns.tsig"}
    files = keasetup.edited_files(conf, keaconf.rename_key(config, "kea-ddns", entry))
    assert "pelagos-ddns.tsig" in files[part] and files[part].startswith("// keys")
    assert '"key-name": "pelagos-ddns"' in files[conf]


def test_minimal_configs():
    c4 = keasetup.minimal_config("kea4", "3.2.1", Path("/hooks"), ["lease_cmds", "ha", "host_cmds"])
    body = c4["Dhcp4"]
    assert body["interfaces-config"] == {"interfaces": []}
    assert body["control-sockets"] == [{"socket-type": "unix", "socket-name": "kea4-ctrl-socket"}]
    assert [h["library"] for h in body["hooks-libraries"]] == [
        "/hooks/libdhcp_lease_cmds.so",
        "/hooks/libdhcp_host_cmds.so",
    ]
    assert body["subnet4"] == []
    c6 = keasetup.minimal_config("kea6", "2.6.3", None, [])
    assert c6["Dhcp6"]["control-socket"]["socket-name"] == "kea6-ctrl-socket"
    assert c6["Dhcp6"]["hooks-libraries"] == []
    key = keasetup.tsig_key_entry(
        "kea-ddns", "hmac-sha256", "c2VjcmV0", Path("/etc/kea/kea-ddns.tsig"), "3.2.1"
    )
    d2 = keasetup.minimal_config("d2", "3.2.1", None, [], [key])["DhcpDdns"]
    assert d2["tsig-keys"] == [
        {"name": "kea-ddns", "algorithm": "HMAC-SHA256", "secret-file": "/etc/kea/kea-ddns.tsig"}
    ]
    old = keasetup.tsig_key_entry("kea-ddns", "hmac-sha256", "c2VjcmV0", Path("/x"), "2.6.3")
    assert old == {"name": "kea-ddns", "algorithm": "HMAC-SHA256", "secret": "c2VjcmV0"}


def test_socket_dropin():
    text = keasetup.socket_dropin(Path("/run/kea/kea4-ctrl-socket"))
    assert "ExecStartPre=-/bin/rm -f /run/kea/kea4-ctrl-socket" in text
    assert "chmod g+w /run/kea/kea4-ctrl-socket" in text and text.startswith("# pelagos:managed v1")


def test_rename_key_updates_references():
    d2 = {
        "DhcpDdns": {
            "tsig-keys": [{"name": "kea-ddns", "algorithm": "HMAC-MD5", "secret": "x"}],
            "forward-ddns": {"ddns-domains": [{"name": "example.lan.", "key-name": "kea-ddns"}]},
            "reverse-ddns": {
                "ddns-domains": [{"name": "2.0.192.in-addr.arpa.", "dns-servers": [{"key-name": "kea-ddns"}]}]
            },
        }
    }
    new = keaconf.rename_key(d2, "kea-ddns", {"name": "kea-ddns-sha256", "algorithm": "HMAC-SHA256"})
    assert [k["name"] for k in keaconf.tsig_keys(new)] == ["kea-ddns-sha256"]
    assert keaconf.domains_using_key(new, "kea-ddns-sha256") == [
        ("forward-ddns", "example.lan."),
        ("reverse-ddns", "2.0.192.in-addr.arpa."),
    ]
    assert keaconf.domains_using_key(d2, "kea-ddns") != []  # original untouched


def test_migrate_inline_secrets_keeps_paths_under_the_conf_dir():
    keys = [
        {"name": "kea-ddns", "algorithm": "HMAC-SHA256", "secret": "c2VjcmV0"},
        {"name": "/etc/cron.d/x", "algorithm": "HMAC-SHA256", "secret": "c2VjcmV0"},
        {"name": "k1", "algorithm": "HMAC-SHA256", "secret": "c2VjcmV0", "secret-file": "/etc/kea/a"},
    ]
    cfg, files = keasetup.migrate_inline_secrets({"DhcpDdns": {"tsig-keys": keys}}, Path("/etc/kea"))
    assert files == {Path("/etc/kea/kea-ddns.tsig"): "c2VjcmV0"}
    out = cfg["DhcpDdns"]["tsig-keys"]
    assert out[0]["secret-file"] == "/etc/kea/kea-ddns.tsig" and "secret" not in out[0]
    assert out[1] == keys[1]  # unsafe name: left for the administrator
    assert out[2] == {"name": "k1", "algorithm": "HMAC-SHA256", "secret-file": "/etc/kea/a"}
    with pytest.raises(ValueError):
        keasetup.secret_file_path(Path("/etc/kea"), "../x")
