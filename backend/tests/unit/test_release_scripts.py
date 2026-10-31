# SPDX-License-Identifier: Apache-2.0
"""scripts/release-assemble.sh, scripts/release-check.sh and the --tag mode of deploy-prod.sh."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(shutil.which("dpkg-deb") is None, reason="dpkg-deb builds the test debs"),
]

REPO = Path(__file__).resolve().parents[3]
CHECK = REPO / "scripts" / "release-check.sh"
ASSEMBLE = REPO / "scripts" / "release-assemble.sh"
DEPLOY = REPO / "scripts" / "deploy-prod.sh"
V = "9.9.9"
RPMS = (f"pelagos-{V}-1.el9.x86_64.rpm", f"pelagos-{V}-1.el10.x86_64.rpm")
REQUIRE_ALL = "deb:amd64,deb:arm64,rpm:el9,rpm:el10"


def run(*args: object, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    # The CI image has no system python3: the scripts get this interpreter.
    env = {**(env or os.environ), "PELAGOS_PYTHON": sys.executable}
    return subprocess.run([str(a) for a in args], capture_output=True, text=True, env=env, check=False)


def make_src(root: Path, version: str = V) -> Path:
    src = root / "src"
    (src / "packaging").mkdir(parents=True)
    shutil.copy(REPO / "packaging" / "version.sh", src / "packaging" / "version.sh")
    (src / "backend" / "pelagos").mkdir(parents=True)
    (src / "backend" / "pelagos" / "__init__.py").write_text(f'__version__ = "{version}"\n')
    (src / "docs" / "releases").mkdir(parents=True)
    (src / "docs" / "releases" / f"{V}.md").write_text(f"# Pelagos {V}\n\nFixes.\n")
    (src / "CHANGELOG.md").write_text(f"# Changelog\n\n## {V}\n\n- Fix.\n")
    (src / "README.md").write_text("# Pelagos\n\nBIND 9.20 and Kea 3.2.1. Latest release: see the badge.\n")
    return src


def make_deb(out: Path, arch: str, version: str = f"{V}-1", description: str = "test") -> Path:
    tree = out / f"tree-{arch}"
    (tree / "DEBIAN").mkdir(parents=True)
    (tree / "DEBIAN" / "control").write_text(
        f"Package: pelagos\nVersion: {version}\nArchitecture: {arch}\nMaintainer: t <t@example.lan>\n"
        f"Description: {description}\n"
    )
    deb = out / f"pelagos_{version}_{arch}.deb"
    subprocess.run(
        ["dpkg-deb", "-Zgzip", "--root-owner-group", "-b", str(tree), str(deb)],
        check=True,
        capture_output=True,
    )
    return deb


@pytest.fixture
def built(tmp_path: Path) -> dict[str, Path]:
    pkgs = tmp_path / "pkgs"
    pkgs.mkdir()
    files = [make_deb(pkgs, "amd64"), make_deb(pkgs, "arm64")]
    for name in RPMS:
        (pkgs / name).write_bytes(name.encode())
        files.append(pkgs / name)
    src = make_src(tmp_path)
    rel = tmp_path / "dist" / V
    env = {**os.environ, "PELAGOS_PYTHON": sys.executable}
    env.pop("PELAGOS_RELEASE_KEY", None)
    r = run(
        ASSEMBLE,
        "--notes",
        src / "docs" / "releases" / f"{V}.md",
        "--published-at",
        "2026-10-31T00:00:00Z",
        rel,
        V,
        *files,
        env=env,
    )
    assert r.returncode == 0, r.stderr
    tested = tmp_path / "tested.sha256"
    tested.write_text(
        "".join(f"{hashlib.sha256(f.read_bytes()).hexdigest()}  build/{f.name}\n" for f in files)
    )
    return {"src": src, "rel": rel, "tested": tested}


def check(b: dict[str, Path], *extra: object, tag: str = f"v{V}") -> subprocess.CompletedProcess[str]:
    return run(
        CHECK,
        "--tag",
        tag,
        "--src",
        b["src"],
        "--require",
        REQUIRE_ALL,
        "--tested",
        b["tested"],
        *extra,
        b["rel"],
    )


def failed(r: subprocess.CompletedProcess[str]) -> str:
    assert r.returncode == 1, r.stdout + r.stderr
    return "\n".join(line for line in r.stdout.splitlines() if line.startswith("FAIL"))


def test_assembled_release_passes_every_check(built):
    r = check(built)
    assert r.returncode == 0, r.stdout
    assert "FAIL" not in r.stdout
    manifest = json.loads((built["rel"] / "release.json").read_text())
    # One package per format and arch for the nodes: the rpms ship beside release.json.
    assert sorted(p["file"] for p in manifest["packages"]) == [
        f"pelagos_{V}-1_amd64.deb",
        f"pelagos_{V}-1_arm64.deb",
    ]
    sums = (built["rel"] / "SHA256SUMS").read_text()
    assert all(n in sums for n in (*RPMS, "release.json", "NOTES.md"))
    notes = (built["rel"] / "NOTES.md").read_text()
    assert notes.startswith(f"# Pelagos {V}\n") and "## Files" in notes and RPMS[0] in notes


def test_source_checks_alone_without_a_release_directory(built):
    r = run(CHECK, "--tag", f"v{V}", "--src", built["src"])
    assert r.returncode == 0, r.stdout


def test_tag_must_match_the_built_tree(built, tmp_path):
    other = make_src(tmp_path / "other", "9.9.8")
    out = failed(check(built, "--tree", other))
    assert "built tree version 9.9.8 is not 9.9.9" in out


def test_pre_release_tag_is_refused(built):
    assert "is not vX.Y.Z" in failed(check(built, tag=f"v{V}rc1"))


@pytest.mark.parametrize(
    ("notes", "expected"),
    [
        (None, "missing or empty"),
        ("Fixes.\n", 'does not start with "# Pelagos 9.9.9"'),
        (f"# Pelagos {V}\n\n", "title only"),
        (f"# Pelagos {V}\n\nFixes.\n\n## Files\n", "Files section"),
    ],
)
def test_release_notes_are_required(built, notes, expected):
    path = built["src"] / "docs" / "releases" / f"{V}.md"
    if notes is None:
        path.unlink()
    else:
        path.write_text(notes)
    assert expected in failed(check(built))


def test_changelog_needs_the_version(built):
    (built["src"] / "CHANGELOG.md").write_text("# Changelog\n\n## 9.9.8\n\n## 9.9.90\n")
    assert 'CHANGELOG.md has no "## 9.9.9" section' in failed(check(built))


@pytest.mark.parametrize(
    "line",
    [f"Install {V}.", f"Version v{V} is out.", "pelagos_1.2.3-1_amd64.deb", "/releases/download/v1.0.0/x"],
)
def test_readme_names_no_version(built, line):
    (built["src"] / "README.md").write_text(f"# Pelagos\n\n{line}\n")
    assert "README.md names a version" in failed(check(built))


def test_tampered_package_fails_sums_and_tested(built):
    deb = built["rel"] / f"pelagos_{V}-1_amd64.deb"
    deb.write_bytes(deb.read_bytes() + b"x")
    out = failed(check(built))
    assert "a sum of SHA256SUMS does not match" in out
    assert f"pelagos_{V}-1_amd64.deb differs from the tested file" in out


def test_rebuilt_package_differs_from_the_tested_one(built):
    rel = built["rel"]
    make_deb(rel / "..", "arm64", description="rebuilt")  # same name and version, other bytes
    shutil.move(str(rel / ".." / f"pelagos_{V}-1_arm64.deb"), rel / f"pelagos_{V}-1_arm64.deb")
    sums = "".join(
        f"{hashlib.sha256(f.read_bytes()).hexdigest()}  {f.name}\n"
        for f in sorted(rel.iterdir())
        if f.name != "SHA256SUMS"
    )
    (rel / "SHA256SUMS").write_text(sums)
    out = failed(check(built))
    assert f"pelagos_{V}-1_arm64.deb differs from the tested file" in out
    assert "sums recomputed" not in out


def test_unlisted_file_and_missing_rpm(built):
    (built["rel"] / RPMS[0]).unlink()
    (built["rel"] / "extra.txt").write_text("x")
    out = failed(check(built))
    assert "SHA256SUMS and the directory differ" in out
    assert "package rpm:el9 missing" in out


def test_asset_names_github_would_rename(built):
    (built["rel"] / "pelagos_9.9.9~rc1-1_amd64.deb").write_bytes(b"x")
    assert "asset names GitHub would rename" in failed(check(built))


def test_manifest_must_hold_exactly_the_debs(built):
    path = built["rel"] / "release.json"
    data = json.loads(path.read_text())
    data["packages"].append({"file": RPMS[1], "format": "rpm", "arch": "x86_64", "version": f"{V}-1.el10"})
    path.write_text(json.dumps(data))
    assert "release.json:" in failed(run(CHECK, "--tag", f"v{V}", "--src", built["src"], built["rel"]))


def test_untested_package_fails(built):
    built["tested"].write_text("\n".join(built["tested"].read_text().splitlines()[:-1]) + "\n")
    assert f"{RPMS[1]} differs from the tested file (or was not tested)" in failed(check(built))


def fake_bin(tmp_path: Path, release: Path) -> dict[str, str]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "gh").write_text(
        f'#!/bin/sh\n# gh release download TAG --repo R --dir D\ncp "{release}"/* "$7"/\n'
    )
    (bin_dir / "ssh").write_text("#!/bin/sh\nexit 255\n")
    for f in bin_dir.iterdir():
        f.chmod(0o755)
    return {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}"}


def test_deploy_fetches_the_tag_and_verifies_it(built, tmp_path):
    env = fake_bin(tmp_path, built["rel"])
    r = run(DEPLOY, "--tag", f"v{V}", "--dry-run", "ns2.example.lan", env=env)
    assert f"release {V}-1 from" in r.stdout, r.stdout + r.stderr
    assert r.returncode != 0  # stops at ssh


def test_deploy_refuses_a_tag_whose_assets_do_not_match(built, tmp_path):
    env = fake_bin(tmp_path, built["rel"])
    assert "release.json of v9.9.8" in run(DEPLOY, "--tag", "v9.9.8", "ns2", env=env).stderr
    deb = built["rel"] / f"pelagos_{V}-1_amd64.deb"
    deb.write_bytes(deb.read_bytes() + b"x")
    r = run(DEPLOY, "--tag", f"v{V}", "--dry-run", "ns2", env=env)
    assert "checksum mismatch" in r.stdout + r.stderr
