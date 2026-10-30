# SPDX-License-Identifier: Apache-2.0
"""Where release files come from (section 29): an upload, a peer that holds them, GitHub.

Everything here writes only into `incoming/<version>/` of the service user, which is never
trusted: the privileged helper copies it without following links and verifies sums, signature
and rules before root installs anything (`installer.updates.verify`). `HeldReleases` serves the
helper's verified copies (`packages/<version>/`) to peers on `/repl/v1/releases`.
"""

from __future__ import annotations

import hashlib
import io
import json
import logging
import os
import re
import shutil
import tempfile
import threading
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO

from pelagos.core import release as rel
from pelagos.domain.updates import (
    CHECKSUMS,
    MANIFEST,
    NOTES,
    SIGNATURE,
    parse_checksums,
    safe_file,
    valid_version,
)

log = logging.getLogger(__name__)

MAX_RELEASE_BYTES = 1 << 30
MAX_SMALL = 1 << 20
CHUNK = 1 << 16
GITHUB_API = "https://api.github.com"
# docs.github.com REST "Releases" and "Release assets" (read on 2026-10-30): `releases/latest` is
# the newest non-draft, non-prerelease release; an asset answers 200 or a 302 to its storage.
GITHUB_HEADERS = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}$")
_DEB = re.compile(r"^pelagos_(?P<version>[0-9][^_/]*?)(?:-[0-9][^_/-]*)?_(?:amd64|arm64)\.deb$")
_RPM = re.compile(r"^pelagos-(?P<version>[0-9][^-/]*)-[^/]+?\.(?:x86_64|aarch64)\.rpm$")


class SourceError(RuntimeError):
    """A release could not be read from its source; `reason` is a short code."""

    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(f"{reason}: {detail}")
        self.reason = reason
        self.detail = detail


def _sha256(path: Path) -> str:
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def _copy(src: BinaryIO, dst: BinaryIO, budget: int) -> int:
    total = 0
    while chunk := src.read(CHUNK):
        total += len(chunk)
        if total > budget:
            raise SourceError("too_large", f"the release exceeds {MAX_RELEASE_BYTES} bytes")
        dst.write(chunk)
    return total


def _new_folder(incoming: Path, prefix: str) -> Path:
    incoming.mkdir(parents=True, exist_ok=True, mode=0o750)
    return Path(tempfile.mkdtemp(prefix=prefix, dir=incoming))


def _publish(tmp: Path, incoming: Path, version: str) -> Path:
    """Moves a complete temporary folder to `incoming/<version>`, replacing an older attempt."""
    dest = incoming / version
    if dest.is_symlink() or dest.is_file():
        dest.unlink()
    elif dest.exists():
        shutil.rmtree(dest)
    os.rename(tmp, dest)
    return dest


def _check_sums(folder: Path, names: Iterable[str]) -> dict[str, str]:
    """Sums of SHA256SUMS against the files of `folder`; SourceError on a missing or different one."""
    try:
        sums = parse_checksums((folder / CHECKSUMS).read_text())
    except (OSError, ValueError) as exc:
        raise SourceError("checksum", f"{CHECKSUMS}: {exc}") from None
    have = set(names)
    for name, digest in sums.items():
        if name not in have:
            raise SourceError("missing", f"{name} is listed in {CHECKSUMS} but was not received")
        if _sha256(folder / name) != digest:
            raise SourceError("checksum", f"{name}: its sha256 does not match {CHECKSUMS}")
    return sums


# Upload --------------------------------------------------------------------------------------


def release_version(folder: Path, names: Iterable[str]) -> str:
    """The version of a release folder: release.json, else the package file names (0.2.x)."""
    if (folder / MANIFEST).is_file():
        try:
            version = str(json.loads((folder / MANIFEST).read_text()).get("version") or "")
        except (OSError, ValueError, AttributeError):
            raise SourceError("manifest", f"{MANIFEST} is not readable JSON") from None
        if valid_version(version):
            return version
        raise SourceError("manifest", f"{MANIFEST} has no valid version")
    found = {m["version"] for n in names if (m := _DEB.fullmatch(n) or _RPM.fullmatch(n))}
    if len(found) != 1 or not valid_version(next(iter(found))):
        raise SourceError("name", f"expected the packages of one version, found {sorted(found) or 'none'}")
    return found.pop()


def stage_upload(incoming: Path, files: Iterable[tuple[str, BinaryIO]]) -> dict[str, Any]:
    """Writes uploaded release files to `incoming/<version>/` once their sums match SHA256SUMS:
    {"version", "files"}. The helper's `update_verify` decides on the signature and the rules."""
    tmp = _new_folder(incoming, ".upload-")
    try:
        names: list[str] = []
        budget = MAX_RELEASE_BYTES
        for name, stream in files:
            name = os.path.basename(name or "")
            if not safe_file(name):
                raise SourceError("name", f"{name!r} is not a release file name")
            if name in names:
                raise SourceError("name", f"{name} was sent twice")
            with (tmp / name).open("xb") as out:
                budget -= _copy(stream, out, budget)
            names.append(name)
        if CHECKSUMS not in names:
            raise SourceError("missing", f"{CHECKSUMS} is missing from the release")
        sums = _check_sums(tmp, names)
        extra = sorted(set(names) - set(sums) - {CHECKSUMS, SIGNATURE})
        if extra:
            raise SourceError("unlisted", f"{', '.join(extra)} not listed in {CHECKSUMS}")
        version = release_version(tmp, names)
        _publish(tmp, incoming, version)
        return {"version": version, "files": sorted(names)}
    finally:
        if tmp.exists():
            shutil.rmtree(tmp, ignore_errors=True)


# Peers ---------------------------------------------------------------------------------------


def fetch_from_peer(client: Any, version: str, incoming: Path) -> dict[str, Any]:
    """Copies a release a peer holds (`/repl/v1/releases`) into `incoming/<version>/`, every file
    checked against the peer's SHA256SUMS; returns the listing."""
    listing = client.release_listing(version)
    names = [str(f.get("name") or "") for f in listing.get("files") or [] if isinstance(f, dict)]
    if CHECKSUMS not in names or not all(safe_file(n) for n in names):
        raise SourceError("missing", f"the peer's listing of {version} has no usable {CHECKSUMS}")
    tmp = _new_folder(incoming, f".{version}.peer-")
    try:
        for name in names:
            with (tmp / name).open("xb") as out:
                client.fetch_release_file(version, name, out)
        _check_sums(tmp, names)
        _publish(tmp, incoming, version)
        return listing
    finally:
        if tmp.exists():
            shutil.rmtree(tmp, ignore_errors=True)


@dataclass(slots=True)
class HeldReleases:
    """`ReleaseStore` of `/repl/v1/releases`: the helper's verified copies in `packages/<version>/`
    (root:pelagos, readable by the node processes)."""

    packages_root: Path
    keys: Callable[[], dict[str, Any]] = rel.load_public_keys
    _cache: dict[str, tuple[float, dict[str, Any]]] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def _folder(self, version: str) -> Path | None:
        if not valid_version(version):
            return None
        folder = self.packages_root / version
        return folder if folder.is_dir() and not folder.is_symlink() else None

    def _sums(self, folder: Path) -> dict[str, str] | None:
        try:
            return parse_checksums((folder / CHECKSUMS).read_text())
        except (OSError, ValueError):
            return None

    def listing(self, version: str) -> dict[str, Any] | None:
        folder = self._folder(version)
        if folder is None:
            return None
        try:
            mtime = (folder / CHECKSUMS).stat().st_mtime
        except OSError:
            return None
        with self._lock:
            hit = self._cache.get(version)
        if hit and hit[0] == mtime:
            return hit[1]
        sums = self._sums(folder)
        if sums is None:
            return None
        files = []
        for name in [CHECKSUMS, SIGNATURE, *sorted(sums)]:
            path = folder / name
            if not path.is_file() or path.is_symlink():
                if name == SIGNATURE:
                    continue
                return None
            files.append(
                {"name": name, "size": path.stat().st_size, "sha256": sums.get(name) or _sha256(path)}
            )
        sig = (folder / SIGNATURE).read_text() if (folder / SIGNATURE).is_file() else None
        state, _key = rel.signature_state((folder / CHECKSUMS).read_bytes(), sig, self.keys())
        out = {"version": version, "files": files, "signature": state.value}
        with self._lock:
            self._cache[version] = (mtime, out)
        return out

    def path(self, version: str, name: str) -> Path | None:
        folder = self._folder(version)
        if folder is None or not safe_file(name):
            return None
        sums = self._sums(folder)
        if sums is None or (name not in sums and name not in (CHECKSUMS, SIGNATURE)):
            return None
        path = folder / name
        return path if path.is_file() and not path.is_symlink() else None

    def holds(self, version: str) -> bool:
        return self.listing(version) is not None


# GitHub --------------------------------------------------------------------------------------


@dataclass(slots=True)
class GithubRelease:
    version: str
    tag: str
    published_at: str | None
    notes: str
    assets: dict[str, int]  # name -> asset id

    def available(self, signature: str, key_id: str | None, source: str = "github") -> dict[str, Any]:
        """The `available` entry of `GET /admin/updates`; the packages themselves are verified by
        the helper when a node installs them."""
        return {
            "version": self.version,
            "source": source,
            "published_at": self.published_at,
            "notes": self.notes,
            "signature": signature,
            "signed": signature == "valid",
            "key_id": key_id,
            "state_schema": None,
            "min_upgrade_from": None,
        }


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class GithubSource:
    """The GitHub releases of `owner/name`, with an optional read-only token. Redirects are
    followed by hand so the token never leaves api.github.com."""

    def __init__(
        self,
        repository: str,
        token: str | None = None,
        api: str = GITHUB_API,
        timeout: float = 30.0,
        opener: Any = None,
    ) -> None:
        if not REPOSITORY_RE.fullmatch(repository or ""):
            raise SourceError("repository", f"{repository!r} is not owner/name")
        self.repository = repository
        self.token = token or None
        self.api = api.rstrip("/")
        self.timeout = timeout
        self.opener = opener or urllib.request.build_opener(_NoRedirect)

    def _open(self, url: str, accept: str | None = None) -> Any:
        host = urllib.parse.urlsplit(self.api).netloc
        for _ in range(5):
            headers = dict(GITHUB_HEADERS)
            if accept:
                headers["Accept"] = accept
            if self.token and urllib.parse.urlsplit(url).netloc == host:
                headers["Authorization"] = f"Bearer {self.token}"
            try:
                request = urllib.request.Request(url, headers=headers)  # noqa: S310 - https API or its redirect
                return self.opener.open(request, timeout=self.timeout)
            except urllib.error.HTTPError as exc:
                location = exc.headers.get("Location") if exc.code in (301, 302, 303, 307, 308) else None
                if not location:
                    raise SourceError("github", f"GET {url}: HTTP {exc.code}") from None
                url = urllib.parse.urljoin(url, location)
                parts = urllib.parse.urlsplit(url)
                if parts.scheme != "https" and parts.netloc != host:
                    raise SourceError("github", f"redirect to {url} refused") from None
            except (urllib.error.URLError, OSError) as exc:
                raise SourceError("github", f"GET {url}: {exc}") from None
        raise SourceError("github", f"too many redirects for {url}")

    def _parse(self, data: Any) -> GithubRelease:
        if not isinstance(data, dict):
            raise SourceError("github", "malformed release")
        tag = str(data.get("tag_name") or "")
        version = tag[1:] if tag[:1] in ("v", "V") else tag
        if not valid_version(version):
            raise SourceError("github", f"tag {tag!r} is not a version")
        assets = {
            str(a.get("name")): int(a["id"])
            for a in data.get("assets") or []
            if isinstance(a, dict) and safe_file(str(a.get("name") or "")) and isinstance(a.get("id"), int)
        }
        return GithubRelease(version, tag, data.get("published_at"), str(data.get("body") or ""), assets)

    def _get(self, path: str) -> Any:
        with self._open(f"{self.api}/repos/{self.repository}{path}") as resp:
            try:
                return json.loads(resp.read(4 * MAX_SMALL))
            except ValueError:
                raise SourceError("github", f"{path}: not JSON") from None

    def latest(self) -> GithubRelease:
        """The newest release that is neither a draft nor a prerelease."""
        return self._parse(self._get("/releases/latest"))

    def release(self, version: str) -> GithubRelease:
        """The release tagged `v<version>` (or `<version>`)."""
        if not valid_version(version):
            raise SourceError("github", f"invalid version {version!r}")
        last: SourceError | None = None
        for tag in (f"v{version}", version):
            try:
                found = self._parse(self._get(f"/releases/tags/{urllib.parse.quote(tag, safe='')}"))
            except SourceError as exc:
                last = exc
                continue
            if found.version == version:
                return found
        raise last or SourceError("github", f"no release {version}")

    def _asset(self, asset_id: int, out: BinaryIO, budget: int) -> int:
        url = f"{self.api}/repos/{self.repository}/releases/assets/{asset_id}"
        with self._open(url, accept="application/octet-stream") as resp:
            return _copy(resp, out, budget)

    def check(self, keys: dict[str, Any] | None = None) -> dict[str, Any]:
        """The latest release as an `available` entry, its signature state read from SHA256SUMS
        and SHA256SUMS.sig against the packaged keys."""
        release = self.latest()
        if CHECKSUMS not in release.assets:
            raise SourceError("missing", f"release {release.tag} has no {CHECKSUMS}")
        sums, sig = io.BytesIO(), io.BytesIO()
        self._asset(release.assets[CHECKSUMS], sums, MAX_SMALL)
        text = None
        if SIGNATURE in release.assets:
            self._asset(release.assets[SIGNATURE], sig, MAX_SMALL)
            text = sig.getvalue().decode("utf-8", "replace")
        keys = rel.load_public_keys() if keys is None else keys
        state, key = rel.signature_state(sums.getvalue(), text, keys)
        return release.available(state.value, key)

    def download(self, release: GithubRelease, incoming: Path) -> dict[str, Any]:
        """The files SHA256SUMS lists, plus SHA256SUMS and its signature, into `incoming/<version>/`."""
        if CHECKSUMS not in release.assets:
            raise SourceError("missing", f"release {release.tag} has no {CHECKSUMS}")
        tmp = _new_folder(incoming, f".{release.version}.github-")
        try:
            budget = MAX_RELEASE_BYTES
            with (tmp / CHECKSUMS).open("xb") as out:
                budget -= self._asset(release.assets[CHECKSUMS], out, MAX_SMALL)
            try:
                sums = parse_checksums((tmp / CHECKSUMS).read_text())
            except ValueError as exc:
                raise SourceError("checksum", str(exc)) from None
            names = [CHECKSUMS]
            for name in [SIGNATURE, *sorted(sums)]:
                if name not in release.assets:
                    if name == SIGNATURE:
                        continue
                    raise SourceError("missing", f"{name} is not attached to release {release.tag}")
                with (tmp / name).open("xb") as out:
                    budget -= self._asset(release.assets[name], out, budget)
                names.append(name)
            _check_sums(tmp, names)
            release_version(tmp, names)
            _publish(tmp, incoming, release.version)
            return {"version": release.version, "files": sorted(names)}
        finally:
            if tmp.exists():
                shutil.rmtree(tmp, ignore_errors=True)


def notes_of(folder: Path) -> str:
    try:
        data = (folder / NOTES).read_bytes()[:MAX_SMALL]
    except OSError:
        return ""
    return data.decode("utf-8", "replace")


# The `available` record ----------------------------------------------------------------------

AVAILABLE_FILE = "available.json"


def available_path(var: Path) -> Path:
    """What the last check found (`{"available", "checked_at", "error"}`), service user's file."""
    return var / "upgrade" / AVAILABLE_FILE


def read_available(var: Path) -> dict[str, Any]:
    try:
        data = json.loads(available_path(var).read_text())
    except (OSError, ValueError):
        return {"available": [], "checked_at": None, "error": None}
    return data if isinstance(data, dict) else {"available": [], "checked_at": None, "error": None}


def check_github(
    var: Path,
    repository: str,
    token: str | None,
    checked_at: str,
    factory: Callable[[str, str | None], Any] = GithubSource,
) -> dict[str, Any]:
    """Reads the latest GitHub release and records it; an error is recorded, never raised."""
    record: dict[str, Any] = {"available": [], "checked_at": checked_at, "error": None}
    try:
        record["available"] = [factory(repository, token).check()]
    except (SourceError, OSError, ValueError) as exc:
        record["error"] = str(exc)
        record["available"] = read_available(var).get("available") or []
    path = available_path(var)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(record, sort_keys=True))
    os.replace(tmp, path)
    return record
