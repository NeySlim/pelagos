# SPDX-License-Identifier: Apache-2.0
"""Package version ordering of dpkg and rpm, in Python so the helper never shells out to compare.

Debian: `verrevcmp` of dpkg (lib/dpkg/version.c, deb-version(7): `~` sorts before anything, letters
before other characters). RPM: `rpmvercmp` of rpm 4.x (rpmio/rpmvercmp.c, with `~` and `^`).
"""

from __future__ import annotations


def _deb_order(c: str) -> int:
    if not c or c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    if c == "~":
        return -1
    return ord(c) + 256


def _deb_part(a: str, b: str) -> int:
    i = j = 0
    while i < len(a) or j < len(b):
        first_diff = 0
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _deb_order(a[i] if i < len(a) and not a[i].isdigit() else "")
            bc = _deb_order(b[j] if j < len(b) and not b[j].isdigit() else "")
            if ac != bc:
                return ac - bc
            i, j = i + 1, j + 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        while i < len(a) and j < len(b) and a[i].isdigit() and b[j].isdigit():
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i, j = i + 1, j + 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first_diff:
            return first_diff
    return 0


def _deb_split(v: str) -> tuple[int, str, str]:
    epoch, _, rest = v.rpartition(":") if ":" in v else ("0", "", v)
    upstream, _, revision = rest.rpartition("-") if "-" in rest else (rest, "", "")
    return int(epoch or 0), upstream, revision


def deb_compare(a: str, b: str) -> int:
    """<0, 0 or >0 as `dpkg --compare-versions a lt|eq|gt b`."""
    ea, ua, ra = _deb_split(a)
    eb, ub, rb = _deb_split(b)
    if ea != eb:
        return ea - eb
    return _deb_part(ua, ub) or _deb_part(ra, rb)


def _rpm_segment(s: str, i: int, digits: bool) -> int:
    while i < len(s) and (s[i].isdigit() if digits else s[i].isascii() and s[i].isalpha()):
        i += 1
    return i


def rpmvercmp(a: str, b: str) -> int:
    """-1, 0 or 1 as rpmvercmp(a, b)."""
    if a == b:
        return 0
    i = j = 0
    sep = lambda c: not (c.isascii() and c.isalnum()) and c not in "~^"  # noqa: E731
    while i < len(a) or j < len(b):
        while i < len(a) and sep(a[i]):
            i += 1
        while j < len(b) and sep(b[j]):
            j += 1
        ca, cb = a[i] if i < len(a) else "", b[j] if j < len(b) else ""
        if ca == "~" or cb == "~":
            if ca != "~":
                return 1
            if cb != "~":
                return -1
            i, j = i + 1, j + 1
            continue
        if ca == "^" or cb == "^":
            if not ca:
                return -1
            if not cb:
                return 1
            if ca != "^":
                return 1
            if cb != "^":
                return -1
            i, j = i + 1, j + 1
            continue
        if not (ca and cb):
            break
        digits = ca.isdigit()
        ei, ej = _rpm_segment(a, i, digits), _rpm_segment(b, j, digits)
        sa, sb = a[i:ei], b[j:ej]
        if not sb:
            return 1 if digits else -1
        if digits:
            sa, sb = sa.lstrip("0"), sb.lstrip("0")
            if len(sa) != len(sb):
                return 1 if len(sa) > len(sb) else -1
        if sa != sb:
            return 1 if sa > sb else -1
        i, j = ei, ej
    if i >= len(a) and j >= len(b):
        return 0
    return -1 if i >= len(a) else 1


def _rpm_split(v: str) -> tuple[int, str, str | None]:
    epoch, _, rest = v.partition(":") if ":" in v else ("0", "", v)
    version, _, release = rest.rpartition("-") if "-" in rest else (rest, "", None)
    return int(epoch or 0), version, release


def rpm_compare(a: str, b: str) -> int:
    """EVR order of rpm; the release is compared only when both sides have one."""
    ea, va, ra = _rpm_split(a)
    eb, vb, rb = _rpm_split(b)
    if ea != eb:
        return 1 if ea > eb else -1
    return rpmvercmp(va, vb) or (rpmvercmp(ra, rb) if ra is not None and rb is not None else 0)


def compare(package_format: str, a: str, b: str) -> int:
    """Sign of a against b for `deb` or `rpm` versions."""
    if package_format == "deb":
        diff = deb_compare(a, b)
    elif package_format == "rpm":
        diff = rpm_compare(a, b)
    else:
        raise ValueError(f"unknown package format {package_format!r}")
    return (diff > 0) - (diff < 0)


def upstream(package_format: str, version: str) -> str:
    """The version without its Debian revision or rpm release (and without epoch)."""
    rest = version.split(":", 1)[1] if ":" in version else version
    return rest.rpartition("-")[0] if "-" in rest else rest
