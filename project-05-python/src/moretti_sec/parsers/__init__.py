"""Log parsers. Each one turns raw lines into normalized AuthEvent objects.

Lines starting with '#' are ignored by every parser, so sample files can carry a
"SYNTHETIC" label on their first line.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from ..models import AuthEvent
from .sshd import parse_sshd
from .windows import parse_windows

FORMATS = {"sshd": parse_sshd, "windows": parse_windows}


def detect_format(lines: list[str]) -> str:
    """Windows exports are JSON (lines or array); anything else is treated as syslog."""
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            return "windows" if stripped[0] in "{[" else "sshd"
    return "sshd"


def parse_file(path: Path, fmt: str | None = None, year: int | None = None) -> Iterator[AuthEvent]:
    lines = path.read_text(encoding="utf-8").splitlines()
    fmt = fmt or detect_format(lines)
    if fmt not in FORMATS:
        raise ValueError(f"unknown format {fmt!r}; expected one of {sorted(FORMATS)}")
    if fmt == "sshd":
        return parse_sshd(lines, year=year)
    return parse_windows(lines)


__all__ = ["FORMATS", "detect_format", "parse_file", "parse_sshd", "parse_windows"]
