"""OpenSSH server messages from syslog (auth.log / secure).

Two timestamp styles are accepted:
  classic  "Sep 26 10:15:01 app-fin01 sshd[812]: ..."   (no year: the caller supplies it)
  RFC 3339 "2026-09-26T10:15:01+00:00 app-fin01 sshd[812]: ..."
Timestamps without a zone are taken as UTC.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from datetime import datetime, timezone

from ..company import normalize_username
from ..models import AuthEvent, Outcome

_HEADER = re.compile(
    r"^(?:(?P<iso>\d{4}-\d{2}-\d{2}T\S+)|(?P<classic>[A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2}))"
    r"\s+(?P<host>\S+)\s+sshd(?:\[\d+\])?:\s+(?P<msg>.*)$"
)
_ATTEMPT = re.compile(
    r"^(?P<result>Accepted|Failed) (?P<method>\S+) for (?:invalid user )?(?P<user>\S+)"
    r" from (?P<ip>[0-9a-fA-F:.]+) port \d+"
)
_INVALID = re.compile(r"^Invalid user (?P<user>\S*) from (?P<ip>[0-9a-fA-F:.]+)")


def parse_sshd(lines: Iterable[str], year: int | None = None) -> Iterator[AuthEvent]:
    year = year or datetime.now(timezone.utc).year
    for line in lines:
        header = _HEADER.match(line.rstrip("\n"))
        if not header:
            continue
        attempt = _ATTEMPT.match(header["msg"])
        if not attempt:
            # "Invalid user" lines are always followed by a "Failed ..." line; skipping them
            # avoids counting one attempt twice.
            continue
        yield AuthEvent(
            timestamp=_timestamp(header, year),
            source="sshd",
            host=header["host"],
            user=normalize_username(attempt["user"]),
            src_ip=attempt["ip"],
            outcome=Outcome.SUCCESS if attempt["result"] == "Accepted" else Outcome.FAILURE,
            detail=f"ssh {attempt['method']}",
        )


def _timestamp(header: re.Match[str], year: int) -> datetime:
    if header["iso"]:
        value = datetime.fromisoformat(header["iso"].replace("Z", "+00:00"))
    else:
        value = datetime.strptime(f"{year} {header['classic']}", "%Y %b %d %H:%M:%S")
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
