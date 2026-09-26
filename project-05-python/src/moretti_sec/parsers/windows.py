"""Windows Security log logon events 4624 (success) and 4625 (failure).

Input is JSON: one object per line, or one JSON array. The expected fields are the event's own
names, as produced by the export in project-05-python/README.en.md:
  TimeCreated, EventID, Computer, TargetUserName, TargetDomainName, IpAddress, LogonType
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from datetime import datetime, timezone

from ..company import normalize_username
from ..models import AuthEvent, Outcome

_OUTCOME = {4624: Outcome.SUCCESS, 4625: Outcome.FAILURE}
_NO_ADDRESS = {"", "-", "::1", "127.0.0.1"}


def parse_windows(lines: Iterable[str]) -> Iterator[AuthEvent]:
    for record in _records(lines):
        try:
            event_id = int(record["EventID"])
        except (KeyError, TypeError, ValueError):
            continue
        if event_id not in _OUTCOME:
            continue
        ip = str(record.get("IpAddress") or "").strip()
        logon_type = record.get("LogonType")
        yield AuthEvent(
            timestamp=_timestamp(record["TimeCreated"]),
            source="windows",
            host=str(record.get("Computer", "")),
            user=normalize_username(record.get("TargetUserName")),
            src_ip=None if ip in _NO_ADDRESS else ip,
            outcome=_OUTCOME[event_id],
            logon_type=int(logon_type) if logon_type not in (None, "", "-") else None,
            detail=f"event {event_id}",
        )


def _records(lines: Iterable[str]) -> Iterator[dict]:
    text = [line for line in lines if not line.lstrip().startswith("#")]
    joined = "\n".join(text).strip()
    if joined.startswith("["):
        yield from json.loads(joined)
        return
    for line in text:
        if line.strip():
            yield json.loads(line)


def _timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
