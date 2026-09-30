"""Wazuh alerts from alerts.json (one JSON object per line, as the manager writes them).

Only the fields the correlated timeline needs are read. Fields that a given alert does not have
(a network alert has no user, an AWS alert has no agent) come back as None. Lines starting with
'#' and blank lines are ignored.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from datetime import datetime, timezone

from ..company import normalize_username
from ..models import WazuhAlert


def _timestamp(value: str | None) -> datetime:
    if not value:
        return datetime.fromtimestamp(0, tz=timezone.utc)
    # Wazuh uses e.g. "2026-09-30T12:00:00.000+0000"; make the offset ISO-parseable.
    text = value.strip()
    if len(text) >= 5 and text[-5] in "+-" and text[-3] != ":":
        text = text[:-2] + ":" + text[-2:]
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return datetime.fromtimestamp(0, tz=timezone.utc)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _first(*values: str | None) -> str | None:
    for value in values:
        if value:
            return value
    return None


def parse_wazuh_alerts(lines: Iterable[str]) -> Iterator[WazuhAlert]:
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        record = json.loads(line)
        rule = record.get("rule") or {}
        data = record.get("data") or {}
        win = (data.get("win") or {}).get("eventdata") or {}
        aws = data.get("aws") or {}
        agent = (record.get("agent") or {}).get("name")
        yield WazuhAlert(
            timestamp=_timestamp(record.get("timestamp")),
            rule_id=str(rule.get("id", "")),
            level=int(rule.get("level", 0)),
            description=rule.get("description", ""),
            agent=agent,
            src_ip=_first(data.get("srcip"), win.get("ipAddress"), aws.get("srcaddr")),
            user=normalize_username(
                _first(data.get("dstuser"), data.get("srcuser"), win.get("targetUserName"))
            ),
            groups=tuple(rule.get("groups", [])),
        )
