"""Chronological view that merges every source and marks events tied to a finding."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime

from .models import EnrichedEvent, Finding


@dataclass(frozen=True)
class TimelineEntry:
    timestamp: datetime
    event: EnrichedEvent
    rule_ids: tuple[str, ...]


def build_timeline(
    events: Iterable[EnrichedEvent], findings: Iterable[Finding], only_flagged: bool = False
) -> list[TimelineEntry]:
    flags: dict[int, set[str]] = {}
    for finding in findings:
        for e in finding.events:
            flags.setdefault(id(e), set()).add(finding.rule_id)
    entries = [
        TimelineEntry(e.event.timestamp, e, tuple(sorted(flags.get(id(e), ())))) for e in events
    ]
    if only_flagged:
        entries = [entry for entry in entries if entry.rule_ids]
    return sorted(entries, key=lambda entry: entry.timestamp)
