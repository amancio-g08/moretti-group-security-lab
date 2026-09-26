"""Attach company context (asset, segment, account owner) to each event."""

from __future__ import annotations

from collections.abc import Iterable

from .company import Company
from .models import AuthEvent, EnrichedEvent


def enrich(events: Iterable[AuthEvent], company: Company) -> list[EnrichedEvent]:
    return [
        EnrichedEvent(
            event=event,
            src=company.ip_context(event.src_ip),
            host_asset=company.asset_by_hostname(event.host),
            account=company.account(event.user),
        )
        for event in events
    ]
