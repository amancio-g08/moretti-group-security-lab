"""Merge authentication events, VPC Flow Logs and Wazuh alerts into one enriched timeline.

Each source is read by its parser, then every record is turned into a TimelineItem with company
context (asset, segment, account) attached from data/. The result is one chronological view, so a
single scenario can be followed from the network flow to the alert to the logon.
"""

from __future__ import annotations

from collections.abc import Iterable

from .company import Company
from .models import AuthEvent, NetworkFlow, TimelineItem, WazuhAlert


def _endpoint(company: Company, ip: str | None):
    return company.ip_context(ip)


def _label(company: Company, ip: str | None) -> str:
    ctx = company.ip_context(ip)
    if ctx and (ctx.asset_id or ctx.segment):
        return f"{ip} ({ctx.asset_id or ctx.segment})"
    return ip or "?"


def auth_item(event: AuthEvent, company: Company) -> TimelineItem:
    account = company.account(event.user)
    who = event.user or "?"
    if account and account.employee_id:
        who += f" ({account.employee_id})"
    return TimelineItem(
        timestamp=event.timestamp,
        source="auth",
        summary=f"{event.outcome.value} logon as {who} on {event.host} "
        f"from {_label(company, event.src_ip)}",
        src=_endpoint(company, event.src_ip),
        account=account,
        outcome=event.outcome.value,
    )


def flow_item(flow: NetworkFlow, company: Company) -> TimelineItem:
    port = f":{flow.dst_port}" if flow.dst_port is not None else ""
    return TimelineItem(
        timestamp=flow.timestamp,
        source="flow",
        summary=f"{flow.action} {flow.protocol} {_label(company, flow.src_ip)} -> "
        f"{_label(company, flow.dst_ip)}{port}",
        src=_endpoint(company, flow.src_ip),
        dst=_endpoint(company, flow.dst_ip),
        outcome=flow.action,
    )


def wazuh_item(alert: WazuhAlert, company: Company) -> TimelineItem:
    where = alert.agent or _label(company, alert.src_ip)
    return TimelineItem(
        timestamp=alert.timestamp,
        source="wazuh",
        summary=f"[{alert.level}] {alert.description} ({where})",
        src=_endpoint(company, alert.src_ip),
        account=company.account(alert.user),
        rule_ids=(alert.rule_id,) if alert.rule_id else (),
    )


def build(
    company: Company,
    auth: Iterable[AuthEvent] = (),
    flows: Iterable[NetworkFlow] = (),
    alerts: Iterable[WazuhAlert] = (),
) -> list[TimelineItem]:
    items = [auth_item(e, company) for e in auth]
    items += [flow_item(f, company) for f in flows]
    items += [wazuh_item(a, company) for a in alerts]
    # Stable sort by time; ties keep the order sources were added, so a flow that logically
    # precedes an alert in the same second stays before it.
    return sorted(items, key=lambda item: item.timestamp)
