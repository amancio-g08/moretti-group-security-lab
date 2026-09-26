"""Detection rules over enriched authentication events.

Rule IDs are stable so reports, Wazuh rules (P03) and scenarios (phase 7) can refer to them.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import date, timedelta

from .models import EnrichedEvent, Finding, Outcome, Severity

# NM-032: device and server administration is allowed only from the jump host.
PRIVILEGED_SOURCE_ASSETS = frozenset({"JUMP01"})
# Windows logon types that mean a person at a keyboard: interactive, RDP, cached interactive.
INTERACTIVE_LOGON_TYPES = frozenset({2, 10, 11})


@dataclass(frozen=True)
class BruteForceConfig:
    threshold: int = 5
    window: timedelta = timedelta(minutes=10)


def run_all(
    events: Iterable[EnrichedEvent], brute_force: BruteForceConfig | None = None
) -> list[Finding]:
    events = sorted(events, key=lambda e: e.event.timestamp)
    findings = detect_brute_force(events, brute_force or BruteForceConfig())
    findings += detect_account_misuse(events)
    return sorted(findings, key=lambda f: (-f.severity.rank, f.first_seen, f.rule_id))


# ------------------------------------------------------------------ brute force (T1110)
def detect_brute_force(events: list[EnrichedEvent], config: BruteForceConfig) -> list[Finding]:
    by_ip: dict[str, list[EnrichedEvent]] = defaultdict(list)
    for e in events:
        if e.event.src_ip:
            by_ip[e.event.src_ip].append(e)

    findings = []
    for items in by_ip.values():
        failures = [e for e in items if e.event.outcome is Outcome.FAILURE]
        for burst in _bursts(failures, config.window):
            if _max_in_window(burst, config.window) < config.threshold:
                continue
            start, end = burst[0].event.timestamp, burst[-1].event.timestamp
            success = next(
                (
                    e
                    for e in items
                    if e.event.outcome is Outcome.SUCCESS
                    and start <= e.event.timestamp <= end + config.window
                ),
                None,
            )
            users = sorted({e.event.user or "-" for e in burst})
            where = _describe_source(burst[0])
            if success:
                findings.append(
                    Finding(
                        rule_id="BF-02",
                        title="Brute force followed by a successful logon",
                        severity=Severity.CRITICAL,
                        description=(
                            f"{len(burst)} failed logons from {where} against "
                            f"{', '.join(users)}, then a successful logon as "
                            f"{success.event.user} on {success.event.host}."
                        ),
                        events=(*burst, success),
                        mitre="T1110 Brute Force; T1078 Valid Accounts",
                    )
                )
            else:
                findings.append(
                    Finding(
                        rule_id="BF-01",
                        title="Brute force (repeated failed logons)",
                        severity=Severity.HIGH if len(users) > 1 else Severity.MEDIUM,
                        description=(
                            f"{len(burst)} failed logons from {where} against "
                            f"{len(users)} account(s): {', '.join(users)}."
                        ),
                        events=tuple(burst),
                        mitre="T1110 Brute Force",
                    )
                )
    return findings


def _bursts(events: list[EnrichedEvent], gap: timedelta) -> list[list[EnrichedEvent]]:
    """Split events into runs where consecutive events are at most `gap` apart."""
    bursts: list[list[EnrichedEvent]] = []
    for e in events:
        if bursts and e.event.timestamp - bursts[-1][-1].event.timestamp <= gap:
            bursts[-1].append(e)
        else:
            bursts.append([e])
    return bursts


def _max_in_window(events: list[EnrichedEvent], window: timedelta) -> int:
    best, left = 0, 0
    for right, e in enumerate(events):
        while e.event.timestamp - events[left].event.timestamp > window:
            left += 1
        best = max(best, right - left + 1)
    return best


# ------------------------------------------------------------------ account misuse (T1078)
@dataclass(frozen=True)
class _AccountRule:
    rule_id: str
    title: str
    severity: Callable[[EnrichedEvent], Severity | None]  # None = the event does not match
    description: str


def _terminated(e: EnrichedEvent) -> Severity | None:
    if e.account and e.account.status == "terminated":
        return Severity.CRITICAL if _succeeded(e) else Severity.MEDIUM
    return None


def _on_leave(e: EnrichedEvent) -> Severity | None:
    if e.account and e.account.status == "on_leave" and _succeeded(e):
        return Severity.MEDIUM
    return None


def _contract_ended(e: EnrichedEvent) -> Severity | None:
    a = e.account
    if (
        a
        and a.employment_type == "contractor"
        and a.end_date
        and _succeeded(e)
        and e.event.timestamp.date() > date.fromisoformat(a.end_date)
    ):
        return Severity.HIGH
    return None


def _break_glass(e: EnrichedEvent) -> Severity | None:
    if e.account and e.account.kind == "break-glass":
        return Severity.CRITICAL if _succeeded(e) else Severity.HIGH
    return None


def _service_interactive(e: EnrichedEvent) -> Severity | None:
    a = e.account
    if (
        a
        and a.kind == "service"
        and a.interactive_logon is False
        and e.event.logon_type in INTERACTIVE_LOGON_TYPES
        and _succeeded(e)
    ):
        return Severity.HIGH
    return None


def _admin_off_jump_host(e: EnrichedEvent) -> Severity | None:
    if not (e.account and e.account.kind == "admin" and _succeeded(e) and e.src):
        return None
    return None if e.src.asset_id in PRIVILEGED_SOURCE_ASSETS else Severity.HIGH


ACCOUNT_RULES = (
    _AccountRule(
        "ACC-01",
        "Logon with a terminated employee's account",
        _terminated,
        "The account belongs to an employee whose status is 'terminated'.",
    ),
    _AccountRule(
        "ACC-02",
        "Logon by an employee on leave",
        _on_leave,
        "The employee is on leave; the logon should be confirmed with the manager.",
    ),
    _AccountRule(
        "ACC-03",
        "Contractor logon after the contract end date",
        _contract_ended,
        "The contractor's end_date has passed; the account should be disabled.",
    ),
    _AccountRule(
        "ACC-04",
        "Break-glass account used",
        _break_glass,
        "Any use of a break-glass account requires an incident record.",
    ),
    _AccountRule(
        "ACC-05",
        "Interactive logon with a service account",
        _service_interactive,
        "The service account is registered with interactive_logon: false.",
    ),
    _AccountRule(
        "ACC-06",
        "Privileged account used outside the jump host",
        _admin_off_jump_host,
        "NM-032: administration is only allowed from JUMP01.",
    ),
)


def detect_account_misuse(events: list[EnrichedEvent]) -> list[Finding]:
    findings = []
    for rule in ACCOUNT_RULES:
        grouped: dict[str, list[tuple[EnrichedEvent, Severity]]] = defaultdict(list)
        for e in events:
            severity = rule.severity(e)
            if severity is not None:
                grouped[e.event.user or "-"].append((e, severity))
        for user, matches in grouped.items():
            severity = max((s for _, s in matches), key=lambda s: s.rank)
            owner = matches[0][0].account
            who = f"{user} ({owner.employee_id})" if owner and owner.employee_id else user
            sources = sorted({_describe_source(e) for e, _ in matches})
            findings.append(
                Finding(
                    rule_id=rule.rule_id,
                    title=rule.title,
                    severity=severity,
                    description=(
                        f"{who}: {len(matches)} event(s) from {', '.join(sources)}. "
                        f"{rule.description}"
                    ),
                    events=tuple(e for e, _ in matches),
                    mitre="T1078 Valid Accounts",
                )
            )
    return findings


# ------------------------------------------------------------------ helpers
def _succeeded(e: EnrichedEvent) -> bool:
    return e.event.outcome is Outcome.SUCCESS


def _describe_source(e: EnrichedEvent) -> str:
    if e.src is None:
        return "an unknown address"
    parts = [p for p in (e.src.asset_id, e.src.segment) if p]
    label = " / ".join(parts) if parts else "external"
    return f"{e.src.ip} ({label})"
