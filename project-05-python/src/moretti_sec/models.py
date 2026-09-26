"""Normalized data structures shared by every stage of the pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class Outcome(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return list(Severity).index(self)


@dataclass(frozen=True)
class AuthEvent:
    """One authentication attempt, whatever log it came from."""

    timestamp: datetime  # timezone-aware
    source: str  # parser that produced it: "sshd" or "windows"
    host: str  # host that recorded the event
    user: str | None  # normalized: lowercase, no domain
    src_ip: str | None
    outcome: Outcome
    logon_type: int | None = None  # Windows logon type (2 interactive, 3 network, 10 RDP)
    detail: str = ""


@dataclass(frozen=True)
class IpContext:
    ip: str
    asset_id: str | None
    segment: str | None


@dataclass(frozen=True)
class AccountContext:
    username: str
    kind: str  # employee | admin | service | break-glass | unknown
    employee_id: str | None = None
    department: str | None = None
    status: str | None = None  # active | on_leave | terminated (of the owning employee)
    employment_type: str | None = None
    end_date: str | None = None
    interactive_logon: bool | None = None  # service accounts only


@dataclass(frozen=True)
class EnrichedEvent:
    event: AuthEvent
    src: IpContext | None
    host_asset: str | None
    account: AccountContext | None


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: Severity
    description: str
    events: tuple[EnrichedEvent, ...] = field(default_factory=tuple)
    mitre: str = ""

    @property
    def first_seen(self) -> datetime | None:
        return min((e.event.timestamp for e in self.events), default=None)
