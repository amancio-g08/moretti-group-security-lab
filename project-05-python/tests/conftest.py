"""Shared fixtures. All log lines in these tests are SYNTHETIC (fictitious lab)."""

from datetime import datetime, timezone
from pathlib import Path

import pytest

from moretti_sec.company import Company
from moretti_sec.models import AuthEvent, Outcome

REPO_DATA = Path(__file__).resolve().parents[2] / "data"
FIXTURES = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture(scope="session")
def company() -> Company:
    return Company.load(REPO_DATA)


@pytest.fixture
def make_event():
    def _make(user, ip, outcome=Outcome.SUCCESS, minute=0, day=26, month=9, logon_type=None):
        return AuthEvent(
            timestamp=datetime(2026, month, day, 12, 0, tzinfo=timezone.utc).replace(minute=minute),
            source="windows",
            host="DC01",
            user=user,
            src_ip=ip,
            outcome=outcome,
            logon_type=logon_type,
        )

    return _make
