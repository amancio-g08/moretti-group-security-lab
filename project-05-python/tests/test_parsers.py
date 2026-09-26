from datetime import datetime, timezone

from conftest import FIXTURES

from moretti_sec.models import Outcome
from moretti_sec.parsers import detect_format, parse_file


def test_sshd_parses_only_authentication_attempts():
    events = list(parse_file(FIXTURES / "synthetic-sshd.log", year=2026))
    # "Invalid user" lines are not counted twice; CRON and "Connection closed" are ignored.
    assert [(e.user, e.outcome) for e in events] == [
        ("admin", Outcome.FAILURE),
        ("root", Outcome.FAILURE),
        ("adm-ana.costa", Outcome.SUCCESS),
        ("joao.silva", Outcome.SUCCESS),
    ]
    assert events[0].src_ip == "198.51.100.66"
    assert events[0].host == "app-fin01"
    assert events[2].timestamp == datetime(2026, 9, 6, 9, 0, 9, tzinfo=timezone.utc)
    assert events[2].detail == "ssh publickey"


def test_sshd_keeps_rfc3339_timezone():
    events = list(parse_file(FIXTURES / "synthetic-sshd.log", year=2026))
    assert events[3].timestamp == datetime(2026, 9, 26, 8, 0, 0, 500000, tzinfo=timezone.utc)


def test_windows_json_array_and_normalization():
    events = list(parse_file(FIXTURES / "synthetic-windows.json"))
    assert len(events) == 3  # 4634 (logoff) is not an authentication attempt
    admin, alan, local = events
    assert (admin.user, admin.src_ip, admin.logon_type) == (
        "adm-marcio.guimaraes",
        "10.10.10.20",
        10,
    )
    assert (alan.user, alan.src_ip, alan.outcome, alan.logon_type) == (
        "alan.moreira",
        None,
        Outcome.FAILURE,
        3,
    )
    assert alan.timestamp.tzinfo is not None
    assert (local.user, local.src_ip) == ("joao.silva", None)


def test_format_detection():
    assert detect_format(["# comment", '{"EventID": 4624}']) == "windows"
    assert detect_format(["# comment", "[{}]"]) == "windows"
    assert detect_format(["Sep 26 09:00:00 host sshd[1]: x"]) == "sshd"
