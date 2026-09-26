from datetime import timedelta

from moretti_sec.detections import BruteForceConfig, run_all
from moretti_sec.enrich import enrich
from moretti_sec.models import Outcome, Severity

FAIL = Outcome.FAILURE


def rules(findings):
    return {(f.rule_id, f.severity) for f in findings}


def test_brute_force_needs_threshold_inside_window(company, make_event):
    spread = [make_event("root", "198.51.100.66", FAIL, minute=m) for m in (0, 11, 22, 33, 44)]
    assert run_all(enrich(spread, company)) == []

    burst = [
        make_event(u, "198.51.100.66", FAIL, minute=m)
        for m, u in enumerate(["root", "admin", "root", "test", "oracle"])
    ]
    findings = run_all(enrich(burst, company))
    assert rules(findings) == {("BF-01", Severity.HIGH)}
    assert len(findings[0].events) == 5


def test_brute_force_on_one_account_is_medium(company, make_event):
    events = [make_event("joao.silva", "10.10.50.10", FAIL, minute=m) for m in range(5)]
    assert rules(run_all(enrich(events, company))) == {("BF-01", Severity.MEDIUM)}


def test_brute_force_followed_by_success_is_critical(company, make_event):
    events = [make_event("joao.silva", "10.10.50.10", FAIL, minute=m) for m in range(5)]
    events.append(make_event("joao.silva", "10.10.50.10", minute=8))
    findings = run_all(enrich(events, company))
    assert rules(findings) == {("BF-02", Severity.CRITICAL)}
    assert "WS-DEV01" in findings[0].description


def test_threshold_is_configurable(company, make_event):
    events = [make_event("root", "198.51.100.66", FAIL, minute=m) for m in range(3)]
    config = BruteForceConfig(threshold=3, window=timedelta(minutes=5))
    assert rules(run_all(enrich(events, company), config)) == {("BF-01", Severity.MEDIUM)}


def test_account_rules(company, make_event):
    events = [
        make_event("alan.moreira", "10.10.60.10"),  # terminated
        make_event("aline.barros", "10.10.20.10", minute=1),  # on leave
        make_event("leandro.viana", "10.10.50.10", day=15, month=11),  # contract ended 2026-10-30
        make_event("bg-admin01", "10.10.10.20", minute=2),  # break-glass
        make_event("svc-app-fin", "10.10.60.10", minute=3, logon_type=10),
        make_event("adm-rogerio.quintela", "10.10.60.10", minute=4),  # admin off JUMP01
    ]
    assert rules(run_all(enrich(events, company))) == {
        ("ACC-01", Severity.CRITICAL),
        ("ACC-02", Severity.MEDIUM),
        ("ACC-03", Severity.HIGH),
        ("ACC-04", Severity.CRITICAL),
        ("ACC-05", Severity.HIGH),
        ("ACC-06", Severity.HIGH),
    }


def test_expected_activity_is_not_flagged(company, make_event):
    events = [
        make_event("adm-marcio.guimaraes", "10.10.10.20", logon_type=10),  # admin from JUMP01
        make_event("svc-app-fin", "10.10.80.30", minute=1, logon_type=3),  # service, network logon
        make_event("leandro.viana", "10.10.50.10", minute=2),  # contract still valid
        make_event("joao.silva", "10.10.20.10", minute=3),
        make_event("alan.moreira", "10.10.60.10", FAIL, minute=4),  # failure only
    ]
    # Only the terminated account's failed attempt is reported, and only as medium.
    assert rules(run_all(enrich(events, company))) == {("ACC-01", Severity.MEDIUM)}


def test_findings_are_sorted_by_severity(company, make_event):
    events = [
        make_event("aline.barros", "10.10.20.10"),
        make_event("bg-admin01", "10.10.10.20", minute=5),
    ]
    assert [f.rule_id for f in run_all(enrich(events, company))] == ["ACC-04", "ACC-02"]
