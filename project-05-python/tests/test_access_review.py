"""Tests for the access review (moretti_sec.access_review).

A synthetic AD export is derived from the real plan so that a clean export produces no findings;
each test then injects one deviation and checks it is reported (and, where relevant, its severity).
"""

import csv
import io
import json

import pytest
from conftest import REPO_DATA

from moretti_sec.access_review import load_ad_export, render_markdown, review
from moretti_sec.models import Severity

PLAN = REPO_DATA.parent / "project-04-iam" / "generated" / "ad-plan.json"


@pytest.fixture(scope="module")
def plan():
    return json.loads(PLAN.read_text(encoding="utf-8"))


def clean_export(plan) -> dict[str, dict]:
    """The AD as the plan expects it: every account enabled per plan, in exactly its groups."""
    from moretti_sec.access_review import _plan_index

    index = _plan_index(plan)
    accounts = {}
    for sam, user in index["users"].items():
        accounts[sam] = {"enabled": user["enabled"], "groups": set(index["expected_groups"][sam])}
    return accounts


def to_csv(accounts: dict[str, dict]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["sam", "enabled", "groups"])
    for sam, acc in accounts.items():
        writer.writerow([sam, str(acc["enabled"]).lower(), ";".join(sorted(acc["groups"]))])
    return buf.getvalue()


def test_clean_export_has_no_findings(plan):
    result = review(plan, clean_export(plan))
    assert result.findings == []
    assert result.accounts_reviewed == len(plan["users"])


def test_round_trips_through_csv(plan, tmp_path):
    path = tmp_path / "export.csv"
    path.write_text(to_csv(clean_export(plan)), encoding="utf-8")
    assert review(plan, load_ad_export(path)).findings == []


def _checks(result):
    return {(f.check, f.account) for f in result.findings}


def test_terminated_account_still_enabled(plan):
    export = clean_export(plan)
    export["alan.moreira"]["enabled"] = True  # MG-0097 is terminated in the plan
    result = review(plan, export)
    assert ("should-be-disabled", "alan.moreira") in _checks(result)


def test_extra_privileged_membership_is_critical(plan):
    export = clean_export(plan)
    export["joao.silva"]["groups"].add("GG-Priv-ServerAdmin")
    finding = next(f for f in review(plan, export).findings if f.check == "extra-membership")
    assert finding.account == "joao.silva"
    assert finding.severity is Severity.CRITICAL


def test_unknown_account_and_its_privilege(plan):
    export = clean_export(plan)
    export["mallory"] = {"enabled": True, "groups": {"Domain Admins"}}
    checks = _checks(review(plan, export))
    assert ("unknown-account", "mallory") in checks
    assert ("privileged-membership", "mallory") in checks


def test_missing_membership_is_flagged(plan):
    export = clean_export(plan)
    export["joao.silva"]["groups"].discard("GG-Role-FinanceStaff")
    assert ("missing-membership", "joao.silva") in _checks(review(plan, export))


def test_segregation_of_duties(plan):
    export = clean_export(plan)
    export["joao.silva"]["groups"].update(
        {"DL-APP-FIN-Ledger-Maker", "DL-APP-FIN-Payment-Approver"}
    )
    finding = next(f for f in review(plan, export).findings if f.check == "segregation-of-duties")
    assert finding.severity is Severity.CRITICAL


def test_account_disabled_against_the_plan(plan):
    export = clean_export(plan)
    export["joao.silva"]["enabled"] = False  # the plan expects him enabled
    assert ("unexpectedly-disabled", "joao.silva") in _checks(review(plan, export))


def test_on_leave_account_keeping_groups_is_not_flagged(plan):
    # aline.barros (MG-0024) is on leave: disabled in the plan but keeps her groups on purpose.
    result = review(plan, clean_export(plan))
    assert not any(f.account == "aline.barros" for f in result.findings)


def test_report_renders(plan):
    export = clean_export(plan)
    export["mallory"] = {"enabled": True, "groups": {"Domain Admins"}}
    text = render_markdown(review(plan, export), "export.csv", plan["domain"]["fqdn"])
    assert "# Access review" in text and "mallory" in text and "corp.moretti.internal" in text


def test_findings_sorted_by_severity(plan):
    export = clean_export(plan)
    export["mallory"] = {"enabled": True, "groups": {"Domain Admins"}}
    export["joao.silva"]["groups"].discard("GG-Role-FinanceStaff")
    ranks = [f.severity.rank for f in review(plan, export).findings]
    assert ranks == sorted(ranks, reverse=True)
