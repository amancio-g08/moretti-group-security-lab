"""Offline checks of the Wazuh detections in project-03-soc.

These prove the files are consistent with each other and with data/. Whether the manager's
parent rules and decoders behave as assumed is checked on SIEM01 by run_logtest.py (W-05..W-07).
"""

import copy
import csv
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest
import yaml
from conftest import REPO_DATA

from moretti_sec.render._cli import PolicyError
from moretti_sec.render.wazuh_lists import LISTS, main, render

SOC = REPO_DATA.parent / "project-03-soc"
RULES = SOC / "detections/rules/moretti_rules.xml"
CASES = SOC / "detections/tests/cases.json"
OSSEC_BLOCK = SOC / "wazuh/moretti-ossec.conf"


@pytest.fixture(scope="module")
def sources():
    accounts = yaml.safe_load((REPO_DATA / "accounts.yaml").read_text(encoding="utf-8"))
    with (REPO_DATA / "employees.csv").open(encoding="utf-8", newline="") as handle:
        return accounts, list(csv.DictReader(handle))


@pytest.fixture(scope="module")
def rules():
    # A Wazuh rules file has several top-level <group> elements: wrap it to parse it.
    root = ET.fromstring(f"<root>{RULES.read_text(encoding='utf-8')}</root>")
    return {int(rule.get("id")): rule for rule in root.iter("rule")}


@pytest.fixture(scope="module")
def cases():
    return json.loads(CASES.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------- lists
def test_generated_lists_are_up_to_date():
    assert main(["--check", "--data-dir", str(REPO_DATA)]) == 0


def test_lists_follow_data(sources):
    lists = render(*sources)
    assert lists["moretti-terminated-accounts"] == {"alan.moreira": "MG-0097"}
    assert lists["moretti-on-leave-accounts"] == {"aline.barros": "MG-0024"}
    assert lists["moretti-break-glass-accounts"] == {"bg-admin01": "security"}
    assert "svc-backup$" in lists["moretti-service-accounts"]  # gMSAs log on with a trailing $
    assert len(lists["moretti-admin-accounts"]) == 9


def test_admin_account_of_a_leaver_is_listed_as_terminated(sources):
    accounts, employees = copy.deepcopy(sources)
    for emp in employees:
        if emp["employee_id"] == "MG-0082":
            emp["status"] = "terminated"
    assert "adm-rogerio.quintela" in render(accounts, employees)["moretti-terminated-accounts"]


def test_invalid_account_name_is_rejected(sources):
    accounts, employees = copy.deepcopy(sources)
    accounts["service_accounts"][0]["username"] = "Svc-Upper"
    with pytest.raises(PolicyError, match="invalid account name"):
        render(accounts, employees)


# ---------------------------------------------------------------------------- rules
def test_rule_ids_are_unique_and_in_the_lab_range(rules):
    text = RULES.read_text(encoding="utf-8")
    ids = [int(i) for i in re.findall(r'<rule id="(\d+)"', text)]
    assert len(ids) == len(set(ids)) == len(rules)
    assert all(100100 <= i <= 100199 for i in ids)


def test_every_rule_is_documented(rules):
    for rule_id, rule in rules.items():
        description = rule.findtext("description")
        assert re.match(r"^(ACC|BF|NET|CT)-\d\d: ", description), rule_id
        assert rule.find("mitre/id") is not None, rule_id
        assert 0 < int(rule.get("level")) <= 15


def test_every_list_used_by_a_rule_is_generated_and_loaded(rules):
    loaded = set(re.findall(r"<list>etc/lists/([\w-]+)</list>", OSSEC_BLOCK.read_text()))
    assert loaded == set(LISTS)
    for rule in rules.values():
        for element in rule.iter("list"):
            name = element.text.rsplit("/", 1)[-1]
            assert name in LISTS
            assert (SOC / "detections/lists" / name).is_file()


# ---------------------------------------------------------------------------- test cases
def test_cases_are_labeled_synthetic(cases):
    assert cases["_synthetic"].startswith("SYNTHETIC")


def test_every_rule_has_a_positive_case(rules, cases):
    expected = {case["expect"] for case in cases["cases"] if "expect" in case}
    assert expected == set(rules)


def test_cases_are_well_formed(cases):
    ids = [case["id"] for case in cases["cases"]]
    assert len(ids) == len(set(ids))
    for case in cases["cases"]:
        assert case["log_format"] in {"eventchannel", "json", "syslog"}
        if case["log_format"] != "syslog":
            json.loads(case["event"])  # must be valid JSON
        assert ("expect" in case) != ("expect_not" in case)


def test_cases_only_use_lab_or_documentation_addresses(cases):
    for case in cases["cases"]:
        for address in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", case["event"]):
            assert address.startswith(("10.10.", "198.51.100.", "203.0.113.")), address


def test_ssh_case_uses_the_guest_network(cases):
    ssh = next(c for c in cases["cases"] if c["id"] == "bf01-ssh-guest")
    assert "from 10.10.90." in ssh["event"]


# ---------------------------------------------------------------------------- configuration files
@pytest.mark.parametrize(
    "path",
    [OSSEC_BLOCK, *sorted((SOC / "agents/groups").glob("*/agent.conf"))],
    ids=lambda p: str(Path(p).relative_to(SOC)),
)
def test_configuration_files_are_well_formed_xml(path):
    ET.fromstring(path.read_text(encoding="utf-8"))
