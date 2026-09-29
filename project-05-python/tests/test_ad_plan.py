import copy
import csv

import pytest
import yaml
from conftest import REPO_DATA

from moretti_sec.render._cli import PolicyError
from moretti_sec.render.ad_plan import SAM_MAX, main, render


def _load(name):
    return yaml.safe_load((REPO_DATA / name).read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def sources():
    with (REPO_DATA / "employees.csv").open(encoding="utf-8", newline="") as handle:
        employees = list(csv.DictReader(handle))
    return _load("company.yaml"), _load("roles.yaml"), _load("accounts.yaml"), employees


@pytest.fixture(scope="module")
def plan(sources):
    return render(*sources)


@pytest.fixture(scope="module")
def users(plan):
    return {u["sam"]: u for u in plan["users"]}


@pytest.fixture(scope="module")
def groups(plan):
    return {g["name"]: g for g in plan["groups"]}


def memberships(groups, sam):
    return {name for name, g in groups.items() if sam in g["members"]}


def effective_members(groups, builtin, name):
    """Accounts that end up in `name`, following nested groups."""
    pending = list(builtin.get(name, [])) + list(groups.get(name, {}).get("members", []))
    seen, accounts = set(), set()
    while pending:
        member = pending.pop()
        if member in seen:
            continue
        seen.add(member)
        if member in groups:
            pending += groups[member]["members"]
        else:
            accounts.add(member)
    return accounts


def test_generated_file_is_up_to_date():
    assert main(["--check", "--data-dir", str(REPO_DATA)]) == 0


def test_every_account_fits_active_directory(plan):
    sams = [u["sam"] for u in plan["users"]]
    assert len(sams) == len(set(sams))
    assert all(len(s) <= SAM_MAX for s in sams)
    assert all(u["upn"].endswith("@corp.moretti.internal") for u in plan["users"])


def test_ous_are_listed_parents_first(plan):
    ous = plan["organizational_units"]
    for index, dn in enumerate(ous):
        parent = dn.split(",", 1)[1]
        assert parent.startswith("DC=") or parent in ous[:index]


def test_active_employee_gets_exactly_its_role(users, groups):
    joao = users["joao.silva"]
    assert joao["enabled"] and joao["ou"].startswith("OU=Finance,OU=Users,")
    assert joao["manager"] == "patricia.lopes"
    assert memberships(groups, "joao.silva") == {"GG-All-Staff", "GG-Role-FinanceStaff"}


def test_terminated_employee_is_disabled_isolated_and_groupless(users, groups):
    alan = users["alan.moreira"]  # MG-0097
    assert not alan["enabled"]
    assert alan["ou"].startswith("OU=Disabled,")
    assert memberships(groups, "alan.moreira") == set()


def test_employee_on_leave_is_disabled_but_keeps_its_role(users, groups):
    aline = users["aline.barros"]  # MG-0024
    assert not aline["enabled"]
    assert "GG-Role-FinanceStaff" in memberships(groups, "aline.barros")


def test_contractor_account_expires_with_the_contract(users):
    assert users["leandro.viana"]["expires_after"] == "2026-10-30"  # MG-0074
    assert users["joao.silva"]["expires_after"] is None


def test_agdlp_role_groups_nest_into_entitlement_groups(groups):
    assert groups["GG-Role-FinanceStaff"]["scope"] == "Global"
    ledger = groups["DL-APP-FIN-Ledger-Maker"]
    assert ledger["scope"] == "DomainLocal"
    assert ledger["members"] == ["GG-Role-FinanceStaff"]  # groups only, never accounts
    for group in groups.values():
        if group["scope"] == "DomainLocal":
            assert all(m in groups for m in group["members"])


def test_segregation_of_duties_payment_maker_is_not_approver(groups, plan):
    makers = effective_members(groups, {}, "DL-APP-FIN-Ledger-Maker")
    approvers = effective_members(groups, {}, "DL-APP-FIN-Payment-Approver")
    assert makers and approvers
    assert not makers & approvers


def test_only_named_tier0_accounts_become_domain_admins(groups, plan):
    builtin = plan["builtin_group_members"]
    assert builtin["Domain Admins"] == ["GG-Priv-Tier0DomainAdmin"]
    assert effective_members(groups, builtin, "Domain Admins") == {
        "adm-marcio.guimaraes",
        "bg-admin01",
    }


def test_employee_accounts_never_hold_privileged_access(users, groups):
    privileged = [name for name, g in groups.items() if g["ou"].startswith("OU=Groups,OU=Admin")]
    employees = {sam for sam, u in users.items() if u["kind"] == "employee"}
    for name in privileged:
        assert not effective_members(groups, {}, name) & employees, name


def test_admin_accounts_are_separate_and_protected(users, groups, plan):
    admin = users["adm-rogerio.quintela"]
    assert admin["kind"] == "admin" and admin["ou"].startswith("OU=Tier1,OU=Admin,")
    assert memberships(groups, "adm-rogerio.quintela") == {
        "GG-Admin-Accounts",
        "GG-Priv-NetworkAdmin",
    }
    assert not admin["must_change_password"]
    assert users["joao.silva"]["must_change_password"]
    assert "adm-rogerio.quintela" in plan["builtin_group_members"]["Protected Users"]
    assert "bg-admin01" not in plan["builtin_group_members"]["Protected Users"]


def test_service_accounts(users, groups, plan):
    scanner = users["svc-vulnscan"]
    assert scanner["password_never_expires"] and not scanner["must_change_password"]
    assert memberships(groups, "svc-vulnscan") == {"GG-Service-Accounts"}
    assert plan["managed_service_accounts"][0]["name"] == "svc-backup"
    assert "svc-backup" not in users  # a gMSA, not a user with a password


def test_delegations_are_scoped_to_one_ou_each(plan):
    rights = {
        (d["group"], d["right"], d["ou"].split(",OU=Moretti")[0]) for d in plan["delegations"]
    }
    assert rights == {
        # Support resets passwords and the SOC disables accounts, only in the standard user OUs
        # (never admin or service accounts).
        ("DL-AD-UserPasswordReset", "reset-password", "OU=Users"),
        ("DL-AD-UserDisable", "disable-account", "OU=Users"),
        # Joining computers follows the admin tiers; the quota for everyone else is 0.
        ("GG-Priv-EndpointAdmin", "join-computers", "OU=Workstations,OU=Computers"),
        ("GG-Priv-ServerAdmin", "join-computers", "OU=Servers,OU=Computers"),
    }
    assert plan["machine_account_quota"] == 0


def test_passwords_are_never_in_the_plan(plan):
    for user in plan["users"]:
        assert "password" not in user
        assert user["password_parameter"].startswith("/moretti-group-lab/ad/")


def test_admin_account_follows_its_owner(sources):
    company, roles, accounts, employees = copy.deepcopy(sources)
    for emp in employees:
        if emp["employee_id"] == "MG-0082":  # owner of adm-rogerio.quintela
            emp["status"] = "terminated"
            emp["end_date"] = "2026-09-01"
    users = {u["sam"]: u for u in render(company, roles, accounts, employees)["users"]}
    assert not users["adm-rogerio.quintela"]["enabled"]


def test_invalid_data_is_rejected(sources):
    company, roles, accounts, employees = copy.deepcopy(sources)
    employees[0]["username"] = "a.very.long.username.x"
    with pytest.raises(PolicyError, match="longer than"):
        render(company, roles, accounts, employees)

    company, roles, accounts, employees = copy.deepcopy(sources)
    accounts["admin_accounts"][0]["privileged_roles"] = ["no-such-role"]
    with pytest.raises(PolicyError, match="unknown privileged role"):
        render(company, roles, accounts, employees)


def test_member_computer_policy(plan):
    assert plan["local_admin_groups"] == {
        "workstations": "DL-Workstations-LocalAdmin",
        "servers": "DL-Servers-LocalAdmin",
    }
    assert plan["deny_interactive_logon"] == ["GG-Service-Accounts", "Domain Admins"]
