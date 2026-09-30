import json

import pytest
import yaml
from conftest import REPO_DATA

from moretti_sec.render.conditional_access import BREAK_GLASS_GROUP, main, render


@pytest.fixture(scope="module")
def policies():
    roles = yaml.safe_load((REPO_DATA / "roles.yaml").read_text(encoding="utf-8"))
    return render(roles)["policies"]


def test_generated_file_is_up_to_date():
    assert main(["--check", "--data-dir", str(REPO_DATA)]) == 0


def test_all_policies_start_report_only(policies):
    assert policies
    assert all(p["state"] == "enabledForReportingButNotEnforced" for p in policies)


def test_break_glass_is_excluded_from_every_policy(policies):
    for p in policies:
        assert BREAK_GLASS_GROUP in p["conditions"]["users"].get("excludeGroups", [])


def test_admin_policy_targets_every_privileged_group(policies):
    roles = yaml.safe_load((REPO_DATA / "roles.yaml").read_text(encoding="utf-8"))
    admin = next(p for p in policies if p["displayName"].startswith("CA02"))
    included = admin["conditions"]["users"]["includeGroups"]
    for role in roles["privileged_roles"]:
        camel = "".join(w[:1].upper() + w[1:] for w in role["id"].split("-"))
        assert f"GG-Priv-{camel}" in included


def test_every_policy_has_a_grant_control(policies):
    for p in policies:
        grant = p["grantControls"]
        assert grant.get("builtInControls") or grant.get("authenticationStrength")


def test_policies_are_valid_json_and_named():
    doc = json.loads(
        (
            REPO_DATA.parent / "project-04-iam" / "generated" / "conditional-access-policies.json"
        ).read_text(encoding="utf-8")
    )
    names = [p["displayName"] for p in doc["policies"]]
    assert len(names) == len(set(names))
    assert all(n.startswith("CA") for n in names)
