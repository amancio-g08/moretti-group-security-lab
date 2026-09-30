"""Company data -> Entra ID Conditional Access policies (ADR-006; design: project-04-iam).

Produces the policies in Microsoft Graph JSON, so the apply script (Connect-Graph) can create them
without any decision being made in the portal. Group names come from data/ (roles.yaml), so the
targeting follows the same source of truth as Active Directory (phase 5).

Policies are created in report-only state by default: the operator confirms they behave as
expected before turning them on, which is the recommended Entra rollout. The apply script can flip
them to enabled.

Run from the repository root:
    python project-04-iam/tools/render_conditional_access.py --write
    python project-04-iam/tools/render_conditional_access.py --check
"""

from __future__ import annotations

from pathlib import Path

from ._cli import load_yaml, run_files

OUTPUT = Path("project-04-iam/generated/conditional-access-policies.json")
# Break-glass accounts are excluded from every policy so a misconfiguration cannot lock everyone
# out; their use is alarmed instead (Wazuh ACC-04). Group display names as created by Entra sync.
BREAK_GLASS_GROUP = "GG-Break-Glass"
ADMIN_GROUP = "GG-Admin-Accounts"


def _camel(identifier: str) -> str:
    return "".join(part[:1].upper() + part[1:] for part in identifier.split("-"))


def render(roles: dict) -> dict:
    admin_role_groups = [f"GG-Priv-{_camel(r['id'])}" for r in roles["privileged_roles"]]
    policies = [
        {
            "displayName": "CA01 - Require MFA for all users",
            "state": "enabledForReportingButNotEnforced",
            "conditions": {
                "users": {"includeUsers": ["All"], "excludeGroups": [BREAK_GLASS_GROUP]},
                "applications": {"includeApplications": ["All"]},
            },
            "grantControls": {"operator": "OR", "builtInControls": ["mfa"]},
        },
        {
            "displayName": "CA02 - Require phishing-resistant MFA for admins",
            "state": "enabledForReportingButNotEnforced",
            "conditions": {
                "users": {
                    "includeGroups": [ADMIN_GROUP, *admin_role_groups],
                    "excludeGroups": [BREAK_GLASS_GROUP],
                },
                "applications": {"includeApplications": ["All"]},
            },
            "grantControls": {
                "operator": "OR",
                "authenticationStrength": {"displayName": "Phishing-resistant MFA"},
            },
        },
        {
            "displayName": "CA03 - Block logon from outside the allowed country",
            "state": "enabledForReportingButNotEnforced",
            "conditions": {
                "users": {"includeUsers": ["All"], "excludeGroups": [BREAK_GLASS_GROUP]},
                "applications": {"includeApplications": ["All"]},
                "locations": {
                    "includeLocations": ["All"],
                    "excludeLocations": ["AllowedCountries"],
                },
            },
            "grantControls": {"operator": "OR", "builtInControls": ["block"]},
        },
        {
            "displayName": "CA04 - Require compliant device for the finance application",
            "state": "enabledForReportingButNotEnforced",
            "conditions": {
                "users": {
                    "includeGroups": ["GG-Role-FinanceStaff", "GG-Role-FinanceManager"],
                    "excludeGroups": [BREAK_GLASS_GROUP],
                },
                "applications": {"includeApplications": ["FinanceApp"]},
            },
            "grantControls": {"operator": "OR", "builtInControls": ["compliantDevice"]},
        },
    ]
    return {
        "_generated": "GENERATED from data/roles.yaml by "
        "project-04-iam/tools/render_conditional_access.py. Do not edit.",
        "_notes": {
            "state": "All policies start in report-only; the apply script enables them once "
            "confirmed. Break-glass accounts are excluded from every policy.",
            "named_locations": "AllowedCountries and the FinanceApp application are named "
            "references the operator creates in the tenant (validation plan).",
        },
        "policies": policies,
    }


def render_from(data_dir: Path) -> dict[Path, str]:
    from .conditional_access import _to_json

    return {OUTPUT: _to_json(render(load_yaml(data_dir / "roles.yaml")))}


def _to_json(document: dict) -> str:
    import json

    return json.dumps(document, indent=2) + "\n"


def main(argv: list[str] | None = None) -> int:
    return run_files(__doc__.splitlines()[0], render_from, argv)


if __name__ == "__main__":
    raise SystemExit(main())
