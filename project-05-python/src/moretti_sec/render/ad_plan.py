"""Company data -> Active Directory plan (ADR-001, ADR-006; design: project-04-iam/documentation).

The plan lists every OU, group, account and group membership the domain must contain, derived
only from data/: employees.csv, roles.yaml, accounts.yaml and company.yaml. The PowerShell script
project-04-iam/scripts/Invoke-ADProvisioning.ps1 applies it; all the decisions live here, where
they can be tested without a domain controller.

Group model (AGDLP, roles.yaml):
    account -> GG-Role-* / GG-Priv-* (global, one per role)
            -> DL-* (domain local, one per entitlement) -> permission on the resource

Account lifecycle, from employees.csv:
    active       enabled, in the department OU, member of its role group
    on_leave     disabled while away; keeps its groups so the return is a single change
    terminated   disabled, moved to the Disabled OU, removed from every group
    end_date     (contractors, interns) the account expires after that day
An admin account follows its owner: if the owner is not active, the admin account is disabled.

Run from the repository root:
    python project-04-iam/tools/render_ad_plan.py --write   # regenerate
    python project-04-iam/tools/render_ad_plan.py --check   # fail if out of date
"""

from __future__ import annotations

import csv
import re
from collections import defaultdict
from pathlib import Path

from ._cli import PolicyError, load_yaml, run

OUTPUT = Path("project-04-iam/generated/ad-plan.json")
PASSWORD_PATH = "/moretti-group-lab/ad"  # SSM Parameter Store prefix (lab-safety.md)
SAM_MAX = 20  # sAMAccountName limit for user accounts
GMSA_MAX = 15  # sAMAccountName limit for managed service accounts (before the "$")
DN_UNSAFE = re.compile(r'[,+"\\<>;=#]')

ALL_STAFF = "GG-All-Staff"
ADMIN_ACCOUNTS = "GG-Admin-Accounts"
SERVICE_ACCOUNTS = "GG-Service-Accounts"
# Entitlements implemented as delegated rights on the standard user OUs, not as a resource ACL.
DELEGATIONS = {"ad-password-reset": "reset-password", "priv-ad-disable-users": "disable-account"}
# Local-admin entitlements whose holders also join computers to the matching OU. With the
# machine account quota at 0, nobody else can add computers to the domain, and joining a
# workstation never needs a Tier 0 credential.
COMPUTER_OUS = {"workstations": "Workstations", "servers": "Servers"}
# Denied local and Remote Desktop logon on member computers: service accounts never log on
# interactively, and Tier 0 credentials never touch a workstation or member server.
DENY_INTERACTIVE_LOGON = [SERVICE_ACCOUNTS, "Domain Admins"]

DEFAULT_PASSWORD_POLICY = {
    "min_length": 14,
    "complexity": True,
    "history": 24,
    "min_age_days": 1,
    "max_age_days": 365,
    "lockout_threshold": 10,
    "lockout_duration_minutes": 15,
    "lockout_window_minutes": 15,
}
FINE_GRAINED_POLICIES = [
    {
        "name": "PSO-Admin-Accounts",
        "precedence": 10,
        "applies_to": [ADMIN_ACCOUNTS],
        "min_length": 20,
        "complexity": True,
        "history": 24,
        "min_age_days": 1,
        "max_age_days": 180,
        "lockout_threshold": 5,
        "lockout_duration_minutes": 30,
        "lockout_window_minutes": 30,
    },
    {
        # No lockout: a locked service account stops the service it runs (the authorized scanner
        # of FP-01 fails logons on purpose). Long random passwords and SIEM alerts compensate.
        "name": "PSO-Service-Accounts",
        "precedence": 20,
        "applies_to": [SERVICE_ACCOUNTS],
        "min_length": 30,
        "complexity": True,
        "history": 24,
        "min_age_days": 0,
        # The accounts are set to never expire; AD still requires valid values for a PSO.
        "max_age_days": 365,
        "lockout_threshold": 0,
        "lockout_duration_minutes": 1,  # ignored while lockout_threshold is 0
        "lockout_window_minutes": 1,
    },
]


def camel(identifier: str) -> str:
    """'tier0-domain-admin' -> 'Tier0DomainAdmin'."""
    return "".join(part[:1].upper() + part[1:] for part in identifier.split("-"))


class Plan:
    def __init__(self, company: dict, roles: dict, accounts: dict, employees: list[dict]):
        self.domain = company["company"]["ad_domain"]
        self.domain_dn = ",".join(f"DC={label}" for label in self.domain.split("."))
        self.departments = {d["id"]: d for d in company["departments"]}
        self.entitlements = {e["id"]: e for e in roles["entitlements"]}
        self.baseline = roles.get("baseline_entitlements", [])
        self.roles = {r["id"]: r for r in roles["roles"]}
        self.privileged_roles = {r["id"]: r for r in roles["privileged_roles"]}
        self.accounts = accounts
        self.employees = {e["employee_id"]: e for e in employees}

        self.ous: list[str] = []
        self.groups: dict[str, dict] = {}
        self.users: list[dict] = []
        self.gmsas: list[dict] = []
        self.builtin: dict[str, list[str]] = defaultdict(list)
        self.delegations: list[dict] = []
        self.local_admins: dict[str, str] = {}

    # ------------------------------------------------------------------ building blocks
    def ou(self, *path: str) -> str:
        """DN of Moretti/<path...>, registering every level (parents first)."""
        dn = f"OU=Moretti,{self.domain_dn}"
        self._add_ou(dn)
        for name in path:
            if DN_UNSAFE.search(name):
                raise PolicyError(f"OU name {name!r} contains characters that need DN escaping")
            dn = f"OU={name},{dn}"
            self._add_ou(dn)
        return dn

    def _add_ou(self, dn: str) -> None:
        if dn not in self.ous:
            self.ous.append(dn)

    def group(self, name: str, scope: str, ou: str, description: str) -> dict:
        if name not in self.groups:
            self.groups[name] = {
                "name": name,
                "scope": scope,
                "ou": ou,
                "description": description,
                "members": [],
            }
        return self.groups[name]

    def add_member(self, group: str, member: str) -> None:
        members = self.groups[group]["members"]
        if member not in members:
            members.append(member)

    def user(self, **fields) -> dict:
        sam = fields["sam"]
        if len(sam) > SAM_MAX:
            raise PolicyError(f"{sam}: sAMAccountName longer than {SAM_MAX} characters")
        if any(u["sam"] == sam for u in self.users):
            raise PolicyError(f"{sam}: duplicate account name")
        entry = {
            "sam": sam,
            "upn": f"{sam}@{self.domain}",
            "given_name": None,
            "surname": None,
            "display_name": sam,
            "employee_id": None,
            "department": None,
            "title": None,
            "manager": None,
            "enabled": True,
            "expires_after": None,
            "must_change_password": True,
            "password_never_expires": False,
            "description": "",
            **fields,
        }
        self.users.append(entry)
        return entry

    # ------------------------------------------------------------------ plan sections
    def build(self) -> dict:
        self._structure()
        self._role_groups()
        self._employees()
        self._privileged()
        self._service_accounts()
        return self._document()

    def _structure(self) -> None:
        for dept in self.departments.values():
            self.ou("Users", dept["name"])
        self.ou("Disabled")
        self.ou("Admin", "Groups")
        for tier in sorted({r["tier"] for r in self.privileged_roles.values()}):
            self.ou("Admin", f"Tier{tier}")
        self.ou("ServiceAccounts")
        self.ou("Computers", "Servers")
        self.ou("Computers", "Workstations")

    def _entitlement_group(self, entitlement_id: str) -> str | None:
        """Create the DL group of an entitlement; None when it maps to a built-in group."""
        ent = self.entitlements.get(entitlement_id)
        if ent is None:
            raise PolicyError(f"unknown entitlement {entitlement_id!r}")
        name = ent["ad_group"]
        if not name.startswith("DL-"):
            return None
        ou = (
            self.ou("Admin", "Groups")
            if ent.get("privileged")
            else self.ou("Groups", "Entitlements")
        )
        self.group(name, "DomainLocal", ou, f"{ent['system']}: {ent['access']}")
        if entitlement_id in DELEGATIONS:
            delegation = {
                "ou": self.ou("Users"),
                "group": name,
                "right": DELEGATIONS[entitlement_id],
            }
            if delegation not in self.delegations:
                self.delegations.append(delegation)
        return name

    def _grant(self, holder: str, entitlement_id: str) -> None:
        target = self._entitlement_group(entitlement_id)
        if target is None:
            self.builtin[self.entitlements[entitlement_id]["ad_group"]].append(holder)
        else:
            self.add_member(target, holder)

    def _role_groups(self) -> None:
        roles_ou = self.ou("Groups", "Roles")
        self.group(ALL_STAFF, "Global", roles_ou, "Every employee account (baseline access)")
        for entitlement_id in self.baseline:
            self._grant(ALL_STAFF, entitlement_id)
        for role in self.roles.values():
            self.group(role["ad_group"], "Global", roles_ou, role["justification"])
            for entitlement_id in role["entitlements"]:
                self._grant(role["ad_group"], entitlement_id)

    def _employees(self) -> None:
        sam_by_id = {e["employee_id"]: e["username"] for e in self.employees.values()}
        for emp in self.employees.values():
            role = self.roles.get(emp["role"])
            if role is None:
                raise PolicyError(f"{emp['employee_id']}: unknown role {emp['role']!r}")
            dept = self.departments[emp["department"]]
            status = emp["status"]
            terminated = status == "terminated"
            description = {
                "active": "",
                "on_leave": "On leave: disabled until the employee returns",
                "terminated": f"Terminated on {emp['end_date']}",
            }[status]
            self.user(
                sam=emp["username"],
                kind="employee",
                ou=self.ou("Disabled") if terminated else self.ou("Users", dept["name"]),
                given_name=emp["first_name"],
                surname=emp["last_name"],
                display_name=f"{emp['first_name']} {emp['last_name']}",
                employee_id=emp["employee_id"],
                department=dept["name"],
                title=emp["title"],
                manager=sam_by_id.get(emp["manager_id"]) or None,
                enabled=status == "active",
                expires_after=None if terminated else (emp["end_date"] or None),
                description=description,
                password_parameter=f"{PASSWORD_PATH}/users/{emp['username']}",
            )
            if not terminated:
                self.add_member(ALL_STAFF, emp["username"])
                self.add_member(role["ad_group"], emp["username"])

    def _privileged(self) -> None:
        groups_ou = self.ou("Admin", "Groups")
        self.group(ADMIN_ACCOUNTS, "Global", groups_ou, "Every admin and break-glass account")
        for role in self.privileged_roles.values():
            name = f"GG-Priv-{camel(role['id'])}"
            self.group(name, "Global", groups_ou, f"Tier {role['tier']}: {role['justification']}")
            for entitlement_id in role["entitlements"]:
                self._grant(name, entitlement_id)
                ent = self.entitlements[entitlement_id]
                if ent.get("privileged") and ent["system"] in COMPUTER_OUS:
                    self.local_admins[ent["system"]] = ent["ad_group"]
                    self.delegations.append(
                        {
                            "ou": self.ou("Computers", COMPUTER_OUS[ent["system"]]),
                            "group": name,
                            "right": "join-computers",
                        }
                    )

        for item in self.accounts.get("admin_accounts", []):
            owner = self.employees.get(item["owner"])
            if owner is None:
                raise PolicyError(f"{item['username']}: unknown owner {item['owner']}")
            roles = [self._privileged_role(item["username"], r) for r in item["privileged_roles"]]
            tier = min(r["tier"] for r in roles)
            self.user(
                sam=item["username"],
                kind="admin",
                ou=self.ou("Admin", f"Tier{tier}"),
                given_name=owner["first_name"],
                surname=owner["last_name"],
                display_name=f"ADM {owner['first_name']} {owner['last_name']}",
                employee_id=owner["employee_id"],
                enabled=owner["status"] == "active",
                # Random, unique and read only by the operator from SSM: a forced change at first
                # logon adds nothing, and it would block non-interactive uses such as a domain join.
                must_change_password=False,
                description=item["justification"],
                password_parameter=f"{PASSWORD_PATH}/admins/{item['username']}",
            )
            self._privileged_membership(item["username"], roles)
            # Protected Users: no NTLM, no delegation, no cached credentials for admin accounts.
            self.builtin["Protected Users"].append(item["username"])

        for item in self.accounts.get("break_glass_accounts", []):
            roles = [self._privileged_role(item["username"], r) for r in item["privileged_roles"]]
            self.user(
                sam=item["username"],
                kind="break-glass",
                ou=self.ou("Admin", f"Tier{min(r['tier'] for r in roles)}"),
                display_name=f"Break-glass {item['username']}",
                must_change_password=False,
                description=item["justification"],
                password_parameter=f"{PASSWORD_PATH}/break-glass/{item['username']}",
            )
            self._privileged_membership(item["username"], roles)

    def _privileged_role(self, account: str, role_id: str) -> dict:
        role = self.privileged_roles.get(role_id)
        if role is None:
            raise PolicyError(f"{account}: unknown privileged role {role_id!r}")
        return role

    def _privileged_membership(self, account: str, roles: list[dict]) -> None:
        self.add_member(ADMIN_ACCOUNTS, account)
        for role in roles:
            self.add_member(f"GG-Priv-{camel(role['id'])}", account)

    def _service_accounts(self) -> None:
        ou = self.ou("ServiceAccounts")
        self.group(SERVICE_ACCOUNTS, "Global", ou, "Service accounts: no interactive logon")
        for item in self.accounts.get("service_accounts", []):
            description = f"{item['purpose']} (owner: {item['owner']})"
            if item.get("type") == "gmsa":
                if len(item["username"]) > GMSA_MAX:
                    raise PolicyError(f"{item['username']}: gMSA name longer than {GMSA_MAX}")
                self.gmsas.append({"name": item["username"], "description": description})
                continue
            self.user(
                sam=item["username"],
                kind="service",
                ou=ou,
                must_change_password=False,
                password_never_expires=True,
                description=description,
                password_parameter=f"{PASSWORD_PATH}/services/{item['username']}",
            )
            self.add_member(SERVICE_ACCOUNTS, item["username"])

    def _document(self) -> dict:
        return {
            "_generated": "GENERATED from data/ by project-04-iam/tools/render_ad_plan.py. "
            "Do not edit.",
            "domain": {
                "fqdn": self.domain,
                "netbios": self.domain.split(".")[0].upper(),
                "dn": self.domain_dn,
            },
            "machine_account_quota": 0,
            "computer_ous": {
                kind: self.ou("Computers", name) for kind, name in COMPUTER_OUS.items()
            },
            "default_password_policy": DEFAULT_PASSWORD_POLICY,
            "fine_grained_password_policies": FINE_GRAINED_POLICIES,
            "organizational_units": self.ous,
            "groups": list(self.groups.values()),
            "users": self.users,
            "managed_service_accounts": self.gmsas,
            "builtin_group_members": {name: members for name, members in self.builtin.items()},
            "delegations": self.delegations,
            # Applied by GPO to member computers (project-04-iam/scripts/New-LabGpos.ps1).
            "local_admin_groups": self.local_admins,
            "deny_interactive_logon": DENY_INTERACTIVE_LOGON,
        }


def render(company: dict, roles: dict, accounts: dict, employees: list[dict]) -> dict:
    return Plan(company, roles, accounts, employees).build()


def render_from(data_dir: Path) -> dict:
    with (data_dir / "employees.csv").open(encoding="utf-8", newline="") as handle:
        employees = list(csv.DictReader(handle))
    return render(
        load_yaml(data_dir / "company.yaml"),
        load_yaml(data_dir / "roles.yaml"),
        load_yaml(data_dir / "accounts.yaml"),
        employees,
    )


def main(argv: list[str] | None = None) -> int:
    return run(__doc__.splitlines()[0], OUTPUT, render_from, argv)


if __name__ == "__main__":
    raise SystemExit(main())
