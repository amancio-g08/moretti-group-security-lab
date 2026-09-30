"""Access review: compare an Active Directory export (reality) with the plan derived from data/.

This is the Entra ID P2 access-review substitute the identity ADR (ADR-006) calls for where the
licensed feature is not available. It reads an export of the domain as it actually is and reports
every deviation from `project-04-iam/generated/ad-plan.json`, which is the policy resolved from
`data/`.

AD export format (CSV, one row per account), producible on DC01 with Get-ADUser / Get-ADGroupMember:

    sam,enabled,groups
    joao.silva,true,GG-All-Staff;GG-Role-FinanceStaff
    alan.moreira,true,GG-Role-Support

`groups` is a semicolon-separated list of the account's group memberships (direct and, if the
export resolves them, nested). Built-in groups such as "Domain Admins" are included by name.
"""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

from .models import Severity

# Group name prefixes / names that grant privilege; membership beyond the plan is high severity.
PRIVILEGED = (
    "GG-Priv-",
    "DL-Servers-LocalAdmin",
    "DL-Workstations-LocalAdmin",
    "DL-Network-Admin",
    "DL-SIEM-Admin",
    "DL-AD-UserDisable",
)
PRIVILEGED_BUILTIN = (
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "Account Operators",
    "Backup Operators",
)
# Pairs that must never be held together (segregation of duties, from roles.yaml entitlements).
SOD_PAIRS = (("DL-APP-FIN-Ledger-Maker", "DL-APP-FIN-Payment-Approver"),)


@dataclass(frozen=True)
class Finding:
    check: str
    severity: Severity
    account: str
    detail: str


@dataclass
class Review:
    findings: list[Finding] = field(default_factory=list)
    accounts_reviewed: int = 0

    def add(self, check, severity, account, detail):
        self.findings.append(Finding(check, severity, account, detail))


def _is_privileged(group: str) -> bool:
    return group in PRIVILEGED_BUILTIN or group.startswith(PRIVILEGED)


def load_ad_export(path: Path) -> dict[str, dict]:
    accounts = {}
    with path.open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            sam = (row.get("sam") or "").strip().lower()
            if not sam:
                continue
            groups = {g.strip() for g in (row.get("groups") or "").split(";") if g.strip()}
            accounts[sam] = {
                "enabled": str(row.get("enabled", "")).strip().lower() in ("true", "1", "yes"),
                "groups": groups,
            }
    return accounts


def _plan_index(plan: dict) -> dict:
    users = {u["sam"]: u for u in plan["users"]}
    expected_groups: dict[str, set[str]] = {sam: set() for sam in users}
    for group in plan["groups"]:
        for member in group["members"]:
            if member in expected_groups:  # a group member that is itself a group is nesting
                expected_groups[member].add(group["name"])
    for name, members in plan.get("builtin_group_members", {}).items():
        # builtin members may be group names (nesting) or accounts
        group_members = {g["name"]: g["members"] for g in plan["groups"]}
        pending = list(members)
        seen = set()
        while pending:
            m = pending.pop()
            if m in seen:
                continue
            seen.add(m)
            if m in group_members:
                pending += group_members[m]
            elif m in expected_groups:
                expected_groups[m].add(name)
    return {"users": users, "expected_groups": expected_groups}


def review(plan: dict, ad_accounts: dict[str, dict], today: date | None = None) -> Review:
    today = today or date.today()
    index = _plan_index(plan)
    users, expected_groups = index["users"], index["expected_groups"]
    result = Review(accounts_reviewed=len(ad_accounts))

    for sam, actual in sorted(ad_accounts.items()):
        planned = users.get(sam)
        if planned is None:
            result.add(
                "unknown-account",
                Severity.HIGH,
                sam,
                "Account exists in AD but not in the plan (data/).",
            )
            for group in sorted(g for g in actual["groups"] if _is_privileged(g)):
                result.add(
                    "privileged-membership",
                    Severity.CRITICAL,
                    sam,
                    f"Unknown account is a member of privileged group {group}.",
                )
            continue

        if actual["enabled"] and not planned["enabled"]:
            sev = (
                Severity.CRITICAL if planned["kind"] in ("admin", "break-glass") else Severity.HIGH
            )
            result.add(
                "should-be-disabled",
                sev,
                sam,
                "Account is enabled in AD but the plan disables it "
                f"({planned['description'] or planned['kind']}).",
            )
        if not actual["enabled"] and planned["enabled"]:
            result.add(
                "unexpectedly-disabled",
                Severity.LOW,
                sam,
                "Account is disabled in AD but the plan expects it enabled.",
            )

        expected = expected_groups.get(sam, set())
        for group in sorted(actual["groups"] - expected):
            sev = Severity.CRITICAL if _is_privileged(group) else Severity.HIGH
            result.add(
                "extra-membership",
                sev,
                sam,
                f"Member of {group}, which the account's role does not grant.",
            )
        for group in sorted(expected - actual["groups"]):
            result.add(
                "missing-membership",
                Severity.MEDIUM,
                sam,
                f"Not a member of {group}, which the account's role grants.",
            )

        # A terminated account keeping any group is caught by extra-membership (its expected set
        # is empty); an on-leave account keeps its groups on purpose, so there is no separate
        # "disabled but has groups" check, which would only be noise.

        expires = planned.get("expires_after")
        if expires and actual["enabled"] and date.fromisoformat(expires) < today:
            result.add(
                "past-expiry",
                Severity.HIGH,
                sam,
                f"Account is enabled but its plan expiry {expires} has passed.",
            )

    for a, b in SOD_PAIRS:
        both = sorted(sam for sam, acc in ad_accounts.items() if {a, b} <= acc["groups"])
        for sam in both:
            result.add(
                "segregation-of-duties",
                Severity.CRITICAL,
                sam,
                f"Holds both {a} and {b}, which must never be combined.",
            )

    result.findings.sort(key=lambda f: (-f.severity.rank, f.check, f.account))
    return result


def render_markdown(result: Review, export_name: str, plan_domain: str) -> str:
    from collections import Counter

    counts = Counter(f.severity for f in result.findings)
    summary = ", ".join(f"{counts[s]} {s.value}" for s in reversed(Severity) if counts[s])
    out = [
        "# Access review",
        "",
        "> Moretti Group lab (FICTITIOUS). Generated by `moretti-sec access-review`. Each finding "
        "is a deviation of the AD export from the policy in `data/`; review before acting.",
        "",
        "## Summary",
        "",
        "| Item | Value |",
        "|---|---|",
        f"| Domain | {plan_domain} |",
        f"| AD export | `{export_name}` |",
        f"| Accounts reviewed | {result.accounts_reviewed} |",
        f"| Findings | {len(result.findings)}{f' ({summary})' if summary else ''} |",
        "",
        "## Findings",
        "",
    ]
    if not result.findings:
        out += ["No deviations: AD matches the policy.", ""]
        return "\n".join(out)
    out += ["| Severity | Check | Account | Detail |", "|---|---|---|---|"]
    for f in result.findings:
        out.append(f"| {f.severity.value} | {f.check} | {f.account} | {f.detail} |")
    out += [
        "",
        "## Limitations",
        "",
        "- The review compares the export against `data/` as it is now; a legitimate change "
        "not yet in `data/` shows up as a deviation.",
        "- Nested group membership is only as complete as the export; run Get-ADGroupMember "
        "with `-Recursive` for privileged groups.",
        "",
    ]
    return "\n".join(out)


def load_plan(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))
