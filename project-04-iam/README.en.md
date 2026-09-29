# Project 04 — Identity and Access Management

[Português](README.md) | **English**

RBAC and least privilege for Moretti Group, evolving from Active Directory to hybrid identity
and Entra ID ([ADR-006](../docs/adr/ADR-006-identity-evolution.md)).

**Status:** phase 5 (Active Directory) code is ready and tested offline; it has **not been
applied** to a domain controller yet. Phase 8 (Entra ID) comes later.

## The idea

No script full of hand-typed user names. Everything comes from `data/`: who works at the company,
each person's role and what each role may access. A Python generator turns that into an AD plan
(`generated/ad-plan.json`), and a PowerShell script makes the domain match the plan. When someone
changes role or leaves in `employees.csv`, the next run adjusts the groups on its own.

```
data/ → generator (Python, tested) → ad-plan.json (reviewed in Git) → PowerShell on DC01
```

## What the domain guarantees

- **AGDLP:** account → role group (`GG-Role-*`) → entitlement group (`DL-*`) → resource.
- **Segregation of duties:** whoever creates a payment cannot approve one.
- **Separate admin accounts** (`adm-*`) by tier (0, 1, 2). Only two accounts reach Domain Admins:
  the named Tier 0 admin and the break-glass account.
- **Lifecycle:** leavers are disabled, moved to the Disabled OU and removed from every group;
  employees on leave are disabled until they return; contractor accounts expire with the contract.
- **Passwords** are random and stored only in SSM Parameter Store, never in Git.
- **Minimal delegation:** the help desk can only reset passwords and the SOC can only disable
  accounts, and neither reaches admin accounts. Workstations are joined with the Tier 2 account,
  never with Domain Admin.
- **GPOs as code:** the audit policy the SOC will need, LLMNR/SMBv1/NTLMv1 off, host firewall,
  screen lock and no interactive logon for service accounts.

The full design is in [documentation/ad-design.md](documentation/ad-design.md).

## Layout

```
project-04-iam/
├── generated/ad-plan.json   # generated from data/, do not edit
├── scripts/                 # PowerShell: create the forest, provision, GPOs, join the domain
├── tests/                   # PowerShell dry runs (simulated domain, no real AD)
├── tools/render_ad_plan.py  # generates the plan
└── documentation/           # AD design and validation plan
```

## Checks

```bash
python3 project-04-iam/tools/render_ad_plan.py --check        # plan matches data/
pytest project-05-python/tests/test_ad_plan.py                # plan rules
pwsh -File project-04-iam/tests/Test-ProvisioningDryRun.ps1   # dry runs: empty domain and a leaver
pwsh -File project-04-iam/tests/Test-GpoTemplates.ps1         # GPO files
```

All of these run in CI, together with PSScriptAnalyzer. The tests prove that the code does what
the design says; whether the real AD behaves the same will only be known from the
[validation plan](documentation/validation-plan.md), once it runs in the lab (steps in the
[checklist](../docs/operator-checklist.md), section D).
