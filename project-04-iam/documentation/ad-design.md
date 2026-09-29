# Active Directory Design

Design of the `corp.moretti.internal` domain (phase 5, [ADR-006](../../docs/adr/ADR-006-identity-evolution.md)).
Every object in this document is **derived from `data/`** (ADR-001): the generator
`moretti_sec.render.ad_plan` turns `employees.csv`, `roles.yaml`, `accounts.yaml` and
`company.yaml` into [`generated/ad-plan.json`](../generated/ad-plan.json), and the scripts in
[`scripts/`](../scripts) make the domain match that plan.

> **Status:** designed, generated and tested offline; **not yet applied** to a domain controller.
> Results are recorded in the [validation plan](validation-plan.md) when the owner runs it.

## 1. Pipeline

```
data/ ──render_ad_plan.py──► generated/ad-plan.json ──Invoke-ADProvisioning.ps1──► DC01
          (Python, tested)        (reviewed in Git)          (PowerShell, idempotent)
```

- The Python generator holds every decision and is covered by unit tests
  (`project-05-python/tests/test_ad_plan.py`), including segregation of duties, the leaver rules
  and who ends up in Domain Admins.
- `pre-commit` and CI fail if the committed plan is not what `data/` produces.
- The PowerShell scripts only apply the plan. They pass PSScriptAnalyzer, and dry runs against a
  simulated domain (`tests/Test-ProvisioningDryRun.ps1`) check that they run end to end and handle a
  leaver correctly.

## 2. Structure

```
corp.moretti.internal
└─ OU=Moretti
   ├─ Users/<department>      one OU per department of company.yaml (10)
   ├─ Disabled                terminated employees
   ├─ Groups/Roles            GG-All-Staff and one GG-Role-* per business role
   ├─ Groups/Entitlements     one DL-* per entitlement
   ├─ Admin/Groups            GG-Priv-*, GG-Admin-Accounts and privileged DL-* groups
   ├─ Admin/Tier0|Tier1|Tier2 admin accounts, placed by their highest tier; break-glass in Tier0
   ├─ ServiceAccounts         service accounts, gMSAs and GG-Service-Accounts
   └─ Computers/Workstations|Servers
```

Keeping admin, service and user accounts in separate OUs is what makes the delegations of
section 7 safe: the help desk's rights stop at `OU=Users`.

## 3. Group model (AGDLP)

| Layer | Groups | Members | Source |
|---|---|---|---|
| Role (global) | `GG-Role-*` (16) and `GG-All-Staff` | Employee accounts | `roles.yaml` → `roles`, `employees.csv` → `role` |
| Privileged role (global) | `GG-Priv-*` (6) | Admin and break-glass accounts | `roles.yaml` → `privileged_roles`, `accounts.yaml` |
| Entitlement (domain local) | `DL-*` | **Groups only**, never accounts | `roles.yaml` → `entitlements` |
| Built-in | Domain Admins ← `GG-Priv-Tier0DomainAdmin`; Protected Users ← every `adm-*` account | | `priv-domain-admin` entitlement |

Properties the tests enforce:

- A resource owner grants access to a `DL-*` group, and a person gets access only through a role.
- **Segregation of duties:** nobody who can create a payment (`DL-APP-FIN-Ledger-Maker`) can approve
  one (`DL-APP-FIN-Payment-Approver`).
- **Separate admin accounts:** no employee account reaches any privileged group, directly or
  through nesting.
- **Domain Admins** resolves to exactly `adm-marcio.guimaraes` and `bg-admin01`.

## 4. Account lifecycle (Joiner / Mover / Leaver)

| Status in `employees.csv` | Account | Groups |
|---|---|---|
| `active` | Enabled, in the department OU | `GG-All-Staff` + the role group |
| `on_leave` | **Disabled** until the return (owner decision, 2026-09-29) | Kept, so the return is one change |
| `terminated` | Disabled, moved to `OU=Disabled`, description `Terminated on <date>` | **Removed from all** |
| `end_date` set (contractor, intern) | Expires at the end of that day | — |

- An **admin account follows its owner**: if the owner is not `active`, the admin account is disabled.
- **Mover:** changing `role` in `employees.csv` moves the account to the new role group and removes
  it from the old one, because the script makes every managed group's membership exact.
- **Passwords:** random, generated on DC01 when an account is created, stored only in SSM Parameter
  Store (SecureString) under `/moretti-group-lab/ad/{users,admins,break-glass,services}/<name>`, and
  never printed or committed (owner decision, 2026-09-29). Employees must change theirs at the first
  logon. Admin, break-glass and service accounts don't have to, because nobody else knows their
  random values.

## 5. Password and lockout policies

| Policy | Applies to | Length | Max age | Lockout |
|---|---|---|---|---|
| Default domain policy | Everyone else | 14, complexity, history 24 | 365 days | 10 failures → 15 min |
| `PSO-Admin-Accounts` | `GG-Admin-Accounts` | 20 | 180 days | 5 failures → 30 min |
| `PSO-Service-Accounts` | `GG-Service-Accounts` | 30 | never (account flag) | **none** |

Service accounts have no lockout on purpose: a locked service account stops its service, and the
authorized scanner fails logons by design (FP-01). The compensating controls are long random
passwords and SIEM alerts on their failures (phase 6).

## 6. Group Policy

Created and linked by `New-LabGpos.ps1`, all as code (no manual console steps):

| GPO | Linked to | Settings |
|---|---|---|
| `MG-Baseline-Security` | Domain root | LLMNR off; SMBv1 server off; NTLMv2 only (`LmCompatibilityLevel` 5); LSA protection; WDigest off; command line in 4688; PowerShell script block logging (4104); **advanced audit policy** (below) |
| `MG-Member-Computers` | Workstations, Servers | Windows Firewall on for every profile; lock after 15 minutes; **deny local and RDP logon** to `GG-Service-Accounts` and `Domain Admins` |
| `MG-Workstation-Admins` | Workstations | `DL-Workstations-LocalAdmin` added to local Administrators |
| `MG-Server-Admins` | Servers | `DL-Servers-LocalAdmin` added to local Administrators |

Advanced audit policy (the events the SOC needs in phase 6):

| Subcategory | Setting | Events |
|---|---|---|
| Credential Validation | Success, Failure | 4776 |
| Kerberos Authentication Service | Success, Failure | 4768, 4771 |
| Kerberos Service Ticket Operations | Success, Failure | 4769 |
| User Account Management | Success, Failure | 4720, 4722, 4725, 4726, 4738, 4740 (locked out) |
| Security Group Management | Success | 4728, 4732, 4756 |
| Logon | Success, Failure | 4624, 4625 |
| Account Lockout | Failure | 4625 with the "locked out" status |
| Special Logon | Success | 4672 |
| Process Creation | Success | 4688 |

Registry settings use `Set-GPRegistryValue`. User rights, local group membership and the audit
policy have no cmdlet, so the script writes the GPO's `GptTmpl.inf` and `audit.csv` in SYSVOL,
registers their client-side extensions and raises the GPO version (`GpoTemplates.ps1`, tested by
`tests/Test-GpoTemplates.ps1`). Local group membership is **additive**: existing local
administrators are not removed by the GPO.

## 7. Delegation and tiering

| Group | Right | Where | Entitlement |
|---|---|---|---|
| `DL-AD-UserPasswordReset` (help desk) | Reset password, unlock | `OU=Users` and below | `ad-password-reset` |
| `DL-AD-UserDisable` (SOC) | Write `userAccountControl` (disable) | `OU=Users` and below | `priv-ad-disable-users` |
| `GG-Priv-EndpointAdmin` (Tier 2) | Create and delete computer objects | `OU=Workstations` | `priv-workstation-admin` |
| `GG-Priv-ServerAdmin` (Tier 1) | Create and delete computer objects | `OU=Servers` | `priv-server-admin` |

- The **machine account quota is 0**: only the groups above can join computers, each to its own OU.
  A workstation is therefore joined with a Tier 2 credential (`Join-LabDomain.ps1`), never a
  Tier 0 one.
- Admin and service accounts live outside `OU=Users`, so neither the help desk nor the SOC can
  reset or disable them.
- `Domain Admins` cannot log on locally or by RDP to workstations and member servers
  (`MG-Member-Computers`).
- Writing `userAccountControl` also allows changing other flags of a standard user account. That
  is broader than "disable only", and accepted for the lab: the SOC role is Tier 1 and audited
  (4738).

## 8. Known limitations

- The plan is applied by a script, not by an identity governance product: approvals and access
  reviews are documented processes, not workflows (phase 8 adds Entra ID access reviews).
- The script **adds** to built-in groups and only **warns** about other members, so it cannot lock
  the operator out. The built-in `Administrator` account stays in Domain Admins until the owner has
  confirmed that `adm-marcio.guimaraes` works (operator checklist).
- On a domain controller, Session Manager's `ssm-user` account is created in the domain. Which
  groups it ends up in is checked and recorded during validation (AD-07); it is not assumed here.
- The gMSA `svc-backup` is created without allowed hosts, because FS01 exists only in Packet
  Tracer.
- `Protected Users` blocks NTLM for admin accounts. Kerberos needs the domain name and DC01 as DNS,
  which is why `Join-LabDomain.ps1` sets DC01 as the DNS server first.
