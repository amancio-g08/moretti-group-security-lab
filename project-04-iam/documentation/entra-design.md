# Entra ID Design (hybrid and cloud identity)

Stage 2 and 3 of the identity evolution (phase 8, [ADR-006](../../docs/adr/ADR-006-identity-evolution.md)):
Active Directory (phase 5) is synchronized to Entra ID, and cloud controls (MFA, Conditional
Access, access reviews, Joiner/Mover/Leaver) are added on top.

> **Status:** the code and policies are ready and tested offline; **nothing has been applied** to a
> tenant. Results go into the [validation plan](entra-validation-plan.md) when the owner runs it
> ([operator checklist](../../docs/operator-checklist.md), section H).

## 1. What is code here vs. done in the tenant

| Built and tested here | Done in the tenant (checklist H) |
|---|---|
| Conditional Access policies as Graph JSON, generated from `data/` | Create the tenant, activate the P1/P2 trial |
| `Set-ConditionalAccess.ps1` to create/update them (report-only first) | Install and scope Entra Cloud Sync on DC01 |
| Access review in Python over an AD export (the P2 substitute) | Create named locations and the app references |
| JML runbook; validation plan | Run Cloud Sync; enable the policies after report-only |

## 2. Cloud Sync (AD -> Entra ID)

- Entra Cloud Sync agent on DC01 (outbound HTTPS only; NM-071/NM-072, ADR-004).
- **Scope:** synchronize `OU=Users,OU=Moretti` and `OU=Groups,OU=Moretti` (the role groups). Do
  **not** synchronize `OU=Admin` or `OU=ServiceAccounts`: cloud admin identities are separate from
  the on-prem Tier 0 accounts, and service accounts have no reason to exist in the cloud.
- Password hash sync provides sign-in with the same password; the account of record stays AD.

## 3. Conditional Access

Generated to `generated/conditional-access-policies.json`. All start in **report-only**; the apply
script enables them once confirmed. **Break-glass accounts are excluded from every policy**, so a
misconfiguration cannot lock everyone out (their use is alarmed by Wazuh ACC-04).

| Policy | Targets | Control |
|---|---|---|
| CA01 | All users | Require MFA |
| CA02 | Admin groups (`GG-Admin-Accounts`, `GG-Priv-*`) | Require phishing-resistant MFA |
| CA03 | All users | Block sign-in from outside the allowed location |
| CA04 | Finance role groups, finance app | Require a compliant device |

`AllowedCountries` (a named location) and `FinanceApp` (an app registration) are references the
operator creates in the tenant; until they exist, `Set-ConditionalAccess.ps1` skips the policies
that need them instead of failing.

## 4. Access review (Entra P2 substitute)

Where P2 access reviews are not in the trial, `moretti-sec access-review` provides the same control
offline: it compares an AD export (`Get-ADUser`/`Get-ADGroupMember`) against the plan generated
from `data/` and reports every deviation — unknown accounts, privilege creep, terminated accounts
still enabled, contract expiry passed, and segregation-of-duties breaches. It is run on a schedule
and its report is the review record.

## 5. Joiner / Mover / Leaver

| Event | On-prem (AD, phase 5) | Cloud (Entra) |
|---|---|---|
| Joiner | Account created in the department OU, added to its role group (`Invoke-ADProvisioning.ps1` from `data/`) | Cloud Sync provisions the account and group membership; CA01 requires MFA registration |
| Mover | `role` changes in `employees.csv` → next provisioning run moves the role group | Cloud Sync updates group membership; access follows the group |
| Leaver | `status: terminated` → account disabled, moved to Disabled OU, removed from groups | Cloud Sync disables the cloud account; sessions revoked |

The access review is the backstop that catches anything the automated flow missed.

## 6. Known limitations

- Conditional Access requires Entra ID P1 and automated access reviews require P2; both are
  trial-based. Where unavailable, the gap is documented and the Python access review covers it
  (ADR-006).
- The policies are written for the Graph schema but have only been validated as JSON here, not
  created in a tenant; `Set-ConditionalAccess.ps1` is the first place a schema mismatch would show.
- Named locations and app registrations are tenant-specific and are created by hand.
