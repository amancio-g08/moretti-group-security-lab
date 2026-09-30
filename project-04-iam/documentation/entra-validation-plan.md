# Entra ID Validation Plan

Tests to run after the phase 8 steps of the [operator checklist](../../docs/operator-checklist.md).
Each test names what it proves ([Entra design](entra-design.md)).

> **Status: not executed.** Fill in "Result" only with what is observed in the tenant. The offline
> tests (`test_conditional_access.py`, `test_access_review.py`) check the generated files, not the
> tenant, and are not a substitute for these tests.

| ID | Proves | How | Expected | Result |
|---|---|---|---|---|
| EN-01 | Cloud Sync | Entra portal → Users | The role-group users from AD appear; admin and service accounts do not | Not executed |
| EN-02 | Group sync | Entra portal → Groups | `GG-Role-*` and `GG-Priv-*` groups present with their members | Not executed |
| EN-03 | Sign-in | Sign in as a synced user | Succeeds with the AD password | Not executed |
| EN-04 | CA created | `Set-ConditionalAccess.ps1 -WhatIf`, then run it | CA01-CA04 created in report-only | Not executed |
| EN-05 | MFA required | Sign-in logs after a test logon | CA01 shows "report-only: would require MFA" | Not executed |
| EN-06 | Break-glass excluded | Check each policy's excluded groups | `GG-Break-Glass` excluded everywhere | Not executed |
| EN-07 | Admin strength | CA02 in the portal | Targets the admin groups, requires phishing-resistant MFA | Not executed |
| EN-08 | Enable | `Set-ConditionalAccess.ps1 -Enable` after report-only looks right | Policies move to enabled | Not executed |
| EN-09 | Leaver end to end | Set an employee `terminated` in `data/`, re-run AD provisioning, wait for sync | Cloud account disabled | Not executed |
| EN-10 | Access review | `moretti-sec access-review --ad-export <export.csv>` on a real export | Report generated; deviations recorded as observed | Not executed |

Record evidence in `project-04-iam/documentation/evidence/` using the test ID, without tenant IDs,
user principal names or tokens.
