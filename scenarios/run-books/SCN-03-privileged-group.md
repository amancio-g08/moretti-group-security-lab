# SCN-03 — Unexpected addition to a privileged group

> **Status: not executed.** Lab only ([safety](../../docs/lab-safety.md)); fill in "Observed" from evidence.

| | |
|---|---|
| **Goal** | Show that a change to a privileged group is detected outside change control |
| **Threat** | T-09 |
| **Group** | `GG-Priv-ServerAdmin` (or Domain Admins) |
| **Detections** | Wazuh ACC-07 (100108); AD event 4728/4732 |

## Steps

1. On DC01, as a Tier 0 admin, add a standard account to a privileged group:
   `Add-ADGroupMember -Identity GG-Priv-ServerAdmin -Members joao.silva`.
2. Note that this is the change the SOC must catch; revert it after the test
   (`Remove-ADGroupMember`), which the next `Invoke-ADProvisioning.ps1` run would also do.

## Evidence

| Source | What |
|---|---|
| Wazuh | Alert 100108 naming the group and who made the change |
| DC01 Security log | 4728/4732 with `MemberName` and `SubjectUserName` |

## Expected

ACC-07 fires within seconds, identifying the group and the admin who made the change.

## Observed

*Not executed.*
