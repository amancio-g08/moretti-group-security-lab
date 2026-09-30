# SCN-02 — Logon attempt with a terminated employee's account

> **Status: not executed.** Lab only ([safety](../../docs/lab-safety.md)); fill in "Observed" from evidence.

| | |
|---|---|
| **Goal** | Show that use of a terminated account is detected and attributed to the person |
| **Threat** | T-10 |
| **Account** | `alan.moreira` (MG-0097, terminated on 2026-08-28) |
| **From** | WS-FIN01 (10.10.20.10) |
| **Detections** | Wazuh ACC-01 (100100/100101); `moretti-sec` ACC-01 |

## Steps

1. On WS-FIN01: `net use \\DC01\NETLOGON /user:CORP\alan.moreira DeliberatelyWrong1!` (failure),
   which is what a real attempt with a disabled account looks like.
2. Confirm in AD that the account is disabled (`Get-ADUser alan.moreira`).

## Evidence

| Source | What |
|---|---|
| Wazuh | Alert 100101 naming `alan.moreira` |
| DC01 Security log | 4625 with the account |
| `moretti-sec` | Report labels the account `terminated (MG-0097)` |

## Expected

ACC-01 fires; the account is confirmed disabled, so the attempt fails. `moretti-sec` marks it
critical if it had succeeded, medium for the failure.

## Observed

*Not executed.*
