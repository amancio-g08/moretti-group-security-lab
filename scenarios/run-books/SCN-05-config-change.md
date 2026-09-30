# SCN-05 — Unauthorized configuration change on the finance application

> **Status: not executed.** Lab only ([safety](../../docs/lab-safety.md)); fill in "Observed" from evidence.

| | |
|---|---|
| **Goal** | Show that a change to a monitored file on APP-FIN01 is detected |
| **Threat** | T-13 |
| **Host** | APP-FIN01 (10.10.80.30), added in phase 7 (`lab_phase=7`) |
| **Detections** | Wazuh file integrity monitoring (syscheck) |

## Steps

1. Deploy APP-FIN01 (`terraform apply -var lab_phase=7`) and enroll the Wazuh agent (linux group,
   plus a syscheck entry for the application's config directory — see the SOC design).
2. On APP-FIN01, modify a monitored configuration file.

## Evidence

| Source | What |
|---|---|
| Wazuh | syscheck alert (rule 550/554) naming the file and the change |
| APP-FIN01 | the modified file's before/after (from the FIM report) |

## Expected

A file integrity alert fires naming the changed file. The change was not made from the jump host
under change control, so it is treated as unauthorized.

## Observed

*Not executed.*
