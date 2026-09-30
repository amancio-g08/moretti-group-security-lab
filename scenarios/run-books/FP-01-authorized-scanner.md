# FP-01 — Authorized scanner that triggers an alert (false positive)

> **Status: not executed.** Lab only ([safety](../../docs/lab-safety.md)); fill in "Observed" from evidence.

| | |
|---|---|
| **Goal** | Practice separating authorized activity from an incident, and document the exception |
| **Account** | `svc-vulnscan` (authorized, restricted to SEC-WS01, NM-028) |
| **Detections** | Whatever the scan trips (failed logons, port sweeps) |

## Steps

1. From the security workstation, run an authorized scan of a lab host with the scanner account.
2. Observe the alerts it raises.

## Evidence

| Source | What |
|---|---|
| Wazuh | The alerts raised by the scan |
| `data/accounts.yaml` | `svc-vulnscan` is authorized and non-interactive |

## Expected

The activity raises alerts that, on triage, are authorized scanning. The point is the reasoning:
same behavior, different verdict, because the source and account are approved.

## Observed

*Not executed.*

## Exception

Record the documented exception in `project-03-soc/alerts/FP-01.md`: what was seen, why it is a
false positive, and how it is distinguished from T-18 (stolen scanner credentials used elsewhere).
