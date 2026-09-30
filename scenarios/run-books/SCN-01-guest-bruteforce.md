# SCN-01 — Password guessing from the guest network

> **Status: not executed.** Run in the lab per the [operator checklist](../../docs/operator-checklist.md)
> section G. Fill in "Observed" only with what the evidence shows. Offensive traffic runs from
> GUEST01 against in-scope lab addresses only ([lab safety](../../docs/lab-safety.md)).

| | |
|---|---|
| **Goal** | Show that repeated failed logons are detected and attributed |
| **Threat** | T-01 (threat model) |
| **From** | GUEST01 (10.10.90.10) |
| **Against** | WS-DEV01 SSH (10.10.50.10:22) |
| **Detections exercised** | Wazuh BF-01 (100110/100111); `moretti-sec` BF-01/BF-02 |

## Steps

1. Start the lab (`lab-up.sh`) and confirm SIEM01 shows the agents Active (W-03).
2. From GUEST01, attempt several SSH logons with wrong passwords against 10.10.50.10 (for example
   `hydra`-style attempts, or a short loop of `ssh` with bad credentials). Stay within the lab.
3. Wait for the Wazuh alert.

## Evidence to collect

| Source | What | Where |
|---|---|---|
| Wazuh | Alert 100111 (SSH brute force from guest) | dashboard → screenshot to `project-03-soc/alerts/SCN-01.png` |
| WS-DEV01 | `/var/log/auth.log` excerpt of the failures | `moretti-sec analyze` on the Mac |
| Flow Logs | The connections from 10.10.90.10 to :22 | via `moretti-sec correlate --flow` |

## Expected

- BF-01 fires in Wazuh with source 10.10.90.10.
- `moretti-sec correlate` places the flow, the failures and the alert on one timeline.

## Observed

*Not executed.*

## Incident report

Write up in `project-03-soc/incidents/` using the [template](../../project-03-soc/incidents/TEMPLATE.md).
