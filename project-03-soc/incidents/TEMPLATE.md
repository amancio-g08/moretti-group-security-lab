# Incident report: <SCN-xx / short title>

> Moretti Group lab (FICTITIOUS). Evidence only; state what could not be determined.

| | |
|---|---|
| Incident ID | INC-<yyyy-nn> |
| Scenario | SCN-xx |
| Date detected | <UTC> |
| Severity | low / medium / high / critical |
| Status | open / contained / closed |

## Summary

One paragraph: what happened, who and what were involved (assets and accounts from `data/`), and
the outcome.

## Timeline

Paste the `moretti-sec correlate` table, or a trimmed version. Each row cites its source.

| Time (UTC) | Source | Event | Evidence file |
|---|---|---|---|

## Detection

Which rule or report first surfaced it (Wazuh rule ID, `moretti-sec` finding), and how long after
the activity.

## Investigation

The reasoning: what each source showed, what was ruled out, and what remains undetermined.

## Response

Containment actions taken (with the delegated rights of the SOC role), and by whom.

## Root cause and follow-up

Why it was possible and what changes in `data/` or configuration prevent a recurrence.

## MITRE ATT&CK

Techniques observed (e.g. T1110, T1078).
