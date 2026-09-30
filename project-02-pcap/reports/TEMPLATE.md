# PCAP investigation: <SCN-xx / short title>

> Moretti Group lab (FICTITIOUS). Evidence only; state what the capture cannot show.

| | |
|---|---|
| Scenario | SCN-xx |
| Capture | `pcaps/curated/<file>.pcap` (SHA-256: <hash>) |
| Captured on | <host> with <tcpdump/pktmon> |
| Analyst tooling | Wireshark + Moretti plugin, `moretti-sec` |

## Question

What the investigation set out to answer (who talked to whom, was it allowed, what was sent).

## Method

Display filters used (including `moretti.verdict == "deny"`), and why.

## Findings

| Frame(s) | Flow (asset → asset) | Verdict / rule | What it shows |
|---|---|---|---|

## Timeline

Correlated with Flow Logs and Wazuh where relevant (`moretti-sec correlate`).

## Conclusion

What the capture establishes, and what it cannot (packets dropped at a Security Group never reach
the destination-side capture; translated addresses show as `internet`).

## Evidence

Files and their SHA-256, stored under `project-02-pcap/evidence/`.
