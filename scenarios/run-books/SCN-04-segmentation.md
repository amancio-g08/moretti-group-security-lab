# SCN-04 — Segmentation violation: guest to finance

> **Status: not executed.** Lab only ([safety](../../docs/lab-safety.md)); fill in "Observed" from evidence.

| | |
|---|---|
| **Goal** | Show that guest-to-internal traffic is blocked, recorded and alerted, and trace it end to end |
| **Threat** | T-02, T-03 |
| **From** | GUEST01 (10.10.90.10) |
| **Against** | WS-FIN01 (10.10.20.10), APP-FIN01 (10.10.80.30) |
| **Detections** | Security Group (NM-004); VPC Flow Logs; Wazuh NET-01 (100120); Wireshark plugin; NSE audit |

## Steps

1. From GUEST01, run the segmentation audit:
   `nmap --script moretti-segmentation --script-args moretti.targets=./moretti_targets.lua`
   (copy `project-02-pcap/nse/*` to GUEST01 first). It should report the guest→internal flows as
   correctly blocked and flag any gap.
2. Also try a direct connection: `nc -zv -w 5 10.10.20.10 445`.
3. Capture on GUEST01 with `tcpdump -w scn-04.pcap` during the attempt.

## Evidence

| Source | What |
|---|---|
| NSE audit | Guest→internal flows blocked as expected; 0 segmentation gaps |
| Flow Logs | REJECT records 10.10.90.10 → 10.10.x (via `moretti-sec correlate --flow`) |
| Wazuh | Alert 100120 (NET-01) |
| Capture | `scn-04.pcap`; open in Wireshark with the plugin, filter `moretti.verdict == "deny"` |
| Timeline | `moretti-sec correlate --flow flowlogs --wazuh alerts.json` |

## Expected

Every guest→internal attempt is blocked at the Security Group, appears as REJECT in Flow Logs,
raises NET-01, and shows as `deny (NM-004)` in the capture. The NSE audit reports no gaps.

## Observed

*Not executed.*

## Reports

- PCAP investigation: `project-02-pcap/reports/` ([template](../../project-02-pcap/reports/TEMPLATE.md)).
- Incident: `project-03-soc/incidents/` ([template](../../project-03-soc/incidents/TEMPLATE.md)).
