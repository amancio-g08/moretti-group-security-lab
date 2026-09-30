# Scenarios: how the pieces fit

Each scenario has a run book in `scenarios/run-books/`. Everything they rely on is already in the
repository and tested offline; only the execution (which needs the lab running) is pending.

```
run book (steps, in-scope) ─► run in the lab ─► evidence from several sources
                                                   │
   VPC Flow Logs ─┐                                │
   Wazuh alerts  ─┼─► moretti-sec correlate ─► one enriched timeline ─► incident report
   Windows/SSH   ─┘                                │
   capture (.pcap) ─► Wireshark + Moretti plugin ─► PCAP investigation report
   NSE segmentation audit (Lua) ─────────────────► segmentation confirmed / gaps
```

| Capability (built and tested here) | Where |
|---|---|
| Correlated timeline (auth + Flow Logs + Wazuh), enriched from `data/` | `moretti-sec correlate` |
| Flow Log and Wazuh alert parsers | `project-05-python/.../parsers/` |
| Wazuh rule ACC-07 for SCN-03, with a privileged-groups list from `data/` | `project-03-soc/detections/` |
| Wireshark plugin (verdict per packet) | `project-02-pcap/wireshark/` |
| Nmap NSE segmentation audit (Lua), targets from `data/` | `project-02-pcap/nse/` |
| Incident and PCAP report templates | `project-03-soc/incidents/`, `project-02-pcap/reports/` |

Nothing above contains a real result: the run books, timelines and reports are filled in from
observed evidence when the scenarios run (operator checklist, section G).
