# Project 03 — SOC with Wazuh

[Português](README.md) | **English**

Log centralization, detection rules, alert triage and incident response. Wazuh runs on SIEM01 and
receives events from the agents (DC01, WS-FIN01, WS-DEV01) and from AWS (CloudTrail and Flow
Logs).

**Status:** phase 6 code is ready and tested offline; it has **not been deployed** to the lab
yet. Real alerts and incidents come in phase 7, with the scenarios.

## What this shows

SIEM rules are often generic: "many failed logons". These rules know who is who in the company.
The lists of terminated, on-leave, service and break-glass accounts are **generated from
`data/`**. When someone leaves in `employees.csv`, the list changes and Wazuh alerts on any use of
that account, without anyone editing a rule.

The rules use the same names as the `moretti-sec` detections (ACC-01, BF-01, ...), so a finding in
the Python report and an alert in Wazuh tell the same story. Each rule has a MITRE ATT&CK
technique and a triage playbook.

| Rule | Detects |
|---|---|
| ACC-01 to ACC-06 | Terminated employee's account, employee on leave, expired account, break-glass, service account at a keyboard, admin blocked by the tiering GPO |
| BF-01 | Brute force from the guest network (Windows and SSH) |
| NET-01 | Guest traffic to the internal network rejected by a Security Group (Flow Logs) |
| CT-01 to CT-03 | Security Group change, root user activity, audit logging disabled (CloudTrail) |

## Layout

```
project-03-soc/
├── wazuh/           # SIEM01 installation and ruleset deployment (deploy-ruleset.sh)
├── agents/          # agent installers (Linux; Windows with Sysmon) and per-group configuration
├── detections/
│   ├── rules/       # custom rules (IDs 100100-100199)
│   ├── lists/       # account lists generated from data/, do not edit
│   └── tests/       # synthetic events and the script that tests the rules on SIEM01
├── tools/           # list generator
└── documentation/   # SOC design, playbooks and validation plan
```

`alerts/` and `incidents/` appear in phase 7, with real alerts and incidents.

## Checks

```bash
python3 project-03-soc/tools/render_wazuh_lists.py --check   # lists match data/
pytest project-05-python/tests/test_wazuh.py                 # rules, lists and test cases
```

They check that the files are consistent with each other. Whether the rules fire in a real Wazuh
is only shown by `run_logtest.py` on SIEM01 ([checklist](../docs/operator-checklist.md),
section E). More in [documentation/soc-design.md](documentation/soc-design.md).
