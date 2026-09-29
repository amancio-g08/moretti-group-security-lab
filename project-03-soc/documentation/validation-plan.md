# SOC Validation Plan

Tests to run after the phase 6 steps of the [operator checklist](../../docs/operator-checklist.md).
Each test names what it proves ([SOC design](soc-design.md)).

> **Status: not executed.** The "Result" column is filled in only with what is actually observed.
> The offline tests (`test_wazuh.py`) check the files, not the running manager, and are not a
> substitute for these tests.

| ID | Proves | How | Expected | Result |
|---|---|---|---|---|
| W-01 | Installation | On SIEM01: `systemctl is-active wazuh-manager wazuh-indexer wazuh-dashboard` | `active` three times | Not executed |
| W-02 | Dashboard only through SSM | Port forwarding (checklist E), open `https://localhost:8443`, log in as `admin` | Dashboard loads; SIEM01 has no inbound rule other than the agent ports (Security Group) | Not executed |
| W-03 | Agents enrolled | On SIEM01: `/var/ossec/bin/agent_control -l` | DC01, WS-FIN01 and WS-DEV01 `Active`; groups as in the design | Not executed |
| W-04 | Enrollment needs the password | On WS-DEV01: move `/var/ossec/etc/authd.pass` aside, run `/var/ossec/bin/agent-auth -m 10.10.70.10 -A test-no-password`, put the file back | Enrollment refused | Not executed |
| W-05 | Account rules | On SIEM01: `run_logtest.py` (checklist E) | ACC cases pass | Not executed |
| W-06 | Brute force rules | Same run | BF-01 cases pass | Not executed |
| W-07 | AWS rules | Same run | NET-01 and CT cases pass | Not executed |
| W-08 | Real Windows event | On WS-FIN01: `net use \\DC01\NETLOGON /user:CORP\alan.moreira DeliberatelyWrong1!` | Alert 100101 (ACC-01) in the dashboard for `alan.moreira` | Not executed |
| W-09 | Real Flow Log event | On GUEST01: `nc -zv -w 5 10.10.50.10 22`, wait up to 20 minutes | Alert 100120 (NET-01) | Not executed |
| W-10 | Sizing (ADR-010) | During W-08/W-09: `top -b -n 1 \| head -15` and `free -m` on SIEM01 | Record CPU and memory use as observed | Not executed |
| W-11 | Retention | `curl -k -u admin https://localhost:9200/_plugins/_ism/policies/moretti-retention` (password from SSM) | Policy present, 14 days | Not executed |

Record evidence in `project-03-soc/documentation/evidence/` using the test ID as the file name,
without passwords, account IDs or tokens.
