# SOC Design (Wazuh)

Security monitoring for the lab (phase 6). SIEM01 runs Wazuh with the server, indexer and
dashboard on one host; agents on the lab hosts and the AWS module send it events; custom rules
and account lists turn the company data in `data/` into detections.

> **Status:** designed, written and tested offline; **not yet deployed**. Results are recorded in
> the [validation plan](validation-plan.md) when the owner runs it.

## 1. Architecture

```
DC01, WS-FIN01  (Windows: Security, Sysmon, PowerShell) ──┐
WS-DEV01        (Linux: auth, file integrity) ─────────────┼─ agents, TCP 1514/1515 (NM-040) ─► SIEM01
CloudTrail + VPC Flow Logs (S3, bootstrap stack) ── AWS module, read-only role ─────────────┘   │
                                                                                                  ▼
data/ ─► account lists (CDB) ─► custom rules 100100-100199 ─► alerts ─► dashboard via SSM port forwarding
```

| Decision | Choice | Why |
|---|---|---|
| Deployment | All-in-one on SIEM01, t3.large, 40 GB | [ADR-010](../../docs/adr/ADR-010-siem-sizing.md): x86_64 for supportability; 3 agents |
| Retention | 14 days of alert indices | Fits the disk (ADR-010) |
| Access | SSM port forwarding to `https://localhost:8443` | No inbound port (lab safety); NM-042 is the Packet Tracer equivalent |
| Secrets | Admin, API and enrollment passwords in SSM Parameter Store | Never on disk or in Git |
| Enrollment | Password required; agents read it from SSM | Only agent roles can read it; GUEST01 cannot |
| GUEST01 | No agent | Untrusted host; NM-040 does not let the guest segment reach SIEM01. Its actions are seen in Flow Logs and on the targets |

## 2. Data sources

| Source | Collected from | Used for |
|---|---|---|
| Windows Security log | DC01, WS-FIN01 (default channels) | Logons, account changes, lockouts; the audit policy comes from `MG-Baseline-Security` (phase 5) |
| Sysmon | DC01, WS-FIN01 (`windows` group) | Process, network and file activity |
| PowerShell Operational | DC01, WS-FIN01 | Script block logging (4104) |
| File integrity | SYSVOL policies on DC01; SSH and sudo files on Linux | GPO tampering; persistence |
| Linux auth log | WS-DEV01 (agent defaults) | SSH logons and failures |
| CloudTrail | Log bucket, `cloudtrail/` | Changes to the AWS account |
| VPC Flow Logs | Log bucket, `flowlogs/` | Traffic rejected by Security Groups |

## 3. Account lists (generated from data/)

`project-03-soc/tools/render_wazuh_lists.py` writes one CDB list per account category; `pre-commit`
and CI fail if they drift from `data/`.

| List | Contents |
|---|---|
| `moretti-terminated-accounts` | Terminated employees, and admin accounts whose owner left |
| `moretti-on-leave-accounts` | Employees on leave |
| `moretti-break-glass-accounts` | Break-glass accounts |
| `moretti-service-accounts` | Service accounts (gMSAs with their trailing `$`) |
| `moretti-admin-accounts` | Admin accounts and their owners |

## 4. Rule catalog

Rule tags match the detections of `moretti-sec` (P05), so a finding in a Python report and an
alert in Wazuh use the same name. Response steps are in the [playbooks](playbooks.md).

| Wazuh ID | Tag | Level | Detects | Source | MITRE ATT&CK |
|---|---|---|---|---|---|
| 100100 | ACC-01 | 13 | Logon with a terminated employee's account | 4624 + list | T1078 |
| 100101 | ACC-01 | 8 | Logon attempt with a terminated employee's account | 4625 + list | T1078 |
| 100102 | ACC-02 | 8 | Logon by an employee on leave | 4624 + list | T1078 |
| 100103 | ACC-03 | 8 | Logon attempt with an expired account (contract ended) | 4625, sub-status `0xC0000193` | T1078 |
| 100104 | ACC-04 | 15 | Break-glass account used | 4624 + list | T1078.002 |
| 100105 | ACC-04 | 12 | Failed logon with the break-glass account | 4625 + list | T1110 |
| 100106 | ACC-05 | 12 | Interactive or RDP logon with a service account | 4624, logon type 2/10/11 + list | T1078.002 |
| 100107 | ACC-06 | 10 | Logon type not granted (tiering GPO or service-account restriction) | 4625, status `0xC000015B` | T1078.002 |
| 100110 | BF-01 | 12 | Repeated Windows logon failures from the guest network | Built-in 60204 + source address | T1110 |
| 100111 | BF-01 | 12 | SSH brute force from the guest network | Built-in 5712/5720 + source address | T1110 |
| 100120 | NET-01 | 10 | Guest traffic to internal hosts rejected by a Security Group (SCN-04) | VPC Flow Logs | T1046 |
| 100130 | CT-01 | 10 | Security Group rule changed | CloudTrail | T1562.007 |
| 100131 | CT-02 | 12 | AWS root user activity | CloudTrail | T1078.004 |
| 100132 | CT-03 | 14 | Audit logging stopped, deleted or changed | CloudTrail | T1562.008 |

What `moretti-sec` detects and Wazuh does not (yet): a successful logon **after** a brute force
(BF-02) needs event correlation across rules, and ACC-06 in Wazuh sees the logon *blocked* by the
GPO rather than an admin logon from a host other than JUMP01 (JUMP01 exists only in Packet
Tracer).

## 5. Testing

| Level | Where | What it proves |
|---|---|---|
| `project-05-python/tests/test_wazuh.py` | Here, CI | Lists match `data/`; rule IDs unique and in range; every rule documented with MITRE and covered by a test case; lists loaded by the configuration; test events use only lab or documentation addresses |
| `detections/tests/run_logtest.py` | SIEM01 | Each synthetic event in `cases.json` fires the expected rule in the real manager, including the Wazuh parent rules this design assumes |
| Validation plan | Lab | Real events from the hosts and from AWS reach the dashboard |

## 6. Known limitations

- The parent rules (groups `authentication_success`/`authentication_failed`, rules 60204, 5712,
  5720 and 80200) and the AWS field names are taken from the Wazuh 4.x ruleset without having been
  run here. `run_logtest.py` is the first place where a wrong assumption would show.
- The CDB lookups match account names exactly as Windows logs them. The lab creates lowercase
  names, so an account typed with other capitalization in a failed logon is not matched.
- Flow Logs and CloudTrail reach Wazuh with a delay: the AWS module polls the bucket every 10
  minutes, and Flow Logs aggregate per minute (architecture, section 7).
- The Sysmon configuration is a community baseline downloaded at install time; the script prints
  its SHA-256 so the validation record identifies the exact file.
