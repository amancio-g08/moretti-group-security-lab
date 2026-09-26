# Threat Model

- **Version:** 1 (design-level, Phase 1)
- **Method:** STRIDE applied per trust boundary, combined with threat actor profiles and attack paths
- **Inputs:** [`data/`](../data/) (company, assets, network matrix, roles, accounts),
  [architecture](architecture.md), [data classification](data-classification.md)

This version is based on the design. It will be revised after the lab scenarios (Phase 7) with
what was actually observed. Detection references point to capabilities planned for the SOC
project; they are not claims that a detection already exists.

---

## 1. What we are protecting

The restricted data domains are the crown jewels:

| Asset | Why an attacker wants it |
|---|---|
| General ledger and payments (APP-FIN01, DB-FIN01) | Direct financial gain: fraudulent payments, altered bank details |
| Deal pipeline and portfolio data (APP-INV01) | Market-sensitive information; valuable to competitors and for insider trading |
| Investor records and KYC (APP-CRM01) | Personal and financial data of investors; extortion and fraud |
| Employee records and payroll (APP-HR01) | Personal data; payroll diversion |
| Active Directory (DC01, DC02) | Control of AD means control of every system above |
| SIEM (SIEM01) | Blinding or misleading the defenders |

## 2. Trust boundaries

| ID | Boundary | Enforced by (PT) | Enforced by (AWS) |
|---|---|---|---|
| TB-01 | Internet ↔ DMZ | FW01 | — (no DMZ in the lab) |
| TB-02 | Internet ↔ internal networks | FW01, R-EDGE01 | No inbound rules; egress toggle |
| TB-03 | DMZ ↔ internal | FW01 | — |
| TB-04 | Guest ↔ internal | Core ACLs | Security Groups |
| TB-05 | User segment ↔ user segment | Core ACLs | Security Groups |
| TB-06 | User segments ↔ servers | Core ACLs + application authorization | Security Groups + application authorization |
| TB-07 | Management plane (jump host, device admin) ↔ everything | Core ACLs, admin accounts | SSM + AWS IAM |
| TB-08 | Security plane (SIEM) ↔ monitored hosts | Core ACLs | Security Groups |
| TB-09 | Identity plane: standard ↔ admin ↔ Tier 0 accounts | AD delegation and tiering | Same, plus Entra ID (Phase 8) |
| TB-10 | Cloud control plane: lab operator ↔ AWS account | — | IAM Identity Center + MFA, CloudTrail |

## 3. Threat actors

| ID | Actor | Motivation | Likely entry point |
|---|---|---|---|
| TA-01 | Financially motivated external attacker | Payment fraud, ransomware | Phishing a finance or executive user; exposed services |
| TA-02 | Targeted attacker (competitor or market abuse) | Deal pipeline, portfolio data | Phishing an investment professional; supply chain |
| TA-03 | Malicious or negligent insider | Data theft, sabotage, mistakes | Legitimate access beyond need; excessive rights |
| TA-04 | Former employee or contractor | Revenge, data theft | Accounts not removed on departure |
| TA-05 | Untrusted device on the premises | Opportunistic scanning, lateral movement | Guest network |
| TA-06 | Compromised developer or pipeline | Access to production, code tampering | Developer workstation, CI/CD |

## 4. Attack surface

| Entry point | Exposure | Main controls |
|---|---|---|
| WEB01 (public website) | Internet, HTTPS | DMZ isolation (NM-001, NM-003); no path inward |
| Email and web browsing | All employees | Outbound web only (NM-070); separate admin accounts; MFA (Phase 8) |
| Guest network | Anyone on premises | Internet only (NM-004 to NM-006) |
| Employee workstations | Users, removable media, browser | No workstation-to-workstation traffic (NM-060); no admin protocols from workstations (NM-033) |
| Remote administration | IT, security | Jump host only (NM-030 to NM-032); SSM in AWS |
| Service accounts | Applications | Non-interactive, least privilege, gMSA where possible |
| Lab operator access to AWS | Lab owner | IAM Identity Center + MFA; no long-lived keys; CloudTrail |
| Git repository | Lab owner and agents | gitleaks pre-commit; no secrets in Git |

## 5. Threats (STRIDE)

S = Spoofing, T = Tampering, R = Repudiation, I = Information disclosure, D = Denial of service,
E = Elevation of privilege.

| ID | Boundary / component | STRIDE | Threat | Mitigations | Detection (planned) | Scenario |
|---|---|---|---|---|---|---|
| T-01 | TB-02 | S, E | Password guessing against exposed or reachable services | No inbound internet access (NM-002); account lockout policy (Phase 5) | Failed-logon bursts (Windows 4625, sshd) | SCN-01 |
| T-02 | TB-04 | I, E | Guest device scans and attacks internal hosts | Guest isolated (NM-004) | Rejected flows from the guest segment (Flow Logs, firewall logs) | SCN-04 |
| T-03 | TB-05 | E, I | Phished workstation used to move laterally to another department (e.g. HR → Finance) | Workstation-to-workstation deny (NM-060); no local admin for users | Rejected east-west flows; unusual logons | SCN-04 |
| T-04 | TB-06 | T | Payment created and approved by the same person (fraud) | Segregation of duties: finance-staff = maker, finance-manager = approver (roles.yaml) | Application audit log (future) | — |
| T-05 | TB-06 | I | Developer accesses production finance or investment data | NM-026 deny; developer role has no business-system entitlements | Rejected flows from development to servers | — |
| T-06 | TB-06 | I | Direct database access bypassing application controls | Only APP-FIN01 reaches DB-FIN01 (NM-021) | Connections to 5432 from any other source | — |
| T-07 | TB-07 | E | Workstation used to administer servers directly | Admin protocols denied from workstations (NM-033); jump host / SSM only | Admin logons not originating from JUMP01 or SSM | — |
| T-08 | TB-09 | E | Help desk account abused to take over an admin account | Password reset delegated on standard user OUs only | Password reset on privileged accounts (4724) | — |
| T-09 | TB-09 | E | User added to a privileged group outside change control | Separate admin accounts; Tier 0 limited to one named admin + break-glass | Group membership changes (4728, 4732, 4756) | SCN-03 |
| T-10 | TB-09 | S | Former employee's account used after termination | Leaver process disables accounts on end date (Phase 5/8) | Logon attempts by disabled/terminated accounts | SCN-02 |
| T-11 | TB-09 | S, E | Break-glass account misused | Credentials sealed; owned by security | Any logon by `bg-*` accounts is critical | — |
| T-12 | TB-08 | T, R | Attacker tampers with or floods the SIEM to hide activity | Only agent, syslog and SOC traffic reach SIEM01 (NM-040 to NM-043) | Agent disconnection alerts | — |
| T-13 | TB-06 | T | Unauthorized configuration change on the finance application | Server admin only from jump host; change management | File integrity monitoring | SCN-05 |
| T-14 | TB-01, TB-03 | E | Public web server compromised and used as a pivot | DMZ cannot initiate connections inward (NM-003) | Denied DMZ → internal flows | — |
| T-15 | TB-10 | S, T, E | Lab operator credentials stolen; attacker controls the AWS account | MFA, IAM Identity Center, no access keys, Budgets alerts | CloudTrail events in Wazuh | — |
| T-16 | TB-06 | D | Ransomware encrypts file shares | Backups pulled by BKP01 (NM-050); least-privilege share permissions | Mass file modification (FIM) | — |
| T-17 | Repository | I | Secrets committed to Git | gitleaks pre-commit; secrets only in SSM Parameter Store | gitleaks in CI (Phase 3) | — |
| T-18 | TB-06 | E | Authorized scanner credentials stolen and reused | Scanner restricted to SEC-WS01 (NM-028); svc-vulnscan non-interactive | svc-vulnscan activity from any other host | FP-01 |

## 6. Key attack paths

**AP-01 — Payment fraud via phishing.** A finance analyst is phished (TA-01). The attacker uses
the analyst's session to create a payment to a controlled account. *Breaks at:* segregation of
duties (T-04) — the analyst can create but not approve; MFA (Phase 8) raises the cost of reusing
stolen credentials.

**AP-02 — Guest to crown jewels.** A device on the guest network scans for reachable services
(TA-05). *Breaks at:* NM-004 — nothing internal is reachable; every attempt is logged. This is the
lab's segmentation-violation scenario (SCN-04).

**AP-03 — Workstation to domain admin.** An attacker on any workstation tries to harvest
credentials and reach a domain controller as an administrator. *Breaks at:* no admin rights on
daily accounts, admin protocols only from the jump host (NM-033), Tier 0 limited to one account.

**AP-04 — Former employee.** A terminated service desk analyst (MG-0097 in the data) still knows
their password and tries to log on. *Breaks at:* leaver process; detected by logon attempts of a
terminated account (SCN-02).

**AP-05 — Blind the SOC.** After gaining a foothold on a server, the attacker tries to stop the
agent or attack SIEM01. *Breaks at:* NM-043; agent-disconnection alerting.

## 7. Accepted and residual risks

| Risk | Why accepted | Production alternative |
|---|---|---|
| Core ACLs are stateless (return traffic must be permitted) | Packet Tracer limitation (ADR-005) | Stateful internal firewall or zone-based firewall |
| Wide dynamic RPC range to domain controllers | Required by Windows domain members | Restrict the RPC range via registry and firewall |
| All employees can reach FS01 over SMB | Authorization is enforced by share and NTFS permissions | Same, plus data-loss prevention and access analytics |
| No web proxy or content filtering | Cost and scope | Secure web gateway |
| No EDR; endpoint visibility limited to Wazuh and Sysmon | Cost and scope | Commercial EDR |
| No network access control on the guest network | Packet Tracer and scope | 802.1X / captive portal |
| Single domain controller and single AZ in AWS | Cost (ADR-003, ADR-007) | Redundant DCs across AZs |
| MFA only in Phase 8 | Identity evolution sequence (ADR-006) | MFA from day one |

## 8. Out of scope

Physical security, denial-of-service testing, social engineering of real people, and any system
outside the lab (see [lab safety](lab-safety.md)).
