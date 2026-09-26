# Data Classification

Moretti Group classifies information into four levels. The level of a piece of data determines
who may access it, how it is protected, how access is reviewed and how incidents involving it are
prioritized. The authoritative list of data domains, owners and systems is in
[`data/company.yaml`](../data/company.yaml).

> All data in this lab is fictitious. Classification is applied as if it were real so that the
> controls built on top of it are meaningful.

## 1. Levels

| Level | Definition | Impact of unauthorized disclosure or change |
|---|---|---|
| **Public** | Approved for anyone, inside or outside the company. | None. |
| **Internal** | For employees; not intended for outsiders, but low sensitivity. | Minor embarrassment or inconvenience. |
| **Confidential** | Limited to the teams that need it for their work. | Measurable harm: competitive disadvantage, operational disruption, contractual breach. |
| **Restricted** | Limited to named roles; the company's most sensitive information. | Severe harm: financial loss, regulatory action, loss of investor trust, harm to individuals. |

## 2. Moretti Group data domains

| Domain | Level | Owner | Systems |
|---|---|---|---|
| Deal pipeline and investment memos | Restricted | Investments | APP-INV01, FS01 |
| Portfolio company financials and board materials | Restricted | Investments | APP-INV01, FS01 |
| Investor (LP) records, commitments and KYC | Restricted | Investor Relations | APP-CRM01, FS01 |
| General ledger, payments and treasury | Restricted | Finance | APP-FIN01, DB-FIN01 |
| Employee records and payroll | Restricted | HR | APP-HR01, FS01 |
| Identity directory and credentials | Restricted | IT | DC01, DC02 |
| Security logs, alerts and incidents | Restricted | Security | SIEM01 |
| Fund administration and settlements | Confidential | Fund Operations | APP-FIN01 |
| Platform source code and CI/CD | Confidential | Development | GIT01 |
| Policies and internal communications | Internal | Executive | FS01 |
| Public website | Public | Investor Relations | WEB01 |

Why security telemetry is Restricted: logs reveal the internal structure of the company, user
behaviour and detection logic. An attacker who reads or alters them can plan an attack and hide it.

## 3. Handling requirements

| Requirement | Public | Internal | Confidential | Restricted |
|---|---|---|---|---|
| Access model | Anyone | All employees | Role-based (need to know) | Named roles only; approved by the data owner |
| Network exposure | Internet (DMZ) | Corporate segments | Only segments allowed in the network matrix | Only segments allowed in the network matrix; no direct user access to databases |
| Authentication | — | Domain account | Domain account | Domain account; MFA once available (Phase 8) |
| Encryption in transit | TLS | TLS where supported | TLS | TLS |
| Encryption at rest | — | — | Encrypted volumes | Encrypted volumes |
| Logging | — | — | Access logged | Access and changes logged and sent to the SIEM |
| Access review | — | Annual | Semiannual | Quarterly |
| External sharing | Allowed | Not without approval | Owner approval | Owner approval and executive sign-off |
| Incident priority floor | Low | Low | Medium | High |

## 4. How classification drives the rest of the lab

- **Assets** inherit the highest level of the data they store or process
  (`classification` in [`data/assets.yaml`](../data/assets.yaml)).
- **Roles** that grant access to restricted data are reviewed quarterly
  ([`data/roles.yaml`](../data/roles.yaml)).
- **Detections** that involve restricted systems start at a higher severity in the SOC.
- **Incident reports** state the highest classification of data involved.

## 5. Ownership

Each data domain has an owning department. The owner decides who may access the data, approves
exceptions and participates in access reviews. IT and Security operate the controls; they do not
own the business data.
