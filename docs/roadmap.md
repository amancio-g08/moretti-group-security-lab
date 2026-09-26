# Roadmap

The lab is built in phases. Each phase follows the same cycle:

1. Objective → 2. Architecture → 3. What will be created → 4. Files → 5. How to run →
6. How to validate → 7. Documented results → 8. Known issues → review before moving on.

Results are only documented from what was actually executed and observed. Steps that require the
lab owner (accounts, credentials, GUI tools) are marked **[USER ACTION REQUIRED]**.

| Phase | Deliverable | Cloud cost | Status |
|---|---|---|---|
| 0 | Repository foundation and ADRs | None | Done |
| 1 | Company data: departments, employees, assets, data classification, `network-matrix.yaml`, IAM roles, threat model v1 | None | In review |
| 2 | P01 — Packet Tracer enterprise design | None | Planned |
| 3 | P05 — Python core (parsers, reports, matrix translation) | None | Planned |
| 4 | Minimal AWS lab: VPC, 5 VMs, SGs from the matrix, Flow Logs, CloudTrail, Budgets | Starts here | Planned |
| 5 | P04a — Active Directory (OUs, GPOs, RBAC, policies) | Low | Planned |
| 6 | P03 — Wazuh + agents, AWS module, custom rules | Medium | Planned |
| 7 | Scenarios end to end: PCAP + SOC + Python (APP-FIN01 added) | Medium | Planned |
| 8 | P04b — Entra ID (Cloud Sync, MFA, Conditional Access, lifecycle) | Trial license | Planned |
| 9 | Portfolio consolidation and teardown | → None | Planned |

## Phase details

### Phase 0 — Foundation
- **Creates:** README, LICENSE, `.gitignore`, `.env.example`, `pre-commit` (gitleaks), editor
  config, architecture overview, roadmap, lab safety rules, ADR-001 … ADR-007, project skeleton.
- **Exit criteria:** `pre-commit run --all-files` passes; ADRs reviewed and accepted by the owner.

### Phase 1 — Company and policy data
- **Creates:** `data/` files (departments, employees, assets, data classification, IAM roles,
  `network-matrix.yaml`), asset inventory, threat model v1.
- **Exit criteria:** every flow in the matrix has a business justification; every role maps to
  departments; data files validate against a schema.

### Phase 2 — P01 Network (Packet Tracer)
- **Creates:** device configurations, ACLs derived from the matrix, addressing plan, hardening
  baseline, build guide, validation test plan.
- **[USER ACTION REQUIRED]:** build the `.pkt` topology in Cisco Packet Tracer (the binary file
  cannot be generated outside the application) and run the validation tests.
- **Exit criteria:** every ALLOW/DENY row marked `pt` is tested in simulation and the result recorded.

### Phase 3 — P05 Python core
- **Creates:** modular package (parsers, normalization, enrichment, timeline, report generation),
  unit tests with fixtures that are clearly labeled as synthetic, matrix → ACL/SG renderers.
- **Exit criteria:** tests and linters pass in CI and locally.

### Phase 4 — Minimal AWS lab
- **Creates:** Terraform for VPC, subnets, Security Groups generated from the matrix, SSM access,
  Flow Logs, CloudTrail, Budgets, scheduled shutdown, egress toggle; start/stop/destroy scripts.
- **[USER ACTION REQUIRED]:** AWS account, MFA on root, IAM Identity Center user, `terraform apply`.
- **Exit criteria:** no inbound internet rules exist; SSM access works; measured costs recorded in
  ADR-004.

### Phase 5 — P04a Active Directory
- **Creates:** OU design, group model, GPOs, password and lockout policies, PowerShell provisioning
  from company data, delegated permissions, admin tiering.
- **Exit criteria:** every user's permissions are traceable to a role in `data/`.

### Phase 6 — P03 Wazuh
- **Creates:** Wazuh deployment notes, agent enrollment, Sysmon, FIM, AWS module, custom rules and
  CDB lists, baseline documentation.
- **Exit criteria:** every host reports to Wazuh; baseline alerts documented.

### Phase 7 — Scenarios
- **Creates:** SCN-01 … SCN-05 and FP-01 run books, captures, investigation reports, incident
  reports, generated Python reports; APP-FIN01 added.
- **Exit criteria:** every scenario traceable across all relevant sources, with observed evidence.

### Phase 8 — P04b Entra ID
- **Creates:** tenant configuration, Cloud Sync, MFA, Conditional Access, Joiner/Mover/Leaver,
  access reviews.
- **[USER ACTION REQUIRED]:** Entra tenant and P1/P2 trial activation.

### Phase 9 — Consolidation
- **Creates:** final diagrams, lessons learned, troubleshooting, portfolio summary; environment
  destroyed.
