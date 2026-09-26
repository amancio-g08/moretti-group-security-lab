# Roadmap

The lab is built in phases. Each phase follows the same cycle:

1. Objective → 2. Architecture → 3. What will be created → 4. Files → 5. How to run →
6. How to validate → 7. Documented results → 8. Known issues → review before moving on.

Results are only documented from what was actually executed and observed. Steps that require the
lab owner (accounts, credentials, GUI tools) are marked **[USER ACTION REQUIRED]**.

| Phase | Deliverable | Cloud cost | Status |
|---|---|---|---|
| 0 | Repository foundation and ADRs | None | Done |
| 1 | Company data: departments, employees, assets, data classification, `network-matrix.yaml`, IAM roles, threat model v1 | None | Done |
| 2 | P01 — Packet Tracer enterprise design | None | Paused (validation in progress, see below) |
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
- **Exit criteria:** stage 1 and the representative sample of the
  [validation plan](../project-01-network/documentation/validation-plan.md#scope-representative-sample)
  are run and their results recorded (owner decision, 2026-09-26: a sample instead of every
  `pt` row; full matrix coverage comes from the static ACL verifier).

- **Status (2026-09-26): paused by the owner** to continue with later phases. Built and partly
  validated in Packet Tracer 9.0.1: C-01, C-02, C-05 pass; C-03 fails (cause not determined).
  To resume:
  1. C-04 — FINANCE DHCP pool on DC01, then renew on PC-DHCP-TEST.
  2. C-06 — FW01 still lacks the WEB01 rule in Packet Tracer (the first run rejected port
     names); re-apply FW01 from `configs/FW01.txt` after clearing its ACLs, turn on HTTPS on
     WEB01. The manual test entries added to OUTSIDE_IN during C-05/C-03 are not in the
     repository.
  3. Apply the core ACLs (`RUN_CORE_ACLS = true`) and turn on HTTPS on APP-FIN01 and APP-HR01.
  4. Run the representative sample of the validation plan and commit the `.pkt` and evidence.

  Later phases do not depend on Packet Tracer: they use `data/` as the source of truth (ADR-001).

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
