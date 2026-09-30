# Roadmap

The lab is built in phases. Each phase follows the same cycle:

1. Objective → 2. Architecture → 3. What will be created → 4. Files → 5. How to run →
6. How to validate → 7. Documented results → 8. Known issues → review before moving on.

Results are only documented from what was actually executed and observed. Steps that require the
lab owner (accounts, credentials, GUI tools) are marked **[USER ACTION REQUIRED]**.
From phase 4 on, the code of each phase is written and tested offline first; the steps that need
the lab owner are collected, in order, in the [operator checklist](operator-checklist.md) and
executed later (owner decision, 2026-09-29).

| Phase | Deliverable | Cloud cost | Status |
|---|---|---|---|
| 0 | Repository foundation and ADRs | None | Done |
| 1 | Company data: departments, employees, assets, data classification, `network-matrix.yaml`, IAM roles, threat model v1 | None | Done |
| 2 | P01 — Packet Tracer enterprise design | None | Paused (validation in progress, see below) |
| 3 | P05 — Python core (parsers, enrichment, detections, reports) | None | Done |
| 4 | Minimal AWS lab: VPC, SGs from the matrix, Flow Logs, CloudTrail, Budgets; hosts per phase (ADR-009) | Starts here | In progress (code ready, not applied) |
| 5 | P04a — Active Directory (OUs, GPOs, RBAC, policies) | Low | In progress (code ready, not applied) |
| 6 | P03 — Wazuh + agents, AWS module, custom rules | Medium | In progress (code ready, not applied) |
| 7 | Scenarios end to end: PCAP + SOC + Python (APP-FIN01 added) | Medium | In progress (all code ready, not executed) |
| 8 | P04b — Entra ID (Cloud Sync, MFA, Conditional Access, lifecycle) | Trial license | In progress (code ready, not applied) |
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
  unit tests with fixtures that are clearly labeled as synthetic. The matrix → ACL renderer
  already lives in P01; the matrix → Security Group renderer moved to phase 4 (owner decision,
  2026-09-26), next to the Terraform that consumes it.
- **Exit criteria:** tests and linters pass in CI and locally.
- **Status (2026-09-26):** `moretti-sec` package with sshd and Windows parsers, enrichment from
  `data/`, detections BF-01/02 and ACC-01…06, IOC extraction, timeline and Markdown report;
  19 tests and ruff pass locally and in `pre-commit`. CI workflow added
  (`.github/workflows/ci.yml`); first run on GitHub (run #1, commit `a6c3498` on `main`)
  passed all three jobs.

### Phase 4 — Minimal AWS lab
- **Creates:** matrix → Security Group renderer (moved from phase 3), Terraform for VPC,
  subnets, Security Groups generated from the matrix, SSM access,
  Flow Logs, CloudTrail, Budgets, scheduled shutdown, egress toggle; start/stop/destroy scripts.
- **[USER ACTION REQUIRED]:** AWS account, MFA on root, IAM Identity Center user, `terraform apply`.
- **Exit criteria:** no inbound internet rules exist; SSM access works; measured costs recorded in
  ADR-004.
- **Status (2026-09-27):** design approved with the cost-optimized package (ADR-009), region
  us-east-1, Terraform state on the operator's machine. Code ready: Security Group renderer in
  P05 (with tests), `bootstrap` and `lab` stacks, offline plan tests with a mocked provider,
  scripts, [deployment guide](../infrastructure/docs/deployment-guide.md) and
  [validation plan](../infrastructure/docs/validation-plan.md). Checked here: `terraform
  validate` and `terraform test` (4 passing), renderer tests, shellcheck. **Not yet applied** to an
  AWS account: [USER ACTION REQUIRED] steps 1–5 of the deployment guide. The first CI run of the
  Terraform job (fmt, validate, offline plan tests) passed on `main` at commit `0320f57`.

### Phase 5 — P04a Active Directory
- **Creates:** OU design, group model, GPOs, password and lockout policies, PowerShell provisioning
  from company data, delegated permissions, admin tiering.
- **Exit criteria:** every user's permissions are traceable to a role in `data/`.
- **Status (2026-09-29):** design approved (employees on leave disabled; random passwords in SSM
  Parameter Store, changed at first logon). Code ready: AD plan generator in P05 with 18 tests
  (AGDLP, segregation of duties, leaver rules, Domain Admins membership), PowerShell scripts to
  create the forest, apply the plan idempotently, create the GPOs (including audit policy and user
  rights written as GPO files) and join WS-FIN01 with a Tier 2 account; DC01-only IAM permission for
  the AD passwords in Terraform. Checked here: PSScriptAnalyzer (0 findings), dry runs against a
  simulated domain (empty domain, leaver), GPO file tests, `terraform test`. **Not yet applied**:
  [operator checklist](operator-checklist.md), section D. Design: [AD design](../project-04-iam/documentation/ad-design.md).

### Phase 6 — P03 Wazuh
- **Creates:** Wazuh deployment notes, agent enrollment, Sysmon, FIM, AWS module, custom rules and
  CDB lists, baseline documentation.
- **Exit criteria:** every host reports to Wazuh; baseline alerts documented.
- **Status (2026-09-29):** design approved (SIEM01 on x86_64 t3.large with 14-day retention,
  [ADR-010](adr/ADR-010-siem-sizing.md); GUEST01 without agent). Code ready: install and
  deployment scripts, agent installers (Linux; Windows with Sysmon), agent group configurations,
  14 custom rules mapped to the `moretti-sec` detections and MITRE ATT&CK, account lists generated
  from `data/`, 15 synthetic logtest cases and a runner for SIEM01, playbooks; per-role IAM in
  Terraform (only agents read the enrollment password; SIEM01 reads the log bucket). Checked here:
  `test_wazuh.py`, shellcheck, PSScriptAnalyzer, `terraform test`, the logtest runner against a
  simulated API. **Not yet deployed**: [operator checklist](operator-checklist.md), section E.

### Phase 7 — Scenarios
- **Creates:** SCN-01 … SCN-05 and FP-01 run books, captures, investigation reports, incident
  reports, generated Python reports; APP-FIN01 added.
- **Exit criteria:** every scenario traceable across all relevant sources, with observed evidence.
- **Status (2026-09-30):** first part done, owner's addition: a **Wireshark plugin in Lua**
  (project-02-pcap) that labels every packet with the asset, the segment and the network matrix
  verdict, from a policy table generated from `data/`. Checked here and in CI: engine unit tests,
  a differential test against an independent Python evaluator (203,228 flows, no disagreement) and
  an end-to-end `tshark` test on a synthetic capture. An Nmap NSE script (Lua) that audits
  segmentation from GUEST01 comes with the scenarios, since it needs the lab running.
- **Status (2026-09-30), code complete:** run books for SCN-01..05 and FP-01; `moretti-sec
  correlate` merging auth logs, VPC Flow Logs and Wazuh alerts into one enriched timeline (new
  parsers, tested with synthetic samples); Wazuh rule ACC-07 (SCN-03) with a privileged-groups
  list generated from `data/`; the Nmap NSE segmentation audit in Lua with its target table
  generated from `data/` and unit-tested; incident and PCAP report templates. Checked here and in
  CI: Python tests, the Lua engine and segmentation tests, tshark end to end. **Not executed**:
  operator checklist, section G.

### Phase 8 — P04b Entra ID
- **Creates:** tenant configuration, Cloud Sync, MFA, Conditional Access, Joiner/Mover/Leaver,
  access reviews.
- **[USER ACTION REQUIRED]:** Entra tenant and P1/P2 trial activation.
- **Status (2026-09-30), code complete:** Conditional Access policies as Graph JSON generated from
  `data/` (report-only, break-glass excluded) with an apply script; `moretti-sec access-review` (the
  Entra P2 substitute the ADR names) comparing an AD export with the plan and flagging deviations;
  Cloud Sync scope, JML mapping and validation plan documented. Checked here and in CI: Python tests
  (access review and CA generator), PSScriptAnalyzer. **Not applied**: operator checklist, section H.

### Phase 9 — Consolidation
- **Creates:** final diagrams, lessons learned, troubleshooting, portfolio summary; environment
  destroyed.
