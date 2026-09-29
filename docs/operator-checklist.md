# Operator Checklist

Everything that only the lab owner can do (own accounts, credentials, GUI tools), in the order
to do it. The code for these steps is already in the repository; nothing here has been executed
until its box is ticked and its result is recorded in the linked plan.

Rules while working through the list:

- Record only what you observe. A step that fails is recorded as failed, with the output.
- Evidence never contains account IDs, e-mail addresses, access portal URLs or passwords: replace
  them with `<account>`, `<email>` and so on.
- The Packet Tracer lab password is lab-only. Never reuse it anywhere else.
- Stop the AWS lab at the end of every session (`infrastructure/scripts/lab-down.sh`).

## A. Packet Tracer (phase 2, paused)

Details: [roadmap, phase 2](roadmap.md#phase-2--p01-network-packet-tracer) and the
[validation plan](../project-01-network/documentation/validation-plan.md).

- [ ] A1. C-04: FINANCE DHCP pool on DC01, then DHCP renew on PC-DHCP-TEST.
- [ ] A2. C-06: clear FW01's ACLs, re-apply `configs/FW01.txt` (numeric ports), turn on HTTPS on
      WEB01, test from INTERNET-SRV.
- [ ] A3. Apply the core ACLs (build script with `RUN_CORE_ACLS = true`); turn on HTTPS on
      APP-FIN01 and APP-HR01.
- [ ] A4. Run the representative sample (V-01, V-05, V-10, V-14, V-17, D-01, D-02, D-04, D-06,
      D-08, D-11, L-01, L-05) and record the results.
- [ ] A5. Optional: revisit C-03 (JUMP01 → R-EDGE01 ping) with `show access-list` counters on FW01.
- [ ] A6. Commit `packet-tracer/moretti-group-network.pkt` and the screenshots in
      `documentation/evidence/`.

## B. AWS account and tools (phase 4)

Details: [deployment guide](../infrastructure/docs/deployment-guide.md), steps 1–3.

- [ ] B1. Create the AWS account; check the free-tier credit offer.
- [ ] B2. Root user: MFA on, no access keys.
- [ ] B3. IAM Identity Center in us-east-1: your user with MFA, AdministratorAccess permission set.
- [ ] B4. On the Mac: `awscli`, `terraform` (HashiCorp tap), `session-manager-plugin`;
      `aws configure sso` with profile `moretti-lab`; `aws sts get-caller-identity` works.

## C. AWS lab, phase 4

Details: [deployment guide](../infrastructure/docs/deployment-guide.md), steps 4–7, and the
[AWS validation plan](../infrastructure/docs/validation-plan.md).

- [ ] C1. Apply `terraform/bootstrap` (budget e-mail in `terraform.tfvars`, never committed).
- [ ] C2. Plan `terraform/lab` (`lab_phase = 4`), review it, apply it.
- [ ] C3. Commit the two `.terraform.lock.hcl` files that `terraform init` created (they pin the
      provider version; they contain no secrets).
- [ ] C4. Run A-01 … A-10 and record the results.
- [ ] C5. After one week: `cost-check.sh` → *Measurements* in ADR-004 (A-11).

## D. Active Directory (phase 5)

Details: [AD design](../project-04-iam/documentation/ad-design.md) and the
[AD validation plan](../project-04-iam/documentation/validation-plan.md). Needs section C done.

- [ ] D1. Deploy DC01 and WS-FIN01: `terraform -chdir=infrastructure/terraform/lab apply -var lab_phase=5`.
- [ ] D2. Open a session on DC01 (`aws ssm start-session --target <DC01 id>`; it starts PowerShell)
      and download the scripts and the plan:
      ```powershell
      $repo = 'https://raw.githubusercontent.com/amancio-g08/moretti-group-security-lab/main/project-04-iam'
      New-Item -ItemType Directory -Force C:\lab\scripts, C:\lab\generated | Out-Null
      'LabCommon.ps1', 'GpoTemplates.ps1', 'Install-DomainController.ps1', 'Invoke-ADProvisioning.ps1', 'New-LabGpos.ps1' |
          ForEach-Object { Invoke-WebRequest "$repo/scripts/$_" -OutFile "C:\lab\scripts\$_" -UseBasicParsing }
      Invoke-WebRequest "$repo/generated/ad-plan.json" -OutFile C:\lab\generated\ad-plan.json -UseBasicParsing
      cd C:\lab\scripts
      ```
- [ ] D3. `.\Install-DomainController.ps1 -WhatIf`, then without `-WhatIf`. DC01 restarts; wait about
      10 minutes and open a new session.
- [ ] D4. `.\Invoke-ADProvisioning.ps1 -WhatIf`, review the list, run it, then run it again (AD-02).
- [ ] D5. `.\New-LabGpos.ps1 -WhatIf`, then without `-WhatIf`.
- [ ] D6. On WS-FIN01: download `Join-LabDomain.ps1` the same way, get the password of
      `adm-kelly.mattos` on your Mac (the command is at the top of the script) and run it.
- [ ] D7. Run AD-01 … AD-16 and record the results.
- [ ] D8. After confirming that `adm-marcio.guimaraes` can administer the domain, disable the
      built-in `Administrator` account and record it (AD-07).
- [ ] D9. `infrastructure/scripts/lab-down.sh`.

## E. SOC with Wazuh (phase 6)

Details: [SOC design](../project-03-soc/documentation/soc-design.md) and the
[SOC validation plan](../project-03-soc/documentation/validation-plan.md). Needs section D done.

- [ ] E1. Deploy SIEM01: `terraform -chdir=infrastructure/terraform/lab apply -var lab_phase=6`.
- [ ] E2. Open the Wazuh quickstart and note the current release (for example `4.12`).
- [ ] E3. On SIEM01 (`aws ssm start-session --target <SIEM01 id>`, then `sudo -i`):
      ```bash
      git clone --depth 1 https://github.com/amancio-g08/moretti-group-security-lab /opt/moretti-lab
      WAZUH_RELEASE=<release> /opt/moretti-lab/project-03-soc/wazuh/install-wazuh.sh
      /var/ossec/bin/wazuh-control info    # note WAZUH_VERSION for the agents
      ```
- [ ] E4. WS-DEV01 (`sudo -i`): clone the repository the same way, then
      `WAZUH_VERSION=<version> /opt/moretti-lab/project-03-soc/agents/install-agent-linux.sh`.
- [ ] E5. DC01 and WS-FIN01 (PowerShell): download `project-03-soc/agents/Install-WazuhAgent.ps1`
      as in D2, then `.\Install-WazuhAgent.ps1 -Version <version>`; on DC01 add
      `-Groups 'windows,domain-controllers'`.
- [ ] E6. Dashboard from the Mac:
      `aws ssm start-session --target <SIEM01 id> --document-name AWS-StartPortForwardingSession --parameters portNumber=443,localPortNumber=8443`,
      then `https://localhost:8443`, user `admin`, password from
      `aws ssm get-parameter --with-decryption --name /moretti-group-lab/wazuh/admin-password --query Parameter.Value --output text`.
- [ ] E7. Rule tests on SIEM01:
      ```bash
      export WAZUH_API_PASSWORD="$(aws ssm get-parameter --with-decryption --name /moretti-group-lab/wazuh/api-password --query Parameter.Value --output text)"
      python3 /opt/moretti-lab/project-03-soc/detections/tests/run_logtest.py
      ```
- [ ] E8. Run W-01 … W-11 and record the results.
- [ ] E9. After any change to `data/` or the rules: `git -C /opt/moretti-lab pull` and
      `/opt/moretti-lab/project-03-soc/wazuh/deploy-ruleset.sh` on SIEM01.
- [ ] E10. `infrastructure/scripts/lab-down.sh`.

## Later phases

Items are added here as the code of each phase is written (7 — scenarios, 8 — Entra ID).
