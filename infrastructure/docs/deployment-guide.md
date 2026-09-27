# AWS Lab Deployment Guide

How to create the AWS lab from this repository. Everything in AWS is done by the lab owner:
the steps below are **[USER ACTION REQUIRED]**. Design decisions: ADR-002, ADR-003, ADR-004,
ADR-007 and [ADR-009](../../docs/adr/ADR-009-cost-optimized-aws-lab.md).

Cost figures in this guide are estimates from list prices. Real costs are measured with
`scripts/cost-check.sh` and recorded in ADR-004.

## What gets created

| Stack | Resources | When |
|---|---|---|
| `terraform/bootstrap` | Monthly budget with e-mail alerts (US$ 10 / 20 / 30), CloudTrail (all regions), encrypted S3 bucket for logs (30-day retention) | Once, **before** anything else |
| `terraform/lab` | VPC `10.10.0.0/16`, one subnet per AWS segment of the matrix, NAT instance, Security Groups generated from the matrix, VPC Flow Logs, SSM role, hosts of the current phase, nightly stop | Every phase (`lab_phase`) |

No instance except the NAT instance has a public IP, no Security Group accepts traffic from the
internet, and there are no SSH keys: hosts are reached only through SSM Session Manager.

## 1. AWS account

1. Create an account at <https://aws.amazon.com>. New accounts may receive free-tier credits; check
   the current offer on the sign-up page.
2. Sign in as the **root user** → top-right menu → **Security credentials** → **Assign MFA device**
   → authenticator app. Do **not** create access keys for the root user.
3. After this step the root user is used only for account-level tasks (billing, closing the
   account).

## 2. Your daily identity: IAM Identity Center

1. Console → region **N. Virginia (us-east-1)** → **IAM Identity Center** → **Enable**.
2. **Users** → **Add user**: your name and e-mail. Accept the invitation e-mail, set a password
   and register MFA.
3. **Permission sets** → **Create** → predefined **AdministratorAccess**, session duration 4 hours.
   Terraform creates IAM roles, so a narrower permission set would not be able to deploy the lab.
4. **AWS accounts** → select your account → **Assign users** → your user + that permission set.
5. Note the **AWS access portal URL** shown on the Identity Center dashboard.

## 3. Tools on the Mac

```bash
brew install awscli
brew tap hashicorp/tap && brew install hashicorp/tap/terraform
brew install --cask session-manager-plugin
```

Log in (the browser opens for the password and MFA):

```bash
aws configure sso          # SSO start URL = access portal URL, region us-east-1, profile moretti-lab
export AWS_PROFILE=moretti-lab
aws sso login
aws sts get-caller-identity   # shows your account and the AdministratorAccess role
```

`aws sso login` is repeated when the session expires; there are no long-lived keys.

## 4. Bootstrap (guardrails first)

```bash
cd infrastructure/terraform/bootstrap
cp terraform.tfvars.example terraform.tfvars    # edit: your e-mail for the budget alerts
terraform init
terraform plan        # review: 1 budget, 1 trail, 1 bucket and its settings
terraform apply
```

`terraform.tfvars` and `terraform.tfstate` stay on your Mac: Git ignores them.

## 5. Lab (phase 4)

```bash
python3 infrastructure/tools/render_security_groups.py --check   # rules match the matrix
cd infrastructure/terraform/lab
terraform init
terraform plan -out phase4.tfplan
```

Review the plan before applying:

- Instances: only `WS-DEV01`, `GUEST01` and the NAT instance.
- `0.0.0.0/0` appears only in **egress** rules and in the transit route table, never in an
  ingress rule.

```bash
terraform apply phase4.tfplan
terraform output ssm_session_commands
```

Then run the [validation plan](validation-plan.md).

## 6. Daily use

| Action | Command |
|---|---|
| Start the lab | `infrastructure/scripts/lab-up.sh` |
| Open a shell on a host | `aws ssm start-session --target <instance-id>` |
| Stop the lab | `infrastructure/scripts/lab-down.sh` (also happens every night at 23:00 São Paulo time) |
| Month-to-date cost | `infrastructure/scripts/cost-check.sh` (US$ 0.01 per call) |
| Next phase | `terraform apply -var lab_phase=5` (adds DC01 and WS-FIN01) |
| Remove egress | `terraform apply -var enable_egress=false` (deletes the NAT instance; hosts lose SSM) |
| Delete everything | `infrastructure/scripts/lab-destroy.sh` |

Stopped instances cost nothing per hour, but their disks are still billed. `lab-destroy.sh`
deletes the disks too; the bootstrap stack (budget, CloudTrail, logs) is kept unless you confirm
its removal.

## 7. After the first week

Run `cost-check.sh` and record the observed figures in the *Measurements* section of
[ADR-004](../../docs/adr/ADR-004-egress-strategy.md).
