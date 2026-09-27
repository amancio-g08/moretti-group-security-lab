# infrastructure/ — AWS lab as code

[Português](README.md) | **English**

Terraform and scripts to create, stop and destroy the AWS lab. The rule here is the same as in
the rest of the project: policy comes from `data/`. Subnets and Security Group rules are
**generated** from `network-matrix.yaml`, so AWS cannot drift from what is documented.

**Status:** phase 4 code is ready and tested offline; it has **not been applied** to an AWS
account yet. Real results go into the [validation plan](docs/validation-plan.md) once it runs.

## How it is built

- **Nothing comes in from the internet.** No Security Group accepts traffic from `0.0.0.0/0`, no
  host has a public IP (only the NAT instance, justified in ADR-009) and there are no SSH keys:
  access is through SSM Session Manager only.
- **Hosts per phase.** The `aws_phase` field in `data/assets.yaml` decides when each host exists.
  Phase 4 deploys only WS-DEV01 and GUEST01.
- **Cost under control.** A budget with alerts at US$ 10, 20 and 30, created before anything
  else; Spot and ARM (Graviton) hosts; a NAT instance instead of a NAT Gateway; an automatic stop
  every night (ADR-009).
- **Evidence.** VPC Flow Logs (1-minute aggregation) and CloudTrail in an encrypted S3 bucket.

## Layout

```
infrastructure/
├── terraform/
│   ├── bootstrap/   # budget, CloudTrail and log bucket (applied first)
│   └── lab/         # VPC, subnets, NAT instance, Security Groups, Flow Logs, hosts, nightly stop
│       ├── generated/security-groups.json   # generated from data/, do not edit
│       └── tests/   # plan tests with a mocked AWS provider (no account needed)
├── scripts/         # lab-up, lab-down, lab-destroy, cost-check
├── tools/           # render_security_groups.py (matrix → Security Groups)
└── docs/            # deployment guide and validation plan
```

## Usage

The step-by-step guide, including creating the account and MFA-protected access, is the
[deployment guide](docs/deployment-guide.md). In short:

```bash
cd infrastructure/terraform/bootstrap && terraform init && terraform apply
cd ../lab && terraform init && terraform plan -out phase4.tfplan && terraform apply phase4.tfplan
infrastructure/scripts/lab-down.sh     # stop everything at the end of a session
```

## Checks

```bash
python3 infrastructure/tools/render_security_groups.py --check   # rules match the matrix
terraform -chdir=infrastructure/terraform/lab test                # offline plan tests
```

Both run in CI, and the first one also runs in `pre-commit`.

## Decisions

[ADR-002](../docs/adr/ADR-002-cloud-platform.md), [003](../docs/adr/ADR-003-single-az.md),
[004](../docs/adr/ADR-004-egress-strategy.md), [007](../docs/adr/ADR-007-minimum-footprint.md) and
[009](../docs/adr/ADR-009-cost-optimized-aws-lab.md).
