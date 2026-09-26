# Lab Safety and Rules of Engagement

This lab contains intentionally generated security events, including simulated attacks. These
rules exist so that the lab never harms third parties and never becomes an exposed, vulnerable
environment. They apply to every phase and every contributor.

## 1. Scope

| In scope | Out of scope |
|---|---|
| Hosts inside the lab VPC `10.10.0.0/16` in the lab owner's own AWS account | Any other IP address, domain or account |
| The lab's own Entra ID tenant | Any production or employer tenant |
| Packet Tracer simulations | Real network equipment not owned by the lab owner |

Any tool that generates offensive traffic (for example, port scanners or password-guessing tools)
must target **only** in-scope lab addresses, and must be launched from the designated lab host
(`GUEST01`) unless a scenario explicitly states otherwise.

AWS allows security testing of your own resources for a defined list of services without prior
approval, but forbids activities such as denial-of-service and flooding. Read the current
[AWS Penetration Testing policy](https://aws.amazon.com/security/penetration-testing/) before
running any scenario. Denial-of-service testing is not part of this lab.

## 2. Exposure rules

- No administrative service (SSH, RDP, WinRM, Wazuh dashboard, database ports) is reachable from
  the internet. Access is brokered by AWS SSM Session Manager.
- No Security Group rule may allow inbound traffic from `0.0.0.0/0` or `::/0`.
- No instance receives a public IP unless an ADR explicitly justifies it.
- Deliberately vulnerable configurations, when a scenario requires them, exist only inside the
  lab, are documented in the scenario, and are reverted afterwards.

## 3. Credentials and data

- All identities, names and business data are fictitious.
- Never use real credentials, real personal data, or credentials reused from any other system.
- Secrets are never committed. Lab passwords are generated at deploy time and stored in AWS SSM
  Parameter Store (SecureString). `gitleaks` runs on every commit.
- Terraform state is never committed (it can contain sensitive attributes).
- Lab operator access to AWS uses IAM Identity Center with MFA; no long-lived access keys.

## 4. Cost and lifecycle

- AWS Budgets alerts are configured before any compute resource is created.
- Instances stop automatically on a schedule; egress is enabled only when needed.
- The environment must be destroyable with `terraform destroy` at any time.

## 5. If something goes wrong

If a resource is found exposed, a secret is committed, or traffic leaves the defined scope:

1. **Contain** — stop the instance or remove the offending rule immediately.
2. **Rotate** — treat any committed secret as compromised and rotate it; removing it from Git
   history alone is not sufficient.
3. **Record** — document what happened in `docs/lessons-learned.md` (created in Phase 9) using the
   same incident format as the SOC project.
