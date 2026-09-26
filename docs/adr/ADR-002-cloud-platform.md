# ADR-002: AWS for infrastructure, Entra ID for cloud identity

- **Status:** Proposed
- **Date:** 2026-09-26
- **Related:** ADR-004, ADR-006

## Context

The lab needs real hosts producing real logs and traffic, cloud-native audit sources, and a cloud
identity platform. It must be low cost, isolated, reproducible from code, and must not expose
administrative services to the internet.

## Options considered

| Option | Pros | Cons |
|---|---|---|
| A. AWS only | Mature IaC; SSM gives brokered access with no inbound ports; Wazuh has a native AWS module | No native enterprise identity platform comparable to Entra ID |
| B. Azure only | Native Entra ID integration | Azure Bastion is costly; brokered access otherwise needs a self-managed VPN |
| C. GCP only | IAP TCP forwarding is inexpensive | Weaker fit for enterprise identity and Windows-centric scenarios |
| D. AWS for infrastructure + Entra ID for identity | Brokered access without open ports; native AWS audit sources; industry-standard identity platform | Two platforms to operate |

## Decision

Option D. AWS hosts the operational lab; a dedicated Entra ID tenant provides cloud identity.

## Rationale

- AWS SSM Session Manager provides shell and port forwarding (RDP, Wazuh dashboard) with **zero
  inbound rules**, which directly satisfies the "no public administration" requirement at no
  bastion cost.
- CloudTrail and VPC Flow Logs integrate with Wazuh natively.
- Entra ID is independent of the infrastructure provider and demonstrates widely used identity
  controls (MFA, Conditional Access, lifecycle).
- Demonstrating both platforms broadens the portfolio.

## Consequences

- Positive: minimal attack surface; strong cloud-logging story; recognizable technologies.
- Negative: Conditional Access requires Entra ID P1, and access reviews/PIM require P2 — these
  depend on a time-limited trial. Where a feature is unavailable, the limitation is documented
  rather than simulated as if it existed.
- Negative: AWS does not offer license-included Windows client OS on standard instances; Windows
  "workstations" run Windows Server. This deviation is documented.
- Follow-up: AWS account hardening (root MFA, IAM Identity Center, Budgets) before any resource
  is created.

## Revisit when

The lab's focus shifts to Microsoft-native security tooling (for example, Defender or Sentinel),
where hosting on Azure would reduce integration effort.
