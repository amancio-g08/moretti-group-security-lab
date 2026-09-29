# Architecture Decision Records

[Português](README.md) | **English**

An ADR captures one significant decision: its context, the options that were considered, the
decision, and its consequences. ADRs are immutable once accepted; a changed decision is recorded
in a new ADR that supersedes the old one.

| ADR | Title | Status |
|---|---|---|
| [001](ADR-001-source-of-truth.md) | Policy files are the single source of truth | Accepted |
| [002](ADR-002-cloud-platform.md) | AWS for infrastructure, Entra ID for cloud identity | Accepted |
| [003](ADR-003-single-az.md) | Single-AZ deployment | Accepted |
| [004](ADR-004-egress-strategy.md) | Terraform-controlled egress; NAT choice deferred until measured | Accepted (NAT: see 009) |
| [005](ADR-005-lab-vs-enterprise.md) | Packet Tracer is the enterprise design; AWS is the operational lab | Accepted |
| [006](ADR-006-identity-evolution.md) | Identity evolves on-prem → hybrid → cloud | Accepted |
| [007](ADR-007-minimum-footprint.md) | Minimum VM footprint, grown per phase | Accepted |
| [008](ADR-008-network-enforcement-points.md) | Core switch ACLs east-west, ASA at the perimeter, NAT at the edge router | Proposed |
| [009](ADR-009-cost-optimized-aws-lab.md) | Cost-optimized AWS lab: hosts per phase, Graviton, Spot and a NAT instance | Accepted |
| [010](ADR-010-siem-sizing.md) | SIEM01 on x86_64, below the recommended size, with 14-day retention | Accepted |

**Statuses:** Proposed → Accepted → (Superseded by ADR-xxx | Deprecated).

New ADRs start from [TEMPLATE.md](TEMPLATE.md).
