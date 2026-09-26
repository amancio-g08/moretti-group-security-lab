# Architecture Decision Records

An ADR captures one significant decision: its context, the options that were considered, the
decision, and its consequences. ADRs are immutable once accepted; a changed decision is recorded
in a new ADR that supersedes the old one.

| ADR | Title | Status |
|---|---|---|
| [001](ADR-001-source-of-truth.md) | Policy files are the single source of truth | Proposed |
| [002](ADR-002-cloud-platform.md) | AWS for infrastructure, Entra ID for cloud identity | Proposed |
| [003](ADR-003-single-az.md) | Single-AZ deployment | Proposed |
| [004](ADR-004-egress-strategy.md) | Terraform-controlled egress; NAT choice deferred until measured | Proposed |
| [005](ADR-005-lab-vs-enterprise.md) | Packet Tracer is the enterprise design; AWS is the operational lab | Proposed |
| [006](ADR-006-identity-evolution.md) | Identity evolves on-prem → hybrid → cloud | Proposed |
| [007](ADR-007-minimum-footprint.md) | Minimum VM footprint, grown per phase | Proposed |

**Statuses:** Proposed → Accepted → (Superseded by ADR-xxx | Deprecated).

New ADRs start from [TEMPLATE.md](TEMPLATE.md).
