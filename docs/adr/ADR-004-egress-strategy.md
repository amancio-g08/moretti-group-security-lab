# ADR-004: Terraform-controlled egress; NAT choice deferred until measured

- **Status:** Proposed (final option pending cost measurement in Phase 4)
- **Date:** 2026-09-26
- **Related:** ADR-002, ADR-007

## Context

Lab instances live in private subnets without public IPs. They still need outbound access for:

- AWS SSM (the only administrative access path) — requires reaching SSM endpoints
- package installation (Wazuh, Sysmon, tooling) and OS updates
- Entra Cloud Sync (Phase 8)

Every egress design has a cost and a security trade-off. An important property: a **NAT Gateway
cannot be stopped** — stopping instances does not stop its hourly charge; it must be deleted.

## Options considered

| Option | Cost model | Security / operations |
|---|---|---|
| A. NAT Gateway | Hourly charge + per-GB processing + public IPv4 charge | Fully managed, no patching; cost accrues whenever it exists |
| B. NAT instance | Small instance + public IPv4 charge | Cheapest hourly; adds a host to patch and harden, and a single point of failure |
| C. VPC interface endpoints (SSM, SSM messages, EC2 messages) + S3 gateway endpoint | Hourly charge per endpoint per AZ | No internet path at all for management; does not cover package installation |
| D. Public IPs on instances, no inbound rules | Public IPv4 charge per instance | No NAT, but every instance becomes internet-addressable; one Security Group mistake exposes it |

## Decision

- Egress is controlled by a **Terraform variable** (`enable_egress`) so it exists only when a
  phase needs it, and is removed when the lab is idle.
- Option D is **rejected**: it contradicts the lab's exposure rules.
- The choice between A, B and C (or A/B combined with C) is **deferred** until Phase 4, when real
  costs are measured with the lab running. Initial implementation uses A because it has no
  maintenance burden; B is evaluated only if the measured cost justifies the added operational
  surface.

## Rationale

Choosing a NAT instance purely to save a few dollars trades cost for maintenance and attack
surface before the actual cost is known. Measuring first keeps the decision evidence-based.

## Consequences

- Positive: egress cost is bounded by usage; decision will be backed by measured numbers.
- Negative: when egress is disabled, SSM access is unavailable unless option C is present, so the
  lab must be "powered up" (egress + instances) before use.
- Follow-up: record measured hourly and monthly costs below and change the status to Accepted.

## Measurements

*To be filled in Phase 4 with observed values from AWS Cost Explorer. No estimates are recorded
here as results.*

## Revisit when

Measured egress cost exceeds the monthly budget share allocated to it, or the lab needs permanent
outbound connectivity.
