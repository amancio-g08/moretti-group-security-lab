# ADR-003: Single-AZ deployment

- **Status:** Proposed
- **Date:** 2026-09-26
- **Related:** ADR-007

## Context

Production AWS architectures spread workloads across multiple Availability Zones for resilience.
This lab's goal is security engineering, not availability, and it runs only while it is being used.

## Options considered

| Option | Pros | Cons |
|---|---|---|
| A. Multi-AZ | Representative of production resilience | More subnets, duplicated components, possible inter-AZ data transfer charges; no benefit to the lab's goals |
| B. Single AZ | Simplest topology; lowest cost; easier troubleshooting | An AZ outage makes the lab unavailable |

## Decision

Option B.

> **Single-AZ architecture is an intentional cost optimization for this laboratory and is not
> representative of a production high-availability architecture.**

## Rationale

The lab is disposable and rebuilt from code. Unavailability during an AZ incident has no business
impact, while multi-AZ would add cost and complexity without improving any security objective.

## Consequences

- Positive: lower cost, fewer moving parts.
- Negative / accepted risk: no resilience to AZ failure.
- Follow-up: the architecture documentation states how a production design would differ
  (multi-AZ subnets, redundant domain controllers, redundant egress).

## Revisit when

The lab starts demonstrating resilience or disaster-recovery scenarios.
