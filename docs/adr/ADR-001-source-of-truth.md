# ADR-001: Policy files are the single source of truth

- **Status:** Proposed
- **Date:** 2026-09-26
- **Related:** ADR-005

## Context

The lab consists of five projects that document and implement the same company from different
angles: network design, cloud controls, identity, detection and automation. If each project keeps
its own copy of "who may talk to whom" or "who has which role", the copies drift apart, and the
portfolio stops being a coherent system. Drift between documented policy and implemented controls
is also a real-world security problem worth demonstrating a solution for.

## Options considered

| Option | Pros | Cons |
|---|---|---|
| A. Each project documents its own policy | Simple to start | Inevitable drift; projects look disconnected |
| B. Policy documented once in Markdown | Human-readable | Not machine-readable; implementations still diverge |
| C. Machine-readable policy files in `data/`, consumed by every project | One definition; can generate and validate controls | Requires a schema and small tooling |

## Decision

Option C. The following files in `data/` are authoritative:

- `network-matrix.yaml` — permitted and denied flows between segments
- company data — departments, employees (fictitious), assets, data classification
- IAM roles — role definitions and their entitlements

## Rationale

A machine-readable policy can be rendered into Packet Tracer ACLs, read directly by Terraform
(`yamldecode`) to build Security Groups, loaded by AD provisioning scripts, and used by the Python
toolkit for enrichment and consistency checks. The policy and the controls cannot silently diverge.

## Consequences

- Positive: consistency across projects; drift becomes detectable by automated checks.
- Positive: strong interview narrative — "one policy, multiple enforcement points".
- Negative: a schema must be defined and kept stable; changes to it ripple through consumers.
- Follow-up: define schemas and validation in Phases 1 and 3.

## Revisit when

The data model grows beyond what YAML/CSV can express clearly (for example, time-bound or
attribute-based access rules).
