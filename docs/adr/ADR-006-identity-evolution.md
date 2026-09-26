# ADR-006: Identity evolves on-prem → hybrid → cloud

- **Status:** Accepted
- **Date:** 2026-09-26
- **Related:** ADR-002

## Context

The lab must demonstrate RBAC, least privilege, Joiner/Mover/Leaver, password and lockout
policies, MFA, Conditional Access and access reviews. These capabilities span Active Directory
and Entra ID. Introducing both at once would mix two sets of problems during troubleshooting and
hide the story of how organizations actually evolve their identity estate.

## Options considered

| Option | Pros | Cons |
|---|---|---|
| A. Hybrid (AD + Entra Cloud Sync) from the start | Full picture early | Two systems to debug at once; sync issues obscure AD design issues |
| B. Entra ID only | Simple; no domain controller | Loses GPOs, Kerberos/NTLM events and Windows domain telemetry for the SOC |
| C. AD first, then hybrid, then cloud controls | Clear progression; each stage validated before the next | Entra features arrive later in the roadmap |

## Decision

Option C.

1. **Stage 1 — On-prem (Phase 5):** Active Directory `corp.moretti.internal` — OUs, users, groups,
   GPOs, RBAC, password and lockout policies, delegated administration, separate admin accounts.
2. **Stage 2 — Hybrid (Phase 8):** Entra Cloud Sync from AD to Entra ID.
3. **Stage 3 — Cloud controls (Phase 8):** MFA, Conditional Access, identity lifecycle, access
   reviews.

## Rationale

The progression mirrors a common enterprise journey and makes each stage independently verifiable.
AD also produces the Windows authentication and directory events that the SOC project depends on.

## Consequences

- Positive: clean troubleshooting boundaries; strong career narrative.
- Negative: Conditional Access requires Entra ID P1 and access reviews require P2 (trial-based);
  where unavailable, the gap is documented, and a Python-based access review over AD exports is
  used instead.
- Negative: Cloud Sync requires DC01 to have outbound connectivity (see ADR-004).
- Note: the AD domain uses the `.internal` suffix, reserved for private use, so it can never
  collide with a public domain.

## Revisit when

The lab no longer needs Windows domain telemetry, making a cloud-only identity model sufficient.
