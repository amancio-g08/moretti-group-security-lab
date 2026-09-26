# ADR-005: Packet Tracer is the enterprise design; AWS is the operational lab

- **Status:** Proposed
- **Date:** 2026-09-26
- **Related:** ADR-001, ADR-007

## Context

The company network is designed in Cisco Packet Tracer: VLANs, inter-VLAN routing, ACLs, a
perimeter firewall, DMZ and device hardening. The lab also needs real hosts producing logs and
traffic, which Packet Tracer cannot provide — it is a simulator, and it cannot export captures
that Wireshark can open.

A tempting approach is to reproduce the Packet Tracer LAN in AWS. That approach is costly,
technically awkward (AWS has no VLANs, switches or broadcast domains) and conceptually wrong:
cloud networks are secured with different primitives.

## Options considered

| Option | Pros | Cons |
|---|---|---|
| A. Replicate the full LAN in AWS | Visual one-to-one mapping | High cost; emulating L2 concepts in a VPC is artificial; many hosts to operate |
| B. Packet Tracer only | Free | No real logs, traffic or identity events |
| C. Packet Tracer for full enterprise design; AWS for a minimal operational lab; both enforce the same policy | Each environment uses its native controls; low cost | The two environments do not match host-for-host |

## Decision

Option C.

- **Packet Tracer = Enterprise Network Design** — the complete corporate LAN.
- **AWS = Cloud Security Implementation** — the minimum hosts needed to produce real evidence.
- Both implement the **same communication policy** from `network-matrix.yaml`.

## Rationale

Security policy is independent of the environment; controls are not. Expressing the policy once
and translating it into VLAN ACLs on-premises and Security Groups in the cloud mirrors how real
hybrid organizations work. In the owner's words: *"I didn't try to physically reproduce the LAN in
the cloud. I kept a single communication policy and implemented the appropriate controls for each
environment."*

## Consequences

- Positive: realistic hybrid narrative; low cost; each environment is used for what it does well.
- Negative: control semantics differ and must be documented:
  - ACLs are stateless and support explicit deny; Security Groups are stateful and allow-only.
    A DENY in the matrix becomes the absence of an allow rule in AWS (or a Network ACL where an
    explicit deny is required).
  - Some flows exist in only one environment (for example, SSH to switches). Each matrix rule
    therefore has an `applies_to` field.
- Follow-up: the Python toolkit renders and validates both translations (Phase 3).

## Revisit when

The lab adds a physical or virtualized router/firewall appliance (for example, a cloud firewall
VM) that would allow like-for-like enforcement.
