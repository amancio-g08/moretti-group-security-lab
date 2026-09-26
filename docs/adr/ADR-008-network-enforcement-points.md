# ADR-008: Network enforcement points in the enterprise design

- **Status:** Proposed
- **Date:** 2026-09-26
- **Related:** ADR-001, ADR-005

## Context

The communication matrix (`data/network-matrix.yaml`) must be enforced somewhere in the Packet
Tracer design. Three kinds of traffic exist: between internal VLANs (east-west), between the
organization and the internet or DMZ (north-south), and address translation towards the internet.
Packet Tracer's device models constrain the options: the Catalyst 3650 routes between VLANs and
supports extended ACLs but is stateless; the ASA 5506-X is stateful but has a reduced feature set
in the simulator.

## Options considered

| Option | Pros | Cons |
|---|---|---|
| A. Route every VLAN through the ASA (ASA as the only enforcement point) | Stateful everywhere; one rule base | All east-west traffic hairpins through one device; subinterface support in the simulated ASA is limited; the ASA becomes a bottleneck and single point of failure |
| B. Inter-VLAN routing and ACLs on the core switch; ASA at the perimeter; NAT on the edge router | Each device does what it is designed for; east-west filtering close to the source; ASA rule base stays small | Core ACLs are stateless; return traffic must be permitted explicitly |
| C. Router-on-a-stick with ACLs | Simple | Single router link carries all inter-VLAN traffic; also stateless |

## Decision

Option B.

| Enforcement point | Traffic | Mechanism |
|---|---|---|
| CORE-SW01 | Between internal VLANs, and towards the core itself | One inbound extended ACL per SVI, **generated** from the matrix |
| FW01 (ASA) | Internal ↔ internet, DMZ ↔ anything | Stateful ACLs on every interface |
| R-EDGE01 | Internet edge | NAT (PAT for users, static for WEB01) and anti-spoofing |
| Access switches | Layer 2 | Port security, DHCP snooping, BPDU Guard, no DTP |

## Rationale

- Filtering at the source VLAN's SVI stops unwanted traffic at the first routed hop.
- Generating the ACLs from the matrix (`project-01-network/tools/render_core_acls.py`) keeps the
  policy and the implementation in sync (ADR-001), and a static verifier checks every generated
  ACL against the matrix before commit.
- NAT on the edge router lets the ASA see real internal addresses, so its rules and logs
  reference the actual hosts.

## Consequences

- Positive: realistic layered design; small, reviewable ASA rule base; verifiable ACLs.
- Negative: stateless core ACLs need explicit return-traffic entries (TCP `established`, UDP
  from the service port, ICMP echo-reply). Known limitations are listed in
  `project-01-network/documentation/acl-design.md`.
- Negative: traffic between hosts in the same VLAN is not filtered (no routing hop). In AWS,
  Security Groups apply per instance, so the cloud lab does filter within a subnet.
- Negative: Packet Tracer does not support the `log` keyword on these ACLs; denied traffic is
  visible in Simulation mode but not in syslog.

## Revisit when

A stateful internal firewall or a zone-based firewall becomes available in the simulator, or the
design moves to a platform that supports it.
