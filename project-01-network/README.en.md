# Project 01 — Enterprise Network (Packet Tracer)

[Português](README.md) | **English**

The complete Moretti Group network designed in Cisco Packet Tracer: 12 VLANs, inter-VLAN routing
on the core switch, an ASA perimeter firewall with a DMZ, NAT at the edge router and device
hardening. Everything follows [`data/network-matrix.yaml`](../data/network-matrix.yaml).

**Status:** configurations and documentation ready; building the topology in Packet Tracer and
running the tests are still pending.

## Contents

| Path | Content |
|---|---|
| [`configs/`](configs/) | Per-device configuration, ready to paste |
| [`configs/generated/CORE-SW01-acls.txt`](configs/generated/CORE-SW01-acls.txt) | Inter-VLAN ACLs, **generated** from the matrix (do not edit by hand) |
| [`tools/render_core_acls.py`](tools/render_core_acls.py) | Generates the core ACLs from the matrix |
| [`tools/verify_core_acls.py`](tools/verify_core_acls.py) | Checks that the generated ACLs do exactly what the matrix says |
| [`documentation/build-guide.md`](documentation/build-guide.md) | Step-by-step build in Packet Tracer |
| [`documentation/addressing-plan.md`](documentation/addressing-plan.md) | VLANs, IPs, ports and DHCP pools |
| [`documentation/acl-design.md`](documentation/acl-design.md) | How the matrix becomes ACLs, and the limits of stateless ACLs |
| [`documentation/hardening.md`](documentation/hardening.md) | Device protections, Layer 2 attacks and known gaps |
| [`documentation/validation-plan.md`](documentation/validation-plan.md) | Tests to run in Packet Tracer |
| `packet-tracer/` | Where the `.pkt` file goes once built |

## Why the ACLs are generated

The core switch ACLs are not written by hand. A script reads the communication matrix and
produces one ACL per VLAN, and a second script evaluates every source, destination and port
combination to confirm the ACL decides exactly as the matrix does. If the matrix changes and the
ACLs are not regenerated, `pre-commit` blocks the commit.

```bash
python3 project-01-network/tools/render_core_acls.py --write   # regenerate
python3 project-01-network/tools/verify_core_acls.py           # must report 0 mismatches
```

This is static analysis of the configuration text. It does not replace the tests in Packet
Tracer, which are in the validation plan.

## Where each kind of traffic is enforced

| Traffic | Enforced by |
|---|---|
| Between internal VLANs | Core switch (CORE-SW01), inbound ACL on each VLAN |
| Internal ↔ internet | Core and firewall (FW01) |
| Internet → DMZ / internal | Firewall and anti-spoofing on the edge router (R-EDGE01) |
| Within one VLAN | Nothing (no routing hop) — in AWS, Security Groups cover this |

Decision record: [ADR-008](../docs/adr/ADR-008-network-enforcement-points.md).
