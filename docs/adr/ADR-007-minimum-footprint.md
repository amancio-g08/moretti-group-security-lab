# ADR-007: Minimum VM footprint, grown per phase

- **Status:** Accepted
- **Date:** 2026-09-26
- **Related:** ADR-003, ADR-004, ADR-005

## Context

The enterprise design contains many servers and workstations. Running all of them in AWS would
raise cost and make troubleshooting harder, while most scenarios only need a few hosts.

## Options considered

| Option | Pros | Cons |
|---|---|---|
| A. Deploy every designed asset | Closest to the design | Highest cost; more to patch, enroll and debug |
| B. Deploy the minimum set, add hosts when a phase needs them | Lower cost; smaller blast radius when troubleshooting | Some designed assets exist only in Packet Tracer |

## Decision

Option B. Initial AWS footprint:

| Host | Segment | Purpose |
|---|---|---|
| DC01 | SERVERS (80) | Active Directory, DNS — identity and authentication events |
| SIEM01 | SECURITY (70) | Wazuh manager, indexer and dashboard |
| WS-FIN01 | FINANCE (20) | Windows workstation — high-value user segment |
| WS-DEV01 | DEVELOPMENT (50) | Linux workstation |
| GUEST01 | GUEST (90) | Untrusted host / simulated attacker for in-scope scenarios |

Added later:

| Host | When | Why |
|---|---|---|
| APP-FIN01 | Phase 7 (scenarios) | Target for finance-system and file-integrity scenarios |
| SEC-WS01 | Only if needed | PCAP analysis runs on the operator's workstation instead |

## Rationale

Five hosts cover identity, detection, a Windows endpoint, a Linux endpoint and an untrusted
source — enough for every planned scenario except those requiring the finance application.

## Consequences

- Positive: lower cost; faster deploys; simpler troubleshooting.
- Negative: captures are taken on the hosts themselves (`tcpdump` on Linux, `pktmon` on Windows)
  and copied to the operator's workstation for analysis.
- Negative: instance sizes are validated during Phase 6 (Wazuh's official sizing guidance may
  exceed the initial instance size); any change is recorded.

## Revisit when

A scenario requires a host that is not deployed, or Wazuh performance is insufficient at the
chosen instance size.
