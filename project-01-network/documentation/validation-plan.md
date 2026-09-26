# Validation Plan

Tests to run in Packet Tracer after the topology is built
([build guide](build-guide.md)). Each test names the matrix rule it proves.

> **Status: in progress.** Stage 1 started on 2026-09-26 in Packet Tracer 9.0.1. The "Result" column is filled in only with what is actually observed
> in Packet Tracer. Static verification of the generated ACLs is a separate check (see
> [ACL design](acl-design.md#5-verification)) and is not a substitute for these tests.

## How to run each method

| Method | Where in Packet Tracer |
|---|---|
| **ping** | Click the PC/server → Desktop → Command Prompt → `ping <ip>` |
| **browser** | Desktop → Web Browser → URL such as `https://10.10.80.30` |
| **nslookup** | Command Prompt → `nslookup <name> <dns-server>` |
| **ssh** | JUMP01 → Desktop → Command Prompt → `ssh -l netadmin <ip>` |
| **dhcp** | Desktop → IP Configuration → select DHCP |
| **pdu** | Simulation mode → *Add Complex PDU* (envelope with a gear) → choose source, destination, protocol and destination port → Create PDU → Play. Watch where the packet stops (a red X means dropped). |
| **show** | Device → CLI → the `show` command given |

Record evidence as screenshots in `project-01-network/documentation/evidence/` using the test
ID as the file name (for example `V-01.png`).

## Stage 1 — Connectivity before applying ACLs

Paste the base configurations first and apply the ACL file only after these pass. This separates
routing problems from filtering problems.

| ID | From | Test | Expected | Result |
|---|---|---|---|---|
| C-01 | WS-FIN01 | ping 10.10.20.1 | Replies | **Pass** (2026-09-26): 4/4 replies, TTL=255 |
| C-02 | WS-FIN01 | ping 10.10.80.10 | Replies | **Pass** (2026-09-26): 4/4 replies, TTL=127 (one routed hop through CORE-SW01) |
| C-03 | JUMP01 | ping 10.10.255.6 | Replies | Not executed |
| C-04 | PC-DHCP-TEST | dhcp | Gets 10.10.20.100 or higher, gateway 10.10.20.1 | Not executed |
| C-05 | WS-FIN01 | browser `http://198.51.100.10` | INTERNET-SRV page loads (NAT works) | Not executed |
| C-06 | INTERNET-SRV | browser `https://203.0.113.3` | WEB01 page loads (static NAT) | Not executed |

## Stage 2 — Allowed flows (after pasting the ACLs)

| ID | Rule | From | Test | Expected | Result |
|---|---|---|---|---|---|
| V-01 | NM-020 | WS-FIN01 | browser `https://10.10.80.30` | APP-FIN01 page loads | Not executed |
| V-02 | NM-020 | WS-EXE01 | browser `https://10.10.80.30` | Loads | Not executed |
| V-03 | NM-020 | WS-OPS01 | browser `https://10.10.80.30` | Loads | Not executed |
| V-04 | NM-022 | WS-INV01 | browser `https://10.10.80.40` | APP-INV01 page loads | Not executed |
| V-05 | NM-023 | WS-HR01 | browser `https://10.10.80.50` | APP-HR01 page loads | Not executed |
| V-06 | NM-024 | WS-IR01 | browser `https://10.10.80.60` | APP-CRM01 page loads | Not executed |
| V-07 | NM-025 | WS-DEV01 | browser `https://10.10.80.70` | GIT01 page loads | Not executed |
| V-08 | NM-010 | WS-FIN01 | nslookup `dc01.corp.moretti.internal 10.10.80.10` | Returns 10.10.80.10 | Not executed |
| V-09 | NM-011 | PC-DHCP-TEST | dhcp (renew) | Address from the FINANCE pool | Not executed |
| V-10 | NM-032 | JUMP01 | ssh 10.10.10.1 | CORE-SW01 password prompt | Not executed |
| V-11 | NM-032 | JUMP01 | ssh 10.10.10.11 | ACC-SW01 password prompt | Not executed |
| V-12 | NM-032 | JUMP01 | ssh 10.10.255.2 | FW01 password prompt | Not executed |
| V-13 | NM-032 | JUMP01 | ssh 10.10.255.6 | R-EDGE01 password prompt | Not executed |
| V-14 | NM-080 | WS-IT01 | ping 10.10.80.30 | Replies | Not executed |
| V-15 | NM-028 | SEC-WS01 | ping 10.10.20.10 | Replies | Not executed |
| V-16 | NM-041 | SIEM01 | Services → SYSLOG | Messages from the switches appear | Not executed |
| V-17 | NM-070 | WS-FIN01 | browser `http://198.51.100.10` | Loads | Not executed |
| V-18 | NM-005 | GUEST01 | browser `http://198.51.100.10` | Loads | Not executed |
| V-19 | NM-006 | GUEST01 | nslookup `www.example.org 198.51.100.10` | Returns 198.51.100.10 | Not executed |
| V-20 | NM-001 | INTERNET-SRV | browser `https://203.0.113.3` | WEB01 page loads | Not executed |
| V-21 | NM-040 | WS-FIN01 | pdu TCP dst port 1514 → 10.10.70.10 | Reaches SIEM01 | Not executed |

## Stage 3 — Denied flows

| ID | Rule | From | Test | Expected | Result |
|---|---|---|---|---|---|
| D-01 | NM-026 | WS-DEV01 | browser `https://10.10.80.30` | Fails (request timeout) | Not executed |
| D-02 | default | WS-HR01 | browser `https://10.10.80.30` | Fails | Not executed |
| D-03 | default | WS-EXE01 | browser `https://10.10.80.50` | Fails (HR system is HR only) | Not executed |
| D-04 | NM-060 | WS-HR01 | ping 10.10.20.10 | Fails | Not executed |
| D-05 | NM-060 | WS-DEV01 | pdu TCP 445 → 10.10.20.10 | Dropped at CORE-SW01 | Not executed |
| D-06 | NM-004 | GUEST01 | ping 10.10.20.10 | Fails | Not executed |
| D-07 | NM-004 | GUEST01 | browser `https://10.10.80.30` | Fails | Not executed |
| D-08 | NM-033 | WS-IT01 | ssh 10.10.10.1 | Fails (not from JUMP01) | Not executed |
| D-09 | NM-033 | WS-FIN01 | pdu TCP 3389 → 10.10.80.10 | Dropped at CORE-SW01 | Not executed |
| D-10 | NM-043 | WS-FIN01 | pdu TCP 22 → 10.10.70.10 | Dropped at CORE-SW01 | Not executed |
| D-11 | default | WS-DEV01 | ping 10.10.80.10 | Fails (users cannot map the network with ICMP) | Not executed |
| D-12 | NM-003 | WEB01 | ping 10.10.80.10 | Fails (dropped at FW01) | Not executed |
| D-13 | default | WS-FIN01 | browser `https://172.16.100.10` | Fails (internal hosts do not use the DMZ address) | Not executed |
| D-14 | NM-002 | INTERNET-SRV | ping 10.10.20.10 | Fails (no route to private space) | Not executed |

## Stage 4 — Layer 2 protections

| ID | Control | Test | Expected | Result |
|---|---|---|---|---|
| L-01 | Trunks | ACC-SW01: `show interfaces trunk` | Native VLAN 999; allowed VLANs 10,20,30,100,120; mode `on` | Not executed |
| L-02 | Unused ports | ACC-SW03: `show interfaces status` | Unused ports `disabled`, VLAN 999 | Not executed |
| L-03 | BPDU Guard | Unplug WS-IR01 and connect a new 2960 to ACC-SW02 Fa0/1 | Port goes `err-disabled` | Not executed |
| L-04 | Port security | WS-FIN01 → Config → FastEthernet0 → change the MAC address twice, then ping 10.10.20.1 | ACC-SW01 `show port-security interface fa0/3` shows the violation counter increasing | Not executed |
| L-05 | DHCP snooping | ACC-SW01: `show ip dhcp snooping` | Enabled on VLANs 20,30,100,120; Gi0/1 trusted | Not executed |
| L-06 | STP root | ACC-SW02: `show spanning-tree vlan 40` | Root bridge is CORE-SW01 | Not executed |

After L-03 and L-04, restore the ports: `shutdown`, `no shutdown` on the interface (and
`clear port-security sticky interface fa0/3` for L-04).
