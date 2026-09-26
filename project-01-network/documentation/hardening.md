# Network Hardening and Attack Surface

What protects the network devices themselves and the Layer 2 fabric, which attacks each measure
addresses, and what the lab does **not** cover. Packet Tracer supports a subset of IOS; where a
feature could not be relied on in the simulator, that is stated.

## 1. Management plane

| Control | Configuration | Why |
|---|---|---|
| SSH v2 only, no Telnet | `transport input ssh`, `ip ssh version 2` | Telnet sends credentials in clear text |
| Management only from JUMP01 | `access-class ACL-VTY-MGMT in` (IOS), `ssh 10.10.10.20 ... inside` (ASA) | Administration has one controlled origin (NM-032) |
| Local accounts with privilege 15, `enable secret` | Set manually, never stored in Git | Individual accountability; secrets stay out of the repository |
| Brute-force protection | `login block-for 120 attempts 3 within 60` | Slows password guessing against SSH |
| Idle timeouts | `exec-timeout 5 0` (console), `10 0` (VTY) | Abandoned sessions close |
| No web management | `no ip http server`, `no ip http secure-server` | Removes an unneeded service |
| Password encryption | `service password-encryption` | Avoids shoulder-surfing of type 7 passwords in configs (not real protection; secrets use `secret`) |
| Legal banner | `banner motd` | States that access is restricted and logged |
| Central logging | `logging host 10.10.70.10` | Device events reach the SIEM (NM-041) |
| Time synchronization | `ntp server 10.10.80.10` | Comparable timestamps across logs (NM-012) |

## 2. Layer 2 attacks and mitigations

| Attack | How it works | Mitigation in this design | Where |
|---|---|---|---|
| Switch spoofing (VLAN hopping via DTP) | A host negotiates a trunk and reaches every VLAN | Access ports forced to `switchport mode access`; trunks use `switchport nonegotiate` | All switches |
| Double tagging (VLAN hopping) | A frame with two 802.1Q tags on the native VLAN reaches another VLAN | Native VLAN is 999, which carries no users; VLAN 1 unused | All trunks |
| Rogue switch / STP root takeover | A device sends superior BPDUs and becomes root | BPDU Guard on every access port; CORE-SW01 is `root primary` for all VLANs | Access ports, core |
| MAC flooding | CAM table filled so the switch floods frames | Port security: max 2 MACs per port, `violation restrict` | Access ports |
| Unauthorized device on a port | Someone plugs in a personal device | Port security with sticky MACs | Access ports |
| Rogue DHCP server | A host answers DHCP and redirects traffic | DHCP snooping; only uplinks (and DC01's port) are trusted | All access switches |
| DHCP starvation | Pool exhausted with fake requests | Port security limits MACs per port (partial mitigation) | Access ports |
| Reconnaissance via CDP | Device model and IOS version disclosed to end hosts | `no cdp enable` on access ports | Access ports |
| Unused ports | An open port is an entry point | Shut down and placed in VLAN 999 | All switches |
| ARP spoofing | Host impersonates the gateway | **Not mitigated in this lab**: Dynamic ARP Inspection was not configured because its support in the Packet Tracer 2960 is not guaranteed | Gap (see §4) |

## 3. Perimeter

| Control | Where | Why |
|---|---|---|
| Stateful filtering with an ACL on every interface | FW01 | Nothing relies on the implicit "higher to lower security level" rule |
| Internal hosts cannot initiate to the DMZ | FW01 `INSIDE_IN` | Only the internet needs the website |
| The DMZ cannot initiate anything | FW01 `DMZ_IN` | A compromised web server has no path inward or outward (NM-003) |
| Anti-spoofing | R-EDGE01 `ACL-INTERNET-IN` | Private, loopback and our own addresses never arrive from the internet |
| NAT at the edge | R-EDGE01 | Internal addressing is not exposed; FW01 logs real internal addresses |

## 4. Known gaps

| Gap | Risk | Production mitigation |
|---|---|---|
| No Dynamic ARP Inspection | ARP spoofing / man-in-the-middle inside a VLAN | DAI bound to DHCP snooping |
| No 802.1X | Any device on an enabled port gets network access (limited by port security) | 802.1X / NAC |
| No IP Source Guard | IP spoofing inside a VLAN | IP Source Guard |
| Local accounts instead of AAA server | No central account lifecycle for network admins | TACACS+/RADIUS bound to AD groups (`priv-network-admin`) |
| No ACL logging | Denied flows not in the SIEM | `log` on DENY entries |
| Single core, single firewall | No redundancy | Redundant core (StackWise/VSS), ASA failover pair |
