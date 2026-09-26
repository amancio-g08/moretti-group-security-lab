# Addressing Plan

All values derive from [`data/network-matrix.yaml`](../../data/network-matrix.yaml) (segments)
and [`data/assets.yaml`](../../data/assets.yaml) (hosts). If they ever differ, the `data/` files
are correct and this page must be updated.

## 1. Conventions

| Range in each /24 | Use |
|---|---|
| `.1` | Default gateway (SVI on CORE-SW01) |
| `.10` – `.99` | Static: servers, infrastructure, reserved workstation addresses |
| `.100` – `.199` | DHCP pool for user devices |
| `.200` – `.254` | Reserved |

Public addresses use RFC 5737 documentation ranges (`203.0.113.0/24`, `198.51.100.0/24`) so the
lab can never collide with a real network.

## 2. VLANs and subnets

| VLAN | Name | Subnet | Gateway | DHCP | Access switch |
|---|---|---|---|---|---|
| 10 | NET-MGMT | 10.10.10.0/24 | 10.10.10.1 | — (static) | all (management SVIs), SRV-SW01 (JUMP01) |
| 20 | FINANCE | 10.10.20.0/24 | 10.10.20.1 | DC01 (relay) | ACC-SW01 |
| 30 | HR | 10.10.30.0/24 | 10.10.30.1 | DC01 (relay) | ACC-SW01 |
| 40 | INVESTOR-RELATIONS | 10.10.40.0/24 | 10.10.40.1 | DC01 (relay) | ACC-SW02 |
| 50 | DEVELOPMENT | 10.10.50.0/24 | 10.10.50.1 | DC01 (relay) | ACC-SW02 |
| 60 | IT | 10.10.60.0/24 | 10.10.60.1 | DC01 (relay) | ACC-SW03 |
| 70 | SECURITY | 10.10.70.0/24 | 10.10.70.1 | DC01 (relay) | ACC-SW03, SRV-SW01 (SIEM01) |
| 80 | SERVERS | 10.10.80.0/24 | 10.10.80.1 | — (static) | SRV-SW01 |
| 90 | GUEST | 10.10.90.0/24 | 10.10.90.1 | CORE-SW01 (local pool) | ACC-SW02 |
| 100 | EXECUTIVE | 10.10.100.0/24 | 10.10.100.1 | DC01 (relay) | ACC-SW01 |
| 110 | OPERATIONS | 10.10.110.0/24 | 10.10.110.1 | DC01 (relay) | ACC-SW02 |
| 120 | INVESTMENTS | 10.10.120.0/24 | 10.10.120.1 | DC01 (relay) | ACC-SW01 |
| 999 | BLACKHOLE | — | — | — | native VLAN and unused ports everywhere |

## 3. Routed links and public addressing

| Link | Network | Addresses |
|---|---|---|
| CORE-SW01 Gi1/0/24 ↔ FW01 Gi1/2 (inside) | 10.10.255.0/30 | .1 core, .2 FW01 |
| FW01 Gi1/1 (outside) ↔ R-EDGE01 Gi0/0/0 | 10.10.255.4/30 | .5 FW01, .6 R-EDGE01 |
| FW01 Gi1/3 (dmz) ↔ WEB01 | 172.16.100.0/24 | .1 FW01, .10 WEB01 |
| R-EDGE01 Gi0/0/1 ↔ ISP-SIM Gi0/0/0 | 203.0.113.0/29 | .1 ISP-SIM, .2 R-EDGE01, .3 WEB01 (static NAT) |
| ISP-SIM Gi0/0/1 ↔ INTERNET-SRV | 198.51.100.0/24 | .1 ISP-SIM, .10 INTERNET-SRV |

## 4. Network device management addresses

| Device | Management IP | Reachable via SSH from |
|---|---|---|
| CORE-SW01 | 10.10.10.1 (and every SVI) | JUMP01 only |
| ACC-SW01 | 10.10.10.11 | JUMP01 only |
| ACC-SW02 | 10.10.10.12 | JUMP01 only |
| ACC-SW03 | 10.10.10.13 | JUMP01 only |
| SRV-SW01 | 10.10.10.14 | JUMP01 only |
| FW01 | 10.10.255.2 (inside) | JUMP01 only |
| R-EDGE01 | 10.10.255.6 | JUMP01 only |

## 5. Hosts in the Packet Tracer topology

| Host | IP | Gateway | DNS | Switch port |
|---|---|---|---|---|
| WS-EXE01 | 10.10.100.10 | 10.10.100.1 | 10.10.80.10 | ACC-SW01 Fa0/1 |
| WS-INV01 | 10.10.120.10 | 10.10.120.1 | 10.10.80.10 | ACC-SW01 Fa0/2 |
| WS-FIN01 | 10.10.20.10 | 10.10.20.1 | 10.10.80.10 | ACC-SW01 Fa0/3 |
| PC-DHCP-TEST | DHCP (10.10.20.100+) | from DHCP | from DHCP | ACC-SW01 Fa0/4 |
| WS-HR01 | 10.10.30.10 | 10.10.30.1 | 10.10.80.10 | ACC-SW01 Fa0/5 |
| WS-IR01 | 10.10.40.10 | 10.10.40.1 | 10.10.80.10 | ACC-SW02 Fa0/1 |
| WS-OPS01 | 10.10.110.10 | 10.10.110.1 | 10.10.80.10 | ACC-SW02 Fa0/2 |
| WS-DEV01 | 10.10.50.10 | 10.10.50.1 | 10.10.80.10 | ACC-SW02 Fa0/3 |
| GUEST01 | 10.10.90.10 | 10.10.90.1 | 198.51.100.10 | ACC-SW02 Fa0/4 |
| WS-IT01 | 10.10.60.10 | 10.10.60.1 | 10.10.80.10 | ACC-SW03 Fa0/1 |
| SEC-WS01 | 10.10.70.20 | 10.10.70.1 | 10.10.80.10 | ACC-SW03 Fa0/2 |
| DC01 | 10.10.80.10 | 10.10.80.1 | 10.10.80.10 (itself) | SRV-SW01 Fa0/1 |
| DC02 | 10.10.80.11 | 10.10.80.1 | 10.10.80.10 | SRV-SW01 Fa0/2 |
| FS01 | 10.10.80.20 | 10.10.80.1 | 10.10.80.10 | SRV-SW01 Fa0/3 |
| APP-FIN01 | 10.10.80.30 | 10.10.80.1 | 10.10.80.10 | SRV-SW01 Fa0/4 |
| DB-FIN01 | 10.10.80.31 | 10.10.80.1 | 10.10.80.10 | SRV-SW01 Fa0/5 |
| APP-INV01 | 10.10.80.40 | 10.10.80.1 | 10.10.80.10 | SRV-SW01 Fa0/6 |
| APP-HR01 | 10.10.80.50 | 10.10.80.1 | 10.10.80.10 | SRV-SW01 Fa0/7 |
| APP-CRM01 | 10.10.80.60 | 10.10.80.1 | 10.10.80.10 | SRV-SW01 Fa0/8 |
| GIT01 | 10.10.80.70 | 10.10.80.1 | 10.10.80.10 | SRV-SW01 Fa0/9 |
| BKP01 | 10.10.80.90 | 10.10.80.1 | 10.10.80.10 | SRV-SW01 Fa0/10 |
| SIEM01 | 10.10.70.10 | 10.10.70.1 | 10.10.80.10 | SRV-SW01 Fa0/20 |
| JUMP01 | 10.10.10.20 | 10.10.10.1 | 10.10.80.10 | SRV-SW01 Fa0/24 |
| WEB01 | 172.16.100.10 | 172.16.100.1 | — (DMZ has no outbound access) | FW01 Gi1/3 |
| INTERNET-SRV | 198.51.100.10 | 198.51.100.1 | itself | ISP-SIM Gi0/0/1 |

`PC-DHCP-TEST` and `INTERNET-SRV` are test fixtures of the simulation, not company assets.

## 6. DHCP pools on DC01

Configured in the DC01 server's DHCP service in Packet Tracer (build guide, step 7). The core
relays requests with `ip helper-address 10.10.80.10`.

| Pool name | Default gateway | DNS | Start IP | Mask | Max users |
|---|---|---|---|---|---|
| FINANCE | 10.10.20.1 | 10.10.80.10 | 10.10.20.100 | 255.255.255.0 | 100 |
| HR | 10.10.30.1 | 10.10.80.10 | 10.10.30.100 | 255.255.255.0 | 100 |
| INVESTOR-RELATIONS | 10.10.40.1 | 10.10.80.10 | 10.10.40.100 | 255.255.255.0 | 100 |
| DEVELOPMENT | 10.10.50.1 | 10.10.80.10 | 10.10.50.100 | 255.255.255.0 | 100 |
| IT | 10.10.60.1 | 10.10.80.10 | 10.10.60.100 | 255.255.255.0 | 100 |
| SECURITY | 10.10.70.1 | 10.10.80.10 | 10.10.70.100 | 255.255.255.0 | 100 |
| EXECUTIVE | 10.10.100.1 | 10.10.80.10 | 10.10.100.100 | 255.255.255.0 | 100 |
| OPERATIONS | 10.10.110.1 | 10.10.80.10 | 10.10.110.100 | 255.255.255.0 | 100 |
| INVESTMENTS | 10.10.120.1 | 10.10.80.10 | 10.10.120.100 | 255.255.255.0 | 100 |
