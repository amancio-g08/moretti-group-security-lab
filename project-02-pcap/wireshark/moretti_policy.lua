-- GENERATED from data/network-matrix.yaml and data/assets.yaml by
-- project-02-pcap/tools/render_wireshark_policy.py. Do not edit.
return {
  default_action = "deny",
  segments = {
    { id = "mgmt", net = "10.10.10.0", bits = 24 },
    { id = "finance", net = "10.10.20.0", bits = 24 },
    { id = "hr", net = "10.10.30.0", bits = 24 },
    { id = "investor-relations", net = "10.10.40.0", bits = 24 },
    { id = "development", net = "10.10.50.0", bits = 24 },
    { id = "it", net = "10.10.60.0", bits = 24 },
    { id = "security", net = "10.10.70.0", bits = 24 },
    { id = "servers", net = "10.10.80.0", bits = 24 },
    { id = "guest", net = "10.10.90.0", bits = 24 },
    { id = "executive", net = "10.10.100.0", bits = 24 },
    { id = "operations", net = "10.10.110.0", bits = 24 },
    { id = "investments", net = "10.10.120.0", bits = 24 },
    { id = "dmz", net = "172.16.100.0", bits = 24 },
    { id = "transit", net = "10.10.255.0", bits = 24 },
  },
  assets = {
    { id = "CORE-SW01", ip = "10.10.10.1", segment = "mgmt" },
    { id = "ACC-SW01", ip = "10.10.10.11", segment = "mgmt" },
    { id = "ACC-SW02", ip = "10.10.10.12", segment = "mgmt" },
    { id = "ACC-SW03", ip = "10.10.10.13", segment = "mgmt" },
    { id = "SRV-SW01", ip = "10.10.10.14", segment = "mgmt" },
    { id = "JUMP01", ip = "10.10.10.20", segment = "mgmt" },
    { id = "WS-FIN01", ip = "10.10.20.10", segment = "finance" },
    { id = "WS-HR01", ip = "10.10.30.10", segment = "hr" },
    { id = "WS-IR01", ip = "10.10.40.10", segment = "investor-relations" },
    { id = "WS-DEV01", ip = "10.10.50.10", segment = "development" },
    { id = "WS-IT01", ip = "10.10.60.10", segment = "it" },
    { id = "SIEM01", ip = "10.10.70.10", segment = "security" },
    { id = "SEC-WS01", ip = "10.10.70.20", segment = "security" },
    { id = "DC01", ip = "10.10.80.10", segment = "servers" },
    { id = "DC02", ip = "10.10.80.11", segment = "servers" },
    { id = "FS01", ip = "10.10.80.20", segment = "servers" },
    { id = "APP-FIN01", ip = "10.10.80.30", segment = "servers" },
    { id = "DB-FIN01", ip = "10.10.80.31", segment = "servers" },
    { id = "APP-INV01", ip = "10.10.80.40", segment = "servers" },
    { id = "APP-HR01", ip = "10.10.80.50", segment = "servers" },
    { id = "APP-CRM01", ip = "10.10.80.60", segment = "servers" },
    { id = "GIT01", ip = "10.10.80.70", segment = "servers" },
    { id = "BKP01", ip = "10.10.80.90", segment = "servers" },
    { id = "GUEST01", ip = "10.10.90.10", segment = "guest" },
    { id = "WS-EXE01", ip = "10.10.100.10", segment = "executive" },
    { id = "WS-OPS01", ip = "10.10.110.10", segment = "operations" },
    { id = "WS-INV01", ip = "10.10.120.10", segment = "investments" },
    { id = "FW01", ip = "10.10.255.2", segment = "transit" },
    { id = "R-EDGE01", ip = "10.10.255.6", segment = "transit" },
    { id = "WEB01", ip = "172.16.100.10", segment = "dmz" },
  },
  rules = {
    pt = {
      {
        id = "NM-001",
        action = "allow",
        src = {
          { internet = true },
        },
        dst = {
          { net = "172.16.100.10", bits = 32 },
        },
        ports = {
          { proto = "tcp", lo = 443, hi = 443 },
        },
      },
      {
        id = "NM-002",
        action = "deny",
        src = {
          { internet = true },
        },
        dst = {
          { net = "10.10.10.0", bits = 24 },
          { net = "10.10.100.0", bits = 24 },
          { net = "10.10.120.0", bits = 24 },
          { net = "10.10.20.0", bits = 24 },
          { net = "10.10.40.0", bits = 24 },
          { net = "10.10.110.0", bits = 24 },
          { net = "10.10.30.0", bits = 24 },
          { net = "10.10.50.0", bits = 24 },
          { net = "10.10.60.0", bits = 24 },
          { net = "10.10.70.0", bits = 24 },
          { net = "10.10.80.0", bits = 24 },
          { net = "10.10.90.0", bits = 24 },
        },
        ports = {
          { proto = "any", lo = 0, hi = 65535 },
        },
      },
      {
        id = "NM-003",
        action = "deny",
        src = {
          { net = "172.16.100.0", bits = 24 },
        },
        dst = {
          { net = "10.10.10.0", bits = 24 },
          { net = "10.10.100.0", bits = 24 },
          { net = "10.10.120.0", bits = 24 },
          { net = "10.10.20.0", bits = 24 },
          { net = "10.10.40.0", bits = 24 },
          { net = "10.10.110.0", bits = 24 },
          { net = "10.10.30.0", bits = 24 },
          { net = "10.10.50.0", bits = 24 },
          { net = "10.10.60.0", bits = 24 },
          { net = "10.10.70.0", bits = 24 },
          { net = "10.10.80.0", bits = 24 },
        },
        ports = {
          { proto = "any", lo = 0, hi = 65535 },
        },
      },
      {
        id = "NM-004",
        action = "deny",
        src = {
          { net = "10.10.90.0", bits = 24 },
        },
        dst = {
          { net = "10.10.10.0", bits = 24 },
          { net = "10.10.100.0", bits = 24 },
          { net = "10.10.120.0", bits = 24 },
          { net = "10.10.20.0", bits = 24 },
          { net = "10.10.40.0", bits = 24 },
          { net = "10.10.110.0", bits = 24 },
          { net = "10.10.30.0", bits = 24 },
          { net = "10.10.50.0", bits = 24 },
          { net = "10.10.60.0", bits = 24 },
          { net = "10.10.70.0", bits = 24 },
          { net = "10.10.80.0", bits = 24 },
          { net = "172.16.100.0", bits = 24 },
        },
        ports = {
          { proto = "any", lo = 0, hi = 65535 },
        },
      },
      {
        id = "NM-005",
        action = "allow",
        src = {
          { net = "10.10.90.0", bits = 24 },
        },
        dst = {
          { internet = true },
        },
        ports = {
          { proto = "tcp", lo = 80, hi = 80 },
          { proto = "tcp", lo = 443, hi = 443 },
        },
      },
      {
        id = "NM-006",
        action = "allow",
        src = {
          { net = "10.10.90.0", bits = 24 },
        },
        dst = {
          { internet = true },
        },
        ports = {
          { proto = "udp", lo = 53, hi = 53 },
          { proto = "tcp", lo = 53, hi = 53 },
        },
      },
      {
        id = "NM-010",
        action = "allow",
        src = {
          { net = "10.10.100.0", bits = 24 },
          { net = "10.10.120.0", bits = 24 },
          { net = "10.10.20.0", bits = 24 },
          { net = "10.10.40.0", bits = 24 },
          { net = "10.10.110.0", bits = 24 },
          { net = "10.10.30.0", bits = 24 },
          { net = "10.10.50.0", bits = 24 },
          { net = "10.10.60.0", bits = 24 },
          { net = "10.10.70.0", bits = 24 },
          { net = "10.10.80.0", bits = 24 },
          { net = "10.10.10.0", bits = 24 },
        },
        dst = {
          { net = "10.10.80.10", bits = 32 },
          { net = "10.10.80.11", bits = 32 },
        },
        ports = {
          { proto = "tcp", lo = 53, hi = 53 },
          { proto = "udp", lo = 53, hi = 53 },
          { proto = "tcp", lo = 88, hi = 88 },
          { proto = "udp", lo = 88, hi = 88 },
          { proto = "tcp", lo = 135, hi = 135 },
          { proto = "tcp", lo = 389, hi = 389 },
          { proto = "udp", lo = 389, hi = 389 },
          { proto = "tcp", lo = 445, hi = 445 },
          { proto = "tcp", lo = 464, hi = 464 },
          { proto = "udp", lo = 464, hi = 464 },
          { proto = "tcp", lo = 636, hi = 636 },
          { proto = "tcp", lo = 3268, hi = 3269 },
          { proto = "udp", lo = 123, hi = 123 },
          { proto = "tcp", lo = 49152, hi = 65535 },
        },
      },
      {
        id = "NM-011",
        action = "allow",
        src = {
          { net = "10.10.100.0", bits = 24 },
          { net = "10.10.120.0", bits = 24 },
          { net = "10.10.20.0", bits = 24 },
          { net = "10.10.40.0", bits = 24 },
          { net = "10.10.110.0", bits = 24 },
          { net = "10.10.30.0", bits = 24 },
          { net = "10.10.50.0", bits = 24 },
          { net = "10.10.60.0", bits = 24 },
          { net = "10.10.70.0", bits = 24 },
        },
        dst = {
          { net = "10.10.80.10", bits = 32 },
        },
        ports = {
          { proto = "udp", lo = 67, hi = 67 },
        },
      },
      {
        id = "NM-012",
        action = "allow",
        src = {
          { net = "10.10.10.0", bits = 24 },
          { net = "10.10.255.0", bits = 24 },
        },
        dst = {
          { net = "10.10.80.10", bits = 32 },
        },
        ports = {
          { proto = "udp", lo = 123, hi = 123 },
        },
      },
      {
        id = "NM-013",
        action = "allow",
        src = {
          { net = "10.10.80.10", bits = 32 },
          { net = "10.10.80.11", bits = 32 },
        },
        dst = {
          { internet = true },
        },
        ports = {
          { proto = "udp", lo = 53, hi = 53 },
          { proto = "tcp", lo = 53, hi = 53 },
        },
      },
      {
        id = "NM-020",
        action = "allow",
        src = {
          { net = "10.10.20.0", bits = 24 },
          { net = "10.10.100.0", bits = 24 },
          { net = "10.10.110.0", bits = 24 },
        },
        dst = {
          { net = "10.10.80.30", bits = 32 },
        },
        ports = {
          { proto = "tcp", lo = 443, hi = 443 },
        },
      },
      {
        id = "NM-021",
        action = "allow",
        src = {
          { net = "10.10.80.30", bits = 32 },
        },
        dst = {
          { net = "10.10.80.31", bits = 32 },
        },
        ports = {
          { proto = "tcp", lo = 5432, hi = 5432 },
        },
      },
      {
        id = "NM-022",
        action = "allow",
        src = {
          { net = "10.10.120.0", bits = 24 },
          { net = "10.10.100.0", bits = 24 },
        },
        dst = {
          { net = "10.10.80.40", bits = 32 },
        },
        ports = {
          { proto = "tcp", lo = 443, hi = 443 },
        },
      },
      {
        id = "NM-023",
        action = "allow",
        src = {
          { net = "10.10.30.0", bits = 24 },
        },
        dst = {
          { net = "10.10.80.50", bits = 32 },
        },
        ports = {
          { proto = "tcp", lo = 443, hi = 443 },
        },
      },
      {
        id = "NM-024",
        action = "allow",
        src = {
          { net = "10.10.40.0", bits = 24 },
          { net = "10.10.100.0", bits = 24 },
        },
        dst = {
          { net = "10.10.80.60", bits = 32 },
        },
        ports = {
          { proto = "tcp", lo = 443, hi = 443 },
        },
      },
      {
        id = "NM-025",
        action = "allow",
        src = {
          { net = "10.10.50.0", bits = 24 },
        },
        dst = {
          { net = "10.10.80.70", bits = 32 },
        },
        ports = {
          { proto = "tcp", lo = 443, hi = 443 },
          { proto = "tcp", lo = 22, hi = 22 },
        },
      },
      {
        id = "NM-026",
        action = "deny",
        src = {
          { net = "10.10.50.0", bits = 24 },
        },
        dst = {
          { net = "10.10.80.30", bits = 32 },
          { net = "10.10.80.31", bits = 32 },
          { net = "10.10.80.40", bits = 32 },
          { net = "10.10.80.50", bits = 32 },
          { net = "10.10.80.60", bits = 32 },
        },
        ports = {
          { proto = "any", lo = 0, hi = 65535 },
        },
      },
      {
        id = "NM-027",
        action = "allow",
        src = {
          { net = "10.10.100.0", bits = 24 },
          { net = "10.10.120.0", bits = 24 },
          { net = "10.10.20.0", bits = 24 },
          { net = "10.10.40.0", bits = 24 },
          { net = "10.10.110.0", bits = 24 },
          { net = "10.10.30.0", bits = 24 },
          { net = "10.10.50.0", bits = 24 },
          { net = "10.10.60.0", bits = 24 },
          { net = "10.10.70.0", bits = 24 },
        },
        dst = {
          { net = "10.10.80.20", bits = 32 },
        },
        ports = {
          { proto = "tcp", lo = 445, hi = 445 },
        },
      },
      {
        id = "NM-028",
        action = "allow",
        src = {
          { net = "10.10.70.20", bits = 32 },
        },
        dst = {
          { net = "10.10.10.0", bits = 24 },
          { net = "10.10.100.0", bits = 24 },
          { net = "10.10.120.0", bits = 24 },
          { net = "10.10.20.0", bits = 24 },
          { net = "10.10.40.0", bits = 24 },
          { net = "10.10.110.0", bits = 24 },
          { net = "10.10.30.0", bits = 24 },
          { net = "10.10.50.0", bits = 24 },
          { net = "10.10.60.0", bits = 24 },
          { net = "10.10.70.0", bits = 24 },
          { net = "10.10.80.0", bits = 24 },
        },
        ports = {
          { proto = "any", lo = 0, hi = 65535 },
        },
      },
      {
        id = "NM-030",
        action = "allow",
        src = {
          { net = "10.10.60.0", bits = 24 },
          { net = "10.10.70.0", bits = 24 },
        },
        dst = {
          { net = "10.10.10.20", bits = 32 },
        },
        ports = {
          { proto = "tcp", lo = 3389, hi = 3389 },
        },
      },
      {
        id = "NM-031",
        action = "allow",
        src = {
          { net = "10.10.10.20", bits = 32 },
        },
        dst = {
          { net = "10.10.80.0", bits = 24 },
          { net = "10.10.70.0", bits = 24 },
        },
        ports = {
          { proto = "tcp", lo = 3389, hi = 3389 },
          { proto = "tcp", lo = 22, hi = 22 },
          { proto = "tcp", lo = 5985, hi = 5986 },
        },
      },
      {
        id = "NM-032",
        action = "allow",
        src = {
          { net = "10.10.10.20", bits = 32 },
        },
        dst = {
          { net = "10.10.10.0", bits = 24 },
          { net = "10.10.255.0", bits = 24 },
        },
        ports = {
          { proto = "tcp", lo = 22, hi = 22 },
        },
      },
      {
        id = "NM-033",
        action = "deny",
        src = {
          { net = "10.10.100.0", bits = 24 },
          { net = "10.10.120.0", bits = 24 },
          { net = "10.10.20.0", bits = 24 },
          { net = "10.10.40.0", bits = 24 },
          { net = "10.10.110.0", bits = 24 },
          { net = "10.10.30.0", bits = 24 },
          { net = "10.10.50.0", bits = 24 },
          { net = "10.10.60.0", bits = 24 },
          { net = "10.10.70.0", bits = 24 },
          { net = "10.10.90.0", bits = 24 },
        },
        dst = {
          { net = "10.10.80.0", bits = 24 },
          { net = "10.10.70.0", bits = 24 },
          { net = "10.10.10.0", bits = 24 },
          { net = "10.10.255.0", bits = 24 },
        },
        ports = {
          { proto = "tcp", lo = 3389, hi = 3389 },
          { proto = "tcp", lo = 22, hi = 22 },
          { proto = "tcp", lo = 5985, hi = 5986 },
        },
      },
      {
        id = "NM-034",
        action = "allow",
        src = {
          { net = "10.10.60.0", bits = 24 },
        },
        dst = {
          { net = "10.10.100.0", bits = 24 },
          { net = "10.10.120.0", bits = 24 },
          { net = "10.10.20.0", bits = 24 },
          { net = "10.10.40.0", bits = 24 },
          { net = "10.10.110.0", bits = 24 },
          { net = "10.10.30.0", bits = 24 },
          { net = "10.10.50.0", bits = 24 },
          { net = "10.10.60.0", bits = 24 },
          { net = "10.10.70.0", bits = 24 },
        },
        ports = {
          { proto = "tcp", lo = 3389, hi = 3389 },
        },
      },
      {
        id = "NM-040",
        action = "allow",
        src = {
          { net = "10.10.10.0", bits = 24 },
          { net = "10.10.100.0", bits = 24 },
          { net = "10.10.120.0", bits = 24 },
          { net = "10.10.20.0", bits = 24 },
          { net = "10.10.40.0", bits = 24 },
          { net = "10.10.110.0", bits = 24 },
          { net = "10.10.30.0", bits = 24 },
          { net = "10.10.50.0", bits = 24 },
          { net = "10.10.60.0", bits = 24 },
          { net = "10.10.70.0", bits = 24 },
          { net = "10.10.80.0", bits = 24 },
        },
        dst = {
          { net = "10.10.70.10", bits = 32 },
        },
        ports = {
          { proto = "tcp", lo = 1514, hi = 1514 },
          { proto = "tcp", lo = 1515, hi = 1515 },
        },
      },
      {
        id = "NM-041",
        action = "allow",
        src = {
          { net = "10.10.10.0", bits = 24 },
          { net = "10.10.255.0", bits = 24 },
        },
        dst = {
          { net = "10.10.70.10", bits = 32 },
        },
        ports = {
          { proto = "udp", lo = 514, hi = 514 },
        },
      },
      {
        id = "NM-042",
        action = "allow",
        src = {
          { net = "10.10.70.0", bits = 24 },
        },
        dst = {
          { net = "10.10.70.10", bits = 32 },
        },
        ports = {
          { proto = "tcp", lo = 443, hi = 443 },
        },
      },
      {
        id = "NM-043",
        action = "deny",
        src = {
          { net = "10.10.10.0", bits = 24 },
          { net = "10.10.100.0", bits = 24 },
          { net = "10.10.120.0", bits = 24 },
          { net = "10.10.20.0", bits = 24 },
          { net = "10.10.40.0", bits = 24 },
          { net = "10.10.110.0", bits = 24 },
          { net = "10.10.30.0", bits = 24 },
          { net = "10.10.50.0", bits = 24 },
          { net = "10.10.60.0", bits = 24 },
          { net = "10.10.70.0", bits = 24 },
          { net = "10.10.80.0", bits = 24 },
        },
        dst = {
          { net = "10.10.70.10", bits = 32 },
        },
        ports = {
          { proto = "any", lo = 0, hi = 65535 },
        },
      },
      {
        id = "NM-050",
        action = "allow",
        src = {
          { net = "10.10.80.90", bits = 32 },
        },
        dst = {
          { net = "10.10.80.0", bits = 24 },
        },
        ports = {
          { proto = "tcp", lo = 9102, hi = 9102 },
        },
      },
      {
        id = "NM-060",
        action = "deny",
        src = {
          { net = "10.10.100.0", bits = 24 },
          { net = "10.10.120.0", bits = 24 },
          { net = "10.10.20.0", bits = 24 },
          { net = "10.10.40.0", bits = 24 },
          { net = "10.10.110.0", bits = 24 },
          { net = "10.10.30.0", bits = 24 },
          { net = "10.10.50.0", bits = 24 },
          { net = "10.10.60.0", bits = 24 },
          { net = "10.10.70.0", bits = 24 },
        },
        dst = {
          { net = "10.10.100.0", bits = 24 },
          { net = "10.10.120.0", bits = 24 },
          { net = "10.10.20.0", bits = 24 },
          { net = "10.10.40.0", bits = 24 },
          { net = "10.10.110.0", bits = 24 },
          { net = "10.10.30.0", bits = 24 },
          { net = "10.10.50.0", bits = 24 },
          { net = "10.10.60.0", bits = 24 },
          { net = "10.10.70.0", bits = 24 },
        },
        ports = {
          { proto = "any", lo = 0, hi = 65535 },
        },
      },
      {
        id = "NM-070",
        action = "allow",
        src = {
          { net = "10.10.100.0", bits = 24 },
          { net = "10.10.120.0", bits = 24 },
          { net = "10.10.20.0", bits = 24 },
          { net = "10.10.40.0", bits = 24 },
          { net = "10.10.110.0", bits = 24 },
          { net = "10.10.30.0", bits = 24 },
          { net = "10.10.50.0", bits = 24 },
          { net = "10.10.60.0", bits = 24 },
          { net = "10.10.70.0", bits = 24 },
        },
        dst = {
          { internet = true },
        },
        ports = {
          { proto = "tcp", lo = 80, hi = 80 },
          { proto = "tcp", lo = 443, hi = 443 },
        },
      },
      {
        id = "NM-071",
        action = "allow",
        src = {
          { net = "10.10.80.10", bits = 32 },
          { net = "10.10.70.10", bits = 32 },
        },
        dst = {
          { internet = true },
        },
        ports = {
          { proto = "tcp", lo = 443, hi = 443 },
        },
      },
      {
        id = "NM-080",
        action = "allow",
        src = {
          { net = "10.10.60.0", bits = 24 },
          { net = "10.10.70.0", bits = 24 },
          { net = "10.10.10.0", bits = 24 },
        },
        dst = {
          { net = "10.10.10.0", bits = 24 },
          { net = "10.10.100.0", bits = 24 },
          { net = "10.10.120.0", bits = 24 },
          { net = "10.10.20.0", bits = 24 },
          { net = "10.10.40.0", bits = 24 },
          { net = "10.10.110.0", bits = 24 },
          { net = "10.10.30.0", bits = 24 },
          { net = "10.10.50.0", bits = 24 },
          { net = "10.10.60.0", bits = 24 },
          { net = "10.10.70.0", bits = 24 },
          { net = "10.10.80.0", bits = 24 },
          { net = "10.10.90.0", bits = 24 },
          { net = "10.10.255.0", bits = 24 },
        },
        ports = {
          { proto = "icmp", lo = 0, hi = 65535 },
        },
      },
    },
    aws = {
      {
        id = "NM-002",
        action = "deny",
        src = {
          { internet = true },
        },
        dst = {
          { net = "10.10.20.0", bits = 24 },
          { net = "10.10.50.0", bits = 24 },
          { net = "10.10.70.0", bits = 24 },
          { net = "10.10.80.0", bits = 24 },
          { net = "10.10.90.0", bits = 24 },
        },
        ports = {
          { proto = "any", lo = 0, hi = 65535 },
        },
      },
      {
        id = "NM-004",
        action = "deny",
        src = {
          { net = "10.10.90.0", bits = 24 },
        },
        dst = {
          { net = "10.10.20.0", bits = 24 },
          { net = "10.10.50.0", bits = 24 },
          { net = "10.10.70.0", bits = 24 },
          { net = "10.10.80.0", bits = 24 },
        },
        ports = {
          { proto = "any", lo = 0, hi = 65535 },
        },
      },
      {
        id = "NM-005",
        action = "allow",
        src = {
          { net = "10.10.90.0", bits = 24 },
        },
        dst = {
          { internet = true },
        },
        ports = {
          { proto = "tcp", lo = 80, hi = 80 },
          { proto = "tcp", lo = 443, hi = 443 },
        },
      },
      {
        id = "NM-006",
        action = "allow",
        src = {
          { net = "10.10.90.0", bits = 24 },
        },
        dst = {
          { internet = true },
        },
        ports = {
          { proto = "udp", lo = 53, hi = 53 },
          { proto = "tcp", lo = 53, hi = 53 },
        },
      },
      {
        id = "NM-010",
        action = "allow",
        src = {
          { net = "10.10.20.0", bits = 24 },
          { net = "10.10.50.0", bits = 24 },
          { net = "10.10.70.0", bits = 24 },
          { net = "10.10.80.0", bits = 24 },
        },
        dst = {
          { net = "10.10.80.10", bits = 32 },
        },
        ports = {
          { proto = "tcp", lo = 53, hi = 53 },
          { proto = "udp", lo = 53, hi = 53 },
          { proto = "tcp", lo = 88, hi = 88 },
          { proto = "udp", lo = 88, hi = 88 },
          { proto = "tcp", lo = 135, hi = 135 },
          { proto = "tcp", lo = 389, hi = 389 },
          { proto = "udp", lo = 389, hi = 389 },
          { proto = "tcp", lo = 445, hi = 445 },
          { proto = "tcp", lo = 464, hi = 464 },
          { proto = "udp", lo = 464, hi = 464 },
          { proto = "tcp", lo = 636, hi = 636 },
          { proto = "tcp", lo = 3268, hi = 3269 },
          { proto = "udp", lo = 123, hi = 123 },
          { proto = "tcp", lo = 49152, hi = 65535 },
        },
      },
      {
        id = "NM-013",
        action = "allow",
        src = {
          { net = "10.10.80.10", bits = 32 },
        },
        dst = {
          { internet = true },
        },
        ports = {
          { proto = "udp", lo = 53, hi = 53 },
          { proto = "tcp", lo = 53, hi = 53 },
        },
      },
      {
        id = "NM-020",
        action = "allow",
        src = {
          { net = "10.10.20.0", bits = 24 },
        },
        dst = {
          { net = "10.10.80.30", bits = 32 },
        },
        ports = {
          { proto = "tcp", lo = 443, hi = 443 },
        },
      },
      {
        id = "NM-026",
        action = "deny",
        src = {
          { net = "10.10.50.0", bits = 24 },
        },
        dst = {
          { net = "10.10.80.30", bits = 32 },
        },
        ports = {
          { proto = "any", lo = 0, hi = 65535 },
        },
      },
      {
        id = "NM-033",
        action = "deny",
        src = {
          { net = "10.10.20.0", bits = 24 },
          { net = "10.10.50.0", bits = 24 },
          { net = "10.10.70.0", bits = 24 },
          { net = "10.10.90.0", bits = 24 },
        },
        dst = {
          { net = "10.10.80.0", bits = 24 },
          { net = "10.10.70.0", bits = 24 },
        },
        ports = {
          { proto = "tcp", lo = 3389, hi = 3389 },
          { proto = "tcp", lo = 22, hi = 22 },
          { proto = "tcp", lo = 5985, hi = 5986 },
        },
      },
      {
        id = "NM-040",
        action = "allow",
        src = {
          { net = "10.10.20.0", bits = 24 },
          { net = "10.10.50.0", bits = 24 },
          { net = "10.10.70.0", bits = 24 },
          { net = "10.10.80.0", bits = 24 },
        },
        dst = {
          { net = "10.10.70.10", bits = 32 },
        },
        ports = {
          { proto = "tcp", lo = 1514, hi = 1514 },
          { proto = "tcp", lo = 1515, hi = 1515 },
        },
      },
      {
        id = "NM-043",
        action = "deny",
        src = {
          { net = "10.10.20.0", bits = 24 },
          { net = "10.10.50.0", bits = 24 },
          { net = "10.10.70.0", bits = 24 },
          { net = "10.10.80.0", bits = 24 },
        },
        dst = {
          { net = "10.10.70.10", bits = 32 },
        },
        ports = {
          { proto = "any", lo = 0, hi = 65535 },
        },
      },
      {
        id = "NM-060",
        action = "deny",
        src = {
          { net = "10.10.20.0", bits = 24 },
          { net = "10.10.50.0", bits = 24 },
          { net = "10.10.70.0", bits = 24 },
        },
        dst = {
          { net = "10.10.20.0", bits = 24 },
          { net = "10.10.50.0", bits = 24 },
          { net = "10.10.70.0", bits = 24 },
        },
        ports = {
          { proto = "any", lo = 0, hi = 65535 },
        },
      },
      {
        id = "NM-070",
        action = "allow",
        src = {
          { net = "10.10.20.0", bits = 24 },
          { net = "10.10.50.0", bits = 24 },
          { net = "10.10.70.0", bits = 24 },
        },
        dst = {
          { internet = true },
        },
        ports = {
          { proto = "tcp", lo = 80, hi = 80 },
          { proto = "tcp", lo = 443, hi = 443 },
        },
      },
      {
        id = "NM-071",
        action = "allow",
        src = {
          { net = "10.10.80.10", bits = 32 },
          { net = "10.10.70.10", bits = 32 },
        },
        dst = {
          { internet = true },
        },
        ports = {
          { proto = "tcp", lo = 443, hi = 443 },
        },
      },
      {
        id = "NM-072",
        action = "allow",
        src = {
          { net = "10.10.20.0", bits = 24 },
          { net = "10.10.50.0", bits = 24 },
          { net = "10.10.70.0", bits = 24 },
          { net = "10.10.80.0", bits = 24 },
          { net = "10.10.90.0", bits = 24 },
        },
        dst = {
          { internet = true },
        },
        ports = {
          { proto = "tcp", lo = 443, hi = 443 },
        },
      },
    },
  },
}
