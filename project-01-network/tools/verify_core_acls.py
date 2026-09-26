#!/usr/bin/env python3
"""Statically verify that the generated core ACLs enforce data/network-matrix.yaml.

For every pair of test endpoints in different segments and every port defined in the matrix
services, the script evaluates:

  * the matrix (rules with applies_to: pt, first match wins, default deny), and
  * the ACL applied inbound on the source VLAN's SVI in the generated CORE-SW01 file
    (first match wins; a new connection never matches "established" entries),

and reports every flow where the two decisions differ. It also checks that every ALLOW has a
return path through the destination VLAN's ACL.

This is static analysis of the configuration text. It does not replace testing in Packet
Tracer (documentation/validation-plan.md).
"""

from __future__ import annotations

import ipaddress
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import render_core_acls as r  # noqa: E402

PRIVATE = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
INTERNET_HOST = ipaddress.ip_address("198.51.100.10")

# Known, documented limitations of stateless ACLs (documentation/acl-design.md):
# UDP return traffic is not permitted for rules whose service is "any" (authorized scanner),
# because a stateless ACL cannot distinguish a UDP reply from new traffic.
KNOWN_REPLY_GAPS = {("any", "udp")}


def is_internet(ip) -> bool:
    return not any(ip in n for n in PRIVATE)


def load_acls(text: str) -> dict[str, list[str]]:
    acls, current = {}, None
    for line in text.splitlines():
        if line.startswith("ip access-list extended "):
            current = line.split()[-1]
            acls[current] = []
        elif current and line.startswith(" ") and line.split()[0] in ("permit", "deny"):
            acls[current].append(line.strip())
        elif line == "exit":
            current = None
    return acls


def ace_matches(line: str, proto: str, src, sport: int, dst, dport: int, reply: bool, icmp_type: str) -> bool:
    verb, a_proto, a_src, a_sport, a_dst, a_dport = r.parse_ace(line)
    if a_proto != "ip" and a_proto != proto:
        return False
    if src not in a_src or dst not in a_dst:
        return False
    if proto in ("tcp", "udp") and not (a_sport[0] <= sport <= a_sport[1] and a_dport[0] <= dport <= a_dport[1]):
        return False
    if "established" in line.split() and not reply:
        return False
    if proto == "icmp" and a_proto == "icmp":
        tail = line.split()[-1]
        if tail in ("echo", "echo-reply") and tail != icmp_type:
            return False
    return True


def acl_decision(acl: list[str], proto, src, sport, dst, dport, reply=False, icmp_type="echo") -> str:
    for line in acl:
        if ace_matches(line, proto, src, sport, dst, dport, reply, icmp_type):
            return "allow" if line.startswith("permit") else "deny"
    return "deny"


def main() -> int:
    model = r.Model()
    acls = load_acls(r.OUTPUT.read_text(encoding="utf-8"))
    segs = {k: v for k, v in model.segments.items() if k not in r.NO_SVI and v["vlan"]}
    seg_net = {k: ipaddress.ip_network(v["cidr"]) for k, v in segs.items()}

    def seg_of(ip):
        return next((k for k, n in seg_net.items() if ip in n), None)

    def ref_contains(ref: str, ip) -> bool:
        if ref == "internet":
            return is_internet(ip)
        kind, value = ref.split(":", 1)
        if kind == "seg":
            return ip in ipaddress.ip_network(model.segments[value]["cidr"])
        if kind == "grp":
            return any(ip in ipaddress.ip_network(model.segments[s]["cidr"]) for s in model.groups[value])
        return str(ip) == model.assets[value]["ip"]

    def matrix_decision(proto, src, dst, dport) -> tuple[str, str]:
        for rule in model.rules:
            if not any(ref_contains(x, src) for x in rule["source"]):
                continue
            if not any(ref_contains(x, dst) for x in rule["destination"]):
                continue
            for p in model.services[rule["service"]]:
                if p["proto"] == "any" or (
                    p["proto"] == proto
                    and (
                        p["port"] == "any"
                        or (isinstance(p["port"], int) and p["port"] == dport)
                        or (isinstance(p["port"], str) and int(p["port"].split("-")[0]) <= dport <= int(p["port"].split("-")[1]))
                    )
                ):
                    return rule["action"], rule["id"]
        return "deny", "default"

    # Test endpoints: every PT asset in an SVI segment, one DHCP-range host per segment,
    # and one internet host.
    endpoints = {a["id"]: ipaddress.ip_address(a["ip"]) for a in model.assets.values() if a["segment"] in segs}
    for k, n in seg_net.items():
        endpoints[f"{k}-client"] = n.network_address + 150
    endpoints["internet"] = INTERNET_HOST
    gateways = {k: next(n.hosts()) for k, n in seg_net.items()}
    for k, g in gateways.items():
        endpoints.setdefault(f"gw-{k}", g)
    gateway_ips = set(gateways.values())

    probes = sorted(
        {("icmp", 0)}
        | {
            (p["proto"], int(str(p["port"]).split("-")[0]))
            for ports in model.services.values()
            for p in ports
            if p["proto"] in ("tcp", "udp")
        }
        | {("tcp", 8080), ("udp", 161)}  # ports no rule allows
    )

    mismatches, checked, allowed = [], 0, 0
    for s_name, s_ip in endpoints.items():
        s_seg = seg_of(s_ip)
        if s_seg is None:  # internet sources are enforced by FW01
            continue
        acl = acls[f"ACL-IN-{segs[s_seg]['name']}"]
        for d_name, d_ip in endpoints.items():
            d_seg = seg_of(d_ip)
            to_core = d_ip in gateway_ips
            if d_seg == s_seg and not to_core:
                continue  # intra-VLAN traffic is not routed by the core
            for proto, port in probes:
                checked += 1
                want, rule_id = matrix_decision(proto, s_ip, d_ip, port)
                if d_ip == gateways[s_seg] and proto == "icmp":
                    want, rule_id = "allow", "infrastructure: ping own gateway"
                got = acl_decision(acl, proto, s_ip, 50000, d_ip, port)
                if want != got:
                    mismatches.append(f"{s_name}({s_ip}) -> {d_name}({d_ip}) {proto}/{port}: matrix={want} [{rule_id}] acl={got}")
                    continue
                service = next((x["service"] for x in model.rules if x["id"] == rule_id), None)
                # Replies generated by the core itself are not subject to inbound ACLs.
                if want == "allow" and d_seg is not None and not to_core and (service, proto) not in KNOWN_REPLY_GAPS:
                    allowed += 1
                    back = acls[f"ACL-IN-{segs[d_seg]['name']}"]
                    ok = acl_decision(back, proto, d_ip, port, s_ip, 50000, reply=True, icmp_type="echo-reply")
                    if ok != "allow":
                        mismatches.append(f"{s_name} -> {d_name} {proto}/{port}: allowed by {rule_id} but the reply is blocked")

    # Sources outside the core VLANs (transit devices): forward traffic is enforced by FW01,
    # but the replies of our hosts cross the core ACLs and must be permitted.
    outside = {a["id"]: ipaddress.ip_address(a["ip"]) for a in model.assets.values()
               if a["segment"] not in segs and a["segment"] != "dmz"}
    for s_name, s_ip in outside.items():
        for d_name, d_ip in endpoints.items():
            d_seg = seg_of(d_ip)
            if d_seg is None or d_ip in gateway_ips:
                continue
            for proto, port in probes:
                want, rule_id = matrix_decision(proto, s_ip, d_ip, port)
                service = next((x["service"] for x in model.rules if x["id"] == rule_id), None)
                if want != "allow" or (service, proto) in KNOWN_REPLY_GAPS:
                    continue
                checked += 1
                allowed += 1
                back = acls[f"ACL-IN-{segs[d_seg]['name']}"]
                if acl_decision(back, proto, d_ip, port, s_ip, 50000, reply=True, icmp_type="echo-reply") != "allow":
                    mismatches.append(f"{s_name} -> {d_name} {proto}/{port}: allowed by {rule_id} but the reply is blocked")

    print(f"flows checked: {checked}  allowed internal flows with verified return path: {allowed}")
    print(f"mismatches: {len(mismatches)}")
    for m in mismatches[:40]:
        print("  " + m)
    return 1 if mismatches else 0


if __name__ == "__main__":
    sys.exit(main())
