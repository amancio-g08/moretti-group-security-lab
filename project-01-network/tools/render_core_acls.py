#!/usr/bin/env python3
"""Render the inter-VLAN ACLs of CORE-SW01 from data/network-matrix.yaml.

The matrix is the single source of truth (ADR-001). This script translates it into one
inbound extended ACL per SVI on the core switch (ADR-008):

* Only rules whose ``applies_to`` contains ``pt`` are used.
* Each ACL filters traffic *entering* the core from one segment, so a rule is rendered in the
  ACL of every segment that appears in its source.
* Traffic that stays inside one VLAN never reaches the core, so destinations in the source's
  own segment are skipped.
* Core ACLs are stateless. For every ALLOW rule, the ACL of the *destination* segment gets a
  matching return-traffic entry (TCP ``established``, UDP from the service port, ICMP
  echo-reply), limited to the initiating network.
* ``internet`` means "any non-private address": internal rules are rendered first, then a
  guard that denies RFC 1918 space, then internet rules. Internal and internet destinations are
  disjoint, so moving internet rules after internal ones does not change the result.
* Sources outside the core (``internet``, DMZ, transit) are enforced by FW01, not here.

Usage:
    python3 project-01-network/tools/render_core_acls.py            # print to stdout
    python3 project-01-network/tools/render_core_acls.py --write    # update the generated file
    python3 project-01-network/tools/render_core_acls.py --check    # fail if the file is stale
"""

from __future__ import annotations

import argparse
import ipaddress
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
MATRIX = ROOT / "data" / "network-matrix.yaml"
ASSETS = ROOT / "data" / "assets.yaml"
OUTPUT = ROOT / "project-01-network" / "configs" / "generated" / "CORE-SW01-acls.txt"

# Segments without an SVI on the core are enforced elsewhere (FW01) or carry no traffic.
NO_SVI = {"dmz", "transit", "blackhole"}
RFC1918 = ["10.0.0.0 0.255.255.255", "172.16.0.0 0.15.255.255", "192.168.0.0 0.0.255.255"]


def wildcard(cidr) -> str:
    net = ipaddress.ip_network(cidr)
    if net.prefixlen == 32:
        return f"host {net.network_address}"
    return f"{net.network_address} {net.hostmask}"


class Model:
    def __init__(self) -> None:
        matrix = yaml.safe_load(MATRIX.read_text(encoding="utf-8"))
        assets = yaml.safe_load(ASSETS.read_text(encoding="utf-8"))["assets"]
        self.version = matrix["version"]
        self.segments = {s["id"]: s for s in matrix["segments"] if "pt" in s["environments"]}
        self.groups = {g["id"]: g["segments"] for g in matrix["segment_groups"]}
        self.services = {s["id"]: s["ports"] for s in matrix["services"]}
        self.rules = [r for r in matrix["rules"] if "pt" in r["applies_to"]]
        self.assets = {a["id"]: a for a in assets if "pt" in a["environments"]}

    # A resolved endpoint: (segment_id or None for internet, network or None for "any")
    def resolve(self, ref: str) -> list[tuple[str | None, ipaddress.IPv4Network | None]]:
        if ref == "internet":
            return [(None, None)]
        kind, value = ref.split(":", 1)
        if kind == "seg":
            return [(value, ipaddress.ip_network(self.segments[value]["cidr"]))]
        if kind == "grp":
            return [(s, ipaddress.ip_network(self.segments[s]["cidr"])) for s in self.groups[value]]
        if kind == "asset":
            a = self.assets[value]
            return [(a["segment"], ipaddress.ip_network(f"{a['ip']}/32"))]
        raise ValueError(f"unknown reference {ref}")


def collapse(nets) -> list[str]:
    """Merge adjacent networks (e.g. DC01 + DC02 -> one /31) to keep the ACLs short."""
    return [wildcard(str(n)) for n in ipaddress.collapse_addresses(nets)]


def port_expr(port) -> str:
    if port == "any":
        return ""
    if isinstance(port, str) and "-" in port:
        lo, hi = port.split("-")
        return f" range {lo} {hi}"
    return f" eq {port}"


def forward_aces(action: str, ports, src: str, dst: str) -> list[str]:
    verb = "permit" if action == "allow" else "deny"
    out = []
    for p in ports:
        proto, port = p["proto"], p["port"]
        if proto == "any":
            out.append(f"{verb} ip {src} {dst}")
        elif proto == "icmp":
            out.append(f"{verb} icmp {src} {dst} echo")
        else:
            out.append(f"{verb} {proto} {src} {dst}{port_expr(port)}")
    return out


def reply_aces(ports, responder: str, initiator: str) -> list[str]:
    out = []
    for p in ports:
        proto, port = p["proto"], p["port"]
        if proto == "any":
            # UDP cannot be told apart from new traffic without state, so "any" services only
            # get TCP and ICMP return traffic (UDP scanning is a documented limitation).
            out += [
                f"permit tcp {responder} {initiator} established",
                f"permit icmp {responder} {initiator} echo-reply",
            ]
        elif proto == "icmp":
            out.append(f"permit icmp {responder} {initiator} echo-reply")
        elif proto == "tcp":
            # One entry per initiator: port-level precision adds little to a stateless
            # "established" match, which can never open a new connection.
            out.append(f"permit tcp {responder} {initiator} established")
        else:
            out.append(f"permit udp {responder}{port_expr(port)} {initiator}")
    return out


def dedupe(lines: list[str]) -> list[str]:
    seen, out = set(), []
    for line in lines:
        if line.startswith("remark") or line not in seen:
            out.append(line)
            seen.add(line)
    return out


# --------------------------------------------------------------------------- redundancy pruning
# An explicit DENY adds nothing to a stateless ACL when no later PERMIT overlaps it: the final
# "deny ip any any" already drops that traffic. On real IOS such entries would carry the "log"
# keyword; Packet Tracer does not support ACL logging, so redundant DENYs are replaced by a remark.

def _addr(tokens: list[str]) -> tuple[ipaddress.IPv4Network, list[str]]:
    if tokens[0] == "any":
        return ipaddress.ip_network("0.0.0.0/0"), tokens[1:]
    if tokens[0] == "host":
        return ipaddress.ip_network(f"{tokens[1]}/32"), tokens[2:]
    wild = ipaddress.ip_address(tokens[1])
    mask = ipaddress.ip_address(int(wild) ^ 0xFFFFFFFF)
    return ipaddress.ip_network(f"{tokens[0]}/{mask}"), tokens[2:]


def _ports(tokens: list[str]) -> tuple[tuple[int, int], list[str]]:
    if tokens and tokens[0] == "eq":
        return (int(tokens[1]), int(tokens[1])), tokens[2:]
    if tokens and tokens[0] == "range":
        return (int(tokens[1]), int(tokens[2])), tokens[3:]
    return (0, 65535), tokens


def parse_ace(line: str):
    t = line.split()
    verb, proto, rest = t[0], t[1], t[2:]
    src, rest = _addr(rest)
    sport, rest = _ports(rest) if proto in ("tcp", "udp") else ((0, 65535), rest)
    dst, rest = _addr(rest)
    dport, rest = _ports(rest) if proto in ("tcp", "udp") else ((0, 65535), rest)
    return verb, proto, src, sport, dst, dport


def overlaps(a, b) -> bool:
    _, pa, sa, spa, da, dpa = a
    _, pb, sb, spb, db, dpb = b
    proto_ok = pa == pb or "ip" in (pa, pb)
    ports_ok = spa[0] <= spb[1] and spb[0] <= spa[1] and dpa[0] <= dpb[1] and dpb[0] <= dpa[1]
    return proto_ok and sa.overlaps(sb) and da.overlaps(db) and ports_ok


def covers(outer, inner) -> bool:
    _, po, so, spo, do, dpo = outer
    _, pi, si, spi, di, dpi = inner
    proto_ok = po == "ip" or po == pi
    ports_ok = spo[0] <= spi[0] and spi[1] <= spo[1] and dpo[0] <= dpi[0] and dpi[1] <= dpo[1]
    return proto_ok and si.subnet_of(so) and di.subnet_of(do) and ports_ok


def reachable_overlap(deny_idx, deny, aces) -> bool:
    """True if some later PERMIT would match traffic of this DENY without another DENY in between
    covering it completely (e.g. the RFC 1918 guard in front of the internet rules)."""
    for j, later in aces:
        if j <= deny_idx or later[0] != "permit" or not overlaps(deny, later):
            continue
        shadowed = any(
            deny_idx < k < j and mid[0] == "deny" and covers(mid, deny) for k, mid in aces
        )
        if not shadowed:
            return True
    return False


def prune_redundant_denies(lines: list[str]) -> list[str]:
    aces = [(i, parse_ace(l)) for i, l in enumerate(lines) if l.split()[0] in ("permit", "deny")]
    last = aces[-1][0]  # final "deny ip any any"
    drop = set()
    # A PERMIT fully covered by an earlier PERMIT can never match: drop it.
    for i, ace in aces:
        if ace[0] == "permit" and any(j < i and e[0] == "permit" and covers(e, ace) and "established" not in lines[j] + lines[i] and "echo" not in lines[j] + lines[i] for j, e in aces):
            drop.add(i)
    for i, ace in aces:
        if ace[0] != "deny" or i == last or lines[i].startswith("deny ip any "):
            continue
        if not reachable_overlap(i, ace, aces):
            drop.add(i)
    out = []
    for i, line in enumerate(lines):
        if i in drop:
            continue
        if line.startswith("remark NM-") and " deny " in line:
            block = []
            for k in range(i + 1, len(lines)):
                if lines[k].startswith("remark"):
                    break
                block.append(k)
            if block and all(k in drop for k in block):
                line = line + " (enforced by default deny)"
        out.append(line)
    return out


INTERNAL_SUPERNET = ipaddress.ip_network("10.10.0.0/16")


def aggregate_replies(lines: list[str]) -> list[str]:
    """Group return-traffic entries that differ only by initiator network. When a responder
    answers three or more internal networks on the same port, one entry towards the internal
    supernet replaces them (fewer lines to paste; the responder and service port stay exact)."""
    ids = sorted({l.split()[1] for l in lines if l.startswith("remark NM-")})
    groups: dict[tuple, list] = {}
    order = []
    for line in lines:
        if line.startswith("remark"):
            continue
        t = line.split()
        verb, proto = t[0], t[1]
        src, rest = _addr(t[2:])
        sport, rest = _ports(rest) if proto in ("tcp", "udp") else ((0, 65535), rest)
        dst, rest = _addr(rest)
        src_txt = " ".join(t[2 : len(t) - len(rest) - len(_dst_tokens(t, rest))])
        key = (verb, proto, src_txt, tuple(rest))
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(dst)
    out = [f"remark return traffic for {', '.join(ids)}"]
    for key in order:
        verb, proto, src_txt, tail = key
        dsts = list(ipaddress.collapse_addresses(groups[key]))
        if len(dsts) >= 3 and all(d.subnet_of(INTERNAL_SUPERNET) for d in dsts):
            dsts = [INTERNAL_SUPERNET]
        for d in dsts:
            out.append(" ".join([verb, proto, src_txt, wildcard(str(d)), *tail]))
    return out


def _dst_tokens(t: list[str], rest: list[str]) -> list[str]:
    """Tokens of the destination address, located just before the trailing keywords."""
    head = t[: len(t) - len(rest)]
    if head[-1] == "any":
        return head[-1:]
    return head[-2:]


def render(model: Model) -> str:
    svi_segments = [s for s in model.segments if s not in NO_SVI and model.segments[s]["vlan"]]
    replies = {s: [] for s in svi_segments}
    internal = {s: [] for s in svi_segments}
    internet = {s: [] for s in svi_segments}
    dhcp_clients = set()
    gateways = {s: next(ipaddress.ip_network(model.segments[s]["cidr"]).hosts()) for s in svi_segments}

    for rule in model.rules:
        ports = model.services[rule["service"]]
        tag = f"remark {rule['id']} {rule['action']} {rule['service']}"
        sources = [e for ref in rule["source"] for e in model.resolve(ref)]
        dests = [e for ref in rule["destination"] for e in model.resolve(ref)]
        for s_seg in dict.fromkeys(seg for seg, _ in sources):
            if s_seg not in internal:
                # Internet, DMZ or transit source: the forward direction is enforced by FW01, but
                # replies from our VLANs still cross the core ACLs.
                if rule["action"] == "allow" and s_seg is not None:
                    for s_addr in collapse([n for seg, n in sources if seg == s_seg]):
                        for d_seg in dict.fromkeys(seg for seg, _ in dests):
                            if d_seg in replies:
                                replies[d_seg] += [f"remark {rule['id']} return traffic"]
                                for r_addr in collapse([n for seg, n in dests if seg == d_seg]):
                                    replies[d_seg] += reply_aces(ports, r_addr, s_addr)
                continue
            for s_addr in collapse([n for seg, n in sources if seg == s_seg]):
                # Destinations inside the source's own VLAN are never routed by the core, except
                # the core itself (the VLAN gateway), which inbound ACLs also protect.
                gw = gateways[s_seg]
                d_int = [n for seg, n in dests if seg is not None and seg != s_seg]
                if any(seg == s_seg and gw in n for seg, n in dests):
                    d_int.append(ipaddress.ip_network(f"{gw}/32"))
                has_internet = any(seg is None for seg, _ in dests)
                fwd_int = [a for d in collapse(d_int) for a in forward_aces(rule["action"], ports, s_addr, d)]
                fwd_ext = forward_aces(rule["action"], ports, s_addr, "any") if has_internet else []
                if fwd_int:
                    internal[s_seg] += [tag] + fwd_int
                if fwd_ext:
                    internet[s_seg] += [tag] + fwd_ext
                if rule["action"] == "allow":
                    for d_seg in dict.fromkeys(seg for seg, _ in dests):
                        if d_seg in replies and d_seg != s_seg:
                            responders = collapse([n for seg, n in dests if seg == d_seg])
                            replies[d_seg] += [f"remark {rule['id']} return traffic"]
                            for r_addr in responders:
                                replies[d_seg] += reply_aces(ports, r_addr, s_addr)
                if rule["service"] == "dhcp":
                    dhcp_clients.add(s_seg)

    header = [
        "! =====================================================================",
        "! GENERATED FILE - do not edit by hand.",
        f"! Source:     data/network-matrix.yaml (version {model.version})",
        "! Generator:  project-01-network/tools/render_core_acls.py",
        "! Regenerate: python3 project-01-network/tools/render_core_acls.py --write",
        "! Paste in global configuration mode on CORE-SW01 (configure terminal).",
        "! =====================================================================",
    ]
    body = []
    for seg_id in sorted(svi_segments, key=lambda s: model.segments[s]["vlan"]):
        seg = model.segments[seg_id]
        name = f"ACL-IN-{seg['name']}"
        net = ipaddress.ip_network(seg["cidr"])
        gateway = next(net.hosts())
        lines = [f"remark Inbound filter for VLAN {seg['vlan']} {seg['name']} {seg['cidr']}"]
        if replies[seg_id]:
            lines += ["remark --- return traffic (core ACLs are stateless)"]
            lines += aggregate_replies(dedupe(replies[seg_id]))
        lines += ["remark --- infrastructure: ping own gateway"]
        lines += [f"permit icmp {wildcard(seg['cidr'])} host {gateway} echo"]
        if seg_id in dhcp_clients or seg_id == "guest":
            lines += ["remark --- infrastructure: DHCP broadcasts (relay or local pool)"]
            lines += ["permit udp host 0.0.0.0 eq 68 host 255.255.255.255 eq 67"]
            lines += [f"permit udp {wildcard(seg['cidr'])} eq 68 host 255.255.255.255 eq 67"]
        if internal[seg_id]:
            lines += ["remark --- internal flows from the matrix"] + internal[seg_id]
        if internet[seg_id]:
            lines += ["remark --- internet means non-private: block RFC 1918 first"]
            lines += [f"deny ip any {r}" for r in RFC1918] + internet[seg_id]
        lines += ["remark --- default deny (matrix default_action)", "deny ip any any"]
        body += ["!", f"no ip access-list extended {name}", f"ip access-list extended {name}"]
        body += [f" {line}" for line in prune_redundant_denies(dedupe(lines))]
        body += ["exit", f"interface Vlan{seg['vlan']}", f" ip access-group {name} in", "exit"]
    return "\n".join(header + body + ["end", ""])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--write", action="store_true", help="write the generated file")
    group.add_argument("--check", action="store_true", help="fail if the generated file is stale")
    args = parser.parse_args()

    text = render(Model())
    if args.write:
        OUTPUT.write_text(text, encoding="utf-8")
        print(f"wrote {OUTPUT.relative_to(ROOT)}")
    elif args.check:
        current = OUTPUT.read_text(encoding="utf-8") if OUTPUT.exists() else ""
        if current != text:
            print(f"{OUTPUT.relative_to(ROOT)} is out of date with data/network-matrix.yaml.")
            print("Run: python3 project-01-network/tools/render_core_acls.py --write")
            return 1
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
