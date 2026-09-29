"""Network matrix -> AWS Security Group rules (ADR-001, ADR-005, ADR-009).

Only segments, assets and rules marked ``aws`` are used. Security Groups are stateful and
allow-only, so the matrix is translated like this:

* An allowed flow becomes an **egress** rule on the source host's group and an **ingress** rule
  on the destination host's group: between two AWS hosts both ends filter the traffic.
* A DENY rule becomes the absence of an allow. Rules are evaluated in order and the first match
  wins, so an allow is emitted only where no earlier DENY covers it. An allow that an earlier
  DENY covers only in part cannot be expressed with Security Groups, and the render stops.
* ``internet`` becomes 0.0.0.0/0 on egress. Isolation between internal hosts does not depend on
  it: every internal destination is an AWS host with its own ingress rules.
* Inbound traffic from the internet is never rendered (NM-002). An AWS allow whose source is
  ``internet`` stops the render.

Run from the repository root:
    python infrastructure/tools/render_security_groups.py --write   # regenerate
    python infrastructure/tools/render_security_groups.py --check   # fail if out of date
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from pathlib import Path

from ._cli import PolicyError, load_yaml, run

ENV = "aws"
OUTPUT = Path("infrastructure/terraform/lab/generated/security-groups.json")
# Default AWS quota for rules per Security Group and direction.
MAX_RULES_PER_DIRECTION = 60
ANYWHERE = ipaddress.ip_network("0.0.0.0/0")


@dataclass(frozen=True)
class Endpoint:
    network: ipaddress.IPv4Network
    internet: bool = False  # "internet" = non-private addresses, disjoint from internal ones

    def covers(self, other: Endpoint) -> bool:
        if self.internet or other.internet:
            return self.internet and other.internet
        return other.network.subnet_of(self.network)

    def overlaps(self, other: Endpoint) -> bool:
        if self.internet or other.internet:
            return self.internet and other.internet
        return self.network.overlaps(other.network)

    @property
    def cidr(self) -> str:
        return str(ANYWHERE if self.internet else self.network)


@dataclass(frozen=True)
class Ports:
    protocol: str  # "tcp", "udp", "icmp" or "-1" (any protocol)
    low: int | None
    high: int | None

    def covers(self, other: Ports) -> bool:
        if self.protocol == "-1":
            return True
        return (
            self.protocol == other.protocol
            and self.low is not None
            and other.low is not None
            and self.low <= other.low
            and other.high <= self.high
        )

    def overlaps(self, other: Ports) -> bool:
        if "-1" in (self.protocol, other.protocol):
            return True
        return self.protocol == other.protocol and self.low <= other.high and other.low <= self.high


def _ports(entry: dict) -> Ports:
    proto, port = entry["proto"], entry["port"]
    if proto == "any":
        return Ports("-1", None, None)
    if proto == "icmp":
        return Ports("icmp", -1, -1)
    if port == "any":
        return Ports(proto, 0, 65535)
    low, _, high = str(port).partition("-")
    return Ports(proto, int(low), int(high or low))


class Model:
    def __init__(self, matrix: dict, assets: list[dict]):
        self.segments = {
            s["id"]: s for s in matrix["segments"] if ENV in s["environments"] and s.get("cidr")
        }
        self.groups = {g["id"]: g["segments"] for g in matrix.get("segment_groups", [])}
        self.services = {s["id"]: [_ports(p) for p in s["ports"]] for s in matrix["services"]}
        self.rules = [r for r in matrix["rules"] if ENV in r["applies_to"]]
        self.hosts = {a["id"]: a for a in assets if ENV in a["environments"]}

    def resolve(self, ref: str) -> list[Endpoint]:
        if ref == "internet":
            return [Endpoint(ANYWHERE, internet=True)]
        kind, _, name = ref.partition(":")
        if kind == "seg":
            names = [name]
        elif kind == "grp":
            names = self.groups[name]
        elif kind == "asset":
            host = self.hosts.get(name)
            return [Endpoint(ipaddress.ip_network(f"{host['ip']}/32"))] if host else []
        else:
            raise PolicyError(f"unknown reference {ref!r}")
        return [
            Endpoint(ipaddress.ip_network(self.segments[n]["cidr"]))
            for n in names
            if n in self.segments
        ]

    def hosts_in(self, endpoint: Endpoint) -> list[str]:
        if endpoint.internet:
            return []
        return [
            host_id
            for host_id, host in self.hosts.items()
            if ipaddress.ip_address(host["ip"]) in endpoint.network
        ]


def render(matrix: dict, assets: list[dict]) -> dict:
    model = Model(matrix, assets)
    rules: dict[str, dict[str, dict]] = {h: {"ingress": {}, "egress": {}} for h in model.hosts}
    denies: list[tuple[str, Endpoint, Endpoint, Ports]] = []

    for rule in model.rules:
        sources = [e for ref in rule["source"] for e in model.resolve(ref)]
        destinations = [e for ref in rule["destination"] for e in model.resolve(ref)]
        ports = model.services[rule["service"]]
        for src in sources:
            for dst in destinations:
                for port in ports:
                    if rule["action"] == "deny":
                        denies.append((rule["id"], src, dst, port))
                        continue
                    if _shadowed(rule["id"], src, dst, port, denies):
                        continue
                    if src.internet:
                        raise PolicyError(
                            f"{rule['id']}: inbound from the internet is not allowed in AWS"
                        )
                    _emit(model, rules, rule["id"], src, dst, port)

    hosts = {}
    for host_id, host in model.hosts.items():
        entry = {
            "segment": host["segment"],
            "ip": host["ip"],
            "platform": "windows" if "windows" in host["os"].lower() else "linux",
            "aws_phase": host["aws_phase"],
        }
        for direction in ("ingress", "egress"):
            items = sorted(rules[host_id][direction].values(), key=_sort_key)
            if len(items) > MAX_RULES_PER_DIRECTION:
                raise PolicyError(
                    f"{host_id}: {len(items)} {direction} rules exceed the AWS default quota "
                    f"of {MAX_RULES_PER_DIRECTION} per Security Group"
                )
            entry[direction] = items
        hosts[host_id] = entry

    return {
        "_generated": "GENERATED from data/network-matrix.yaml and data/assets.yaml by "
        "infrastructure/tools/render_security_groups.py. Do not edit.",
        "segments": {
            seg_id: {"name": seg["name"], "cidr": seg["cidr"]}
            for seg_id, seg in model.segments.items()
        },
        "hosts": hosts,
    }


def _shadowed(rule_id, src, dst, port, denies) -> bool:
    for deny_id, d_src, d_dst, d_port in denies:
        if d_src.covers(src) and d_dst.covers(dst) and d_port.covers(port):
            return True
        if d_src.overlaps(src) and d_dst.overlaps(dst) and d_port.overlaps(port):
            raise PolicyError(
                f"{rule_id} is partly shadowed by the earlier {deny_id}; "
                "Security Groups cannot express this (split the rule or use a Network ACL)"
            )
    return False


def _emit(model: Model, rules: dict, rule_id: str, src: Endpoint, dst: Endpoint, port: Ports):
    for host_id in model.hosts_in(src):
        if not _is_host(model, host_id, dst):
            _add(rules[host_id]["egress"], rule_id, port, dst.cidr)
    for host_id in model.hosts_in(dst):
        if not _is_host(model, host_id, src):
            _add(rules[host_id]["ingress"], rule_id, port, src.cidr)


def _is_host(model: Model, host_id: str, endpoint: Endpoint) -> bool:
    """True when the endpoint is exactly this host: traffic to itself needs no rule."""
    return not endpoint.internet and endpoint.network == ipaddress.ip_network(
        f"{model.hosts[host_id]['ip']}/32"
    )


def _add(target: dict, rule_id: str, port: Ports, cidr: str) -> None:
    key = f"{port.protocol}-{port.low}-{port.high}-{cidr}".replace("None", "all")
    if key in target:
        if rule_id not in target[key]["rules"]:
            target[key]["rules"].append(rule_id)
        return
    target[key] = {
        "key": key,
        "rules": [rule_id],
        "protocol": port.protocol,
        "from_port": port.low,
        "to_port": port.high,
        "cidr": cidr,
    }


def _sort_key(item: dict) -> tuple:
    return (item["rules"][0], item["cidr"], item["protocol"], item["from_port"] or 0)


def render_from(data_dir: Path) -> dict:
    matrix = load_yaml(data_dir / "network-matrix.yaml")
    return render(matrix, load_yaml(data_dir / "assets.yaml")["assets"])


def main(argv: list[str] | None = None) -> int:
    return run(__doc__.splitlines()[0], OUTPUT, render_from, argv)


if __name__ == "__main__":
    raise SystemExit(main())
