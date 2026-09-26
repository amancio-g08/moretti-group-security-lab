#!/usr/bin/env python3
"""Generate the Packet Tracer Builder script that builds the Moretti Group topology.

Inputs (no data is duplicated here):
  project-01-network/topology.yaml              device models, positions, cabling
  data/assets.yaml + data/network-matrix.yaml   host IP, mask, gateway, DNS
  project-01-network/configs/*.txt              device configurations
  project-01-network/configs/generated/CORE-SW01-acls.txt

Output:
  project-01-network/packet-tracer/build-topology.js
  (run inside Packet Tracer with the PTBuilder extension: Extensions -> Builder Code Editor)

Usage:
    python3 project-01-network/tools/build_ptbuilder_script.py --write
    python3 project-01-network/tools/build_ptbuilder_script.py --check
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
NET = ROOT / "project-01-network"
OUTPUT = NET / "packet-tracer" / "build-topology.js"

# DNS used by hosts, per segment (matches documentation/addressing-plan.md).
INTERNAL_DNS = "10.10.80.10"
SEGMENT_DNS = {"guest": "198.51.100.10", "dmz": ""}


def host_ip_settings() -> list[dict]:
    topo = yaml.safe_load((NET / "topology.yaml").read_text(encoding="utf-8"))
    assets = {a["id"]: a for a in yaml.safe_load((ROOT / "data/assets.yaml").read_text(encoding="utf-8"))["assets"]}
    segments = {s["id"]: s for s in yaml.safe_load((ROOT / "data/network-matrix.yaml").read_text(encoding="utf-8"))["segments"]}
    fixtures = {f["name"]: f for f in topo["fixtures"]}
    hosts = []
    for dev in topo["devices"]:
        if dev["model"] not in ("PC-PT", "Server-PT"):
            continue
        name = dev["name"]
        if name in fixtures:
            f = fixtures[name]
            hosts.append({"name": name, "dhcp": bool(f.get("dhcp")), "ip": f.get("ip", ""),
                          "mask": f.get("mask", ""), "gateway": f.get("gateway", ""), "dns": f.get("dns", "")})
            continue
        asset = assets[name]
        net = ipaddress.ip_network(segments[asset["segment"]]["cidr"])
        hosts.append({
            "name": name, "dhcp": False, "ip": asset["ip"], "mask": str(net.netmask),
            "gateway": str(next(net.hosts())), "dns": SEGMENT_DNS.get(asset["segment"], INTERNAL_DNS),
        })
    return hosts


def config_lines(path: Path) -> list[str]:
    """Configuration commands without comments, blank lines and the final 'end'."""
    lines = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith("!"):
            continue
        lines.append(line)
    while lines and lines[-1].strip() == "end":
        lines.pop()
    return lines


def render() -> str:
    topo = yaml.safe_load((NET / "topology.yaml").read_text(encoding="utf-8"))
    devices = [{k: d[k] for k in ("name", "model", "x", "y")} | {"power_supply": bool(d.get("power_supply"))} for d in topo["devices"]]
    links = topo["links"]
    configs = {
        d["name"]: {"credentials": d.get("credentials", ""), "commands": config_lines(NET / "configs" / d["config"])}
        for d in topo["devices"] if d.get("config")
    }
    core_acls = config_lines(NET / "configs" / "generated" / "CORE-SW01-acls.txt")

    js = lambda v: json.dumps(v, ensure_ascii=False, indent=1)  # noqa: E731
    template = (NET / "tools" / "build-topology.template.js").read_text(encoding="utf-8")
    return (
        template.replace("__DEVICES__", js(devices))
        .replace("__LINKS__", js(links))
        .replace("__HOSTS__", js(host_ip_settings()))
        .replace("__CONFIGS__", js(configs))
        .replace("__CORE_ACLS__", js(core_acls))
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--write", action="store_true")
    group.add_argument("--check", action="store_true")
    args = parser.parse_args()
    text = render()
    if args.write:
        OUTPUT.write_text(text, encoding="utf-8")
        print(f"wrote {OUTPUT.relative_to(ROOT)}")
    elif args.check:
        if not OUTPUT.exists() or OUTPUT.read_text(encoding="utf-8") != text:
            print(f"{OUTPUT.relative_to(ROOT)} is out of date. Run: python3 project-01-network/tools/build_ptbuilder_script.py --write")
            return 1
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
