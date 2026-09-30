"""Network matrix -> policy table for the Wireshark plugin (project-02-pcap/wireshark).

The plugin labels every packet with the asset and segment at each end and with the matrix
verdict for the flow. It cannot read YAML, so this renderer resolves the matrix into a plain Lua
table: per environment ("pt" or "aws"), the ordered rules with their sources and destinations
expanded to networks and their services expanded to protocol and port ranges.

Only segments and assets that exist in an environment are used for its rules, exactly as the
core ACL generator (pt) and the Security Group renderer (aws) do. "internet" stays symbolic: the
plugin matches it against any non-private address.

Run from the repository root:
    python project-02-pcap/tools/render_wireshark_policy.py --write   # regenerate
    python project-02-pcap/tools/render_wireshark_policy.py --check   # fail if out of date
"""

from __future__ import annotations

import ipaddress
from pathlib import Path

from ._cli import PolicyError, load_yaml, run_files

OUTPUT = Path("project-02-pcap/wireshark/moretti_policy.lua")
ENVIRONMENTS = ("pt", "aws")


def _ports(entry: dict) -> dict:
    proto, port = entry["proto"], entry["port"]
    if proto == "any":
        return {"proto": "any", "lo": 0, "hi": 65535}
    if proto == "icmp" or port == "any":
        return {"proto": proto, "lo": 0, "hi": 65535}
    low, _, high = str(port).partition("-")
    return {"proto": proto, "lo": int(low), "hi": int(high or low)}


def resolve(ref: str, env: str, matrix: dict, assets: list[dict]) -> list[dict]:
    """A matrix reference as endpoints: {"internet": True} or {"net": ..., "bits": ...}."""
    if ref == "internet":
        return [{"internet": True}]
    kind, _, name = ref.partition(":")
    segments = {
        s["id"]: s for s in matrix["segments"] if env in s["environments"] and s.get("cidr")
    }
    if kind == "seg":
        names = [name]
    elif kind == "grp":
        groups = {g["id"]: g["segments"] for g in matrix.get("segment_groups", [])}
        if name not in groups:
            raise PolicyError(f"unknown segment group {name!r}")
        names = groups[name]
    elif kind == "asset":
        host = next((a for a in assets if a["id"] == name and env in a["environments"]), None)
        return [{"net": host["ip"], "bits": 32}] if host else []
    else:
        raise PolicyError(f"unknown reference {ref!r}")
    endpoints = []
    for segment in names:
        if segment in segments:
            network = ipaddress.ip_network(segments[segment]["cidr"])
            endpoints.append({"net": str(network.network_address), "bits": network.prefixlen})
    return endpoints


def render(matrix: dict, assets: list[dict]) -> dict:
    services = {s["id"]: [_ports(p) for p in s["ports"]] for s in matrix["services"]}
    rules = {}
    for env in ENVIRONMENTS:
        rules[env] = [
            {
                "id": rule["id"],
                "action": rule["action"],
                "src": [e for ref in rule["source"] for e in resolve(ref, env, matrix, assets)],
                "dst": [
                    e for ref in rule["destination"] for e in resolve(ref, env, matrix, assets)
                ],
                "ports": services[rule["service"]],
            }
            for rule in matrix["rules"]
            if env in rule["applies_to"]
        ]
    return {
        "default_action": matrix["default_action"],
        "segments": [
            {"id": s["id"], "net": str(net.network_address), "bits": net.prefixlen}
            for s in matrix["segments"]
            if s.get("cidr")
            for net in [ipaddress.ip_network(s["cidr"])]
        ],
        "assets": [
            {"id": a["id"], "ip": a["ip"], "segment": a["segment"]}
            for a in sorted(assets, key=lambda a: ipaddress.ip_address(a["ip"]))
            if a.get("ip")
        ],
        "rules": rules,
    }


def to_lua(value, indent: str = "") -> str:
    """Lua table constructor for JSON-like data (dicts, lists, strings, numbers, booleans)."""
    inner = indent + "  "
    if isinstance(value, dict):
        if not value:
            return "{}"
        items = [f"{inner}{key} = {to_lua(item, inner)}," for key, item in value.items()]
        return "{\n" + "\n".join(items) + f"\n{indent}}}"
    if isinstance(value, list):
        if not value:
            return "{}"
        if all(isinstance(item, dict) and len(item) <= 4 for item in value):
            items = [f"{inner}{_inline(item)}," for item in value]
        else:
            items = [f"{inner}{to_lua(item, inner)}," for item in value]
        return "{\n" + "\n".join(items) + f"\n{indent}}}"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
    raise PolicyError(f"cannot write {type(value).__name__} to Lua")


def _inline(item: dict) -> str:
    return "{ " + ", ".join(f"{key} = {to_lua(value)}" for key, value in item.items()) + " }"


def render_from(data_dir: Path) -> dict[Path, str]:
    matrix = load_yaml(data_dir / "network-matrix.yaml")
    assets = load_yaml(data_dir / "assets.yaml")["assets"]
    header = (
        "-- GENERATED from data/network-matrix.yaml and data/assets.yaml by\n"
        "-- project-02-pcap/tools/render_wireshark_policy.py. Do not edit.\n"
    )
    return {OUTPUT: header + "return " + to_lua(render(matrix, assets)) + "\n"}


def main(argv: list[str] | None = None) -> int:
    return run_files(__doc__.splitlines()[0], render_from, argv)


if __name__ == "__main__":
    raise SystemExit(main())
