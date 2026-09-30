"""Network matrix -> expected reachability table for the Nmap NSE segmentation audit.

For each ordered pair of AWS hosts and each TCP service the matrix knows, this records whether the
matrix allows the destination port (allow / deny, with the deciding rule). The NSE script
(project-02-pcap/nse/moretti-segmentation.nse) runs on a lab host, connects to those ports and
compares what it observes with this table, so a segmentation gap becomes a diff, not a judgement
call in the field.

Only AWS hosts and TCP ports are included: the audit connects with TCP, and the operational lab
is the AWS environment. Run from the repository root:
    python project-02-pcap/tools/render_nse_targets.py --write
    python project-02-pcap/tools/render_nse_targets.py --check
"""

from __future__ import annotations

from pathlib import Path

from ._cli import load_yaml, run_files
from .wireshark_policy import render as render_policy

OUTPUT = Path("project-02-pcap/nse/moretti_targets.lua")
ENV = "aws"


def _tcp_ports(services: list[dict]) -> set[int]:
    ports: set[int] = set()
    for service in services:
        for entry in service["ports"]:
            if entry["proto"] != "tcp":
                continue
            port = entry["port"]
            if isinstance(port, int):
                ports.add(port)
            elif str(port).isdigit():
                ports.add(int(port))
            # port ranges (49152-65535) are not probed one by one
    return ports


def _verdict(engine_rules, src_ip, dst_ip, port):
    """First matching rule wins; ports are matched as the matrix does."""
    for rule in engine_rules:
        if (
            _covers(rule["src"], src_ip)
            and _covers(rule["dst"], dst_ip)
            and _port(rule["ports"], port)
        ):
            return rule["action"], rule["id"]
    return "deny", "default"


def _covers(endpoints, ip):
    import ipaddress

    address = ipaddress.ip_address(ip)
    for e in endpoints:
        if e.get("internet"):
            if not address.is_private:
                return True
        elif address in ipaddress.ip_network(f"{e['net']}/{e['bits']}"):
            return True
    return False


def _port(ports, wanted):
    for p in ports:
        if p["proto"] == "any":
            return True
        if p["proto"] == "tcp" and p["lo"] <= wanted <= p["hi"]:
            return True
    return False


def render(matrix: dict, assets: list[dict]) -> dict:
    policy = render_policy(matrix, assets)
    rules = policy["rules"][ENV]
    hosts = [
        {"id": a["id"], "ip": a["ip"]}
        for a in sorted(assets, key=lambda a: a["ip"])
        if ENV in a["environments"] and a.get("ip")
    ]
    ports = sorted(_tcp_ports(matrix["services"]))
    checks = []
    for src in hosts:
        for dst in hosts:
            if src["id"] == dst["id"]:
                continue
            for port in ports:
                action, rule = _verdict(rules, src["ip"], dst["ip"], port)
                checks.append(
                    {
                        "from_id": src["id"],
                        "from_ip": src["ip"],
                        "to_id": dst["id"],
                        "to_ip": dst["ip"],
                        "port": port,
                        "expected": action,
                        "rule": rule,
                    }
                )
    return {"ports": ports, "checks": checks}


def render_from(data_dir: Path) -> dict[Path, str]:
    from .wireshark_policy import to_lua

    matrix = load_yaml(data_dir / "network-matrix.yaml")
    assets = load_yaml(data_dir / "assets.yaml")["assets"]
    header = (
        "-- GENERATED from data/network-matrix.yaml and data/assets.yaml by\n"
        "-- project-02-pcap/tools/render_nse_targets.py. Do not edit.\n"
    )
    return {OUTPUT: header + "return " + to_lua(render(matrix, assets)) + "\n"}


def main(argv: list[str] | None = None) -> int:
    return run_files(__doc__.splitlines()[0], render_from, argv)


if __name__ == "__main__":
    raise SystemExit(main())
