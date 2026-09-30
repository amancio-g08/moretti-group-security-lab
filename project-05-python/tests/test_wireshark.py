"""Checks of the Wireshark plugin (project-02-pcap/wireshark).

1. The generated Lua policy table matches data/.
2. Differential test: the Lua engine and an independent Python evaluator of the matrix give the
   same verdict for every flow between lab addresses, in both environments.
3. End to end: tshark with the plugin labels a SYNTHETIC capture as expected.

Tests 2 and 3 need lua5.4 and tshark; they are skipped when the tools are missing, except in CI
(MORETTI_REQUIRE_WIRESHARK=1). Wireshark refuses to run Lua scripts as root, so test 3 is also
skipped for root.
"""

import importlib.util
import ipaddress
import os
import shutil
import subprocess

import pytest
import yaml
from conftest import REPO_DATA

from moretti_sec.render.wireshark_policy import main

REPO = REPO_DATA.parent
PLUGIN = REPO / "project-02-pcap/wireshark"
LUA = shutil.which("lua5.4") or shutil.which("lua")
TSHARK = shutil.which("tshark")
# CI sets this, so a missing tool fails the build instead of skipping the test silently.
REQUIRED = os.environ.get("MORETTI_REQUIRE_WIRESHARK") == "1"

DRIVER = """
local engine = dofile(arg[1] .. "/policy_engine.lua")
local policy = dofile(arg[1] .. "/moretti_policy.lua")
local evaluators = { pt = engine.new(policy, "pt"), aws = engine.new(policy, "aws") }
for line in io.lines() do
  local env, src, dst, proto, port = line:match("^(%S+) (%S+) (%S+) (%S+) (%S+)$")
  local action, rule = evaluators[env].verdict(src, dst, proto, tonumber(port))
  io.write(action, " ", rule, "\\n")
end
"""


def test_generated_policy_is_up_to_date():
    assert main(["--check", "--data-dir", str(REPO_DATA)]) == 0


# ---------------------------------------------------------------------------- reference evaluator
class Reference:
    """Evaluates the matrix straight from the YAML, without the renderer's code."""

    PRIVATE = tuple(
        ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
    )

    def __init__(self, env):
        matrix = yaml.safe_load((REPO_DATA / "network-matrix.yaml").read_text(encoding="utf-8"))
        assets = yaml.safe_load((REPO_DATA / "assets.yaml").read_text(encoding="utf-8"))["assets"]
        self.segments = {
            s["id"]: ipaddress.ip_network(s["cidr"])
            for s in matrix["segments"]
            if env in s["environments"] and s.get("cidr")
        }
        self.groups = {g["id"]: g["segments"] for g in matrix["segment_groups"]}
        self.assets = {a["id"]: a["ip"] for a in assets if env in a["environments"]}
        self.services = {s["id"]: s["ports"] for s in matrix["services"]}
        self.rules = [r for r in matrix["rules"] if env in r["applies_to"]]
        self.default = matrix["default_action"]
        self._cache = {}

    def matches(self, ref, address):
        key = (ref, address)
        if key not in self._cache:
            self._cache[key] = self._matches(ref, address)
        return self._cache[key]

    def _matches(self, ref, address):
        if ref == "internet":
            return not any(address in net for net in self.PRIVATE)
        kind, _, name = ref.partition(":")
        if kind == "asset":
            return name in self.assets and address == ipaddress.ip_address(self.assets[name])
        names = [name] if kind == "seg" else self.groups[name]
        return any(n in self.segments and address in self.segments[n] for n in names)

    def service(self, name, proto, port):
        for entry in self.services[name]:
            if entry["proto"] == "any":
                return True
            if entry["proto"] != proto:
                continue
            if proto == "icmp" or entry["port"] == "any":
                return True
            low, _, high = str(entry["port"]).partition("-")
            if int(low) <= port <= int(high or low):
                return True
        return False

    def verdict(self, src, dst, proto, port):
        s, d = ipaddress.ip_address(src), ipaddress.ip_address(dst)
        for rule in self.rules:
            if (
                any(self.matches(r, s) for r in rule["source"])
                and any(self.matches(r, d) for r in rule["destination"])
                and self.service(rule["service"], proto, port)
            ):
                return rule["action"], rule["id"]
        return self.default, "default"


def _flows():
    matrix = yaml.safe_load((REPO_DATA / "network-matrix.yaml").read_text(encoding="utf-8"))
    assets = yaml.safe_load((REPO_DATA / "assets.yaml").read_text(encoding="utf-8"))["assets"]
    addresses = {a["ip"] for a in assets if a.get("ip")}
    for segment in matrix["segments"]:
        if segment.get("cidr"):  # one address per segment that is not an asset (DHCP range)
            addresses.add(str(ipaddress.ip_network(segment["cidr"]).network_address + 150))
    addresses |= {"198.51.100.10", "203.0.113.50", "192.168.1.20"}
    ports = {22, 8080, 50000}
    for service in matrix["services"]:
        for entry in service["ports"]:
            if str(entry["port"]).split("-")[0].isdigit():
                ports.add(int(str(entry["port"]).split("-")[0]))
    for src in sorted(addresses):
        for dst in sorted(addresses):
            if src == dst:
                continue
            yield src, dst, "icmp", 0
            for port in sorted(ports):
                yield src, dst, "tcp", port
                yield src, dst, "udp", port


@pytest.mark.skipif(LUA is None and not REQUIRED, reason="lua interpreter not installed")
def test_lua_engine_agrees_with_reference_evaluator(tmp_path):
    driver = tmp_path / "driver.lua"
    driver.write_text(DRIVER, encoding="utf-8")
    flows = list(_flows())
    lines, expected = [], []
    for env in ("pt", "aws"):
        reference = Reference(env)
        for src, dst, proto, port in flows:
            lines.append(f"{env} {src} {dst} {proto} {port}")
            expected.append(" ".join(reference.verdict(src, dst, proto, port)))
    result = subprocess.run(
        [LUA, str(driver), str(PLUGIN)],
        input="\n".join(lines) + "\n",
        capture_output=True,
        text=True,
        check=True,
    )
    got = result.stdout.splitlines()
    mismatches = [
        (line, want, have)
        for line, want, have in zip(lines, expected, got, strict=False)
        if want != have
    ]
    assert len(got) == len(expected)
    assert mismatches == [], mismatches[:10]
    assert len(expected) > 50_000  # the comparison really covered the matrix


# ---------------------------------------------------------------------------- end to end
def _load_pcap_builder():
    path = REPO / "project-02-pcap/tests/make_synthetic_pcap.py"
    spec = importlib.util.spec_from_file_location("make_synthetic_pcap", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.skipif(TSHARK is None and not REQUIRED, reason="tshark not installed")
@pytest.mark.skipif(os.geteuid() == 0, reason="Wireshark does not run Lua plugins as root")
@pytest.mark.parametrize("environment", ["aws", "pt"])
def test_tshark_labels_the_synthetic_capture(tmp_path, environment):
    builder = _load_pcap_builder()
    capture = tmp_path / "synthetic.pcap"
    builder.write(capture)
    fields = ["frame.number", "moretti.verdict", "moretti.rule", "moretti.flow"]
    result = subprocess.run(
        [TSHARK, "-r", str(capture), "-X", f"lua_script:{PLUGIN / 'moretti.lua'}",
         "-o", f"moretti.environment:{environment}", "-T", "fields", "-E", "separator=,",
         *[arg for field in fields for arg in ("-e", field)]],
        capture_output=True, text=True, check=True,
    )  # fmt: skip
    rows = [line.split(",") for line in result.stdout.splitlines()]
    assert len(rows) == len(builder.PACKETS)
    for row, packet in zip(rows, builder.PACKETS, strict=True):
        verdict, rule = packet[7][environment]
        assert row[1:] == [verdict, rule, packet[8]], packet[0]


def test_synthetic_capture_is_labeled_and_uses_lab_addresses():
    builder = _load_pcap_builder()
    assert "SYNTHETIC" in builder.__doc__
    lab = ipaddress.ip_network("10.10.0.0/16")
    documentation = [ipaddress.ip_network(n) for n in ("198.51.100.0/24", "203.0.113.0/24")]
    for packet in builder.PACKETS:
        for address in (packet[2], packet[4]):
            ip = ipaddress.ip_address(address)
            assert ip in lab or any(ip in net for net in documentation), address
