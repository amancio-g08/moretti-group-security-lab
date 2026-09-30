#!/usr/bin/env python3
"""Write a SYNTHETIC capture for the Wireshark plugin: hand-built packets, no real traffic.

    python3 project-02-pcap/tests/make_synthetic_pcap.py /tmp/moretti-demo.pcap

Every packet in PACKETS carries the verdict, rule and flow role the plugin must show, so the same
list drives the end-to-end test (project-05-python/tests/test_wireshark.py) and the demo capture
described in project-02-pcap/documentation/wireshark-plugin.md. Addresses are lab addresses
(data/assets.yaml) or documentation ranges; nothing here was captured from a network.
"""

from __future__ import annotations

import socket
import struct
import sys
from pathlib import Path

SYN, ACK, PSH, RST = 0x02, 0x10, 0x08, 0x04

# (description, protocol, src, sport, dst, dport, TCP flags or ICMP type,
#  expected {environment: (verdict, rule)}, expected flow role)
PACKETS = [
    (
        "SCN-04: guest tries SMB on a finance workstation",
        "tcp",
        "10.10.90.10",
        50120,
        "10.10.20.10",
        445,
        SYN,
        {"aws": ("deny", "NM-004"), "pt": ("deny", "NM-004")},
        "initiator",
    ),
    (
        "finance opens a web site",
        "tcp",
        "10.10.20.10",
        50200,
        "198.51.100.10",
        443,
        SYN,
        {"aws": ("allow", "NM-070"), "pt": ("allow", "NM-070")},
        "initiator",
    ),
    (
        "web site answers",
        "tcp",
        "198.51.100.10",
        443,
        "10.10.20.10",
        50200,
        SYN | ACK,
        {"aws": ("allow", "NM-070"), "pt": ("allow", "NM-070")},
        "reply",
    ),
    (
        "finance continues the connection",
        "tcp",
        "10.10.20.10",
        50200,
        "198.51.100.10",
        443,
        ACK | PSH,
        {"aws": ("allow", "NM-070"), "pt": ("allow", "NM-070")},
        "initiator",
    ),
    (
        "development tries the finance application",
        "tcp",
        "10.10.50.10",
        50300,
        "10.10.80.30",
        443,
        SYN,
        {"aws": ("deny", "NM-026"), "pt": ("deny", "NM-026")},
        "initiator",
    ),
    (
        "finance asks DC01 for a name",
        "udp",
        "10.10.20.10",
        53000,
        "10.10.80.10",
        53,
        None,
        {"aws": ("allow", "NM-010"), "pt": ("allow", "NM-010")},
        "initiator",
    ),
    (
        "DC01 answers",
        "udp",
        "10.10.80.10",
        53,
        "10.10.20.10",
        53000,
        None,
        {"aws": ("allow", "NM-010"), "pt": ("allow", "NM-010")},
        "reply",
    ),
    (
        "SMB already in progress when the capture started",
        "tcp",
        "10.10.50.10",
        50400,
        "10.10.80.10",
        445,
        ACK | PSH,
        {"aws": ("allow", "NM-010"), "pt": ("allow", "NM-010")},
        "untracked",
    ),
    (
        "guest pings a developer workstation",
        "icmp",
        "10.10.90.10",
        None,
        "10.10.50.10",
        None,
        8,
        {"aws": ("deny", "NM-004"), "pt": ("deny", "NM-004")},
        "initiator",
    ),
    (
        "the workstation replies",
        "icmp",
        "10.10.50.10",
        None,
        "10.10.90.10",
        None,
        0,
        {"aws": ("deny", "NM-004"), "pt": ("deny", "NM-004")},
        "reply",
    ),
    (
        "IT pings the finance application",
        "icmp",
        "10.10.60.10",
        None,
        "10.10.80.30",
        None,
        8,
        {"aws": ("deny", "default"), "pt": ("allow", "NM-080")},
        "initiator",
    ),
]


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def _packet(proto: str, src: str, sport, dst: str, dport, flags, seq: int) -> bytes:
    s, d = socket.inet_aton(src), socket.inet_aton(dst)
    if proto == "tcp":
        header = struct.pack("!HHIIBBHHH", sport, dport, seq, 0, 5 << 4, flags, 64240, 0, 0)
        pseudo = s + d + struct.pack("!BBH", 0, 6, len(header))
        payload = header[:16] + struct.pack("!H", _checksum(pseudo + header)) + header[18:]
        number = 6
    elif proto == "udp":
        data = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"  # a DNS header, no question
        header = struct.pack("!HHHH", sport, dport, 8 + len(data), 0)
        pseudo = s + d + struct.pack("!BBH", 0, 17, len(header) + len(data))
        payload = header[:6] + struct.pack("!H", _checksum(pseudo + header + data)) + data
        number = 17
    else:
        body = struct.pack("!BBHHH", flags, 0, 0, 0x4D47, seq) + b"moretti-lab"
        payload = body[:2] + struct.pack("!H", _checksum(body)) + body[4:]
        number = 1
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), seq, 0, 64, number, 0, s, d)
    ip = ip[:10] + struct.pack("!H", _checksum(ip)) + ip[12:]
    ethernet = b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01" + b"\x08\x00"
    return ethernet + ip + payload


def write(path: Path) -> None:
    records = [struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)]  # pcap, Ethernet
    for index, (_, proto, src, sport, dst, dport, flags, _, _) in enumerate(PACKETS, 1):
        frame = _packet(proto, src, sport, dst, dport, flags, index)
        records.append(struct.pack("<IIII", 1790000000 + index, 0, len(frame), len(frame)) + frame)
    path.write_bytes(b"".join(records))


if __name__ == "__main__":
    target = Path(sys.argv[1] if len(sys.argv) > 1 else "moretti-synthetic.pcap")
    write(target)
    print(f"wrote {target} ({len(PACKETS)} SYNTHETIC packets)")
