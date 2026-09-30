"""VPC Flow Logs (version 2), the default space-separated format delivered to S3.

The header line names the fields, so the order is read from it instead of being assumed. Records
whose action is not ACCEPT or REJECT (for example NODATA/SKIPDATA) are ignored. Lines starting
with '#' are ignored, so a sample file can carry a "SYNTHETIC" label.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from datetime import datetime, timezone

from ..models import NetworkFlow

_PROTOCOLS = {"1": "icmp", "6": "tcp", "17": "udp"}
# fmt: off
_DEFAULT_FIELDS = [
    "version", "account-id", "interface-id", "srcaddr", "dstaddr", "srcport", "dstport",
    "protocol", "packets", "bytes", "start", "end", "action", "log-status",
]
# fmt: on


def _int(value: str | None) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def parse_flowlog(lines: Iterable[str]) -> Iterator[NetworkFlow]:
    fields = _DEFAULT_FIELDS
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if parts and parts[0] == "version":
            fields = parts  # a header line redefines the field order for what follows
            continue
        record = dict(zip(fields, parts, strict=False))
        action = record.get("action", "")
        if action not in ("ACCEPT", "REJECT"):
            continue  # NODATA / SKIPDATA carry no flow
        start = _int(record.get("start"))
        yield NetworkFlow(
            timestamp=datetime.fromtimestamp(start or 0, tz=timezone.utc),
            src_ip=record.get("srcaddr") or None,
            dst_ip=record.get("dstaddr") or None,
            src_port=_int(record.get("srcport")),
            dst_port=_int(record.get("dstport")),
            protocol=_PROTOCOLS.get(record.get("protocol", ""), record.get("protocol", "")),
            action=action,
            packets=_int(record.get("packets")) or 0,
            bytes=_int(record.get("bytes")) or 0,
        )
