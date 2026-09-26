"""Company context loaded from data/, the lab's source of truth (ADR-001)."""

from __future__ import annotations

import csv
import ipaddress
import os
from dataclasses import dataclass
from pathlib import Path

import yaml

from .models import AccountContext, IpContext

DATA_DIR_ENV = "MORETTI_DATA_DIR"


def find_data_dir(start: Path | None = None) -> Path:
    """Return data/ from $MORETTI_DATA_DIR or the nearest parent that contains it."""
    env = os.environ.get(DATA_DIR_ENV)
    if env:
        return Path(env)
    here = (start or Path.cwd()).resolve()
    for directory in (here, *here.parents):
        candidate = directory / "data"
        if (candidate / "company.yaml").is_file():
            return candidate
    raise FileNotFoundError(f"data/ not found; set {DATA_DIR_ENV} or run inside the repository")


def normalize_username(raw: str | None) -> str | None:
    """'CORP\\Alan.Moreira', 'alan.moreira@corp.moretti.internal' -> 'alan.moreira'."""
    if raw is None:
        return None
    name = raw.strip()
    if not name or name == "-":
        return None
    name = name.rsplit("\\", 1)[-1].split("@", 1)[0]
    return name.lower() or None


@dataclass
class Company:
    assets_by_ip: dict[str, str]
    segments: list[tuple[str, ipaddress.IPv4Network]]
    accounts: dict[str, AccountContext]

    @classmethod
    def load(cls, data_dir: Path | None = None) -> Company:
        data_dir = data_dir or find_data_dir()
        assets = _yaml(data_dir / "assets.yaml")["assets"]
        matrix = _yaml(data_dir / "network-matrix.yaml")
        assets_by_ip = {a["ip"]: a["id"] for a in assets if a.get("ip")}
        segments = [
            (s["id"], ipaddress.ip_network(s["cidr"])) for s in matrix["segments"] if s.get("cidr")
        ]
        # Most specific network first, so a /30 inside a /24 would win.
        segments.sort(key=lambda item: item[1].prefixlen, reverse=True)
        return cls(assets_by_ip, segments, _load_accounts(data_dir))

    def ip_context(self, ip: str | None) -> IpContext | None:
        if not ip:
            return None
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return None
        segment = next((sid for sid, net in self.segments if address in net), None)
        return IpContext(ip=ip, asset_id=self.assets_by_ip.get(ip), segment=segment)

    def account(self, username: str | None) -> AccountContext | None:
        name = normalize_username(username)
        if name is None:
            return None
        return self.accounts.get(name, AccountContext(username=name, kind="unknown"))

    def asset_by_hostname(self, host: str) -> str | None:
        wanted = host.split(".", 1)[0].upper()
        return wanted if wanted in self.assets_by_ip.values() else None


def _yaml(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def _load_accounts(data_dir: Path) -> dict[str, AccountContext]:
    employees: dict[str, dict] = {}
    with (data_dir / "employees.csv").open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            employees[row["employee_id"]] = row

    accounts: dict[str, AccountContext] = {}
    for row in employees.values():
        accounts[row["username"].lower()] = _employee_account(row["username"], "employee", row)

    extra = _yaml(data_dir / "accounts.yaml")
    for item in extra.get("admin_accounts", []):
        owner = employees.get(item["owner"], {})
        accounts[item["username"].lower()] = _employee_account(item["username"], "admin", owner)
    for item in extra.get("service_accounts", []):
        accounts[item["username"].lower()] = AccountContext(
            username=item["username"].lower(),
            kind="service",
            department=item.get("owner"),
            interactive_logon=bool(item.get("interactive_logon", False)),
        )
    for item in extra.get("break_glass_accounts", []):
        accounts[item["username"].lower()] = AccountContext(
            username=item["username"].lower(), kind="break-glass", department=item.get("owner")
        )
    return accounts


def _employee_account(username: str, kind: str, row: dict) -> AccountContext:
    return AccountContext(
        username=username.lower(),
        kind=kind,
        employee_id=row.get("employee_id"),
        department=row.get("department"),
        status=row.get("status"),
        employment_type=row.get("employment_type"),
        end_date=row.get("end_date") or None,
    )
