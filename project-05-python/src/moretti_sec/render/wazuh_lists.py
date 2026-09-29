"""Company data -> Wazuh CDB lists (ADR-001; design: project-03-soc/documentation/soc-design.md).

The custom Wazuh rules (project-03-soc/detections/rules) look account names up in these lists,
so an alert about a terminated employee, a break-glass account or a service account follows
data/ automatically. Each file has one "key:value" line per account: the account name as Active
Directory stores it (lowercase), and who it belongs to.

Run from the repository root:
    python project-03-soc/tools/render_wazuh_lists.py --write   # regenerate
    python project-03-soc/tools/render_wazuh_lists.py --check   # fail if out of date
"""

from __future__ import annotations

import csv
from pathlib import Path

from ._cli import PolicyError, load_yaml, run_files

LIST_DIR = Path("project-03-soc/detections/lists")
LISTS = (
    "moretti-terminated-accounts",
    "moretti-on-leave-accounts",
    "moretti-break-glass-accounts",
    "moretti-service-accounts",
    "moretti-admin-accounts",
)


def render(accounts: dict, employees: list[dict]) -> dict[str, dict[str, str]]:
    """List name -> {account name: value}."""
    by_id = {e["employee_id"]: e for e in employees}
    lists: dict[str, dict[str, str]] = {name: {} for name in LISTS}

    for emp in employees:
        if emp["status"] == "terminated":
            lists["moretti-terminated-accounts"][emp["username"]] = emp["employee_id"]
        elif emp["status"] == "on_leave":
            lists["moretti-on-leave-accounts"][emp["username"]] = emp["employee_id"]

    for item in accounts.get("admin_accounts", []):
        owner = by_id.get(item["owner"])
        if owner is None:
            raise PolicyError(f"{item['username']}: unknown owner {item['owner']}")
        lists["moretti-admin-accounts"][item["username"]] = item["owner"]
        # An admin account of someone who left must not be used either (it is disabled in AD).
        if owner["status"] == "terminated":
            lists["moretti-terminated-accounts"][item["username"]] = item["owner"]

    for item in accounts.get("break_glass_accounts", []):
        lists["moretti-break-glass-accounts"][item["username"]] = item["owner"]

    for item in accounts.get("service_accounts", []):
        name = item["username"] + ("$" if item.get("type") == "gmsa" else "")
        lists["moretti-service-accounts"][name] = item["owner"]

    for name, entries in lists.items():
        for key in entries:
            if key != key.lower() or ":" in key or not key:
                raise PolicyError(f"{name}: invalid account name {key!r}")
    return lists


def to_cdb(entries: dict[str, str]) -> str:
    return "".join(f"{key}:{value}\n" for key, value in sorted(entries.items()))


def render_from(data_dir: Path) -> dict[Path, str]:
    with (data_dir / "employees.csv").open(encoding="utf-8", newline="") as handle:
        employees = list(csv.DictReader(handle))
    lists = render(load_yaml(data_dir / "accounts.yaml"), employees)
    return {LIST_DIR / name: to_cdb(entries) for name, entries in lists.items()}


def main(argv: list[str] | None = None) -> int:
    return run_files(__doc__.splitlines()[0], render_from, argv)


if __name__ == "__main__":
    raise SystemExit(main())
