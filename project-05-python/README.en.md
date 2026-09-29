# Project 05 — Security Automation (Python)

[Português](README.md) | **English**

`moretti-sec` is a command line tool that does an analyst's repetitive work: it reads
authentication logs, matches every event against the company data in `data/` and writes a
Markdown report with what needs attention.

The goal was not just to count failed logons. An alert saying "6 failures from 10.10.50.10" leaves
the analyst to find out whose address and whose account that is. With enrichment, the report
already says the address is **WS-DEV01, in Development**, and that the account belongs to a
**contractor** or a **terminated** employee, based on the lab's source of truth (ADR-001).

**Status:** phase 3 done (core). New log readers come in phases 6 (Wazuh) and 7 (scenarios and
PCAP).

## How it works

```
logs (Linux sshd, Windows events 4624/4625)
  → parsers      → normalized event (time, host, user, IP, outcome)
  → enrichment   → IP becomes asset + segment; user becomes employee, status, account kind
  → detections   → brute force and account misuse
  → timeline + Markdown report
```

## Detections

| Rule | What it detects | Severity |
|---|---|---|
| BF-01 | Brute force: N failures from one IP inside the window (default: 5 in 10 min) | medium (1 account) / high (several) |
| BF-02 | Brute force followed by a successful logon from the same IP | critical |
| ACC-01 | Logon with a terminated employee's account | critical (success) / medium (failure) |
| ACC-02 | Logon by an employee on leave | medium |
| ACC-03 | Contractor logon after the contract end date | high |
| ACC-04 | Break-glass account used | critical |
| ACC-05 | Interactive logon with a service account | high |
| ACC-06 | Privileged account used outside JUMP01 (rule NM-032) | high |

## Usage

```bash
cd project-05-python
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# report from the sample logs
moretti-sec analyze examples/logs/* --year 2026 --report report.md

# extract IOCs from text (defanged indicators such as hxxp and [.] are accepted)
moretti-sec ioc ticket.txt
```

The report generated from the sample logs is
[`examples/reports/sample-auth-report.md`](examples/reports/sample-auth-report.md).

### Exporting Windows logs

The Windows parser reads JSON with the event's own field names. On the domain controller, in
PowerShell:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625} -MaxEvents 5000 |
  ForEach-Object {
    $x = [xml]$_.ToXml(); $d = @{}
    $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    [pscustomobject]@{
      TimeCreated = $_.TimeCreated.ToUniversalTime().ToString('o'); EventID = $_.Id
      Computer = $_.MachineName; TargetUserName = $d.TargetUserName
      TargetDomainName = $d.TargetDomainName; IpAddress = $d.IpAddress; LogonType = $d.LogonType
    }
  } | ConvertTo-Json | Out-File logons.json -Encoding utf8
```

## Tests

```bash
pytest          # 66 tests
ruff check . && ruff format --check .
```

The same commands run in CI (`.github/workflows/ci.yml`) and in `pre-commit`.

## Limitations

- Sample logs and test data are **synthetic**: written by hand, not taken from any real system.
- Context comes from `data/` as it is today. A status change after the event is not reflected.
- Syslog lines carry no year; it comes from `--year` or the current year.

## Layout

```
project-05-python/
├── src/moretti_sec/   # package: parsers, enrichment, detections, IOC, timeline, report, CLI
│   └── render/        # data/ → Security Groups (infrastructure/), AD plan (project-04-iam/) and Wazuh lists (project-03-soc/)
├── tests/             # tests (fixtures labeled as synthetic)
└── examples/          # synthetic logs and the report generated from them
```
