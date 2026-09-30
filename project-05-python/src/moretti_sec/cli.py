"""Command line interface: `moretti-sec analyze` and `moretti-sec ioc`."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import timedelta
from pathlib import Path

from . import __version__, correlate
from .company import Company, find_data_dir
from .detections import BruteForceConfig, run_all
from .enrich import enrich
from .ioc import extract_iocs
from .parsers import FORMATS, parse_file
from .parsers.flowlog import parse_flowlog
from .parsers.wazuh_alerts import parse_wazuh_alerts
from .report import render_markdown, render_timeline_markdown


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    return args.func(args)


def _analyze(args: argparse.Namespace) -> int:
    company = Company.load(args.data_dir or find_data_dir())
    events = []
    for path in args.logs:
        events.extend(parse_file(path, fmt=args.format, year=args.year))
    enriched = enrich(events, company)
    findings = run_all(enriched, BruteForceConfig(args.threshold, timedelta(minutes=args.window)))
    report = render_markdown(enriched, findings, [p.name for p in args.logs])
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(report, encoding="utf-8")
        print(f"{len(enriched)} events, {len(findings)} findings -> {args.report}")
    else:
        print(report)
    return 0


def _read(paths, parser, **kwargs):
    items = []
    for path in paths or []:
        items.extend(parser(path.read_text(encoding="utf-8").splitlines(), **kwargs))
    return items


def _correlate(args: argparse.Namespace) -> int:
    company = Company.load(args.data_dir or find_data_dir())
    auth = _read(args.auth, _sshd_or_windows, year=args.year)
    flows = _read(args.flow, parse_flowlog)
    alerts = _read(args.wazuh, parse_wazuh_alerts)
    if not (auth or flows or alerts):
        print("nothing to correlate: pass --auth, --flow and/or --wazuh", file=sys.stderr)
        return 2
    timeline = correlate.build(company, auth=auth, flows=flows, alerts=alerts)
    names = [p.name for group in (args.auth, args.flow, args.wazuh) if group for p in group]
    report = render_timeline_markdown(timeline, names)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(report, encoding="utf-8")
        print(f"{len(timeline)} timeline items -> {args.report}")
    else:
        print(report)
    return 0


def _sshd_or_windows(lines, year=None):
    from .parsers import detect_format, parse_sshd, parse_windows

    if detect_format(lines) == "windows":
        return parse_windows(lines)
    return parse_sshd(lines, year=year)


def _ioc(args: argparse.Namespace) -> int:
    text = args.file.read_text(encoding="utf-8") if args.file else sys.stdin.read()
    print(json.dumps(extract_iocs(text), indent=2))
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="moretti-sec", description="Moretti Group lab security automation (fictitious)."
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(required=True)

    analyze = sub.add_parser("analyze", help="analyze authentication logs and write a report")
    analyze.add_argument("logs", nargs="+", type=Path, help="log files (sshd syslog, Windows JSON)")
    analyze.add_argument("--format", choices=sorted(FORMATS), help="force a format for all files")
    analyze.add_argument("--year", type=int, help="year for syslog lines without one")
    analyze.add_argument("--data-dir", type=Path, help="path to data/ (default: auto-detect)")
    analyze.add_argument(
        "--threshold", type=int, default=5, help="failures that count as brute force"
    )
    analyze.add_argument("--window", type=int, default=10, help="brute force window, in minutes")
    analyze.add_argument("--report", type=Path, help="write the Markdown report to this file")
    analyze.set_defaults(func=_analyze)

    corr = sub.add_parser(
        "correlate", help="merge auth logs, Flow Logs and Wazuh alerts into a timeline"
    )
    corr.add_argument("--auth", type=Path, action="append", help="sshd or Windows log (repeatable)")
    corr.add_argument("--flow", type=Path, action="append", help="VPC Flow Log file (repeatable)")
    corr.add_argument("--wazuh", type=Path, action="append", help="Wazuh alerts.json (repeatable)")
    corr.add_argument("--year", type=int, help="year for syslog lines without one")
    corr.add_argument("--data-dir", type=Path, help="path to data/ (default: auto-detect)")
    corr.add_argument("--report", type=Path, help="write the Markdown timeline to this file")
    corr.set_defaults(func=_correlate)

    ioc = sub.add_parser("ioc", help="extract indicators of compromise from text (JSON output)")
    ioc.add_argument("file", nargs="?", type=Path, help="text file (default: standard input)")
    ioc.set_defaults(func=_ioc)
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
