"""Command line interface: `moretti-sec analyze` and `moretti-sec ioc`."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import timedelta
from pathlib import Path

from . import __version__
from .company import Company, find_data_dir
from .detections import BruteForceConfig, run_all
from .enrich import enrich
from .ioc import extract_iocs
from .parsers import FORMATS, parse_file
from .report import render_markdown


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

    ioc = sub.add_parser("ioc", help="extract indicators of compromise from text (JSON output)")
    ioc.add_argument("file", nargs="?", type=Path, help="text file (default: standard input)")
    ioc.set_defaults(func=_ioc)
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
