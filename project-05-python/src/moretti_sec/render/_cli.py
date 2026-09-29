"""Shared --write / --check command line for renderers that turn data/ into a generated file."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable
from pathlib import Path

import yaml

from ..company import find_data_dir


class PolicyError(ValueError):
    """data/ contains something the target platform cannot enforce as written."""


def load_yaml(path: Path):
    with path.open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def to_json(document: dict) -> str:
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


def run(
    description: str,
    output: Path,
    render: Callable[[Path], dict],
    argv: list[str] | None = None,
) -> int:
    """Render from data/ and write `output` (repository-relative), or check it is up to date."""
    parser = argparse.ArgumentParser(description=description)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true", help="regenerate the output file")
    mode.add_argument("--check", action="store_true", help="fail if the output is out of date")
    parser.add_argument("--data-dir", type=Path, help="path to data/ (default: auto-detect)")
    args = parser.parse_args(argv)

    data_dir = args.data_dir or find_data_dir()
    target = data_dir.parent / output
    try:
        expected = to_json(render(data_dir))
    except PolicyError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    if args.check:
        current = target.read_text(encoding="utf-8") if target.is_file() else ""
        if current != expected:
            print(f"{output} is out of date: regenerate it with --write", file=sys.stderr)
            return 1
        print(f"{output} is up to date")
        return 0
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(expected, encoding="utf-8")
    print(f"wrote {output}")
    return 0
