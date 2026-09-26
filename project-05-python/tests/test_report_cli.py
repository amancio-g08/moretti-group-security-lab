from pathlib import Path

from conftest import REPO_DATA

from moretti_sec.cli import main

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def test_cli_reproduces_the_committed_sample_report(tmp_path):
    report = tmp_path / "report.md"
    logs = sorted(str(p) for p in (EXAMPLES / "logs").iterdir())
    assert (
        main(
            [
                "analyze",
                *logs,
                "--year",
                "2026",
                "--data-dir",
                str(REPO_DATA),
                "--report",
                str(report),
            ]
        )
        == 0
    )
    expected = (EXAMPLES / "reports" / "sample-auth-report.md").read_text(encoding="utf-8")
    assert report.read_text(encoding="utf-8") == expected


def test_cli_ioc(tmp_path, capsys):
    text = tmp_path / "ticket.txt"
    text.write_text("SYNTHETIC: callback to 198.51.100[.]66", encoding="utf-8")
    assert main(["ioc", str(text)]) == 0
    assert '"198.51.100.66"' in capsys.readouterr().out
