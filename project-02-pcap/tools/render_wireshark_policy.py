"""Regenerate the Wireshark policy table from data/ (wrapper around the moretti_sec renderer).

python project-02-pcap/tools/render_wireshark_policy.py --write   # regenerate
python project-02-pcap/tools/render_wireshark_policy.py --check   # fail if out of date
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "project-05-python" / "src"))

from moretti_sec.render.wireshark_policy import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main([*sys.argv[1:], "--data-dir", str(ROOT / "data")]))
