"""Regenerate the Entra ID Conditional Access policies from data/ (wrapper around the moretti_sec renderer).

python project-02-pcap/tools/render_conditional_access.py --write   # regenerate
python project-02-pcap/tools/render_conditional_access.py --check   # fail if out of date
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "project-05-python" / "src"))

from moretti_sec.render.conditional_access import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main([*sys.argv[1:], "--data-dir", str(ROOT / "data")]))
