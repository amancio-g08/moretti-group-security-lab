"""Regenerate the Active Directory plan from data/ (wrapper around the moretti_sec renderer).

    python project-04-iam/tools/render_ad_plan.py --write   # regenerate
    python project-04-iam/tools/render_ad_plan.py --check   # fail if out of date
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "project-05-python" / "src"))

from moretti_sec.render.ad_plan import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main([*sys.argv[1:], "--data-dir", str(ROOT / "data")]))
