"""Regenerate the Wazuh CDB lists from data/ (wrapper around the moretti_sec renderer).

python project-03-soc/tools/render_wazuh_lists.py --write   # regenerate
python project-03-soc/tools/render_wazuh_lists.py --check   # fail if out of date
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "project-05-python" / "src"))

from moretti_sec.render.wazuh_lists import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main([*sys.argv[1:], "--data-dir", str(ROOT / "data")]))
