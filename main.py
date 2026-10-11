"""CLI entry point.

Thin wrapper so ``python main.py ...`` keeps working from the repository root
without an editable install. The full pipeline lives in ``ids.pipeline``.
"""

import sys
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from ids.pipeline import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
