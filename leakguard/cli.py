"""Package entrypoint for leakguard CLI."""

import sys
from pathlib import Path

# Ensure root path is imported
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from cli import main, build_parser, scan_target, discover_python_files

if __name__ == "__main__":
    sys.exit(main())
