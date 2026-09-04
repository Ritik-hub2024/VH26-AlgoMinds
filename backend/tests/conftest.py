import sys
from pathlib import Path

# Ensure backend package is in sys.path during test runs
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))
