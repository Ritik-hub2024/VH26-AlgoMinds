"""
LeakGuard multi-command runner.

Handles commands like:
  python run.py
  python run app.py
  python run demo
  python run test
  python run cli.py python/
"""

import sys
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def main():
    args = sys.argv[1:]

    # Jury demo command
    if args and args[0] in ("demo", "jury", "jury-demo"):
        import demo
        sys.exit(demo.main())

    # Dashboard / web commands
    if not args or any(a in ("app.py", "app.js", "dev", "web", "dashboard", "server", "start") for a in args):
        import app
        sys.exit(app.main())

    # Test commands
    if args[0] in ("test", "tests", "pytest"):
        cmd = [sys.executable, "-m", "pytest", "tests/", "-v"] + args[1:]
        sys.exit(subprocess.call(cmd))

    # Direct CLI scan
    if args[0] in ("cli.py", "cli", "scan"):
        import cli
        sys.exit(cli.main(args[1:]))

    # Pass-through to cli.py
    import cli
    sys.exit(cli.main(args))


if __name__ == "__main__":
    main()
