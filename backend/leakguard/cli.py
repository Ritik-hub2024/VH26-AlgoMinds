"""CLI entry point for backend/leakguard."""

import argparse
import os
import sys
import time
from pathlib import Path
from typing import List, Optional, Sequence

_BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

from leakguard.analyzer.leak_analyzer import LeakAnalyzer
from leakguard.models.resource import Resource
from leakguard.parser.python_parser import PythonParser, ParseResult


def discover_files(target_path: Path) -> List[Path]:
    """Recursively collect .py files."""
    if target_path.is_file():
        return [target_path]

    py_files = []
    ignored = {"__pycache__", ".git", ".venv", "venv", "build", "dist", ".pytest_cache"}
    for root, dirs, files in os.walk(target_path):
        dirs[:] = [d for d in dirs if d not in ignored and not d.startswith(".")]
        for f in sorted(files):
            if f.endswith(".py"):
                py_files.append(Path(root) / f)
    return sorted(py_files)


def scan(target_str: str):
    """Scan file or directory and return (scanned_count, parse_results, all_resources)."""
    target = Path(target_str).resolve()
    files = discover_files(target)
    analyzer = LeakAnalyzer()

    results = []
    resources = []
    for f in files:
        parse_res, res_list = analyzer.analyze_file(f)
        results.append(parse_res)
        resources.extend(res_list)
    return len(files), results, resources


def print_report(target_str: str, scanned_count: int, results: List[ParseResult], resources: List[Resource], elapsed: float) -> int:
    """Print the actionable CLI report containing file, line, resource, problem, leak path, recommendation."""
    syntax_errors = [r.syntax_error for r in results if r.syntax_error]
    leaks = [r for r in resources if r.status == "LEAK"]

    print("\n" + "=" * 64)
    print("  LeakGuard Static Analysis Report (Jury Version)")
    print("  Scope: Intra-procedural AST Control-Flow Analysis")
    print("=" * 64)
    print(f" Target:   {target_str}")
    print(f" Files:    {scanned_count} scanned")
    print(f" Duration: {elapsed:.4f}s")
    print("-" * 64 + "\n")

    if syntax_errors:
        print(f"Syntax Errors ({len(syntax_errors)}):")
        for err in syntax_errors:
            loc = f"{err.filename}:{err.line}:{err.column}" if err.line else err.filename
            print(f"  [-] {loc}")
            print(f"      Message: {err.message}")
            if err.text:
                print(f"      Snippet: {err.text.strip()}")
        print()

    if leaks:
        print(f"Detected Issues ({len(leaks)}):")
        for idx, res in enumerate(leaks, start=1):
            func_desc = f" in {res.function_name}()" if res.function_name else ""
            print(f"  [{idx}] [HIGH] LEAK001{func_desc}")
            print(f"      File:           {res.file_path}")
            print(f"      Line:           {res.opening_line}")
            print(f"      Resource:       {res.variable_name} (type: {res.resource_type})")
            print(f"      Problem:        {res.explanation}")
            if res.leak_path:
                print(f"      Leak Path:      {res.leak_path}")
            rec = f"Use 'with open(...) as {res.variable_name}:', or ensure '{res.variable_name}.close()' is called."
            print(f"      Recommendation: {rec}")
            print()

    print("-" * 64)
    if not syntax_errors and not leaks:
        print(" Result: PASSED: All files parsed cleanly. No syntax errors or leaks detected.")
        has_failure = False
    else:
        print(" Result: FAILED: Resource leaks or syntax errors detected.")
        clean_count = scanned_count - len({r.file_path for r in leaks} | {e.filename for e in syntax_errors})
        print(f" Summary: {max(0, clean_count)}/{scanned_count} clean files, {len(syntax_errors)} syntax errors, {len(leaks)} issues.")
        has_failure = True

    print(" Note:   Intra-procedural scope. Cross-function ownership is not claimed.")
    print("=" * 64 + "\n")
    return 1 if has_failure else 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="leakguard",
        description="LeakGuard: AST-based Python static analyzer for resource leaks.",
    )
    parser.add_argument("path", nargs="?", default=".", help="File or directory to scan.")
    args = parser.parse_args(argv)

    target_path = Path(args.path)
    if not target_path.exists():
        sys.stderr.write(f"Error: Target path '{args.path}' does not exist.\n")
        return 2

    t0 = time.perf_counter()
    count, results, resources = scan(str(target_path))
    elapsed = time.perf_counter() - t0

    return print_report(str(target_path), count, results, resources, elapsed)


if __name__ == "__main__":
    sys.exit(main())
