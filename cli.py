"""CLI entry point for LeakGuard."""

import argparse
import os
import sys
import time
from pathlib import Path
from typing import List, Sequence, Optional

# Ensure project root is in sys.path
_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from models.report import AnalysisReport, ParseResult, SyntaxErrorInfo
from parser.ast_parser import ASTParser
from analyzer.engine import AnalysisEngine
from reporter.console import ConsoleReporter
from reporter.json_reporter import JSONReporter
from reporter.markdown import MarkdownReporter

# Ignored directory names during recursive scans
IGNORED_DIRS = {
    "__pycache__",
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "env",
    ".env",
    "build",
    "dist",
    ".pytest_cache",
    ".mypy_cache",
    ".tox",
    "node_modules",
}


def discover_python_files(target_path: Path) -> List[Path]:
    """Recursively collect .py files from target path, skipping ignored directories."""
    if target_path.is_file():
        return [target_path]

    py_files: List[Path] = []
    for root, dirs, files in os.walk(target_path):
        # Modify dirs in-place to skip ignored directories
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRS and not d.startswith(".")]
        for file in files:
            if file.endswith(".py"):
                py_files.append(Path(root) / file)

    return sorted(py_files)


def scan_target(
    target_str: str,
    engine: Optional[AnalysisEngine] = None,
) -> AnalysisReport:
    """Scan a file or directory using the AST parser and registered analyzer rules.

    Target code is strictly parsed into AST and NEVER executed.
    """
    start_time = time.perf_counter()
    target_path = Path(target_str).resolve()
    report = AnalysisReport(target_path=str(target_path))

    if not target_path.exists():
        report.parse_results.append(
            ParseResult(
                file_path=str(target_path),
                success=False,
                read_error=f"Target path does not exist: {target_path}",
            )
        )
        report.duration_seconds = time.perf_counter() - start_time
        return report

    files_to_scan = discover_python_files(target_path)
    report.files_scanned = len(files_to_scan)

    parser = ASTParser()
    analysis_engine = engine or AnalysisEngine()

    for file_path in files_to_scan:
        parse_result = parser.parse_file(file_path)
        report.parse_results.append(parse_result)

        if not parse_result.success:
            if parse_result.syntax_error:
                report.syntax_errors.append(parse_result.syntax_error)
            continue

        if parse_result.tree is not None and analysis_engine.rules:
            issues = analysis_engine.analyze_tree(parse_result.tree, str(file_path))
            report.issues.extend(issues)

    report.duration_seconds = time.perf_counter() - start_time
    return report


def build_parser() -> argparse.ArgumentParser:
    """Construct CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="leakguard",
        description="LeakGuard: Pure AST Python static analyzer for detecting resource and memory leaks.",
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=None,
        help="Path to Python file or directory to scan (default: current directory).",
    )
    parser.add_argument(
        "-t",
        "--target",
        dest="target",
        default=None,
        help="Path to Python file or directory to scan (alternative to positional argument).",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["console", "json", "markdown"],
        default="console",
        help="Output report format (default: console).",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        default=None,
        help="Write report output to specified file path.",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colors in console output.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        default=True,
        help="Return exit code 1 if syntax errors or issues are found (default: True).",
    )
    parser.add_argument(
        "--github-summary",
        nargs="?",
        const="AUTO_ENV",
        default=None,
        help="Write GitHub Step Summary markdown to file path (or $GITHUB_STEP_SUMMARY if flag passed without value).",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="LeakGuard 0.1.0 (Python AST Static Analyzer)",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """CLI execution entrypoint."""
    arg_parser = build_parser()
    args = arg_parser.parse_args(argv)

    target_str = args.target or args.path or "."
    target_path = Path(target_str)
    if not target_path.exists():
        sys.stderr.write(f"Error: Target path '{target_str}' does not exist.\n")
        return 2

    # Perform AST scanning
    report = scan_target(str(target_path))

    # Determine reporter
    if args.format == "json":
        reporter = JSONReporter(stream=sys.stdout)
    elif args.format == "markdown":
        reporter = MarkdownReporter(stream=sys.stdout)
    else:
        reporter = ConsoleReporter(stream=sys.stdout, use_color=not args.no_color)

    # Render report to stdout
    reporter.report(report)

    # Optional file output
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as out_f:
                if args.format == "json":
                    out_reporter = JSONReporter(stream=out_f)
                elif args.format == "markdown":
                    out_reporter = MarkdownReporter(stream=out_f)
                else:
                    out_reporter = ConsoleReporter(stream=out_f, use_color=False)
                out_reporter.report(report)
        except OSError as err:
            sys.stderr.write(f"Error writing to output file '{args.output}': {err}\n")

    # Optional GitHub Step Summary output
    summary_target = args.github_summary
    if summary_target == "AUTO_ENV":
        summary_target = os.environ.get("GITHUB_STEP_SUMMARY")

    if summary_target:
        try:
            summary_path = Path(summary_target)
            summary_path.parent.mkdir(parents=True, exist_ok=True)
            mode = "a" if summary_path.exists() else "w"
            with open(summary_path, mode, encoding="utf-8") as sum_f:
                MarkdownReporter(stream=sum_f).report(report)
        except OSError as err:
            sys.stderr.write(f"Warning: Failed to write GitHub Step Summary to '{summary_target}': {err}\n")

    # Exit code determination
    if args.strict and report.has_errors_or_issues:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
