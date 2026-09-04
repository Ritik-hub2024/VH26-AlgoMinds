"""CLI entry point for LeakGuard."""

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Sequence, Optional

# Ensure project root is in sys.path
_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from models.report import AnalysisReport, ParseResult, SyntaxErrorInfo
from models.policy import SecurityPolicy, BlockLevel
from models.baseline import DifferentialReport, compute_finding_fingerprint
from parser.ast_parser import ASTParser
from analyzer.engine import AnalysisEngine
from reporter.console import ConsoleReporter
from reporter.json_reporter import JSONReporter
from reporter.markdown import MarkdownReporter
from reporter.sarif import SARIFReporter

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
    block_unknown: bool = False,
) -> AnalysisReport:
    """Scan a file or directory using the AST parser and registered analyzer rules.

    Target code is strictly parsed into AST and NEVER executed.
    """
    start_time = time.perf_counter()
    target_path = Path(target_str).resolve()
    report = AnalysisReport(target_path=str(target_path), block_unknown=block_unknown)

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
        choices=["console", "json", "markdown", "sarif"],
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
        "--baseline",
        type=str,
        default=None,
        help="Path to historical baseline JSON file to compare against.",
    )
    parser.add_argument(
        "--baseline-out",
        type=str,
        default=None,
        help="Export current findings as a baseline JSON file for future PR differential checks.",
    )
    parser.add_argument(
        "--policy",
        "--block-level",
        dest="policy",
        type=str,
        choices=["HIGH", "MEDIUM", "LOW", "high", "medium", "low"],
        default="HIGH",
        help="Security policy blocking severity threshold (default: HIGH).",
    )
    parser.add_argument(
        "--block-unknown",
        action="store_true",
        help="Treat UNKNOWN resource ownership findings as blocking (exit code 1). Default is advisory/warning only.",
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
        "--record",
        action="store_true",
        help="Record scan result into local SQLite database for Admin dashboard.",
    )
    parser.add_argument(
        "--project-id",
        type=str,
        default=None,
        help="Project identifier to associate scan with when --record is used.",
    )
    parser.add_argument(
        "--ci-export",
        type=str,
        default=None,
        help="Export portable CI analysis result artifact JSON (e.g. leakguard-ci-result.json).",
    )
    parser.add_argument(
        "--ingest",
        type=str,
        default=None,
        help="Ingest a portable CI result JSON file into local SQLite database for Admin view.",
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

    # Fast-path for --ingest
    if args.ingest:
        ingest_path = Path(args.ingest)
        if not ingest_path.exists():
            sys.stderr.write(f"Error: Ingest file '{args.ingest}' does not exist.\n")
            return 2
        try:
            with open(ingest_path, "r", encoding="utf-8") as f:
                ci_payload = json.load(f)
            from storage.database import Database
            db = Database()
            scan_rec = db.ingest_ci_result(ci_payload)
            print(f"Successfully ingested CI result into project '{scan_rec.project_id}' (Scan ID: {scan_rec.scan_id}, Status: {scan_rec.status}, Score: {scan_rec.health_score}).")
            return 0
        except Exception as err:
            sys.stderr.write(f"Error ingesting CI result '{args.ingest}': {err}\n")
            return 1

    target_str = args.target or args.path or "."
    target_path = Path(target_str)
    if not target_path.exists():
        sys.stderr.write(f"Error: Target path '{target_str}' does not exist.\n")
        return 2

    # Perform AST scanning
    report = scan_target(str(target_path), block_unknown=args.block_unknown)

    # Build security policy and differential report
    policy = SecurityPolicy(
        block_level=args.policy.upper() if args.policy else "HIGH",
        block_unknown=args.block_unknown,
    )
    diff_report = DifferentialReport.create(
        report=report,
        baseline_source=args.baseline,
        policy=policy,
        base_dir=str(target_path),
    )

    # Optional baseline export
    if args.baseline_out:
        try:
            baseline_out_path = Path(args.baseline_out)
            baseline_out_path.parent.mkdir(parents=True, exist_ok=True)
            baseline_data = {
                "baseline_version": "1.0",
                "target_path": str(target_path),
                "fingerprints": [
                    compute_finding_fingerprint(i, base_dir=str(target_path)) for i in report.issues
                ],
                "issues": [i.to_dict() for i in report.issues],
            }
            with open(baseline_out_path, "w", encoding="utf-8") as bf:
                json.dump(baseline_data, bf, indent=2)
        except OSError as b_err:
            sys.stderr.write(f"Error writing baseline file '{args.baseline_out}': {b_err}\n")

    # Determine reporter
    if args.format == "json":
        reporter = JSONReporter(stream=sys.stdout)
    elif args.format == "sarif":
        reporter = SARIFReporter(stream=sys.stdout)
    elif args.format == "markdown":
        reporter = MarkdownReporter(stream=sys.stdout)
    else:
        reporter = ConsoleReporter(stream=sys.stdout, use_color=not args.no_color)

    # Render report to stdout
    if isinstance(reporter, MarkdownReporter):
        reporter.report(report, diff_report=diff_report)
    elif isinstance(reporter, ConsoleReporter):
        reporter.report(report, diff_report=diff_report)
    else:
        reporter.report(report)

    # Optional file output
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as out_f:
                if args.format == "json":
                    out_reporter = JSONReporter(stream=out_f)
                    out_reporter.report(report)
                elif args.format == "sarif":
                    out_reporter = SARIFReporter(stream=out_f)
                    out_reporter.report(report)
                elif args.format == "markdown":
                    out_reporter = MarkdownReporter(stream=out_f)
                    out_reporter.report(report, diff_report=diff_report)
                else:
                    out_reporter = ConsoleReporter(stream=out_f, use_color=False)
                    out_reporter.report(report, diff_report=diff_report)
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
                MarkdownReporter(stream=sum_f).report(report, diff_report=diff_report)
        except OSError as err:
            sys.stderr.write(f"Warning: Failed to write GitHub Step Summary to '{summary_target}': {err}\n")

    # Determine exit code
    if not args.strict:
        final_exit_code = 0
    elif args.baseline:
        final_exit_code = diff_report.exit_code
    elif report.has_errors_or_issues:
        final_exit_code = 1
    else:
        final_exit_code = 0

    ci_status = "PASS" if final_exit_code == 0 else "FAILED"

    # Compute baseline vs new finding metrics
    baseline_fps = set()
    if diff_report and diff_report.baseline_fingerprints:
        baseline_fps = diff_report.baseline_fingerprints

    prepared_findings = []
    new_leaks_count = 0
    baseline_leaks_count = 0
    for issue in report.issues:
        fp = compute_finding_fingerprint(issue, base_dir=str(target_path))
        is_bl = fp in baseline_fps
        if is_bl:
            baseline_leaks_count += 1
        else:
            new_leaks_count += 1
        prepared_findings.append({
            "file": issue.location.file_path,
            "line": issue.location.line,
            "column": issue.location.column,
            "resource": f"{issue.resource_name} ({issue.resource_type})" if issue.resource_name else issue.resource_type,
            "variable": issue.resource_name or "f",
            "severity": issue.severity.value if hasattr(issue.severity, "value") else str(issue.severity),
            "reason": issue.message or issue.problem,
            "leak_path": issue.leak_path or "",
            "recommendation": issue.recommendation or "",
            "cleanup_status": "UNCLOSED",
            "classification": getattr(issue, "classification", "LEAK"),
            "ownership_status": getattr(issue, "ownership_status", "LOCAL"),
            "callee_name": getattr(issue, "callee_name", None),
            "transfer_line": getattr(issue, "transfer_line", None),
            "scope_limitation": getattr(issue, "scope_limitation", None),
            "is_baseline": is_bl,
            "fingerprint": fp,
        })

    syntax_err_list = [
        se.to_dict() if hasattr(se, "to_dict") else {
            "filename": getattr(se, "filename", ""),
            "line": getattr(se, "line", 0),
            "column": getattr(se, "column", 0),
            "message": getattr(se, "message", ""),
            "text": getattr(se, "text", ""),
        }
        for se in report.syntax_errors
    ]

    # Optional CI result artifact export
    if args.ci_export:
        try:
            from models.project import CIMetadata
            from storage.database import calculate_health_score
            ci_meta = CIMetadata.from_env()

            score, _ = calculate_health_score(
                prepared_findings,
                syntax_err_list,
                ci_status,
                new_leaks=new_leaks_count,
                baseline_leaks=baseline_leaks_count,
            )

            ci_export_path = Path(args.ci_export)
            ci_export_path.parent.mkdir(parents=True, exist_ok=True)
            norm_target = str(target_path).replace("\\", "/")
            if "python/leaks" in norm_target:
                auto_proj_id = "python-leaks"
            elif "python/safe" in norm_target:
                auto_proj_id = "python-safe"
            elif "python/syntax" in norm_target:
                auto_proj_id = "python-syntax"
            else:
                auto_proj_id = "leakguard-core"

            ci_result_payload = {
                "version": "1.0",
                "source": "CI",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "project_id": args.project_id or auto_proj_id,
                "target": norm_target,
                "status": ci_status,
                "health_score": score,
                "summary": {
                    "files_scanned": report.files_scanned,
                    "clean_files": report.clean_files_count,
                    "syntax_errors": len(report.syntax_errors),
                    "total_leaks": len(report.issues),
                    "unknown_ownership": len(report.unknown_issues),
                    "new_leaks": new_leaks_count,
                    "baseline_leaks": baseline_leaks_count,
                    "duration_ms": round(report.duration_seconds * 1000, 2),
                },
                "ci_metadata": ci_meta.to_dict(),
                "findings": prepared_findings,
                "syntax_errors": syntax_err_list,
            }

            with open(ci_export_path, "w", encoding="utf-8") as cef:
                json.dump(ci_result_payload, cef, indent=2)
        except Exception as exp_err:
            sys.stderr.write(f"Warning: Failed to export CI result to '{args.ci_export}': {exp_err}\n")

    # Optional database persistence for Admin dashboard
    if args.record:
        try:
            from storage.database import Database
            from models.project import CIMetadata
            db = Database()
            is_ci = bool(os.environ.get("GITHUB_ACTIONS") or summary_target)
            scan_type = "CI" if is_ci else "LOCAL SCAN"
            ci_meta = CIMetadata.from_env() if is_ci else None

            db.record_scan(
                report=report,
                project_id=args.project_id,
                target_override=str(target_path),
                scan_type=scan_type,
                commit_sha=ci_meta.commit_sha if ci_meta else None,
                branch=ci_meta.branch if ci_meta and ci_meta.branch else "main",
                repository=ci_meta.repository if ci_meta and ci_meta.repository else "Ritik-hub2024/VH26-AlgoMinds",
                pull_request=ci_meta.pull_request if ci_meta else None,
                workflow_run=ci_meta.workflow_run if ci_meta else None,
                prepared_findings=prepared_findings,
                new_leaks=new_leaks_count,
                baseline_leaks=baseline_leaks_count,
            )
        except Exception as rec_err:
            sys.stderr.write(f"Warning: Failed to record scan to database: {rec_err}\n")

    return final_exit_code


if __name__ == "__main__":
    sys.exit(main())
