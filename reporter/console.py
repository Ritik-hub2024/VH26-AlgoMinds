"""Terminal console reporter for LeakGuard analysis results."""

import sys
from typing import TextIO
from models.report import AnalysisReport


class ConsoleReporter:
    """Formats and prints actionable analysis reports to console/terminal."""

    def __init__(self, stream: TextIO = sys.stdout, use_color: bool = True) -> None:
        self.stream = stream
        # Determine if colors should be enabled (auto-check isatty or forced flag)
        self.use_color = use_color and hasattr(stream, "isatty") and stream.isatty()

    def _color(self, text: str, code: str) -> str:
        if not self.use_color:
            return text
        return f"\033[{code}m{text}\033[0m"

    def green(self, text: str) -> str:
        return self._color(text, "32")

    def red(self, text: str) -> str:
        return self._color(text, "31")

    def yellow(self, text: str) -> str:
        return self._color(text, "33")

    def cyan(self, text: str) -> str:
        return self._color(text, "36")

    def magenta(self, text: str) -> str:
        return self._color(text, "35")

    def bold(self, text: str) -> str:
        return self._color(text, "1")

    def report(self, report: AnalysisReport) -> None:
        """Render complete actionable report to stream."""
        p = self.stream.write

        p("\n" + self.bold("=" * 64) + "\n")
        p(f"  {self.bold(self.cyan('LeakGuard Static Analysis Report (Jury Version)'))}\n")
        p(f"  {self.magenta('Scope: Intra-procedural AST Control-Flow Analysis')}\n")
        p(self.bold("=" * 64) + "\n")
        p(f" Target:   {report.target_path}\n")
        p(f" Files:    {report.files_scanned} scanned\n")
        p(f" Duration: {report.duration_seconds:.4f}s\n")
        p("-" * 64 + "\n\n")

        # 1. Report read errors if any
        read_errors = [r for r in report.parse_results if r.read_error]
        if read_errors:
            p(self.bold(self.red("Read / OS Errors:")) + "\n")
            for r in read_errors:
                p(f"  [!] {r.file_path}: {r.read_error}\n")
            p("\n")

        # 2. Report syntax errors
        if report.syntax_errors:
            p(self.bold(self.red(f"Syntax Errors ({len(report.syntax_errors)}):")) + "\n")
            for err in report.syntax_errors:
                loc = f"{err.filename}:{err.line}:{err.column}" if err.line else err.filename
                p(f"  [-] {self.red(loc)}\n")
                p(f"      Message: {err.message}\n")
                if err.text:
                    p(f"      Snippet: {err.text.strip()}\n")
            p("\n")

        # 3. Report detected leak issues with 6 actionable dimensions
        if report.issues:
            p(self.bold(self.yellow(f"Detected Issues ({len(report.issues)}):")) + "\n")
            for idx, issue in enumerate(report.issues, start=1):
                func_info = f" in {issue.function_name}()" if issue.function_name else ""
                res_info = f"{issue.resource_name} (type: {issue.resource_type})" if issue.resource_name else issue.resource_type

                p(f"  [{idx}] [{self.bold(self.red(issue.severity.value))}] {self.bold(issue.rule_id)}{func_info}\n")
                p(f"      {self.bold('File:')}           {issue.location.file_path}\n")
                p(f"      {self.bold('Line:')}           {issue.location.line}\n")
                p(f"      {self.bold('Resource:')}       {res_info}\n")
                p(f"      {self.bold('Problem:')}        {issue.problem}\n")
                if issue.leak_path:
                    p(f"      {self.bold('Leak Path:')}      {self.yellow(issue.leak_path)}\n")
                if issue.recommendation:
                    p(f"      {self.bold('Recommendation:')} {self.green(issue.recommendation)}\n")
                p("\n")

        # 4. Summary banner
        p("-" * 64 + "\n")
        if not report.has_errors_or_issues:
            status = self.bold(self.green("PASSED: All files parsed cleanly. No syntax errors or leaks detected."))
            p(f" Result: {status}\n")
        else:
            status = self.bold(self.red("FAILED: Resource leaks or syntax errors detected."))
            p(f" Result: {status}\n")
            p(f" Summary: {report.clean_files_count}/{report.files_scanned} clean files, ")
            p(f"{len(report.syntax_errors)} syntax errors, {len(report.issues)} issues.\n")

        p(f" Note:   Intra-procedural scope. Cross-function ownership is not claimed.\n")
        p(self.bold("=" * 64) + "\n\n")
