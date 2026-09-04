"""Markdown and GitHub Step Summary reporter for LeakGuard."""

from typing import TextIO, Optional, Union
from pathlib import Path

from models.report import AnalysisReport
from models.baseline import DifferentialReport
from models.policy import SecurityPolicy


class MarkdownReporter:
    """Formats analysis report into GitHub Step Summary Markdown with baseline & policy support."""

    def __init__(self, stream: Optional[TextIO] = None) -> None:
        self.stream = stream

    def to_markdown(
        self,
        report: Union[AnalysisReport, DifferentialReport],
        diff_report: Optional[DifferentialReport] = None,
    ) -> str:
        """Render report as GitHub-flavored markdown."""
        if isinstance(report, DifferentialReport):
            diff = report
            base_report = report.report
        elif diff_report is not None:
            diff = diff_report
            base_report = report
        else:
            base_report = report
            diff = DifferentialReport.create(report)

        policy_desc = f"{diff.policy.block_level.value} (blocks ≥ {diff.policy.block_level.value})"

        lines = [
            "## 🛡️ LeakGuard Security Scan",
            "",
            f"- **Status:** {diff.status_badge}",
            f"- **Target:** `{base_report.target_path}`",
            f"- **Files Scanned:** {base_report.files_scanned}",
            f"- **Clean Files:** {base_report.clean_files_count}",
            f"- **Syntax Errors:** {len(base_report.syntax_errors)}",
            f"- **Total Leaks:** {len(base_report.issues)}",
            f"- **New Leaks:** {len(diff.new_issues)}",
            f"- **Existing / Baseline Leaks:** {len(diff.baseline_issues)}",
        ]
        unknown_count = len(getattr(base_report, "unknown_issues", []))
        if unknown_count > 0:
            lines.append(f"- **Ambiguous Ownership (UNKNOWN):** {unknown_count} (advisory)")
        lines.extend([
            f"- **Duration:** {base_report.duration_seconds:.4f}s",
            f"- **Security Policy:** `{policy_desc}`",
            "",
        ])

        # 1. New Findings Section (Blocking and Warnings - Definite Leaks)
        definite_new_leaks = [i for i in diff.new_issues if getattr(i, "classification", "LEAK") != "UNKNOWN"]
        if definite_new_leaks:
            lines.extend([
                "### 🚨 NEW FINDINGS / Detected Resource Leaks",
                "",
                "| Gate Impact | Severity | File:Line | Resource | Leak Path | Recommendation |",
                "| :---: | :---: | :--- | :--- | :--- | :--- |",
            ])
            for issue in definite_new_leaks:
                is_block = diff.policy.is_blocking(issue.severity)
                impact_badge = "❌ **BLOCKING**" if is_block else "⚠️ **WARNING**"
                sev = getattr(issue.severity, "value", str(issue.severity))
                res = f"{issue.resource_name} ({issue.resource_type})" if issue.resource_name else issue.resource_type
                leak_path = issue.leak_path.replace("->", "→") if issue.leak_path else "-"
                loc = f"`{issue.location.file_path}:{issue.location.line}`"
                rec = issue.recommendation or "-"
                lines.append(f"| {impact_badge} | **{sev}** | {loc} | `{res}` | `{leak_path}` | {rec} |")
            lines.append("")

        # 1.5 Ambiguous Ownership Section (UNKNOWN)
        unknown_new = [i for i in diff.new_issues if getattr(i, "classification", "LEAK") == "UNKNOWN"]
        if unknown_new:
            lines.extend([
                "### 🟡 AMBIGUOUS OWNERSHIP / ESCAPED RESOURCES (UNKNOWN)",
                "",
                "> [!NOTE]",
                "> LeakGuard detected resources whose ownership escaped local scope (argument transfer, return, container escape, or attribute assignment). Conservative analysis classifies these as **UNKNOWN** rather than guessing safe or leak.",
                "",
                "| Status | Ownership Transfer | File:Line | Resource | Callee / Target | Scope Limitation |",
                "| :---: | :---: | :--- | :--- | :--- | :--- |",
            ])
            for issue in unknown_new:
                status_badge = "❌ **BLOCKING**" if diff.policy.block_unknown else "🟡 **UNKNOWN**"
                transfer_type = getattr(issue, "ownership_status", "TRANSFERRED")
                loc = f"`{issue.location.file_path}:{issue.location.line}`"
                res = f"{issue.resource_name} ({issue.resource_type})" if issue.resource_name else issue.resource_type
                callee = f"`{issue.callee_name}()`" if getattr(issue, "callee_name", None) else "-"
                limit = getattr(issue, "scope_limitation", "-") or "-"
                lines.append(f"| {status_badge} | `{transfer_type}` | {loc} | `{res}` | {callee} | {limit} |")
            lines.append("")

        # 2. Existing / Baseline Findings Section (Informational & Non-Blocking)
        if diff.baseline_issues:
            lines.extend([
                "### 📋 EXISTING / BASELINE FINDINGS (Tolerated / Non-Blocking)",
                "",
                "> [!NOTE]",
                f"> **{len(diff.baseline_issues)} existing leak(s)** match the established project baseline and will not fail this PR gate.",
                "",
                "| Status | Severity | File:Line | Resource | Leak Path | Notes |",
                "| :---: | :---: | :--- | :--- | :--- | :--- |",
            ])
            for issue in diff.baseline_issues:
                sev = getattr(issue.severity, "value", str(issue.severity))
                res = f"{issue.resource_name} ({issue.resource_type})" if issue.resource_name else issue.resource_type
                leak_path = issue.leak_path.replace("->", "→") if issue.leak_path else "-"
                loc = f"`{issue.location.file_path}:{issue.location.line}`"
                lines.append(f"| ℹ️ `TOLERATED` | **{sev}** | {loc} | `{res}` | `{leak_path}` | Pre-existing in baseline |")
            lines.append("")

        # 3. Syntax Errors Section (Always Blocking)
        if base_report.syntax_errors:
            lines.extend([
                "### 🛑 SYNTAX ERRORS (Gate Blocking)",
                "",
                "| File:Line:Column | Error Message |",
                "| :--- | :--- |",
            ])
            for err in base_report.syntax_errors:
                col = f":{err.column}" if err.column else ""
                lines.append(f"| `{err.filename}:{err.line}{col}` | {err.message} |")
            lines.append("")

        # 4. PR Decision Callout
        if diff.has_syntax_errors:
            lines.extend([
                "> [!CAUTION]",
                f"> ❌ **PR BLOCKED**: {len(base_report.syntax_errors)} syntax error(s) must be resolved before merging.",
                "",
            ])
        elif diff.blocking_issues:
            lines.extend([
                "> [!CAUTION]",
                f"> ❌ **PR BLOCKED**: {len(diff.blocking_issues)} new blocking resource issue(s) detected. Clean up resources or resolve blocking ownership transfers.",
                "",
            ])
        elif diff.warning_issues or (diff.unknown_issues and not diff.policy.block_unknown):
            total_warn = len(diff.warning_issues) + len(diff.unknown_issues)
            lines.extend([
                "> [!WARNING]",
                f"> ⚠️ **PR PASSED WITH WARNINGS**: {total_warn} non-blocking issue(s) / ambiguous ownership warnings detected.",
                "",
            ])
        elif diff.has_baseline and diff.baseline_issues:
            lines.extend([
                "> [!NOTE]",
                f"> ✅ **PR PASSED**: Zero new resource leaks introduced. {len(diff.baseline_issues)} pre-existing baseline leak(s) tolerated.",
                "",
            ])
        else:
            lines.extend([
                "> [!NOTE]",
                "> ✅ **PR PASSED**: All scanned files are clean. Zero resource leaks or syntax errors detected.",
                "",
            ])

        return "\n".join(lines)

    def report(
        self,
        report: Union[AnalysisReport, DifferentialReport],
        diff_report: Optional[DifferentialReport] = None,
    ) -> None:
        """Write markdown report to stream."""
        md = self.to_markdown(report, diff_report=diff_report)
        if self.stream:
            try:
                self.stream.write(md)
                self.stream.write("\n")
            except UnicodeEncodeError:
                encoding = getattr(self.stream, "encoding", "utf-8") or "utf-8"
                safe_md = md.encode(encoding, errors="replace").decode(encoding)
                self.stream.write(safe_md)
                self.stream.write("\n")
