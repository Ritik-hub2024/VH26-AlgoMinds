"""Markdown and GitHub Step Summary reporter for LeakGuard."""

from typing import TextIO, Optional
from pathlib import Path
from models.report import AnalysisReport


class MarkdownReporter:
    """Formats analysis report into GitHub Step Summary Markdown."""

    def __init__(self, stream: Optional[TextIO] = None) -> None:
        self.stream = stream

    def to_markdown(self, report: AnalysisReport) -> str:
        """Render report as GitHub-flavored markdown."""
        status_str = "FAILED" if report.has_errors_or_issues else "PASS"
        status_badge = "🛡️ **PASS**" if not report.has_errors_or_issues else "❌ **FAILED**"

        lines = [
            "## 🛡️ LeakGuard Security Scan",
            "",
            f"- **Status:** {status_badge}",
            f"- **Target:** `{report.target_path}`",
            f"- **Files Scanned:** {report.files_scanned}",
            f"- **Clean Files:** {report.clean_files_count}",
            f"- **Leaks Detected:** {len(report.issues)}",
            f"- **Syntax Errors:** {len(report.syntax_errors)}",
            f"- **Duration:** {report.duration_seconds:.4f}s",
            "",
        ]

        if report.issues:
            lines.extend([
                "### ⚠️ Detected Resource Leaks",
                "",
                "| Severity | File:Line | Resource | Leak Path | Recommendation |",
                "| :---: | :--- | :--- | :--- | :--- |",
            ])
            for issue in report.issues:
                sev = getattr(issue.severity, "value", str(issue.severity))
                res = f"{issue.resource_name} ({issue.resource_type})" if issue.resource_name else issue.resource_type
                leak_path = issue.leak_path.replace("->", "→") if issue.leak_path else "-"
                loc = f"`{issue.location.file_path}:{issue.location.line}`"
                rec = issue.recommendation or "-"
                lines.append(f"| **{sev}** | {loc} | `{res}` | `{leak_path}` | {rec} |")
            lines.append("")

        if report.syntax_errors:
            lines.extend([
                "### ❌ Syntax Errors",
                "",
                "| File:Line:Column | Error Message |",
                "| :--- | :--- |",
            ])
            for err in report.syntax_errors:
                col = f":{err.column}" if err.column else ""
                lines.append(f"| `{err.filename}:{err.line}{col}` | {err.message} |")
            lines.append("")

        if not report.has_errors_or_issues:
            lines.extend([
                "> [!NOTE]",
                "> ✅ **All scanned files are clean. Zero resource leaks or syntax errors detected.**",
                "",
            ])

        return "\n".join(lines)

    def report(self, report: AnalysisReport) -> None:
        """Write markdown report to stream."""
        md = self.to_markdown(report)
        if self.stream:
            try:
                self.stream.write(md)
                self.stream.write("\n")
            except UnicodeEncodeError:
                encoding = getattr(self.stream, "encoding", "utf-8") or "utf-8"
                safe_md = md.encode(encoding, errors="replace").decode(encoding)
                self.stream.write(safe_md)
                self.stream.write("\n")
