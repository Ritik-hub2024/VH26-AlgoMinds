"""Report and parse result models."""

import ast
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from .issue import LeakIssue


@dataclass
class SyntaxErrorInfo:
    """Detailed information regarding a syntax error during parsing."""

    message: str
    filename: str
    line: Optional[int]
    column: Optional[int]
    text: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert error info to dictionary."""
        return {
            "message": self.message,
            "filename": self.filename,
            "line": self.line,
            "column": self.column,
            "text": self.text.strip() if self.text else None,
        }

    def __str__(self) -> str:
        loc = f"{self.filename}:{self.line}:{self.column}" if self.line else self.filename
        snippet = f" -> '{self.text.strip()}'" if self.text else ""
        return f"SyntaxError at {loc}: {self.message}{snippet}"


@dataclass
class ParseResult:
    """Result of an AST parsing operation on a single file or source."""

    file_path: str
    success: bool
    tree: Optional[ast.AST] = None
    syntax_error: Optional[SyntaxErrorInfo] = None
    read_error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert parse result to dictionary (excluding raw AST)."""
        return {
            "file_path": self.file_path,
            "success": self.success,
            "has_ast": self.tree is not None,
            "syntax_error": self.syntax_error.to_dict() if self.syntax_error else None,
            "read_error": self.read_error,
        }


@dataclass
class AnalysisReport:
    """Overall analysis report containing parse and issue results."""

    target_path: str
    files_scanned: int = 0
    parse_results: List[ParseResult] = field(default_factory=list)
    issues: List[LeakIssue] = field(default_factory=list)
    syntax_errors: List[SyntaxErrorInfo] = field(default_factory=list)
    duration_seconds: float = 0.0

    @property
    def clean_files_count(self) -> int:
        """Count of files that parsed successfully and have no issues."""
        failed_files = {e.filename for e in self.syntax_errors}
        failed_files.update({res.file_path for res in self.parse_results if not res.success})
        issue_files = {issue.location.file_path for issue in self.issues}
        problem_files = failed_files.union(issue_files)
        return max(0, self.files_scanned - len(problem_files))

    @property
    def has_errors_or_issues(self) -> bool:
        """True if any syntax errors, read failures, or issues exist."""
        return bool(self.syntax_errors or self.issues or any(not r.success for r in self.parse_results))

    def to_dict(self) -> Dict[str, Any]:
        """Serialize report to structured JSON-compatible dictionary."""
        return {
            "target_path": self.target_path,
            "summary": {
                "files_scanned": self.files_scanned,
                "clean_files": self.clean_files_count,
                "syntax_errors_count": len(self.syntax_errors),
                "issues_count": len(self.issues),
                "duration_seconds": round(self.duration_seconds, 4),
            },
            "syntax_errors": [err.to_dict() for err in self.syntax_errors],
            "issues": [issue.to_dict() for issue in self.issues],
            "files": [r.to_dict() for r in self.parse_results],
        }
