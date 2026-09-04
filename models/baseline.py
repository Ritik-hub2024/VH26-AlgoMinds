"""Baseline support and differential report analysis for GitHub PR checks."""

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Any, List, Set, Optional, Union, TextIO

from .issue import LeakIssue, Severity
from .report import AnalysisReport
from .policy import SecurityPolicy, BlockLevel


def normalize_path(file_path: Union[str, Path], base_dir: Optional[Union[str, Path]] = None) -> str:
    """Normalize file path to POSIX style relative to base directory or cwd."""
    p_str = str(file_path).replace("\\", "/")
    
    # Strip leading current directory markers
    while p_str.startswith("./"):
        p_str = p_str[2:]

    p = Path(p_str)
    
    # Try relative to explicit base_dir
    if base_dir:
        try:
            base_p = Path(base_dir).resolve()
            resolved = p.resolve() if p.is_absolute() else (base_p / p).resolve()
            rel = resolved.relative_to(base_p)
            return str(rel).replace("\\", "/")
        except Exception:
            pass

    # Try relative to current working directory
    try:
        cwd = Path.cwd().resolve()
        if p.is_absolute():
            rel = p.resolve().relative_to(cwd)
            return str(rel).replace("\\", "/")
    except Exception:
        pass

    # If relative, return clean posix
    if not p.is_absolute():
        return p.as_posix()

    # Fallback to normalized absolute posix
    return p.as_posix()


def compute_finding_fingerprint(
    issue: Union[LeakIssue, Dict[str, Any]],
    base_dir: Optional[Union[str, Path]] = None,
) -> str:
    """Compute stable, deterministic finding fingerprint.
    
    Tuple: (rule_id, normalized_relative_file_path, line, resource_type, resource_name)
    Format: "{rule_id}:{norm_file}:{line}:{resource_type}:{resource_name}"
    """
    if isinstance(issue, LeakIssue):
        rule_id = issue.rule_id or "LEAK001"
        raw_file = issue.location.file_path if issue.location else ""
        line = issue.location.line if issue.location else 0
        resource_type = issue.resource_type or "file"
        resource_name = issue.resource_name or issue.variable or ""
    elif isinstance(issue, dict):
        rule_id = issue.get("rule_id") or "LEAK001"
        loc = issue.get("location") or {}
        raw_file = issue.get("file") or loc.get("file_path") or ""
        line = issue.get("line") or loc.get("line") or 0
        resource_type = issue.get("resource_type") or "file"
        resource_name = issue.get("resource_name") or issue.get("variable") or ""
    else:
        raise TypeError(f"Unsupported issue type: {type(issue)}")

    norm_file = normalize_path(raw_file, base_dir=base_dir)
    return f"{rule_id}:{norm_file}:{line}:{resource_type}:{resource_name}"


def load_baseline(source: Union[str, Path, TextIO, Dict[str, Any], List[Any], Set[str]]) -> Set[str]:
    """Load baseline fingerprints from file path, JSON content, or dict/list structure."""
    if isinstance(source, set):
        return source

    data = None
    if isinstance(source, (str, Path)):
        p = Path(source)
        if not p.exists():
            raise FileNotFoundError(f"Baseline file not found: {source}")
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
    elif hasattr(source, "read"):
        data = json.load(source)
    else:
        data = source

    fingerprints: Set[str] = set()

    if isinstance(data, list):
        for item in data:
            if isinstance(item, str):
                fingerprints.add(item)
            elif isinstance(item, dict):
                fingerprints.add(compute_finding_fingerprint(item))
    elif isinstance(data, dict):
        if "fingerprints" in data and isinstance(data["fingerprints"], list):
            fingerprints.update(data["fingerprints"])
        elif "issues" in data and isinstance(data["issues"], list):
            for issue_dict in data["issues"]:
                fingerprints.add(compute_finding_fingerprint(issue_dict))
        elif "findings" in data and isinstance(data["findings"], list):
            for finding_dict in data["findings"]:
                fingerprints.add(compute_finding_fingerprint(finding_dict))
        elif "fingerprint" in data:
            fingerprints.add(str(data["fingerprint"]))

    return fingerprints


@dataclass
class DifferentialReport:
    """Differential analysis comparing scan report with baseline findings."""

    report: AnalysisReport
    policy: SecurityPolicy = field(default_factory=SecurityPolicy)
    baseline_fingerprints: Set[str] = field(default_factory=set)
    has_baseline: bool = False
    new_issues: List[LeakIssue] = field(default_factory=list)
    baseline_issues: List[LeakIssue] = field(default_factory=list)
    blocking_issues: List[LeakIssue] = field(default_factory=list)
    warning_issues: List[LeakIssue] = field(default_factory=list)

    @classmethod
    def create(
        cls,
        report: AnalysisReport,
        baseline_source: Optional[Union[str, Path, TextIO, Dict[str, Any], List[Any], Set[str]]] = None,
        policy: Optional[SecurityPolicy] = None,
        base_dir: Optional[Union[str, Path]] = None,
    ) -> "DifferentialReport":
        """Build differential report from scan results, baseline, and security policy."""
        active_policy = policy or SecurityPolicy()
        effective_base = base_dir or report.target_path

        has_baseline = False
        baseline_fps: Set[str] = set()

        if baseline_source is not None:
            has_baseline = True
            baseline_fps = load_baseline(baseline_source)

        new_issues: List[LeakIssue] = []
        baseline_issues: List[LeakIssue] = []
        blocking_issues: List[LeakIssue] = []
        warning_issues: List[LeakIssue] = []

        for issue in report.issues:
            fp = compute_finding_fingerprint(issue, base_dir=effective_base)
            if has_baseline and fp in baseline_fps:
                baseline_issues.append(issue)
            else:
                new_issues.append(issue)
                if active_policy.is_blocking(issue.severity):
                    blocking_issues.append(issue)
                else:
                    warning_issues.append(issue)

        return cls(
            report=report,
            policy=active_policy,
            baseline_fingerprints=baseline_fps,
            has_baseline=has_baseline,
            new_issues=new_issues,
            baseline_issues=baseline_issues,
            blocking_issues=blocking_issues,
            warning_issues=warning_issues,
        )

    @property
    def has_syntax_errors(self) -> bool:
        """True if any syntax errors exist in the scanned target."""
        return bool(self.report.syntax_errors)

    @property
    def has_blocking_issues(self) -> bool:
        """True if there are any new blocking severity leaks or syntax errors."""
        return bool(self.blocking_issues or self.has_syntax_errors)

    @property
    def is_clean(self) -> bool:
        """True if zero new leaks and zero syntax errors."""
        return len(self.new_issues) == 0 and not self.has_syntax_errors

    @property
    def exit_code(self) -> int:
        """Exit code based on policy and syntax error presence."""
        return 1 if self.has_blocking_issues else 0

    @property
    def status_title(self) -> str:
        """Human-readable PR status label."""
        if self.has_syntax_errors:
            return "PR BLOCKED: SYNTAX ERROR"
        if self.blocking_issues:
            count = len(self.blocking_issues)
            plural = "LEAKS" if count > 1 else "LEAK"
            return f"PR BLOCKED: {count} NEW BLOCKING {plural}"
        if self.warning_issues:
            count = len(self.warning_issues)
            plural = "WARNINGS" if count > 1 else "WARNING"
            return f"PR WARNING: {count} NEW {plural}"
        return "PR PASSED"

    @property
    def status_badge(self) -> str:
        """GitHub Markdown formatted status badge."""
        if self.has_syntax_errors:
            return "❌ **PR BLOCKED: FAILED (Syntax Error)**"
        if self.blocking_issues:
            count = len(self.blocking_issues)
            plural = "leaks" if count > 1 else "leak"
            return f"❌ **PR BLOCKED: FAILED ({count} new blocking {plural})**"
        if self.warning_issues:
            count = len(self.warning_issues)
            plural = "warnings" if count > 1 else "warning"
            return f"⚠️ **PR WARNING ({count} new {plural}, 0 blocking)**"
        if self.has_baseline and self.baseline_issues:
            return f"🛡️ **PR PASSED (PASS)**: 0 new leaks, {len(self.baseline_issues)} existing baseline leaks tolerated"
        return "🛡️ **PR PASSED (PASS)**: Zero leaks detected"

    def to_dict(self) -> Dict[str, Any]:
        """Convert differential report to dictionary."""
        return {
            "status": self.status_title,
            "passed": not self.has_blocking_issues,
            "has_baseline": self.has_baseline,
            "policy": self.policy.to_dict(),
            "metrics": {
                "files_scanned": self.report.files_scanned,
                "clean_files": self.report.clean_files_count,
                "syntax_errors": len(self.report.syntax_errors),
                "total_leaks": len(self.report.issues),
                "new_leaks": len(self.new_issues),
                "blocking_leaks": len(self.blocking_issues),
                "warning_leaks": len(self.warning_issues),
                "baseline_leaks": len(self.baseline_issues),
                "duration_seconds": round(self.report.duration_seconds, 4),
            },
            "new_issues": [i.to_dict() for i in self.new_issues],
            "baseline_issues": [i.to_dict() for i in self.baseline_issues],
            "syntax_errors": [e.to_dict() for e in self.report.syntax_errors],
            "fingerprints": [
                compute_finding_fingerprint(i, base_dir=self.report.target_path)
                for i in self.report.issues
            ],
        }
