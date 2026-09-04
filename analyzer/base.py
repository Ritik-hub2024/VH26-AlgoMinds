"""Base abstractions for AST-based leak detection rules."""

import ast
from abc import ABC, abstractmethod
from typing import List, Optional

from models.issue import LeakIssue, Severity
from models.location import SourceLocation


class BaseRule(ast.NodeVisitor, ABC):
    """Abstract base class for all AST-based static analysis rules.

    All inspections MUST rely on AST visitor methods and MUST NOT use
    regular expressions or raw string matching on source code.
    """

    rule_id: str = "BASE000"
    description: str = "Base AST rule"
    severity: Severity = Severity.MEDIUM

    def __init__(self) -> None:
        self.current_file: str = ""
        self.issues: List[LeakIssue] = []

    def create_location(self, node: ast.AST) -> SourceLocation:
        """Helper to create a SourceLocation from an AST node."""
        lineno = getattr(node, "lineno", 1)
        col_offset = getattr(node, "col_offset", 0)
        end_lineno = getattr(node, "end_lineno", None)
        end_col_offset = getattr(node, "end_col_offset", None)

        return SourceLocation(
            file_path=self.current_file,
            line=lineno,
            column=col_offset,
            end_line=end_lineno,
            end_column=end_col_offset,
        )

    def add_issue(
        self,
        node: ast.AST,
        message: str,
        recommendation: str = "",
        severity: Optional[Severity] = None,
        resource_name: str = "",
        resource_type: str = "file",
        problem: str = "",
        leak_path: str = "",
        function_name: str = "",
    ) -> None:
        """Record an actionable issue detected at the given AST node."""
        issue = LeakIssue(
            rule_id=self.rule_id,
            message=message,
            severity=severity or self.severity,
            location=self.create_location(node),
            recommendation=recommendation,
            resource_name=resource_name,
            resource_type=resource_type,
            problem=problem or message,
            leak_path=leak_path,
            function_name=function_name,
        )
        self.issues.append(issue)

    def run(self, tree: ast.AST, file_path: str) -> List[LeakIssue]:
        """Execute AST visitor rule on the provided syntax tree.

        Args:
            tree: The parsed AST root node.
            file_path: Path of the file being analyzed.

        Returns:
            List of detected LeakIssue instances.
        """
        self.current_file = file_path
        self.issues = []
        self.visit(tree)
        return list(self.issues)
