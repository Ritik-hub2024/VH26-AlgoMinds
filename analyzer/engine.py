"""Analysis engine orchestrating AST rule evaluation."""

import ast
from pathlib import Path
from typing import List, Optional, Type, Sequence

from models.issue import LeakIssue
from models.report import ParseResult
from parser.ast_parser import ASTParser
from .base import BaseRule
from .rules.file_leak import FileLeakRule


class AnalysisEngine:
    """Orchestrates AST-based analysis without executing scanned code."""

    def __init__(self, rules: Optional[Sequence[BaseRule]] = None) -> None:
        self._rules: List[BaseRule] = list(rules) if rules is not None else [FileLeakRule()]
        self._parser: ASTParser = ASTParser()

    def register_rule(self, rule: BaseRule) -> None:
        """Register a new AST inspection rule."""
        self._rules.append(rule)

    @property
    def rules(self) -> List[BaseRule]:
        """Return list of registered rules."""
        return list(self._rules)

    def analyze_tree(self, tree: ast.AST, file_path: str) -> List[LeakIssue]:
        """Run all registered AST rules on a parsed syntax tree.

        Args:
            tree: Parsed AST tree.
            file_path: Origin path for location tracking.

        Returns:
            List of detected issues across all rules.
        """
        all_issues: List[LeakIssue] = []
        for rule in self._rules:
            issues = rule.run(tree, file_path)
            all_issues.extend(issues)
        return all_issues

    def analyze_file(self, file_path: str | Path) -> tuple[ParseResult, List[LeakIssue]]:
        """Parse and analyze a single file.

        Args:
            file_path: Path to the Python file.

        Returns:
            Tuple of (ParseResult, List[LeakIssue]).
        """
        parse_res = self._parser.parse_file(file_path)
        if not parse_res.success or parse_res.tree is None:
            return parse_res, []

        issues = self.analyze_tree(parse_res.tree, parse_res.file_path)
        return parse_res, issues
