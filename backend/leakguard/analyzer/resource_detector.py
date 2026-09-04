"""AST-based file resource allocation detector."""

import ast
from typing import List, Optional, Tuple
from ..models.resource import Resource


class ResourceDetector:
    """Detects resource allocation expressions such as f = open('data.txt') using AST nodes."""

    @staticmethod
    def is_open_call(node: ast.AST) -> bool:
        """Check if an AST node is a call to open()."""
        if not isinstance(node, ast.Call):
            return False

        func = node.func
        if isinstance(func, ast.Name) and func.id == "open":
            return True

        if (
            isinstance(func, ast.Attribute)
            and func.attr == "open"
            and isinstance(func.value, ast.Name)
            and func.value.id in ("builtins", "io")
        ):
            return True

        return False

    @classmethod
    def extract_allocation(
        cls, stmt: ast.AST
    ) -> Optional[Tuple[str, int, ast.AST]]:
        """Extract variable name, line number, and AST target node for an assignment to open()."""
        # Assign: f = open(...)
        if isinstance(stmt, ast.Assign) and cls.is_open_call(stmt.value):
            for target in stmt.targets:
                if isinstance(target, ast.Name):
                    return target.id, stmt.lineno, target

        # AnnAssign: f: Any = open(...)
        if (
            isinstance(stmt, ast.AnnAssign)
            and stmt.value is not None
            and cls.is_open_call(stmt.value)
        ):
            if isinstance(stmt.target, ast.Name):
                return stmt.target.id, stmt.lineno, stmt.target

        return None
