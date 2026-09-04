"""AST-based resource release (close) detector."""

import ast
from typing import Optional, List


class CloseDetector:
    """Detects explicit resource release calls such as f.close() using AST nodes."""

    @staticmethod
    def is_close_call(node: ast.AST, var_name: str) -> bool:
        """Check if an AST node is an explicit var_name.close() call."""
        if not isinstance(node, ast.Call):
            return False

        func = node.func
        return (
            isinstance(func, ast.Attribute)
            and func.attr == "close"
            and isinstance(func.value, ast.Name)
            and func.value.id == var_name
        )

    @classmethod
    def find_close_in_stmts(
        cls, stmts: List[ast.stmt], var_name: str
    ) -> Optional[int]:
        """Find the line number of var_name.close() within a list of statements."""
        for s in stmts:
            if isinstance(s, ast.Expr) and cls.is_close_call(s.value, var_name):
                return s.lineno
            for child in ast.walk(s):
                if isinstance(child, ast.Call) and cls.is_close_call(child, var_name):
                    return getattr(child, "lineno", getattr(s, "lineno", None))
        return None
