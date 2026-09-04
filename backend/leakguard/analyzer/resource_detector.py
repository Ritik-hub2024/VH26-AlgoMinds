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

    @staticmethod
    def is_sqlite_connect_call(node: ast.AST) -> bool:
        """Check if an AST node is a call to sqlite3.connect() or connect()."""
        if not isinstance(node, ast.Call):
            return False

        func = node.func
        if isinstance(func, ast.Attribute) and func.attr == "connect":
            if isinstance(func.value, ast.Name) and func.value.id in ("sqlite3", "sqlite"):
                return True

        if isinstance(func, ast.Name) and func.id == "connect":
            return True

        return False

    @classmethod
    def get_resource_type(cls, call_node: ast.AST) -> Optional[str]:
        """Return resource type string if call is a recognized resource allocator."""
        if cls.is_open_call(call_node):
            return "file"
        if cls.is_sqlite_connect_call(call_node):
            return "SQLite connection"
        return None

    @classmethod
    def extract_allocation(
        cls, stmt: ast.AST
    ) -> Optional[Tuple[str, int, ast.AST, str]]:
        """Extract variable name, line number, AST target node, and resource type for an assignment."""
        # Assign: var = allocate(...)
        if isinstance(stmt, ast.Assign):
            res_type = cls.get_resource_type(stmt.value)
            if res_type:
                for target in stmt.targets:
                    if isinstance(target, ast.Name):
                        return target.id, stmt.lineno, target, res_type

        # AnnAssign: var: Any = allocate(...)
        if isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
            res_type = cls.get_resource_type(stmt.value)
            if res_type:
                if isinstance(stmt.target, ast.Name):
                    return stmt.target.id, stmt.lineno, stmt.target, res_type

        return None
