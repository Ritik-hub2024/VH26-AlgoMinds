"""AST-based SQLite database connection leak detector with control-flow analysis.

Detects unclosed SQLite database connections created via sqlite3.connect() without guaranteed close() calls.
Operates strictly on Python Abstract Syntax Trees (AST) without plain-text searching or code execution.
Supports sequential execution, try/finally cleanup, exception paths, and if/else branch analysis.
"""

import ast
from typing import Optional, Tuple

from models.issue import Severity
from models.resource import Resource
from .base_lifecycle import BaseResourceLifecycleRule


class SqliteLeakRule(BaseResourceLifecycleRule):
    """Detects unclosed SQLite database connections created via sqlite3.connect() without guaranteed close().

    Rule ID: LEAK002
    Severity: HIGH
    """

    rule_id: str = "LEAK002"
    description: str = "Unclosed SQLite database connection leak"
    severity: Severity = Severity.HIGH
    resource_type: str = "SQLite connection"
    acquire_name: str = "sqlite3.connect"
    release_method_name: str = "close"

    # -------------------------------------------------------------------------
    # Acquisition and Release Checking
    # -------------------------------------------------------------------------

    def _is_connect_call(self, call_node: ast.AST) -> bool:
        """Check if an AST node is a call to sqlite3.connect() or connect()."""
        if not isinstance(call_node, ast.Call):
            return False

        func = call_node.func
        # sqlite3.connect(...) or sqlite.connect(...)
        if isinstance(func, ast.Attribute) and func.attr == "connect":
            if isinstance(func.value, ast.Name) and func.value.id in ("sqlite3", "sqlite"):
                return True

        # connect(...) from sqlite3 import connect
        if isinstance(func, ast.Name) and func.id == "connect":
            return True

        return False

    def _is_acquire_call(self, call_node: ast.AST) -> bool:
        """Hook for BaseResourceLifecycleRule checking acquisition calls."""
        return self._is_connect_call(call_node)

    def _extract_connect_assignment(
        self, stmt: ast.AST
    ) -> Optional[Tuple[str, int, ast.AST]]:
        """Extract variable name, opening line, and target node from an assignment to connect()."""
        return self._extract_acquire_assignment(stmt)

    def _is_close_call(self, call_node: ast.AST, var_name: str) -> bool:
        """Check if AST node is an explicit var_name.close() call."""
        return self._is_release_call(call_node, var_name)

    # -------------------------------------------------------------------------
    # Context Manager Handling
    # -------------------------------------------------------------------------

    def _handle_with_statement(
        self, node: ast.AST, function_name: Optional[str]
    ) -> None:
        """Process 'with contextlib.closing(sqlite3.connect(...)) as conn:' or similar."""
        items = getattr(node, "items", [])
        for item in items:
            context_expr = getattr(item, "context_expr", None)
            if not context_expr:
                continue

            # Check for contextlib.closing(sqlite3.connect(...)) or closing(sqlite3.connect(...))
            is_closing_wrapper = (
                isinstance(context_expr, ast.Call)
                and (
                    (isinstance(context_expr.func, ast.Name) and context_expr.func.id == "closing")
                    or (
                        isinstance(context_expr.func, ast.Attribute)
                        and context_expr.func.attr == "closing"
                    )
                )
                and context_expr.args
                and self._is_connect_call(context_expr.args[0])
            )

            if is_closing_wrapper:
                opt = getattr(item, "optional_vars", None)
                var_name = opt.id if isinstance(opt, ast.Name) else "<context_manager>"
                self.resources.append(
                    Resource(
                        variable_name=var_name,
                        resource_type=self.resource_type,
                        opening_line=node.lineno,
                        function_name=function_name,
                        status="SAFE",
                        closing_line=getattr(node, "end_lineno", node.lineno),
                        explanation=f"Safely managed by contextlib.closing context manager.",
                        file_path=self.current_file,
                        is_context_manager=True,
                    )
                )

    # -------------------------------------------------------------------------
    # Recommendations
    # -------------------------------------------------------------------------

    def _recommend_unclosed(self, var_name: str) -> str:
        return f"Call '{var_name}.close()' in finally or use a supported context-management pattern."

    def _recommend_early_return(self, var_name: str, exit_line: int) -> str:
        return f"Call '{var_name}.close()' before returning at line {exit_line}, or wrap in try...finally."

    def _recommend_raise(self, var_name: str) -> str:
        return f"Wrap database connection in 'try...finally' to guarantee '{var_name}.close()' runs on error."

    def _recommend_exception_path(self, var_name: str, exc_desc: str) -> str:
        return (
            f"Ensure '{var_name}.close()' is called in a 'finally:' block "
            f"or inside the '{exc_desc}' handler."
        )

    def _recommend_try_return(self, var_name: str, try_return: int) -> str:
        return f"Ensure '{var_name}.close()' executes in a 'finally:' block."

    def _recommend_try_close_missing_finally(self, var_name: str) -> str:
        return f"Move '{var_name}.close()' into a 'finally:' block to guarantee closing on error."

    def _recommend_conditional(self, var_name: str, exit_line: int) -> str:
        return f"Invoke '{var_name}.close()' before returning at line {exit_line}, or wrap in try...finally."

    def _recommend_conditional_close(self, var_name: str) -> str:
        return f"Ensure '{var_name}.close()' executes on all code paths or wrap in try...finally."

    def _recommend_reassign(self, var_name: str) -> str:
        return f"Close previous database connection '{var_name}.close()' before reassigning."
