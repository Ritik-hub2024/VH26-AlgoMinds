"""AST-based file resource leak detector with control-flow and context manager analysis.

Detects unclosed file handles opened via open() without guaranteed close() calls.
Operates strictly on Python Abstract Syntax Trees (AST) without plain-text searching.
Supports sequential execution, if/else branch analysis, return statements, and with context managers.
"""

import ast
from typing import List, Optional, Tuple

from models.issue import Severity
from models.resource import Resource
from .base_lifecycle import BaseResourceLifecycleRule


class FileLeakRule(BaseResourceLifecycleRule):
    """Detects unclosed file handles opened via open() without guaranteed close().

    Rule ID: LEAK001
    Severity: HIGH
    """

    rule_id: str = "LEAK001"
    description: str = "Unclosed file resource leak"
    severity: Severity = Severity.HIGH
    resource_type: str = "file"
    acquire_name: str = "open"
    release_method_name: str = "close"

    # -------------------------------------------------------------------------
    # Acquisition and Release Checking
    # -------------------------------------------------------------------------

    def _is_open_call(self, call_node: ast.AST) -> bool:
        """Check if AST node is a call to the built-in open() function."""
        if not isinstance(call_node, ast.Call):
            return False

        func = call_node.func
        # Plain open(...)
        if isinstance(func, ast.Name) and func.id == "open":
            return True

        # builtins.open(...) or io.open(...)
        if (
            isinstance(func, ast.Attribute)
            and func.attr == "open"
            and isinstance(func.value, ast.Name)
            and func.value.id in ("builtins", "io")
        ):
            return True

        return False

    def _is_acquire_call(self, call_node: ast.AST) -> bool:
        """Hook for BaseResourceLifecycleRule checking acquisition calls."""
        return self._is_open_call(call_node)

    def _extract_open_assignment(
        self, stmt: ast.AST
    ) -> Optional[Tuple[str, int, ast.AST]]:
        """Extract variable name, opening line, and target node from an assignment to open()."""
        return self._extract_acquire_assignment(stmt)

    def _is_close_call(self, call_node: ast.AST, var_name: str) -> bool:
        """Check if AST node is an explicit var_name.close() call."""
        return self._is_release_call(call_node, var_name)

    def _find_close_in_stmts(
        self, stmts: List[ast.stmt], var_name: str
    ) -> Optional[int]:
        """Find the line number of a var_name.close() call within a list of statements."""
        return self._find_release_in_stmts(stmts, var_name)

    # -------------------------------------------------------------------------
    # Context Manager Handling
    # -------------------------------------------------------------------------

    def _handle_with_statement(
        self, node: ast.AST, function_name: Optional[str]
    ) -> None:
        """Process 'with open(...) [as var]:' statement and register as safe context manager."""
        items = getattr(node, "items", [])
        for item in items:
            context_expr = getattr(item, "context_expr", None)
            if context_expr and self._is_open_call(context_expr):
                optional_vars = getattr(item, "optional_vars", None)
                if isinstance(optional_vars, ast.Name):
                    var_name = optional_vars.id
                else:
                    var_name = "<context_manager>"

                # Context managers guarantee closing via __exit__ on all paths
                res = Resource(
                    variable_name=var_name,
                    resource_type=self.resource_type,
                    opening_line=node.lineno,
                    function_name=function_name,
                    status="SAFE",
                    closing_line=getattr(node, "end_lineno", node.lineno),
                    explanation=f"Safely managed by context manager (with open(...) as {var_name}).",
                    file_path=self.current_file,
                    is_context_manager=True,
                )
                self.resources.append(res)

    # -------------------------------------------------------------------------
    # Recommendations
    # -------------------------------------------------------------------------

    def _recommend_unclosed(self, var_name: str) -> str:
        return f"Add '{var_name}.close()' or convert to 'with open(...) as {var_name}:'."

    def _recommend_early_return(self, var_name: str, exit_line: int) -> str:
        return f"Call '{var_name}.close()' before returning at line {exit_line}, or use 'with open(...) as {var_name}:'."

    def _recommend_raise(self, var_name: str) -> str:
        return f"Wrap resource in 'try...finally' to guarantee '{var_name}.close()' runs on error."

    def _recommend_exception_path(self, var_name: str, exc_desc: str) -> str:
        return (
            f"Ensure '{var_name}.close()' is called in a 'finally:' block or inside the '{exc_desc}' handler, "
            f"or use 'with open(...) as {var_name}:'."
        )

    def _recommend_try_return(self, var_name: str, try_return: int) -> str:
        return (
            f"Ensure '{var_name}.close()' executes in a 'finally:' block, "
            f"or use 'with open(...) as {var_name}:'."
        )

    def _recommend_try_close_missing_finally(self, var_name: str) -> str:
        return f"Move '{var_name}.close()' into a 'finally:' block or use 'with open(...) as {var_name}:'."

    def _recommend_conditional(self, var_name: str, exit_line: int) -> str:
        return (
            f"Use 'with open(...) as {var_name}:', or invoke '{var_name}.close()' "
            f"before returning at line {exit_line}."
        )

    def _recommend_conditional_close(self, var_name: str) -> str:
        return f"Ensure '{var_name}.close()' executes on all code paths or use 'with open(...) as {var_name}:'."

    def _recommend_reassign(self, var_name: str) -> str:
        return f"Close previous resource '{var_name}.close()' before reassigning."
