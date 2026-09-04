"""AST-based file resource leak detector with control-flow and context manager analysis.

Detects unclosed file handles opened via open() without guaranteed close() calls.
Operates strictly on Python Abstract Syntax Trees (AST) without plain-text searching.
Supports sequential execution, if/else branch analysis, return statements, and with context managers.
"""

import ast
from typing import List, Optional, Tuple, Sequence

from analyzer.base import BaseRule
from models.issue import Severity
from models.resource import Resource


class FileLeakRule(BaseRule):
    """Detects unclosed file handles opened via open() without guaranteed close().

    Rule ID: LEAK001
    Severity: HIGH
    """

    rule_id: str = "LEAK001"
    description: str = "Unclosed file resource leak"
    severity: Severity = Severity.HIGH

    def __init__(self) -> None:
        super().__init__()
        self.resources: List[Resource] = []
        self._current_function: Optional[str] = None

    def run(self, tree: ast.AST, file_path: str) -> List[Resource]:
        """Execute rule on AST and populate detected issues."""
        self.current_file = file_path
        self.issues = []
        self.resources = []
        self._current_function = None
        self.visit(tree)
        return list(self.issues)

    def detect_resources(self, tree: ast.AST, file_path: str = "") -> List[Resource]:
        """Directly run detection and return all tracked Resource objects."""
        self.run(tree, file_path)
        return list(self.resources)

    # -------------------------------------------------------------------------
    # AST Node Visitors
    # -------------------------------------------------------------------------

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Analyze a standard function definition."""
        prev_func = self._current_function
        self._current_function = node.name
        self._analyze_statement_block(node.body, function_name=node.name)
        self.generic_visit(node)
        self._current_function = prev_func

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Analyze an async function definition."""
        prev_func = self._current_function
        self._current_function = node.name
        self._analyze_statement_block(node.body, function_name=node.name)
        self.generic_visit(node)
        self._current_function = prev_func

    def visit_Module(self, node: ast.Module) -> None:
        """Analyze module-level statements."""
        self._analyze_statement_block(node.body, function_name=None)
        self.generic_visit(node)

    # -------------------------------------------------------------------------
    # AST Helper Checks
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

    def _extract_open_assignment(
        self, stmt: ast.AST
    ) -> Optional[Tuple[str, int, ast.AST]]:
        """Extract variable name, opening line, and target node from an assignment to open()."""
        # Assign: f = open(...)
        if isinstance(stmt, ast.Assign) and self._is_open_call(stmt.value):
            for target in stmt.targets:
                if isinstance(target, ast.Name):
                    return target.id, stmt.lineno, target

        # AnnAssign: f: Any = open(...)
        if (
            isinstance(stmt, ast.AnnAssign)
            and stmt.value is not None
            and self._is_open_call(stmt.value)
        ):
            if isinstance(stmt.target, ast.Name):
                return stmt.target.id, stmt.lineno, stmt.target

        return None

    def _is_close_call(self, call_node: ast.AST, var_name: str) -> bool:
        """Check if AST node is an explicit var_name.close() call."""
        if not isinstance(call_node, ast.Call):
            return False

        func = call_node.func
        return (
            isinstance(func, ast.Attribute)
            and func.attr == "close"
            and isinstance(func.value, ast.Name)
            and func.value.id == var_name
        )

    def _format_node(self, node: ast.AST) -> str:
        """Helper to get clean string representation of an AST expression."""
        try:
            return ast.unparse(node).strip()
        except Exception:
            return getattr(node, "id", "condition")

    # -------------------------------------------------------------------------
    # Analysis Logic
    # -------------------------------------------------------------------------

    def _analyze_statement_block(
        self, statements: List[ast.stmt], function_name: Optional[str]
    ) -> None:
        """Analyze a linear block of statements for resource allocations and guarantees of closing."""
        for i, stmt in enumerate(statements):
            # 1. Check for 'with open(...) as f:' pattern (Safe Context Manager)
            if isinstance(stmt, (ast.With, ast.AsyncWith)):
                self._handle_with_statement(stmt, function_name)
                continue

            # 2. Check for manual 'f = open(...)' assignment
            alloc_info = self._extract_open_assignment(stmt)
            if not alloc_info:
                continue

            var_name, open_line, target_node = alloc_info

            # Create initial Resource object
            resource = Resource(
                variable_name=var_name,
                resource_type="file",
                opening_line=open_line,
                function_name=function_name,
                status="LEAK",
                file_path=self.current_file,
            )

            # Analyze subsequent statements for guaranteed close via control-flow analysis
            subsequent_stmts = statements[i + 1 :]
            status, close_line, problem, leak_path, recommendation = (
                self._evaluate_control_flow(
                    var_name=var_name,
                    open_line=open_line,
                    subsequent_stmts=subsequent_stmts,
                    function_name=function_name,
                )
            )

            resource.status = status
            resource.closing_line = close_line
            resource.explanation = problem
            resource.leak_path = leak_path
            self.resources.append(resource)

            if status == "LEAK":
                scope_desc = (
                    f"in function '{function_name}'"
                    if function_name
                    else "at module level"
                )
                message = (
                    f"Resource '{var_name}' (type: file) allocated at line {open_line} {scope_desc} "
                    f"is not guaranteed to be closed: {problem}"
                )
                self.add_issue(
                    node=target_node,
                    message=message,
                    recommendation=recommendation,
                    severity=self.severity,
                    resource_name=var_name,
                    resource_type="file",
                    problem=problem,
                    leak_path=leak_path or f"L{open_line}: open()",
                    function_name=function_name or "<module>",
                )

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
                    resource_type="file",
                    opening_line=node.lineno,
                    function_name=function_name,
                    status="SAFE",
                    closing_line=getattr(node, "end_lineno", node.lineno),
                    explanation=f"Safely managed by context manager (with open(...) as {var_name}).",
                    file_path=self.current_file,
                    is_context_manager=True,
                )
                self.resources.append(res)

    def _evaluate_control_flow(
        self,
        var_name: str,
        open_line: int,
        subsequent_stmts: List[ast.stmt],
        function_name: Optional[str],
    ) -> Tuple[str, Optional[int], str, Optional[str], str]:
        """Perform intra-procedural control-flow analysis for sequential statements and if/else branches.

        Returns:
            (status, closing_line, problem, leak_path, recommendation)
        """
        if not subsequent_stmts:
            problem = f"Resource '{var_name}' opened at line {open_line} is never closed before end of scope."
            leak_path = f"L{open_line}: open() -> end of scope"
            recommendation = f"Ensure '{var_name}.close()' is called before exit, or use 'with open(...) as {var_name}:'."
            return "LEAK", None, problem, leak_path, recommendation

        base_path = f"L{open_line}: open()"

        for stmt in subsequent_stmts:
            # 1. Direct sequential close call: f.close()
            if isinstance(stmt, ast.Expr) and self._is_close_call(stmt.value, var_name):
                return (
                    "SAFE",
                    stmt.lineno,
                    f"Guaranteed closed via '{var_name}.close()' at line {stmt.lineno}.",
                    None,
                    "",
                )

            # 2. Sequential early return or raise before close
            if isinstance(stmt, ast.Return):
                problem = f"Early return at line {stmt.lineno} exits before '{var_name}.close()' is reached."
                leak_path = f"{base_path} -> L{stmt.lineno}: return (leak)"
                recommendation = f"Call '{var_name}.close()' before returning at line {stmt.lineno}, or use 'with open(...) as {var_name}:'."
                return "LEAK", None, problem, leak_path, recommendation

            if isinstance(stmt, ast.Raise):
                problem = f"Exception raised at line {stmt.lineno} terminates execution before '{var_name}.close()'."
                leak_path = f"{base_path} -> L{stmt.lineno}: raise (leak)"
                recommendation = f"Wrap resource in 'try...finally' to guarantee '{var_name}.close()' runs on error."
                return "LEAK", None, problem, leak_path, recommendation

            # 3. Try / Finally block analysis
            if isinstance(stmt, ast.Try):
                finally_close = self._find_close_in_stmts(stmt.finalbody, var_name)
                if finally_close:
                    return (
                        "SAFE",
                        finally_close,
                        f"Guaranteed closed in finally block at line {finally_close}.",
                        None,
                        "",
                    )
                # If close is only in try body, an unhandled exception or return inside try is a leak
                try_close = self._find_close_in_stmts(stmt.body, var_name)
                if try_close:
                    problem = f"Closed in try-block at line {try_close}, but missing in finally block (leaks on error)."
                    leak_path = f"{base_path} -> L{stmt.lineno}: try (exception path leaks)"
                    recommendation = f"Move '{var_name}.close()' into a 'finally:' block or use 'with open(...) as {var_name}:'."
                    return "LEAK", try_close, problem, leak_path, recommendation

            # 4. If / Else branching control-flow analysis
            if isinstance(stmt, ast.If):
                cond_text = self._format_node(stmt.test)
                if_desc = f"if {cond_text}"

                # Check if TRUE branch has an unclosed return or raise
                # Pattern: open -> if condition -> return -> close
                exit_line = self._find_unclosed_exit_in_stmts(stmt.body, var_name)
                if exit_line:
                    problem = (
                        f"Resource '{var_name}' opened at line {open_line} is not closed if condition "
                        f"'{cond_text}' at line {stmt.lineno} is met due to early return at line {exit_line}."
                    )
                    leak_path = f"{base_path} -> L{stmt.lineno}: {if_desc} -> L{exit_line}: return (leak)"
                    recommendation = (
                        f"Use 'with open(...) as {var_name}:', or invoke '{var_name}.close()' "
                        f"before returning at line {exit_line}."
                    )
                    return "LEAK", None, problem, leak_path, recommendation

                # Check if FALSE branch (else / elif) has an unclosed return or raise
                if stmt.orelse:
                    else_exit_line = self._find_unclosed_exit_in_stmts(stmt.orelse, var_name)
                    if else_exit_line:
                        problem = (
                            f"Resource '{var_name}' opened at line {open_line} is not closed in else branch "
                            f"due to early return at line {else_exit_line}."
                        )
                        leak_path = f"{base_path} -> L{stmt.lineno}: else -> L{else_exit_line}: return (leak)"
                        recommendation = (
                            f"Use 'with open(...) as {var_name}:', or invoke '{var_name}.close()' "
                            f"before returning at line {else_exit_line}."
                        )
                        return "LEAK", None, problem, leak_path, recommendation

                # Check if close is called inside both if and else branches
                body_close = self._find_close_in_stmts(stmt.body, var_name)
                else_close = self._find_close_in_stmts(stmt.orelse, var_name) if stmt.orelse else None

                if body_close and else_close:
                    return (
                        "SAFE",
                        body_close,
                        f"Guaranteed closed in both if and else branches (lines {body_close} and {else_close}).",
                        None,
                        "",
                    )
                if body_close and not stmt.orelse:
                    problem = (
                        f"Resource '{var_name}' is conditionally closed in if-branch at line {body_close}, "
                        f"but leaks if condition is False."
                    )
                    leak_path = f"{base_path} -> L{stmt.lineno}: {if_desc} (False branch bypasses close)"
                    recommendation = f"Ensure '{var_name}.close()' executes on all code paths or use 'with open(...) as {var_name}:'."
                    return "LEAK", body_close, problem, leak_path, recommendation

            # 5. Reassignment to same variable without closing
            alloc_info = self._extract_open_assignment(stmt)
            if alloc_info and alloc_info[0] == var_name:
                problem = f"Variable '{var_name}' is reassigned at line {stmt.lineno} before previous resource was closed."
                leak_path = f"{base_path} -> L{stmt.lineno}: reassigned"
                recommendation = f"Close previous resource '{var_name}.close()' before reassigning."
                return "LEAK", None, problem, leak_path, recommendation

        problem = f"Resource '{var_name}' opened at line {open_line} is never closed."
        leak_path = f"{base_path} -> end of scope (no close)"
        recommendation = f"Add '{var_name}.close()' or convert to 'with open(...) as {var_name}:'."
        return "LEAK", None, problem, leak_path, recommendation

    def _find_close_in_stmts(
        self, stmts: List[ast.stmt], var_name: str
    ) -> Optional[int]:
        """Find the line number of a var_name.close() call within a list of statements."""
        for s in stmts:
            if isinstance(s, ast.Expr) and self._is_close_call(s.value, var_name):
                return s.lineno
            # Recursively check nested nodes
            for child in ast.walk(s):
                if isinstance(child, ast.Call) and self._is_close_call(child, var_name):
                    return child.lineno
        return None

    def _find_unclosed_exit_in_stmts(
        self, stmts: List[ast.stmt], var_name: str
    ) -> Optional[int]:
        """Find line of a return/raise statement that occurs before any var_name.close() in statements."""
        for s in stmts:
            if isinstance(s, ast.Expr) and self._is_close_call(s.value, var_name):
                return None  # Closed before any exit in this block

            if isinstance(s, (ast.Return, ast.Raise)):
                return s.lineno

            # If statement inside branch (nested if)
            if isinstance(s, ast.If):
                nested_exit = self._find_unclosed_exit_in_stmts(s.body, var_name)
                if nested_exit:
                    return nested_exit
                if s.orelse:
                    nested_else = self._find_unclosed_exit_in_stmts(s.orelse, var_name)
                    if nested_else:
                        return nested_else

        return None
