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
        self,
        statements: List[ast.stmt],
        function_name: Optional[str],
        parent_try: Optional[ast.Try] = None,
        outer_subsequent: Optional[List[ast.stmt]] = None,
    ) -> None:
        """Analyze a linear block of statements for resource allocations and guarantees of closing."""
        for i, stmt in enumerate(statements):
            # 1. Check for 'with open(...) as f:' pattern (Safe Context Manager)
            if isinstance(stmt, (ast.With, ast.AsyncWith)):
                self._handle_with_statement(stmt, function_name)
                # Recurse into with-block body to check for any nested raw open calls
                self._analyze_statement_block(
                    stmt.body,
                    function_name=function_name,
                    parent_try=parent_try,
                    outer_subsequent=statements[i + 1 :] + (outer_subsequent or []),
                )
                continue

            # 2. Check for manual 'f = open(...)' assignment
            alloc_info = self._extract_open_assignment(stmt)
            if alloc_info:
                var_name, open_line, target_node = alloc_info

                resource = Resource(
                    variable_name=var_name,
                    resource_type="file",
                    opening_line=open_line,
                    function_name=function_name,
                    status="LEAK",
                    file_path=self.current_file,
                )

                subsequent_stmts = statements[i + 1 :] + (outer_subsequent or [])

                # If parent_try has a guaranteed finally close, evaluate that first
                if parent_try and parent_try.finalbody:
                    finally_close = self._find_close_in_stmts(parent_try.finalbody, var_name)
                    if finally_close and not self._find_unclosed_exit_detail(parent_try.finalbody, var_name):
                        resource.status = "SAFE"
                        resource.closing_line = finally_close
                        resource.explanation = f"Guaranteed closed in finally block at line {finally_close}."
                        resource.leak_path = None
                        self.resources.append(resource)
                        continue

                status, close_line, problem, leak_path, recommendation = (
                    self._evaluate_control_flow(
                        var_name=var_name,
                        open_line=open_line,
                        subsequent_stmts=subsequent_stmts,
                        function_name=function_name,
                    )
                )

                # If parent_try exists without finally close, check parent_try handlers
                if parent_try and status == "SAFE":
                    for h in parent_try.handlers:
                        h_exit = self._find_unclosed_exit_detail(h.body, var_name)
                        if h_exit:
                            exit_line, exit_type = h_exit
                            exc_type_str = self._format_node(h.type) if h.type else ""
                            exc_desc = f"except {exc_type_str}" if exc_type_str else "except"
                            status = "LEAK"
                            close_line = None
                            problem = (
                                f"Resource '{var_name}' opened at line {open_line} is not closed on exception path "
                                f"'{exc_desc}' at line {h.lineno} due to {exit_type} at line {exit_line}."
                            )
                            leak_path = (
                                f"L{open_line}: open() -> L{parent_try.lineno}: try -> L{h.lineno}: {exc_desc} "
                                f"-> L{exit_line}: {exit_type} (leak)"
                            )
                            recommendation = (
                                f"Ensure '{var_name}.close()' is called in a 'finally:' block or inside the '{exc_desc}' handler, "
                                f"or use 'with open(...) as {var_name}:'."
                            )
                            break

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
                continue

            # 3. Recurse into Try statements for allocations inside try blocks
            if isinstance(stmt, ast.Try):
                self._analyze_statement_block(
                    stmt.body,
                    function_name=function_name,
                    parent_try=stmt,
                    outer_subsequent=statements[i + 1 :] + (outer_subsequent or []),
                )
                if stmt.orelse:
                    self._analyze_statement_block(
                        stmt.orelse,
                        function_name=function_name,
                        parent_try=stmt,
                        outer_subsequent=statements[i + 1 :] + (outer_subsequent or []),
                    )
                for h in stmt.handlers:
                    self._analyze_statement_block(
                        h.body,
                        function_name=function_name,
                        outer_subsequent=statements[i + 1 :] + (outer_subsequent or []),
                    )
                if stmt.finalbody:
                    self._analyze_statement_block(
                        stmt.finalbody,
                        function_name=function_name,
                        outer_subsequent=statements[i + 1 :] + (outer_subsequent or []),
                    )
                continue

            # 4. Recurse into If statements for allocations inside branches
            if isinstance(stmt, ast.If):
                self._analyze_statement_block(
                    stmt.body,
                    function_name=function_name,
                    parent_try=parent_try,
                    outer_subsequent=statements[i + 1 :] + (outer_subsequent or []),
                )
                if stmt.orelse:
                    self._analyze_statement_block(
                        stmt.orelse,
                        function_name=function_name,
                        parent_try=parent_try,
                        outer_subsequent=statements[i + 1 :] + (outer_subsequent or []),
                    )
                continue

            # 5. Recurse into loop statements
            if isinstance(stmt, (ast.For, ast.AsyncFor, ast.While)):
                self._analyze_statement_block(
                    stmt.body,
                    function_name=function_name,
                    parent_try=parent_try,
                    outer_subsequent=statements[i + 1 :] + (outer_subsequent or []),
                )
                if stmt.orelse:
                    self._analyze_statement_block(
                        stmt.orelse,
                        function_name=function_name,
                        parent_try=parent_try,
                        outer_subsequent=statements[i + 1 :] + (outer_subsequent or []),
                    )
                continue

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

            # 3. Try / Except / Finally block analysis
            if isinstance(stmt, ast.Try):
                # 3a. Guaranteed close in finally block
                finally_close = self._find_close_in_stmts(stmt.finalbody, var_name)
                if finally_close:
                    finally_exit = self._find_unclosed_exit_detail(stmt.finalbody, var_name)
                    if not finally_exit:
                        return (
                            "SAFE",
                            finally_close,
                            f"Guaranteed closed in finally block at line {finally_close}.",
                            None,
                            "",
                        )

                # 3b. Except handlers early return or raise before close
                for h in stmt.handlers:
                    exc_type_str = self._format_node(h.type) if h.type else ""
                    exc_desc = f"except {exc_type_str}" if exc_type_str else "except"
                    h_exit = self._find_unclosed_exit_detail(h.body, var_name)
                    if h_exit:
                        exit_line, exit_type = h_exit
                        problem = (
                            f"Resource '{var_name}' opened at line {open_line} is not closed on exception path "
                            f"'{exc_desc}' at line {h.lineno} due to {exit_type} at line {exit_line}."
                        )
                        leak_path = (
                            f"{base_path} -> L{stmt.lineno}: try -> L{h.lineno}: {exc_desc} "
                            f"-> L{exit_line}: {exit_type} (leak)"
                        )
                        recommendation = (
                            f"Ensure '{var_name}.close()' is called in a 'finally:' block or inside the '{exc_desc}' handler, "
                            f"or use 'with open(...) as {var_name}:'."
                        )
                        return "LEAK", None, problem, leak_path, recommendation

                # 3c. Try block early return before close
                try_return = self._find_unclosed_return_in_stmts(stmt.body, var_name)
                if try_return:
                    problem = (
                        f"Resource '{var_name}' opened at line {open_line} is not closed in try-block "
                        f"due to early return at line {try_return}."
                    )
                    leak_path = f"{base_path} -> L{stmt.lineno}: try -> L{try_return}: return (leak)"
                    recommendation = (
                        f"Ensure '{var_name}.close()' executes in a 'finally:' block, "
                        f"or use 'with open(...) as {var_name}:'."
                    )
                    return "LEAK", None, problem, leak_path, recommendation

                # 3d. Close in try-block but missing in finally block (leaks on error)
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
                    return getattr(child, "lineno", getattr(s, "lineno", None))
        return None

    def _find_unclosed_exit_detail(
        self, stmts: List[ast.stmt], var_name: str
    ) -> Optional[Tuple[int, str]]:
        """Find line number and exit type ('return' or 'raise') of an exit occurring before var_name.close()."""
        for s in stmts:
            if isinstance(s, ast.Expr) and self._is_close_call(s.value, var_name):
                return None  # Closed before any exit in this sequence

            if isinstance(s, ast.Return):
                return s.lineno, "return"

            if isinstance(s, ast.Raise):
                return s.lineno, "raise"

            if isinstance(s, ast.If):
                exit_body = self._find_unclosed_exit_detail(s.body, var_name)
                if exit_body:
                    return exit_body
                if s.orelse:
                    exit_else = self._find_unclosed_exit_detail(s.orelse, var_name)
                    if exit_else:
                        return exit_else

            if isinstance(s, ast.Try):
                finally_close = self._find_close_in_stmts(s.finalbody, var_name)
                if not finally_close:
                    try_exit = self._find_unclosed_exit_detail(s.body, var_name)
                    if try_exit:
                        return try_exit
                    for h in s.handlers:
                        h_exit = self._find_unclosed_exit_detail(h.body, var_name)
                        if h_exit:
                            return h_exit

        return None

    def _find_unclosed_exit_in_stmts(
        self, stmts: List[ast.stmt], var_name: str
    ) -> Optional[int]:
        """Find line of a return/raise statement that occurs before any var_name.close() in statements."""
        detail = self._find_unclosed_exit_detail(stmts, var_name)
        return detail[0] if detail else None

    def _find_unclosed_return_in_stmts(
        self, stmts: List[ast.stmt], var_name: str
    ) -> Optional[int]:
        """Find line number of a return occurring before any var_name.close() in statements."""
        for s in stmts:
            if isinstance(s, ast.Expr) and self._is_close_call(s.value, var_name):
                return None
            if isinstance(s, ast.Return):
                return s.lineno
            if isinstance(s, ast.If):
                exit_body = self._find_unclosed_return_in_stmts(s.body, var_name)
                if exit_body:
                    return exit_body
                if s.orelse:
                    exit_else = self._find_unclosed_return_in_stmts(s.orelse, var_name)
                    if exit_else:
                        return exit_else
        return None

