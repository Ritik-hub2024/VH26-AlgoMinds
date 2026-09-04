"""Base lifecycle rule providing reusable control-flow analysis for resource leak detection.

Operates strictly on Python Abstract Syntax Trees (AST) without plain-text matching or code execution.
Provides intra-procedural control-flow evaluation across sequential statements, if/else branches,
early returns, exception handlers, and finally cleanup blocks.
Subclasses define resource-specific acquisition patterns and release semantics.
"""

import ast
from typing import List, Optional, Tuple, Sequence

from analyzer.base import BaseRule
from models.issue import Severity
from models.resource import Resource


class BaseResourceLifecycleRule(BaseRule):
    """Abstract base rule for intra-procedural resource lifecycle tracking and leak detection."""

    rule_id: str = "LEAK000"
    description: str = "Resource lifecycle leak"
    severity: Severity = Severity.HIGH
    resource_type: str = "resource"
    acquire_name: str = "acquire"
    release_method_name: str = "close"

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
    # Hooks for Subclasses
    # -------------------------------------------------------------------------

    def _is_acquire_call(self, call_node: ast.AST) -> bool:
        """Check if AST node represents an acquisition call for this resource type."""
        raise NotImplementedError

    def _extract_acquire_assignment(
        self, stmt: ast.AST
    ) -> Optional[Tuple[str, int, ast.AST]]:
        """Extract variable name, opening line, and target node from an assignment to acquisition."""
        # Assign: var = acquire(...)
        if isinstance(stmt, ast.Assign) and self._is_acquire_call(stmt.value):
            for target in stmt.targets:
                if isinstance(target, ast.Name):
                    return target.id, stmt.lineno, target

        # AnnAssign: var: Any = acquire(...)
        if (
            isinstance(stmt, ast.AnnAssign)
            and stmt.value is not None
            and self._is_acquire_call(stmt.value)
        ):
            if isinstance(stmt.target, ast.Name):
                return stmt.target.id, stmt.lineno, stmt.target

        return None

    def _is_release_call(self, call_node: ast.AST, var_name: str) -> bool:
        """Check if AST node is an explicit var_name.<release_method_name>() call."""
        if not isinstance(call_node, ast.Call):
            return False

        func = call_node.func
        return (
            isinstance(func, ast.Attribute)
            and func.attr == self.release_method_name
            and isinstance(func.value, ast.Name)
            and func.value.id == var_name
        )

    def _handle_with_statement(
        self, node: ast.AST, function_name: Optional[str]
    ) -> None:
        """Process 'with' statement and register as safe context manager if applicable."""
        pass

    def _format_node(self, node: ast.AST) -> str:
        """Helper to get clean string representation of an AST expression."""
        try:
            return ast.unparse(node).strip()
        except Exception:
            return getattr(node, "id", "condition")

    def _get_base_path(self, open_line: int) -> str:
        """Base leak path string."""
        return f"L{open_line}: {self.acquire_name}()"

    # -------------------------------------------------------------------------
    # Recommendation Helpers (Overrideable)
    # -------------------------------------------------------------------------

    def _recommend_unclosed(self, var_name: str) -> str:
        return f"Add '{var_name}.{self.release_method_name}()' or manage lifecycle properly."

    def _recommend_early_return(self, var_name: str, exit_line: int) -> str:
        return f"Call '{var_name}.{self.release_method_name}()' before returning at line {exit_line}."

    def _recommend_raise(self, var_name: str) -> str:
        return f"Wrap resource in 'try...finally' to guarantee '{var_name}.{self.release_method_name}()' runs on error."

    def _recommend_exception_path(self, var_name: str, exc_desc: str) -> str:
        return (
            f"Ensure '{var_name}.{self.release_method_name}()' is called in a 'finally:' block "
            f"or inside the '{exc_desc}' handler."
        )

    def _recommend_try_return(self, var_name: str, try_return: int) -> str:
        return f"Ensure '{var_name}.{self.release_method_name}()' executes in a 'finally:' block."

    def _recommend_try_close_missing_finally(self, var_name: str) -> str:
        return f"Move '{var_name}.{self.release_method_name}()' into a 'finally:' block."

    def _recommend_conditional(self, var_name: str, exit_line: int) -> str:
        return f"Invoke '{var_name}.{self.release_method_name}()' before returning at line {exit_line}."

    def _recommend_conditional_close(self, var_name: str) -> str:
        return f"Ensure '{var_name}.{self.release_method_name}()' executes on all code paths."

    def _recommend_reassign(self, var_name: str) -> str:
        return f"Close previous resource '{var_name}.{self.release_method_name}()' before reassigning."

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
        """Analyze a linear block of statements for resource allocations and guarantees of release."""
        for i, stmt in enumerate(statements):
            # 1. Check for context manager
            if isinstance(stmt, (ast.With, ast.AsyncWith)):
                self._handle_with_statement(stmt, function_name)
                # Recurse into with-block body to check for any nested raw acquire calls
                self._analyze_statement_block(
                    stmt.body,
                    function_name=function_name,
                    parent_try=parent_try,
                    outer_subsequent=statements[i + 1 :] + (outer_subsequent or []),
                )
                continue

            # 2. Check for resource assignment
            alloc_info = self._extract_acquire_assignment(stmt)
            if alloc_info:
                var_name, open_line, target_node = alloc_info

                resource = Resource(
                    variable_name=var_name,
                    resource_type=self.resource_type,
                    opening_line=open_line,
                    function_name=function_name,
                    status="LEAK",
                    file_path=self.current_file,
                )

                subsequent_stmts = statements[i + 1 :] + (outer_subsequent or [])

                # If parent_try has a guaranteed finally close, evaluate that first
                if parent_try and parent_try.finalbody:
                    finally_close = self._find_release_in_stmts(parent_try.finalbody, var_name)
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
                                f"{self._get_base_path(open_line)} -> L{parent_try.lineno}: try -> L{h.lineno}: {exc_desc} "
                                f"-> L{exit_line}: {exit_type} (leak)"
                            )
                            recommendation = self._recommend_exception_path(var_name, exc_desc)
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
                        f"Resource '{var_name}' (type: {self.resource_type}) allocated at line {open_line} {scope_desc} "
                        f"is not guaranteed to be closed: {problem}"
                    )
                    self.add_issue(
                        node=target_node,
                        message=message,
                        recommendation=recommendation,
                        severity=self.severity,
                        resource_name=var_name,
                        resource_type=self.resource_type,
                        problem=problem,
                        leak_path=leak_path or self._get_base_path(open_line),
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

    def _evaluate_control_flow(
        self,
        var_name: str,
        open_line: int,
        subsequent_stmts: List[ast.stmt],
        function_name: Optional[str],
    ) -> Tuple[str, Optional[int], str, Optional[str], str]:
        """Perform intra-procedural control-flow analysis for sequential statements, try/finally, and if/else branches.

        Returns:
            (status, closing_line, problem, leak_path, recommendation)
        """
        base_path = self._get_base_path(open_line)

        if not subsequent_stmts:
            problem = f"Resource '{var_name}' opened at line {open_line} is never closed before end of scope."
            leak_path = f"{base_path} -> end of scope"
            recommendation = self._recommend_unclosed(var_name)
            return "LEAK", None, problem, leak_path, recommendation

        for stmt in subsequent_stmts:
            # 1. Direct sequential release call
            if isinstance(stmt, ast.Expr) and self._is_release_call(stmt.value, var_name):
                return (
                    "SAFE",
                    stmt.lineno,
                    f"Guaranteed closed via '{var_name}.{self.release_method_name}()' at line {stmt.lineno}.",
                    None,
                    "",
                )

            # 2. Sequential early return or raise before release
            if isinstance(stmt, ast.Return):
                problem = f"Early return at line {stmt.lineno} exits before '{var_name}.{self.release_method_name}()' is reached."
                leak_path = f"{base_path} -> L{stmt.lineno}: return (leak)"
                recommendation = self._recommend_early_return(var_name, stmt.lineno)
                return "LEAK", None, problem, leak_path, recommendation

            if isinstance(stmt, ast.Raise):
                problem = f"Exception raised at line {stmt.lineno} terminates execution before '{var_name}.{self.release_method_name}()'."
                leak_path = f"{base_path} -> L{stmt.lineno}: raise (leak)"
                recommendation = self._recommend_raise(var_name)
                return "LEAK", None, problem, leak_path, recommendation

            # 3. Try / Except / Finally block analysis
            if isinstance(stmt, ast.Try):
                # 3a. Guaranteed release in finally block
                finally_close = self._find_release_in_stmts(stmt.finalbody, var_name)
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

                # 3b. Except handlers early return or raise before release
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
                        recommendation = self._recommend_exception_path(var_name, exc_desc)
                        return "LEAK", None, problem, leak_path, recommendation

                # 3c. Try block early return before release
                try_return = self._find_unclosed_return_in_stmts(stmt.body, var_name)
                if try_return:
                    problem = (
                        f"Resource '{var_name}' opened at line {open_line} is not closed in try-block "
                        f"due to early return at line {try_return}."
                    )
                    leak_path = f"{base_path} -> L{stmt.lineno}: try -> L{try_return}: return (leak)"
                    recommendation = self._recommend_try_return(var_name, try_return)
                    return "LEAK", None, problem, leak_path, recommendation

                # 3d. Close in try-block but missing in finally block (leaks on error)
                try_close = self._find_release_in_stmts(stmt.body, var_name)
                if try_close:
                    problem = f"Closed in try-block at line {try_close}, but missing in finally block (leaks on error)."
                    leak_path = f"{base_path} -> L{stmt.lineno}: try (exception path leaks)"
                    recommendation = self._recommend_try_close_missing_finally(var_name)
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
                    recommendation = self._recommend_conditional(var_name, exit_line)
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
                        recommendation = self._recommend_conditional(var_name, else_exit_line)
                        return "LEAK", None, problem, leak_path, recommendation

                # Check if release is called inside both if and else branches
                body_close = self._find_release_in_stmts(stmt.body, var_name)
                else_close = self._find_release_in_stmts(stmt.orelse, var_name) if stmt.orelse else None

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
                    recommendation = self._recommend_conditional_close(var_name)
                    return "LEAK", body_close, problem, leak_path, recommendation

            # 5. Reassignment to same variable without release
            alloc_info = self._extract_acquire_assignment(stmt)
            if alloc_info and alloc_info[0] == var_name:
                problem = f"Variable '{var_name}' is reassigned at line {stmt.lineno} before previous resource was closed."
                leak_path = f"{base_path} -> L{stmt.lineno}: reassigned"
                recommendation = self._recommend_reassign(var_name)
                return "LEAK", None, problem, leak_path, recommendation

        problem = f"Resource '{var_name}' opened at line {open_line} is never closed."
        leak_path = f"{base_path} -> end of scope (no close)"
        recommendation = self._recommend_unclosed(var_name)
        return "LEAK", None, problem, leak_path, recommendation

    def _find_release_in_stmts(
        self, stmts: List[ast.stmt], var_name: str
    ) -> Optional[int]:
        """Find the line number of a release call within a list of statements."""
        for s in stmts:
            if isinstance(s, ast.Expr) and self._is_release_call(s.value, var_name):
                return s.lineno
            # Recursively check nested nodes
            for child in ast.walk(s):
                if isinstance(child, ast.Call) and self._is_release_call(child, var_name):
                    return getattr(child, "lineno", getattr(s, "lineno", None))
        return None

    def _find_unclosed_exit_detail(
        self, stmts: List[ast.stmt], var_name: str
    ) -> Optional[Tuple[int, str]]:
        """Find line number and exit type ('return' or 'raise') of an exit occurring before release."""
        for s in stmts:
            if isinstance(s, ast.Expr) and self._is_release_call(s.value, var_name):
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
                finally_close = self._find_release_in_stmts(s.finalbody, var_name)
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
        """Find line of a return/raise statement that occurs before release in statements."""
        detail = self._find_unclosed_exit_detail(stmts, var_name)
        return detail[0] if detail else None

    def _find_unclosed_return_in_stmts(
        self, stmts: List[ast.stmt], var_name: str
    ) -> Optional[int]:
        """Find line number of a return occurring before release in statements."""
        for s in stmts:
            if isinstance(s, ast.Expr) and self._is_release_call(s.value, var_name):
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
