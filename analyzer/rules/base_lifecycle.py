"""Base lifecycle rule providing reusable control-flow analysis for resource leak detection.

Operates strictly on Python Abstract Syntax Trees (AST) without plain-text matching or code execution.
Provides intra-procedural control-flow evaluation across sequential statements, if/else branches,
early returns, exception handlers, and finally cleanup blocks.
Subclasses define resource-specific acquisition patterns and release semantics.
"""

import ast
from typing import List, Optional, Tuple, Sequence, Set, Union, Dict

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
        self._module_functions: dict = {}

    def _index_functions(self, tree: ast.AST) -> None:
        """Index all function definitions within the module for lightweight interprocedural proofs."""
        self._module_functions = {}
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._module_functions[node.name] = node

    def run(self, tree: ast.AST, file_path: str) -> List[Resource]:
        """Execute rule on AST and populate detected issues."""
        self.current_file = file_path
        self.issues = []
        self.resources = []
        self._current_function = None
        self._index_functions(tree)
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
        # Assign: var = acquire(...) or self.attr = acquire(...)
        if isinstance(stmt, ast.Assign) and self._is_acquire_call(stmt.value):
            for target in stmt.targets:
                if isinstance(target, ast.Name):
                    return target.id, stmt.lineno, target
                if isinstance(target, ast.Attribute):
                    try:
                        return ast.unparse(target).strip(), stmt.lineno, target
                    except Exception:
                        val = getattr(target.value, "id", "self")
                        return f"{val}.{target.attr}", stmt.lineno, target

        # AnnAssign: var: Any = acquire(...) or self.attr: Any = acquire(...)
        if (
            isinstance(stmt, ast.AnnAssign)
            and stmt.value is not None
            and self._is_acquire_call(stmt.value)
        ):
            if isinstance(stmt.target, ast.Name):
                return stmt.target.id, stmt.lineno, stmt.target
            if isinstance(stmt.target, ast.Attribute):
                try:
                    return ast.unparse(stmt.target).strip(), stmt.lineno, stmt.target
                except Exception:
                    val = getattr(stmt.target.value, "id", "self")
                    return f"{val}.{stmt.target.attr}", stmt.lineno, stmt.target

        return None

    def _is_release_call(self, call_node: ast.AST, var_name: str) -> bool:
        """Check if AST node is an explicit var_name.<release_method_name>() call."""
        if not isinstance(call_node, ast.Call):
            return False

        func = call_node.func
        if not (isinstance(func, ast.Attribute) and func.attr == self.release_method_name):
            return False

        if isinstance(func.value, ast.Name) and func.value.id == var_name:
            return True

        try:
            if ast.unparse(func.value).strip() == var_name:
                return True
        except Exception:
            pass

        return False

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
                if parent_try:
                    if parent_try.finalbody:
                        finally_close = self._find_release_in_stmts(parent_try.finalbody, var_name)
                        if finally_close and not self._find_unclosed_exit_detail(parent_try.finalbody, var_name):
                            resource.status = "SAFE"
                            resource.closing_line = finally_close
                            resource.explanation = f"Guaranteed closed in finally block at line {finally_close}."
                            resource.leak_path = None
                            self.resources.append(resource)
                            continue
                    nested_fin = self._find_guaranteed_release_in_stmts(parent_try.body, var_name)
                    if nested_fin:
                        resource.status = "SAFE"
                        resource.closing_line = nested_fin
                        resource.explanation = f"Guaranteed closed in nested finally block at line {nested_fin}."
                        resource.leak_path = None
                        self.resources.append(resource)
                        continue

                status, close_line, problem, leak_path, recommendation, classification, ownership_status, callee_name, transfer_line = (
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
                            classification = "LEAK"
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
                resource.classification = classification
                resource.ownership_status = ownership_status
                resource.callee_name = callee_name
                resource.transfer_line = transfer_line
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
                        classification="LEAK",
                        ownership_status=ownership_status,
                        callee_name=callee_name,
                        transfer_line=transfer_line,
                    )
                elif status == "UNKNOWN":
                    scope_desc = (
                        f"in function '{function_name}'"
                        if function_name
                        else "at module level"
                    )
                    message = (
                        f"Resource '{var_name}' (type: {self.resource_type}) allocated at line {open_line} {scope_desc}: {problem}"
                    )
                    self.add_issue(
                        node=target_node,
                        message=message,
                        recommendation=recommendation,
                        severity=Severity.LOW,
                        resource_name=var_name,
                        resource_type=self.resource_type,
                        problem=problem,
                        leak_path=leak_path or self._get_base_path(open_line),
                        function_name=function_name or "<module>",
                        classification="UNKNOWN",
                        ownership_status=ownership_status,
                        callee_name=callee_name,
                        transfer_line=transfer_line,
                        scope_limitation="LeakGuard currently performs limited interprocedural reasoning.",
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
    ) -> Tuple[str, Optional[int], str, Optional[str], str, str, str, str, Optional[int]]:
        """Perform intra-procedural control-flow and ownership analysis.

        Returns:
            (status, closing_line, problem, leak_path, recommendation, classification, ownership_status, callee_name, transfer_line)
        """
        base_path = self._get_base_path(open_line)
        aliases: Set[str] = {var_name}
        is_attribute = "." in var_name or var_name.startswith("self.")

        if not subsequent_stmts:
            if is_attribute:
                problem = f"Resource stored in attribute '{var_name}'. Cleanup cannot be proven within the current analysis scope."
                leak_path = f"{base_path} -> attribute storage '{var_name}'"
                recommendation = f"Ensure '{var_name}' is closed in a cleanup method or context manager."
                return "UNKNOWN", None, problem, leak_path, recommendation, "UNKNOWN", "ATTRIBUTE", "", None

            problem = f"Resource '{var_name}' opened at line {open_line} is never closed before end of scope."
            leak_path = f"{base_path} -> end of scope"
            recommendation = self._recommend_unclosed(var_name)
            return "LEAK", None, problem, leak_path, recommendation, "LEAK", "LOCAL", "", None

        for idx, stmt in enumerate(subsequent_stmts):
            remaining_stmts = subsequent_stmts[idx + 1 :]

            # 1. Direct sequential release call on var_name or any alias
            for alias in list(aliases):
                if isinstance(stmt, ast.Expr) and self._is_release_call(stmt.value, alias):
                    owner_st = "LOCAL" if alias == var_name else "ALIAS"
                    return (
                        "SAFE",
                        stmt.lineno,
                        f"Guaranteed closed via '{alias}.{self.release_method_name}()' at line {stmt.lineno}.",
                        None,
                        "",
                        "SAFE",
                        owner_st,
                        "",
                        None,
                    )

            # 2. Local Alias assignment: g = f (where f is in aliases)
            if isinstance(stmt, ast.Assign):
                if isinstance(stmt.value, ast.Name) and stmt.value.id in aliases:
                    for target in stmt.targets:
                        if isinstance(target, ast.Name):
                            aliases.add(target.id)
            elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
                if isinstance(stmt.value, ast.Name) and stmt.value.id in aliases:
                    if isinstance(stmt.target, ast.Name):
                        aliases.add(stmt.target.id)

            # 3. Reassignment without release
            # If stmt assigns to var_name or any alias, but NOT alias creation (e.g. g = f)
            is_reassign = False
            if isinstance(stmt, ast.Assign):
                for target in stmt.targets:
                    if isinstance(target, ast.Name) and target.id in aliases:
                        if not (isinstance(stmt.value, ast.Name) and stmt.value.id in aliases):
                            is_reassign = True
                    elif isinstance(target, ast.Attribute):
                        try:
                            if ast.unparse(target).strip() in aliases:
                                is_reassign = True
                        except Exception:
                            pass
            elif isinstance(stmt, ast.AnnAssign):
                if isinstance(stmt.target, ast.Name) and stmt.target.id in aliases:
                    if not (stmt.value and isinstance(stmt.value, ast.Name) and stmt.value.id in aliases):
                        is_reassign = True
                elif isinstance(stmt.target, ast.Attribute):
                    try:
                        if ast.unparse(stmt.target).strip() in aliases:
                            is_reassign = True
                    except Exception:
                        pass

            if is_reassign:
                problem = f"Variable '{var_name}' is reassigned at line {stmt.lineno} before previous resource was closed."
                leak_path = f"{base_path} -> L{stmt.lineno}: reassigned"
                recommendation = self._recommend_reassign(var_name)
                return "LEAK", None, problem, leak_path, recommendation, "LEAK", "REASSIGNED", "", None

            # 4. Container / Collection escape: resources.append(f), dict[k] = f
            if self._check_container_escape(stmt, aliases):
                future_close = self._find_release_in_stmts(remaining_stmts, aliases)
                if not future_close:
                    problem = f"Resource '{var_name}' was stored in a container and ownership could not be proven within the current analysis scope."
                    leak_path = f"{base_path} -> L{stmt.lineno}: container escape"
                    recommendation = "Ensure resources stored in container are closed when no longer needed."
                    return "UNKNOWN", None, problem, leak_path, recommendation, "UNKNOWN", "CONTAINER", "", None

            # 5. Function argument transfer: process(f)
            transfer_info = self._find_argument_transfer(stmt, aliases)
            if transfer_info:
                callee_name, call_node, arg_idx = transfer_info
                future_close = self._find_release_in_stmts(remaining_stmts, aliases)
                if not future_close:
                    can_prove, callee_close_line = self._prove_callee_closes(callee_name, arg_idx)
                    if can_prove and callee_close_line:
                        return (
                            "SAFE",
                            callee_close_line,
                            f"Guaranteed closed by callee '{callee_name}()' at line {callee_close_line}.",
                            None,
                            "",
                            "SAFE",
                            "TRANSFERRED",
                            callee_name,
                            stmt.lineno,
                        )
                    problem = f"Resource '{var_name}' is passed to {callee_name}(); cleanup cannot be proven within the current analysis scope."
                    leak_path = f"{base_path} -> L{stmt.lineno}: {callee_name}({var_name}) (ownership transferred)"
                    recommendation = f"Ensure '{callee_name}()' or caller closes the resource, or manage lifecycle locally."
                    return "UNKNOWN", None, problem, leak_path, recommendation, "UNKNOWN", "TRANSFERRED", callee_name, stmt.lineno

            # 6. Sequential return statement
            if isinstance(stmt, ast.Return):
                if self._expr_contains_alias(stmt.value, aliases):
                    problem = (
                        f"Resource '{var_name}' is returned from {function_name or 'function'}(). "
                        f"Cleanup occurs outside the current function scope and cannot be proven here."
                    )
                    leak_path = f"{base_path} -> L{stmt.lineno}: return {self._format_node(stmt.value)} (ownership transferred via return)"
                    recommendation = f"Ensure caller of '{function_name or 'function'}' manages and closes the returned resource."
                    return "UNKNOWN", None, problem, leak_path, recommendation, "UNKNOWN", "RETURNED", "", None

                problem = f"Early return at line {stmt.lineno} exits before '{var_name}.{self.release_method_name}()' is reached."
                leak_path = f"{base_path} -> L{stmt.lineno}: return (leak)"
                recommendation = self._recommend_early_return(var_name, stmt.lineno)
                return "LEAK", None, problem, leak_path, recommendation, "LEAK", "LOCAL", "", None

            # 7. Sequential raise statement
            if isinstance(stmt, ast.Raise):
                problem = f"Exception raised at line {stmt.lineno} terminates execution before '{var_name}.{self.release_method_name}()'."
                leak_path = f"{base_path} -> L{stmt.lineno}: raise (leak)"
                recommendation = self._recommend_raise(var_name)
                return "LEAK", None, problem, leak_path, recommendation, "LEAK", "LOCAL", "", None

            # 8. Try / Except / Finally block analysis (supporting aliases)
            if isinstance(stmt, ast.Try):
                # 8a. Guaranteed release in finally block
                finally_close = self._find_release_in_stmts(stmt.finalbody, aliases)
                if finally_close:
                    finally_exit = self._find_unclosed_exit_detail(stmt.finalbody, aliases)
                    if not finally_exit:
                        return (
                            "SAFE",
                            finally_close,
                            f"Guaranteed closed in finally block at line {finally_close}.",
                            None,
                            "",
                            "SAFE",
                            "LOCAL",
                            "",
                            None,
                        )

                # Check nested try...finally
                nested_fin = self._find_guaranteed_release_in_stmts(stmt.body, aliases)
                if nested_fin:
                    return (
                        "SAFE",
                        nested_fin,
                        f"Guaranteed closed in nested finally block at line {nested_fin}.",
                        None,
                        "",
                        "SAFE",
                        "LOCAL",
                        "",
                        None,
                    )

                # 8b. Except handlers early return or raise before release
                for h in stmt.handlers:
                    exc_type_str = self._format_node(h.type) if h.type else ""
                    exc_desc = f"except {exc_type_str}" if exc_type_str else "except"
                    h_exit = self._find_unclosed_exit_detail(h.body, aliases)
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
                        return "LEAK", None, problem, leak_path, recommendation, "LEAK", "LOCAL", "", None

                # 8c. Try block early return before release
                try_return = self._find_unclosed_return_in_stmts(stmt.body, aliases)
                if try_return:
                    problem = (
                        f"Resource '{var_name}' opened at line {open_line} is not closed in try-block "
                        f"due to early return at line {try_return}."
                    )
                    leak_path = f"{base_path} -> L{stmt.lineno}: try -> L{try_return}: return (leak)"
                    recommendation = self._recommend_try_return(var_name, try_return)
                    return "LEAK", None, problem, leak_path, recommendation, "LEAK", "LOCAL", "", None

                # 8d. Close in try-block but missing in finally block
                try_close = self._find_release_in_stmts(stmt.body, aliases)
                if try_close:
                    problem = f"Closed in try-block at line {try_close}, but missing in finally block (leaks on error)."
                    leak_path = f"{base_path} -> L{stmt.lineno}: try (exception path leaks)"
                    recommendation = self._recommend_try_close_missing_finally(var_name)
                    return "LEAK", try_close, problem, leak_path, recommendation, "LEAK", "LOCAL", "", None

            # 9. If / Else branching control-flow analysis
            if isinstance(stmt, ast.If):
                cond_text = self._format_node(stmt.test)
                if_desc = f"if {cond_text}"

                # Check if TRUE branch has an unclosed return or raise
                exit_line = self._find_unclosed_exit_in_stmts(stmt.body, aliases)
                if exit_line:
                    problem = (
                        f"Resource '{var_name}' opened at line {open_line} is not closed if condition "
                        f"'{cond_text}' at line {stmt.lineno} is met due to early return at line {exit_line}."
                    )
                    leak_path = f"{base_path} -> L{stmt.lineno}: {if_desc} -> L{exit_line}: return (leak)"
                    recommendation = self._recommend_conditional(var_name, exit_line)
                    return "LEAK", None, problem, leak_path, recommendation, "LEAK", "LOCAL", "", None

                # Check if FALSE branch (else / elif) has an unclosed return or raise
                if stmt.orelse:
                    else_exit_line = self._find_unclosed_exit_in_stmts(stmt.orelse, aliases)
                    if else_exit_line:
                        problem = (
                            f"Resource '{var_name}' opened at line {open_line} is not closed in else branch "
                            f"due to early return at line {else_exit_line}."
                        )
                        leak_path = f"{base_path} -> L{stmt.lineno}: else -> L{else_exit_line}: return (leak)"
                        recommendation = self._recommend_conditional(var_name, else_exit_line)
                        return "LEAK", None, problem, leak_path, recommendation, "LEAK", "LOCAL", "", None

                # Check if release is called inside both if and else branches
                body_close = self._find_release_in_stmts(stmt.body, aliases)
                else_close = self._find_release_in_stmts(stmt.orelse, aliases) if stmt.orelse else None

                if body_close and else_close:
                    return (
                        "SAFE",
                        body_close,
                        f"Guaranteed closed in both if and else branches (lines {body_close} and {else_close}).",
                        None,
                        "",
                        "SAFE",
                        "LOCAL",
                        "",
                        None,
                    )
                if body_close and not stmt.orelse:
                    problem = (
                        f"Resource '{var_name}' is conditionally closed in if-branch at line {body_close}, "
                        f"but leaks if condition is False."
                    )
                    leak_path = f"{base_path} -> L{stmt.lineno}: {if_desc} (False branch bypasses close)"
                    recommendation = self._recommend_conditional_close(var_name)
                    return "LEAK", body_close, problem, leak_path, recommendation, "LEAK", "LOCAL", "", None

            # 10. Loop statements (for / while)
            if isinstance(stmt, (ast.For, ast.AsyncFor, ast.While)):
                loop_exit = self._find_unclosed_exit_detail(stmt.body, aliases)
                if loop_exit:
                    exit_line, exit_type = loop_exit
                    problem = (
                        f"Resource '{var_name}' opened at line {open_line} is not closed due to "
                        f"{exit_type} inside loop at line {exit_line}."
                    )
                    leak_path = f"{base_path} -> L{stmt.lineno}: loop -> L{exit_line}: {exit_type} (leak)"
                    recommendation = self._recommend_early_return(var_name, exit_line)
                    return "LEAK", None, problem, leak_path, recommendation, "LEAK", "LOCAL", "", None

                if stmt.orelse:
                    else_exit = self._find_unclosed_exit_detail(stmt.orelse, aliases)
                    if else_exit:
                        exit_line, exit_type = else_exit
                        problem = (
                            f"Resource '{var_name}' opened at line {open_line} is not closed in loop else branch "
                            f"due to {exit_type} at line {exit_line}."
                        )
                        leak_path = f"{base_path} -> L{stmt.lineno}: loop else -> L{exit_line}: {exit_type} (leak)"
                        recommendation = self._recommend_early_return(var_name, exit_line)
                        return "LEAK", None, problem, leak_path, recommendation, "LEAK", "LOCAL", "", None

        # End of loop without close
        if is_attribute:
            problem = f"Resource stored in attribute '{var_name}'. Cleanup cannot be proven within the current analysis scope."
            leak_path = f"{base_path} -> attribute storage '{var_name}'"
            recommendation = f"Ensure '{var_name}' is closed in a cleanup method or context manager."
            return "UNKNOWN", None, problem, leak_path, recommendation, "UNKNOWN", "ATTRIBUTE", "", None

        problem = f"Resource '{var_name}' opened at line {open_line} is never closed."
        leak_path = f"{base_path} -> end of scope (no close)"
        recommendation = self._recommend_unclosed(var_name)
        return "LEAK", None, problem, leak_path, recommendation, "LEAK", "LOCAL", "", None

    # -------------------------------------------------------------------------
    # Ownership & Interprocedural Helper Methods
    # -------------------------------------------------------------------------

    def _get_callee_name(self, func_node: ast.AST) -> Optional[str]:
        """Extract function name string from Call func AST node."""
        if isinstance(func_node, ast.Name):
            return func_node.id
        if isinstance(func_node, ast.Attribute):
            return func_node.attr
        return None

    def _find_argument_transfer(
        self, stmt: ast.AST, aliases: Set[str]
    ) -> Optional[Tuple[str, ast.Call, int]]:
        """Detect if an aliased resource is passed as an argument to a function/method call."""
        for node in ast.walk(stmt):
            if isinstance(node, ast.Call):
                # Release calls are cleanup, not transfers
                if isinstance(node.func, ast.Attribute) and node.func.attr == self.release_method_name:
                    continue

                # Container append/add/etc handled by container escape check
                if isinstance(node.func, ast.Attribute) and node.func.attr in ("append", "add", "extend", "insert"):
                    continue

                # Positional argument matches
                for idx, arg in enumerate(node.args):
                    if isinstance(arg, ast.Name) and arg.id in aliases:
                        callee_name = self._get_callee_name(node.func)
                        if callee_name:
                            return callee_name, node, idx

                # Keyword argument matches
                for kw in node.keywords:
                    if isinstance(kw.value, ast.Name) and kw.value.id in aliases:
                        callee_name = self._get_callee_name(node.func)
                        if callee_name:
                            return callee_name, node, -1
        return None

    def _prove_callee_closes(
        self, callee_name: str, arg_index: int
    ) -> Tuple[bool, Optional[int]]:
        """Attempt lightweight proof that callee defined in same module unconditionally closes argument."""
        if not hasattr(self, "_module_functions") or callee_name not in self._module_functions:
            return False, None

        func_def = self._module_functions[callee_name]
        args = func_def.args.args
        if arg_index < 0 or arg_index >= len(args):
            return False, None
        param_name = args[arg_index].arg

        # The parameter must be unconditionally closed on all execution paths before any return/raise
        close_line = self._find_unconditional_release(func_def.body, param_name)
        if not close_line:
            return False, None

        # Check for unclosed exits before close_line
        exit_detail = self._find_unclosed_exit_detail(func_def.body, param_name)
        if exit_detail:
            return False, None

        # Check if param is reassigned or escapes inside callee
        for s in func_def.body:
            if isinstance(s, ast.Assign):
                for t in s.targets:
                    if isinstance(t, ast.Name) and t.id == param_name:
                        return False, None
            if isinstance(s, ast.Return) and self._expr_contains_alias(s.value, {param_name}):
                return False, None

        return True, close_line

    def _find_unconditional_release(
        self, stmts: List[ast.stmt], var_name: str
    ) -> Optional[int]:
        """Verify that var_name is unconditionally released on all execution paths."""
        for s in stmts:
            if isinstance(s, ast.Expr) and self._is_release_call(s.value, var_name):
                return s.lineno
            if isinstance(s, ast.If):
                if s.orelse:
                    body_rel = self._find_unconditional_release(s.body, var_name)
                    else_rel = self._find_unconditional_release(s.orelse, var_name)
                    if body_rel and else_rel:
                        return body_rel
            if isinstance(s, ast.Try):
                if s.finalbody:
                    fin_rel = self._find_unconditional_release(s.finalbody, var_name)
                    if fin_rel:
                        return fin_rel
                body_rel = self._find_unconditional_release(s.body, var_name)
                if body_rel and s.handlers and all(self._find_unconditional_release(h.body, var_name) for h in s.handlers):
                    return body_rel
            if isinstance(s, (ast.Return, ast.Raise)):
                return None
        return None

    def _check_container_escape(
        self, stmt: ast.AST, aliases: Set[str]
    ) -> bool:
        """Check if any aliased resource is stored into a container (list, dict, set)."""
        for node in ast.walk(stmt):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr in ("append", "add", "extend", "insert"):
                    for arg in node.args:
                        if isinstance(arg, ast.Name) and arg.id in aliases:
                            return True
                        if isinstance(arg, (ast.List, ast.Tuple, ast.Set)):
                            for elt in arg.elts:
                                if isinstance(elt, ast.Name) and elt.id in aliases:
                                    return True

        if isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                if isinstance(target, ast.Subscript):
                    if isinstance(stmt.value, ast.Name) and stmt.value.id in aliases:
                        return True
        return False

    def _expr_contains_alias(self, expr: Optional[ast.AST], aliases: Set[str]) -> bool:
        """Check if expression returns or references the resource handle itself."""
        if not expr:
            return False
        if isinstance(expr, ast.Name) and expr.id in aliases:
            return True
        if isinstance(expr, (ast.Tuple, ast.List, ast.Set)):
            return any(self._expr_contains_alias(elt, aliases) for elt in expr.elts)
        return False

    def _find_release_in_stmts(
        self, stmts: List[ast.stmt], var_names: Union[str, Sequence[str], Set[str]]
    ) -> Optional[int]:
        """Find the line number of a release call within a list of statements."""
        names = {var_names} if isinstance(var_names, str) else set(var_names)
        for s in stmts:
            if isinstance(s, ast.Expr):
                if any(self._is_release_call(s.value, n) for n in names):
                    return s.lineno
            for child in ast.walk(s):
                if isinstance(child, ast.Call) and any(self._is_release_call(child, n) for n in names):
                    return getattr(child, "lineno", getattr(s, "lineno", None))
        return None

    def _find_guaranteed_release_in_stmts(
        self, stmts: List[ast.stmt], var_names: Union[str, Sequence[str], Set[str]]
    ) -> Optional[int]:
        """Find release that is guaranteed to run in a nested try...finally block."""
        names = {var_names} if isinstance(var_names, str) else set(var_names)
        for s in stmts:
            if isinstance(s, (ast.Return, ast.Raise)):
                return None
            if isinstance(s, ast.Try):
                if s.finalbody:
                    fin_close = self._find_release_in_stmts(s.finalbody, names)
                    if fin_close and not self._find_unclosed_exit_detail(s.finalbody, names):
                        return fin_close
                nested = self._find_guaranteed_release_in_stmts(s.body, names)
                if nested:
                    return nested
        return None

    def _find_unclosed_exit_detail(
        self, stmts: List[ast.stmt], var_names: Union[str, Sequence[str], Set[str]]
    ) -> Optional[Tuple[int, str]]:
        """Find line number and exit type ('return' or 'raise') of an exit occurring before release."""
        names = {var_names} if isinstance(var_names, str) else set(var_names)
        for s in stmts:
            if isinstance(s, ast.Expr) and any(self._is_release_call(s.value, n) for n in names):
                return None  # Closed before any exit in this sequence

            if isinstance(s, ast.Return):
                return s.lineno, "return"

            if isinstance(s, ast.Raise):
                return s.lineno, "raise"

            if isinstance(s, ast.If):
                exit_body = self._find_unclosed_exit_detail(s.body, names)
                if exit_body:
                    return exit_body
                if s.orelse:
                    exit_else = self._find_unclosed_exit_detail(s.orelse, names)
                    if exit_else:
                        return exit_else

            if isinstance(s, (ast.For, ast.While)):
                loop_exit = self._find_unclosed_exit_detail(s.body, names)
                if loop_exit:
                    return loop_exit
                if s.orelse:
                    exit_else = self._find_unclosed_exit_detail(s.orelse, names)
                    if exit_else:
                        return exit_else

            if isinstance(s, ast.Try):
                finally_close = self._find_release_in_stmts(s.finalbody, names)
                if not finally_close:
                    try_exit = self._find_unclosed_exit_detail(s.body, names)
                    if try_exit:
                        return try_exit
                    for h in s.handlers:
                        h_exit = self._find_unclosed_exit_detail(h.body, names)
                        if h_exit:
                            return h_exit

        return None

    def _find_unclosed_exit_in_stmts(
        self, stmts: List[ast.stmt], var_names: Union[str, Sequence[str], Set[str]]
    ) -> Optional[int]:
        """Find line of a return/raise statement that occurs before release in statements."""
        detail = self._find_unclosed_exit_detail(stmts, var_names)
        return detail[0] if detail else None

    def _find_unclosed_return_in_stmts(
        self, stmts: List[ast.stmt], var_names: Union[str, Sequence[str], Set[str]]
    ) -> Optional[int]:
        """Find line number of a return occurring before release in statements."""
        names = {var_names} if isinstance(var_names, str) else set(var_names)
        for s in stmts:
            if isinstance(s, ast.Expr) and any(self._is_release_call(s.value, n) for n in names):
                return None
            if isinstance(s, ast.Return):
                return s.lineno
            if isinstance(s, ast.If):
                exit_body = self._find_unclosed_return_in_stmts(s.body, names)
                if exit_body:
                    return exit_body
                if s.orelse:
                    exit_else = self._find_unclosed_return_in_stmts(s.orelse, names)
                    if exit_else:
                        return exit_else
            if isinstance(s, (ast.For, ast.While)):
                loop_ret = self._find_unclosed_return_in_stmts(s.body, names)
                if loop_ret:
                    return loop_ret
                if s.orelse:
                    exit_else = self._find_unclosed_return_in_stmts(s.orelse, names)
                    if exit_else:
                        return exit_else
            if isinstance(s, ast.Try):
                finally_close = self._find_release_in_stmts(s.finalbody, names)
                if not finally_close:
                    try_ret = self._find_unclosed_return_in_stmts(s.body, names)
                    if try_ret:
                        return try_ret
                    for h in s.handlers:
                        h_ret = self._find_unclosed_return_in_stmts(h.body, names)
                        if h_ret:
                            return h_ret
        return None
