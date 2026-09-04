"""Main LeakAnalyzer coordinating AST resource detection and control flow."""

from leakguard.analyzer.close_detector import CloseDetector
import ast
from pathlib import Path
from typing import List, Optional, Union

from ..models.resource import Resource
from ..parser.python_parser import PythonParser, ParseResult
from .resource_detector import ResourceDetector
from .control_flow import ControlFlowAnalyzer


class LeakAnalyzer(ast.NodeVisitor):
    """AST visitor that tracks file resources and detects leaks across control-flow paths."""

    def __init__(self) -> None:
        self.resources: List[Resource] = []
        self.current_file: str = ""
        self._current_function: Optional[str] = None
        self._parser = PythonParser()


    def analyze_file(self, file_path: Union[str, Path]) -> tuple[ParseResult, List[Resource]]:
        """Parse and analyze a single file for resource leaks."""
        res = self._parser.parse_file(file_path)
        if not res.success or res.tree is None:
            return res, []

        resources = self.analyze_tree(res.tree, file_path=str(file_path))
        return res, resources

    def analyze_tree(self, tree: ast.AST, file_path: str = "") -> List[Resource]:
        """Analyze an AST tree for resource leaks."""
        self.resources = []
        self.current_file = file_path
        self._current_function = None
        self.visit(tree)
        return list(self.resources)

    # -------------------------------------------------------------------------
    # Visitors
    # -------------------------------------------------------------------------

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        prev = self._current_function
        self._current_function = node.name
        self._analyze_statements(node.body)
        self.generic_visit(node)
        self._current_function = prev

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        prev = self._current_function
        self._current_function = node.name
        self._analyze_statements(node.body)
        self.generic_visit(node)
        self._current_function = prev

    def visit_Module(self, node: ast.Module) -> None:
        self._analyze_statements(node.body)
        self.generic_visit(node)

    # -------------------------------------------------------------------------
    # Analysis
    # -------------------------------------------------------------------------

    def _analyze_statements(
        self,
        statements: List[ast.stmt],
        parent_try: Optional[ast.Try] = None,
        outer_subsequent: Optional[List[ast.stmt]] = None,
    ) -> None:
        for i, stmt in enumerate(statements):
            # 1. with open(...) context manager (SAFE)
            if isinstance(stmt, (ast.With, ast.AsyncWith)):
                self._handle_with(stmt)
                self._analyze_statements(
                    stmt.body,
                    parent_try=parent_try,
                    outer_subsequent=statements[i + 1 :] + (outer_subsequent or []),
                )
                continue

            # 2. Raw allocation: f = open(...) or conn = sqlite3.connect(...)
            alloc = ResourceDetector.extract_allocation(stmt)
            if alloc:
                var_name, open_line, target, *rest = alloc
                res_type = rest[0] if rest else "file"
                acquire_name = "sqlite3.connect" if res_type == "SQLite connection" else "open"

                resource = Resource(
                    variable_name=var_name,
                    resource_type=res_type,
                    opening_line=open_line,
                    function_name=self._current_function,
                    status="LEAK",
                    file_path=self.current_file,
                )

                subsequent_stmts = statements[i + 1 :] + (outer_subsequent or [])

                # If parent_try has a guaranteed finally close, evaluate that first
                if parent_try and parent_try.finalbody:
                    finally_close = CloseDetector.find_close_in_stmts(parent_try.finalbody, var_name)
                    if finally_close and not ControlFlowAnalyzer._find_unclosed_exit_detail(parent_try.finalbody, var_name):
                        resource.status = "SAFE"
                        resource.closing_line = finally_close
                        resource.explanation = f"Guaranteed closed in finally block at line {finally_close}."
                        resource.leak_path = None
                        self.resources.append(resource)
                        continue

                status, close_line, problem, leak_path, _ = (
                    ControlFlowAnalyzer.evaluate_resource_lifecycle(
                        var_name=var_name,
                        open_line=open_line,
                        subsequent_stmts=subsequent_stmts,
                        function_name=self._current_function,
                        resource_type=res_type,
                        acquire_name=acquire_name,
                    )
                )

                # If parent_try exists without finally close, check parent_try handlers
                if parent_try and status == "SAFE":
                    for h in parent_try.handlers:
                        h_exit = ControlFlowAnalyzer._find_unclosed_exit_detail(h.body, var_name)
                        if h_exit:
                            exit_line, exit_type = h_exit
                            exc_type_str = ControlFlowAnalyzer.format_condition(h.type) if h.type else ""
                            exc_desc = f"except {exc_type_str}" if exc_type_str else "except"
                            status = "LEAK"
                            close_line = None
                            problem = (
                                f"Resource '{var_name}' opened at line {open_line} is not closed on exception path "
                                f"'{exc_desc}' at line {h.lineno} due to {exit_type} at line {exit_line}."
                            )
                            leak_path = (
                                f"L{open_line}: {acquire_name}() -> L{parent_try.lineno}: try -> L{h.lineno}: {exc_desc} "
                                f"-> L{exit_line}: {exit_type} (leak)"
                            )
                            break

                resource.status = status
                resource.closing_line = close_line
                resource.explanation = problem
                resource.leak_path = leak_path
                self.resources.append(resource)
                continue

            # 3. Recurse into Try statements
            if isinstance(stmt, ast.Try):
                self._analyze_statements(
                    stmt.body,
                    parent_try=stmt,
                    outer_subsequent=statements[i + 1 :] + (outer_subsequent or []),
                )
                if stmt.orelse:
                    self._analyze_statements(
                        stmt.orelse,
                        parent_try=stmt,
                        outer_subsequent=statements[i + 1 :] + (outer_subsequent or []),
                    )
                for h in stmt.handlers:
                    self._analyze_statements(
                        h.body,
                        outer_subsequent=statements[i + 1 :] + (outer_subsequent or []),
                    )
                if stmt.finalbody:
                    self._analyze_statements(
                        stmt.finalbody,
                        outer_subsequent=statements[i + 1 :] + (outer_subsequent or []),
                    )
                continue

            # 4. Recurse into If statements
            if isinstance(stmt, ast.If):
                self._analyze_statements(
                    stmt.body,
                    parent_try=parent_try,
                    outer_subsequent=statements[i + 1 :] + (outer_subsequent or []),
                )
                if stmt.orelse:
                    self._analyze_statements(
                        stmt.orelse,
                        parent_try=parent_try,
                        outer_subsequent=statements[i + 1 :] + (outer_subsequent or []),
                    )
                continue

            # 5. Recurse into loop statements
            if isinstance(stmt, (ast.For, ast.AsyncFor, ast.While)):
                self._analyze_statements(
                    stmt.body,
                    parent_try=parent_try,
                    outer_subsequent=statements[i + 1 :] + (outer_subsequent or []),
                )
                if stmt.orelse:
                    self._analyze_statements(
                        stmt.orelse,
                        parent_try=parent_try,
                        outer_subsequent=statements[i + 1 :] + (outer_subsequent or []),
                    )
                continue

    def _handle_with(self, node: ast.AST) -> None:
        items = getattr(node, "items", [])
        for item in items:
            context_expr = getattr(item, "context_expr", None)
            if context_expr and ResourceDetector.is_open_call(context_expr):
                opt = getattr(item, "optional_vars", None)
                var_name = opt.id if isinstance(opt, ast.Name) else "<context_manager>"
                self.resources.append(
                    Resource(
                        variable_name=var_name,
                        resource_type="file",
                        opening_line=node.lineno,
                        function_name=self._current_function,
                        status="SAFE",
                        closing_line=getattr(node, "end_lineno", node.lineno),
                        explanation=f"Safely managed by context manager (with open(...) as {var_name}).",
                        file_path=self.current_file,
                        is_context_manager=True,
                    )
                )
