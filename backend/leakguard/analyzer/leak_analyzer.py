"""Main LeakAnalyzer coordinating AST resource detection and control flow."""

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

    def _analyze_statements(self, statements: List[ast.stmt]) -> None:
        for i, stmt in enumerate(statements):
            # 1. with open(...) context manager (SAFE)
            if isinstance(stmt, (ast.With, ast.AsyncWith)):
                self._handle_with(stmt)
                continue

            # 2. Raw allocation: f = open(...)
            alloc = ResourceDetector.extract_allocation(stmt)
            if not alloc:
                continue

            var_name, open_line, _ = alloc
            resource = Resource(
                variable_name=var_name,
                resource_type="file",
                opening_line=open_line,
                function_name=self._current_function,
                status="LEAK",
                file_path=self.current_file,
            )

            status, close_line, problem, leak_path, _ = (
                ControlFlowAnalyzer.evaluate_resource_lifecycle(
                    var_name=var_name,
                    open_line=open_line,
                    subsequent_stmts=statements[i + 1 :],
                    function_name=self._current_function,
                )
            )

            resource.status = status
            resource.closing_line = close_line
            resource.explanation = problem
            resource.leak_path = leak_path
            self.resources.append(resource)

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
