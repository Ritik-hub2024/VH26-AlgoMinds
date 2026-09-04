"""Intra-procedural control-flow analysis for resource leak detection."""

import ast
from typing import List, Optional, Tuple
from .close_detector import CloseDetector
from .resource_detector import ResourceDetector


class ControlFlowAnalyzer:
    """Evaluates control-flow paths across sequential statements and if/else branches.

    Detects leaks where early returns bypass resource closure.
    """

    @staticmethod
    def format_condition(node: ast.AST) -> str:
        """Get string representation of an if condition expression."""
        try:
            return ast.unparse(node).strip()
        except Exception:
            return getattr(node, "id", "condition")

    @classmethod
    def evaluate_resource_lifecycle(
        cls,
        var_name: str,
        open_line: int,
        subsequent_stmts: List[ast.stmt],
        function_name: Optional[str] = None,
    ) -> Tuple[str, Optional[int], str, Optional[str], str]:
        """Analyze subsequent statements along control-flow paths.

        Returns:
            (status, closing_line, problem, leak_path, recommendation)
        """
        base_path = f"L{open_line}: open()"

        if not subsequent_stmts:
            problem = f"Resource '{var_name}' opened at line {open_line} is never closed."
            leak_path = f"{base_path} -> end of scope (no close)"
            recommendation = f"Ensure '{var_name}.close()' is called before exit, or use 'with open(...) as {var_name}:'."
            return "LEAK", None, problem, leak_path, recommendation

        for stmt in subsequent_stmts:
            # 1. Sequential close call
            if isinstance(stmt, ast.Expr) and CloseDetector.is_close_call(stmt.value, var_name):
                return (
                    "SAFE",
                    stmt.lineno,
                    f"Guaranteed closed via '{var_name}.close()' at line {stmt.lineno}.",
                    None,
                    "",
                )

            # 2. Sequential early return or raise
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

            # 3. Try / Finally block
            if isinstance(stmt, ast.Try):
                finally_close = CloseDetector.find_close_in_stmts(stmt.finalbody, var_name)
                if finally_close:
                    return (
                        "SAFE",
                        finally_close,
                        f"Guaranteed closed in finally block at line {finally_close}.",
                        None,
                        "",
                    )
                try_close = CloseDetector.find_close_in_stmts(stmt.body, var_name)
                if try_close:
                    problem = f"Closed in try-block at line {try_close}, but missing in finally block (leaks on error)."
                    leak_path = f"{base_path} -> L{stmt.lineno}: try (exception path leaks)"
                    recommendation = f"Move '{var_name}.close()' into a 'finally:' block or use 'with open(...) as {var_name}:'."
                    return "LEAK", try_close, problem, leak_path, recommendation

            # 4. If / Else branching
            if isinstance(stmt, ast.If):
                cond_text = cls.format_condition(stmt.test)
                if_desc = f"if {cond_text}"

                # Pattern: open -> if condition -> return -> close
                exit_line = cls._find_unclosed_exit(stmt.body, var_name)
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

                if stmt.orelse:
                    else_exit_line = cls._find_unclosed_exit(stmt.orelse, var_name)
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

                # Check if closed in both branches
                body_close = CloseDetector.find_close_in_stmts(stmt.body, var_name)
                else_close = CloseDetector.find_close_in_stmts(stmt.orelse, var_name) if stmt.orelse else None

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

            # 5. Reassignment without close
            alloc_info = ResourceDetector.extract_allocation(stmt)
            if alloc_info and alloc_info[0] == var_name:
                problem = f"Variable '{var_name}' is reassigned at line {stmt.lineno} before previous resource was closed."
                leak_path = f"{base_path} -> L{stmt.lineno}: reassigned"
                recommendation = f"Close previous resource '{var_name}.close()' before reassigning."
                return "LEAK", None, problem, leak_path, recommendation

        problem = f"Resource '{var_name}' opened at line {open_line} is never closed."
        leak_path = f"{base_path} -> end of scope (no close)"
        recommendation = f"Add '{var_name}.close()' or convert to 'with open(...) as {var_name}:'."
        return "LEAK", None, problem, leak_path, recommendation

    @classmethod
    def _find_unclosed_exit(
        cls, stmts: List[ast.stmt], var_name: str
    ) -> Optional[int]:
        """Find return/raise occurring before any var_name.close() in a statement list."""
        for s in stmts:
            if isinstance(s, ast.Expr) and CloseDetector.is_close_call(s.value, var_name):
                return None
            if isinstance(s, (ast.Return, ast.Raise)):
                return s.lineno
            if isinstance(s, ast.If):
                exit_body = cls._find_unclosed_exit(s.body, var_name)
                if exit_body:
                    return exit_body
                if s.orelse:
                    exit_else = cls._find_unclosed_exit(s.orelse, var_name)
                    if exit_else:
                        return exit_else
        return None
