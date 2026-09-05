"""AST-guided resource leak fixer.

Transforms unclosed file and database resource allocations into safe context managers
(`with open(...) as f:`) or `try: ... finally: resource.close()` blocks.
"""

import ast
import re
from typing import Any, Dict, List, Optional, Tuple

from .validator import validate_python_syntax


class ResourceFixer:
    """Generates safe transformations for detected resource leaks."""

    def __init__(self) -> None:
        pass

    def can_fix(self, finding: Dict[str, Any]) -> bool:
        """Check whether the given finding is supported for automated safe fixing."""
        rule_id = finding.get("rule_id", "")
        resource = (finding.get("resource") or finding.get("resource_name") or "").lower()
        classification = finding.get("classification", "LEAK")
        ownership = finding.get("ownership_status", "LOCAL")

        # We safely fix local file and sqlite leaks
        if rule_id in ("LEAK001", "LEAK002"):
            if classification == "UNKNOWN" or ownership in ("TRANSFERRED", "RETURNED", "ATTRIBUTE"):
                # Interprocedural or transferred ownership requires manual review
                return False
            return True

        if "file" in resource or "open" in resource or "sqlite" in resource or "connect" in resource:
            return True

        return False

    def generate_fix(
        self, source_code: str, finding: Dict[str, Any]
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """Generate fixed source code for the given finding.

        Args:
            source_code: Complete original source code of the file.
            finding: Finding metadata dictionary containing file, line, variable, rule_id, etc.

        Returns:
            Tuple of (success: bool, fixed_code: Optional[str], error_message: Optional[str]).
        """
        if not self.can_fix(finding):
            return False, None, "Finding requires manual review (interprocedural transfer or unsupported pattern)."

        line_num = finding.get("line") or finding.get("opened_line") or 0
        rule_id = finding.get("rule_id", "LEAK001")
        var_name = finding.get("variable") or finding.get("resource_name") or "f"

        try:
            tree = ast.parse(source_code)
        except SyntaxError as se:
            return False, None, f"Original file has syntax errors: {se}"

        # Strategy 1: File leak with open() -> with open(...) as var:
        if rule_id == "LEAK001" or "file" in (finding.get("resource") or "").lower():
            return self._fix_file_leak(source_code, tree, line_num, var_name)

        # Strategy 2: SQLite connection -> try ... finally: conn.close()
        if rule_id == "LEAK002" or "sqlite" in (finding.get("resource") or "").lower():
            return self._fix_sqlite_leak(source_code, tree, line_num, var_name)

        return False, None, "No automated fix strategy available for this rule."

    def _find_enclosing_node_and_stmt(
        self, tree: ast.AST, line_num: int
    ) -> Tuple[Optional[ast.AST], Optional[int], Optional[ast.stmt]]:
        """Locate the statement at line_num and its parent body list and index."""
        target_stmt = None
        parent_body = None
        stmt_idx = None

        for node in ast.walk(tree):
            for attr in ("body", "orelse", "finalbody"):
                body_list = getattr(node, attr, None)
                if isinstance(body_list, list):
                    for idx, stmt in enumerate(body_list):
                        if getattr(stmt, "lineno", None) == line_num:
                            target_stmt = stmt
                            parent_body = body_list
                            stmt_idx = idx
                            break
                        # Also check if line falls within statement range
                        if hasattr(stmt, "lineno") and hasattr(stmt, "end_lineno"):
                            if stmt.lineno <= line_num <= (stmt.end_lineno or stmt.lineno):
                                target_stmt = stmt
                                parent_body = body_list
                                stmt_idx = idx
                                break
                    if target_stmt:
                        break
            if target_stmt:
                break

        return parent_body, stmt_idx, target_stmt

    def _fix_file_leak(
        self, source_code: str, tree: ast.AST, line_num: int, var_name: str
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """Transform `var = open(...)` into `with open(...) as var:` preserving inner body."""
        lines = source_code.splitlines()
        if not (1 <= line_num <= len(lines)):
            return False, None, f"Line number {line_num} out of bounds."

        # Locate the assignment line
        target_line_idx = line_num - 1
        target_line_text = lines[target_line_idx]

        indent_match = re.match(r"^(\s*)", target_line_text)
        base_indent = indent_match.group(1) if indent_match else ""
        extra_indent = "    "

        # Search for pattern: var = open(...)
        # Match assignment
        assign_match = re.match(
            r"^(\s*)([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(open\s*\(.*\)|io\.open\s*\(.*\)|builtins\.open\s*\(.*\))\s*$",
            target_line_text,
        )

        if not assign_match:
            # Try multi-line or relaxed pattern
            assign_match = re.search(
                r"([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(open\(.*|io\.open\(.*|builtins\.open\(.*)",
                target_line_text,
            )
            if not assign_match:
                # If target_line doesn't match directly, look nearby (+/- 1 line)
                for offset in (-1, 1):
                    chk_idx = target_line_idx + offset
                    if 0 <= chk_idx < len(lines):
                        m = re.match(
                            r"^(\s*)([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(open\s*\(.*\)|io\.open\s*\(.*\)|builtins\.open\s*\(.*\))\s*$",
                            lines[chk_idx],
                        )
                        if m:
                            target_line_idx = chk_idx
                            target_line_text = lines[chk_idx]
                            base_indent = m.group(1)
                            assign_match = m
                            break

        if not assign_match:
            return False, None, f"Could not precisely match `open()` assignment on line {line_num}."

        detected_var = assign_match.group(2) if len(assign_match.groups()) >= 2 else var_name
        open_call = assign_match.group(3) if len(assign_match.groups()) >= 3 else assign_match.group(2)

        # Clean closing comments if any
        open_call = open_call.rstrip()

        # Find the scope/block that follows the assignment
        # Statements in the same block after target_line_idx up to the end of the function or block
        subsequent_lines: List[str] = []
        end_idx = len(lines)

        for idx in range(target_line_idx + 1, len(lines)):
            line = lines[idx]
            # If line is blank or comment, keep it
            if not line.strip() or line.strip().startswith("#"):
                subsequent_lines.append(line)
                continue

            current_indent = len(re.match(r"^(\s*)", line).group(1))
            if current_indent < len(base_indent):
                # We left the enclosing block (e.g. ended function or outer block)
                end_idx = idx
                break
            if current_indent == len(base_indent):
                # Check if this line is a closing call `var.close()` or `return` at same level
                # In Python, subsequent statements in same function body have same indent as the assignment!
                subsequent_lines.append(line)
            else:
                # Nested block inside current function
                subsequent_lines.append(line)

        # Filter out redundant `var.close()` calls inside the new with-block
        filtered_subsequent: List[str] = []
        close_regex = re.compile(rf"^\s*{re.escape(detected_var)}\.close\(\)\s*(#.*)?$")

        for s_line in subsequent_lines:
            if close_regex.match(s_line):
                # Skip explicit close because with-statement guarantees closing!
                continue
            filtered_subsequent.append(s_line)

        # Indent the statements that belong inside the with-block
        indented_body: List[str] = []
        for s_line in filtered_subsequent:
            if s_line.strip():
                indented_body.append(f"{base_indent}{extra_indent}{s_line[len(base_indent):] if s_line.startswith(base_indent) else s_line.lstrip()}")
            else:
                indented_body.append(s_line)

        # If body is empty (e.g. assignment was last line), add `pass`
        if not indented_body or all(not l.strip() for l in indented_body):
            indented_body = [f"{base_indent}{extra_indent}pass"]

        with_header = f"{base_indent}with {open_call} as {detected_var}:"

        new_lines = (
            lines[:target_line_idx]
            + [with_header]
            + indented_body
            + lines[target_line_idx + 1 + len(subsequent_lines):]
        )

        fixed_code = "\n".join(new_lines)
        if source_code.endswith("\n") and not fixed_code.endswith("\n"):
            fixed_code += "\n"

        # Validate syntax
        is_valid, err = validate_python_syntax(fixed_code)
        if not is_valid:
            return False, None, f"Generated fix failed syntax validation: {err}"

        return True, fixed_code, None

    def _fix_sqlite_leak(
        self, source_code: str, tree: ast.AST, line_num: int, var_name: str
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """Transform sqlite connection into try: ... finally: conn.close()."""
        lines = source_code.splitlines()
        if not (1 <= line_num <= len(lines)):
            return False, None, f"Line number {line_num} out of bounds."

        target_line_idx = line_num - 1
        target_line_text = lines[target_line_idx]

        indent_match = re.match(r"^(\s*)", target_line_text)
        base_indent = indent_match.group(1) if indent_match else ""
        extra_indent = "    "

        # Match sqlite assignment
        assign_match = re.search(
            r"([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(sqlite3\.connect\s*\(.*\)|connect\s*\(.*\))",
            target_line_text,
        )

        detected_var = assign_match.group(1) if assign_match else var_name

        # Subsequent lines in same function
        subsequent_lines: List[str] = []
        end_idx = len(lines)

        for idx in range(target_line_idx + 1, len(lines)):
            line = lines[idx]
            if not line.strip() or line.strip().startswith("#"):
                subsequent_lines.append(line)
                continue

            current_indent = len(re.match(r"^(\s*)", line).group(1))
            if current_indent < len(base_indent):
                end_idx = idx
                break
            subsequent_lines.append(line)

        # Filter out existing close calls
        filtered_subsequent: List[str] = []
        close_regex = re.compile(rf"^\s*{re.escape(detected_var)}\.close\(\)\s*(#.*)?$")
        for s_line in subsequent_lines:
            if close_regex.match(s_line):
                continue
            filtered_subsequent.append(s_line)

        indented_body: List[str] = []
        for s_line in filtered_subsequent:
            if s_line.strip():
                indented_body.append(f"{base_indent}{extra_indent}{s_line[len(base_indent):] if s_line.startswith(base_indent) else s_line.lstrip()}")
            else:
                indented_body.append(s_line)

        if not indented_body or all(not l.strip() for l in indented_body):
            indented_body = [f"{base_indent}{extra_indent}pass"]

        try_block = (
            [target_line_text]
            + [f"{base_indent}try:"]
            + indented_body
            + [f"{base_indent}finally:"]
            + [f"{base_indent}{extra_indent}{detected_var}.close()"]
        )

        new_lines = (
            lines[:target_line_idx]
            + try_block
            + lines[target_line_idx + 1 + len(subsequent_lines):]
        )

        fixed_code = "\n".join(new_lines)
        if source_code.endswith("\n") and not fixed_code.endswith("\n"):
            fixed_code += "\n"

        is_valid, err = validate_python_syntax(fixed_code)
        if not is_valid:
            return False, None, f"Generated fix failed syntax validation: {err}"

        return True, fixed_code, None
