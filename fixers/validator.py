"""AST Syntax and Patch Validation Utilities."""

import ast
from typing import Optional, Tuple


def validate_python_syntax(code: str, filename: str = "<string>") -> Tuple[bool, Optional[str]]:
    """Validate that Python code string parses into a valid AST without syntax errors.

    Args:
        code: Source code string to validate.
        filename: Optional filename for error reporting.

    Returns:
        Tuple of (is_valid, error_message). If is_valid is True, error_message is None.
    """
    try:
        ast.parse(code, filename=filename)
        return True, None
    except SyntaxError as se:
        loc = f"Line {se.lineno}:{se.offset}" if se.lineno is not None else ""
        msg = f"Syntax error at {loc}: {se.msg}" if loc else f"Syntax error: {se.msg}"
        return False, msg
    except Exception as exc:
        return False, f"Validation error: {exc}"


def check_patch_syntax(modified_code: str, filename: str = "<string>") -> Tuple[bool, Optional[str]]:
    """Convenience alias for patch verification."""
    return validate_python_syntax(modified_code, filename=filename)
