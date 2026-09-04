"""Pure Python AST parser implementation."""

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Union, Dict, Any


@dataclass
class SyntaxErrorInfo:
    """Detailed information regarding a syntax error during parsing."""

    message: str
    filename: str
    line: Optional[int]
    column: Optional[int]
    text: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "message": self.message,
            "filename": self.filename,
            "line": self.line,
            "column": self.column,
            "text": self.text.strip() if self.text else None,
        }

    def __str__(self) -> str:
        loc = f"{self.filename}:{self.line}:{self.column}" if self.line else self.filename
        snippet = f" -> '{self.text.strip()}'" if self.text else ""
        return f"SyntaxError at {loc}: {self.message}{snippet}"


@dataclass
class ParseResult:
    """Result of an AST parsing operation on a single file or source."""

    file_path: str
    success: bool
    tree: Optional[ast.AST] = None
    syntax_error: Optional[SyntaxErrorInfo] = None
    read_error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_path": self.file_path,
            "success": self.success,
            "has_ast": self.tree is not None,
            "syntax_error": self.syntax_error.to_dict() if self.syntax_error else None,
            "read_error": self.read_error,
        }


class PythonParser:
    """Safely parses Python source code and files into AST representations

    without executing any target code.
    """

    def parse_source(self, source: str, filename: str = "<string>") -> ParseResult:
        """Parse raw Python source string into an AST tree using ast.parse."""
        try:
            tree = ast.parse(source, filename=filename)
            return ParseResult(
                file_path=filename,
                success=True,
                tree=tree,
                syntax_error=None,
                read_error=None,
            )
        except SyntaxError as e:
            syntax_err = SyntaxErrorInfo(
                message=e.msg if hasattr(e, "msg") and e.msg else str(e),
                filename=e.filename or filename,
                line=e.lineno,
                column=e.offset,
                text=e.text,
            )
            return ParseResult(
                file_path=filename,
                success=False,
                tree=None,
                syntax_error=syntax_err,
                read_error=None,
            )

    def parse_file(self, file_path: Union[str, Path]) -> ParseResult:
        """Read and parse a Python file into an AST tree safely."""
        path = Path(file_path)
        normalized_path = str(path.resolve() if path.exists() else path)

        if not path.exists():
            return ParseResult(
                file_path=normalized_path,
                success=False,
                read_error=f"File not found: {normalized_path}",
            )

        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                source = f.read()
        except OSError as err:
            return ParseResult(
                file_path=normalized_path,
                success=False,
                read_error=f"Failed to read file: {err}",
            )

        return self.parse_source(source, filename=normalized_path)


def parse_python_file(file_path: Union[str, Path]) -> ParseResult:
    return PythonParser().parse_file(file_path)


def parse_python_source(source: str, filename: str = "<string>") -> ParseResult:
    return PythonParser().parse_source(source, filename=filename)
