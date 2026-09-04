"""Pure AST parser for Python source code and files."""

import ast
from pathlib import Path
from typing import Union, Optional

from models.report import ParseResult, SyntaxErrorInfo


class ASTParser:
    """Safely parses Python source code and files into AST representations

    without executing any target code.
    """

    def __init__(self) -> None:
        pass

    def parse_source(self, source: str, filename: str = "<string>") -> ParseResult:
        """Parse raw Python source string into an AST tree using ast.parse.

        Args:
            source: The Python code string to parse.
            filename: Name/path to attribute to this source for error reporting.

        Returns:
            ParseResult containing the AST tree on success, or SyntaxErrorInfo on failure.
        """
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
        """Read and parse a Python file into an AST tree safely.

        Target code is strictly parsed and NEVER executed.

        Args:
            file_path: Path to the .py file to parse.

        Returns:
            ParseResult with the parsed AST or error information.
        """
        path = Path(file_path)
        normalized_path = str(path.resolve() if path.exists() else path)

        if not path.exists():
            return ParseResult(
                file_path=normalized_path,
                success=False,
                read_error=f"File not found: {normalized_path}",
            )

        if not path.is_file():
            return ParseResult(
                file_path=normalized_path,
                success=False,
                read_error=f"Path is not a regular file: {normalized_path}",
            )

        try:
            # Read source using utf-8 with fallback replacement to avoid crashing on encodings
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
    """Convenience function to parse a file with the default ASTParser."""
    return ASTParser().parse_file(file_path)


def parse_python_source(source: str, filename: str = "<string>") -> ParseResult:
    """Convenience function to parse source text with the default ASTParser."""
    return ASTParser().parse_source(source, filename=filename)
