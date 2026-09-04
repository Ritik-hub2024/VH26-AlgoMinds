"""Source location representation for AST analysis."""

from dataclasses import dataclass
from typing import Optional, Dict, Any


@dataclass(frozen=True)
class SourceLocation:
    """Represents a location in a source file."""

    file_path: str
    line: int
    column: int
    end_line: Optional[int] = None
    end_column: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert location to serializable dictionary."""
        return {
            "file_path": self.file_path,
            "line": self.line,
            "column": self.column,
            "end_line": self.end_line,
            "end_column": self.end_column,
        }

    def __str__(self) -> str:
        if self.end_line is not None and self.end_column is not None:
            return f"{self.file_path}:{self.line}:{self.column}-{self.end_line}:{self.end_column}"
        return f"{self.file_path}:{self.line}:{self.column}"
