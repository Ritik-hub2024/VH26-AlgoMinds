"""Resource data model for LeakGuard static analysis."""

from dataclasses import dataclass
from typing import Optional, Dict, Any


@dataclass
class Resource:
    """Represents an allocated resource (e.g. file handle) tracked during AST analysis."""

    variable_name: str
    resource_type: str
    opening_line: int
    function_name: Optional[str] = None
    status: str = "LEAK"
    closing_line: Optional[int] = None
    explanation: str = ""
    file_path: str = ""
    leak_path: Optional[str] = None
    is_context_manager: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert resource to dictionary."""
        return {
            "variable_name": self.variable_name,
            "variable": self.variable_name,
            "resource": f"{self.variable_name} ({self.resource_type})",
            "resource_type": self.resource_type,
            "opening_line": self.opening_line,
            "opened_line": self.opening_line,
            "function_name": self.function_name,
            "status": self.status,
            "cleanup_status": self.status,
            "closing_line": self.closing_line,
            "explanation": self.explanation,
            "reason": self.explanation,
            "file_path": self.file_path,
            "leak_path": self.leak_path,
            "path": self.leak_path,
            "is_context_manager": self.is_context_manager,
        }

    def __str__(self) -> str:
        fn = f" in {self.function_name}()" if self.function_name else ""
        close_info = f", closed at line {self.closing_line}" if self.closing_line else ""
        cm_info = " [context manager]" if self.is_context_manager else ""
        return (
            f"Resource({self.variable_name}: {self.resource_type} "
            f"opened at L{self.opening_line}{fn}{cm_info} -> {self.status}{close_info})"
        )
