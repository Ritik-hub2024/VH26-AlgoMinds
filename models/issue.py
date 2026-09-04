"""Leak issue and severity representation."""

from dataclasses import dataclass
from enum import Enum
from typing import Dict, Any
from .location import SourceLocation


class Severity(str, Enum):
    """Issue severity levels."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class LeakIssue:
    """Represents an actionable issue detected during AST analysis."""

    rule_id: str
    message: str
    severity: Severity
    location: SourceLocation
    recommendation: str = ""
    resource_name: str = ""
    resource_type: str = "file"
    problem: str = ""
    leak_path: str = ""
    function_name: str = ""

    def __post_init__(self) -> None:
        if not self.problem:
            self.problem = self.message

    def to_dict(self) -> Dict[str, Any]:
        """Convert issue to serializable dictionary."""
        return {
            "rule_id": self.rule_id,
            "message": self.message,
            "severity": self.severity.value if isinstance(self.severity, Severity) else str(self.severity),
            "location": self.location.to_dict(),
            "file": self.location.file_path,
            "line": self.location.line,
            "resource": f"{self.resource_name} ({self.resource_type})" if self.resource_name else self.resource_type,
            "resource_name": self.resource_name,
            "resource_type": self.resource_type,
            "problem": self.problem,
            "leak_path": self.leak_path,
            "recommendation": self.recommendation,
            "function_name": self.function_name,
        }
