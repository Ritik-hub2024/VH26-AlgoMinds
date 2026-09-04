"""Leak issue and severity representation."""

from dataclasses import dataclass
from enum import Enum
from typing import Dict, Any, Optional
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
    variable: str = ""
    cleanup_status: str = "UNCLOSED"
    classification: str = "LEAK"  # LEAK, UNKNOWN, SAFE
    ownership_status: str = "LOCAL"  # LOCAL, TRANSFERRED, RETURNED, ATTRIBUTE, ALIAS, REASSIGNED
    callee_name: str = ""
    transfer_line: Optional[int] = None
    scope_limitation: str = ""

    def __post_init__(self) -> None:
        if not self.problem:
            self.problem = self.message
        if not self.variable and self.resource_name:
            self.variable = self.resource_name
        elif not self.resource_name and self.variable:
            self.resource_name = self.variable
        if self.classification == "UNKNOWN" and not self.scope_limitation:
            self.scope_limitation = "LeakGuard currently performs limited interprocedural reasoning."

    def to_dict(self) -> Dict[str, Any]:
        """Convert issue to serializable dictionary."""
        var_name = self.variable or self.resource_name
        return {
            "rule_id": self.rule_id,
            "message": self.message,
            "severity": self.severity.value if isinstance(self.severity, Severity) else str(self.severity),
            "location": self.location.to_dict(),
            "file": self.location.file_path,
            "line": self.location.line,
            "opened_line": self.location.line,
            "resource": f"{var_name} ({self.resource_type})" if var_name else self.resource_type,
            "resource_name": var_name,
            "variable": var_name,
            "resource_type": self.resource_type,
            "problem": self.problem,
            "reason": self.message or self.problem,
            "leak_path": self.leak_path,
            "path": self.leak_path,
            "cleanup_status": self.cleanup_status,
            "recommendation": self.recommendation,
            "function_name": self.function_name,
            "classification": self.classification,
            "ownership_status": self.ownership_status,
            "callee_name": self.callee_name,
            "transfer_line": self.transfer_line,
            "scope_limitation": self.scope_limitation,
        }

