"""Domain models for product-level project tracking and scan history."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, List, Dict, Any


class ProjectHealth(str, Enum):
    """Health status of a monitored project."""
    HEALTHY = "HEALTHY"
    AT_RISK = "AT_RISK"
    REVIEW = "REVIEW"
    NOT_SCANNED = "NOT_SCANNED"


class ScanStatus(str, Enum):
    """Execution status of an analysis scan."""
    PASS = "PASS"
    FAILED = "FAILED"
    ERROR = "ERROR"


@dataclass
class FindingRecord:
    """Persistent representation of an individual detected resource leak or issue."""
    finding_id: str
    scan_id: str
    file: str
    line: int
    column: Optional[int]
    resource: str
    variable: str
    severity: str
    reason: str
    leak_path: str
    recommendation: str
    cleanup_status: str = "UNCLOSED"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "scan_id": self.scan_id,
            "file": self.file,
            "line": self.line,
            "column": self.column,
            "resource": self.resource,
            "variable": self.variable,
            "severity": self.severity,
            "reason": self.reason,
            "leak_path": self.leak_path,
            "recommendation": self.recommendation,
            "cleanup_status": self.cleanup_status,
        }


@dataclass
class ScanRecord:
    """Persistent record of an executed analysis scan."""
    scan_id: str
    project_id: str
    timestamp: str
    target: str
    files_scanned: int
    clean_files: int
    syntax_errors: int
    leaks_detected: int
    status: str
    duration_ms: float
    scan_type: str = "LOCAL SCAN"
    findings: List[FindingRecord] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "project_id": self.project_id,
            "timestamp": self.timestamp,
            "target": self.target,
            "scan_type": self.scan_type,
            "files_scanned": self.files_scanned,
            "clean_files": self.clean_files,
            "syntax_errors": self.syntax_errors,
            "leaks_detected": self.leaks_detected,
            "status": self.status,
            "duration_ms": self.duration_ms,
            "findings_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class Project:
    """Monitored project/repository entity."""
    project_id: str
    name: str
    repository: str
    branch: str
    status: str = ProjectHealth.NOT_SCANNED.value
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    latest_scan: Optional[ScanRecord] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "project_id": self.project_id,
            "name": self.name,
            "repository": self.repository,
            "branch": self.branch,
            "status": self.status,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "latest_scan": self.latest_scan.to_dict() if self.latest_scan else None,
        }
