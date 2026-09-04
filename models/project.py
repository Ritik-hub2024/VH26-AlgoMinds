"""Domain models for product-level project tracking and scan history."""

import os
import re
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
class CIMetadata:
    """Structured continuous integration execution metadata."""
    source: str = "CI"
    repository: Optional[str] = None
    branch: Optional[str] = None
    commit_sha: Optional[str] = None
    pull_request: Optional[str] = None
    workflow_run: Optional[str] = None
    workflow_name: Optional[str] = None
    actor: Optional[str] = None

    @classmethod
    def from_env(cls, overrides: Optional[Dict[str, Any]] = None) -> "CIMetadata":
        """Extract CI metadata from standard environment variables (GitHub Actions, etc)."""
        overrides = overrides or {}

        # Repository
        repo = overrides.get("repository") or os.environ.get("GITHUB_REPOSITORY")

        # Branch
        branch = overrides.get("branch") or os.environ.get("GITHUB_REF_NAME") or os.environ.get("GITHUB_HEAD_REF")

        # Commit SHA
        sha = overrides.get("commit_sha") or os.environ.get("GITHUB_SHA")

        # Pull Request number
        pr = overrides.get("pull_request")
        if not pr:
            ref = os.environ.get("GITHUB_REF", "")
            m = re.match(r"^refs/pull/(\d+)/", ref)
            if m:
                pr = f"#{m.group(1)}"

        # Workflow run ID
        run_id = overrides.get("workflow_run") or os.environ.get("GITHUB_RUN_ID")
        workflow_name = overrides.get("workflow_name") or os.environ.get("GITHUB_WORKFLOW")
        actor = overrides.get("actor") or os.environ.get("GITHUB_ACTOR")

        return cls(
            source="CI",
            repository=repo or None,
            branch=branch or None,
            commit_sha=sha or None,
            pull_request=pr or None,
            workflow_run=str(run_id) if run_id else None,
            workflow_name=workflow_name or None,
            actor=actor or None,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "repository": self.repository,
            "branch": self.branch,
            "commit_sha": self.commit_sha,
            "pull_request": self.pull_request,
            "workflow_run": self.workflow_run,
            "workflow_name": self.workflow_name,
            "actor": self.actor,
        }


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
    is_baseline: bool = False
    classification: str = "LEAK"
    ownership_status: str = "LOCAL"
    callee_name: Optional[str] = None
    transfer_line: Optional[int] = None
    scope_limitation: Optional[str] = None

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
            "is_baseline": self.is_baseline,
            "classification": self.classification,
            "ownership_status": self.ownership_status,
            "callee_name": self.callee_name,
            "transfer_line": self.transfer_line,
            "scope_limitation": self.scope_limitation,
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
    commit_sha: Optional[str] = None
    branch: Optional[str] = None
    repository: Optional[str] = None
    pull_request: Optional[str] = None
    workflow_run: Optional[str] = None
    new_leaks: int = 0
    baseline_leaks: int = 0
    health_score: int = 100
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
            "commit_sha": self.commit_sha,
            "branch": self.branch,
            "repository": self.repository,
            "pull_request": self.pull_request,
            "workflow_run": self.workflow_run,
            "new_leaks": self.new_leaks,
            "baseline_leaks": self.baseline_leaks,
            "health_score": self.health_score,
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
    health_score: int = 100
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
            "health_score": self.health_score,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "latest_scan": self.latest_scan.to_dict() if self.latest_scan else None,
        }
