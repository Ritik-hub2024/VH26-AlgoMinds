"""Lightweight SQLite persistence layer for LeakGuard Admin & Scan History.

Completely decoupled from the core AST analyzer.
Stores project metadata, scan executions, and detected leak findings.
"""

import contextlib
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List, Dict, Any, Union, Sequence

from models.project import Project, ProjectHealth, ScanRecord, FindingRecord, ScanStatus
from models.report import AnalysisReport


_CANONICAL_DB_PATH = Path(__file__).resolve().parent.parent / "leakguard.db"
_DEFAULT_DB_PATH = Path(os.environ.get("LEAKGUARD_DB_PATH") or os.environ.get("LEAKGUARD_DB") or _CANONICAL_DB_PATH)


def calculate_health_score(
    issues: Sequence[Any],
    syntax_errors: Sequence[Any],
    status: str,
    new_leaks: Optional[int] = None,
    baseline_leaks: Optional[int] = None,
) -> tuple[int, str]:
    """Calculate deterministic project security health score (0-100) and health status tier.

    Formula:
    - Base score: 100
    - Deductions:
      - Critical severity leak: -20
      - High severity leak: -10
      - Medium severity leak: -3
      - Low severity leak: -1
      - Syntax error: -25
      - Failed scan overall penalty: -5
    - Score clamped to [0, 100]
    - Status tiers:
      - score >= 85: HEALTHY
      - 60 <= score < 85: REVIEW
      - score < 60: AT_RISK
    """
    score = 100
    for issue in issues:
        sev = getattr(issue, "severity", None)
        if hasattr(sev, "value"):
            sev_str = str(sev.value).upper()
        elif isinstance(issue, dict):
            sev_str = str(issue.get("severity", "HIGH")).upper()
        else:
            sev_str = str(sev).upper() if sev else "HIGH"

        if "CRITICAL" in sev_str:
            score -= 20
        elif "HIGH" in sev_str:
            score -= 10
        elif "MEDIUM" in sev_str:
            score -= 3
        elif "LOW" in sev_str:
            score -= 1
        else:
            score -= 5

    # Syntax error penalty
    score -= len(syntax_errors) * 25

    # Failed scan penalty
    if status == ScanStatus.FAILED.value or (isinstance(status, str) and status.upper() == "FAILED"):
        score -= 5

    score = max(0, min(100, score))

    has_syntax = len(syntax_errors) > 0
    total_leaks = len(issues)

    if total_leaks == 0 and not has_syntax and score >= 85 and status != ScanStatus.FAILED.value and status != "FAILED":
        tier = ProjectHealth.HEALTHY.value
    elif has_syntax or score < 60 or total_leaks >= 3:
        tier = ProjectHealth.AT_RISK.value
    else:
        tier = ProjectHealth.REVIEW.value

    return score, tier


class Database:
    """Thread-safe SQLite database adapter for LeakGuard project history."""

    def __init__(self, db_path: Optional[Union[str, Path]] = None) -> None:
        if db_path:
            self.db_path = str(db_path)
        else:
            env_db = os.environ.get("LEAKGUARD_DB_PATH") or os.environ.get("LEAKGUARD_DB")
            self.db_path = str(env_db) if env_db else str(_DEFAULT_DB_PATH)
        self._lock = threading.Lock()
        self._init_db()

    @contextlib.contextmanager
    def _connection(self):
        with self._lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            try:
                yield conn
                conn.commit()
            finally:
                conn.close()

    def _init_db(self) -> None:
        with self._connection() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS projects (
                    project_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    repository TEXT NOT NULL,
                    branch TEXT NOT NULL,
                    status TEXT NOT NULL,
                    health_score INTEGER NOT NULL DEFAULT 100,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    target TEXT NOT NULL,
                    files_scanned INTEGER NOT NULL,
                    clean_files INTEGER NOT NULL,
                    syntax_errors INTEGER NOT NULL,
                    leaks_detected INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    duration_ms REAL NOT NULL,
                    scan_type TEXT NOT NULL DEFAULT 'LOCAL SCAN',
                    commit_sha TEXT,
                    branch TEXT,
                    repository TEXT,
                    pull_request TEXT,
                    workflow_run TEXT,
                    new_leaks INTEGER NOT NULL DEFAULT 0,
                    baseline_leaks INTEGER NOT NULL DEFAULT 0,
                    health_score INTEGER NOT NULL DEFAULT 100,
                    FOREIGN KEY (project_id) REFERENCES projects (project_id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS findings (
                    finding_id TEXT PRIMARY KEY,
                    scan_id TEXT NOT NULL,
                    file TEXT NOT NULL,
                    line INTEGER NOT NULL,
                    column INTEGER,
                    resource TEXT NOT NULL,
                    variable TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    leak_path TEXT NOT NULL,
                    recommendation TEXT NOT NULL,
                    cleanup_status TEXT NOT NULL,
                    is_baseline INTEGER NOT NULL DEFAULT 0,
                    classification TEXT NOT NULL DEFAULT 'LEAK',
                    ownership_status TEXT NOT NULL DEFAULT 'LOCAL',
                    callee_name TEXT,
                    transfer_line INTEGER,
                    scope_limitation TEXT,
                    FOREIGN KEY (scan_id) REFERENCES scans (scan_id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_scans_project_id ON scans (project_id);
                CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans (timestamp);
                CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings (scan_id);
                CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings (severity);
                """
            )
            # Automatic schema migration for existing databases
            cur = conn.cursor()
            cur.execute("PRAGMA table_info(scans)")
            scan_columns = [row["name"] for row in cur.fetchall()]
            if "scan_type" not in scan_columns:
                cur.execute("ALTER TABLE scans ADD COLUMN scan_type TEXT NOT NULL DEFAULT 'LOCAL SCAN'")
            if "commit_sha" not in scan_columns:
                cur.execute("ALTER TABLE scans ADD COLUMN commit_sha TEXT")
            if "branch" not in scan_columns:
                cur.execute("ALTER TABLE scans ADD COLUMN branch TEXT")
            if "repository" not in scan_columns:
                cur.execute("ALTER TABLE scans ADD COLUMN repository TEXT")
            if "pull_request" not in scan_columns:
                cur.execute("ALTER TABLE scans ADD COLUMN pull_request TEXT")
            if "workflow_run" not in scan_columns:
                cur.execute("ALTER TABLE scans ADD COLUMN workflow_run TEXT")
            if "new_leaks" not in scan_columns:
                cur.execute("ALTER TABLE scans ADD COLUMN new_leaks INTEGER NOT NULL DEFAULT 0")
            if "baseline_leaks" not in scan_columns:
                cur.execute("ALTER TABLE scans ADD COLUMN baseline_leaks INTEGER NOT NULL DEFAULT 0")
            if "health_score" not in scan_columns:
                cur.execute("ALTER TABLE scans ADD COLUMN health_score INTEGER NOT NULL DEFAULT 100")

            cur.execute("PRAGMA table_info(findings)")
            findings_columns = [row["name"] for row in cur.fetchall()]
            if "is_baseline" not in findings_columns:
                cur.execute("ALTER TABLE findings ADD COLUMN is_baseline INTEGER NOT NULL DEFAULT 0")
            if "classification" not in findings_columns:
                cur.execute("ALTER TABLE findings ADD COLUMN classification TEXT NOT NULL DEFAULT 'LEAK'")
            if "ownership_status" not in findings_columns:
                cur.execute("ALTER TABLE findings ADD COLUMN ownership_status TEXT NOT NULL DEFAULT 'LOCAL'")
            if "callee_name" not in findings_columns:
                cur.execute("ALTER TABLE findings ADD COLUMN callee_name TEXT")
            if "transfer_line" not in findings_columns:
                cur.execute("ALTER TABLE findings ADD COLUMN transfer_line INTEGER")
            if "scope_limitation" not in findings_columns:
                cur.execute("ALTER TABLE findings ADD COLUMN scope_limitation TEXT")

            cur.execute("PRAGMA table_info(projects)")
            project_columns = [row["name"] for row in cur.fetchall()]
            if "health_score" not in project_columns:
                cur.execute("ALTER TABLE projects ADD COLUMN health_score INTEGER NOT NULL DEFAULT 100")

    # -------------------------------------------------------------------------
    # Project Operations
    # -------------------------------------------------------------------------

    def ensure_project(
        self,
        project_id: str,
        name: str,
        repository: str = "Ritik-hub2024/VH26-AlgoMinds",
        branch: str = "main",
        status: str = ProjectHealth.NOT_SCANNED.value,
        health_score: int = 100,
    ) -> Project:
        """Create project if it does not already exist, or return existing."""
        now = datetime.now(timezone.utc).isoformat()
        with self._connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM projects WHERE project_id = ?", (project_id,))
            row = cur.fetchone()
            if row:
                row_dict = dict(row)
                return Project(
                    project_id=row_dict["project_id"],
                    name=row_dict["name"],
                    repository=row_dict["repository"],
                    branch=row_dict["branch"],
                    status=row_dict["status"],
                    health_score=row_dict.get("health_score", 100),
                    created_at=row_dict["created_at"],
                    updated_at=row_dict["updated_at"],
                )

            cur.execute(
                """
                INSERT INTO projects (project_id, name, repository, branch, status, health_score, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (project_id, name, repository, branch, status, health_score, now, now),
            )
            return Project(
                project_id=project_id,
                name=name,
                repository=repository,
                branch=branch,
                status=status,
                health_score=health_score,
                created_at=now,
                updated_at=now,
            )

    def resolve_project_for_target(self, target_str: str) -> tuple[str, str]:
        """Infer project_id and project name from scan target path."""
        norm = target_str.replace("\\", "/").strip("/")
        if "python/leaks" in norm:
            return "python-leaks", "Python Leaks Suite"
        elif "python/safe" in norm:
            return "python-safe", "Python Safe Suite"
        elif "python/syntax" in norm:
            return "python-syntax", "Python Syntax Suite"
        elif norm.startswith("python") or "/python" in norm:
            return "python-corpus", "Python Canonical Corpus"
        elif norm.startswith("examples"):
            return "examples-suite", "Examples Suite"
        return "leakguard-core", "LeakGuard Core"

    # -------------------------------------------------------------------------
    # Scan & Finding Recording
    # -------------------------------------------------------------------------

    def record_scan(
        self,
        report: AnalysisReport,
        project_id: Optional[str] = None,
        project_name: Optional[str] = None,
        target_override: Optional[str] = None,
        branch: str = "main",
        repository: str = "Ritik-hub2024/VH26-AlgoMinds",
        prepared_findings: Optional[List[Dict[str, Any]]] = None,
        scan_type: str = "LOCAL SCAN",
        commit_sha: Optional[str] = None,
        pull_request: Optional[str] = None,
        workflow_run: Optional[str] = None,
        new_leaks: Optional[int] = None,
        baseline_leaks: Optional[int] = None,
    ) -> ScanRecord:
        """Persist an AnalysisReport and its findings into SQLite."""
        target = target_override or getattr(report, "target_path", "unknown")
        if not project_id:
            project_id, auto_name = self.resolve_project_for_target(target)
            proj_name = project_name or auto_name
        else:
            proj_name = project_name or project_id.replace("-", " ").title()

        self.ensure_project(project_id, name=proj_name, repository=repository, branch=branch)

        now = datetime.now(timezone.utc).isoformat()
        scan_id = f"scan_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"

        has_leaks = len(report.issues) > 0
        has_syntax_errors = len(report.syntax_errors) > 0
        status = ScanStatus.FAILED.value if (has_leaks or has_syntax_errors) else ScanStatus.PASS.value
        duration_ms = round(report.duration_seconds * 1000, 2)

        # Build FindingRecords
        findings_to_insert: List[FindingRecord] = []
        if prepared_findings:
            for item in prepared_findings:
                fnd = FindingRecord(
                    finding_id=f"fnd_{uuid.uuid4().hex[:8]}",
                    scan_id=scan_id,
                    file=str(item.get("file", "")),
                    line=int(item.get("line", 1)),
                    column=item.get("column"),
                    resource=str(item.get("resource", "file")),
                    variable=str(item.get("variable", "f")),
                    severity=str(item.get("severity", "HIGH")),
                    reason=str(item.get("reason", "")),
                    leak_path=str(item.get("leak_path", "")),
                    recommendation=str(item.get("recommendation", "")),
                    cleanup_status=str(item.get("cleanup_status", "UNCLOSED")),
                    is_baseline=bool(item.get("is_baseline", False)),
                    classification=str(item.get("classification", "LEAK")),
                    ownership_status=str(item.get("ownership_status", "LOCAL")),
                    callee_name=item.get("callee_name"),
                    transfer_line=item.get("transfer_line"),
                    scope_limitation=item.get("scope_limitation"),
                )
                findings_to_insert.append(fnd)
        else:
            for issue in report.issues:
                fnd = FindingRecord(
                    finding_id=f"fnd_{uuid.uuid4().hex[:8]}",
                    scan_id=scan_id,
                    file=issue.location.file_path,
                    line=issue.location.line,
                    column=issue.location.column,
                    resource=f"{issue.resource_name} ({issue.resource_type})" if issue.resource_name else issue.resource_type,
                    variable=issue.resource_name or "f",
                    severity=issue.severity.value if hasattr(issue.severity, "value") else str(issue.severity),
                    reason=issue.message or issue.problem,
                    leak_path=issue.leak_path or "",
                    recommendation=issue.recommendation or "",
                    cleanup_status="UNCLOSED",
                    is_baseline=bool(getattr(issue, "is_baseline", False)),
                    classification=getattr(issue, "classification", "LEAK"),
                    ownership_status=getattr(issue, "ownership_status", "LOCAL"),
                    callee_name=getattr(issue, "callee_name", None),
                    transfer_line=getattr(issue, "transfer_line", None),
                    scope_limitation=getattr(issue, "scope_limitation", None),
                )
                findings_to_insert.append(fnd)

        # Calculate differential counts if not explicitly supplied
        if baseline_leaks is None:
            baseline_leaks = sum(1 for f in findings_to_insert if f.is_baseline)
        if new_leaks is None:
            new_leaks = len(findings_to_insert) - baseline_leaks

        # Calculate deterministic health score and tier
        health_score, new_project_health = calculate_health_score(
            report.issues,
            report.syntax_errors,
            status,
            new_leaks=new_leaks,
            baseline_leaks=baseline_leaks,
        )

        with self._connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO scans (
                    scan_id, project_id, timestamp, target, files_scanned,
                    clean_files, syntax_errors, leaks_detected, status, duration_ms, scan_type,
                    commit_sha, branch, repository, pull_request, workflow_run,
                    new_leaks, baseline_leaks, health_score
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    project_id,
                    now,
                    target,
                    report.files_scanned,
                    report.clean_files_count,
                    len(report.syntax_errors),
                    len(report.issues),
                    status,
                    duration_ms,
                    scan_type,
                    commit_sha,
                    branch,
                    repository,
                    pull_request,
                    workflow_run,
                    new_leaks,
                    baseline_leaks,
                    health_score,
                ),
            )

            for f in findings_to_insert:
                cur.execute(
                    """
                    INSERT INTO findings (
                        finding_id, scan_id, file, line, column, resource,
                        variable, severity, reason, leak_path, recommendation, cleanup_status,
                        is_baseline, classification, ownership_status, callee_name, transfer_line, scope_limitation
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        f.finding_id,
                        f.scan_id,
                        f.file,
                        f.line,
                        f.column,
                        f.resource,
                        f.variable,
                        f.severity,
                        f.reason,
                        f.leak_path,
                        f.recommendation,
                        f.cleanup_status,
                        1 if f.is_baseline else 0,
                        f.classification,
                        f.ownership_status,
                        f.callee_name,
                        f.transfer_line,
                        f.scope_limitation,
                    ),
                )

            cur.execute(
                """
                UPDATE projects
                SET status = ?, health_score = ?, updated_at = ?
                WHERE project_id = ?
                """,
                (new_project_health, health_score, now, project_id),
            )

        return ScanRecord(
            scan_id=scan_id,
            project_id=project_id,
            timestamp=now,
            target=target,
            files_scanned=report.files_scanned,
            clean_files=report.clean_files_count,
            syntax_errors=len(report.syntax_errors),
            leaks_detected=len(report.issues),
            status=status,
            duration_ms=duration_ms,
            scan_type=scan_type,
            commit_sha=commit_sha,
            branch=branch,
            repository=repository,
            pull_request=pull_request,
            workflow_run=workflow_run,
            new_leaks=new_leaks,
            baseline_leaks=baseline_leaks,
            health_score=health_score,
            findings=findings_to_insert,
        )

    def ingest_ci_result(self, data: Dict[str, Any]) -> ScanRecord:
        """Ingest a portable leakguard-ci-result.json payload into SQLite.

        Attributed strictly to CI scan type and records all associated commit/branch/PR
        metadata and differential leak categorization.
        """
        ci_meta = data.get("ci_metadata") or {}
        repo = ci_meta.get("repository") or data.get("repository") or "Ritik-hub2024/VH26-AlgoMinds"
        branch = ci_meta.get("branch") or data.get("branch") or "main"
        commit_sha = ci_meta.get("commit_sha") or data.get("commit_sha")
        pull_request = ci_meta.get("pull_request") or data.get("pull_request")
        workflow_run = ci_meta.get("workflow_run") or data.get("workflow_run")

        target = data.get("target") or "unknown"
        project_id = data.get("project_id")
        if not project_id:
            project_id, auto_name = self.resolve_project_for_target(target)
            proj_name = data.get("project_name") or auto_name
        else:
            proj_name = data.get("project_name") or project_id.replace("-", " ").title()

        summary = data.get("summary") or {}
        files_scanned = summary.get("files_scanned", data.get("files_scanned", 0))
        clean_files = summary.get("clean_files", data.get("clean_files", 0))
        syntax_errors_count = summary.get("syntax_errors", len(data.get("syntax_errors", [])))
        raw_findings = data.get("findings", [])
        total_leaks = summary.get("total_leaks", len(raw_findings))
        new_leaks = summary.get("new_leaks", total_leaks)
        baseline_leaks = summary.get("baseline_leaks", 0)
        duration_ms = float(summary.get("duration_ms", data.get("duration_ms", 0.0)))
        status = data.get("status") or (ScanStatus.FAILED.value if (total_leaks > 0 or syntax_errors_count > 0) else ScanStatus.PASS.value)

        # Health score calculation / validation
        given_score = data.get("health_score")
        if given_score is not None:
            health_score = int(given_score)
            if health_score >= 85:
                tier = ProjectHealth.HEALTHY.value
            elif health_score >= 60:
                tier = ProjectHealth.REVIEW.value
            else:
                tier = ProjectHealth.AT_RISK.value
        else:
            health_score, tier = calculate_health_score(
                raw_findings,
                data.get("syntax_errors", []),
                status,
                new_leaks=new_leaks,
                baseline_leaks=baseline_leaks,
            )

        self.ensure_project(
            project_id,
            name=proj_name,
            repository=repo,
            branch=branch,
            status=tier,
            health_score=health_score,
        )

        now = data.get("timestamp") or datetime.now(timezone.utc).isoformat()
        scan_id = data.get("scan_id") or f"scan_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"

        findings_to_insert: List[FindingRecord] = []
        for item in raw_findings:
            fnd = FindingRecord(
                finding_id=item.get("finding_id") or f"fnd_{uuid.uuid4().hex[:8]}",
                scan_id=scan_id,
                file=str(item.get("file", "")),
                line=int(item.get("line", 1)),
                column=item.get("column"),
                resource=str(item.get("resource", "file")),
                variable=str(item.get("variable", "f")),
                severity=str(item.get("severity", "HIGH")),
                reason=str(item.get("reason", "")),
                leak_path=str(item.get("leak_path", "")),
                recommendation=str(item.get("recommendation", "")),
                cleanup_status=str(item.get("cleanup_status", "UNCLOSED")),
                is_baseline=bool(item.get("is_baseline", False)),
                classification=str(item.get("classification", "LEAK")),
                ownership_status=str(item.get("ownership_status", "LOCAL")),
                callee_name=item.get("callee_name"),
                transfer_line=item.get("transfer_line"),
                scope_limitation=item.get("scope_limitation"),
            )
            findings_to_insert.append(fnd)

        with self._connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO scans (
                    scan_id, project_id, timestamp, target, files_scanned,
                    clean_files, syntax_errors, leaks_detected, status, duration_ms, scan_type,
                    commit_sha, branch, repository, pull_request, workflow_run,
                    new_leaks, baseline_leaks, health_score
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    project_id,
                    now,
                    target,
                    files_scanned,
                    clean_files,
                    syntax_errors_count,
                    total_leaks,
                    status,
                    duration_ms,
                    "CI",
                    commit_sha,
                    branch,
                    repo,
                    pull_request,
                    workflow_run,
                    new_leaks,
                    baseline_leaks,
                    health_score,
                ),
            )

            for f in findings_to_insert:
                cur.execute(
                    """
                    INSERT INTO findings (
                        finding_id, scan_id, file, line, column, resource,
                        variable, severity, reason, leak_path, recommendation, cleanup_status,
                        is_baseline, classification, ownership_status, callee_name, transfer_line, scope_limitation
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        f.finding_id,
                        f.scan_id,
                        f.file,
                        f.line,
                        f.column,
                        f.resource,
                        f.variable,
                        f.severity,
                        f.reason,
                        f.leak_path,
                        f.recommendation,
                        f.cleanup_status,
                        1 if f.is_baseline else 0,
                        f.classification,
                        f.ownership_status,
                        f.callee_name,
                        f.transfer_line,
                        f.scope_limitation,
                    ),
                )

            cur.execute(
                """
                UPDATE projects
                SET status = ?, health_score = ?, updated_at = ?
                WHERE project_id = ?
                """,
                (tier, health_score, now, project_id),
            )

        return ScanRecord(
            scan_id=scan_id,
            project_id=project_id,
            timestamp=now,
            target=target,
            files_scanned=files_scanned,
            clean_files=clean_files,
            syntax_errors=syntax_errors_count,
            leaks_detected=total_leaks,
            status=status,
            duration_ms=duration_ms,
            scan_type="CI",
            commit_sha=commit_sha,
            branch=branch,
            repository=repo,
            pull_request=pull_request,
            workflow_run=workflow_run,
            new_leaks=new_leaks,
            baseline_leaks=baseline_leaks,
            health_score=health_score,
            findings=findings_to_insert,
        )

    # -------------------------------------------------------------------------
    # Admin Queries
    # -------------------------------------------------------------------------

    def get_projects(self) -> List[Dict[str, Any]]:
        """List all projects with latest scan details and health metrics."""
        with self._connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT p.*,
                       s.scan_id AS latest_scan_id,
                       s.timestamp AS latest_scan_time,
                       s.target AS latest_scan_target,
                       s.files_scanned AS latest_files_scanned,
                       s.clean_files AS latest_clean_files,
                       s.syntax_errors AS latest_syntax_errors,
                       s.leaks_detected AS latest_leaks,
                       s.status AS latest_status,
                       s.duration_ms AS latest_duration_ms,
                       s.scan_type AS latest_scan_type,
                       s.commit_sha AS latest_commit_sha,
                       s.branch AS latest_scan_branch,
                       s.repository AS latest_scan_repository,
                       s.pull_request AS latest_pull_request,
                       s.workflow_run AS latest_workflow_run,
                       s.new_leaks AS latest_new_leaks,
                       s.baseline_leaks AS latest_baseline_leaks,
                       s.health_score AS latest_scan_health_score,
                       (SELECT COUNT(*) FROM scans WHERE project_id = p.project_id) AS total_scans
                FROM projects p
                LEFT JOIN scans s ON s.scan_id = (
                    SELECT scan_id FROM scans
                    WHERE project_id = p.project_id
                    ORDER BY timestamp DESC, rowid DESC
                    LIMIT 1
                )
                ORDER BY p.updated_at DESC
                """
            )
            rows = cur.fetchall()
            result = []
            for r in rows:
                row_dict = dict(r)
                result.append({
                    "project_id": row_dict["project_id"],
                    "name": row_dict["name"],
                    "repository": row_dict["repository"],
                    "branch": row_dict["branch"],
                    "status": row_dict["status"],
                    "health_score": row_dict.get("health_score", 100),
                    "created_at": row_dict["created_at"],
                    "updated_at": row_dict["updated_at"],
                    "total_scans": row_dict["total_scans"],
                    "latest_scan": {
                        "scan_id": row_dict["latest_scan_id"],
                        "timestamp": row_dict["latest_scan_time"],
                        "target": row_dict["latest_scan_target"],
                        "files_scanned": row_dict["latest_files_scanned"],
                        "clean_files": row_dict["latest_clean_files"],
                        "syntax_errors": row_dict["latest_syntax_errors"],
                        "leaks_detected": row_dict["latest_leaks"] if row_dict["latest_leaks"] is not None else 0,
                        "status": row_dict["latest_status"] or "NOT_SCANNED",
                        "duration_ms": row_dict["latest_duration_ms"] or 0,
                        "scan_type": row_dict.get("latest_scan_type") or "LOCAL SCAN",
                        "commit_sha": row_dict.get("latest_commit_sha"),
                        "branch": row_dict.get("latest_scan_branch"),
                        "repository": row_dict.get("latest_scan_repository"),
                        "pull_request": row_dict.get("latest_pull_request"),
                        "workflow_run": row_dict.get("latest_workflow_run"),
                        "new_leaks": row_dict.get("latest_new_leaks") or 0,
                        "baseline_leaks": row_dict.get("latest_baseline_leaks") or 0,
                        "health_score": row_dict.get("latest_scan_health_score") if row_dict.get("latest_scan_health_score") is not None else 100,
                    } if row_dict["latest_scan_id"] else None,
                })
            return result

    def get_project(self, project_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single project by ID with full scan history and open findings."""
        with self._connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM projects WHERE project_id = ?", (project_id,))
            p = cur.fetchone()
            if not p:
                return None
            p_dict = dict(p)

            # Get latest scan
            cur.execute(
                """
                SELECT * FROM scans
                WHERE project_id = ?
                ORDER BY timestamp DESC, rowid DESC
                LIMIT 1
                """,
                (project_id,),
            )
            latest_scan_row = cur.fetchone()

            open_findings = []
            if latest_scan_row:
                cur.execute(
                    """
                    SELECT * FROM findings
                    WHERE scan_id = ?
                    ORDER BY rowid ASC
                    """,
                    (latest_scan_row["scan_id"],),
                )
                open_findings = [dict(f) for f in cur.fetchall()]

            # Get scan history
            cur.execute(
                """
                SELECT scan_id, timestamp, target, files_scanned, clean_files,
                       syntax_errors, leaks_detected, status, duration_ms, scan_type,
                       commit_sha, branch, repository, pull_request, workflow_run,
                       new_leaks, baseline_leaks, health_score
                FROM scans
                WHERE project_id = ?
                ORDER BY timestamp DESC, rowid DESC
                LIMIT 30
                """,
                (project_id,),
            )
            history = [dict(h) for h in cur.fetchall()]

            return {
                "project_id": p_dict["project_id"],
                "name": p_dict["name"],
                "repository": p_dict["repository"],
                "branch": p_dict["branch"],
                "status": p_dict["status"],
                "health_score": p_dict.get("health_score", 100),
                "created_at": p_dict["created_at"],
                "updated_at": p_dict["updated_at"],
                "latest_scan": dict(latest_scan_row) if latest_scan_row else None,
                "open_findings": open_findings,
                "scan_history": history,
            }

    def get_recent_scans(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve recent scans stream across all projects."""
        with self._connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT s.*, p.name AS project_name, p.repository, p.branch
                FROM scans s
                JOIN projects p ON s.project_id = p.project_id
                ORDER BY s.timestamp DESC, s.rowid DESC
                LIMIT ?
                """,
                (limit,),
            )
            return [dict(r) for r in cur.fetchall()]

    def get_summary(self) -> Dict[str, Any]:
        """Aggregate high-level security posture KPIs for Admin cards."""
        with self._connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) AS count FROM projects")
            projects_count = cur.fetchone()["count"]

            cur.execute("SELECT COUNT(*) AS count FROM scans")
            total_scans = cur.fetchone()["count"]

            # Open leaks in the latest scan of each project
            cur.execute(
                """
                SELECT SUM(s.leaks_detected) AS total_open_leaks
                FROM scans s
                WHERE s.scan_id IN (
                    SELECT scan_id FROM scans s2
                    WHERE s2.project_id = s.project_id
                    ORDER BY s2.timestamp DESC, s2.rowid DESC
                    LIMIT 1
                )
                """
            )
            open_leaks = cur.fetchone()["total_open_leaks"] or 0

            # High severity findings in the latest scan of each project
            cur.execute(
                """
                SELECT COUNT(*) AS high_count
                FROM findings f
                WHERE f.severity = 'HIGH' AND f.scan_id IN (
                    SELECT scan_id FROM scans s2
                    WHERE s2.project_id = (SELECT project_id FROM scans WHERE scan_id = f.scan_id)
                    ORDER BY s2.timestamp DESC, s2.rowid DESC
                    LIMIT 1
                )
                """
            )
            high_severity = cur.fetchone()["high_count"] or 0

            # CI Blocked: count of projects whose latest scan is FAILED
            cur.execute(
                """
                SELECT COUNT(*) AS failed_count
                FROM scans s
                WHERE s.status = 'FAILED' AND s.scan_id IN (
                    SELECT scan_id FROM scans s2
                    WHERE s2.project_id = s.project_id
                    ORDER BY s2.timestamp DESC, s2.rowid DESC
                    LIMIT 1
                )
                """
            )
            ci_blocked = cur.fetchone()["failed_count"] or 0

            return {
                "projects_count": projects_count,
                "total_scans": total_scans,
                "open_leaks": open_leaks,
                "high_severity": high_severity,
                "ci_blocked": ci_blocked,
            }

    def get_analytics(
        self, project_id: Optional[str] = None, days: Optional[int] = None
    ) -> Dict[str, Any]:
        """Prepare analytics for leak trends, resource breakdown, and CI statistics with time & project filtering."""
        from datetime import timedelta

        with self._connection() as conn:
            cur = conn.cursor()

            # Build where clause for scans
            scan_conditions: List[str] = []
            scan_params: List[Any] = []

            if project_id and project_id not in ("all", "ALL", ""):
                scan_conditions.append("s.project_id = ?")
                scan_params.append(project_id)

            if days and days > 0:
                cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
                scan_conditions.append("s.timestamp >= ?")
                scan_params.append(cutoff)

            scan_where = f"WHERE {' AND '.join(scan_conditions)}" if scan_conditions else ""

            # 1. Leaks over time / Trend (Confirmed LEAK findings only per scan)
            cur.execute(
                f"""
                SELECT 
                    s.scan_id, 
                    s.timestamp, 
                    s.target, 
                    s.status,
                    COUNT(CASE WHEN f.classification = 'LEAK' AND f.is_baseline = 0 THEN 1 END) AS confirmed_leaks,
                    COUNT(CASE WHEN f.ownership_status = 'UNKNOWN' THEN 1 END) AS unknown_leaks
                FROM scans s
                LEFT JOIN findings f ON s.scan_id = f.scan_id
                {scan_where}
                GROUP BY s.scan_id, s.timestamp, s.target, s.status
                ORDER BY s.timestamp ASC, s.rowid ASC
                LIMIT 50
                """,
                scan_params,
            )
            raw_scans = cur.fetchall()

            trend = [
                {
                    "scan_id": r["scan_id"],
                    "timestamp": r["timestamp"],
                    "target": r["target"],
                    "leak_count": r["confirmed_leaks"] or 0,
                    "leaks": r["confirmed_leaks"] or 0,
                    "unknown_leaks": r["unknown_leaks"] or 0,
                    "status": r["status"],
                }
                for r in raw_scans
            ]

            # 2. Resource Types Distribution (from confirmed non-baseline leaks)
            finding_conditions: List[str] = ["f.classification = 'LEAK'", "f.is_baseline = 0"]
            finding_params: List[Any] = []

            if project_id and project_id not in ("all", "ALL", ""):
                finding_conditions.append("s.project_id = ?")
                finding_params.append(project_id)

            if days and days > 0:
                cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
                finding_conditions.append("s.timestamp >= ?")
                finding_params.append(cutoff)

            finding_where = f"WHERE {' AND '.join(finding_conditions)}"

            cur.execute(
                f"""
                SELECT 
                    CASE 
                        WHEN LOWER(f.resource) LIKE '%sqlite%' THEN 'SQLite Connection'
                        WHEN LOWER(f.resource) LIKE '%file%' OR f.resource = 'file' THEN 'File'
                        WHEN LOWER(f.resource) LIKE '%socket%' THEN 'Socket'
                        WHEN LOWER(f.resource) LIKE '%thread%' OR LOWER(f.resource) LIKE '%process%' THEN 'Thread / Process'
                        WHEN LOWER(f.resource) LIKE '%db%' OR LOWER(f.resource) LIKE '%cursor%' THEN 'Database Cursor'
                        ELSE f.resource 
                    END AS resource_type,
                    COUNT(*) AS count
                FROM findings f
                JOIN scans s ON f.scan_id = s.scan_id
                {finding_where}
                GROUP BY resource_type
                ORDER BY count DESC
                """,
                finding_params,
            )
            raw_resources = cur.fetchall()
            resource_types = [
                {"type": r["resource_type"], "resource_type": r["resource_type"], "resource": r["resource_type"], "count": r["count"]}
                for r in raw_resources
            ]

            # 3. Unknown ownership findings count (tracked separately)
            cur.execute(
                f"""
                SELECT COUNT(*) as count
                FROM findings f
                JOIN scans s ON f.scan_id = s.scan_id
                WHERE f.ownership_status = 'UNKNOWN'
                {"AND s.project_id = ?" if (project_id and project_id not in ("all", "ALL", "")) else ""}
                {"AND s.timestamp >= ?" if (days and days > 0) else ""}
                """,
                [p for p in (scan_params if scan_params else [])],
            )
            unknown_count = cur.fetchone()["count"] or 0

            # 4. Leaks by project
            cur.execute(
                f"""
                SELECT p.name AS project_name, SUM(s.leaks_detected) AS total_leaks
                FROM projects p
                JOIN scans s ON p.project_id = s.project_id
                {scan_where}
                GROUP BY p.project_id
                ORDER BY total_leaks DESC
                """,
                scan_params,
            )
            leaks_by_project = [
                {"project_name": r["project_name"], "leaks": r["total_leaks"] or 0}
                for r in cur.fetchall()
            ]

            # 5. Scans over time (grouped by date)
            cur.execute(
                f"""
                SELECT substr(s.timestamp, 1, 10) AS scan_date, COUNT(*) AS count
                FROM scans s
                {scan_where}
                GROUP BY scan_date
                ORDER BY scan_date ASC
                """,
                scan_params,
            )
            scans_over_time = [
                {"date": r["scan_date"], "count": r["count"]}
                for r in cur.fetchall()
            ]

            # 6. CI failure stats
            ci_where_failed = f"{scan_where} {'AND' if scan_where else 'WHERE'} s.status = 'FAILED'"
            cur.execute(f"SELECT COUNT(*) as failed FROM scans s {ci_where_failed}", scan_params)
            ci_failures = cur.fetchone()["failed"] or 0

            ci_where_passed = f"{scan_where} {'AND' if scan_where else 'WHERE'} s.status = 'PASS'"
            cur.execute(f"SELECT COUNT(*) as passed FROM scans s {ci_where_passed}", scan_params)
            ci_passes = cur.fetchone()["passed"] or 0

            has_data = len(trend) > 0
            total_confirmed_leaks = sum(t["leak_count"] for t in trend)

            return {
                "has_data": has_data,
                "total_confirmed_leaks": total_confirmed_leaks,
                "unknown_ownership_count": unknown_count,
                "unknown_count": unknown_count,
                "trend": trend,
                "leaks_over_time": trend,
                "resource_types": resource_types,
                "leaks_by_resource": resource_types,
                "leaks_by_project": leaks_by_project,
                "scans_over_time": scans_over_time,
                "ci_stats": {
                    "failures": ci_failures,
                    "passes": ci_passes,
                    "total": ci_failures + ci_passes,
                },
                "filter_info": {
                    "project_id": project_id or "all",
                    "days": days,
                },
            }
