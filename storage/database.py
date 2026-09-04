"""Lightweight SQLite persistence layer for LeakGuard Admin & Scan History.

Completely decoupled from the core AST analyzer.
Stores project metadata, scan executions, and detected leak findings.
"""

import contextlib
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List, Dict, Any, Union

from models.project import Project, ProjectHealth, ScanRecord, FindingRecord, ScanStatus
from models.report import AnalysisReport


_DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "leakguard.db"


class Database:
    """Thread-safe SQLite database adapter for LeakGuard project history."""

    def __init__(self, db_path: Optional[Union[str, Path]] = None) -> None:
        self.db_path = str(db_path) if db_path else str(_DEFAULT_DB_PATH)
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
            columns = [row["name"] for row in cur.fetchall()]
            if "scan_type" not in columns:
                cur.execute("ALTER TABLE scans ADD COLUMN scan_type TEXT NOT NULL DEFAULT 'LOCAL SCAN'")

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
    ) -> Project:
        """Create project if it does not already exist, or return existing."""
        now = datetime.now(timezone.utc).isoformat()
        with self._connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM projects WHERE project_id = ?", (project_id,))
            row = cur.fetchone()
            if row:
                return Project(
                    project_id=row["project_id"],
                    name=row["name"],
                    repository=row["repository"],
                    branch=row["branch"],
                    status=row["status"],
                    created_at=row["created_at"],
                    updated_at=row["updated_at"],
                )

            cur.execute(
                """
                INSERT INTO projects (project_id, name, repository, branch, status, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (project_id, name, repository, branch, status, now, now),
            )
            return Project(
                project_id=project_id,
                name=name,
                repository=repository,
                branch=branch,
                status=status,
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
                )
                findings_to_insert.append(fnd)

        # Update project status based on scan outcome
        if status == ScanStatus.PASS.value:
            new_project_health = ProjectHealth.HEALTHY.value
        else:
            # If 3 or more leaks or syntax errors -> AT_RISK, else REVIEW
            if len(report.issues) >= 3 or len(report.syntax_errors) > 0:
                new_project_health = ProjectHealth.AT_RISK.value
            else:
                new_project_health = ProjectHealth.REVIEW.value

        with self._connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO scans (
                    scan_id, project_id, timestamp, target, files_scanned,
                    clean_files, syntax_errors, leaks_detected, status, duration_ms, scan_type
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                ),
            )

            for f in findings_to_insert:
                cur.execute(
                    """
                    INSERT INTO findings (
                        finding_id, scan_id, file, line, column, resource,
                        variable, severity, reason, leak_path, recommendation, cleanup_status
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    ),
                )

            cur.execute(
                """
                UPDATE projects
                SET status = ?, updated_at = ?
                WHERE project_id = ?
                """,
                (new_project_health, now, project_id),
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
                result.append({
                    "project_id": r["project_id"],
                    "name": r["name"],
                    "repository": r["repository"],
                    "branch": r["branch"],
                    "status": r["status"],
                    "created_at": r["created_at"],
                    "updated_at": r["updated_at"],
                    "total_scans": r["total_scans"],
                    "latest_scan": {
                        "scan_id": r["latest_scan_id"],
                        "timestamp": r["latest_scan_time"],
                        "target": r["latest_scan_target"],
                        "files_scanned": r["latest_files_scanned"],
                        "clean_files": r["latest_clean_files"],
                        "syntax_errors": r["latest_syntax_errors"],
                        "leaks_detected": r["latest_leaks"] if r["latest_leaks"] is not None else 0,
                        "status": r["latest_status"] or "NOT_SCANNED",
                        "duration_ms": r["latest_duration_ms"] or 0,
                    } if r["latest_scan_id"] else None,
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
                       syntax_errors, leaks_detected, status, duration_ms, scan_type
                FROM scans
                WHERE project_id = ?
                ORDER BY timestamp DESC, rowid DESC
                LIMIT 30
                """,
                (project_id,),
            )
            history = [dict(h) for h in cur.fetchall()]

            return {
                "project_id": p["project_id"],
                "name": p["name"],
                "repository": p["repository"],
                "branch": p["branch"],
                "status": p["status"],
                "created_at": p["created_at"],
                "updated_at": p["updated_at"],
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

    def get_analytics(self) -> Dict[str, Any]:
        """Prepare analytics for leak trends, resource breakdown, and CI statistics."""
        with self._connection() as conn:
            cur = conn.cursor()

            # Leaks over time (from latest 30 scans)
            cur.execute(
                """
                SELECT scan_id, timestamp, target, leaks_detected, status
                FROM scans
                ORDER BY timestamp ASC, rowid ASC
                LIMIT 50
                """
            )
            leaks_over_time = [
                {
                    "scan_id": r["scan_id"],
                    "timestamp": r["timestamp"],
                    "target": r["target"],
                    "leaks": r["leaks_detected"],
                    "status": r["status"],
                }
                for r in cur.fetchall()
            ]

            # Leaks by resource type (from all recorded findings)
            cur.execute(
                """
                SELECT resource, COUNT(*) AS count
                FROM findings
                GROUP BY resource
                ORDER BY count DESC
                """
            )
            leaks_by_resource = [
                {"resource": r["resource"], "count": r["count"]}
                for r in cur.fetchall()
            ]

            # Leaks by project
            cur.execute(
                """
                SELECT p.name AS project_name, SUM(s.leaks_detected) AS total_leaks
                FROM projects p
                JOIN scans s ON p.project_id = s.project_id
                GROUP BY p.project_id
                ORDER BY total_leaks DESC
                """
            )
            leaks_by_project = [
                {"project_name": r["project_name"], "leaks": r["total_leaks"] or 0}
                for r in cur.fetchall()
            ]

            # Scans over time (grouped by date)
            cur.execute(
                """
                SELECT substr(timestamp, 1, 10) AS scan_date, COUNT(*) AS count
                FROM scans
                GROUP BY scan_date
                ORDER BY scan_date ASC
                """
            )
            scans_over_time = [
                {"date": r["scan_date"], "count": r["count"]}
                for r in cur.fetchall()
            ]

            # CI failure stats
            cur.execute(
                "SELECT COUNT(*) as failed FROM scans WHERE status = 'FAILED'"
            )
            ci_failures = cur.fetchone()["failed"] or 0

            cur.execute(
                "SELECT COUNT(*) as passed FROM scans WHERE status = 'PASS'"
            )
            ci_passes = cur.fetchone()["passed"] or 0

            has_data = len(leaks_over_time) > 0

            return {
                "has_data": has_data,
                "leaks_over_time": leaks_over_time,
                "leaks_by_resource": leaks_by_resource,
                "leaks_by_project": leaks_by_project,
                "scans_over_time": scans_over_time,
                "ci_stats": {
                    "failures": ci_failures,
                    "passes": ci_passes,
                    "total": ci_failures + ci_passes,
                },
            }
