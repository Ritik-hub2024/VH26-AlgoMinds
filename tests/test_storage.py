"""Automated tests for SQLite persistence layer and project history tracking."""

import pytest
from pathlib import Path

from models.issue import LeakIssue, Severity
from models.location import SourceLocation
from models.project import ProjectHealth, ScanStatus
from models.report import AnalysisReport, ParseResult
from storage.database import Database


@pytest.fixture
def db(tmp_path: Path) -> Database:
    """Fixture providing an isolated SQLite database instance in temporary directory."""
    db_file = tmp_path / "test_leakguard.db"
    return Database(db_path=db_file)


class TestDatabasePersistence:
    """Test suite for Database operations, schema creation, and queries."""

    def test_empty_database_state(self, db: Database):
        """Empty database returns clean zero counts without fake data."""
        summary = db.get_summary()
        assert summary["projects_count"] == 0
        assert summary["total_scans"] == 0
        assert summary["open_leaks"] == 0
        assert summary["high_severity"] == 0
        assert summary["ci_blocked"] == 0

        projects = db.get_projects()
        assert projects == []

        recent_scans = db.get_recent_scans()
        assert recent_scans == []

        analytics = db.get_analytics()
        assert analytics["has_data"] is False
        assert analytics["leaks_over_time"] == []
        assert analytics["leaks_by_resource"] == []

    def test_ensure_project(self, db: Database):
        """Verify project creation and idempotency."""
        p1 = db.ensure_project(
            project_id="test-proj",
            name="Test Project",
            repository="org/repo",
            branch="main",
        )
        assert p1.project_id == "test-proj"
        assert p1.name == "Test Project"
        assert p1.repository == "org/repo"
        assert p1.branch == "main"
        assert p1.status == ProjectHealth.NOT_SCANNED.value

        # Second call returns existing project without duplication
        p2 = db.ensure_project(project_id="test-proj", name="Test Project")
        assert p2.project_id == p1.project_id
        assert p2.created_at == p1.created_at

        projects = db.get_projects()
        assert len(projects) == 1
        assert projects[0]["project_id"] == "test-proj"

    def test_record_safe_scan(self, db: Database):
        """Safe scan outcome updates project to HEALTHY and records PASS scan."""
        report = AnalysisReport(target_path="python/safe")
        report.files_scanned = 5
        report.duration_seconds = 0.015

        scan_rec = db.record_scan(
            report=report,
            project_id="safe-proj",
            target_override="python/safe",
        )

        assert scan_rec.status == ScanStatus.PASS.value
        assert scan_rec.files_scanned == 5
        assert scan_rec.leaks_detected == 0
        assert len(scan_rec.findings) == 0

        # Check project was updated to HEALTHY
        proj_dict = db.get_project("safe-proj")
        assert proj_dict is not None
        assert proj_dict["status"] == ProjectHealth.HEALTHY.value
        assert proj_dict["latest_scan"]["status"] == "PASS"
        assert proj_dict["latest_scan"]["leaks_detected"] == 0
        assert len(proj_dict["open_findings"]) == 0

    def test_record_failed_scan_with_findings(self, db: Database):
        """Failed scan with leaks updates project to AT_RISK and records FindingRecords."""
        report = AnalysisReport(target_path="python/leaks")
        report.files_scanned = 6
        report.duration_seconds = 0.025

        # Create 3 leak issues
        for i in range(1, 4):
            issue = LeakIssue(
                rule_id="LEAK001",
                message=f"Resource 'f{i}' is not closed.",
                severity=Severity.HIGH,
                location=SourceLocation(file_path=f"file_{i}.py", line=i * 5, column=4),
                resource_name=f"f{i}",
                resource_type="file",
                leak_path=f"L{i*5}: open() -> L{i*5+2}: return (leak)",
                recommendation=f"Use with open(...) as f{i}:",
            )
            report.issues.append(issue)

        scan_rec = db.record_scan(
            report=report,
            project_id="leak-proj",
            target_override="python/leaks",
        )

        assert scan_rec.status == ScanStatus.FAILED.value
        assert scan_rec.leaks_detected == 3
        assert len(scan_rec.findings) == 3

        # Project should be AT_RISK (>= 3 leaks)
        proj_dict = db.get_project("leak-proj")
        assert proj_dict is not None
        assert proj_dict["status"] == ProjectHealth.AT_RISK.value
        assert proj_dict["latest_scan"]["status"] == "FAILED"
        assert proj_dict["latest_scan"]["leaks_detected"] == 3
        assert len(proj_dict["open_findings"]) == 3

        # Verify finding details
        first_fnd = proj_dict["open_findings"][0]
        assert first_fnd["severity"] == "HIGH"
        assert first_fnd["file"] == "file_1.py"
        assert first_fnd["line"] == 5
        assert first_fnd["variable"] == "f1"
        assert "open() ->" in first_fnd["leak_path"]

    def test_summary_and_analytics_aggregation(self, db: Database):
        """Summary and analytics accurately aggregate multiple projects and scans."""
        # Project 1: Safe
        safe_report = AnalysisReport(target_path="python/safe")
        safe_report.files_scanned = 5
        safe_report.duration_seconds = 0.01
        db.record_scan(safe_report, project_id="safe-project", target_override="python/safe")

        # Project 2: Leaks
        leak_report = AnalysisReport(target_path="python/leaks")
        leak_report.files_scanned = 6
        leak_report.duration_seconds = 0.02
        leak_report.issues.append(
            LeakIssue(
                rule_id="LEAK002",
                message="SQLite connection not closed.",
                severity=Severity.HIGH,
                location=SourceLocation(file_path="db.py", line=10, column=0),
                resource_name="conn",
                resource_type="SQLite connection",
                leak_path="L10: connect() -> L12: return",
                recommendation="Call conn.close()",
            )
        )
        db.record_scan(leak_report, project_id="leak-project", target_override="python/leaks")

        summary = db.get_summary()
        assert summary["projects_count"] == 2
        assert summary["total_scans"] == 2
        assert summary["open_leaks"] == 1
        assert summary["high_severity"] == 1
        assert summary["ci_blocked"] == 1

        analytics = db.get_analytics()
        assert analytics["has_data"] is True
        assert len(analytics["leaks_over_time"]) == 2
        assert analytics["ci_stats"]["failures"] == 1
        assert analytics["ci_stats"]["passes"] == 1

    def test_scan_history_chronology(self, db: Database):
        """Multiple scans for a single project maintain chronological history."""
        proj_id = "evolving-proj"

        # Scan 1: FAILED with 2 leaks
        rep1 = AnalysisReport(target_path="src/")
        rep1.files_scanned = 10
        rep1.duration_seconds = 0.02
        rep1.issues.append(
            LeakIssue(
                rule_id="LEAK001",
                message="leak a",
                severity=Severity.HIGH,
                location=SourceLocation(file_path="a.py", line=4, column=0),
                resource_name="f",
            )
        )
        db.record_scan(rep1, project_id=proj_id, target_override="src/")

        # Scan 2: PASS (fixed)
        rep2 = AnalysisReport(target_path="src/")
        rep2.files_scanned = 10
        rep2.duration_seconds = 0.015
        db.record_scan(rep2, project_id=proj_id, target_override="src/")

        proj = db.get_project(proj_id)
        assert proj is not None
        # Latest scan is PASS
        assert proj["status"] == ProjectHealth.HEALTHY.value
        assert proj["latest_scan"]["status"] == "PASS"
        assert proj["latest_scan"]["leaks_detected"] == 0
        assert len(proj["open_findings"]) == 0

        # History contains both scans, newest first
        history = proj["scan_history"]
        assert len(history) == 2
        assert history[0]["status"] == "PASS"
        assert history[1]["status"] == "FAILED"

    def test_get_analytics_filtering_and_resource_types(self, db: Database):
        """get_analytics filters by project_id and days, computing leak trend and resource types."""
        # Project A with file leak and sqlite leak
        repA = AnalysisReport(target_path="repoA/")
        repA.files_scanned = 4
        repA.issues.extend([
            LeakIssue(
                rule_id="LEAK001",
                message="file unclosed",
                severity=Severity.HIGH,
                location=SourceLocation(file_path="a.py", line=10, column=0),
                resource_name="f",
                resource_type="File",
            ),
            LeakIssue(
                rule_id="LEAK002",
                message="db unclosed",
                severity=Severity.MEDIUM,
                location=SourceLocation(file_path="db.py", line=20, column=0),
                resource_name="db",
                resource_type="SQLite Connection",
            ),
        ])
        db.record_scan(repA, project_id="proj-a", target_override="repoA/")

        # Project B with 2 file leaks
        repB = AnalysisReport(target_path="repoB/")
        repB.files_scanned = 2
        repB.issues.extend([
            LeakIssue(
                rule_id="LEAK001",
                message="file 1 unclosed",
                severity=Severity.HIGH,
                location=SourceLocation(file_path="b1.py", line=5, column=0),
                resource_name="f1",
                resource_type="File",
            ),
            LeakIssue(
                rule_id="LEAK001",
                message="file 2 unclosed",
                severity=Severity.HIGH,
                location=SourceLocation(file_path="b2.py", line=8, column=0),
                resource_name="f2",
                resource_type="File",
            ),
        ])
        db.record_scan(repB, project_id="proj-b", target_override="repoB/")

        # 1. Query All Projects
        analytics_all = db.get_analytics()
        assert analytics_all["has_data"] is True
        assert analytics_all["total_confirmed_leaks"] == 4
        assert len(analytics_all["trend"]) == 2
        assert len(analytics_all["resource_types"]) == 2
        # Resource Types: File (3), SQLite Connection (1)
        res_map = {r["type"]: r["count"] for r in analytics_all["resource_types"]}
        assert res_map["File"] == 3
        assert res_map["SQLite Connection"] == 1

        # 2. Query Project A Only
        analytics_a = db.get_analytics(project_id="proj-a")
        assert analytics_a["has_data"] is True
        assert analytics_a["total_confirmed_leaks"] == 2
        assert len(analytics_a["trend"]) == 1
        assert analytics_a["trend"][0]["leak_count"] == 2
        res_map_a = {r["type"]: r["count"] for r in analytics_a["resource_types"]}
        assert res_map_a["File"] == 1
        assert res_map_a["SQLite Connection"] == 1

        # 3. Query Project B Only
        analytics_b = db.get_analytics(project_id="proj-b")
        assert analytics_b["total_confirmed_leaks"] == 2
        assert len(analytics_b["trend"]) == 1
        res_map_b = {r["type"]: r["count"] for r in analytics_b["resource_types"]}
        assert res_map_b["File"] == 2
        assert "SQLite Connection" not in res_map_b

    def test_get_analytics_excludes_unknown_and_baseline(self, db: Database):
        """get_analytics strictly excludes baseline findings and tracks UNKNOWN ownership separately."""
        rep = AnalysisReport(target_path="app/")
        rep.files_scanned = 3
        rep.issues.append(
            LeakIssue(
                rule_id="LEAK001",
                message="real leak",
                severity=Severity.HIGH,
                location=SourceLocation(file_path="main.py", line=12, column=0),
                resource_name="f",
                resource_type="File",
            )
        )
        scan = db.record_scan(rep, project_id="mixed-proj", target_override="app/")

        # Insert a baseline finding and an UNKNOWN ownership finding manually to test classification filtering
        with db._connection() as conn:
            # Baseline finding (should be excluded from confirmed leaks)
            conn.execute(
                """
                INSERT INTO findings (
                    finding_id, scan_id, file, line, column, resource,
                    variable, severity, reason, leak_path, recommendation, cleanup_status,
                    is_baseline, classification, ownership_status, callee_name, transfer_line, scope_limitation
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                ("fnd-baseline", scan.scan_id, "base.py", 1, 0, "File", "b", "HIGH", "old base", "", "", "CLEANUP_MISSING", 1, "LEAK", "INTERNAL", None, None, None)
            )
            # UNKNOWN ownership finding (should be tracked under unknown_ownership_count, not in confirmed leaks)
            conn.execute(
                """
                INSERT INTO findings (
                    finding_id, scan_id, file, line, column, resource,
                    variable, severity, reason, leak_path, recommendation, cleanup_status,
                    is_baseline, classification, ownership_status, callee_name, transfer_line, scope_limitation
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                ("fnd-unknown", scan.scan_id, "unk.py", 5, 0, "Socket", "u", "MEDIUM", "unknown leak", "", "", "CLEANUP_MISSING", 0, "UNKNOWN", "UNKNOWN", None, None, None)
            )

        analytics = db.get_analytics(project_id="mixed-proj")
        assert analytics["total_confirmed_leaks"] == 1
        assert analytics["unknown_ownership_count"] == 1
        assert len(analytics["resource_types"]) == 1
        assert analytics["resource_types"][0]["type"] == "File"
        assert analytics["resource_types"][0]["count"] == 1


