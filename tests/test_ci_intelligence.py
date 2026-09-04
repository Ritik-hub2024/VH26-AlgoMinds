"""Comprehensive test suite for Step 7: CI → Admin Security Intelligence.

Verifies:
- CI metadata extraction and environment variable detection
- Scan execution attribution (CI vs LOCAL SCAN vs UPLOAD)
- Deterministic project security health score formula (0-100)
- Differential leak categorization (Total, New/Blocking, Baseline/Tolerated)
- CLI --ci-export portable JSON artifact generation
- CLI --ingest persistence
- Backend HTTP POST /api/admin/ingest endpoint
- Admin portfolio and drilldown API extensions
- Edge cases and empty database states
"""

import json
import os
import tempfile
import urllib.request
from pathlib import Path
from typing import Dict, Any

import pytest

from cli import main, scan_target
from models.baseline import DifferentialReport
from models.issue import LeakIssue, Severity, SourceLocation
from models.policy import SecurityPolicy
from models.project import CIMetadata, ProjectHealth, ScanStatus
from models.report import AnalysisReport, SyntaxErrorInfo
from storage.database import Database, calculate_health_score


@pytest.fixture
def temp_db():
    """Isolated temporary SQLite database for tests."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_ci.db"
        yield Database(db_path=db_path)


class TestCIMetadata:
    """Test CI metadata capture and environment variable extraction."""

    def test_ci_metadata_defaults(self):
        meta = CIMetadata()
        assert meta.source == "CI"
        assert meta.repository is None
        assert meta.branch is None
        assert meta.commit_sha is None
        assert meta.pull_request is None

    def test_ci_metadata_from_env(self, monkeypatch):
        monkeypatch.setenv("GITHUB_ACTIONS", "true")
        monkeypatch.setenv("GITHUB_REPOSITORY", "octocat/Hello-World")
        monkeypatch.setenv("GITHUB_REF_NAME", "feature/auth-leaks")
        monkeypatch.setenv("GITHUB_SHA", "7fd1a60b01f91b314f59955a4e4d4e80d8edf11d")
        monkeypatch.setenv("GITHUB_REF", "refs/pull/42/merge")
        monkeypatch.setenv("GITHUB_RUN_ID", "123456789")
        monkeypatch.setenv("GITHUB_WORKFLOW", "LeakGuard CI")
        monkeypatch.setenv("GITHUB_ACTOR", "octocat")

        meta = CIMetadata.from_env()
        assert meta.source == "CI"
        assert meta.repository == "octocat/Hello-World"
        assert meta.branch == "feature/auth-leaks"
        assert meta.commit_sha == "7fd1a60b01f91b314f59955a4e4d4e80d8edf11d"
        assert meta.pull_request == "#42"
        assert meta.workflow_run == "123456789"
        assert meta.workflow_name == "LeakGuard CI"
        assert meta.actor == "octocat"

        d = meta.to_dict()
        assert d["pull_request"] == "#42"
        assert d["workflow_run"] == "123456789"

    def test_ci_metadata_overrides(self):
        meta = CIMetadata.from_env(overrides={
            "repository": "custom/repo",
            "branch": "develop",
            "commit_sha": "abc1234",
            "pull_request": "#99",
        })
        assert meta.repository == "custom/repo"
        assert meta.branch == "develop"
        assert meta.commit_sha == "abc1234"
        assert meta.pull_request == "#99"


class TestHealthScoreCalculation:
    """Test deterministic 0-100 project security health score formula."""

    def test_perfect_health_score(self):
        score, tier = calculate_health_score(
            issues=[],
            syntax_errors=[],
            status=ScanStatus.PASS.value,
        )
        assert score == 100
        assert tier == ProjectHealth.HEALTHY.value

    def test_single_high_leak_deduction(self):
        # Base 100 - 10 (HIGH) - 5 (FAILED) = 85
        issue = LeakIssue(
            rule_id="LEAK001",
            message="Unclosed file",
            severity=Severity.HIGH,
            location=SourceLocation("a.py", 1, 1),
            resource_type="file",
            resource_name="f",
        )
        score, tier = calculate_health_score(
            issues=[issue],
            syntax_errors=[],
            status=ScanStatus.FAILED.value,
            new_leaks=1,
            baseline_leaks=0,
        )
        assert score == 85
        assert tier == ProjectHealth.REVIEW.value

    def test_three_high_leaks_at_risk(self):
        # Base 100 - 30 (3*HIGH) - 5 (FAILED) = 65
        # With 3 leaks, status tier is AT_RISK
        issues = [
            LeakIssue(
                rule_id=f"LEAK00{i}",
                message="Unclosed file",
                severity=Severity.HIGH,
                location=SourceLocation(f"a_{i}.py", 1, 1),
                resource_type="file",
                resource_name=f"f{i}",
            )
            for i in range(1, 4)
        ]
        score, tier = calculate_health_score(
            issues=issues,
            syntax_errors=[],
            status=ScanStatus.FAILED.value,
            new_leaks=3,
            baseline_leaks=0,
        )
        assert score == 65
        assert tier == ProjectHealth.AT_RISK.value

    def test_critical_and_syntax_error_deductions(self):
        # Base 100 - 20 (CRITICAL) - 25 (Syntax error) - 5 (FAILED) = 50 -> AT_RISK
        issue = {"severity": "CRITICAL", "message": "Critical leak"}
        syntax_err = SyntaxErrorInfo("bad.py", 1, 1, "invalid syntax", "bad")
        score, tier = calculate_health_score(
            issues=[issue],
            syntax_errors=[syntax_err],
            status=ScanStatus.FAILED.value,
        )
        assert score == 50
        assert tier == ProjectHealth.AT_RISK.value

    def test_score_clamped_to_zero(self):
        # Many severe leaks clamp at 0
        issues = [{"severity": "CRITICAL"} for _ in range(10)]
        syntax_errors = [SyntaxErrorInfo("bad.py", 1, 1, "err", "x") for _ in range(5)]
        score, tier = calculate_health_score(
            issues=issues,
            syntax_errors=syntax_errors,
            status=ScanStatus.FAILED.value,
        )
        assert score == 0
        assert tier == ProjectHealth.AT_RISK.value


class TestCIResultIngestionAndAttribution:
    """Test portable CI artifact ingestion into SQLite and execution attribution."""

    def test_ingest_ci_result_attribution(self, temp_db: Database):
        ci_payload = {
            "version": "1.0",
            "source": "CI",
            "timestamp": "2026-09-05T01:00:00Z",
            "project_id": "ci-audit-project",
            "project_name": "CI Audit Project",
            "target": "python/leaks",
            "status": "FAILED",
            "health_score": 65,
            "summary": {
                "files_scanned": 8,
                "clean_files": 0,
                "syntax_errors": 0,
                "total_leaks": 3,
                "new_leaks": 2,
                "baseline_leaks": 1,
                "duration_ms": 15.2,
            },
            "ci_metadata": {
                "source": "CI",
                "repository": "Ritik-hub2024/VH26-AlgoMinds",
                "branch": "feature/security-audit",
                "commit_sha": "e1a2b3c4d5",
                "pull_request": "#77",
                "workflow_run": "99887766",
            },
            "findings": [
                {
                    "file": "python/leaks/file_no_close.py",
                    "line": 10,
                    "column": 4,
                    "resource": "f (file)",
                    "variable": "f",
                    "severity": "HIGH",
                    "reason": "Unclosed resource",
                    "leak_path": "open() -> return",
                    "recommendation": "Use with open",
                    "cleanup_status": "UNCLOSED",
                    "is_baseline": False,
                },
                {
                    "file": "python/leaks/sqlite_leak.py",
                    "line": 20,
                    "column": 4,
                    "resource": "conn (sqlite3)",
                    "variable": "conn",
                    "severity": "HIGH",
                    "reason": "Unclosed database connection",
                    "leak_path": "connect() -> exit",
                    "recommendation": "Call conn.close()",
                    "cleanup_status": "UNCLOSED",
                    "is_baseline": True,
                },
            ],
            "syntax_errors": [],
        }

        scan_rec = temp_db.ingest_ci_result(ci_payload)

        # 1. Attribution check: MUST be 'CI'
        assert scan_rec.scan_type == "CI"
        assert scan_rec.scan_type != "LOCAL SCAN"
        assert scan_rec.scan_type != "FILE UPLOAD"
        assert scan_rec.scan_type != "PROJECT UPLOAD"

        # 2. Metadata check
        assert scan_rec.commit_sha == "e1a2b3c4d5"
        assert scan_rec.branch == "feature/security-audit"
        assert scan_rec.repository == "Ritik-hub2024/VH26-AlgoMinds"
        assert scan_rec.pull_request == "#77"
        assert scan_rec.workflow_run == "99887766"
        assert scan_rec.new_leaks == 2
        assert scan_rec.baseline_leaks == 1
        assert scan_rec.health_score == 65

        # 3. Project record verification
        proj = temp_db.get_project("ci-audit-project")
        assert proj is not None
        assert proj["health_score"] == 65
        assert proj["latest_scan"]["scan_type"] == "CI"
        assert proj["latest_scan"]["commit_sha"] == "e1a2b3c4d5"
        assert proj["latest_scan"]["pull_request"] == "#77"

        # 4. Open findings check with is_baseline
        findings = proj["open_findings"]
        assert len(findings) == 2
        assert findings[0]["is_baseline"] == 0 or findings[0]["is_baseline"] is False
        assert findings[1]["is_baseline"] == 1 or findings[1]["is_baseline"] is True

    def test_cli_ci_export_and_ingest_flow(self, temp_db: Database, tmp_path: Path):
        """Test full end-to-end CLI generation of artifact and ingestion via CLI."""
        export_file = tmp_path / "ci-export-test.json"
        
        # 1. Run cli with --ci-export on safe corpus
        code = main([
            "--target", "python/safe",
            "--ci-export", str(export_file),
            "--strict",
        ])
        assert code == 0
        assert export_file.exists()

        with open(export_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        assert data["version"] == "1.0"
        assert data["source"] == "CI"
        assert data["status"] == "PASS"
        assert data["health_score"] == 100
        assert data["summary"]["clean_files"] == 8

        # 2. Ingest artifact via cli --ingest using the temporary database
        # Patch default DB path temporarily
        from storage import database
        orig_default = database._DEFAULT_DB_PATH
        try:
            database._DEFAULT_DB_PATH = Path(temp_db.db_path)
            ingest_code = main(["--ingest", str(export_file)])
            assert ingest_code == 0

            # Verify in db
            proj = temp_db.get_project("python-safe")
            assert proj is not None
            assert proj["latest_scan"]["scan_type"] == "CI"
            assert proj["latest_scan"]["status"] == "PASS"
            assert proj["health_score"] == 100
        finally:
            database._DEFAULT_DB_PATH = orig_default


class TestAdminAPIEndpoints:
    """Test HTTP API endpoints for Step 7 intelligence."""

    def test_admin_ingest_via_http(self):
        """Start a local server thread and post CI intelligence payload to /api/admin/ingest."""
        import http.server
        import threading
        from app import Handler, ReusableTCPServer
        
        with tempfile.TemporaryDirectory() as tmpdir:
            test_db_path = Path(tmpdir) / "api_test.db"
            test_db = Database(db_path=test_db_path)

            server = ReusableTCPServer(("127.0.0.1", 0), Handler)
            server._db = test_db
            port = server.server_address[1]

            t = threading.Thread(target=server.serve_forever)
            t.daemon = True
            t.start()

            try:
                url = f"http://127.0.0.1:{port}/api/admin/ingest"
                payload = {
                    "version": "1.0",
                    "source": "CI",
                    "project_id": "http-ci-project",
                    "target": "python/safe",
                    "status": "PASS",
                    "health_score": 95,
                    "summary": {
                        "files_scanned": 5,
                        "clean_files": 5,
                        "syntax_errors": 0,
                        "total_leaks": 0,
                        "new_leaks": 0,
                        "baseline_leaks": 0,
                        "duration_ms": 12.0,
                    },
                    "ci_metadata": {
                        "source": "CI",
                        "repository": "test/repo",
                        "branch": "main",
                        "commit_sha": "beef1234",
                        "pull_request": "#10",
                    },
                    "findings": [],
                    "syntax_errors": [],
                }
                req = urllib.request.Request(
                    url,
                    data=json.dumps(payload).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(req) as resp:
                    assert resp.status == 200
                    resp_data = json.loads(resp.read().decode("utf-8"))
                    assert resp_data["status"] == "SUCCESS"
                    assert resp_data["scan"]["scan_type"] == "CI"
                    assert resp_data["scan"]["commit_sha"] == "beef1234"

                # Verify GET /api/admin/project?id=http-ci-project
                get_url = f"http://127.0.0.1:{port}/api/admin/project?id=http-ci-project"
                with urllib.request.urlopen(get_url) as resp:
                    assert resp.status == 200
                    proj_data = json.loads(resp.read().decode("utf-8"))
                    p = proj_data["project"]
                    assert p["health_score"] == 95
                    assert p["latest_scan"]["scan_type"] == "CI"
                    assert p["latest_scan"]["pull_request"] == "#10"
            finally:
                server.shutdown()
                server.server_close()
