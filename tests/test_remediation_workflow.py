"""End-to-end integration tests for LeakGuard remediation workflow:
Scan -> Detect -> Fix -> Diff -> Apply -> Re-scan Verification.
"""

import tempfile
from pathlib import Path
import pytest

import cli
from fixers.engine import RemediationEngine


def test_full_remediation_and_verification_flow():
    """Test full cycle: detect leak, generate fix, apply fix, re-scan, verify leak is gone."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        target_file = tmp_path / "service.py"
        target_file.write_text(
            """def fetch_configuration(config_path: str) -> str:
    f = open(config_path, "r")
    content = f.read()
    return content
""",
            encoding="utf-8",
        )

        # 1. Initial Scan: Detects the leak
        report = cli.scan_target(str(target_file))
        assert len(report.issues) == 1
        issue = report.issues[0]
        assert issue.rule_id == "LEAK001"
        assert issue.location.line == 2

        # 2. Generate Fix
        engine = RemediationEngine()
        finding_dict = issue.to_dict()
        gen_res = engine.generate_fix_for_finding(target_file, finding_dict)
        assert gen_res["success"] is True
        fix_record = gen_res["fix"]
        assert "with open(config_path, \"r\") as f:" in fix_record["modified_code"]

        # 3. Apply Fix & Verify Re-scan
        apply_res = engine.apply_fix(fix_record["fix_id"], base_scan_dir=tmp_path)
        assert apply_res["success"] is True
        assert apply_res["verified"] is True

        # 4. Independent re-scan confirms 0 leaks!
        verify_report = cli.scan_target(str(target_file))
        assert len(verify_report.issues) == 0
        assert verify_report.clean_files_count == 1

        # 5. Check Summary Stats
        summary = engine.get_summary()
        assert summary["total_fixes"] == 1
        assert summary["verified_fixes"] == 1
        assert "service.py" in summary["files_changed"]


def test_remediation_rollback_on_syntax_error():
    """Test that if a corrupted/invalid patch is applied, it automatically rolls back."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        target_file = tmp_path / "bad_patch.py"
        original_code = "def valid():\n    f = open('data.txt')\n    return f.read()\n"
        target_file.write_text(original_code, encoding="utf-8")

        engine = RemediationEngine()
        fix_id = "test_corrupt_fix"
        engine._fixes[fix_id] = {
            "fix_id": fix_id,
            "file_path": str(target_file),
            "rel_file": "bad_patch.py",
            "rule_id": "LEAK001",
            "line": 2,
            "original_code": original_code,
            "modified_code": "def valid():\n    with open('data.txt') as f:\n      broken syntax (((\n",
            "diff": {"additions": 1, "deletions": 1},
            "status": "PROPOSED",
        }

        apply_res = engine.apply_fix(fix_id, base_scan_dir=tmp_path)
        assert apply_res["success"] is False
        assert "Syntax validation failed" in apply_res["error"]

        # Confirm original code was restored
        assert target_file.read_text(encoding="utf-8") == original_code
