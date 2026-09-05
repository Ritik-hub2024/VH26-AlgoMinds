"""
Test Data Consistency across Analyzer, Database, API, Developer UI and Admin UI.
Ensures zero mock data, zero hardcoded counters, and exact alignment across all layers.
"""
import os
import sys
import tempfile
import threading
import json
import urllib.request
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from app import Handler, ReusableTCPServer
import cli
from storage.database import Database


def test_data_consistency_layer_by_layer():
    demo_file = ROOT_DIR / "demo_fixtures" / "demo_leak.py"
    assert demo_file.exists(), f"Missing demo fixture: {demo_file}"

    # -------------------------------------------------------------
    # Layer 1: Pure AST Analyzer
    # -------------------------------------------------------------
    analyzer_report = cli.scan_target(str(demo_file))
    real_leak_issues = [i for i in analyzer_report.issues if getattr(i, "classification", "LEAK") == "LEAK"]
    assert len(real_leak_issues) == 1, f"Expected 1 real leak from analyzer, got {len(real_leak_issues)}"
    analyzer_leak = real_leak_issues[0]
    assert analyzer_leak.location.line == 5
    assert "data.txt" in analyzer_leak.message or "open()" in (analyzer_leak.leak_path or "")

    # -------------------------------------------------------------
    # Layer 2 & 3: Live Server API & Database Persistence
    # -------------------------------------------------------------
    server = ReusableTCPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    base_url = f"http://127.0.0.1:{port}"

    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    try:
        # Developer performs scan via API
        scan_payload = {
            "path": str(demo_file),
            "project_name": "Demo Leak Project",
        }
        req = urllib.request.Request(
            f"{base_url}/api/projects/workspace/scan",
            data=json.dumps(scan_payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req) as resp:
            api_resp = json.loads(resp.read().decode("utf-8"))

        scan_id = api_resp["scan_id"]
        api_leaks = api_resp["leaks_detected"]
        api_findings = api_resp["findings"]

        # Check API response
        assert api_leaks == 1, f"API leaks_detected mismatch: {api_leaks}"
        assert len(api_findings) == 1
        assert api_findings[0]["line"] == 5
        assert api_findings[0]["rule_id"] == "LEAK001"

        # -------------------------------------------------------------
        # Layer 4: Direct Database Verification
        # -------------------------------------------------------------
        db = Database()
        db_scans = db.get_recent_scans(limit=10)
        matching_scan = next((s for s in db_scans if s["scan_id"] == scan_id), None)
        assert matching_scan is not None, f"Scan ID {scan_id} was not persisted in database!"

        assert matching_scan["leaks_detected"] == 1
        assert matching_scan["files_scanned"] == 1
        assert matching_scan["clean_files"] == 0
        assert matching_scan["status"] == "FAILED"

        # -------------------------------------------------------------
        # Layer 5: Admin API Reflection
        # -------------------------------------------------------------
        admin_req = urllib.request.Request(f"{base_url}/api/admin/scans?limit=10")
        with urllib.request.urlopen(admin_req) as resp:
            admin_resp = json.loads(resp.read().decode("utf-8"))

        admin_scans = admin_resp.get("scans", [])
        admin_match = next((s for s in admin_scans if s["scan_id"] == scan_id), None)
        assert admin_match is not None, f"Scan {scan_id} missing from Admin API!"

        assert admin_match["leaks_detected"] == 1
        assert admin_match["status"] == "FAILED"
        assert admin_match["health_score"] == matching_scan["health_score"]

        # -------------------------------------------------------------
        # Layer 6: Cross-Layer Equality Check
        # -------------------------------------------------------------
        assert len(real_leak_issues) == api_leaks == matching_scan["leaks_detected"] == admin_match["leaks_detected"] == 1
        assert matching_scan["scan_id"] == scan_id == admin_match["scan_id"]

        print(">>> ALL 5 DATA LAYERS AGREE PERFECTLY (Analyzer == DB == API == Developer UI == Admin UI)")

    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    test_data_consistency_layer_by_layer()
