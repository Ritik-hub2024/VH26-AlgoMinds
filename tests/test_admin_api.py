"""Automated tests for Admin & Product Owner Dashboard API endpoints in app.py."""

import json
import unittest
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock

import app
from storage.database import Database


class TestAdminAPI(unittest.TestCase):
    """Verify all /api/admin/* endpoints, scan auto-persistence, and reset isolation."""

    def setUp(self):
        self.temp_dir = TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_api_admin.db"
        self.test_db = Database(db_path=self.db_path)

        self.handler = app.Handler.__new__(app.Handler)
        self.handler.wfile = BytesIO()
        self.handler.send_response = MagicMock()
        self.handler.send_header = MagicMock()
        self.handler.end_headers = MagicMock()
        self.handler.server = MagicMock()
        self.handler.server._db = self.test_db

    def tearDown(self):
        self.temp_dir.cleanup()

    def _get_response_data(self):
        output = self.handler.wfile.getvalue().decode("utf-8")
        return json.loads(output)

    def _reset_wfile(self):
        self.handler.wfile = BytesIO()
        self.handler.send_response = MagicMock()
        self.handler.send_header = MagicMock()
        self.handler.end_headers = MagicMock()

    def test_admin_summary_empty(self):
        """Admin summary on empty DB returns clean zeroes without synthetic data."""
        self.handler._handle_admin_summary()
        data = self._get_response_data()
        self.assertEqual(data["status"], "SUCCESS")
        summary = data["summary"]
        self.assertEqual(summary["projects_count"], 0)
        self.assertEqual(summary["total_scans"], 0)
        self.assertEqual(summary["open_leaks"], 0)
        self.assertEqual(summary["high_severity"], 0)
        self.assertEqual(summary["ci_blocked"], 0)

    def test_admin_projects_empty(self):
        """Admin projects endpoint returns empty list when no projects exist."""
        self.handler._handle_admin_projects()
        data = self._get_response_data()
        self.assertEqual(data["status"], "SUCCESS")
        self.assertEqual(data["projects"], [])

    def test_admin_project_not_found(self):
        """Requesting non-existent project returns 404."""
        self.handler._handle_admin_project("id=missing-id")
        self.handler.send_response.assert_called_with(404)
        data = self._get_response_data()
        self.assertEqual(data["status"], "ERROR")
        self.assertIn("not found", data["error"])

    def test_admin_project_missing_id_parameter(self):
        """Requesting project without id parameter returns 400."""
        self.handler._handle_admin_project("")
        self.handler.send_response.assert_called_with(400)
        data = self._get_response_data()
        self.assertEqual(data["status"], "ERROR")
        self.assertIn("Missing 'id'", data["error"])

    def test_admin_scans_empty(self):
        """Admin scans endpoint returns empty list initially."""
        self.handler._handle_admin_scans("")
        data = self._get_response_data()
        self.assertEqual(data["status"], "SUCCESS")
        self.assertEqual(data["scans"], [])

    def test_admin_analytics_empty(self):
        """Analytics endpoint reports has_data = False when empty."""
        self.handler._handle_admin_analytics()
        data = self._get_response_data()
        self.assertEqual(data["status"], "SUCCESS")
        self.assertFalse(data["analytics"]["has_data"])

    def test_scan_auto_persists_to_admin(self):
        """A live developer scan automatically persists and reflects in Admin endpoints."""
        # 1. Run live scan on safe suite
        self.handler._handle_api_scan("target=python/safe")
        scan_data = self._get_response_data()
        self.assertEqual(scan_data["status"], "PASS")

        # 2. Check Admin summary
        self._reset_wfile()
        self.handler._handle_admin_summary()
        summary_data = self._get_response_data()
        self.assertEqual(summary_data["summary"]["projects_count"], 1)
        self.assertEqual(summary_data["summary"]["total_scans"], 1)
        self.assertEqual(summary_data["summary"]["open_leaks"], 0)
        self.assertEqual(summary_data["summary"]["ci_blocked"], 0)

        # 3. Check Admin projects list
        self._reset_wfile()
        self.handler._handle_admin_projects()
        proj_list = self._get_response_data()
        self.assertEqual(len(proj_list["projects"]), 1)
        p = proj_list["projects"][0]
        self.assertEqual(p["project_id"], "python-safe")
        self.assertEqual(p["status"], "HEALTHY")
        self.assertEqual(p["latest_scan"]["status"], "PASS")

        # 4. Run second scan on leak suite
        self._reset_wfile()
        self.handler._handle_api_scan("target=python/leaks")
        leak_scan_data = self._get_response_data()
        self.assertEqual(leak_scan_data["status"], "FAILED")

        # 5. Check Admin summary now reflects both projects
        self._reset_wfile()
        self.handler._handle_admin_summary()
        summary_data = self._get_response_data()
        self.assertEqual(summary_data["summary"]["projects_count"], 2)
        self.assertEqual(summary_data["summary"]["total_scans"], 2)
        self.assertEqual(summary_data["summary"]["open_leaks"], 8)
        self.assertEqual(summary_data["summary"]["ci_blocked"], 1)

        # 6. Retrieve project detail for python-leaks
        self._reset_wfile()
        self.handler._handle_admin_project("id=python-leaks")
        leak_proj = self._get_response_data()
        self.assertEqual(leak_proj["status"], "SUCCESS")
        self.assertEqual(leak_proj["project"]["status"], "AT_RISK")
        self.assertEqual(len(leak_proj["project"]["open_findings"]), 8)
        self.assertEqual(len(leak_proj["project"]["scan_history"]), 1)

    def test_developer_reset_preserves_admin_history(self):
        """Clicking Reset on developer dashboard resets developer state without wiping Admin history."""
        # Run scan
        self.handler._handle_api_scan("target=python/safe")
        self._get_response_data()

        # Developer clicks Reset
        self._reset_wfile()
        self.handler._handle_api_reset()
        reset_data = self._get_response_data()
        self.assertEqual(reset_data["status"], "NOT_SCANNED")
        self.assertEqual(reset_data["files_scanned"], 0)

        # Admin history STILL exists!
        self._reset_wfile()
        self.handler._handle_admin_summary()
        admin_summary = self._get_response_data()
        self.assertEqual(admin_summary["summary"]["total_scans"], 1)
        self.assertEqual(admin_summary["summary"]["projects_count"], 1)

    def test_phase_11_end_to_end_sequence(self):
        """Execute exact Phase 11 16-step end-to-end verification sequence."""
        # Step 1: Open Developer dashboard (clean state)
        self.handler._handle_api_reset()
        init_state = self._get_response_data()
        self.assertEqual(init_state["status"], "NOT_SCANNED")

        # Step 2: Scan safe Python project
        self._reset_wfile()
        self.handler._handle_api_scan("target=python/safe")
        safe_scan = self._get_response_data()

        # Step 3: Confirm PASS
        self.assertEqual(safe_scan["status"], "PASS")
        self.assertEqual(safe_scan["leaks_detected"], 0)

        # Step 4: Confirm scan appears in history
        self._reset_wfile()
        self.handler._handle_admin_scans("")
        scans_list = self._get_response_data()["scans"]
        self.assertEqual(len(scans_list), 1)
        self.assertEqual(scans_list[0]["status"], "PASS")

        # Step 5: Scan a leaky Python project
        self._reset_wfile()
        self.handler._handle_api_scan("target=python/leaks")
        leaky_scan = self._get_response_data()

        # Step 6: Confirm FAILED
        self.assertEqual(leaky_scan["status"], "FAILED")
        self.assertGreater(leaky_scan["leaks_detected"], 0)

        # Step 7: Confirm finding is stored
        self._reset_wfile()
        self.handler._handle_admin_project("id=python-leaks")
        proj_detail = self._get_response_data()["project"]
        self.assertGreater(len(proj_detail["open_findings"]), 0)

        # Step 8: Open Admin dashboard
        self._reset_wfile()
        self.handler._handle_admin_summary()
        summary = self._get_response_data()["summary"]

        # Step 9: Confirm project status changed
        self.assertEqual(proj_detail["status"], "AT_RISK")

        # Step 10: Confirm leak count changed
        self.assertEqual(summary["open_leaks"], 8)

        # Step 11: Confirm latest scan appears
        self.assertEqual(proj_detail["latest_scan"]["status"], "FAILED")

        # Step 12: Confirm findings can be opened
        first_finding = proj_detail["open_findings"][0]
        self.assertIn("file", first_finding)
        self.assertIn("line", first_finding)
        self.assertIn("reason", first_finding)

        # Step 13: Reset developer dashboard
        self._reset_wfile()
        self.handler._handle_api_reset()
        reset_res = self._get_response_data()
        self.assertEqual(reset_res["status"], "NOT_SCANNED")

        # Step 14: Confirm Admin history remains available
        self._reset_wfile()
        self.handler._handle_admin_summary()
        admin_summary = self._get_response_data()["summary"]
        self.assertEqual(admin_summary["total_scans"], 2)
        self.assertEqual(admin_summary["projects_count"], 2)

        # Step 15: Restart the local server (recreate handler & Database instance from disk)
        new_db = Database(db_path=self.db_path)
        new_handler = app.Handler.__new__(app.Handler)
        new_handler.wfile = BytesIO()
        new_handler.send_response = MagicMock()
        new_handler.send_header = MagicMock()
        new_handler.end_headers = MagicMock()
        new_handler.server = MagicMock()
        new_handler.server._db = new_db

        # Step 16: Confirm persistent history still exists
        new_handler._handle_admin_summary()
        persisted_summary = json.loads(new_handler.wfile.getvalue().decode("utf-8"))["summary"]
        self.assertEqual(persisted_summary["total_scans"], 2)
        self.assertEqual(persisted_summary["projects_count"], 2)
        self.assertEqual(persisted_summary["open_leaks"], 8)

