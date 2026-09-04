"""Tests for dashboard HTTP server and /api/scan endpoint."""

import json
import unittest
from io import BytesIO
from unittest.mock import MagicMock
import app


class TestServerHandler(unittest.TestCase):
    def setUp(self):
        self.handler = app.Handler.__new__(app.Handler)
        self.handler.wfile = BytesIO()
        self.handler.send_response = MagicMock()
        self.handler.send_header = MagicMock()
        self.handler.end_headers = MagicMock()

    def test_handle_api_scan_leak_target(self):
        self.handler._handle_api_scan("target=python")
        output = self.handler.wfile.getvalue().decode("utf-8")
        data = json.loads(output)

        self.assertIn("status", data)
        self.assertIn("files_scanned", data)
        self.assertIn("clean_files", data)
        self.assertIn("syntax_errors", data)
        self.assertIn("leaks_detected", data)
        self.assertIn("findings", data)

        # Scanning 'python' target has leaks
        self.assertEqual(data["status"], "FAILED")
        self.assertGreater(data["leaks_detected"], 0)
        self.assertGreater(len(data["findings"]), 0)

        # Check structure of findings
        first_finding = data["findings"][0]
        self.assertIn("severity", first_finding)
        self.assertIn("file", first_finding)
        self.assertIn("line", first_finding)
        self.assertIn("resource", first_finding)
        self.assertIn("reason", first_finding)
        self.assertIn("leak_path", first_finding)
        self.assertIn("recommendation", first_finding)

    def test_handle_api_scan_safe_target(self):
        self.handler._handle_api_scan("target=python/safe_file.py")
        output = self.handler.wfile.getvalue().decode("utf-8")
        data = json.loads(output)

        self.assertEqual(data["status"], "PASS")
        self.assertEqual(data["leaks_detected"], 0)
        self.assertEqual(len(data["findings"]), 0)

    def test_handle_api_scan_nonexistent_target(self):
        self.handler._handle_api_scan("target=does_not_exist_xyz")
        output = self.handler.wfile.getvalue().decode("utf-8")
        data = json.loads(output)

        self.assertEqual(data["status"], "ERROR")
        self.assertIn("does_not_exist_xyz", data["error"])


if __name__ == "__main__":
    unittest.main()
