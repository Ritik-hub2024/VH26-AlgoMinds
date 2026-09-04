"""Tests for dashboard HTTP server, /api/scan endpoint, security checks, and data contract."""

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

    def _get_response_data(self):
        output = self.handler.wfile.getvalue().decode("utf-8")
        return json.loads(output)

    def test_default_target_examples_suite(self):
        """Scanning default target (examples) should detect both the leak and the syntax error."""
        self.handler._handle_api_scan("")  # defaults to examples
        data = self._get_response_data()

        self.assertEqual(data["status"], "FAILED")
        self.assertEqual(data["target"], "examples")
        self.assertEqual(data["files_scanned"], 3)
        self.assertEqual(data["clean_files"], 1)
        self.assertEqual(data["syntax_errors"], 1)
        self.assertEqual(data["leaks_detected"], 1)
        self.assertGreater(len(data["findings"]), 0)
        self.assertGreater(len(data["files"]), 0)

        # Check finding structure matches Phase 4 data contract
        f = data["findings"][0]
        self.assertEqual(f["severity"], "HIGH")
        self.assertIn("examples/resource_sample.py", f["file"].replace("\\", "/"))
        self.assertEqual(f["line"], 5)
        self.assertEqual(f["variable"], "f")
        self.assertIn("not guaranteed to be closed", f["reason"])
        self.assertIn("open()", f["leak_path"])
        self.assertIn("close()", f["recommendation"])

    def test_handle_api_scan_leaks_suite(self):
        """Scanning python/leaks should return FAILED with exact leak findings."""
        self.handler._handle_api_scan("target=python/leaks")
        data = self._get_response_data()

        self.assertEqual(data["status"], "FAILED")
        self.assertEqual(data["files_scanned"], 2)
        self.assertEqual(data["clean_files"], 0)
        self.assertEqual(data["leaks_detected"], 2)
        self.assertEqual(len(data["findings"]), 2)

    def test_handle_api_scan_safe_suite(self):
        """Scanning python/safe should return PASS with zero leaks and clean file inventory."""
        self.handler._handle_api_scan("target=python/safe")
        data = self._get_response_data()

        self.assertEqual(data["status"], "PASS")
        self.assertEqual(data["files_scanned"], 2)
        self.assertEqual(data["clean_files"], 2)
        self.assertEqual(data["leaks_detected"], 0)
        self.assertEqual(len(data["findings"]), 0)
        for file_item in data["files"]:
            self.assertEqual(file_item["status"], "CLEAN")

    def test_handle_api_scan_individual_safe_with_file(self):
        """Context manager with open(...) as f: returns PASS."""
        self.handler._handle_api_scan("target=python/safe/with_file.py")
        data = self._get_response_data()

        self.assertEqual(data["status"], "PASS")
        self.assertEqual(data["leaks_detected"], 0)
        self.assertEqual(len(data["findings"]), 0)

    def test_handle_api_scan_individual_safe_explicit_close(self):
        """Explicit close f.close() returns PASS."""
        self.handler._handle_api_scan("target=python/safe/explicit_close.py")
        data = self._get_response_data()

        self.assertEqual(data["status"], "PASS")
        self.assertEqual(data["leaks_detected"], 0)

    def test_handle_api_scan_early_return_leak(self):
        """Early return before close returns FAILED with line and leak path."""
        self.handler._handle_api_scan("target=python/leaks/early_return.py")
        data = self._get_response_data()

        self.assertEqual(data["status"], "FAILED")
        self.assertEqual(data["leaks_detected"], 1)
        finding = data["findings"][0]
        self.assertIn("early_return.py", finding["file"].replace("\\", "/"))
        self.assertIn("return", finding["leak_path"])

    def test_handle_api_scan_file_no_close_leak(self):
        """Missing close before return returns FAILED."""
        self.handler._handle_api_scan("target=python/leaks/file_no_close.py")
        data = self._get_response_data()

        self.assertEqual(data["status"], "FAILED")
        self.assertEqual(data["leaks_detected"], 1)

    def test_handle_api_scan_security_path_traversal(self):
        """Path traversal outside project root must be rejected with 403."""
        self.handler._handle_api_scan("target=../../windows")
        self.handler.send_response.assert_called_with(403)
        data = self._get_response_data()
        self.assertEqual(data["status"], "ERROR")
        self.assertIn("Access denied", data["error"])

    def test_handle_api_scan_nonexistent_target(self):
        """Non-existent target must return 404."""
        self.handler._handle_api_scan("target=non_existent_folder_123")
        self.handler.send_response.assert_called_with(404)
        data = self._get_response_data()
        self.assertEqual(data["status"], "ERROR")
        self.assertIn("does not exist", data["error"])

    def test_handle_api_reset(self):
        """Reset endpoint should return clean initial state."""
        self.handler._handle_api_reset()
        data = self._get_response_data()

        self.assertEqual(data["status"], "NOT_SCANNED")
        self.assertEqual(data["files_scanned"], 0)
        self.assertEqual(data["clean_files"], 0)
        self.assertEqual(data["syntax_errors"], 0)
        self.assertEqual(data["leaks_detected"], 0)
        self.assertEqual(len(data["findings"]), 0)


if __name__ == "__main__":
    unittest.main()
