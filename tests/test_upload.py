"""Automated tests for Unified Developer Input (File/Folder Uploads) in app.py."""

import json
import unittest
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock

import app
from storage.database import Database


class TestUploadAPI(unittest.TestCase):
    """Test suite for /api/scan/upload single-file and folder upload static AST analysis."""

    def setUp(self):
        self.temp_dir = TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_upload_admin.db"
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

    def _post_upload(self, payload: dict, content_type: str = "application/json", path: str = "/api/scan/upload"):
        payload_bytes = json.dumps(payload).encode("utf-8")
        self.handler.rfile = BytesIO(payload_bytes)
        self.handler.wfile = BytesIO()
        self.handler.send_response = MagicMock()
        self.handler.send_header = MagicMock()
        self.handler.end_headers = MagicMock()
        self.handler.headers = {
            "Content-Length": str(len(payload_bytes)),
            "Content-Type": content_type,
        }
        self.handler.path = path
        self.handler.do_POST()

        output = self.handler.wfile.getvalue().decode("utf-8")
        status_code = self.handler.send_response.call_args[0][0] if self.handler.send_response.call_args else 200
        data = json.loads(output) if output else {}
        return status_code, data

    def test_single_safe_python_file_upload(self):
        """Uploading a single safe Python file returns PASS and records FILE UPLOAD in Admin DB."""
        safe_code = """
def read_data(path):
    with open(path, "r") as f:
        return f.read()
"""
        payload = {
            "filename": "safe_script.py",
            "content": safe_code,
        }
        status, data = self._post_upload(payload)
        self.assertEqual(status, 200)
        self.assertEqual(data["status"], "PASS")
        self.assertEqual(data["files_scanned"], 1)
        self.assertEqual(data["clean_files"], 1)
        self.assertEqual(data["leaks_detected"], 0)
        self.assertEqual(len(data["findings"]), 0)

        # Verify persisted scan_type in database
        recent = self.test_db.get_recent_scans(limit=1)
        self.assertEqual(len(recent), 1)
        self.assertEqual(recent[0]["scan_type"], "FILE UPLOAD")
        self.assertEqual(recent[0]["status"], "PASS")

    def test_single_leaking_python_file_upload(self):
        """Uploading a single leaking Python file returns FAILED with actionable findings."""
        leak_code = """
def process():
    f = open("leak.log", "w")
    if True:
        return None
    f.close()
"""
        payload = {
            "filename": "leaking_script.py",
            "content": leak_code,
        }
        status, data = self._post_upload(payload)
        self.assertEqual(status, 200)
        self.assertEqual(data["status"], "FAILED")
        self.assertEqual(data["files_scanned"], 1)
        self.assertEqual(data["clean_files"], 0)
        self.assertGreaterEqual(data["leaks_detected"], 1)
        self.assertGreaterEqual(len(data["findings"]), 1)

        finding = data["findings"][0]
        self.assertEqual(finding["rule_id"], "LEAK001")
        self.assertIn("file", finding["resource"].lower())

        # Check Admin scan history
        recent = self.test_db.get_recent_scans(limit=1)
        self.assertEqual(len(recent), 1)
        self.assertEqual(recent[0]["scan_type"], "FILE UPLOAD")
        self.assertEqual(recent[0]["status"], "FAILED")

    def test_syntax_error_file_upload(self):
        """Uploading a file with invalid Python syntax returns FAILED with syntax error info."""
        bad_syntax = "def invalid_syntax(:"
        payload = {
            "filename": "broken.py",
            "content": bad_syntax,
        }
        status, data = self._post_upload(payload)
        self.assertEqual(status, 200)
        self.assertEqual(data["status"], "FAILED")
        self.assertEqual(data["syntax_errors"], 1)
        self.assertEqual(len(data["syntax_errors_list"]), 1)
        self.assertIn("broken.py", data["syntax_errors_list"][0]["filename"])

    def test_non_python_single_file_rejected(self):
        """Uploading a single non-Python file returns 400 Bad Request."""
        payload = {
            "filename": "notes.txt",
            "content": "This is a plain text file.",
        }
        status, data = self._post_upload(payload)
        self.assertEqual(status, 400)
        self.assertEqual(data["status"], "ERROR")
        self.assertIn("Only Python (.py) files are supported", data["error"])

    def test_project_folder_upload_multi_file(self):
        """Uploading a project folder scans multiple files and records PROJECT UPLOAD."""
        payload = {
            "target_name": "my_service",
            "files": [
                {
                    "path": "my_service/utils.py",
                    "content": "def add(a, b):\n    return a + b\n",
                },
                {
                    "path": "my_service/io_handler.py",
                    "content": "def write(p, d):\n    f = open(p, 'w')\n    f.write(d)\n",
                },
            ],
        }
        status, data = self._post_upload(payload)
        self.assertEqual(status, 200)
        self.assertEqual(data["status"], "FAILED")
        self.assertEqual(data["files_scanned"], 2)
        self.assertEqual(data["clean_files"], 1)
        self.assertGreaterEqual(data["leaks_detected"], 1)

        # Verify Admin persistence
        recent = self.test_db.get_recent_scans(limit=1)
        self.assertEqual(len(recent), 1)
        self.assertEqual(recent[0]["scan_type"], "PROJECT UPLOAD")
        self.assertIn("my_service", recent[0]["target"])

    def test_folder_upload_ignores_non_python_files(self):
        """Uploading a folder with mixed files parses only .py files and ignores assets."""
        payload = {
            "target_name": "mixed_project",
            "files": [
                {
                    "path": "mixed_project/main.py",
                    "content": "def main():\n    with open('cfg.json') as f:\n        pass\n",
                },
                {
                    "path": "mixed_project/README.md",
                    "content": "# Mixed Project\nDocumentation file",
                },
                {
                    "path": "mixed_project/assets/logo.png",
                    "content": "fake image binary",
                },
            ],
        }
        status, data = self._post_upload(payload)
        self.assertEqual(status, 200)
        self.assertEqual(data["status"], "PASS")
        self.assertEqual(data["files_scanned"], 1)
        self.assertEqual(data["clean_files"], 1)

    def test_folder_upload_without_python_files_rejected(self):
        """Uploading a folder containing no .py files returns 400 Bad Request."""
        payload = {
            "target_name": "docs_only",
            "files": [
                {"path": "docs_only/guide.md", "content": "# Guide"},
                {"path": "docs_only/info.json", "content": "{}"},
            ],
        }
        status, data = self._post_upload(payload)
        self.assertEqual(status, 400)
        self.assertEqual(data["status"], "ERROR")
        self.assertIn("No Python (.py) files found", data["error"])

    def test_path_traversal_attempts_rejected(self):
        """Path traversal attempts using '..' or absolute paths are blocked with 400."""
        traversal_cases = [
            {"filename": "../escaped.py", "content": "x = 1"},
            {"filename": "..\\escaped.py", "content": "x = 1"},
            {"filename": "/etc/passwd.py", "content": "x = 1"},
            {"filename": "C:/Windows/system32/cmd.py", "content": "x = 1"},
        ]
        for case in traversal_cases:
            status, data = self._post_upload(case)
            self.assertEqual(status, 400, f"Failed to reject traversal case: {case['filename']}")
            self.assertEqual(data["status"], "ERROR")

    def test_zero_code_execution_guarantee(self):
        """Uploaded code containing malicious or explosive side-effects is NEVER executed."""
        # This code would crash Python or exit if executed
        malicious_code = """
import sys

# If executed, this would immediately terminate the process or raise
raise RuntimeError("CODE EXECUTION DETECTED! AST PARSER WAS BYPASSED!")
sys.exit(99)
"""
        payload = {
            "filename": "unexecuted.py",
            "content": malicious_code,
        }
        # The AST parser should safely parse the AST without executing a single line
        status, data = self._post_upload(payload)
        self.assertEqual(status, 200)
        # AST parse succeeds; no resource leaks in this snippet; execution never occurred
        self.assertEqual(data["status"], "PASS")
        self.assertEqual(data["files_scanned"], 1)

    def test_developer_reset_preserves_upload_history_in_admin(self):
        """Resetting the developer dashboard preserves persistent upload scan history."""
        # 1. Perform upload scan
        payload = {
            "filename": "persistent_upload.py",
            "content": "with open('a.txt') as f: pass\n",
        }
        self._post_upload(payload)

        # 2. Trigger developer reset
        self.handler.wfile = BytesIO()
        self.handler.send_response = MagicMock()
        self.handler._handle_api_reset()
        reset_output = json.loads(self.handler.wfile.getvalue().decode("utf-8"))
        self.assertEqual(reset_output["status"], "NOT_SCANNED")

        # 3. Verify Admin scan history retains the uploaded scan
        recent = self.test_db.get_recent_scans(limit=10)
        self.assertEqual(len(recent), 1)
        self.assertEqual(recent[0]["scan_type"], "FILE UPLOAD")
        self.assertIn("persistent_upload.py", recent[0]["target"])

    def test_file_upload_updates_admin_history(self):
        """Mandatory regression test: POST /api/scan/upload-file reflects in Admin scans."""
        leak_code = (
            "def leak_file():\n"
            "    f = open('admin_sync_test.txt', 'w')\n"
            "    f.write('data')\n"
        )
        payload = {
            "project_id": "runtime-admin-sync-test",
            "filename": "admin_sync_test.py",
            "content": leak_code,
        }
        status, data = self._post_upload(payload, path="/api/scan/upload-file")
        self.assertEqual(status, 200)
        self.assertEqual(data["status"], "FAILED")
        self.assertEqual(data["files_scanned"], 1)
        self.assertGreaterEqual(len(data.get("findings", [])), 1)
        self.assertEqual(data.get("project_id"), "runtime-admin-sync-test")
        self.assertEqual(data.get("scan_type"), "FILE UPLOAD")
        self.assertIsNotNone(data.get("scan_id"))

        # Query Admin scans endpoint directly
        self.handler.wfile = BytesIO()
        self.handler.send_response = MagicMock()
        self.handler._handle_admin_scans("limit=10")
        admin_data = json.loads(self.handler.wfile.getvalue().decode("utf-8"))
        self.assertEqual(admin_data["status"], "SUCCESS")

        scans = admin_data.get("scans", [])
        self.assertGreaterEqual(len(scans), 1)
        latest = scans[0]
        self.assertEqual(latest["scan_id"], data["scan_id"])
        self.assertEqual(latest["project_id"], "runtime-admin-sync-test")
        self.assertEqual(latest["scan_type"], "FILE UPLOAD")
        self.assertGreaterEqual(latest["leaks_detected"], 1)

    def test_folder_upload_updates_admin_history(self):
        """Folder upload via /api/scan/upload-folder persists as PROJECT UPLOAD."""
        payload = {
            "target_name": "sample_pkg",
            "files": [
                {"path": "sample_pkg/a.py", "content": "with open('f') as f: pass\n"}
            ]
        }
        status, data = self._post_upload(payload, path="/api/scan/upload-folder")
        self.assertEqual(status, 200)
        self.assertEqual(data["status"], "PASS")
        self.assertEqual(data.get("scan_type"), "PROJECT UPLOAD")

        self.handler.wfile = BytesIO()
        self.handler.send_response = MagicMock()
        self.handler._handle_admin_scans("limit=10")
        admin_data = json.loads(self.handler.wfile.getvalue().decode("utf-8"))
        latest = admin_data["scans"][0]
        self.assertEqual(latest["scan_type"], "PROJECT UPLOAD")

    def test_upload_and_admin_use_same_database_path(self):
        """Developer scan process and Admin API process resolve to the identical database file."""
        self.assertEqual(Path(self.handler.db.db_path).resolve(), Path(self.test_db.db_path).resolve())

    def test_developer_reset_does_not_delete_admin_history(self):
        """Resetting the developer view must preserve historical scans in the database."""
        self.test_developer_reset_preserves_upload_history_in_admin()

    def test_deterministic_project_id_accumulates_history(self):
        """Successive scans of the same uploaded file accumulate history under the same project."""
        code_1 = "f = open('test.txt', 'w')\n"
        code_2 = "with open('test.txt', 'w') as f: pass\n"

        status_1, data_1 = self._post_upload({"filename": "sync_test.py", "content": code_1}, path="/api/scan/upload-file")
        status_2, data_2 = self._post_upload({"filename": "sync_test.py", "content": code_2}, path="/api/scan/upload-file")

        self.assertEqual(status_1, 200)
        self.assertEqual(status_2, 200)
        self.assertEqual(data_1["project_id"], data_2["project_id"])

        # Fetch project details from Admin
        self.handler.wfile = BytesIO()
        self.handler.send_response = MagicMock()
        self.handler._handle_admin_project(f"id={data_1['project_id']}")
        proj_resp = json.loads(self.handler.wfile.getvalue().decode("utf-8"))
        self.assertEqual(proj_resp["status"], "SUCCESS")
        project = proj_resp["project"]
        self.assertEqual(len(project["scan_history"]), 2)


if __name__ == "__main__":
    unittest.main()
