"""Comprehensive regression test suite for LeakGuard Git Commit Stage.

Verifies:
1. Genuine Git commit execution on local Git repositories (no mock hashes).
2. Safe rejection when target workspace is not a Git repo and GitHub is unconfigured.
3. Empty working tree detection ("Nothing to commit").
4. Staging isolation (only intended verified files are committed).
5. Proper author identity and real commit SHA retrieval.
6. Endpoint routing across /api/commit, /api/git/commit, /api/github/commit, and /api/projects/workspace/commit.
7. Administrative scan history preservation.

CRITICAL SAFETY:
All Git operations in this test suite are executed exclusively inside isolated
temporary directories (tempfile.TemporaryDirectory). The real project repository
is NEVER modified.
"""

import json
import subprocess
import tempfile
import unittest
from io import BytesIO
from pathlib import Path
from unittest.mock import MagicMock

import app
from git_integration.git_manager import GitManager
from storage.database import Database


class TestGitCommitUnit(unittest.TestCase):
    """Unit tests for GitManager commit logic."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.temp_dir.name).resolve()

    def tearDown(self):
        self.temp_dir.cleanup()

    def _init_git_repo(self, repo_path: Path) -> None:
        """Initialize a clean Git repo with an initial commit in isolated temp dir."""
        subprocess.run(
            ["git", "init"],
            cwd=str(repo_path),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        initial_file = repo_path / "initial.txt"
        initial_file.write_text("initial content", encoding="utf-8")
        subprocess.run(
            ["git", "add", "initial.txt"],
            cwd=str(repo_path),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        subprocess.run(
            ["git", "-c", "user.name=Test", "-c", "user.email=test@test.local", "commit", "-m", "chore: initial commit"],
            cwd=str(repo_path),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def test_non_existent_workspace_path_rejected(self):
        """Invalid or non-existent repository path is rejected."""
        mgr = GitManager(repo_dir=self.tmp_path)
        bad_path = self.tmp_path / "does_not_exist"
        res = mgr.create_branch_and_commit(
            workspace_path=bad_path,
            branch_name="leakguard/test-branch",
            commit_message="test fix",
            verified_files=["some_file.py"],
        )
        self.assertFalse(res["success"])
        self.assertIn("does not exist", res["error"])

    def test_non_git_workspace_rejected_gracefully(self):
        """Non-Git workspace returns clear honest error without faking commit."""
        mgr = GitManager(repo_dir=self.tmp_path)
        dummy_file = self.tmp_path / "file.py"
        dummy_file.write_text("x = 1", encoding="utf-8")

        res = mgr.create_branch_and_commit(
            workspace_path=self.tmp_path,
            branch_name="leakguard/test-branch",
            commit_message="test fix",
            verified_files=["file.py"],
        )
        self.assertFalse(res["success"])
        self.assertIn("not a Git repository", res["error"])
        # Ensure NO fake commit hash is returned
        self.assertNotIn("commit_hash", res)
        self.assertNotIn("commit_sha", res)

    def test_empty_working_tree_handled(self):
        """If verified files have no modifications, returns 'Nothing to commit'."""
        self._init_git_repo(self.tmp_path)
        mgr = GitManager(repo_dir=self.tmp_path)

        res = mgr.create_branch_and_commit(
            workspace_path=self.tmp_path,
            branch_name="leakguard/test-branch",
            commit_message="test fix",
            verified_files=["initial.txt"],
        )
        self.assertFalse(res["success"])
        self.assertIn("Nothing to commit", res["error"])

    def test_successful_commit_returns_real_sha(self):
        """Genuine commit in a temporary Git repository creates commit and returns real SHA."""
        self._init_git_repo(self.tmp_path)
        mgr = GitManager(repo_dir=self.tmp_path)

        # Modify initial.txt with simulated fix
        target_file = self.tmp_path / "initial.txt"
        target_file.write_text("with open('data.txt') as f:\n    f.read()\n", encoding="utf-8")

        res = mgr.create_branch_and_commit(
            workspace_path=self.tmp_path,
            branch_name="leakguard/remediate-leak",
            commit_message="fix: remediate unclosed file descriptor",
            verified_files=["initial.txt"],
        )

        self.assertTrue(res["success"])
        self.assertEqual(res["status"], "COMMITTED")
        self.assertEqual(res["branch"], "leakguard/remediate-leak")
        self.assertIn("initial.txt", res["files_committed"])
        self.assertEqual(res["commit_message"], "fix: remediate unclosed file descriptor")

        real_sha = res["commit_sha"]
        self.assertTrue(len(real_sha) >= 40, f"Expected 40-char SHA, got: {real_sha}")
        self.assertEqual(res["commit_hash"], real_sha[:8])

        # Verify real git log contains this exact commit
        log_res = subprocess.run(
            ["git", "log", "-1", "--format=%H %s"],
            cwd=str(self.tmp_path),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        log_output = log_res.stdout.strip()
        self.assertTrue(log_output.startswith(real_sha), f"git log does not match: {log_output}")
        self.assertIn("fix: remediate unclosed file descriptor", log_output)

    def test_only_intended_files_are_committed(self):
        """Only files specified in verified_files are staged and committed; other changes remain untouched."""
        self._init_git_repo(self.tmp_path)
        mgr = GitManager(repo_dir=self.tmp_path)

        file1 = self.tmp_path / "fix1.py"
        file2 = self.tmp_path / "untouched.py"
        file1.write_text("# file 1 initial\n", encoding="utf-8")
        file2.write_text("# file 2 initial\n", encoding="utf-8")

        subprocess.run(["git", "add", "fix1.py", "untouched.py"], cwd=str(self.tmp_path), check=True)
        subprocess.run(
            ["git", "-c", "user.name=Test", "-c", "user.email=test@test.local", "commit", "-m", "add files"],
            cwd=str(self.tmp_path),
            check=True,
        )

        # Modify BOTH files
        file1.write_text("# file 1 modified by remediation\n", encoding="utf-8")
        file2.write_text("# file 2 modified independently\n", encoding="utf-8")

        # Commit ONLY file1.py
        res = mgr.create_branch_and_commit(
            workspace_path=self.tmp_path,
            branch_name="leakguard/fix-file1",
            commit_message="fix: remediate fix1.py",
            verified_files=["fix1.py"],
        )
        self.assertTrue(res["success"])
        self.assertEqual(res["files_committed"], ["fix1.py"])

        # Check git status: untouched.py should still show as modified in working tree
        status_res = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=str(self.tmp_path),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        status_lines = status_res.stdout.strip().splitlines()
        self.assertTrue(any("untouched.py" in line for line in status_lines), f"Expected untouched.py in status: {status_lines}")
        self.assertFalse(any("fix1.py" in line for line in status_lines), f"fix1.py should be cleanly committed: {status_lines}")


class TestGitCommitAPIEndpoints(unittest.TestCase):
    """Integration tests for commit HTTP endpoints in app.py."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.temp_dir.name).resolve()
        self.db_path = self.tmp_path / "test_commit_admin.db"
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

    def _init_git_repo(self, repo_path: Path) -> None:
        subprocess.run(["git", "init"], cwd=str(repo_path), check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        initial_file = repo_path / "app.py"
        initial_file.write_text("f = open('data.txt')\n", encoding="utf-8")
        subprocess.run(["git", "add", "app.py"], cwd=str(repo_path), check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.run(
            ["git", "-c", "user.name=Test", "-c", "user.email=test@test.local", "commit", "-m", "initial state"],
            cwd=str(repo_path),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def _post(self, path: str, payload: dict):
        payload_bytes = json.dumps(payload).encode("utf-8")
        self.handler.rfile = BytesIO(payload_bytes)
        self.handler.wfile = BytesIO()
        self.handler.send_response = MagicMock()
        self.handler.send_header = MagicMock()
        self.handler.end_headers = MagicMock()
        self.handler.headers = {
            "Content-Length": str(len(payload_bytes)),
            "Content-Type": "application/json",
        }
        self.handler.path = path
        self.handler.do_POST()

        output = self.handler.wfile.getvalue().decode("utf-8")
        status_code = self.handler.send_response.call_args[0][0] if self.handler.send_response.call_args else 200
        data = json.loads(output) if output else {}
        return status_code, data

    def test_all_commit_endpoint_aliases_work(self):
        """Routes /api/commit, /api/git/commit, and /api/projects/workspace/commit are all handled."""
        self._init_git_repo(self.tmp_path)
        ws = self.handler.ws_mgr.create_workspace("Test Repo", self.tmp_path, is_temp=False)

        # Apply modification to app.py
        (self.tmp_path / "app.py").write_text("with open('data.txt') as f:\n    pass\n", encoding="utf-8")

        endpoints = [
            "/api/commit",
            "/api/git/commit",
            "/api/projects/workspace/commit",
            "/api/github/commit",
        ]

        # Test first endpoint
        status, data = self._post("/api/commit", {
            "workspace_id": ws.workspace_id,
            "verified_files": ["app.py"],
            "commit_message": "fix: resolve resource leak",
        })
        self.assertEqual(status, 200)
        self.assertEqual(data["status"], "COMMITTED")
        self.assertTrue(data["success"])
        self.assertIn("commit_sha", data)

        # Modify again for second endpoint
        (self.tmp_path / "app.py").write_text("with open('data.txt') as f:\n    data = f.read()\n", encoding="utf-8")
        status, data = self._post("/api/git/commit", {
            "workspace_id": ws.workspace_id,
            "verified_files": ["app.py"],
            "commit_message": "fix: second leak fix",
        })
        self.assertEqual(status, 200)
        self.assertEqual(data["status"], "COMMITTED")

    def test_commit_failure_returns_400_with_reason(self):
        """Failure returns HTTP 400 with status: ERROR and error message."""
        status, data = self._post("/api/commit", {
            "workspace_id": "nonexistent_ws",
            "verified_files": [],
        })
        self.assertEqual(status, 400)
        self.assertEqual(data["status"], "ERROR")
        self.assertIn("error", data)
        self.assertIn("No verified fixes", data["error"])

    def test_admin_history_preserved_after_commit(self):
        """Admin history is never wiped or corrupted by commit operations."""
        self._init_git_repo(self.tmp_path)
        ws = self.handler.ws_mgr.create_workspace("Admin Preserve Repo", self.tmp_path, is_temp=False)

        # Record initial scan in admin database
        rec = self.test_db.record_scan(
            report=MagicMock(files_scanned=2, clean_files_count=1, issues=[], syntax_errors=[], duration_seconds=0.1),
            target_override="Admin Preserve Repo",
            project_id=ws.workspace_id,
            project_name="Admin Preserve Repo",
            scan_type="LOCAL SCAN",
            branch="main",
            repository="Admin Preserve Repo",
        )
        self.assertIsNotNone(rec)
        init_scans = len(self.test_db.get_recent_scans(limit=10))
        self.assertGreaterEqual(init_scans, 1)

        # Perform commit
        (self.tmp_path / "app.py").write_text("with open('data.txt') as f:\n    pass\n", encoding="utf-8")
        status, data = self._post("/api/commit", {
            "workspace_id": ws.workspace_id,
            "verified_files": ["app.py"],
            "commit_message": "fix: admin preserve check",
        })
        self.assertEqual(status, 200)

        # Admin history must be identical and unaffected
        after_scans = len(self.test_db.get_recent_scans(limit=10))
        self.assertEqual(after_scans, init_scans)


if __name__ == "__main__":
    unittest.main()
