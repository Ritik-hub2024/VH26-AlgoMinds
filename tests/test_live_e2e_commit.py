"""
Phase 14 End-to-End Live Workflow Verification
Tests Upload/Open -> Scan -> Findings -> Fix -> Verify -> Commit
Spins up a live LeakGuard HTTP server instance on an ephemeral port.
Uses an isolated temporary Git repository (never touches the main repo).
"""
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import Handler, ReusableTCPServer


def run_git(args, cwd):
    res = subprocess.run(["git"] + args, cwd=cwd, capture_output=True, text=True, check=True)
    return res.stdout.strip()


def main():
    print(">>> Starting Phase 14 Live E2E Verification Server...")
    server = ReusableTCPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    base_url = f"http://127.0.0.1:{port}"

    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    print(f"  Live test server running on {base_url}")

    def post_json(path, data):
        url = base_url + path
        req = urllib.request.Request(
            url,
            data=json.dumps(data).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def get_json(path):
        url = base_url + path
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8"))

    try:
        # 1. Create temporary git repo outside workspace
        with tempfile.TemporaryDirectory(prefix="leakguard_live_test_") as tmpdir:
            repo_dir = os.path.join(tmpdir, "my_test_repo")
            os.makedirs(repo_dir)
            run_git(["init", "-b", "main"], cwd=repo_dir)
            run_git(["config", "user.name", "Live Tester"], cwd=repo_dir)
            run_git(["config", "user.email", "live@test.local"], cwd=repo_dir)

            # Create a file with a resource leak
            leaking_file = os.path.join(repo_dir, "service.py")
            with open(leaking_file, "w", encoding="utf-8") as f:
                f.write(
                    "def process_data(path, flag):\n"
                    "    f = open(path, 'r')\n"
                    "    if flag:\n"
                    "        return None\n"
                    "    data = f.read()\n"
                    "    f.close()\n"
                    "    return data\n"
                )

            # Also create an untracked/clean file
            clean_file = os.path.join(repo_dir, "utils.py")
            with open(clean_file, "w", encoding="utf-8") as f:
                f.write("def add(a, b):\n    return a + b\n")

            run_git(["add", "."], cwd=repo_dir)
            run_git(["commit", "-m", "Initial commit"], cwd=repo_dir)
            initial_sha = run_git(["rev-parse", "HEAD"], cwd=repo_dir)
            print(f"  [1] Initialized git repo at {repo_dir} with commit {initial_sha[:8]}")

            # 2. Open workspace
            open_res = post_json("/api/projects/workspace/open", {"workspace_path": repo_dir})
            assert open_res.get("success"), f"Failed to open workspace: {open_res}"
            ws_id = open_res["workspace"]["id"]
            print(f"  [2] Workspace opened: {ws_id}")

            # 3. Scan workspace
            scan_res = post_json("/api/projects/workspace/scan", {"workspace_id": ws_id})
            assert "findings" in scan_res, f"Scan failed: {scan_res}"
            findings = scan_res.get("findings", [])
            assert len(findings) >= 1, f"Expected findings, got {findings}"
            finding = findings[0]
            finding_id = finding["id"]
            print(f"  [3] Scan completed with {len(findings)} findings. First finding ID: {finding_id}")

            # 4. Generate fix
            fix_res = post_json("/api/findings/generate-fix", {
                "finding_id": finding_id,
                "workspace_id": ws_id
            })
            assert fix_res.get("success"), f"Generate fix failed: {fix_res}"
            fix_id = fix_res["fix"]["fix_id"]
            print("  [4] Remediation code generated successfully.")

            # 5. Apply fix
            apply_res = post_json("/api/findings/apply-fix", {
                "finding_id": finding_id,
                "workspace_id": ws_id,
                "fix_id": fix_id
            })
            assert apply_res.get("success"), f"Apply fix failed: {apply_res}"
            print(f"  [5] Fix applied: {apply_res.get('message')}")

            # 6. Verify (Re-scan workspace)
            verify_scan = post_json("/api/projects/workspace/scan", {"workspace_id": ws_id})
            assert "findings" in verify_scan, f"Verify scan failed: {verify_scan}"
            assert len(verify_scan.get("findings", [])) == 0, f"Expected 0 findings after fix, got {verify_scan.get('findings')}"
            print("  [6] Re-scan verified 0 remaining leaks.")

            # Also check verify-summary
            summary = get_json(f"/api/projects/workspace/verify-summary?workspace_id={ws_id}")
            assert summary.get("success"), f"Verify summary failed: {summary}"
            assert summary.get("remediation_ready") is True
            print("  [7] Verify-summary reports remediation_ready = True.")

            # 7. Commit changes via /api/commit
            commit_res = post_json("/api/commit", {
                "workspace_id": ws_id,
                "commit_message": "fix(leak): apply context manager to service.py"
            })
            assert commit_res.get("success") is True, f"Commit endpoint failed: {commit_res}"
            commit_data = commit_res["commit"]
            new_sha = commit_data["sha"]
            branch = commit_data["branch"]
            files_committed = commit_data["files"]
            print(f"  [8] Commit succeeded via API! SHA: {new_sha[:8]}, Branch: {branch}, Files: {files_committed}")

            # 8. Verify git repo state directly using git commands
            repo_sha = run_git(["rev-parse", "HEAD"], cwd=repo_dir)
            assert repo_sha == new_sha, f"Mismatch in repo HEAD ({repo_sha}) vs returned sha ({new_sha})"
            assert repo_sha != initial_sha, "Commit SHA did not change!"
            git_log_subject = run_git(["log", "-1", "--format=%s"], cwd=repo_dir)
            assert git_log_subject == "fix(leak): apply context manager to service.py", f"Unexpected subject: {git_log_subject}"
            git_log_files = run_git(["diff-tree", "--no-commit-id", "--name-only", "-r", repo_sha], cwd=repo_dir)
            assert "service.py" in git_log_files, f"service.py was not in commit diff: {git_log_files}"
            assert "utils.py" not in git_log_files, "utils.py was unexpectedly committed!"
            print(f"  [9] Verified git repo: HEAD is {repo_sha[:8]}, only service.py modified.")

            # 9. Test committing again when nothing has changed -> should detect nothing to commit
            try:
                commit_res2 = post_json("/api/commit", {
                    "workspace_id": ws_id,
                    "commit_message": "second commit"
                })
            except urllib.error.HTTPError as he:
                error_body = json.loads(he.read().decode("utf-8"))
                commit_res2 = error_body

            assert commit_res2.get("success") is False, "Expected error on empty working tree"
            assert "Nothing to commit" in commit_res2.get("error", ""), f"Unexpected error message: {commit_res2}"
            print(f"  [10] Verified clean error on unchanged tree: {commit_res2.get('error')}")

            # 10. Check Admin dashboard data is preserved
            admin_scans = get_json("/api/admin/scans?limit=5")
            assert admin_scans.get("status") == "SUCCESS" or admin_scans.get("success") is True, f"Admin scans failed: {admin_scans}"
            print(f"  [11] Admin dashboard scans retrieved successfully ({len(admin_scans.get('scans', []))} scans present).")

        print(">>> ALL PHASE 14 END-TO-END LIVE WORKFLOW CHECKS PASSED PERFECTLY!")

    finally:
        server.shutdown()
        server.server_close()


def test_phase14_live_e2e_workflow():
    main()


if __name__ == "__main__":
    main()
