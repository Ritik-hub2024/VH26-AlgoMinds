"""
LeakGuard Dashboard Server & Runner

Starts a local HTTP server serving the frontend dashboard
and provides live AST scan results, ZIP project ingestion, automated
remediation fix engine, diff viewer, verification re-scanning, and GitHub OAuth/App workflows.
"""

import http.server
import io
import json
import os
import re
import socketserver
import sys
import tempfile
import time
import urllib.parse
import uuid
import webbrowser
import zipfile
from email import message_from_bytes
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT_DIR = Path(__file__).resolve().parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import cli
from storage.database import Database
from fixers.engine import RemediationEngine
from fixers.patch_generator import generate_diff_chunks
from git_integration.git_manager import GitManager, load_dotenv

# Preload environment variables from .env
load_dotenv()

HOST = "127.0.0.1"
DEFAULT_PORT = int(os.environ.get("PORT", 8000))
FRONTEND_DIR = ROOT_DIR / "frontend"


class Workspace:
    """Manages an active project workspace for scanning and remediation."""

    def __init__(self, workspace_id: str, project_name: str, root_path: Path, is_temp: bool = False):
        self.workspace_id = workspace_id
        self.project_name = project_name
        self.root_path = root_path
        self.is_temp = is_temp
        self.remediation_engine = RemediationEngine()
        self.git_manager = GitManager(repo_dir=root_path)
        self.last_report = None
        self.findings_map: Dict[str, Dict[str, Any]] = {}
        self.created_at = time.time()

    def get_python_files(self) -> List[Path]:
        return cli.discover_python_files(self.root_path)

    def count_lines(self) -> int:
        total = 0
        for f in self.get_python_files():
            try:
                total += len(f.read_text(encoding="utf-8", errors="ignore").splitlines())
            except Exception:
                pass
        return total


class WorkspaceManager:
    """Global manager for active workspaces."""

    def __init__(self):
        self._workspaces: Dict[str, Workspace] = {}
        # Default local workspace
        self.default_workspace = Workspace("default", "LeakGuard Project", ROOT_DIR, is_temp=False)
        self._workspaces["default"] = self.default_workspace

    def get_workspace(self, ws_id: Optional[str]) -> Workspace:
        if not ws_id or ws_id not in self._workspaces:
            return self.default_workspace
        return self._workspaces[ws_id]

    def create_workspace(self, project_name: str, root_path: Path, is_temp: bool = True) -> Workspace:
        ws_id = f"ws_{int(time.time() * 1000)}_{os.urandom(3).hex()}"
        ws = Workspace(ws_id, project_name, root_path, is_temp=is_temp)
        self._workspaces[ws_id] = ws
        return ws


_GLOBAL_WORKSPACE_MGR = WorkspaceManager()
_GLOBAL_GIT_MGR = GitManager(repo_dir=ROOT_DIR)


class ReusableTCPServer(socketserver.TCPServer):
    allow_reuse_address = (sys.platform != "win32")


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(FRONTEND_DIR), **kwargs)

    @property
    def db(self) -> Database:
        if not hasattr(self, "server") or self.server is None:
            if not hasattr(self, "_test_db") or self._test_db is None:
                self._test_db = Database()
            return self._test_db
        if not hasattr(self.server, "_db") or self.server._db is None:
            self.server._db = Database()
        return self.server._db

    @property
    def ws_mgr(self) -> WorkspaceManager:
        return _GLOBAL_WORKSPACE_MGR

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/api/scan":
            self._handle_api_scan(parsed.query)
            return
        if parsed.path in ("/api/projects/workspace/scan", "/api/projects/scan", "/api/scan/workspace"):
            self._handle_workspace_scan()
            return
        if parsed.path == "/api/reset":
            self._handle_api_reset()
            return
        if parsed.path == "/api/projects/workspace/file":
            self._handle_workspace_file(parsed.query)
            return
        if parsed.path == "/api/projects/workspace/verify-summary":
            self._handle_verify_summary(parsed.query)
            return
        # GitHub OAuth & API (Support both /api/github/* and /auth/github/* / /github/*)
        if parsed.path in ("/api/github/auth", "/auth/github"):
            self._handle_github_auth(parsed.query)
            return
        if parsed.path in ("/api/github/callback", "/auth/github/callback"):
            self._handle_github_callback(parsed.query)
            return
        if parsed.path in ("/api/github/status", "/github/status"):
            self._handle_github_status()
            return
        if parsed.path in ("/api/github/config", "/github/config"):
            self._handle_github_config()
            return
        if parsed.path in ("/api/github/repositories", "/github/repositories"):
            self._handle_github_repositories()
            return
        if parsed.path in ("/api/github/branches", "/github/branches"):
            self._handle_github_branches(parsed.query)
            return

        # Support path-based branch lookup: /github/repositories/{owner}/{repo}/branches and /api/github/repositories/{owner}/{repo}/branches
        branch_match = re.match(r"^/(?:api/)?github/repositories/([^/]+)/([^/]+)/branches/?$", parsed.path)
        if branch_match:
            owner, repo_name = branch_match.groups()
            self._handle_github_branches_for(owner, repo_name)
            return

        if parsed.path == "/api/admin/summary":
            self._handle_admin_summary()
            return
        if parsed.path == "/api/admin/projects":
            self._handle_admin_projects()
            return
        if parsed.path == "/api/admin/project":
            self._handle_admin_project(parsed.query)
            return
        if parsed.path == "/api/admin/scans":
            self._handle_admin_scans(parsed.query)
            return
        if parsed.path in ("/api/admin/analytics", "/api/admin/analytics/trend", "/api/admin/analytics/resource-types"):
            self._handle_admin_analytics(parsed.query)
            return
        if parsed.path in ("/admin", "/admin/"):
            self.send_response(302)
            self.send_header("Location", "/#admin")
            self.end_headers()
            return
        super().do_GET()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path in ("/api/scan/upload-file", "/api/upload-file"):
            self._handle_api_upload(force_mode="file")
            return
        if parsed.path in ("/api/scan/upload-folder", "/api/upload-folder"):
            self._handle_api_upload(force_mode="folder")
            return
        if parsed.path in ("/api/scan/upload-zip", "/api/projects/upload-zip"):
            self._handle_upload_zip()
            return
        if parsed.path in ("/api/projects/workspace/scan", "/api/projects/scan", "/api/scan/workspace", "/api/scan", "/api/github/scan", "/github/scan"):
            self._handle_workspace_scan()
            return
        if parsed.path == "/api/findings/generate-fix":
            self._handle_generate_fix()
            return
        if parsed.path == "/api/findings/apply-fix":
            self._handle_apply_fix()
            return
        if parsed.path == "/api/findings/reject-fix":
            self._handle_reject_fix()
            return
        if parsed.path in ("/api/github/auth-token", "/auth/github/token"):
            self._handle_github_auth_token()
            return
        if parsed.path in ("/api/github/connect", "/github/connect"):
            self._handle_github_connect()
            return
        if parsed.path in ("/api/github/disconnect", "/github/disconnect"):
            self._handle_github_disconnect()
            return
        if parsed.path in ("/api/commit", "/api/git/commit", "/api/projects/workspace/commit", "/api/github/commit", "/github/commit"):
            self._handle_commit()
            return
        if parsed.path in ("/api/projects/workspace/open", "/api/workspace/open", "/api/projects/open"):
            self._handle_workspace_open()
            return
        if parsed.path in ("/api/github/pull-request", "/github/pull-request"):
            self._handle_github_pull_request()
            return
        if parsed.path in ("/api/scan/upload", "/api/upload"):
            self._handle_api_upload()
            return
        if parsed.path == "/api/admin/ingest":
            self._handle_admin_ingest()
            return
        self._send_json({"error": f"Endpoint '{parsed.path}' not found.", "status": "ERROR"}, status=404)

    # -------------------------------------------------------------------------
    # GitHub OAuth, Repositories, Branches & Connection
    # -------------------------------------------------------------------------

    def _handle_github_config(self):
        """Return safe GitHub integration configuration status. Never reveals secrets."""
        self._send_json(_GLOBAL_GIT_MGR.get_config_status())

    def _handle_github_branches_for(self, owner: str, repo: str):
        """Fetch branches for specified repository via path parameters."""
        ok, branches, err = _GLOBAL_GIT_MGR.github_client.list_repository_branches(owner, repo)
        if not ok:
            self._send_json({"error": err or "Failed to fetch branches.", "status": "ERROR"}, status=500)
            return
        self._send_json({"status": "SUCCESS", "branches": branches})

    def _handle_github_auth(self, query_str: str = ""):
        """Initiate GitHub OAuth or return current status."""
        state = os.urandom(8).hex()
        host = self.headers.get("Host", "localhost:8000")
        env_redirect = os.environ.get("GITHUB_REDIRECT_URI") or os.environ.get("GITHUB_CALLBACK_URL")
        redirect_uri = env_redirect or f"http://{host}/api/github/callback"

        qs = urllib.parse.parse_qs(query_str)
        force_redirect = qs.get("redirect", ["false"])[0].lower() in ("1", "true", "yes")
        accept_header = self.headers.get("Accept", "")

        is_configured = _GLOBAL_GIT_MGR.is_oauth_configured()
        config_status = _GLOBAL_GIT_MGR.get_config_status()

        if is_configured:
            auth_url = _GLOBAL_GIT_MGR.get_oauth_authorize_url(redirect_uri, state)
            if force_redirect or ("text/html" in accept_header and "application/json" not in accept_header):
                self.send_response(302)
                self.send_header("Location", auth_url)
                self.end_headers()
                return

            self._send_json({
                "configured": True,
                "auth_url": auth_url,
                "authorize_url": auth_url,
                "dev_mode": False,
                "authenticated": bool(_GLOBAL_GIT_MGR.authenticated_user),
                "user": _GLOBAL_GIT_MGR.authenticated_user,
                "config_status": config_status["oauth"],
            })
        elif _GLOBAL_GIT_MGR.github_token and _GLOBAL_GIT_MGR.authenticated_user:
            self._send_json({
                "configured": True,
                "authenticated": True,
                "dev_mode": True,
                "user": _GLOBAL_GIT_MGR.authenticated_user,
                "config_status": config_status["oauth"],
                "message": f"Connected as @{_GLOBAL_GIT_MGR.authenticated_user.get('login')}",
            })
        else:
            if force_redirect or ("text/html" in accept_header and "application/json" not in accept_header):
                self.send_response(302)
                self.send_header("Location", "/#github_modal=open&error=oauth_not_configured")
                self.end_headers()
                return

            self._send_json({
                "configured": False,
                "auth_url": None,
                "authorize_url": None,
                "dev_mode": True,
                "authenticated": False,
                "config_status": config_status["oauth"],
                "message": (
                    "GitHub OAuth is not configured in backend.\n"
                    "Required backend variables in .env:\n"
                    "- GITHUB_CLIENT_ID\n"
                    "- GITHUB_CLIENT_SECRET\n"
                    "- GITHUB_REDIRECT_URI (default: http://localhost:8000/api/github/callback)\n\n"
                    "See docs/github-oauth.md for step-by-step setup instructions."
                ),
            })

    def _handle_github_callback(self, query_str: str):
        """Handle OAuth callback from GitHub."""
        qs = urllib.parse.parse_qs(query_str)
        error = qs.get("error", [""])[0]
        error_description = qs.get("error_description", [""])[0]
        if error:
            err_msg = error_description or error or "access_denied"
            self.send_response(302)
            self.send_header("Location", f"/#error={urllib.parse.quote(err_msg)}")
            self.end_headers()
            return

        code = qs.get("code", [""])[0]
        host = self.headers.get("Host", "localhost:8000")
        env_redirect = os.environ.get("GITHUB_REDIRECT_URI")
        redirect_uri = env_redirect or f"http://{host}/api/github/callback"

        if not code:
            self.send_response(302)
            self.send_header("Location", "/#error=missing_authorization_code")
            self.end_headers()
            return

        success, err = _GLOBAL_GIT_MGR.exchange_oauth_code(code, redirect_uri)
        self.send_response(302)
        if success:
            self.send_header("Location", "/#github_connected=true")
        else:
            self.send_header("Location", f"/#error={urllib.parse.quote(err or 'auth_failed')}")
        self.end_headers()

    def _handle_github_status(self):
        """Return GitHub connection status."""
        self._send_json({
            "authenticated": bool(_GLOBAL_GIT_MGR.github_token and _GLOBAL_GIT_MGR.authenticated_user),
            "user": _GLOBAL_GIT_MGR.authenticated_user,
            "connected_repo": _GLOBAL_GIT_MGR.connected_repo,
            "base_branch": _GLOBAL_GIT_MGR.base_branch,
            "oauth_configured": _GLOBAL_GIT_MGR.is_oauth_configured(),
            "has_token": bool(_GLOBAL_GIT_MGR.github_token),
        })

    def _handle_github_auth_token(self):
        """Authenticate session using a Personal Access Token or direct token."""
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)
            payload = json.loads(body.decode("utf-8"))
            token = payload.get("token", "").strip()

            if not token:
                self._send_json({"error": "Please provide a valid GitHub Personal Access Token.", "status": "ERROR"}, status=400)
                return

            _GLOBAL_GIT_MGR.set_authenticated_token(token)
            if not _GLOBAL_GIT_MGR.authenticated_user:
                self._send_json({
                    "error": "GitHub token authentication failed. Please ensure the token is valid and has 'repo' / 'read:user' scopes.",
                    "status": "ERROR",
                }, status=401)
                return

            self._send_json({
                "status": "SUCCESS",
                "authenticated": True,
                "user": _GLOBAL_GIT_MGR.authenticated_user,
                "message": f"Successfully authenticated as @{_GLOBAL_GIT_MGR.authenticated_user.get('login')}",
            })
        except Exception as e:
            self._send_json({"error": str(e), "status": "ERROR"}, status=500)

    def _handle_github_repositories(self):
        """Fetch real repositories for the authenticated GitHub user."""
        if not _GLOBAL_GIT_MGR.github_token:
            self._send_json({
                "error": "Not authenticated with GitHub. Please connect your GitHub account.",
                "status": "ERROR",
            }, status=401)
            return

        ok, repos, err = _GLOBAL_GIT_MGR.github_client.list_user_repositories()
        if not ok:
            self._send_json({"error": err or "Failed to fetch repositories.", "status": "ERROR"}, status=500)
            return

        self._send_json({"status": "SUCCESS", "repositories": repos})

    def _handle_github_branches(self, query_str: str):
        """Fetch branch names for a repository."""
        qs = urllib.parse.parse_qs(query_str)
        repo_full = qs.get("repo", [""])[0].strip()
        if not repo_full or "/" not in repo_full:
            self._send_json({
                "error": "Missing or invalid 'repo' query parameter. Must be 'owner/repo'.",
                "status": "ERROR",
            }, status=400)
            return

        owner, repo_name = repo_full.split("/", 1)
        ok, branches, err = _GLOBAL_GIT_MGR.github_client.list_repository_branches(owner, repo_name)
        if not ok:
            self._send_json({"error": err or "Failed to fetch branches.", "status": "ERROR"}, status=500)
            return

        self._send_json({"status": "SUCCESS", "branches": branches})

    def _handle_github_connect(self):
        """Connect to a repository, download its archive from GitHub, and set it as active workspace."""
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)
            payload = json.loads(body.decode("utf-8"))

            repo = payload.get("repository", "").strip()
            branch = payload.get("branch", "main").strip() or "main"
            token = payload.get("token", "").strip() or None

            if token:
                _GLOBAL_GIT_MGR.set_authenticated_token(token)

            res = _GLOBAL_GIT_MGR.connect_github(repo, base_branch=branch)
            if not res.get("success"):
                self._send_json({"status": "ERROR", "error": res.get("error")}, status=400)
                return

            owner, repo_name = repo.split("/", 1)

            # Extract archive into isolated temporary workspace
            tmp_dir = tempfile.mkdtemp(prefix="leakguard_gh_")
            tmp_path = Path(tmp_dir).resolve()

            ok_dl, dl_err = _GLOBAL_GIT_MGR.github_client.download_repository_archive(
                owner, repo_name, branch, tmp_path
            )

            if not ok_dl:
                # If download failed because of no network / local workspace fallback
                self._send_json({
                    "status": "ERROR",
                    "error": f"Could not fetch repository '{repo}' ({branch}): {dl_err}",
                }, status=400)
                return

            workspace = self.ws_mgr.create_workspace(f"{repo} ({branch})", tmp_path, is_temp=True)
            workspace.git_manager.connected_repo = repo
            workspace.git_manager.base_branch = branch
            workspace.git_manager.github_token = _GLOBAL_GIT_MGR.github_token

            py_files = workspace.get_python_files()
            total_lines = workspace.count_lines()

            self._send_json({
                "status": "CONNECTED",
                "workspace_id": workspace.workspace_id,
                "repository": repo,
                "branch": branch,
                "files_count": len(py_files),
                "lines_count": total_lines,
                "python_files": [f.relative_to(tmp_path).as_posix() for f in py_files],
                "message": f"Successfully connected to '{repo}' on '{branch}' ({len(py_files)} Python files, {total_lines:,} lines).",
            })
        except Exception as e:
            self._send_json({"error": str(e), "status": "ERROR"}, status=500)

    def _handle_github_disconnect(self):
        """Disconnect GitHub account and clear session."""
        _GLOBAL_GIT_MGR.disconnect_github()
        self._send_json({"status": "DISCONNECTED", "message": "GitHub account disconnected."})

    def _handle_workspace_open(self):
        """Safely open an existing directory as an active workspace."""
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length) if content_length > 0 else b"{}"
            payload = {}
            if body:
                try:
                    payload = json.loads(body.decode("utf-8"))
                except Exception:
                    payload = {}

            target_path_str = payload.get("path") or payload.get("directory") or payload.get("target") or payload.get("workspace_path") or ""
            target_path_str = target_path_str.strip()
            if not target_path_str:
                self._send_json({"error": "Missing 'path' parameter.", "status": "ERROR"}, status=400)
                return

            target_dir = Path(target_path_str).resolve()
            if not target_dir.exists():
                self._send_json({"error": f"Path '{target_path_str}' does not exist.", "status": "ERROR"}, status=404)
                return
            if not target_dir.is_dir():
                self._send_json({"error": f"Path '{target_path_str}' is not a directory.", "status": "ERROR"}, status=400)
                return

            proj_name = payload.get("project_name") or target_dir.name
            workspace = self.ws_mgr.create_workspace(proj_name, target_dir, is_temp=False)

            self._send_json({
                "status": "OPENED",
                "success": True,
                "workspace_id": workspace.workspace_id,
                "project_name": workspace.project_name,
                "path": str(workspace.root_path),
                "is_git_repo": workspace.git_manager.is_git_repo(workspace.root_path),
                "workspace": {
                    "id": workspace.workspace_id,
                    "name": workspace.project_name,
                    "path": str(workspace.root_path),
                    "is_git_repo": workspace.git_manager.is_git_repo(workspace.root_path),
                },
            })
        except Exception as e:
            self._send_json({"error": str(e), "status": "ERROR"}, status=500)

    def _handle_commit(self):
        """Create dedicated branch and commit verified changes."""
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length) if content_length > 0 else b"{}"
            payload = {}
            if body:
                try:
                    payload = json.loads(body.decode("utf-8"))
                except Exception:
                    payload = {}

            ws_id = payload.get("workspace_id") or "default"
            workspace = self.ws_mgr.get_workspace(ws_id)

            summary = workspace.remediation_engine.get_summary()
            verified_files = payload.get("verified_files") or summary.get("files_changed") or []

            if not verified_files:
                err_msg = "No verified fixes available to commit. Please apply and verify fixes first."
                self._send_json({
                    "status": "ERROR",
                    "success": False,
                    "error": err_msg,
                    "reason": err_msg,
                }, status=400)
                return

            branch_name = payload.get("branch_name") or workspace.git_manager.generate_branch_name()
            commit_msg = payload.get("commit_message") or "fix: resolve Python resource leaks"

            res = workspace.git_manager.create_branch_and_commit(
                workspace.root_path, branch_name, commit_msg, verified_files, summary
            )

            if not res.get("success"):
                err_msg = res.get("error", "Commit failed.")
                self._send_json({
                    "status": "ERROR",
                    "success": False,
                    "error": err_msg,
                    "reason": err_msg,
                }, status=400)
                return

            commit_payload = {
                "branch": res["branch"],
                "commit_hash": res["commit_hash"],
                "commit_sha": res.get("commit_sha", res["commit_hash"]),
                "sha": res.get("commit_sha", res["commit_hash"]),
                "commit_url": res.get("commit_url"),
                "commit_message": res.get("commit_message", commit_msg),
                "message": res.get("message", commit_msg),
                "files": res.get("files_committed", verified_files),
                "files_committed": res.get("files_committed", verified_files),
                "repository": res.get("repository", workspace.project_name),
                "mode": res.get("mode", "LOCAL_GIT"),
            }
            self._send_json({
                "status": "COMMITTED",
                "success": True,
                "branch": res["branch"],
                "commit_hash": res["commit_hash"],
                "commit_sha": res.get("commit_sha", res["commit_hash"]),
                "sha": res.get("commit_sha", res["commit_hash"]),
                "commit_url": res.get("commit_url"),
                "commit_message": res.get("commit_message", commit_msg),
                "message": res.get("message", commit_msg),
                "files_committed": res.get("files_committed", verified_files),
                "repository": res.get("repository", workspace.project_name),
                "mode": res.get("mode", "LOCAL_GIT"),
                "commit": commit_payload,
            })

        except Exception as e:
            self._send_json({"error": str(e), "reason": str(e), "status": "ERROR", "success": False}, status=500)

    # Maintain backward-compatible alias
    _handle_github_commit = _handle_commit

    def _handle_github_pull_request(self):
        """Create Pull Request for verified fixes branch."""
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)
            payload = json.loads(body.decode("utf-8"))

            ws_id = payload.get("workspace_id") or "default"
            workspace = self.ws_mgr.get_workspace(ws_id)

            summary = workspace.remediation_engine.get_summary()
            verified_count = summary["verified_fixes"]
            files_changed = summary["files_changed"]

            branch_name = payload.get("branch_name") or _GLOBAL_GIT_MGR.generate_branch_name()
            title = payload.get("title") or "LeakGuard: Fix detected resource leaks"
            desc = payload.get("description") or ""

            res = workspace.git_manager.create_pull_request(
                branch_name, title, desc, verified_count, files_changed
            )

            if not res.get("success"):
                self._send_json({"status": "ERROR", "error": res.get("error")}, status=400)
                return

            self._send_json({
                "status": "PR_CREATED",
                "pr_number": res.get("pr_number"),
                "pr_url": res.get("pr_url"),
                "title": res.get("title"),
                "branch": res.get("branch"),
                "base": res.get("base"),
                "body": res.get("body"),
                "message": f"Pull Request created successfully on '{res.get('branch')}'.",
            })

        except Exception as e:
            self._send_json({"error": str(e), "status": "ERROR"}, status=500)

    # -------------------------------------------------------------------------
    # ZIP Upload and Extraction Handling
    # -------------------------------------------------------------------------

    def _handle_upload_zip(self):
        """Safely extract uploaded ZIP file into an isolated temporary workspace."""
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length <= 0:
                self._send_json({"error": "Empty upload payload.", "status": "ERROR"}, status=400)
                return
            if content_length > 100 * 1024 * 1024:  # 100 MB max
                self._send_json({"error": "ZIP payload exceeds 100MB limit.", "status": "ERROR"}, status=413)
                return

            raw_body = self.rfile.read(content_length)
            content_type = self.headers.get("Content-Type", "")

            zip_bytes = None
            orig_filename = "project.zip"

            if "multipart/form-data" in content_type:
                msg = message_from_bytes(f"Content-Type: {content_type}\r\n\r\n".encode("latin1") + raw_body)
                for part in msg.walk():
                    fname = part.get_filename()
                    if fname and fname.lower().endswith(".zip"):
                        orig_filename = fname
                        zip_bytes = part.get_payload(decode=True)
                        break
            else:
                zip_bytes = raw_body

            if not zip_bytes:
                self._send_json({"error": "No valid ZIP file found in request.", "status": "ERROR"}, status=400)
                return

            if not zipfile.is_zipfile(io.BytesIO(zip_bytes)):
                self._send_json({"error": "Uploaded file is not a valid ZIP archive.", "status": "ERROR"}, status=400)
                return

            tmp_dir = tempfile.mkdtemp(prefix="leakguard_ws_")
            tmp_path = Path(tmp_dir).resolve()

            with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as zf:
                for member in zf.infolist():
                    m_path = member.filename.replace("\\", "/")
                    if "\0" in m_path:
                        self._send_json({"error": "Invalid zip entry: null byte detected.", "status": "ERROR"}, status=400)
                        return

                    if m_path.startswith("/") or ":" in m_path or ".." in Path(m_path).parts:
                        self._send_json({"error": f"Path traversal attempt detected in ZIP member: {m_path}", "status": "ERROR"}, status=400)
                        return

                    parts = Path(m_path).parts
                    if any(part in cli.IGNORED_DIRS or part.startswith(".") for part in parts):
                        continue

                    dest_file = (tmp_path / m_path).resolve()
                    try:
                        dest_file.relative_to(tmp_path)
                    except ValueError:
                        self._send_json({"error": "Path traversal detected.", "status": "ERROR"}, status=400)
                        return

                    if member.is_dir():
                        dest_file.mkdir(parents=True, exist_ok=True)
                    else:
                        dest_file.parent.mkdir(parents=True, exist_ok=True)
                        with zf.open(member) as source, open(dest_file, "wb") as target:
                            target.write(source.read())

            project_name = Path(orig_filename).stem or "Uploaded Project"
            workspace = self.ws_mgr.create_workspace(project_name, tmp_path, is_temp=True)
            py_files = workspace.get_python_files()
            total_lines = workspace.count_lines()

            if not py_files:
                self._send_json({
                    "status": "ERROR",
                    "error": "No Python (.py) source files found in the uploaded ZIP.",
                }, status=400)
                return

            self._send_json({
                "status": "UPLOADED",
                "workspace_id": workspace.workspace_id,
                "project_name": project_name,
                "files_count": len(py_files),
                "lines_count": total_lines,
                "python_files": [f.relative_to(tmp_path).as_posix() for f in py_files],
                "message": f"Successfully extracted '{project_name}' ({len(py_files)} Python files, {total_lines:,} lines). Ready to scan.",
            })

        except Exception as e:
            self._send_json({"error": f"Failed to process ZIP upload: {e}", "status": "ERROR"}, status=500)

    # -------------------------------------------------------------------------
    # Workspace AST Scanning
    # -------------------------------------------------------------------------

    def _handle_workspace_scan(self):
        """Run full AST static analysis on active workspace."""
        try:
            parsed = urllib.parse.urlparse(self.path)
            qs = urllib.parse.parse_qs(parsed.query)
            content_length = int(self.headers.get("Content-Length", 0))
            payload = {}
            if content_length > 0:
                body = self.rfile.read(content_length)
                try:
                    payload = json.loads(body.decode("utf-8"))
                except Exception:
                    payload = {}

            ws_id = payload.get("workspace_id") or qs.get("workspace_id", ["default"])[0] or "default"
            target_sub = payload.get("target") or qs.get("target", [""])[0] or ""
            target_sub = target_sub.strip()
            req_path = payload.get("workspace_path") or payload.get("path") or qs.get("path", [None])[0]

            workspace = self.ws_mgr.get_workspace(ws_id)
            scan_path = workspace.root_path

            if req_path:
                cand_path = Path(req_path).resolve()
                if cand_path.exists():
                    if cand_path.is_file():
                        workspace = self.ws_mgr.create_workspace(cand_path.stem, cand_path.parent, is_temp=False)
                        scan_path = cand_path
                    elif cand_path.is_dir():
                        workspace = self.ws_mgr.create_workspace(cand_path.name, cand_path, is_temp=False)
                        if target_sub and (cand_path / target_sub).exists():
                            scan_path = cand_path / target_sub
                        else:
                            scan_path = cand_path
            elif target_sub:
                sub_candidate = (workspace.root_path / target_sub).resolve()
                try:
                    sub_candidate.relative_to(workspace.root_path)
                    if sub_candidate.exists():
                        scan_path = sub_candidate
                except ValueError:
                    abs_cand = Path(target_sub).resolve()
                    if abs_cand.exists():
                        if abs_cand.is_file():
                            workspace = self.ws_mgr.create_workspace(abs_cand.stem, abs_cand.parent, is_temp=False)
                            scan_path = abs_cand
                        elif abs_cand.is_dir():
                            workspace = self.ws_mgr.create_workspace(abs_cand.name, abs_cand, is_temp=False)
                            scan_path = abs_cand

            import importlib
            importlib.reload(cli)
            report = cli.scan_target(str(scan_path))
            workspace.last_report = report

            findings = []
            workspace.findings_map.clear()

            for idx, issue in enumerate(report.issues):
                try:
                    rel_file = Path(issue.location.file_path).relative_to(workspace.root_path).as_posix()
                except Exception:
                    rel_file = Path(issue.location.file_path).name

                finding_id = f"f_{idx + 1}_{Path(rel_file).name}_{issue.location.line}"
                rule_id = issue.rule_id
                severity = issue.severity.value if hasattr(issue.severity, "value") else str(issue.severity)

                var_name = issue.resource_name or getattr(issue, "variable", "f")
                resource_type = issue.resource_type or "resource"

                if rule_id == "LEAK001" or "file" in resource_type.lower():
                    why_dangerous = (
                        "Unclosed file descriptors cause operating system descriptor exhaustion, "
                        "prevent file deletion/locking on Windows, and lead to silent data loss if write buffers remain un-flushed."
                    )
                elif rule_id == "LEAK002" or "sqlite" in resource_type.lower():
                    why_dangerous = (
                        "Unclosed database connections cause connection pool starvation, "
                        "lock database files, and consume memory buffers on the database engine."
                    )
                else:
                    why_dangerous = "Unmanaged system resources can lead to memory exhaustion and denial-of-service under high load."

                finding_dict = {
                    "id": finding_id,
                    "rule_id": rule_id,
                    "severity": severity,
                    "file": rel_file,
                    "line": issue.location.line,
                    "opened_line": issue.location.line,
                    "resource": f"{var_name} ({resource_type})" if var_name else resource_type,
                    "resource_name": var_name,
                    "variable": var_name,
                    "resource_type": resource_type,
                    "problem": issue.message or issue.problem,
                    "reason": issue.message or issue.problem,
                    "why_dangerous": why_dangerous,
                    "leak_path": issue.leak_path or "",
                    "path": issue.leak_path or "",
                    "cleanup_status": getattr(issue, "cleanup_status", "UNCLOSED"),
                    "recommendation": issue.recommendation or f"Wrap '{var_name}' in a context manager (`with` statement) or `try/finally` block.",
                    "function_name": issue.function_name or "",
                    "classification": getattr(issue, "classification", "LEAK"),
                    "ownership_status": getattr(issue, "ownership_status", "LOCAL"),
                    "is_fixable": workspace.remediation_engine.can_fix({
                        "rule_id": rule_id,
                        "resource": resource_type,
                        "classification": getattr(issue, "classification", "LEAK"),
                        "ownership_status": getattr(issue, "ownership_status", "LOCAL"),
                    }),
                }
                findings.append(finding_dict)
                workspace.findings_map[finding_id] = finding_dict

            syntax_errors = []
            for err in report.syntax_errors:
                try:
                    rel_filename = Path(err.filename).relative_to(workspace.root_path).as_posix()
                except Exception:
                    rel_filename = Path(err.filename).name
                syntax_errors.append({
                    "file": rel_filename,
                    "filename": rel_filename,
                    "line": err.line,
                    "column": err.column,
                    "message": err.message,
                    "text": err.text,
                })

            sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            for f in findings:
                s = (f.get("severity") or "HIGH").upper()
                if s in sev_counts:
                    sev_counts[s] += 1
                else:
                    sev_counts["HIGH"] += 1

            files_inventory = []
            for r in report.parse_results:
                try:
                    rel_path = Path(r.file_path).relative_to(workspace.root_path).as_posix()
                except Exception:
                    rel_path = Path(r.file_path).name

                if not r.success:
                    status_val = "SYNTAX ERROR" if r.syntax_error else "READ ERROR"
                    details = f"SyntaxError: {r.syntax_error.message}" if r.syntax_error else (r.read_error or "Parse failure")
                    loc = f"L{r.syntax_error.line}:{r.syntax_error.column}" if r.syntax_error and r.syntax_error.line else "-"
                else:
                    file_issues = [i for i in report.issues if i.location.file_path == r.file_path]
                    if file_issues:
                        status_val = "LEAK"
                        details = f"{len(file_issues)} resource leak(s) detected"
                        loc = f"Line {file_issues[0].location.line}"
                    else:
                        status_val = "CLEAN"
                        details = "Clean AST parse - zero leaks"
                        loc = "Safe"

                files_inventory.append({
                    "file": rel_path,
                    "status": status_val,
                    "ast_details": details,
                    "location": loc,
                })

            status_str = "FAILED" if (len(findings) > 0 or len(syntax_errors) > 0) else "PASS"

            scan_rec = None
            target_override = target_sub if target_sub else workspace.project_name
            try:
                repo_name = getattr(workspace.git_manager, "connected_repo", None) or "Workspace"
                scan_rec = self.db.record_scan(
                    report=report,
                    target_override=target_override,
                    prepared_findings=findings,
                    project_id=workspace.workspace_id,
                    project_name=workspace.project_name,
                    scan_type="WORKSPACE SCAN",
                    branch="main",
                    repository=repo_name,
                )
            except Exception as e:
                print(f"[!] Warning: DB record_scan failed: {e}", file=sys.stderr)

            resp_data = {
                "status": status_str,
                "scan_id": scan_rec.scan_id if scan_rec else f"scan_{uuid.uuid4().hex[:8]}",
                "project_id": scan_rec.project_id if scan_rec else workspace.workspace_id,
                "scan_type": scan_rec.scan_type if scan_rec else "WORKSPACE SCAN",
                "health_score": scan_rec.health_score if scan_rec else (100 if status_str == "PASS" else 60),
                "target": target_sub or str(scan_path),
                "workspace_id": workspace.workspace_id,
                "project_name": workspace.project_name,
                "files_scanned": report.files_scanned,
                "clean_files": report.clean_files_count,
                "syntax_errors": len(syntax_errors),
                "leaks_detected": len(findings),
                "issues_count": len(findings) + len(syntax_errors),
                "severity_counts": sev_counts,
                "duration_seconds": round(report.duration_seconds, 4),
                "scan_duration_ms": round(report.duration_seconds * 1000, 2),
                "findings": findings,
                "syntax_errors_list": syntax_errors,
                "files": files_inventory,
                "summary": {
                    "files_scanned": report.files_scanned,
                    "clean_files": report.clean_files_count,
                    "syntax_errors_count": len(syntax_errors),
                    "issues_count": len(findings),
                    "duration_seconds": round(report.duration_seconds, 4),
                },
            }

            self._send_json(resp_data)

        except Exception as e:
            self._send_json({"error": str(e), "status": "ERROR"}, status=500)

    # -------------------------------------------------------------------------
    # Code View Endpoint
    # -------------------------------------------------------------------------

    def _handle_workspace_file(self, query_str: str):
        """Fetch surrounding source code for code view modal."""
        try:
            qs = urllib.parse.parse_qs(query_str)
            ws_id = qs.get("workspace_id", ["default"])[0]
            rel_file = qs.get("file", [""])[0].strip()
            highlight_line = int(qs.get("line", ["1"])[0])

            workspace = self.ws_mgr.get_workspace(ws_id)
            target_path = (workspace.root_path / rel_file).resolve()

            try:
                target_path.relative_to(workspace.root_path)
            except ValueError:
                self._send_json({"error": "Access denied.", "status": "ERROR"}, status=403)
                return

            if not target_path.exists():
                self._send_json({"error": f"File '{rel_file}' does not exist.", "status": "ERROR"}, status=404)
                return

            content = target_path.read_text(encoding="utf-8", errors="replace")
            lines = content.splitlines()

            start_line = max(1, highlight_line - 12)
            end_line = min(len(lines), highlight_line + 12)

            snippet_lines = []
            for i in range(start_line, end_line + 1):
                snippet_lines.append({
                    "line_number": i,
                    "code": lines[i - 1],
                    "is_target": i == highlight_line,
                })

            self._send_json({
                "status": "SUCCESS",
                "file": rel_file,
                "highlight_line": highlight_line,
                "total_lines": len(lines),
                "start_line": start_line,
                "end_line": end_line,
                "lines": snippet_lines,
                "full_code": content,
            })

        except Exception as e:
            self._send_json({"error": str(e), "status": "ERROR"}, status=500)

    # -------------------------------------------------------------------------
    # Fix Generation & Remediation Endpoints
    # -------------------------------------------------------------------------

    def _handle_generate_fix(self):
        """Generate safe AST patch and unified diff for a given finding."""
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)
            payload = json.loads(body.decode("utf-8"))

            ws_id = payload.get("workspace_id") or "default"
            finding_id = payload.get("finding_id")
            workspace = self.ws_mgr.get_workspace(ws_id)

            finding = workspace.findings_map.get(finding_id) or payload.get("finding")
            if not finding:
                self._send_json({"status": "ERROR", "error": f"Finding '{finding_id}' not found."}, status=404)
                return

            rel_file = finding.get("file")
            target_path = (workspace.root_path / rel_file).resolve()

            res = workspace.remediation_engine.generate_fix_for_finding(target_path, finding)
            if not res.get("success"):
                self._send_json({"status": "ERROR", "error": res.get("error", "Fix generation failed.")}, status=400)
                return

            self._send_json({
                "status": "SUCCESS",
                "success": True,
                "fix": res["fix"],
                "diff": res["diff"],
            })

        except Exception as e:
            self._send_json({"error": f"Error generating fix: {e}", "status": "ERROR"}, status=500)

    def _handle_apply_fix(self):
        """Apply patch to workspace file and re-scan for automatic verification."""
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)
            payload = json.loads(body.decode("utf-8"))

            ws_id = payload.get("workspace_id") or "default"
            fix_id = payload.get("fix_id")

            workspace = self.ws_mgr.get_workspace(ws_id)
            res = workspace.remediation_engine.apply_fix(fix_id, base_scan_dir=workspace.root_path)

            if not res.get("success"):
                self._send_json({
                    "status": "ERROR",
                    "success": False,
                    "verified": False,
                    "error": res.get("error", "Failed to apply fix."),
                }, status=400)
                return

            import importlib
            importlib.reload(cli)
            updated_report = cli.scan_target(str(workspace.root_path))
            workspace.last_report = updated_report

            self._send_json({
                "status": "VERIFIED",
                "success": True,
                "verified": True,
                "message": "Fix applied and verified! Issue no longer detected.",
                "fix": res["fix"],
                "remaining_leaks": len(updated_report.issues),
                "clean_files": updated_report.clean_files_count,
            })

        except Exception as e:
            self._send_json({"error": f"Error applying fix: {e}", "status": "ERROR"}, status=500)

    def _handle_reject_fix(self):
        """Reject fix proposal."""
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)
            payload = json.loads(body.decode("utf-8"))
            fix_id = payload.get("fix_id")
            self._send_json({"status": "REJECTED", "success": True, "fix_id": fix_id, "message": "Fix rejected."})
        except Exception as e:
            self._send_json({"error": str(e), "status": "ERROR"}, status=500)

    def _handle_verify_summary(self, query_str: str):
        """Get summary of remediation progress and diff statistics."""
        try:
            qs = urllib.parse.parse_qs(query_str)
            ws_id = qs.get("workspace_id", ["default"])[0]
            workspace = self.ws_mgr.get_workspace(ws_id)

            summary = workspace.remediation_engine.get_summary()
            total_detected = len(workspace.findings_map)
            verified = summary["verified_fixes"]
            manual_required = max(0, total_detected - verified)

            self._send_json({
                "status": "SUCCESS",
                "success": True,
                "total_issues": total_detected,
                "automatically_fixed": verified,
                "manual_review_required": manual_required,
                "remediation_ready": verified > 0 and len(summary["files_changed"]) > 0,
                "files_changed": summary["files_changed"],
                "lines_added": summary["lines_added"],
                "lines_removed": summary["lines_removed"],
            })
        except Exception as e:
            self._send_json({"error": str(e), "status": "ERROR"}, status=500)

    # -------------------------------------------------------------------------
    # Legacy & Admin Endpoints
    # -------------------------------------------------------------------------

    def _handle_admin_ingest(self):
        content_len = self.headers.get("Content-Length")
        if not content_len:
            self._send_json({"status": "ERROR", "error": "Missing Content-Length header."}, status=400)
            return

        try:
            length = int(content_len)
            body = self.rfile.read(length)
            payload = json.loads(body.decode("utf-8"))
        except Exception as parse_err:
            self._send_json({"status": "ERROR", "error": f"Invalid JSON body: {parse_err}"}, status=400)
            return

        if not isinstance(payload, dict):
            self._send_json({"status": "ERROR", "error": "Payload must be a JSON object."}, status=400)
            return

        try:
            scan_rec = self.db.ingest_ci_result(payload)
            self._send_json({
                "status": "SUCCESS",
                "message": f"Successfully ingested CI result into project '{scan_rec.project_id}'.",
                "scan": scan_rec.to_dict(),
            })
        except Exception as e:
            self._send_json({"status": "ERROR", "error": f"Failed to ingest CI result: {e}"}, status=500)

    def _handle_admin_summary(self):
        try:
            summary = self.db.get_summary()
            self._send_json({"status": "SUCCESS", "summary": summary})
        except Exception as e:
            self._send_json({"status": "ERROR", "error": str(e)}, status=500)

    def _handle_admin_projects(self):
        try:
            projects = self.db.get_projects()
            self._send_json({"status": "SUCCESS", "projects": projects})
        except Exception as e:
            self._send_json({"status": "ERROR", "error": str(e)}, status=500)

    def _handle_admin_project(self, query_str: str):
        qs = urllib.parse.parse_qs(query_str)
        proj_id = qs.get("id", [""])[0].strip()
        if not proj_id:
            self._send_json({"status": "ERROR", "error": "Missing 'id' query parameter."}, status=400)
            return
        try:
            project = self.db.get_project(proj_id)
            if not project:
                self._send_json({"status": "ERROR", "error": f"Project '{proj_id}' not found."}, status=404)
                return
            self._send_json({"status": "SUCCESS", "project": project})
        except Exception as e:
            self._send_json({"status": "ERROR", "error": str(e)}, status=500)

    def _handle_admin_scans(self, query_str: str):
        qs = urllib.parse.parse_qs(query_str)
        raw_limit = qs.get("limit", ["50"])[0]
        limit = int(raw_limit) if raw_limit.isdigit() else 50
        try:
            scans = self.db.get_recent_scans(limit=limit)
            self._send_json({"status": "SUCCESS", "scans": scans})
        except Exception as e:
            self._send_json({"status": "ERROR", "error": str(e)}, status=500)

    def _handle_admin_analytics(self, query_str: str = ""):
        qs = urllib.parse.parse_qs(query_str)
        project_id = qs.get("project_id", [None])[0]
        if project_id in ("all", "ALL", ""):
            project_id = None

        time_range = qs.get("time_range", [None])[0]
        raw_days = qs.get("days", [None])[0]
        days = None
        if raw_days and raw_days.isdigit():
            days = int(raw_days)
        elif time_range:
            tr_clean = time_range.lower().strip()
            if tr_clean in ("7", "7d", "7days"):
                days = 7
            elif tr_clean in ("30", "30d", "30days"):
                days = 30
            elif tr_clean in ("90", "90d", "90days"):
                days = 90
            elif tr_clean in ("all", "alltime"):
                days = None

        try:
            analytics = self.db.get_analytics(project_id=project_id, days=days)
            self._send_json({"status": "SUCCESS", "analytics": analytics})
        except Exception as e:
            self._send_json({"status": "ERROR", "error": str(e)}, status=500)

    def _handle_api_reset(self):
        self._send_json({
            "status": "NOT_SCANNED",
            "files_scanned": 0,
            "clean_files": 0,
            "syntax_errors": 0,
            "leaks_detected": 0,
            "last_scan": None,
            "scan_duration_ms": 0,
            "target": "examples/",
            "findings": [],
            "files": []
        })

    def _handle_api_scan(self, query_str: str):
        qs = urllib.parse.parse_qs(query_str)
        target = qs.get("target", ["examples"])[0].strip() or "examples"

        try:
            target_path = (ROOT_DIR / target).resolve()
            target_path.relative_to(ROOT_DIR)
        except (ValueError, RuntimeError):
            self._send_json(
                {
                    "error": "Access denied: Scan target must be within the LeakGuard project workspace.",
                    "status": "ERROR",
                    "files_scanned": 0,
                    "clean_files": 0,
                    "syntax_errors": 0,
                    "leaks_detected": 0,
                    "findings": [],
                    "files": [],
                },
                status=403,
            )
            return

        if not target_path.exists():
            self._send_json(
                {
                    "error": f"Target path '{target}' does not exist.",
                    "status": "ERROR",
                    "files_scanned": 0,
                    "clean_files": 0,
                    "syntax_errors": 0,
                    "leaks_detected": 0,
                    "findings": [],
                    "files": [],
                },
                status=404,
            )
            return

        try:
            import importlib
            importlib.reload(cli)
            report = cli.scan_target(str(target_path))
            self._build_scan_response(
                report=report,
                target_display=target,
                base_dir=ROOT_DIR,
                project_id=None,
                project_name=None,
                scan_type="LOCAL SCAN",
                branch="main",
                repository="Local Workspace",
            )
        except Exception as exc:
            self._send_json({"error": str(exc), "status": "ERROR"}, status=500)

    def _build_scan_response(
        self,
        report,
        target_display: str,
        base_dir: Path | None = None,
        project_id: str | None = None,
        project_name: str | None = None,
        scan_type: str = "LOCAL SCAN",
        branch: str = "main",
        repository: str = "Local Workspace",
        workspace_id: str | None = None,
        workspace: Any = None,
    ):
        has_leaks = len(report.issues) > 0
        has_syntax_errors = len(report.syntax_errors) > 0
        status_str = "FAILED" if (has_leaks or has_syntax_errors) else "PASS"

        ref_dir = base_dir or ROOT_DIR

        findings = []
        for idx, issue in enumerate(report.issues):
            try:
                rel_file = Path(issue.location.file_path).relative_to(ref_dir).as_posix()
            except Exception:
                rel_file = Path(issue.location.file_path).name

            finding_id = f"f_{idx + 1}_{Path(rel_file).name}_{issue.location.line}"
            rule_id = issue.rule_id
            severity = issue.severity.value if hasattr(issue.severity, "value") else str(issue.severity)
            var_name = issue.resource_name or getattr(issue, "variable", "f")
            resource_type = issue.resource_type or "resource"

            finding_dict = {
                "id": finding_id,
                "rule_id": rule_id,
                "severity": severity,
                "file": rel_file,
                "line": issue.location.line,
                "opened_line": issue.location.line,
                "resource": f"{var_name} ({resource_type})" if var_name else resource_type,
                "resource_name": var_name,
                "variable": var_name,
                "resource_type": resource_type,
                "problem": issue.message or issue.problem,
                "reason": issue.message or issue.problem,
                "why_dangerous": "Unmanaged system resources can lead to exhaustion, file locks, or silent data loss under high load.",
                "leak_path": issue.leak_path or "",
                "path": issue.leak_path or "",
                "cleanup_status": getattr(issue, "cleanup_status", "UNCLOSED"),
                "recommendation": issue.recommendation or "",
                "function_name": issue.function_name or "",
                "classification": getattr(issue, "classification", "LEAK"),
                "ownership_status": getattr(issue, "ownership_status", "LOCAL"),
                "is_fixable": True,
            }
            findings.append(finding_dict)
            if workspace is not None:
                workspace.findings_map[finding_id] = finding_dict

        syntax_errors = []
        for err in report.syntax_errors:
            try:
                rel_filename = Path(err.filename).relative_to(ref_dir).as_posix()
            except Exception:
                rel_filename = Path(err.filename).name
            syntax_errors.append({
                "file": rel_filename,
                "filename": rel_filename,
                "line": err.line,
                "column": err.column,
                "message": err.message,
                "text": err.text,
            })

        files_inventory = []
        for r in report.parse_results:
            try:
                rel_path = Path(r.file_path).relative_to(ref_dir).as_posix()
            except Exception:
                rel_path = Path(r.file_path).name

            if not r.success:
                status_val = "SYNTAX ERROR" if r.syntax_error else "READ ERROR"
                details = f"SyntaxError: {r.syntax_error.message}" if r.syntax_error else (r.read_error or "Parse failure")
                loc = f"L{r.syntax_error.line}:{r.syntax_error.column}" if r.syntax_error and r.syntax_error.line else "-"
            else:
                file_issues = [i for i in report.issues if i.location.file_path == r.file_path]
                if file_issues:
                    status_val = "LEAK"
                    details = f"{len(file_issues)} resource leak(s) detected"
                    loc = f"Line {file_issues[0].location.line}"
                else:
                    status_val = "CLEAN"
                    details = "Clean AST parse - no resource leaks or syntax errors"
                    loc = "Safe"

            files_inventory.append({
                "file": rel_path,
                "status": status_val,
                "ast_details": details,
                "location": loc,
            })

        data = {
            "status": status_str,
            "target": target_display,
            "files_scanned": report.files_scanned,
            "clean_files": report.clean_files_count,
            "syntax_errors": len(report.syntax_errors),
            "leaks_detected": len(report.issues),
            "last_scan": None,
            "scan_duration_ms": round(report.duration_seconds * 1000, 2),
            "duration_seconds": round(report.duration_seconds, 4),
            "findings": findings,
            "syntax_errors_list": syntax_errors,
            "files": files_inventory,
            "summary": {
                "files_scanned": report.files_scanned,
                "clean_files": report.clean_files_count,
                "syntax_errors_count": len(report.syntax_errors),
                "issues_count": len(report.issues),
                "duration_seconds": round(report.duration_seconds, 4),
            },
        }

        if workspace_id:
            data["workspace_id"] = workspace_id

        # Persist scan result automatically for Admin & History
        scan_rec = None
        try:
            scan_rec = self.db.record_scan(
                report=report,
                target_override=target_display,
                prepared_findings=findings,
                project_id=project_id,
                project_name=project_name,
                scan_type=scan_type,
                branch=branch,
                repository=repository,
            )
        except Exception as db_err:
            print(f"[!] Warning: Failed to persist scan to database: {db_err}", file=sys.stderr)

        if scan_rec:
            data["scan_id"] = scan_rec.scan_id
            data["project_id"] = scan_rec.project_id
            data["scan_type"] = scan_rec.scan_type
            data["health_score"] = scan_rec.health_score
        else:
            data["project_id"] = project_id
            data["scan_type"] = scan_type

        # Update frontend/report.json for offline tooling
        try:
            report_file = FRONTEND_DIR / "report.json"
            with open(report_file, "w", encoding="utf-8") as rf:
                json.dump(data, rf, indent=2)
        except Exception:
            pass

        self._send_json(data)

    def _handle_api_upload(self, force_mode: str | None = None):
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length <= 0:
                self._send_json({"error": "Empty upload payload.", "status": "ERROR"}, status=400)
                return
            if content_length > 50 * 1024 * 1024:
                self._send_json({"error": "Payload exceeds maximum allowed size of 50MB.", "status": "ERROR"}, status=413)
                return

            raw_body = self.rfile.read(content_length)
            content_type = self.headers.get("Content-Type", "")

            uploaded_files = []
            target_folder_name = None
            requested_project_id = None
            requested_project_name = None

            parsed_url = urllib.parse.urlparse(self.path)
            url_qs = urllib.parse.parse_qs(parsed_url.query)
            if "project_id" in url_qs:
                requested_project_id = url_qs["project_id"][0].strip()
            if "project_name" in url_qs:
                requested_project_name = url_qs["project_name"][0].strip()

            if "multipart/form-data" in content_type:
                msg = message_from_bytes(f"Content-Type: {content_type}\r\n\r\n".encode("latin1") + raw_body)
                for part in msg.walk():
                    fname = part.get_filename()
                    name_field = part.get_param("name", header="content-disposition")
                    if fname:
                        payload = part.get_payload(decode=True)
                        if payload is not None:
                            uploaded_files.append((fname, payload))
                    elif name_field == "project_id":
                        p_val = part.get_payload(decode=True)
                        if p_val:
                            requested_project_id = p_val.decode("utf-8", errors="replace").strip()
                    elif name_field == "project_name":
                        p_val = part.get_payload(decode=True)
                        if p_val:
                            requested_project_name = p_val.decode("utf-8", errors="replace").strip()
                    elif name_field in ("target_name", "folder_name"):
                        p_val = part.get_payload(decode=True)
                        if p_val:
                            target_folder_name = p_val.decode("utf-8", errors="replace").strip()
            else:
                try:
                    payload_data = json.loads(raw_body.decode("utf-8"))
                except Exception as e:
                    self._send_json({"error": f"Invalid JSON payload: {e}", "status": "ERROR"}, status=400)
                    return

                if isinstance(payload_data, dict):
                    target_folder_name = payload_data.get("target_name") or payload_data.get("folder_name")
                    if payload_data.get("project_id"):
                        requested_project_id = str(payload_data["project_id"]).strip()
                    if payload_data.get("project_name"):
                        requested_project_name = str(payload_data["project_name"]).strip()

                    if "files" in payload_data and isinstance(payload_data["files"], list):
                        for item in payload_data["files"]:
                            fpath = item.get("path") or item.get("filename") or item.get("name") or ""
                            fcontent = item.get("content", item.get("code", ""))
                            if isinstance(fcontent, str):
                                fcontent = fcontent.encode("utf-8")
                            uploaded_files.append((fpath, fcontent))
                    elif any(k in payload_data for k in ("filename", "path", "name", "file")):
                        fpath = payload_data.get("filename") or payload_data.get("path") or payload_data.get("name") or payload_data.get("file") or ""
                        fcontent = payload_data.get("content", payload_data.get("code", ""))
                        if isinstance(fcontent, str):
                            fcontent = fcontent.encode("utf-8")
                        uploaded_files.append((fpath, fcontent))
                elif isinstance(payload_data, list):
                    for item in payload_data:
                        fpath = item.get("path") or item.get("filename") or item.get("name") or ""
                        fcontent = item.get("content", item.get("code", ""))
                        if isinstance(fcontent, str):
                            fcontent = fcontent.encode("utf-8")
                        uploaded_files.append((fpath, fcontent))

            if not uploaded_files:
                self._send_json({"error": "No files provided in upload.", "status": "ERROR"}, status=400)
                return

            clean_files = []
            for path_str, content_bytes in uploaded_files:
                path_str = path_str.strip().replace("\\", "/")
                if not path_str:
                    continue
                if "\0" in path_str:
                    self._send_json({"error": "Invalid path: null byte detected.", "status": "ERROR"}, status=400)
                    return
                if path_str.startswith("/") or ":" in path_str:
                    self._send_json({"error": f"Invalid path '{path_str}': Absolute paths are not permitted.", "status": "ERROR"}, status=400)
                    return
                p = Path(path_str)
                if ".." in p.parts:
                    self._send_json({"error": f"Invalid path '{path_str}': Directory traversal ('..') is not permitted.", "status": "ERROR"}, status=400)
                    return
                clean_files.append((path_str, content_bytes))

            if not clean_files:
                self._send_json({"error": "No valid files provided in upload.", "status": "ERROR"}, status=400)
                return

            # Determine whether single file or folder upload
            if force_mode == "file":
                is_single = True
            elif force_mode == "folder":
                is_single = False
            elif len(clean_files) == 1:
                first_path = clean_files[0][0]
                if not target_folder_name or target_folder_name.endswith(".py") or target_folder_name == first_path or "/" not in first_path:
                    is_single = True
                else:
                    is_single = False
            else:
                is_single = False

            if is_single:
                single_path, single_content = clean_files[0]
                if not single_path.lower().endswith(".py"):
                    self._send_json({"error": "Invalid file type: Only Python (.py) files are supported.", "status": "ERROR"}, status=400)
                    return
                fname = Path(single_path).name
                py_files = [(fname, single_content)]
                target_display = f"upload:{fname}"
                default_proj_name = f"Upload: {fname}"
                stem = Path(fname).stem.replace("_", "-").replace(".", "-").lower()
                default_project_id = f"upload-{stem}"
                scan_type = "FILE UPLOAD"
            else:
                py_files = [(p, c) for p, c in clean_files if p.lower().endswith(".py")]
                if not py_files:
                    self._send_json({"error": "No Python (.py) files found in uploaded folder.", "status": "ERROR"}, status=400)
                    return
                folder_name = target_folder_name or (Path(py_files[0][0]).parts[0] if len(Path(py_files[0][0]).parts) > 1 else "uploaded_project")
                target_display = f"upload:{folder_name}"
                default_proj_name = f"Upload: {folder_name}"
                folder_slug = folder_name.replace("_", "-").replace(".", "-").replace("/", "-").lower()
                default_project_id = f"upload-{folder_slug}"
                scan_type = "PROJECT UPLOAD"

            final_project_id = requested_project_id or default_project_id
            final_project_name = requested_project_name or default_proj_name

            # Create persistent isolated workspace directory for this upload
            tmp_dir = tempfile.mkdtemp(prefix="leakguard_upload_")
            tmpdir_path = Path(tmp_dir).resolve()
            for rel_path, content_bytes in py_files:
                dest = (tmpdir_path / rel_path).resolve()
                try:
                    dest.relative_to(tmpdir_path)
                except ValueError:
                    self._send_json({"error": "Path traversal detected.", "status": "ERROR"}, status=400)
                    return
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(content_bytes)

            workspace = self.ws_mgr.create_workspace(final_project_name, tmpdir_path, is_temp=True)

            if is_single:
                scan_target_path = str(tmpdir_path / py_files[0][0])
            else:
                scan_target_path = str(tmpdir_path)

            import importlib
            importlib.reload(cli)
            report = cli.scan_target(scan_target_path)
            workspace.last_report = report

            self._build_scan_response(
                report=report,
                target_display=target_display,
                base_dir=tmpdir_path,
                project_id=final_project_id,
                project_name=final_project_name,
                scan_type=scan_type,
                branch="upload",
                repository="Uploaded Code",
                workspace_id=workspace.workspace_id,
                workspace=workspace,
            )
        except Exception as e:
            self._send_json({"error": str(e), "status": "ERROR"}, status=500)

    def _send_json(self, payload: dict, status: int = 200):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def find_server(host: str = HOST, start_port: int = DEFAULT_PORT, max_attempts: int = 20):
    for port in range(start_port, start_port + max_attempts):
        try:
            server = ReusableTCPServer((host, port), Handler)
            return server, port
        except OSError as e:
            if "Address already in use" in str(e) or getattr(e, "errno", None) in (48, 98, 10048, 10013):
                continue
            raise
        except Exception:
            continue
    raise RuntimeError(f"Could not find an available port between {start_port} and {start_port + max_attempts - 1}")


def main():
    try:
        httpd, port = find_server(host=HOST, start_port=DEFAULT_PORT)
    except Exception as e:
        print(f"[!] Error starting server: {e}")
        return 1

    url = f"http://localhost:{port}"
    print("=" * 60)
    print("  [LeakGuard] Security Remediation Platform Server")
    print("=" * 60)
    print(f"Serving dashboard from: {FRONTEND_DIR}")
    print(f"Dashboard URL:          {url}")
    print("Press Ctrl+C to stop the server.")
    print("=" * 60)

    if "--no-browser" not in sys.argv:
        try:
            webbrowser.open(url)
        except Exception:
            pass

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping LeakGuard server...")
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    main()
