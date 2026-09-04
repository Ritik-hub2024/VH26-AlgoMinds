"""
LeakGuard Dashboard Server & Runner

Starts a local HTTP server serving the frontend dashboard
and provides live AST scan results via /api/scan.
"""

import http.server
import json
import os
import socketserver
import sys
import tempfile
import time
import urllib.parse
import webbrowser
from email import message_from_bytes
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import cli
from storage.database import Database

HOST = "127.0.0.1"
DEFAULT_PORT = 8000
FRONTEND_DIR = ROOT_DIR / "frontend"


class ReusableTCPServer(socketserver.TCPServer):
    allow_reuse_address = True


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(FRONTEND_DIR), **kwargs)

    @property
    def db(self) -> Database:
        if not hasattr(self.server, "_db") or self.server._db is None:
            self.server._db = Database()
        return self.server._db

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/api/scan":
            self._handle_api_scan(parsed.query)
            return
        if parsed.path == "/api/reset":
            self._handle_api_reset()
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
        if parsed.path == "/api/admin/analytics":
            self._handle_admin_analytics()
            return
        if parsed.path in ("/admin", "/admin/"):
            self.send_response(302)
            self.send_header("Location", "/#admin")
            self.end_headers()
            return
        super().do_GET()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path in ("/api/scan/upload", "/api/upload"):
            self._handle_api_upload()
            return
        self._send_json({"error": f"Endpoint '{parsed.path}' not found.", "status": "ERROR"}, status=404)

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

    def _handle_admin_analytics(self):
        try:
            analytics = self.db.get_analytics()
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

        # Security check: disallow path traversal outside project root
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
    ):
        has_leaks = len(report.issues) > 0
        has_syntax_errors = len(report.syntax_errors) > 0
        status_str = "FAILED" if (has_leaks or has_syntax_errors) else "PASS"

        ref_dir = base_dir or ROOT_DIR

        # Findings adhering to the data contract
        findings = []
        for issue in report.issues:
            try:
                rel_file = Path(issue.location.file_path).relative_to(ref_dir).as_posix()
            except Exception:
                rel_file = Path(issue.location.file_path).name

            findings.append({
                "severity": issue.severity.value if hasattr(issue.severity, "value") else str(issue.severity),
                "file": rel_file,
                "line": issue.location.line,
                "opened_line": issue.location.line,
                "resource": f"{issue.resource_name} ({issue.resource_type})" if issue.resource_name else (issue.resource_type or "Resource"),
                "variable": issue.resource_name or getattr(issue, "variable", "f"),
                "reason": issue.message or issue.problem,
                "leak_path": issue.leak_path or "",
                "path": issue.leak_path or "",
                "cleanup_status": getattr(issue, "cleanup_status", "UNCLOSED"),
                "recommendation": issue.recommendation or "",
                "function_name": issue.function_name or "",
                "rule_id": issue.rule_id,
            })

        # Syntax errors
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

        # File inventory
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

        # Persist scan result automatically for Admin & History
        try:
            self.db.record_scan(
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

        # Update frontend/report.json for offline tooling
        try:
            report_file = FRONTEND_DIR / "report.json"
            with open(report_file, "w", encoding="utf-8") as rf:
                json.dump(data, rf, indent=2)
        except Exception:
            pass

        self._send_json(data)

    def _handle_api_upload(self):
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length <= 0:
                self._send_json({"error": "Empty upload payload.", "status": "ERROR"}, status=400)
                return
            if content_length > 50 * 1024 * 1024:  # 50 MB limit
                self._send_json({"error": "Payload exceeds maximum allowed size of 50MB.", "status": "ERROR"}, status=413)
                return

            raw_body = self.rfile.read(content_length)
            content_type = self.headers.get("Content-Type", "")

            uploaded_files = []  # list of (rel_path: str, content_bytes: bytes)
            target_folder_name = None

            if "multipart/form-data" in content_type:
                msg = message_from_bytes(f"Content-Type: {content_type}\r\n\r\n".encode("latin1") + raw_body)
                for part in msg.walk():
                    fname = part.get_filename()
                    if fname:
                        payload = part.get_payload(decode=True)
                        if payload is not None:
                            uploaded_files.append((fname, payload))
            else:
                # Assume JSON payload
                try:
                    payload_data = json.loads(raw_body.decode("utf-8"))
                except Exception as e:
                    self._send_json({"error": f"Invalid JSON payload: {e}", "status": "ERROR"}, status=400)
                    return

                if isinstance(payload_data, dict):
                    target_folder_name = payload_data.get("target_name")
                    if "files" in payload_data and isinstance(payload_data["files"], list):
                        for item in payload_data["files"]:
                            fpath = item.get("path") or item.get("filename") or ""
                            fcontent = item.get("content", "")
                            if isinstance(fcontent, str):
                                fcontent = fcontent.encode("utf-8")
                            uploaded_files.append((fpath, fcontent))
                    elif "filename" in payload_data:
                        fpath = payload_data.get("filename") or ""
                        fcontent = payload_data.get("content", "")
                        if isinstance(fcontent, str):
                            fcontent = fcontent.encode("utf-8")
                        uploaded_files.append((fpath, fcontent))
                elif isinstance(payload_data, list):
                    for item in payload_data:
                        fpath = item.get("path") or item.get("filename") or ""
                        fcontent = item.get("content", "")
                        if isinstance(fcontent, str):
                            fcontent = fcontent.encode("utf-8")
                        uploaded_files.append((fpath, fcontent))

            if not uploaded_files:
                self._send_json({"error": "No files provided in upload.", "status": "ERROR"}, status=400)
                return

            # Validate path safety
            clean_files = []
            for path_str, content_bytes in uploaded_files:
                path_str = path_str.strip().replace("\\", "/")
                if not path_str:
                    continue
                if "\0" in path_str:
                    self._send_json({"error": "Invalid path: null byte detected.", "status": "ERROR"}, status=400)
                    return
                # Check absolute or colon (Windows drive letter)
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

            # Single file vs folder upload check
            if len(clean_files) == 1 and not target_folder_name:
                single_path, single_content = clean_files[0]
                if not single_path.lower().endswith(".py"):
                    self._send_json({"error": "Invalid file type: Only Python (.py) files are supported.", "status": "ERROR"}, status=400)
                    return
                py_files = [(Path(single_path).name, single_content)]
                is_single = True
                target_display = f"upload:{Path(single_path).name}"
                project_name = f"Upload: {Path(single_path).name}"
                scan_type = "FILE UPLOAD"
            else:
                # Folder upload / multi-file: Filter and ignore non-Python files
                py_files = [(p, c) for p, c in clean_files if p.lower().endswith(".py")]
                if not py_files:
                    self._send_json({"error": "No Python (.py) files found in uploaded folder.", "status": "ERROR"}, status=400)
                    return
                is_single = False
                folder_name = target_folder_name or (Path(py_files[0][0]).parts[0] if len(Path(py_files[0][0]).parts) > 1 else "uploaded_project")
                target_display = f"upload:{folder_name}"
                project_name = f"Upload: {folder_name}"
                scan_type = "PROJECT UPLOAD"

            # Execute AST scan in isolated temporary directory
            with tempfile.TemporaryDirectory(prefix="leakguard_upload_") as tmpdir:
                tmpdir_path = Path(tmpdir).resolve()
                for rel_path, content_bytes in py_files:
                    dest = (tmpdir_path / rel_path).resolve()
                    # Verify dest is strictly within tmpdir_path
                    try:
                        dest.relative_to(tmpdir_path)
                    except ValueError:
                        self._send_json({"error": "Path traversal detected.", "status": "ERROR"}, status=400)
                        return
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.write_bytes(content_bytes)

                if is_single:
                    scan_target_path = str(tmpdir_path / py_files[0][0])
                else:
                    scan_target_path = str(tmpdir_path)

                import importlib
                importlib.reload(cli)
                report = cli.scan_target(scan_target_path)

                self._build_scan_response(
                    report=report,
                    target_display=target_display,
                    base_dir=tmpdir_path,
                    project_id=f"upload_{int(time.time() * 1000)}",
                    project_name=project_name,
                    scan_type=scan_type,
                    branch="upload",
                    repository="Uploaded Code",
                )
        except Exception as e:
            self._send_json({"error": str(e), "status": "ERROR"}, status=500)

    def _send_json(self, payload: dict, status: int = 200):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
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
    print("  [LeakGuard] Web Dashboard Server")
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
