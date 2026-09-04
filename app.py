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
import urllib.parse
import webbrowser
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import cli

HOST = "127.0.0.1"
DEFAULT_PORT = 8000
FRONTEND_DIR = ROOT_DIR / "frontend"


class ReusableTCPServer(socketserver.TCPServer):
    allow_reuse_address = True


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(FRONTEND_DIR), **kwargs)

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
        super().do_GET()

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
            report = cli.scan_target(str(target_path))
            has_leaks = len(report.issues) > 0
            has_syntax_errors = len(report.syntax_errors) > 0

            status_str = "FAILED" if (has_leaks or has_syntax_errors) else "PASS"

            # Findings adhering to the data contract
            findings = []
            for issue in report.issues:
                try:
                    rel_file = Path(issue.location.file_path).relative_to(ROOT_DIR).as_posix()
                except Exception:
                    rel_file = issue.location.file_path

                findings.append({
                    "severity": issue.severity.value if hasattr(issue.severity, "value") else str(issue.severity),
                    "file": rel_file,
                    "line": issue.location.line,
                    "resource": f"{issue.resource_name} ({issue.resource_type})" if issue.resource_name else (issue.resource_type or "Resource"),
                    "variable": issue.resource_name or "f",
                    "reason": issue.message or issue.problem,
                    "leak_path": issue.leak_path or "",
                    "recommendation": issue.recommendation or "",
                    "function_name": issue.function_name or "",
                    "rule_id": issue.rule_id,
                })

            # Syntax errors
            syntax_errors = []
            for err in report.syntax_errors:
                try:
                    rel_filename = Path(err.filename).relative_to(ROOT_DIR).as_posix()
                except Exception:
                    rel_filename = err.filename
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
                    rel_path = Path(r.file_path).relative_to(ROOT_DIR).as_posix()
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
                "target": target,
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

            # Update frontend/report.json for offline tooling
            try:
                report_file = FRONTEND_DIR / "report.json"
                with open(report_file, "w", encoding="utf-8") as rf:
                    json.dump(data, rf, indent=2)
            except Exception:
                pass

            self._send_json(data)
        except Exception as exc:
            self._send_json({"error": str(exc), "status": "ERROR"}, status=500)

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
